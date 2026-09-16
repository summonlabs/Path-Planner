#include "pathplanner/path.hpp"

#include <algorithm>
#include <string>

#include "pathplanner/version.hpp"

namespace summon::pathplanner {
namespace {

bool AddChecked(CostValue& accumulator, CostValue addend) noexcept {
  const std::optional<CostValue> sum = CheckedAdd(accumulator, addend);
  if (!sum.has_value()) {
    return false;
  }
  accumulator = *sum;
  return true;
}

}  // namespace

bool operator==(const PathHop& lhs, const PathHop& rhs) noexcept {
  return lhs.link == rhs.link && lhs.from == rhs.from && lhs.to == rhs.to && lhs.from_port == rhs.from_port &&
         lhs.to_port == rhs.to_port && lhs.layer == rhs.layer && lhs.relationship == rhs.relationship &&
         lhs.structural_generation == rhs.structural_generation && lhs.static_cost == rhs.static_cost &&
         lhs.link_state == rhs.link_state && lhs.degraded == rhs.degraded;
}

bool CandidatePath::IsWellFormed() const noexcept {
  if (!source.IsValid() || !destination.IsValid()) {
    return false;
  }
  if (nodes.size() != hops.size() + 1) {
    return false;
  }
  if (nodes.empty()) {
    return false;
  }
  if (nodes.front() != source || nodes.back() != destination) {
    return false;
  }
  for (std::size_t i = 0; i < hops.size(); ++i) {
    if (hops[i].from != nodes[i] || hops[i].to != nodes[i + 1]) {
      return false;
    }
    if (hops[i].layer != layer) {
      return false;
    }
    if (!hops[i].link.IsValid() || !hops[i].from_port.IsValid() || !hops[i].to_port.IsValid()) {
      return false;
    }
  }
  return true;
}

bool CandidatePath::IsSimple() const noexcept {
  if (nodes.size() < 2) {
    return true;
  }
  std::vector<NodeId> sorted(nodes.begin(), nodes.end());
  std::sort(sorted.begin(), sorted.end());
  return std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end();
}

void CandidatePath::Encode(ByteWriter& writer) const {
  writer.U32(kPathEncodingVersion);
  writer.FixedBytes(source.Span());
  writer.FixedBytes(destination.Span());
  writer.U32(static_cast<std::uint32_t>(layer));
  writer.VarU64(hops.size());
  for (const PathHop& hop : hops) {
    writer.FixedBytes(hop.link.Span());
    writer.FixedBytes(hop.from.Span());
    writer.FixedBytes(hop.to.Span());
    writer.FixedBytes(hop.from_port.Span());
    writer.FixedBytes(hop.to_port.Span());
    writer.U32(static_cast<std::uint32_t>(hop.layer));
    writer.U32(static_cast<std::uint32_t>(hop.relationship));
    writer.U64(hop.structural_generation.Value());
    writer.U32(hop.static_cost.Value());
  }
}

Sha256Digest CandidatePath::Digest() const {
  const std::size_t ceiling = 256 + hops.size() * 128;
  ByteWriter writer(ceiling);
  Encode(writer);
  if (writer.overflowed()) {
    return Sha256Digest{};
  }
  return Sha256::Hash(writer.span());
}

CandidatePathId CandidatePath::Id() const {
  const Sha256Digest digest = Digest();
  if (digest.IsZero()) {
    return CandidatePathId{};
  }
  return CandidatePathId::FromDigest(digest);
}

std::string CandidatePath::Render() const {
  std::string out;
  for (std::size_t i = 0; i < nodes.size(); ++i) {
    if (i != 0) {
      out += " -> ";
    }
    out += nodes[i].ToString();
  }
  return out;
}

std::string CandidatePath::RenderHops() const {
  std::string out;
  for (const PathHop& hop : hops) {
    out += hop.link.ToString();
    out += ":";
    out += hop.from.ToString();
    out += "->";
    out += hop.to.ToString();
    out += " ";
  }
  if (!out.empty()) {
    out.pop_back();
  }
  return out;
}

bool operator==(const PathCost& lhs, const PathCost& rhs) noexcept {
  return lhs.hops_cost == rhs.hops_cost && lhs.static_cost == rhs.static_cost &&
         lhs.degraded_penalty == rhs.degraded_penalty && lhs.locality_penalty == rhs.locality_penalty &&
         lhs.total == rhs.total && lhs.hops == rhs.hops && lhs.degraded_hops == rhs.degraded_hops &&
         lhs.locality_breaches == rhs.locality_breaches;
}

std::optional<PathCost> AccumulatePathCost(const std::vector<HopCostInput>& hops, const CostModel& model) {
  if (hops.size() > static_cast<std::size_t>(kMaxHopCount)) {
    return std::nullopt;
  }
  PathCost cost;
  cost.hops = HopCount(static_cast<std::uint32_t>(hops.size()));

  const std::optional<CostValue> hops_cost = CheckedMul(model.hop_cost, static_cast<std::uint64_t>(hops.size()));
  if (!hops_cost.has_value()) {
    return std::nullopt;
  }
  cost.hops_cost = *hops_cost;

  std::uint64_t degraded_hops = 0;
  std::uint64_t locality_breaches = 0;
  for (const HopCostInput& hop : hops) {
    if (!AddChecked(cost.static_cost, CostValue(hop.static_cost.Value()))) {
      return std::nullopt;
    }
    if (hop.degraded) {
      degraded_hops += 1;
    }
    if (hop.outside_locality) {
      locality_breaches += 1;
    }
  }
  cost.degraded_hops = static_cast<std::uint32_t>(degraded_hops);
  cost.locality_breaches = static_cast<std::uint32_t>(locality_breaches);

  const std::optional<CostValue> degraded = CheckedMul(model.degraded_penalty, degraded_hops);
  if (!degraded.has_value()) {
    return std::nullopt;
  }
  cost.degraded_penalty = *degraded;

  const std::optional<CostValue> locality = CheckedMul(model.locality_penalty, locality_breaches);
  if (!locality.has_value()) {
    return std::nullopt;
  }
  cost.locality_penalty = *locality;

  CostValue total;
  if (!AddChecked(total, cost.hops_cost) || !AddChecked(total, cost.static_cost) ||
      !AddChecked(total, cost.degraded_penalty) || !AddChecked(total, cost.locality_penalty)) {
    return std::nullopt;
  }
  cost.total = total;
  return cost;
}

std::strong_ordering CompareCanonicalPaths(const CandidatePath& lhs, const CandidatePath& rhs) noexcept {
  const std::size_t shared = std::min(lhs.nodes.size(), rhs.nodes.size());
  for (std::size_t index = 0; index < shared; ++index) {
    if (lhs.nodes[index] != rhs.nodes[index]) {
      return lhs.nodes[index] < rhs.nodes[index] ? std::strong_ordering::less
                                                 : std::strong_ordering::greater;
    }
  }
  if (lhs.nodes.size() != rhs.nodes.size()) {
    return lhs.nodes.size() < rhs.nodes.size() ? std::strong_ordering::less
                                                : std::strong_ordering::greater;
  }
  const std::size_t shared_hops = std::min(lhs.hops.size(), rhs.hops.size());
  for (std::size_t index = 0; index < shared_hops; ++index) {
    if (lhs.hops[index].link != rhs.hops[index].link) {
      return lhs.hops[index].link < rhs.hops[index].link ? std::strong_ordering::less
                                                          : std::strong_ordering::greater;
    }
  }
  if (lhs.hops.size() != rhs.hops.size()) {
    return lhs.hops.size() < rhs.hops.size() ? std::strong_ordering::less
                                              : std::strong_ordering::greater;
  }
  return std::strong_ordering::equal;
}

bool RanksBefore(const Candidate& lhs, const Candidate& rhs) noexcept {
  if (lhs.cost.total != rhs.cost.total) {
    return lhs.cost.total < rhs.cost.total;
  }
  if (lhs.cost.hops != rhs.cost.hops) {
    return lhs.cost.hops < rhs.cost.hops;
  }
  return CompareCanonicalPaths(lhs.path, rhs.path) == std::strong_ordering::less;
}

}  // namespace summon::pathplanner

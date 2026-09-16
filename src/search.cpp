#include "search.hpp"

#include <algorithm>
#include <queue>
#include <string>
#include <utility>

namespace summon::pathplanner::internal {
namespace {

constexpr std::uint32_t kInfiniteHops = 0xFFFFFFFFu;

struct QueueEntry {
  CostValue cost;
  std::uint32_t hops = 0;
  std::uint32_t state = 0;
};

struct QueueGreater {
  bool operator()(const QueueEntry& lhs, const QueueEntry& rhs) const noexcept {
    if (lhs.cost != rhs.cost) {
      return lhs.cost > rhs.cost;
    }
    if (lhs.hops != rhs.hops) {
      return lhs.hops > rhs.hops;
    }
    return lhs.state > rhs.state;
  }
};

bool BetterLabel(CostValue cost, std::uint32_t hops, CostValue other_cost, std::uint32_t other_hops) noexcept {
  if (cost != other_cost) {
    return cost < other_cost;
  }
  return hops < other_hops;
}

std::optional<CostValue> HopIncrement(const PlanningView& view, const Adjacency& entry) {
  return CheckedAdd(view.cost_model.hop_cost, entry.traversal_cost);
}

std::uint32_t AdjacencyBegin(const PlanningView& view, std::uint32_t node) noexcept {
  return view.offsets[node];
}

std::uint32_t AdjacencyEnd(const PlanningView& view, std::uint32_t node) noexcept {
  return view.offsets[static_cast<std::size_t>(node) + 1];
}

struct RankedRawPath {
  RawPath path;
  PathCost cost;
};

bool RankedBefore(const PlanningView& view, const RankedRawPath& lhs, const RankedRawPath& rhs) {
  if (lhs.cost.total != rhs.cost.total) {
    return lhs.cost.total < rhs.cost.total;
  }
  if (lhs.cost.hops != rhs.cost.hops) {
    return lhs.cost.hops < rhs.cost.hops;
  }
  const std::size_t shared = std::min(lhs.path.nodes.size(), rhs.path.nodes.size());
  for (std::size_t i = 0; i < shared; ++i) {
    const NodeId& left = view.NodeAt(lhs.path.nodes[i]).id;
    const NodeId& right = view.NodeAt(rhs.path.nodes[i]).id;
    if (left != right) {
      return left < right;
    }
  }
  if (lhs.path.nodes.size() != rhs.path.nodes.size()) {
    return lhs.path.nodes.size() < rhs.path.nodes.size();
  }
  const std::size_t shared_hops = std::min(lhs.path.adjacency.size(), rhs.path.adjacency.size());
  for (std::size_t i = 0; i < shared_hops; ++i) {
    const LinkId& left = view.EdgeAt(view.adjacency[lhs.path.adjacency[i]].edge).id;
    const LinkId& right = view.EdgeAt(view.adjacency[rhs.path.adjacency[i]].edge).id;
    if (left != right) {
      return left < right;
    }
  }
  return false;
}

std::optional<CostValue> IncrementFor(const PlanningView& view, std::uint32_t adjacency_index) {
  return HopIncrement(view, view.adjacency[adjacency_index]);
}

}  // namespace

void BanSet::AddNode(std::uint32_t view_index) {
  nodes_.push_back(view_index);
  normalized_ = false;
}

void BanSet::AddAdjacency(std::uint32_t adjacency_index) {
  adjacency_.push_back(adjacency_index);
  normalized_ = false;
}

void BanSet::Normalize() const {
  if (normalized_) {
    return;
  }
  std::sort(nodes_.begin(), nodes_.end());
  nodes_.erase(std::unique(nodes_.begin(), nodes_.end()), nodes_.end());
  std::sort(adjacency_.begin(), adjacency_.end());
  adjacency_.erase(std::unique(adjacency_.begin(), adjacency_.end()), adjacency_.end());
  normalized_ = true;
}

bool BanSet::NodeBanned(std::uint32_t view_index) const noexcept {
  Normalize();
  return std::binary_search(nodes_.begin(), nodes_.end(), view_index);
}

bool BanSet::AdjacencyBanned(std::uint32_t adjacency_index) const noexcept {
  Normalize();
  return std::binary_search(adjacency_.begin(), adjacency_.end(), adjacency_index);
}

bool SameRawPath(const RawPath& lhs, const RawPath& rhs) noexcept {
  return lhs.nodes == rhs.nodes && lhs.adjacency == rhs.adjacency;
}

bool RawPathRanksBefore(const PlanningView& view, const RawPath& lhs, const RawPath& rhs) {
  const std::optional<PathCost> lhs_cost = ComputeRawPathCost(view, lhs);
  const std::optional<PathCost> rhs_cost = ComputeRawPathCost(view, rhs);
  if (!lhs_cost.has_value() || !rhs_cost.has_value()) {
    return lhs_cost.has_value();
  }
  RankedRawPath left{lhs, *lhs_cost};
  RankedRawPath right{rhs, *rhs_cost};
  return RankedBefore(view, left, right);
}

std::optional<PathCost> ComputeRawPathCost(const PlanningView& view, const RawPath& raw) {
  std::vector<HopCostInput> hops;
  hops.reserve(raw.adjacency.size());
  for (const std::uint32_t adjacency_index : raw.adjacency) {
    const Adjacency& entry = view.adjacency[adjacency_index];
    HopCostInput input;
    input.static_cost = view.EdgeAt(entry.edge).static_cost;
    input.degraded = entry.degraded;
    input.outside_locality = entry.outside_locality;
    hops.push_back(input);
  }
  return AccumulatePathCost(hops, view.cost_model);
}

bool DomainMemberLimitCompliant(const PlanningView& view, const RawPath& raw, std::uint32_t limit,
                                bool fail_closed) {
  if (raw.adjacency.empty()) {
    return true;
  }
  std::vector<std::pair<FailureDomainId, std::uint32_t>> counts;
  for (const std::uint32_t adjacency_index : raw.adjacency) {
    const Adjacency& entry = view.adjacency[adjacency_index];
    const LinkId& link = view.EdgeAt(entry.edge).id;
    const FailureDomainView::Membership membership =
        view.snapshot->FailureDomains().MembershipOf(SubjectKey::ForLink(link));
    if (!membership.known) {
      if (fail_closed) {
        return false;
      }
      continue;
    }
    for (const FailureDomainId& domain : membership.domains) {
      auto it = std::lower_bound(counts.begin(), counts.end(), domain,
                                 [](const std::pair<FailureDomainId, std::uint32_t>& item,
                                    const FailureDomainId& value) { return item.first < value; });
      if (it == counts.end() || it->first != domain) {
        it = counts.insert(it, std::make_pair(domain, 0u));
      }
      it->second += 1;
      if (it->second > limit) {
        return false;
      }
    }
  }
  return true;
}

CandidatePath BuildCandidatePath(const PlanningView& view, const RawPath& raw) {
  CandidatePath path;
  if (raw.nodes.empty()) {
    return path;
  }
  path.layer = view.layer;
  path.source = view.NodeAt(raw.nodes.front()).id;
  path.destination = view.NodeAt(raw.nodes.back()).id;
  path.nodes.reserve(raw.nodes.size());
  for (const std::uint32_t node : raw.nodes) {
    path.nodes.push_back(view.NodeAt(node).id);
  }
  path.hops.reserve(raw.adjacency.size());
  for (const std::uint32_t adjacency_index : raw.adjacency) {
    const Adjacency& entry = view.adjacency[adjacency_index];
    const EdgeRecord& edge = view.EdgeAt(entry.edge);
    PathHop hop;
    hop.link = edge.id;
    hop.from = edge.from;
    hop.to = edge.to;
    hop.from_port = edge.from_port;
    hop.to_port = edge.to_port;
    hop.layer = edge.layer;
    hop.relationship = edge.relationship;
    hop.structural_generation = edge.structural_generation;
    hop.static_cost = edge.static_cost;
    hop.link_state = view.snapshot->LinkStates().StateOf(edge.id);
    hop.degraded = entry.degraded;
    path.hops.push_back(hop);
  }
  return path;
}

Searcher::Searcher(const PlanningView& view, WorkBudget& budget, PlannerStatistics& stats)
    : view_(view), budget_(budget), stats_(stats) {}

bool Searcher::SpendState() {
  if (budget_.states_remaining == 0) {
    budget_.exhausted = true;
    return false;
  }
  budget_.states_remaining -= 1;
  stats_.states_expanded += 1;
  return true;
}

bool Searcher::SpendPush() {
  if (budget_.pushes_remaining == 0) {
    budget_.exhausted = true;
    return false;
  }
  budget_.pushes_remaining -= 1;
  stats_.queue_pushes += 1;
  return true;
}

SearchOutcome Searcher::ShortestPath(std::uint32_t source, std::uint32_t dest, std::uint32_t hop_budget,
                                     const BanSet& bans) {
  SearchOutcome outcome;
  if (source == dest) {
    outcome.found = true;
    outcome.path.nodes.push_back(source);
    return outcome;
  }
  const std::uint32_t node_count = view_.NodeCount();
  if (source >= node_count || dest >= node_count) {
    return outcome;
  }
  if (hop_budget == 0) {
    return outcome;
  }
  if (hop_budget == kNoHopBound) {
    return PlainSearch(source, dest, kNoHopBound, bans);
  }
  const std::uint32_t simple_bound = node_count == 0 ? 0 : node_count - 1;
  if (hop_budget < simple_bound) {
    return ExpandedSearch(source, dest, hop_budget, bans);
  }
  return PlainSearch(source, dest, hop_budget, bans);
}

SearchOutcome Searcher::PlainSearch(std::uint32_t source, std::uint32_t dest, std::uint32_t hop_budget,
                                    const BanSet& bans) {
  SearchOutcome outcome;
  const std::uint32_t node_count = view_.NodeCount();
  std::vector<CostValue> dist(node_count, CostValue::Max());
  std::vector<std::uint32_t> hops(node_count, kInfiniteHops);
  std::vector<std::uint8_t> settled(node_count, 0);

  std::priority_queue<QueueEntry, std::vector<QueueEntry>, QueueGreater> queue;
  dist[source] = CostValue(0);
  hops[source] = 0;
  queue.push(QueueEntry{CostValue(0), 0, source});
  if (!SpendPush()) {
    outcome.resource_limit = true;
    return outcome;
  }

  while (!queue.empty()) {
    const QueueEntry entry = queue.top();
    queue.pop();
    const std::uint32_t node = entry.state;
    if (settled[node] != 0) {
      continue;
    }
    if (BetterLabel(dist[node], hops[node], entry.cost, entry.hops)) {
      continue;
    }
    settled[node] = 1;
    for (std::uint32_t adjacency_index = AdjacencyBegin(view_, node);
         adjacency_index < AdjacencyEnd(view_, node); ++adjacency_index) {
      if (bans.AdjacencyBanned(adjacency_index)) {
        continue;
      }
      const Adjacency& candidate = view_.adjacency[adjacency_index];
      if (bans.NodeBanned(candidate.to)) {
        continue;
      }
      const std::uint32_t next_hops = hops[node] + 1;
      if (hop_budget != kNoHopBound && next_hops > hop_budget) {
        continue;
      }
      const std::optional<CostValue> increment = HopIncrement(view_, candidate);
      if (!increment.has_value()) {
        outcome.cost_overflow = true;
        continue;
      }
      const std::optional<CostValue> next_cost = CheckedAdd(entry.cost, *increment);
      if (!next_cost.has_value()) {
        outcome.cost_overflow = true;
        continue;
      }
      if (!SpendState()) {
        outcome.resource_limit = true;
        return outcome;
      }
      if (!BetterLabel(*next_cost, next_hops, dist[candidate.to], hops[candidate.to])) {
        continue;
      }
      dist[candidate.to] = *next_cost;
      hops[candidate.to] = next_hops;
      queue.push(QueueEntry{*next_cost, next_hops, candidate.to});
      if (!SpendPush()) {
        outcome.resource_limit = true;
        return outcome;
      }
    }
  }

  if (dist[dest] == CostValue::Max()) {
    return outcome;
  }

  const std::uint32_t target_hops = hops[dest];
  std::vector<std::vector<std::uint32_t>> buckets(target_hops + 1);
  for (std::uint32_t node = 0; node < node_count; ++node) {
    if (dist[node] != CostValue::Max() && hops[node] <= target_hops) {
      buckets[hops[node]].push_back(node);
    }
  }

  std::vector<std::uint8_t> can_reach(node_count, 0);
  can_reach[dest] = 1;
  for (std::uint32_t level = target_hops; level > 0; --level) {
    const std::uint32_t current = level - 1;
    for (const std::uint32_t node : buckets[current]) {
      bool reachable = false;
      for (std::uint32_t adjacency_index = AdjacencyBegin(view_, node);
           adjacency_index < AdjacencyEnd(view_, node); ++adjacency_index) {
        if (bans.AdjacencyBanned(adjacency_index)) {
          continue;
        }
        const Adjacency& candidate = view_.adjacency[adjacency_index];
        if (bans.NodeBanned(candidate.to)) {
          continue;
        }
        if (hops[candidate.to] != current + 1 || can_reach[candidate.to] == 0) {
          continue;
        }
        const std::optional<CostValue> increment = HopIncrement(view_, candidate);
        if (!increment.has_value()) {
          continue;
        }
        const std::optional<CostValue> next_cost = CheckedAdd(dist[node], *increment);
        if (!next_cost.has_value() || *next_cost != dist[candidate.to]) {
          continue;
        }
        reachable = true;
        break;
      }
      can_reach[node] = reachable ? 1 : 0;
    }
  }

  if (can_reach[source] == 0) {
    return outcome;
  }

  RawPath path;
  path.nodes.push_back(source);
  std::uint32_t current = source;
  while (current != dest) {
    bool advanced = false;
    for (std::uint32_t adjacency_index = AdjacencyBegin(view_, current);
         adjacency_index < AdjacencyEnd(view_, current); ++adjacency_index) {
      if (bans.AdjacencyBanned(adjacency_index)) {
        continue;
      }
      const Adjacency& candidate = view_.adjacency[adjacency_index];
      if (bans.NodeBanned(candidate.to) || can_reach[candidate.to] == 0) {
        continue;
      }
      if (hops[candidate.to] != hops[current] + 1) {
        continue;
      }
      const std::optional<CostValue> increment = HopIncrement(view_, candidate);
      if (!increment.has_value()) {
        continue;
      }
      const std::optional<CostValue> next_cost = CheckedAdd(dist[current], *increment);
      if (!next_cost.has_value() || *next_cost != dist[candidate.to]) {
        continue;
      }
      path.nodes.push_back(candidate.to);
      path.adjacency.push_back(adjacency_index);
      current = candidate.to;
      advanced = true;
      break;
    }
    if (!advanced) {
      return outcome;
    }
  }
  outcome.found = true;
  outcome.path = std::move(path);
  return outcome;
}

SearchOutcome Searcher::ExpandedSearch(std::uint32_t source, std::uint32_t dest, std::uint32_t hop_budget,
                                       const BanSet& bans) {
  SearchOutcome outcome;
  const std::uint32_t node_count = view_.NodeCount();
  const std::uint64_t state_count = (static_cast<std::uint64_t>(hop_budget) + 1) * node_count;
  if (state_count > view_.limits.max_search_states) {
    budget_.state_space_exceeded = true;
    outcome.resource_limit = true;
    return outcome;
  }
  const std::size_t states = static_cast<std::size_t>(state_count);
  const auto index_of = [node_count](std::uint32_t hops, std::uint32_t node) {
    return static_cast<std::size_t>(hops) * node_count + node;
  };

  std::vector<CostValue> dist(states, CostValue::Max());
  std::vector<std::uint8_t> settled(states, 0);
  std::priority_queue<QueueEntry, std::vector<QueueEntry>, QueueGreater> queue;
  dist[index_of(0, source)] = CostValue(0);
  queue.push(QueueEntry{CostValue(0), 0, source});
  if (!SpendPush()) {
    outcome.resource_limit = true;
    return outcome;
  }

  while (!queue.empty()) {
    const QueueEntry entry = queue.top();
    queue.pop();
    const std::uint32_t hops = entry.hops;
    const std::uint32_t node = entry.state;
    const std::size_t state = index_of(hops, node);
    if (settled[state] != 0) {
      continue;
    }
    if (dist[state] != entry.cost) {
      continue;
    }
    settled[state] = 1;
    if (hops == hop_budget) {
      continue;
    }
    for (std::uint32_t adjacency_index = AdjacencyBegin(view_, node);
         adjacency_index < AdjacencyEnd(view_, node); ++adjacency_index) {
      if (bans.AdjacencyBanned(adjacency_index)) {
        continue;
      }
      const Adjacency& candidate = view_.adjacency[adjacency_index];
      if (bans.NodeBanned(candidate.to)) {
        continue;
      }
      const std::optional<CostValue> increment = HopIncrement(view_, candidate);
      if (!increment.has_value()) {
        outcome.cost_overflow = true;
        continue;
      }
      const std::optional<CostValue> next_cost = CheckedAdd(entry.cost, *increment);
      if (!next_cost.has_value()) {
        outcome.cost_overflow = true;
        continue;
      }
      if (!SpendState()) {
        outcome.resource_limit = true;
        return outcome;
      }
      const std::size_t next_state = index_of(hops + 1, candidate.to);
      if (dist[next_state] <= *next_cost) {
        continue;
      }
      dist[next_state] = *next_cost;
      queue.push(QueueEntry{*next_cost, hops + 1, candidate.to});
      if (!SpendPush()) {
        outcome.resource_limit = true;
        return outcome;
      }
    }
  }

  CostValue best_cost = CostValue::Max();
  std::uint32_t best_hops = kInfiniteHops;
  for (std::uint32_t hops = 0; hops <= hop_budget; ++hops) {
    const CostValue value = dist[index_of(hops, dest)];
    if (value == CostValue::Max()) {
      continue;
    }
    if (value < best_cost || (value == best_cost && hops < best_hops)) {
      best_cost = value;
      best_hops = hops;
    }
  }
  if (best_hops == kInfiniteHops) {
    return outcome;
  }

  std::vector<std::uint8_t> can_reach(states, 0);
  can_reach[index_of(best_hops, dest)] = 1;
  for (std::uint32_t level = best_hops; level > 0; --level) {
    const std::uint32_t hops = level - 1;
    for (std::uint32_t node = 0; node < node_count; ++node) {
      const CostValue base = dist[index_of(hops, node)];
      if (base == CostValue::Max()) {
        continue;
      }
      bool reachable = false;
      for (std::uint32_t adjacency_index = AdjacencyBegin(view_, node);
           adjacency_index < AdjacencyEnd(view_, node); ++adjacency_index) {
        if (bans.AdjacencyBanned(adjacency_index)) {
          continue;
        }
        const Adjacency& candidate = view_.adjacency[adjacency_index];
        if (bans.NodeBanned(candidate.to)) {
          continue;
        }
        const std::size_t next_state = index_of(hops + 1, candidate.to);
        if (can_reach[next_state] == 0) {
          continue;
        }
        const std::optional<CostValue> increment = HopIncrement(view_, candidate);
        if (!increment.has_value()) {
          continue;
        }
        const std::optional<CostValue> next_cost = CheckedAdd(base, *increment);
        if (!next_cost.has_value() || *next_cost != dist[next_state]) {
          continue;
        }
        reachable = true;
        break;
      }
      can_reach[index_of(hops, node)] = reachable ? 1 : 0;
    }
  }

  RawPath path;
  path.nodes.push_back(source);
  std::uint32_t current = source;
  std::uint32_t hops = 0;
  while (current != dest || hops != best_hops) {
    bool advanced = false;
    for (std::uint32_t adjacency_index = AdjacencyBegin(view_, current);
         adjacency_index < AdjacencyEnd(view_, current); ++adjacency_index) {
      if (bans.AdjacencyBanned(adjacency_index)) {
        continue;
      }
      const Adjacency& candidate = view_.adjacency[adjacency_index];
      if (bans.NodeBanned(candidate.to)) {
        continue;
      }
      const std::size_t next_state = index_of(hops + 1, candidate.to);
      if (can_reach[next_state] == 0) {
        continue;
      }
      const std::optional<CostValue> increment = HopIncrement(view_, candidate);
      if (!increment.has_value()) {
        continue;
      }
      const std::optional<CostValue> next_cost = CheckedAdd(dist[index_of(hops, current)], *increment);
      if (!next_cost.has_value() || *next_cost != dist[next_state]) {
        continue;
      }
      path.nodes.push_back(candidate.to);
      path.adjacency.push_back(adjacency_index);
      current = candidate.to;
      hops += 1;
      advanced = true;
      break;
    }
    if (!advanced) {
      return outcome;
    }
  }
  outcome.found = true;
  outcome.path = std::move(path);
  return outcome;
}

namespace {

bool RawPathIsSimple(const RawPath& path) {
  std::vector<std::uint32_t> sorted(path.nodes.begin(), path.nodes.end());
  std::sort(sorted.begin(), sorted.end());
  return std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end();
}

bool ContainsRawPath(const std::vector<RankedRawPath>& paths, const RawPath& candidate) {
  for (const RankedRawPath& entry : paths) {
    if (SameRawPath(entry.path, candidate)) {
      return true;
    }
  }
  return false;
}

}  // namespace

EnumerationResult EnumerateCandidatePaths(const PlanningView& view, const PlanningRequest& request,
                                          const EnumerationOptions& options, WorkBudget& budget,
                                          PlannerStatistics& stats) {
  EnumerationResult result;
  Searcher searcher(view, budget, stats);
  const std::vector<TransitStage>& stages = request.constraints.required_transit;

  // -------------------------------------------------------------------------
  // Required transit: staged legs over an ordered waypoint sequence.
  //
  // Documented semantics: each stage is satisfied in order; each leg is the
  // canonical-minimum path in the eligible graph with the nodes already used by
  // earlier legs excluded. Every alternative combination is evaluated (bounded by
  // max_transit_combinations) and the canonical-minimum result is returned, so the
  // outcome does not depend on enumeration order.
  // -------------------------------------------------------------------------
  if (!stages.empty()) {
    if (options.max_candidates > 1) {
      result.failure = DiagnosticCode::kUnsupportedRequest;
      result.detail =
          "K > 1 with required transit stages is not supported: staged legs have no proven K-shortest semantics";
      return result;
    }
    std::uint64_t combinations = 1;
    std::uint64_t alternatives = 0;
    for (const TransitStage& stage : stages) {
      if (stage.alternatives.empty()) {
        result.failure = DiagnosticCode::kMalformedIdentifier;
        result.detail = "transit stage has no alternatives";
        return result;
      }
      alternatives += static_cast<std::uint64_t>(stage.alternatives.size());
      if (stage.alternatives.size() != 0 &&
          combinations > static_cast<std::uint64_t>(view.limits.max_transit_combinations) / stage.alternatives.size()) {
        result.resource_limit = true;
        result.failure = DiagnosticCode::kConstraintCountExceeded;
        result.detail = "required transit expands beyond the configured combination limit";
        return result;
      }
      combinations *= static_cast<std::uint64_t>(stage.alternatives.size());
    }
    if (alternatives > static_cast<std::uint64_t>(view.limits.max_transit_alternatives)) {
      result.resource_limit = true;
      result.failure = DiagnosticCode::kConstraintCountExceeded;
      result.detail = "required transit alternative count exceeds the configured limit";
      return result;
    }
    if (combinations > static_cast<std::uint64_t>(view.limits.max_transit_combinations)) {
      result.resource_limit = true;
      result.failure = DiagnosticCode::kConstraintCountExceeded;
      result.detail = "required transit combination count exceeds the configured limit";
      return result;
    }

    std::optional<RankedRawPath> best;
    DiagnosticCode leg_failure = DiagnosticCode::kRequiredNodeMissing;
    for (std::uint64_t combination = 0; combination < combinations; ++combination) {
      std::vector<std::size_t> selection(stages.size(), 0);
      std::uint64_t remainder = combination;
      for (std::size_t index = stages.size(); index-- > 0;) {
        const std::size_t size = stages[index].alternatives.size();
        selection[index] = static_cast<std::size_t>(remainder % size);
        remainder /= size;
      }

      RawPath combined;
      combined.nodes.push_back(options.source_view);
      std::uint32_t current = options.source_view;
      std::uint32_t used_hops = 0;
      bool combination_ok = true;
      for (std::size_t stage_index = 0; stage_index < stages.size() && combination_ok; ++stage_index) {
        const TransitStage& stage = stages[stage_index];
        const std::uint32_t target_view = view.ViewIndex(stage.alternatives[selection[stage_index]]);
        if (target_view == kInvalidIndex) {
          combination_ok = false;
          leg_failure = DiagnosticCode::kRequiredNodeMissing;
          break;
        }
        if (options.max_hops != kNoHopBound && used_hops >= options.max_hops) {
          combination_ok = false;
          leg_failure = DiagnosticCode::kMaxHopsExceeded;
          break;
        }
        BanSet bans;
        for (const std::uint32_t node : combined.nodes) {
          if (node != current) {
            bans.AddNode(node);
          }
        }
        const std::uint32_t leg_budget =
            options.max_hops == kNoHopBound ? kNoHopBound : options.max_hops - used_hops;
        const SearchOutcome leg = searcher.ShortestPath(current, target_view, leg_budget, bans);
        if (leg.resource_limit) {
          result.resource_limit = true;
          result.failure = DiagnosticCode::kWorkBudgetExhausted;
          result.detail = "work budget exhausted during a required transit leg";
          return result;
        }
        if (!leg.found) {
          combination_ok = false;
          leg_failure = stage.kind == TransitKind::kExact ? DiagnosticCode::kRequiredNodeMissing
                                                          : DiagnosticCode::kRequiredAnySetUnsatisfied;
          break;
        }
        combined.nodes.insert(combined.nodes.end(), leg.path.nodes.begin() + 1, leg.path.nodes.end());
        combined.adjacency.insert(combined.adjacency.end(), leg.path.adjacency.begin(),
                                  leg.path.adjacency.end());
        used_hops += static_cast<std::uint32_t>(leg.path.HopCount());
        current = target_view;
      }
      if (!combination_ok) {
        continue;
      }
      if (options.max_hops != kNoHopBound && used_hops >= options.max_hops &&
          current != options.destination_view) {
        leg_failure = DiagnosticCode::kMaxHopsExceeded;
        continue;
      }
      BanSet final_bans;
      for (const std::uint32_t node : combined.nodes) {
        if (node != current && node != options.destination_view) {
          final_bans.AddNode(node);
        }
      }
      const std::uint32_t final_budget =
          options.max_hops == kNoHopBound ? kNoHopBound : options.max_hops - used_hops;
      const SearchOutcome final_leg =
          searcher.ShortestPath(current, options.destination_view, final_budget, final_bans);
      if (final_leg.resource_limit) {
        result.resource_limit = true;
        result.failure = DiagnosticCode::kWorkBudgetExhausted;
        result.detail = "work budget exhausted during the final transit leg";
        return result;
      }
      if (!final_leg.found) {
        leg_failure = DiagnosticCode::kMaxHopsExceeded;
        continue;
      }
      combined.nodes.insert(combined.nodes.end(), final_leg.path.nodes.begin() + 1, final_leg.path.nodes.end());
      combined.adjacency.insert(combined.adjacency.end(), final_leg.path.adjacency.begin(),
                                final_leg.path.adjacency.end());
      if (!RawPathIsSimple(combined)) {
        continue;
      }
      const std::optional<PathCost> cost = ComputeRawPathCost(view, combined);
      if (!cost.has_value()) {
        leg_failure = DiagnosticCode::kCostOverflow;
        continue;
      }
      RankedRawPath ranked{std::move(combined), *cost};
      if (!best.has_value() || RankedBefore(view, ranked, *best)) {
        best = std::move(ranked);
      }
    }

    if (!best.has_value()) {
      result.failure = leg_failure;
      result.detail = "no staged path satisfies the ordered transit requirement";
      return result;
    }
    result.ok = true;
    result.paths.push_back(std::move(best->path));
    return result;
  }

  // -------------------------------------------------------------------------
  // Unconstrained enumeration (Yen over the eligible view).
  // -------------------------------------------------------------------------
  const std::uint32_t wanted =
      options.enumeration_ceiling > 0 ? options.enumeration_ceiling : options.max_candidates;
  BanSet no_bans;
  SearchOutcome first =
      searcher.ShortestPath(options.source_view, options.destination_view, options.max_hops, no_bans);
  if (first.resource_limit) {
    result.resource_limit = true;
    result.failure = DiagnosticCode::kWorkBudgetExhausted;
    return result;
  }
  if (!first.found) {
    result.failure = first.cost_overflow ? DiagnosticCode::kCostOverflow : DiagnosticCode::kNoStructuralPath;
    return result;
  }
  const std::optional<PathCost> first_cost = ComputeRawPathCost(view, first.path);
  if (!first_cost.has_value()) {
    result.failure = DiagnosticCode::kCostOverflow;
    return result;
  }

  std::vector<RankedRawPath> accepted;
  accepted.push_back(RankedRawPath{std::move(first.path), *first_cost});
  std::vector<RankedRawPath> pending;

  while (accepted.size() < wanted) {
    const RankedRawPath previous = accepted.back();
    const std::size_t hop_count = previous.path.HopCount();
    for (std::size_t spur_index = 0; spur_index < hop_count; ++spur_index) {
      const std::uint32_t spur_node = previous.path.nodes[spur_index];
      BanSet bans;
      for (std::size_t index = 0; index < spur_index; ++index) {
        bans.AddNode(previous.path.nodes[index]);
      }
      for (const RankedRawPath& candidate : accepted) {
        if (candidate.path.nodes.size() > spur_index + 1 &&
            std::equal(previous.path.nodes.begin(),
                       previous.path.nodes.begin() + static_cast<std::ptrdiff_t>(spur_index) + 1,
                       candidate.path.nodes.begin())) {
          bans.AddAdjacency(candidate.path.adjacency[spur_index]);
        }
      }
      if (budget.spur_remaining == 0) {
        budget.exhausted = true;
        result.resource_limit = true;
        result.failure = DiagnosticCode::kWorkBudgetExhausted;
        result.detail = "spur search budget exhausted";
        return result;
      }
      budget.spur_remaining -= 1;
      stats.spur_searches += 1;
      const std::uint32_t spur_budget =
          options.max_hops == kNoHopBound ? kNoHopBound
                                          : options.max_hops - static_cast<std::uint32_t>(spur_index);
      const SearchOutcome spur =
          searcher.ShortestPath(spur_node, options.destination_view, spur_budget, bans);
      if (spur.resource_limit) {
        result.resource_limit = true;
        result.failure = DiagnosticCode::kWorkBudgetExhausted;
        result.detail = "work budget exhausted during a spur search";
        return result;
      }
      if (!spur.found) {
        continue;
      }
      RawPath total;
      total.nodes.assign(previous.path.nodes.begin(),
                         previous.path.nodes.begin() + static_cast<std::ptrdiff_t>(spur_index) + 1);
      total.adjacency.assign(previous.path.adjacency.begin(),
                             previous.path.adjacency.begin() + static_cast<std::ptrdiff_t>(spur_index));
      total.nodes.insert(total.nodes.end(), spur.path.nodes.begin() + 1, spur.path.nodes.end());
      total.adjacency.insert(total.adjacency.end(), spur.path.adjacency.begin(), spur.path.adjacency.end());
      if (!RawPathIsSimple(total)) {
        continue;
      }
      if (ContainsRawPath(accepted, total) || ContainsRawPath(pending, total)) {
        continue;
      }
      const std::optional<PathCost> cost = ComputeRawPathCost(view, total);
      if (!cost.has_value()) {
        continue;
      }
      pending.push_back(RankedRawPath{std::move(total), *cost});
    }
    if (pending.empty()) {
      break;
    }
    std::size_t best_index = 0;
    for (std::size_t index = 1; index < pending.size(); ++index) {
      if (RankedBefore(view, pending[index], pending[best_index])) {
        best_index = index;
      }
    }
    accepted.push_back(std::move(pending[best_index]));
    pending.erase(pending.begin() + static_cast<std::ptrdiff_t>(best_index));
  }

  const bool hit_ceiling = accepted.size() >= wanted;

  if (options.domain_member_limit_active && request.constraints.max_members_per_failure_domain.has_value()) {
    std::vector<RankedRawPath> compliant;
    for (RankedRawPath& entry : accepted) {
      if (DomainMemberLimitCompliant(view, entry.path, *request.constraints.max_members_per_failure_domain,
                                     request.constraints.fail_closed_on_unknown_domains)) {
        compliant.push_back(std::move(entry));
      }
      if (compliant.size() >= options.max_candidates) {
        break;
      }
    }
    accepted = std::move(compliant);
    if (accepted.size() < options.max_candidates && hit_ceiling) {
      result.truncated = true;
    }
  }

  if (accepted.size() > options.max_candidates) {
    accepted.resize(options.max_candidates);
  }
  result.paths.reserve(accepted.size());
  for (RankedRawPath& entry : accepted) {
    result.paths.push_back(std::move(entry.path));
  }
  result.ok = !result.paths.empty();
  if (!result.ok) {
    result.failure = DiagnosticCode::kNoStructuralPath;
  }
  return result;
}

}  // namespace summon::pathplanner::internal


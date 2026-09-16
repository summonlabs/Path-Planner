#include "pathplanner/store.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include "pathplanner/version.hpp"

namespace summon::pathplanner {
namespace {

StoreResult Failure(DiagnosticCode code, std::string detail) {
  StoreResult result;
  result.ok = false;
  result.code = code;
  result.detail = std::move(detail);
  return result;
}

StoreResult Success() {
  StoreResult result;
  result.ok = true;
  result.code = DiagnosticCode::kPersistenceCorrupt;
  result.detail.clear();
  return result;
}

void WriteId(ByteWriter& writer, const auto& id) { writer.FixedBytes(id.Span()); }

bool ReadId(ByteReader& reader, auto& id, std::string& detail, const char* name) {
  std::array<std::byte, std::remove_reference_t<decltype(id)>::kByteCount> bytes{};
  if (!reader.FixedBytes(std::span<std::byte>(bytes.data(), bytes.size()))) {
    detail = std::string(name) + " is truncated";
    return false;
  }
  using IdType = std::remove_reference_t<decltype(id)>;
  id = IdType::FromBytes(bytes);
  if (!id.IsValid()) {
    detail = std::string(name) + " is nil";
    return false;
  }
  return true;
}

bool ReadStrong(ByteReader& reader, auto& value, std::string& detail, const char* name) {
  const std::optional<std::uint64_t> raw = reader.U64();
  if (!raw.has_value()) {
    detail = std::string(name) + " is truncated";
    return false;
  }
  using ValueType = std::remove_reference_t<decltype(value)>;
  const std::optional<ValueType> typed = ValueType::TryFrom(*raw);
  if (!typed.has_value()) {
    detail = std::string(name) + " is out of range";
    return false;
  }
  value = *typed;
  return true;
}

bool ReadEnumValue(ByteReader& reader, const EnumEntry* table, std::size_t count, std::uint32_t& out,
                   std::string& detail, const char* name) {
  const std::optional<std::uint32_t> raw = reader.U32();
  if (!raw.has_value()) {
    detail = std::string(name) + " is truncated";
    return false;
  }
  if (detail::EnumNameFromValue(table, count, *raw).empty()) {
    detail = std::string(name) + " has an unknown enumeration value " + std::to_string(*raw);
    return false;
  }
  out = *raw;
  return true;
}

void WriteGenerations(ByteWriter& writer, const SnapshotGenerations& generations) { generations.Encode(writer); }

bool ReadGenerations(ByteReader& reader, SnapshotGenerations& generations, std::string& detail) {
  return ReadStrong(reader, generations.topology, detail, "topology generation") &&
         ReadStrong(reader, generations.link_state, detail, "link-state generation") &&
         ReadStrong(reader, generations.ports, detail, "port generation") &&
         ReadStrong(reader, generations.capabilities, detail, "capability generation") &&
         ReadStrong(reader, generations.failure_domains, detail, "failure-domain generation") &&
         ReadStrong(reader, generations.epoch, detail, "fabric epoch") &&
         ReadStrong(reader, generations.policy, detail, "policy generation") &&
         ReadStrong(reader, generations.constraints, detail, "constraint generation");
}

bool ReadEvidence(ByteReader& reader, EvidenceVector& evidence, std::string& detail) {
  if (!ReadId(reader, evidence.snapshot, detail, "snapshot identity")) {
    return false;
  }
  if (!ReadGenerations(reader, evidence.generations, detail)) {
    return false;
  }
  std::uint32_t source = 0;
  if (!ReadEnumValue(reader, kEvidenceSourceNames, std::size(kEvidenceSourceNames), source, detail,
                     "evidence source")) {
    return false;
  }
  evidence.source = static_cast<EvidenceSource>(source);
  return ReadStrong(reader, evidence.publish_sequence, detail, "publish sequence");
}

void WritePath(ByteWriter& writer, const CandidatePath& path) { path.Encode(writer); }

bool ReadPath(ByteReader& reader, const ResourceLimits& limits, CandidatePath& path, std::string& detail) {
  const std::optional<std::uint32_t> encoding_version = reader.U32();
  if (!encoding_version.has_value() || *encoding_version != kPathEncodingVersion) {
    detail = "path encoding version is unsupported";
    return false;
  }
  if (!ReadId(reader, path.source, detail, "path source") ||
      !ReadId(reader, path.destination, detail, "path destination")) {
    return false;
  }
  std::uint32_t layer = 0;
  if (!ReadEnumValue(reader, kPathLayerNames, std::size(kPathLayerNames), layer, detail, "path layer")) {
    return false;
  }
  path.layer = static_cast<PathLayer>(layer);
  const std::optional<std::uint64_t> hop_count = reader.VarU64();
  if (!hop_count.has_value() || *hop_count > static_cast<std::uint64_t>(limits.max_hops)) {
    detail = "path hop count exceeds the configured limit";
    return false;
  }
  path.hops.clear();
  path.hops.reserve(static_cast<std::size_t>(*hop_count));
  for (std::uint64_t index = 0; index < *hop_count; ++index) {
    PathHop hop;
    if (!ReadId(reader, hop.link, detail, "hop link") || !ReadId(reader, hop.from, detail, "hop source node") ||
        !ReadId(reader, hop.to, detail, "hop destination node") ||
        !ReadId(reader, hop.from_port, detail, "hop source port") ||
        !ReadId(reader, hop.to_port, detail, "hop destination port")) {
      return false;
    }
    std::uint32_t hop_layer = 0;
    std::uint32_t relationship = 0;
    if (!ReadEnumValue(reader, kPathLayerNames, std::size(kPathLayerNames), hop_layer, detail, "hop layer") ||
        !ReadEnumValue(reader, kRelationshipTypeNames, std::size(kRelationshipTypeNames), relationship, detail,
                       "hop relationship")) {
      return false;
    }
    hop.layer = static_cast<PathLayer>(hop_layer);
    hop.relationship = static_cast<RelationshipType>(relationship);
    if (!ReadStrong(reader, hop.structural_generation, detail, "hop structural generation")) {
      return false;
    }
    const std::optional<std::uint32_t> static_cost = reader.U32();
    if (!static_cost.has_value()) {
      detail = "hop static cost is truncated";
      return false;
    }
    hop.static_cost = StaticCost(*static_cost);
    hop.link_state = LinkState::kUnknown;
    path.hops.push_back(hop);
  }
  path.nodes.assign(path.hops.size() + 1, NodeId{});
  path.nodes.front() = path.source;
  for (std::size_t index = 0; index < path.hops.size(); ++index) {
    path.nodes[index + 1] = path.hops[index].to;
  }
  if (!path.IsWellFormed()) {
    detail = "decoded path is not well formed";
    return false;
  }
  if (!path.IsSimple()) {
    detail = "decoded path is not simple";
    return false;
  }
  return true;
}

void WriteCost(ByteWriter& writer, const PathCost& cost) {
  writer.U64(cost.total.Value());
  writer.U64(cost.hops_cost.Value());
  writer.U64(cost.static_cost.Value());
  writer.U64(cost.degraded_penalty.Value());
  writer.U64(cost.locality_penalty.Value());
  writer.U32(cost.hops.Value());
  writer.U32(cost.degraded_hops);
  writer.U32(cost.locality_breaches);
}

bool ReadCost(ByteReader& reader, PathCost& cost, std::string& detail) {
  const std::optional<std::uint64_t> total = reader.U64();
  const std::optional<std::uint64_t> hops_cost = reader.U64();
  const std::optional<std::uint64_t> static_cost = reader.U64();
  const std::optional<std::uint64_t> degraded = reader.U64();
  const std::optional<std::uint64_t> locality = reader.U64();
  const std::optional<std::uint32_t> hops = reader.U32();
  const std::optional<std::uint32_t> degraded_hops = reader.U32();
  const std::optional<std::uint32_t> locality_breaches = reader.U32();
  if (!total.has_value() || !hops_cost.has_value() || !static_cost.has_value() || !degraded.has_value() ||
      !locality.has_value() || !hops.has_value() || !degraded_hops.has_value() || !locality_breaches.has_value()) {
    detail = "path cost is truncated";
    return false;
  }
  const std::optional<HopCount> typed_hops = HopCount::TryFrom(*hops);
  if (!typed_hops.has_value()) {
    detail = "path cost hop count is out of range";
    return false;
  }
  cost.total = CostValue(*total);
  cost.hops_cost = CostValue(*hops_cost);
  cost.static_cost = CostValue(*static_cost);
  cost.degraded_penalty = CostValue(*degraded);
  cost.locality_penalty = CostValue(*locality);
  cost.hops = *typed_hops;
  cost.degraded_hops = *degraded_hops;
  cost.locality_breaches = *locality_breaches;
  std::optional<CostValue> accumulated = CheckedAdd(cost.hops_cost, cost.static_cost);
  if (accumulated.has_value()) {
    accumulated = CheckedAdd(*accumulated, cost.degraded_penalty);
  }
  if (accumulated.has_value()) {
    accumulated = CheckedAdd(*accumulated, cost.locality_penalty);
  }
  if (!accumulated.has_value() || *accumulated != cost.total) {
    detail = "path cost does not equal the sum of its components";
    return false;
  }
  if (cost.degraded_hops > cost.hops.Value() || cost.locality_breaches > cost.hops.Value()) {
    detail = "path cost penalty counts exceed the hop count";
    return false;
  }
  return true;
}

std::string TempPathFor(const std::string& path) { return path + ".tmp"; }

bool ReplaceFile(const std::string& temporary, const std::string& destination, std::string& detail) {
#ifdef _WIN32
  const int wide_length = MultiByteToWideChar(CP_UTF8, 0, destination.c_str(), -1, nullptr, 0);
  const int wide_temp_length = MultiByteToWideChar(CP_UTF8, 0, temporary.c_str(), -1, nullptr, 0);
  if (wide_length <= 0 || wide_temp_length <= 0) {
    detail = "cannot convert the store path to UTF-16";
    return false;
  }
  std::wstring wide_destination(static_cast<std::size_t>(wide_length), L'\0');
  std::wstring wide_temporary(static_cast<std::size_t>(wide_temp_length), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, destination.c_str(), -1, wide_destination.data(), wide_length);
  MultiByteToWideChar(CP_UTF8, 0, temporary.c_str(), -1, wide_temporary.data(), wide_temp_length);
  if (MoveFileExW(wide_temporary.c_str(), wide_destination.c_str(),
                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    detail = "atomic replacement failed with error " + std::to_string(GetLastError());
    return false;
  }
  return true;
#else
  if (std::rename(temporary.c_str(), destination.c_str()) != 0) {
    detail = "atomic replacement failed";
    return false;
  }
  return true;
#endif
}

}  // namespace

StoredPlanRecord ToStoredRecord(const PathPlan& plan) {
  StoredPlanRecord record;
  record.request = plan.request;
  record.plan = plan.id;
  record.generation = plan.generation;
  record.publish_sequence = plan.publish_sequence;
  record.status = plan.status;
  record.evidence = plan.evidence;
  record.constraint_set = plan.constraint_set;
  record.constraint_generation = plan.constraint_generation;
  record.policy_generation = plan.policy_generation;
  record.source = plan.source;
  record.destination = plan.destination;
  record.layer = plan.layer;
  record.diagnostic_mode = plan.diagnostic_mode;
  record.semantic_digest = plan.semantic_digest;
  for (const Candidate& candidate : plan.candidates) {
    record.candidates.push_back(candidate.path);
    record.costs.push_back(candidate.cost);
    record.ranks.push_back(candidate.rank);
  }
  return record;
}

PathPlan FromStoredRecord(const StoredPlanRecord& record) {
  PathPlan plan;
  plan.request = record.request;
  plan.id = record.plan;
  plan.generation = record.generation;
  plan.publish_sequence = record.publish_sequence;
  plan.status = record.status;
  plan.evidence = record.evidence;
  plan.policy_generation = record.policy_generation;
  plan.constraint_set = record.constraint_set;
  plan.constraint_generation = record.constraint_generation;
  plan.source = record.source;
  plan.destination = record.destination;
  plan.layer = record.layer;
  plan.diagnostic_mode = record.diagnostic_mode;
  // A recovered record is never current fabric truth.
  plan.currentness_proven = false;
  plan.semantic_digest = record.semantic_digest;
  const std::size_t count = std::min(record.candidates.size(), record.costs.size());
  for (std::size_t index = 0; index < count; ++index) {
    Candidate candidate;
    candidate.path = record.candidates[index];
    candidate.id = candidate.path.Id();
    candidate.cost = record.costs[index];
    candidate.rank = index < record.ranks.size() ? record.ranks[index]
                                                  : CandidateRank(static_cast<std::uint32_t>(index) + 1);
    candidate.evidence = record.evidence;
    candidate.currentness = Currentness::kRevalidationRequired;
    candidate.authority = AuthorityValidation::kNotRequested;
    plan.candidates.push_back(std::move(candidate));
  }
  return plan;
}

StoreResult EncodePlanStore(const std::vector<StoredPlanRecord>& records, const StoreOptions& options,
                            std::vector<std::byte>& out) {
  if (const std::optional<DiagnosticCode> limits_error = ValidateLimits(options.limits);
      limits_error.has_value()) {
    return Failure(*limits_error, "resource limits are incoherent");
  }
  if (records.size() > static_cast<std::size_t>(options.limits.max_persisted_plans)) {
    return Failure(DiagnosticCode::kPersistenceLimitExceeded, "record count exceeds the configured ceiling");
  }
  ByteWriter payload(options.limits.max_frame_bytes * 16u);
  payload.U64(options.publish_sequence.Value());
  payload.VarU64(records.size());
  for (const StoredPlanRecord& record : records) {
    if (!record.plan.IsValid() || !record.request.IsValid()) {
      return Failure(DiagnosticCode::kMalformedIdentifier, "record carries a nil identity");
    }
    if (record.candidates.size() != record.costs.size()) {
      return Failure(DiagnosticCode::kPersistenceCorrupt, "candidate and cost counts disagree");
    }
    if (record.candidates.size() > static_cast<std::size_t>(options.limits.max_candidates_per_request)) {
      return Failure(DiagnosticCode::kPersistenceLimitExceeded, "candidate count exceeds the configured ceiling");
    }
    WriteId(payload, record.request);
    WriteId(payload, record.plan);
    payload.U64(record.generation.Value());
    payload.U64(record.publish_sequence.Value());
    payload.U32(static_cast<std::uint32_t>(record.status));
    WriteId(payload, record.constraint_set);
    payload.U64(record.constraint_generation.Value());
    payload.U64(record.policy_generation.Value());
    WriteId(payload, record.source);
    WriteId(payload, record.destination);
    payload.U32(static_cast<std::uint32_t>(record.layer));
    payload.Bool(record.diagnostic_mode);
    WriteId(payload, record.evidence.snapshot);
    WriteGenerations(payload, record.evidence.generations);
    payload.U32(static_cast<std::uint32_t>(record.evidence.source));
    payload.U64(record.evidence.publish_sequence.Value());
    payload.FixedBytes(std::span<const std::byte>(record.semantic_digest.bytes.data(),
                                                  record.semantic_digest.bytes.size()));
    payload.VarU64(record.candidates.size());
    for (std::size_t index = 0; index < record.candidates.size(); ++index) {
      WritePath(payload, record.candidates[index]);
      WriteCost(payload, record.costs[index]);
      const CandidateRank rank = index < record.ranks.size()
                                     ? record.ranks[index]
                                     : CandidateRank(static_cast<std::uint32_t>(index) + 1);
      payload.U32(rank.Value());
    }
  }
  if (payload.overflowed()) {
    return Failure(DiagnosticCode::kPersistenceLimitExceeded, "store payload exceeded its ceiling");
  }

  ByteWriter header(kStoreHeaderBytes);
  header.FixedBytes(std::span<const std::byte>(reinterpret_cast<const std::byte*>(kStoreMagic.data()),
                                               kStoreMagic.size()));
  header.U32(kPersistedFormatVersion);
  header.U32(kPlanningRuleVersion);
  header.U32(kPathEncodingVersion);
  header.U64(records.size());
  header.U64(payload.size());
  if (header.overflowed()) {
    return Failure(DiagnosticCode::kPersistenceCorrupt, "store header encoding failed");
  }
  Sha256 hasher;
  hasher.Update(header.span());
  hasher.Update(payload.span());
  const Sha256Digest digest = hasher.Finish();

  out.clear();
  out.reserve(kStoreHeaderBytes + kStoreDigestBytes + payload.size());
  out.insert(out.end(), header.data().begin(), header.data().end());
  out.insert(out.end(), digest.bytes.begin(), digest.bytes.end());
  out.insert(out.end(), payload.data().begin(), payload.data().end());
  return Success();
}

StoreResult DecodePlanStore(std::span<const std::byte> image, const ResourceLimits& limits,
                            std::vector<StoredPlanRecord>& out) {
  if (image.size() < kStoreHeaderBytes + kStoreDigestBytes) {
    return Failure(DiagnosticCode::kPersistenceCorrupt, "store image is shorter than its header");
  }
  ByteReader header(image.subspan(0, kStoreHeaderBytes));
  std::array<std::byte, 8> magic{};
  if (!header.FixedBytes(std::span<std::byte>(magic.data(), magic.size()))) {
    return Failure(DiagnosticCode::kPersistenceCorrupt, "store magic is truncated");
  }
  if (std::string_view(reinterpret_cast<const char*>(magic.data()), magic.size()) != kStoreMagic) {
    return Failure(DiagnosticCode::kPersistenceCorrupt, "store magic mismatch");
  }
  const std::optional<std::uint32_t> format_version = header.U32();
  const std::optional<std::uint32_t> rule_version = header.U32();
  const std::optional<std::uint32_t> encoding_version = header.U32();
  const std::optional<std::uint64_t> record_count = header.U64();
  const std::optional<std::uint64_t> payload_length = header.U64();
  if (!format_version.has_value() || !rule_version.has_value() || !encoding_version.has_value() ||
      !record_count.has_value() || !payload_length.has_value()) {
    return Failure(DiagnosticCode::kPersistenceCorrupt, "store header is truncated");
  }
  if (*format_version != kPersistedFormatVersion) {
    return Failure(DiagnosticCode::kPersistenceVersionUnsupported, "unsupported persisted format version");
  }
  if (*rule_version != kPlanningRuleVersion || *encoding_version != kPathEncodingVersion) {
    return Failure(DiagnosticCode::kPersistenceVersionUnsupported,
                   "stored planning-rule or path-encoding version is unsupported");
  }
  if (*record_count > static_cast<std::uint64_t>(limits.max_persisted_plans)) {
    return Failure(DiagnosticCode::kPersistenceLimitExceeded, "stored record count exceeds the configured ceiling");
  }
  const std::size_t expected_size =
      kStoreHeaderBytes + kStoreDigestBytes + static_cast<std::size_t>(*payload_length);
  if (image.size() < expected_size) {
    return Failure(DiagnosticCode::kPersistenceCorrupt, "store image is truncated");
  }
  if (image.size() > expected_size) {
    return Failure(DiagnosticCode::kPersistenceTrailingBytes, "store image carries trailing bytes");
  }
  Sha256 hasher;
  hasher.Update(image.subspan(0, kStoreHeaderBytes));
  hasher.Update(image.subspan(kStoreHeaderBytes + kStoreDigestBytes, static_cast<std::size_t>(*payload_length)));
  const Sha256Digest expected = hasher.Finish();
  for (std::size_t index = 0; index < kStoreDigestBytes; ++index) {
    if (image[kStoreHeaderBytes + index] != expected.bytes[index]) {
      return Failure(DiagnosticCode::kPersistenceDigestMismatch, "store integrity digest mismatch");
    }
  }

  ByteReader reader(image.subspan(kStoreHeaderBytes + kStoreDigestBytes, static_cast<std::size_t>(*payload_length)));
  const std::optional<std::uint64_t> publish_sequence = reader.U64();
  const std::optional<std::uint64_t> stored_count = reader.VarU64();
  if (!publish_sequence.has_value() || !stored_count.has_value() || *stored_count != *record_count) {
    return Failure(DiagnosticCode::kPersistenceCorrupt, "store payload header disagrees with the store header");
  }

  std::vector<StoredPlanRecord> records;
  records.reserve(static_cast<std::size_t>(*record_count));
  std::vector<PathPlanId> seen_plans;
  std::string detail;
  for (std::uint64_t index = 0; index < *record_count; ++index) {
    StoredPlanRecord record;
    if (!ReadId(reader, record.request, detail, "request identity") ||
        !ReadId(reader, record.plan, detail, "plan identity") ||
        !ReadStrong(reader, record.generation, detail, "planning generation") ||
        !ReadStrong(reader, record.publish_sequence, detail, "publish sequence")) {
      return Failure(DiagnosticCode::kPersistenceCorrupt, detail);
    }
    std::uint32_t status = 0;
    if (!ReadEnumValue(reader, kPlanStatusNames, std::size(kPlanStatusNames), status, detail, "plan status")) {
      return Failure(DiagnosticCode::kPersistenceCorrupt, detail);
    }
    record.status = static_cast<PlanStatus>(status);
    if (!ReadId(reader, record.constraint_set, detail, "constraint set identity") ||
        !ReadStrong(reader, record.constraint_generation, detail, "constraint generation") ||
        !ReadStrong(reader, record.policy_generation, detail, "policy generation") ||
        !ReadId(reader, record.source, detail, "source node") ||
        !ReadId(reader, record.destination, detail, "destination node")) {
      return Failure(DiagnosticCode::kPersistenceCorrupt, detail);
    }
    std::uint32_t layer = 0;
    if (!ReadEnumValue(reader, kPathLayerNames, std::size(kPathLayerNames), layer, detail, "plan layer")) {
      return Failure(DiagnosticCode::kPersistenceCorrupt, detail);
    }
    record.layer = static_cast<PathLayer>(layer);
    const std::optional<bool> diagnostic_mode = reader.Bool();
    if (!diagnostic_mode.has_value()) {
      return Failure(DiagnosticCode::kPersistenceCorrupt, "diagnostic-mode flag is truncated");
    }
    record.diagnostic_mode = *diagnostic_mode;
    if (!ReadEvidence(reader, record.evidence, detail)) {
      return Failure(DiagnosticCode::kPersistenceCorrupt, detail);
    }
    if (!reader.FixedBytes(std::span<std::byte>(record.semantic_digest.bytes.data(),
                                                 record.semantic_digest.bytes.size()))) {
      return Failure(DiagnosticCode::kPersistenceCorrupt, "semantic digest is truncated");
    }
    const std::optional<std::uint64_t> candidate_count = reader.VarU64();
    if (!candidate_count.has_value() ||
        *candidate_count > static_cast<std::uint64_t>(limits.max_candidates_per_request)) {
      return Failure(DiagnosticCode::kPersistenceLimitExceeded, "candidate count exceeds the configured ceiling");
    }
    std::vector<CandidatePathId> seen_candidates;
    for (std::uint64_t candidate_index = 0; candidate_index < *candidate_count; ++candidate_index) {
      CandidatePath path;
      if (!ReadPath(reader, limits, path, detail)) {
        return Failure(DiagnosticCode::kPersistenceCorrupt, detail);
      }
      PathCost cost;
      if (!ReadCost(reader, cost, detail)) {
        return Failure(DiagnosticCode::kPersistenceCorrupt, detail);
      }
      const std::optional<std::uint32_t> rank_value = reader.U32();
      const std::optional<CandidateRank> rank =
          rank_value.has_value() ? CandidateRank::TryFrom(*rank_value) : std::nullopt;
      if (!rank.has_value() || rank->Value() != candidate_index + 1) {
        return Failure(DiagnosticCode::kPersistenceCorrupt, "candidate rank is not the expected sequence");
      }
      if (cost.hops.Value() != path.HopCountValue()) {
        return Failure(DiagnosticCode::kPersistenceImpossibleValue,
                       "candidate cost hop count does not match the encoded path");
      }
      for (const PathHop& hop : path.hops) {
        if (hop.structural_generation.Value() > record.evidence.generations.topology.Value()) {
          return Failure(DiagnosticCode::kPersistenceImpossibleValue,
                         "candidate hop structural generation exceeds the stored topology generation");
        }
      }
      const CandidatePathId candidate_id = path.Id();
      if (std::find(seen_candidates.begin(), seen_candidates.end(), candidate_id) != seen_candidates.end()) {
        return Failure(DiagnosticCode::kPersistenceDuplicateCandidate, "duplicate candidate identity in a record");
      }
      seen_candidates.push_back(candidate_id);
      record.candidates.push_back(std::move(path));
      record.costs.push_back(cost);
      record.ranks.push_back(*rank);
    }
    for (std::size_t candidate_index = 1; candidate_index < record.costs.size(); ++candidate_index) {
      if (record.costs[candidate_index].total < record.costs[candidate_index - 1].total) {
        return Failure(DiagnosticCode::kPersistenceCorrupt, "candidate costs are not non-decreasing");
      }
    }
    if (std::find(seen_plans.begin(), seen_plans.end(), record.plan) != seen_plans.end()) {
      return Failure(DiagnosticCode::kPersistenceDuplicatePlan, "duplicate plan identity in the store");
    }
    seen_plans.push_back(record.plan);
    // Recompute the semantic digest of the recovered plan: a record whose digest does
    // not match its content is refused even when the transport digest was intact.
    const PathPlan recovered = FromStoredRecord(record);
    const Sha256Digest recomputed = recovered.ComputeSemanticDigest();
    if (recomputed != record.semantic_digest) {
      return Failure(DiagnosticCode::kPersistenceDigestMismatch,
                     "record semantic digest does not match its content");
    }
    records.push_back(std::move(record));
  }
  if (!reader.AtEnd()) {
    return Failure(DiagnosticCode::kPersistenceTrailingBytes, "store payload carries trailing bytes");
  }
  out = std::move(records);
  return Success();
}

StoreResult SavePlanStore(const std::string& path, const std::vector<StoredPlanRecord>& records,
                          const StoreOptions& options) {
  if (path.empty()) {
    return Failure(DiagnosticCode::kPersistenceCorrupt, "store path is empty");
  }
  std::vector<std::byte> image;
  const StoreResult encoded = EncodePlanStore(records, options, image);
  if (!encoded.ok) {
    return encoded;
  }
  const std::string temporary = TempPathFor(path);
  {
    std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
    if (!stream.is_open()) {
      return Failure(DiagnosticCode::kPersistenceCorrupt, "cannot open the temporary store file");
    }
    stream.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
    stream.flush();
    if (!stream.good()) {
      return Failure(DiagnosticCode::kPersistenceCorrupt, "cannot write the temporary store file");
    }
  }
  std::string detail;
  if (!ReplaceFile(temporary, path, detail)) {
    std::remove(temporary.c_str());
    return Failure(DiagnosticCode::kPersistenceCorrupt, detail);
  }
  return Success();
}

StoreResult LoadPlanStore(const std::string& path, const ResourceLimits& limits,
                          std::vector<StoredPlanRecord>& out) {
  if (path.empty()) {
    return Failure(DiagnosticCode::kPersistenceCorrupt, "store path is empty");
  }
  std::ifstream stream(path, std::ios::binary);
  if (!stream.is_open()) {
    return Failure(DiagnosticCode::kPersistenceCorrupt, "store file not found or not readable");
  }
  std::vector<std::byte> image;
  const std::size_t ceiling = kStoreHeaderBytes + kStoreDigestBytes +
                              static_cast<std::size_t>(limits.max_frame_bytes) * 16u;
  std::array<char, 65536> buffer{};
  while (stream.good()) {
    stream.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const std::streamsize read = stream.gcount();
    if (read <= 0) {
      break;
    }
    if (image.size() + static_cast<std::size_t>(read) > ceiling) {
      return Failure(DiagnosticCode::kPersistenceLimitExceeded, "store image exceeds the configured ceiling");
    }
    for (std::streamsize index = 0; index < read; ++index) {
      image.push_back(std::byte{static_cast<unsigned char>(buffer[static_cast<std::size_t>(index)])});
    }
  }
  return DecodePlanStore(std::span<const std::byte>(image.data(), image.size()), limits, out);
}

}  // namespace summon::pathplanner

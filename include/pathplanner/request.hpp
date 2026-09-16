#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "pathplanner/graph.hpp"
#include "pathplanner/ids.hpp"
#include "pathplanner/limits.hpp"
#include "pathplanner/path.hpp"
#include "pathplanner/status.hpp"

namespace summon::pathplanner {

// ---------------------------------------------------------------------------
// Endpoint reference: canonical Fabric Registry identity plus the exact entity
// generation the caller intends to plan from/to. Resolution is exact; nothing is
// inferred from naming.
// ---------------------------------------------------------------------------
struct EndpointRef {
  EndpointId id;
  EndpointClass endpoint_class = EndpointClass::kEndpoint;
  EntityGeneration generation;
};

// ---------------------------------------------------------------------------
// Capability requirements.
// ---------------------------------------------------------------------------
enum class CapabilityScope : std::uint32_t {
  kEveryNode = 1,
  kEveryLink = 2,
  kEveryPort = 3,
  kSourceNode = 4,
  kDestinationNode = 5,
};

inline constexpr EnumEntry kCapabilityScopeNames[] = {
    {"EVERY_NODE", 1},
    {"EVERY_LINK", 2},
    {"EVERY_PORT", 3},
    {"SOURCE_NODE", 4},
    {"DESTINATION_NODE", 5},
};

inline std::string_view ToString(CapabilityScope value) { return EnumName(kCapabilityScopeNames, value); }
inline std::optional<CapabilityScope> ParseCapabilityScope(std::string_view name) {
  return ParseEnum<CapabilityScope>(kCapabilityScopeNames, name);
}

enum class CapabilityComparator : std::uint32_t {
  kAtLeast = 1,
  kAtMost = 2,
  kEqual = 3,
};

inline constexpr EnumEntry kCapabilityComparatorNames[] = {
    {"AT_LEAST", 1},
    {"AT_MOST", 2},
    {"EQUAL", 3},
};

inline std::string_view ToString(CapabilityComparator value) { return EnumName(kCapabilityComparatorNames, value); }
inline std::optional<CapabilityComparator> ParseCapabilityComparator(std::string_view name) {
  return ParseEnum<CapabilityComparator>(kCapabilityComparatorNames, name);
}

struct CapabilityRequirement {
  CapabilityId capability;
  CapabilityScope scope = CapabilityScope::kEveryLink;
  CapabilityComparator comparator = CapabilityComparator::kAtLeast;
  CapabilityValue value;

  bool SatisfiedBy(CapabilityValue observed) const noexcept;
};

// ---------------------------------------------------------------------------
// Ordered transit requirement.
//
// A stage is either one exact node or a bounded set of alternatives. Stages are
// traversed in order. Required transit never implies a legality claim; it is a
// hard planning requirement.
// ---------------------------------------------------------------------------
enum class TransitKind : std::uint32_t {
  kExact = 1,
  kAnyOf = 2,
};

inline constexpr EnumEntry kTransitKindNames[] = {
    {"EXACT", 1},
    {"ANY_OF", 2},
};

inline std::string_view ToString(TransitKind value) { return EnumName(kTransitKindNames, value); }
inline std::optional<TransitKind> ParseTransitKind(std::string_view name) { return ParseEnum<TransitKind>(kTransitKindNames, name); }

struct TransitStage {
  TransitKind kind = TransitKind::kExact;
  std::vector<NodeId> alternatives;

  NodeId Exact() const noexcept { return alternatives.empty() ? NodeId{} : alternatives.front(); }
};

// ---------------------------------------------------------------------------
// Constraint set: only the bounded primitives Path Planner 1.0.0 implements.
// ---------------------------------------------------------------------------
struct ConstraintSet {
  ConstraintSetId id;
  ConstraintGeneration generation;
  PathLayer layer = PathLayer::kPhysical;

  std::vector<NodeId> forbidden_nodes;
  std::vector<LinkId> forbidden_links;
  std::vector<PortId> forbidden_ports;
  std::vector<FailureDomainId> forbidden_failure_domains;
  std::vector<FailureDomainClass> forbidden_failure_domain_classes;

  std::vector<TransitStage> required_transit;
  std::vector<CapabilityRequirement> required_capabilities;

  std::optional<HopCount> max_hops;
  std::optional<std::uint32_t> max_members_per_failure_domain;
  // When true (default) an entity whose failure-domain membership is not proven
  // fails a domain constraint instead of being assumed compliant.
  bool fail_closed_on_unknown_domains = true;

  std::size_t EntryCount() const noexcept;
  std::size_t TransitAlternativeCount() const noexcept;
};

// ---------------------------------------------------------------------------
// Planning policy: explicit, deterministic planning preferences. Legality is
// never expressed here; only eligibility policy and cost weighting.
// ---------------------------------------------------------------------------
enum class AuthorityValidationMode : std::uint32_t {
  kNone = 1,        // Path Planner makes no legality claim
  kBestEffort = 2,  // ask Path Authority when configured; unavailability is reported
  kRequired = 3,    // every returned candidate must be validated by Path Authority
};

inline constexpr EnumEntry kAuthorityValidationModeNames[] = {
    {"NONE", 1},
    {"BEST_EFFORT", 2},
    {"REQUIRED", 3},
};

inline std::string_view ToString(AuthorityValidationMode value) {
  return EnumName(kAuthorityValidationModeNames, value);
}
inline std::optional<AuthorityValidationMode> ParseAuthorityValidationMode(std::string_view name) {
  return ParseEnum<AuthorityValidationMode>(kAuthorityValidationModeNames, name);
}

struct PlanningPolicy {
  PolicyGeneration generation;
  CostModel cost_model;

  // DEGRADED links are traversable only when explicitly permitted; the cost model
  // then charges model.degraded_penalty per degraded hop.
  bool allow_degraded_links = false;
  // DRAINING / MAINTENANCE ports require explicit policy. In STANDARD mode these
  // flags still yield REVALIDATION_REQUIRED results, never CURRENT.
  bool allow_draining_ports = false;
  bool allow_maintenance_ports = false;
  // When true, a link or port without authoritative operational proof (UNKNOWN) is
  // ineligible. UNKNOWN is never treated as UP.
  bool require_operational_proof = true;
  // source == destination: when true a zero-hop candidate is returned.
  bool allow_zero_hop_self_path = true;

  // Nodes considered local. A hop whose destination leaves this set is charged
  // cost_model.locality_penalty. Empty scope disables the penalty.
  std::vector<NodeId> locality_scope;

  AuthorityValidationMode authority_validation = AuthorityValidationMode::kNone;
};

// ---------------------------------------------------------------------------
// Caller authority. Request authorization is separate from path legality.
// ---------------------------------------------------------------------------
struct CallerAuthority {
  std::uint32_t scope_mask = 0;
  PublisherId publisher;
  WorkerBootId worker_boot;
  CoordinatorEpoch coordinator_epoch;
  MutationAttemptId attempt;
  // When true the coordinator epoch is checked against the runtime epoch.
  bool epoch_bound = false;
  // When true the request is rejected unless it carries kSubmitPlanRequest.
  bool enforce_scope = false;
};

// ---------------------------------------------------------------------------
// Planning request.
// ---------------------------------------------------------------------------
struct PlanningRequest {
  PlanningRequestId id;
  EndpointRef source;
  EndpointRef destination;
  ConstraintSet constraints;
  PlanningPolicy policy;
  std::uint32_t max_candidates = 1;
  PlanningMode mode = PlanningMode::kStandard;
  CallerAuthority authority;

  // Optional explicit currentness expectations. When expect_epoch is set, the
  // request is rejected as EPOCH_STALE unless the captured snapshot matches.
  bool expect_epoch = false;
  FabricEpoch expected_epoch;
  bool expect_topology = false;
  TopologyGeneration expected_topology;
  bool expect_snapshot = false;
  SnapshotId expected_snapshot;
};

// ---------------------------------------------------------------------------
// Request validation. Returns the first structural problem found.
// ---------------------------------------------------------------------------
struct RequestValidation {
  std::optional<DiagnosticCode> code;
  std::string detail;
  bool ok() const noexcept { return !code.has_value(); }
};

RequestValidation ValidateRequest(const PlanningRequest& request, const ResourceLimits& limits);
RequestValidation ValidateConstraintSet(const ConstraintSet& constraints, const ResourceLimits& limits);
RequestValidation ValidatePolicy(const PlanningPolicy& policy, const ResourceLimits& limits);

// Maps a validation diagnostic onto the structured status the planner reports.
PlanStatus StatusForValidationCode(DiagnosticCode code) noexcept;

}  // namespace summon::pathplanner

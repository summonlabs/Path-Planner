#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace summon::pathplanner {

// ---------------------------------------------------------------------------
// Enum plumbing
//
// Every enumeration that crosses a representation boundary (persistence, wire,
// rendering) carries explicit stable numeric values. Ordinal layout is never
// relied upon. Parsing is exact and case-sensitive.
// ---------------------------------------------------------------------------

struct EnumEntry {
  std::string_view name;
  std::uint32_t value;
};

namespace detail {
std::optional<std::uint32_t> EnumValueFromName(const EnumEntry* table, std::size_t count, std::string_view name);
std::string_view EnumNameFromValue(const EnumEntry* table, std::size_t count, std::uint32_t value);
}  // namespace detail

template <class Enum, std::size_t N>
std::optional<Enum> ParseEnum(const EnumEntry (&table)[N], std::string_view name) {
  const std::optional<std::uint32_t> value = detail::EnumValueFromName(table, N, name);
  if (!value.has_value()) {
    return std::nullopt;
  }
  return static_cast<Enum>(*value);
}

// Stable rendering. Unknown numeric values render as "UNKNOWN_VALUE" rather than
// silently matching another entry.
template <class Enum, std::size_t N>
std::string_view EnumName(const EnumEntry (&table)[N], Enum value) {
  const std::string_view name = detail::EnumNameFromValue(table, N, static_cast<std::uint32_t>(value));
  return name.empty() ? std::string_view{"UNKNOWN_VALUE"} : name;
}

template <class Enum, std::size_t N>
bool IsKnownEnumValue(const EnumEntry (&table)[N], std::uint32_t value) {
  return !detail::EnumNameFromValue(table, N, value).empty();
}

// ---------------------------------------------------------------------------
// PlanStatus - the structured outcome of a planning attempt.
// ---------------------------------------------------------------------------
enum class PlanStatus : std::uint32_t {
  kPlanned = 1,
  kNoPath = 2,
  kSourceUnknown = 3,
  kDestinationUnknown = 4,
  kSourceStale = 5,
  kDestinationStale = 6,
  kTopologyStale = 7,
  kEpochStale = 8,
  kConstraintUnsatisfied = 9,
  kResourceLimit = 10,
  kRevalidationRequired = 11,
  kMalformedRequest = 12,
  kUnauthorized = 13,
  kUnsupported = 14,
  kTruncatedByLimit = 15,
};

inline constexpr EnumEntry kPlanStatusNames[] = {
    {"PLANNED", 1},
    {"NO_PATH", 2},
    {"SOURCE_UNKNOWN", 3},
    {"DESTINATION_UNKNOWN", 4},
    {"SOURCE_STALE", 5},
    {"DESTINATION_STALE", 6},
    {"TOPOLOGY_STALE", 7},
    {"EPOCH_STALE", 8},
    {"CONSTRAINT_UNSATISFIED", 9},
    {"RESOURCE_LIMIT", 10},
    {"REVALIDATION_REQUIRED", 11},
    {"MALFORMED_REQUEST", 12},
    {"UNAUTHORIZED", 13},
    {"UNSUPPORTED", 14},
    {"TRUNCATED_BY_LIMIT", 15},
};

inline std::string_view ToString(PlanStatus value) { return EnumName(kPlanStatusNames, value); }
inline std::optional<PlanStatus> ParsePlanStatus(std::string_view name) { return ParseEnum<PlanStatus>(kPlanStatusNames, name); }

// PLANNED and TRUNCATED_BY_LIMIT carry a usable (possibly partial) candidate list.
// REVALIDATION_REQUIRED carries candidates computed from non-current evidence, or
// a result whose publication watermark changed; such candidates are never CURRENT.
inline constexpr bool CarriesCandidates(PlanStatus status) {
  return status == PlanStatus::kPlanned || status == PlanStatus::kTruncatedByLimit ||
         status == PlanStatus::kRevalidationRequired;
}

// ---------------------------------------------------------------------------
// Currentness of a plan with respect to the evidence that produced it.
// ---------------------------------------------------------------------------
enum class Currentness : std::uint32_t {
  kCurrent = 1,
  kRevalidationRequired = 2,
  kStaleTopology = 3,
  kStaleLinkState = 4,
  kStalePortState = 5,
  kStaleCapability = 6,
  kStaleFailureDomain = 7,
  kStalePolicy = 8,
  kStaleEpoch = 9,
  kRetired = 10,
};

inline constexpr EnumEntry kCurrentnessNames[] = {
    {"CURRENT", 1},
    {"REVALIDATION_REQUIRED", 2},
    {"STALE_TOPOLOGY", 3},
    {"STALE_LINK_STATE", 4},
    {"STALE_PORT_STATE", 5},
    {"STALE_CAPABILITY", 6},
    {"STALE_FAILURE_DOMAIN", 7},
    {"STALE_POLICY", 8},
    {"STALE_EPOCH", 9},
    {"RETIRED", 10},
};

inline std::string_view ToString(Currentness value) { return EnumName(kCurrentnessNames, value); }
inline std::optional<Currentness> ParseCurrentness(std::string_view name) { return ParseEnum<Currentness>(kCurrentnessNames, name); }

// Precedence used when several dependency dimensions changed: the most severe
// (least usable) classification wins. Lower rank == more severe, and CURRENT is the
// least severe value, so folding a change onto CURRENT always yields the change.
inline constexpr int CurrentnessSeverity(Currentness value) {
  switch (value) {
    case Currentness::kRetired: return 0;
    case Currentness::kStaleEpoch: return 1;
    case Currentness::kStaleTopology: return 2;
    case Currentness::kStaleLinkState: return 3;
    case Currentness::kStalePortState: return 4;
    case Currentness::kStaleCapability: return 5;
    case Currentness::kStaleFailureDomain: return 6;
    case Currentness::kStalePolicy: return 7;
    // Generic revalidation is less specific (and therefore less severe) than a named
    // stale dimension, but still not current.
    case Currentness::kRevalidationRequired: return 8;
    case Currentness::kCurrent: return 9;
  }
  return 0;
}

inline constexpr Currentness MoreSevere(Currentness a, Currentness b) {
  return CurrentnessSeverity(a) <= CurrentnessSeverity(b) ? a : b;
}

// ---------------------------------------------------------------------------
// Consumed authoritative state enumerations.
// ---------------------------------------------------------------------------
enum class LinkState : std::uint32_t {
  kUp = 1,
  kDown = 2,
  kFaulted = 3,
  kRetired = 4,
  kRevalidationRequired = 5,
  kUnknown = 6,
  kDegraded = 7,
};

inline constexpr EnumEntry kLinkStateNames[] = {
    {"UP", 1},
    {"DOWN", 2},
    {"FAULTED", 3},
    {"RETIRED", 4},
    {"REVALIDATION_REQUIRED", 5},
    {"UNKNOWN", 6},
    {"DEGRADED", 7},
};

inline std::string_view ToString(LinkState value) { return EnumName(kLinkStateNames, value); }
inline std::optional<LinkState> ParseLinkState(std::string_view name) { return ParseEnum<LinkState>(kLinkStateNames, name); }

enum class PortState : std::uint32_t {
  kUp = 1,
  kAdminDisabled = 2,
  kDraining = 3,
  kMaintenance = 4,
  kRetired = 5,
  kSuperseded = 6,
  kRevalidationRequired = 7,
  kUnknown = 8,
};

inline constexpr EnumEntry kPortStateNames[] = {
    {"UP", 1},
    {"ADMIN_DISABLED", 2},
    {"DRAINING", 3},
    {"MAINTENANCE", 4},
    {"RETIRED", 5},
    {"SUPERSEDED", 6},
    {"REVALIDATION_REQUIRED", 7},
    {"UNKNOWN", 8},
};

inline std::string_view ToString(PortState value) { return EnumName(kPortStateNames, value); }
inline std::optional<PortState> ParsePortState(std::string_view name) { return ParseEnum<PortState>(kPortStateNames, name); }

enum class PathLayer : std::uint32_t {
  kPhysical = 1,
  kLogical = 2,
  kOverlay = 3,
  kTunnel = 4,
};

inline constexpr EnumEntry kPathLayerNames[] = {
    {"PHYSICAL", 1},
    {"LOGICAL", 2},
    {"OVERLAY", 3},
    {"TUNNEL", 4},
};

inline std::string_view ToString(PathLayer value) { return EnumName(kPathLayerNames, value); }
inline std::optional<PathLayer> ParsePathLayer(std::string_view name) { return ParseEnum<PathLayer>(kPathLayerNames, name); }

enum class RelationshipType : std::uint32_t {
  kDirectLink = 1,
  kLogicalAdjacency = 2,
  kTunnelEncapsulation = 3,
  kPortPairing = 4,
};

inline constexpr EnumEntry kRelationshipTypeNames[] = {
    {"DIRECT_LINK", 1},
    {"LOGICAL_ADJACENCY", 2},
    {"TUNNEL_ENCAPSULATION", 3},
    {"PORT_PAIRING", 4},
};

inline std::string_view ToString(RelationshipType value) { return EnumName(kRelationshipTypeNames, value); }
inline std::optional<RelationshipType> ParseRelationshipType(std::string_view name) { return ParseEnum<RelationshipType>(kRelationshipTypeNames, name); }

enum class EndpointClass : std::uint32_t {
  kEndpoint = 1,
  kNic = 2,
  kPort = 3,
  kSwitchAttachment = 4,
  kLogicalEndpoint = 5,
};

inline constexpr EnumEntry kEndpointClassNames[] = {
    {"ENDPOINT", 1},
    {"NIC", 2},
    {"PORT", 3},
    {"SWITCH_ATTACHMENT", 4},
    {"LOGICAL_ENDPOINT", 5},
};

inline std::string_view ToString(EndpointClass value) { return EnumName(kEndpointClassNames, value); }
inline std::optional<EndpointClass> ParseEndpointClass(std::string_view name) { return ParseEnum<EndpointClass>(kEndpointClassNames, name); }

// Provenance label of the evidence a snapshot was built from. Never a quality claim.
enum class EvidenceSource : std::uint32_t {
  kReal = 1,
  kSynthetic = 2,
  kMixed = 3,
};

inline constexpr EnumEntry kEvidenceSourceNames[] = {
    {"REAL", 1},
    {"SYNTHETIC", 2},
    {"MIXED", 3},
};

inline std::string_view ToString(EvidenceSource value) { return EnumName(kEvidenceSourceNames, value); }
inline std::optional<EvidenceSource> ParseEvidenceSource(std::string_view name) { return ParseEnum<EvidenceSource>(kEvidenceSourceNames, name); }

// ---------------------------------------------------------------------------
// Planning mode.
// ---------------------------------------------------------------------------
enum class PlanningMode : std::uint32_t {
  // Only currently-proven-eligible elements are traversable.
  kStandard = 1,
  // Diagnostic mode: additionally traverses non-current elements (DRAINING,
  // MAINTENANCE, UNKNOWN operational state, REVALIDATION_REQUIRED). Results are
  // never CURRENT; they are reported as REVALIDATION_REQUIRED.
  kDiagnosticNonCurrent = 2,
};

inline constexpr EnumEntry kPlanningModeNames[] = {
    {"STANDARD", 1},
    {"DIAGNOSTIC_NON_CURRENT", 2},
};

inline std::string_view ToString(PlanningMode value) { return EnumName(kPlanningModeNames, value); }
inline std::optional<PlanningMode> ParsePlanningMode(std::string_view name) { return ParseEnum<PlanningMode>(kPlanningModeNames, name); }

// ---------------------------------------------------------------------------
// Replanning outcome relative to a prior plan.
// ---------------------------------------------------------------------------
enum class ReplanOutcome : std::uint32_t {
  kUnchanged = 1,
  kOrderingChanged = 2,
  kCandidateSetChanged = 3,
  kNoPath = 4,
  kRevalidationRequired = 5,
};

inline constexpr EnumEntry kReplanOutcomeNames[] = {
    {"UNCHANGED", 1},
    {"ORDERING_CHANGED", 2},
    {"CANDIDATE_SET_CHANGED", 3},
    {"NO_PATH", 4},
    {"REVALIDATION_REQUIRED", 5},
};

inline std::string_view ToString(ReplanOutcome value) { return EnumName(kReplanOutcomeNames, value); }
inline std::optional<ReplanOutcome> ParseReplanOutcome(std::string_view name) { return ParseEnum<ReplanOutcome>(kReplanOutcomeNames, name); }

// ---------------------------------------------------------------------------
// Explicit Path Authority integration status. Path Planner never claims legality
// on its own; absence of validation is reported as NOT_REQUESTED.
// ---------------------------------------------------------------------------
enum class AuthorityValidation : std::uint32_t {
  kNotRequested = 1,
  kValidated = 2,
  kRejected = 3,
  kUnavailable = 4,
};

inline constexpr EnumEntry kAuthorityValidationNames[] = {
    {"NOT_REQUESTED", 1},
    {"VALIDATED", 2},
    {"REJECTED", 3},
    {"UNAVAILABLE", 4},
};

inline std::string_view ToString(AuthorityValidation value) { return EnumName(kAuthorityValidationNames, value); }
inline std::optional<AuthorityValidation> ParseAuthorityValidation(std::string_view name) { return ParseEnum<AuthorityValidation>(kAuthorityValidationNames, name); }

// ---------------------------------------------------------------------------
// Caller authority scope (bit flags). Request authorization is independent of
// path legality authority.
// ---------------------------------------------------------------------------
enum class AuthorityScope : std::uint32_t {
  kNone = 0,
  kSubmitPlanRequest = 1u << 0,
  kReadPlan = 1u << 1,
  kPublishPlanResult = 1u << 2,
  kAdvanceEpoch = 1u << 3,
  kFenceWorker = 1u << 4,
};

inline constexpr std::uint32_t ToMask(AuthorityScope scope) { return static_cast<std::uint32_t>(scope); }
inline constexpr bool HasScope(std::uint32_t mask, AuthorityScope scope) {
  return (mask & static_cast<std::uint32_t>(scope)) == static_cast<std::uint32_t>(scope);
}
inline constexpr std::uint32_t CombineScopes(AuthorityScope a, AuthorityScope b) {
  return static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b);
}

// ---------------------------------------------------------------------------
// Diagnostics: structured secondary evidence behind a status or rejection.
// ---------------------------------------------------------------------------
enum class DiagnosticCode : std::uint32_t {
  kMalformedIdentifier = 1,
  kDuplicateIdentifier = 2,
  kUnknownEndpoint = 3,
  kAmbiguousEndpoint = 4,
  kEntityGenerationMismatch = 5,
  kTopologyGenerationMismatch = 6,
  kEpochMismatch = 7,
  kLinkStateDown = 8,
  kLinkStateFaulted = 9,
  kLinkStateRetired = 10,
  kLinkStateRevalidationRequired = 11,
  kLinkStateUnknown = 12,
  kLinkStateDegradedDisallowed = 13,
  kPortAdminDisabled = 14,
  kPortDraining = 15,
  kPortMaintenance = 16,
  kPortRetired = 17,
  kPortSuperseded = 18,
  kPortRevalidationRequired = 19,
  kPortUnknown = 20,
  kCapabilityUnknown = 21,
  kCapabilityInsufficient = 22,
  kFailureDomainForbidden = 23,
  kFailureDomainUnknown = 24,
  kFailureDomainMemberLimitExceeded = 25,
  kFailureDomainClassForbidden = 26,
  kForbiddenNode = 27,
  kForbiddenLink = 28,
  kForbiddenPort = 29,
  kRequiredNodeMissing = 30,
  kRequiredAnySetUnsatisfied = 31,
  kMaxHopsExceeded = 32,
  kLayerMismatch = 33,
  kSelfLoopRejected = 34,
  kDisconnectedGraph = 35,
  kNoStructuralPath = 36,
  kCostOverflow = 37,
  kHopCountOverflow = 38,
  kWorkBudgetExhausted = 39,
  kCandidateLimitExceeded = 40,
  kConstraintCountExceeded = 41,
  kRequestedCandidatesAboveCeiling = 42,
  kDuplicateConstraintEntry = 43,
  kZeroHopSelfPathDisallowed = 44,
  kStaleEvidence = 45,
  kInvalidationWatermarkChanged = 46,
  kWorkerBootFenced = 47,
  kCoordinatorEpochStale = 48,
  kAuthorityScopeInsufficient = 49,
  kPersistenceCorrupt = 50,
  kPersistenceVersionUnsupported = 51,
  kPersistenceDigestMismatch = 52,
  kPersistenceTrailingBytes = 53,
  kPersistenceDuplicatePlan = 54,
  kPersistenceDuplicateCandidate = 55,
  kPersistenceLimitExceeded = 56,
  kProtocolMalformedFrame = 57,
  kProtocolVersionMismatch = 58,
  kProtocolIntegrityMismatch = 59,
  kProtocolTrailingBytes = 60,
  kProtocolUnknownMessage = 61,
  kProtocolReceiveBoundExceeded = 62,
  kProtocolSessionLimit = 63,
  kProtocolSlowPeer = 64,
  kGraphTooLarge = 65,
  kTooManyEdges = 66,
  kNonCurrentCandidate = 67,
  kAuthorityValidationRejected = 68,
  kAuthorityValidationUnavailable = 69,
  kUnsupportedEndpointClass = 70,
  kUnsupportedLayer = 71,
  kUnsupportedRequest = 72,
  kTruncatedByLimit = 73,
  kUnknownSourceEntity = 74,
  kUnknownDestinationEntity = 75,
  kSnapshotNotAvailable = 76,
  kPlanNotFound = 77,
  kPlanRetired = 78,
  kDuplicatePlanIdentity = 79,
  kCancelled = 80,
  kPersistenceImpossibleValue = 81,
};

inline constexpr EnumEntry kDiagnosticCodeNames[] = {
    {"MALFORMED_IDENTIFIER", 1},
    {"DUPLICATE_IDENTIFIER", 2},
    {"UNKNOWN_ENDPOINT", 3},
    {"AMBIGUOUS_ENDPOINT", 4},
    {"ENTITY_GENERATION_MISMATCH", 5},
    {"TOPOLOGY_GENERATION_MISMATCH", 6},
    {"EPOCH_MISMATCH", 7},
    {"LINK_STATE_DOWN", 8},
    {"LINK_STATE_FAULTED", 9},
    {"LINK_STATE_RETIRED", 10},
    {"LINK_STATE_REVALIDATION_REQUIRED", 11},
    {"LINK_STATE_UNKNOWN", 12},
    {"LINK_STATE_DEGRADED_DISALLOWED", 13},
    {"PORT_ADMIN_DISABLED", 14},
    {"PORT_DRAINING", 15},
    {"PORT_MAINTENANCE", 16},
    {"PORT_RETIRED", 17},
    {"PORT_SUPERSEDED", 18},
    {"PORT_REVALIDATION_REQUIRED", 19},
    {"PORT_UNKNOWN", 20},
    {"CAPABILITY_UNKNOWN", 21},
    {"CAPABILITY_INSUFFICIENT", 22},
    {"FAILURE_DOMAIN_FORBIDDEN", 23},
    {"FAILURE_DOMAIN_UNKNOWN", 24},
    {"FAILURE_DOMAIN_MEMBER_LIMIT_EXCEEDED", 25},
    {"FAILURE_DOMAIN_CLASS_FORBIDDEN", 26},
    {"FORBIDDEN_NODE", 27},
    {"FORBIDDEN_LINK", 28},
    {"FORBIDDEN_PORT", 29},
    {"REQUIRED_NODE_MISSING", 30},
    {"REQUIRED_ANY_SET_UNSATISFIED", 31},
    {"MAX_HOPS_EXCEEDED", 32},
    {"LAYER_MISMATCH", 33},
    {"SELF_LOOP_REJECTED", 34},
    {"DISCONNECTED_GRAPH", 35},
    {"NO_STRUCTURAL_PATH", 36},
    {"COST_OVERFLOW", 37},
    {"HOP_COUNT_OVERFLOW", 38},
    {"WORK_BUDGET_EXHAUSTED", 39},
    {"CANDIDATE_LIMIT_EXCEEDED", 40},
    {"CONSTRAINT_COUNT_EXCEEDED", 41},
    {"REQUESTED_CANDIDATES_ABOVE_CEILING", 42},
    {"DUPLICATE_CONSTRAINT_ENTRY", 43},
    {"ZERO_HOP_SELF_PATH_DISALLOWED", 44},
    {"STALE_EVIDENCE", 45},
    {"INVALIDATION_WATERMARK_CHANGED", 46},
    {"WORKER_BOOT_FENCED", 47},
    {"COORDINATOR_EPOCH_STALE", 48},
    {"AUTHORITY_SCOPE_INSUFFICIENT", 49},
    {"PERSISTENCE_CORRUPT", 50},
    {"PERSISTENCE_VERSION_UNSUPPORTED", 51},
    {"PERSISTENCE_DIGEST_MISMATCH", 52},
    {"PERSISTENCE_TRAILING_BYTES", 53},
    {"PERSISTENCE_DUPLICATE_PLAN", 54},
    {"PERSISTENCE_DUPLICATE_CANDIDATE", 55},
    {"PERSISTENCE_LIMIT_EXCEEDED", 56},
    {"PROTOCOL_MALFORMED_FRAME", 57},
    {"PROTOCOL_VERSION_MISMATCH", 58},
    {"PROTOCOL_INTEGRITY_MISMATCH", 59},
    {"PROTOCOL_TRAILING_BYTES", 60},
    {"PROTOCOL_UNKNOWN_MESSAGE", 61},
    {"PROTOCOL_RECEIVE_BOUND_EXCEEDED", 62},
    {"PROTOCOL_SESSION_LIMIT", 63},
    {"PROTOCOL_SLOW_PEER", 64},
    {"GRAPH_TOO_LARGE", 65},
    {"TOO_MANY_EDGES", 66},
    {"NON_CURRENT_CANDIDATE", 67},
    {"AUTHORITY_VALIDATION_REJECTED", 68},
    {"AUTHORITY_VALIDATION_UNAVAILABLE", 69},
    {"UNSUPPORTED_ENDPOINT_CLASS", 70},
    {"UNSUPPORTED_LAYER", 71},
    {"UNSUPPORTED_REQUEST", 72},
    {"TRUNCATED_BY_LIMIT", 73},
    {"UNKNOWN_SOURCE_ENTITY", 74},
    {"UNKNOWN_DESTINATION_ENTITY", 75},
    {"SNAPSHOT_NOT_AVAILABLE", 76},
    {"PLAN_NOT_FOUND", 77},
    {"PLAN_RETIRED", 78},
    {"DUPLICATE_PLAN_IDENTITY", 79},
    {"CANCELLED", 80},
    {"PERSISTENCE_IMPOSSIBLE_VALUE", 81},
};

inline std::string_view ToString(DiagnosticCode value) { return EnumName(kDiagnosticCodeNames, value); }
inline std::optional<DiagnosticCode> ParseDiagnosticCode(std::string_view name) { return ParseEnum<DiagnosticCode>(kDiagnosticCodeNames, name); }

}  // namespace summon::pathplanner

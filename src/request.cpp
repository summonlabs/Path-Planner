#include "pathplanner/request.hpp"

#include <algorithm>
#include <string>

namespace summon::pathplanner {
namespace {

template <class Id>
bool HasDuplicate(const std::vector<Id>& values) {
  std::vector<Id> sorted(values.begin(), values.end());
  std::sort(sorted.begin(), sorted.end());
  return std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end();
}

bool Exceeds(std::size_t count, std::uint32_t limit) noexcept {
  return count > static_cast<std::size_t>(limit);
}

RequestValidation Fail(DiagnosticCode code, std::string detail) {
  RequestValidation result;
  result.code = code;
  result.detail = std::move(detail);
  return result;
}

}  // namespace

bool CapabilityRequirement::SatisfiedBy(CapabilityValue observed) const noexcept {
  switch (comparator) {
    case CapabilityComparator::kAtLeast:
      return observed >= value;
    case CapabilityComparator::kAtMost:
      return observed <= value;
    case CapabilityComparator::kEqual:
      return observed == value;
  }
  return false;
}

std::size_t ConstraintSet::EntryCount() const noexcept {
  return forbidden_nodes.size() + forbidden_links.size() + forbidden_ports.size() +
         forbidden_failure_domains.size() + forbidden_failure_domain_classes.size() + required_transit.size() +
         required_capabilities.size();
}

std::size_t ConstraintSet::TransitAlternativeCount() const noexcept {
  std::size_t total = 0;
  for (const TransitStage& stage : required_transit) {
    total += stage.alternatives.size();
  }
  return total;
}

RequestValidation ValidateConstraintSet(const ConstraintSet& constraints, const ResourceLimits& limits) {
  if (!constraints.id.IsValid()) {
    return Fail(DiagnosticCode::kMalformedIdentifier, "constraint set identity is nil");
  }
  if (Exceeds(constraints.EntryCount(), limits.max_constraints_total)) {
    return Fail(DiagnosticCode::kConstraintCountExceeded, "constraint entry count exceeds the configured limit");
  }
  if (Exceeds(constraints.forbidden_nodes.size(), limits.max_forbidden_ids) ||
      Exceeds(constraints.forbidden_links.size(), limits.max_forbidden_ids) ||
      Exceeds(constraints.forbidden_ports.size(), limits.max_forbidden_ids) ||
      Exceeds(constraints.forbidden_failure_domains.size(), limits.max_forbidden_ids) ||
      Exceeds(constraints.forbidden_failure_domain_classes.size(), limits.max_forbidden_domain_classes)) {
    return Fail(DiagnosticCode::kConstraintCountExceeded, "forbidden identifier count exceeds the configured limit");
  }
  if (Exceeds(constraints.required_transit.size(), limits.max_required_ids)) {
    return Fail(DiagnosticCode::kConstraintCountExceeded, "transit stage count exceeds the configured limit");
  }
  if (Exceeds(constraints.required_capabilities.size(), limits.max_capability_requirements)) {
    return Fail(DiagnosticCode::kConstraintCountExceeded, "capability requirement count exceeds the configured limit");
  }

  for (const NodeId& id : constraints.forbidden_nodes) {
    if (!id.IsValid()) {
      return Fail(DiagnosticCode::kMalformedIdentifier, "forbidden node identity is nil");
    }
  }
  for (const LinkId& id : constraints.forbidden_links) {
    if (!id.IsValid()) {
      return Fail(DiagnosticCode::kMalformedIdentifier, "forbidden link identity is nil");
    }
  }
  for (const PortId& id : constraints.forbidden_ports) {
    if (!id.IsValid()) {
      return Fail(DiagnosticCode::kMalformedIdentifier, "forbidden port identity is nil");
    }
  }
  for (const FailureDomainId& id : constraints.forbidden_failure_domains) {
    if (!id.IsValid()) {
      return Fail(DiagnosticCode::kMalformedIdentifier, "forbidden failure domain identity is nil");
    }
  }
  for (const FailureDomainClass& id : constraints.forbidden_failure_domain_classes) {
    if (!id.IsValid()) {
      return Fail(DiagnosticCode::kMalformedIdentifier, "forbidden failure domain class identity is nil");
    }
  }

  if (HasDuplicate(constraints.forbidden_nodes) || HasDuplicate(constraints.forbidden_links) ||
      HasDuplicate(constraints.forbidden_ports) || HasDuplicate(constraints.forbidden_failure_domains) ||
      HasDuplicate(constraints.forbidden_failure_domain_classes)) {
    return Fail(DiagnosticCode::kDuplicateConstraintEntry, "duplicate forbidden constraint entry");
  }

  std::vector<NodeId> transit_nodes;
  for (const TransitStage& stage : constraints.required_transit) {
    if (stage.alternatives.empty()) {
      return Fail(DiagnosticCode::kMalformedIdentifier, "transit stage has no alternatives");
    }
    if (stage.kind == TransitKind::kExact && stage.alternatives.size() != 1) {
      return Fail(DiagnosticCode::kConstraintCountExceeded, "EXACT transit stage must name exactly one node");
    }
    if (Exceeds(stage.alternatives.size(), limits.max_members_in_any_set)) {
      return Fail(DiagnosticCode::kConstraintCountExceeded, "transit stage alternative count exceeds the limit");
    }
    for (const NodeId& id : stage.alternatives) {
      if (!id.IsValid()) {
        return Fail(DiagnosticCode::kMalformedIdentifier, "transit node identity is nil");
      }
    }
    if (HasDuplicate(stage.alternatives)) {
      return Fail(DiagnosticCode::kDuplicateConstraintEntry, "duplicate alternative in a transit stage");
    }
    transit_nodes.push_back(stage.alternatives.front());
  }

  for (const CapabilityRequirement& requirement : constraints.required_capabilities) {
    if (!requirement.capability.IsValid()) {
      return Fail(DiagnosticCode::kMalformedIdentifier, "capability identity is nil");
    }
  }

  if (constraints.max_hops.has_value()) {
    if (constraints.max_hops->Value() > limits.max_hops) {
      return Fail(DiagnosticCode::kMaxHopsExceeded, "max_hops exceeds the configured ceiling");
    }
  }
  if (constraints.max_members_per_failure_domain.has_value() &&
      *constraints.max_members_per_failure_domain == 0) {
    return Fail(DiagnosticCode::kConstraintCountExceeded, "max_members_per_failure_domain must be positive");
  }
  return RequestValidation{};
}

RequestValidation ValidatePolicy(const PlanningPolicy& policy, const ResourceLimits& limits) {
  if (policy.locality_scope.size() > static_cast<std::size_t>(limits.max_forbidden_ids)) {
    return Fail(DiagnosticCode::kConstraintCountExceeded, "locality scope exceeds the configured limit");
  }
  for (const NodeId& id : policy.locality_scope) {
    if (!id.IsValid()) {
      return Fail(DiagnosticCode::kMalformedIdentifier, "locality scope node identity is nil");
    }
  }
  if (HasDuplicate(policy.locality_scope)) {
    return Fail(DiagnosticCode::kDuplicateConstraintEntry, "duplicate node in locality scope");
  }
  // A locality penalty only has meaning with an explicit locality scope; an empty
  // scope disables it (documented) rather than penalising every hop by accident.
  if (policy.cost_model.locality_penalty.Value() != 0 && policy.locality_scope.empty()) {
    return Fail(DiagnosticCode::kUnsupportedRequest,
                "locality_penalty requires a non-empty locality_scope");
  }
  return RequestValidation{};
}

RequestValidation ValidateRequest(const PlanningRequest& request, const ResourceLimits& limits) {
  if (!request.id.IsValid()) {
    return Fail(DiagnosticCode::kMalformedIdentifier, "planning request identity is nil");
  }
  if (!request.source.id.IsValid()) {
    return Fail(DiagnosticCode::kMalformedIdentifier, "source endpoint identity is nil");
  }
  if (!request.destination.id.IsValid()) {
    return Fail(DiagnosticCode::kMalformedIdentifier, "destination endpoint identity is nil");
  }
  if (request.max_candidates == 0) {
    return Fail(DiagnosticCode::kCandidateLimitExceeded, "max_candidates must be at least 1");
  }
  if (request.max_candidates > limits.max_candidates_per_request) {
    return Fail(DiagnosticCode::kRequestedCandidatesAboveCeiling,
                "max_candidates exceeds the configured ceiling");
  }
  if (!IsKnownEnumValue<PathLayer>(kPathLayerNames, static_cast<std::uint32_t>(request.constraints.layer))) {
    return Fail(DiagnosticCode::kUnsupportedLayer, "unknown planning layer");
  }
  if (!IsKnownEnumValue<PlanningMode>(kPlanningModeNames, static_cast<std::uint32_t>(request.mode))) {
    return Fail(DiagnosticCode::kUnsupportedRequest, "unknown planning mode");
  }
  if (!IsKnownEnumValue<AuthorityValidationMode>(kAuthorityValidationModeNames,
                        static_cast<std::uint32_t>(request.policy.authority_validation))) {
    return Fail(DiagnosticCode::kUnsupportedRequest, "unknown authority validation mode");
  }
  for (const CapabilityRequirement& requirement : request.constraints.required_capabilities) {
    if (!IsKnownEnumValue<CapabilityScope>(kCapabilityScopeNames, static_cast<std::uint32_t>(requirement.scope)) ||
        !IsKnownEnumValue<CapabilityComparator>(kCapabilityComparatorNames, static_cast<std::uint32_t>(requirement.comparator))) {
      return Fail(DiagnosticCode::kUnsupportedRequest, "unknown capability requirement encoding");
    }
  }
  if (RequestValidation constraints = ValidateConstraintSet(request.constraints, limits); !constraints.ok()) {
    return constraints;
  }
  if (RequestValidation policy = ValidatePolicy(request.policy, limits); !policy.ok()) {
    return policy;
  }
  if (request.expect_topology) {
    if (request.expected_topology.Value() == 0) {
      return Fail(DiagnosticCode::kMalformedIdentifier, "expected topology generation must be positive");
    }
  }
  if (request.expect_snapshot && !request.expected_snapshot.IsValid()) {
    return Fail(DiagnosticCode::kMalformedIdentifier, "expected snapshot identity is nil");
  }
  return RequestValidation{};
}

PlanStatus StatusForValidationCode(DiagnosticCode code) noexcept {
  switch (code) {
    case DiagnosticCode::kMalformedIdentifier:
    case DiagnosticCode::kDuplicateConstraintEntry:
    case DiagnosticCode::kDuplicateIdentifier:
    case DiagnosticCode::kSelfLoopRejected:
      return PlanStatus::kMalformedRequest;
    case DiagnosticCode::kRequestedCandidatesAboveCeiling:
    case DiagnosticCode::kConstraintCountExceeded:
    case DiagnosticCode::kGraphTooLarge:
    case DiagnosticCode::kTooManyEdges:
    case DiagnosticCode::kWorkBudgetExhausted:
      return PlanStatus::kResourceLimit;
    case DiagnosticCode::kCandidateLimitExceeded:
      // A candidate count of zero is an invalid value, not a resource ceiling breach.
      return PlanStatus::kMalformedRequest;
    case DiagnosticCode::kMaxHopsExceeded:
      return PlanStatus::kConstraintUnsatisfied;
    case DiagnosticCode::kUnsupportedLayer:
    case DiagnosticCode::kUnsupportedRequest:
    case DiagnosticCode::kUnsupportedEndpointClass:
      return PlanStatus::kUnsupported;
    default:
      return PlanStatus::kMalformedRequest;
  }
}

}  // namespace summon::pathplanner

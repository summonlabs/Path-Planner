#include "pathplanner/planner.hpp"

#include <algorithm>
#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "pathplanner/version.hpp"
#include "planning_view.hpp"
#include "search.hpp"

namespace summon::pathplanner {
namespace {

using internal::kInvalidIndex;

std::string EvidenceChangeDetail(const char* dimension, std::uint64_t before, std::uint64_t after) {
  return std::string(dimension) + " generation changed: " + std::to_string(before) + " -> " + std::to_string(after);
}

std::vector<ExplanationEntry> DiffEvidence(const EvidenceVector& prior, const EvidenceVector& current) {
  std::vector<ExplanationEntry> changes;
  if (prior.generations.topology != current.generations.topology) {
    changes.push_back(ExplanationEntry{DiagnosticCode::kTopologyGenerationMismatch,
                                       EvidenceChangeDetail("topology", prior.generations.topology.Value(),
                                                            current.generations.topology.Value())});
  }
  if (prior.generations.link_state != current.generations.link_state) {
    changes.push_back(ExplanationEntry{DiagnosticCode::kStaleEvidence,
                                       EvidenceChangeDetail("link-state", prior.generations.link_state.Value(),
                                                            current.generations.link_state.Value())});
  }
  if (prior.generations.ports != current.generations.ports) {
    changes.push_back(ExplanationEntry{DiagnosticCode::kStaleEvidence,
                                       EvidenceChangeDetail("port", prior.generations.ports.Value(),
                                                            current.generations.ports.Value())});
  }
  if (prior.generations.capabilities != current.generations.capabilities) {
    changes.push_back(ExplanationEntry{DiagnosticCode::kStaleEvidence,
                                       EvidenceChangeDetail("capability", prior.generations.capabilities.Value(),
                                                            current.generations.capabilities.Value())});
  }
  if (prior.generations.failure_domains != current.generations.failure_domains) {
    changes.push_back(ExplanationEntry{
        DiagnosticCode::kStaleEvidence,
        EvidenceChangeDetail("failure-domain", prior.generations.failure_domains.Value(),
                             current.generations.failure_domains.Value())});
  }
  if (prior.generations.policy != current.generations.policy) {
    changes.push_back(ExplanationEntry{DiagnosticCode::kStaleEvidence,
                                       EvidenceChangeDetail("policy", prior.generations.policy.Value(),
                                                            current.generations.policy.Value())});
  }
  if (prior.generations.epoch != current.generations.epoch) {
    changes.push_back(ExplanationEntry{DiagnosticCode::kEpochMismatch,
                                       EvidenceChangeDetail("fabric epoch", prior.generations.epoch.Value(),
                                                            current.generations.epoch.Value())});
  }
  if (prior.snapshot != current.snapshot) {
    changes.push_back(ExplanationEntry{DiagnosticCode::kStaleEvidence,
                                       "snapshot identity changed: " + prior.snapshot.ToString() + " -> " +
                                           current.snapshot.ToString()});
  }
  if (prior.publish_sequence != current.publish_sequence) {
    changes.push_back(ExplanationEntry{DiagnosticCode::kInvalidationWatermarkChanged,
                                       "publication watermark advanced: " +
                                           prior.publish_sequence.ToString() + " -> " +
                                           current.publish_sequence.ToString()});
  }
  return changes;
}

// Structural reachability: connectivity that ignores operational state, capability and
// failure-domain constraints, returning the minimum hop count. Used to distinguish
// "no structural path" from "every structural path was filtered out" and from
// "a path exists but exceeds the requested hop bound".
std::optional<std::uint32_t> StructuralHopDistance(const FabricSnapshot& snapshot, const NodeId& source,
                                                   const NodeId& destination, const PlanningRequest& request) {
  if (source == destination) {
    return 0;
  }
  const std::vector<NodeRecord>& nodes = snapshot.Nodes();
  const std::vector<EdgeRecord>& edges = snapshot.Edges();
  std::unordered_map<std::string, std::uint32_t> index_of;
  index_of.reserve(nodes.size());
  for (std::size_t index = 0; index < nodes.size(); ++index) {
    index_of.emplace(nodes[index].id.ToString(), static_cast<std::uint32_t>(index));
  }
  const auto source_it = index_of.find(source.ToString());
  const auto destination_it = index_of.find(destination.ToString());
  if (source_it == index_of.end() || destination_it == index_of.end()) {
    return std::nullopt;
  }
  std::vector<NodeId> forbidden_nodes = request.constraints.forbidden_nodes;
  std::vector<LinkId> forbidden_links = request.constraints.forbidden_links;
  std::sort(forbidden_nodes.begin(), forbidden_nodes.end());
  std::sort(forbidden_links.begin(), forbidden_links.end());

  std::vector<std::vector<std::uint32_t>> adjacency(nodes.size());
  for (std::size_t index = 0; index < edges.size(); ++index) {
    const EdgeRecord& edge = edges[index];
    if (edge.layer != request.constraints.layer) {
      continue;
    }
    if (std::binary_search(forbidden_links.begin(), forbidden_links.end(), edge.id)) {
      continue;
    }
    const auto from_it = index_of.find(edge.from.ToString());
    const auto to_it = index_of.find(edge.to.ToString());
    if (from_it == index_of.end() || to_it == index_of.end()) {
      continue;
    }
    if (std::binary_search(forbidden_nodes.begin(), forbidden_nodes.end(), edge.from) ||
        std::binary_search(forbidden_nodes.begin(), forbidden_nodes.end(), edge.to)) {
      continue;
    }
    adjacency[from_it->second].push_back(to_it->second);
  }

  std::vector<std::uint32_t> distance(nodes.size(), 0xFFFFFFFFu);
  std::vector<std::uint32_t> queue;
  queue.push_back(source_it->second);
  distance[source_it->second] = 0;
  for (std::size_t head = 0; head < queue.size(); ++head) {
    const std::uint32_t node = queue[head];
    if (node == destination_it->second) {
      return distance[node];
    }
    for (const std::uint32_t next : adjacency[node]) {
      if (distance[next] == 0xFFFFFFFFu) {
        distance[next] = distance[node] + 1;
        queue.push_back(next);
      }
    }
  }
  return std::nullopt;
}

// Deterministic primary failure classification (precedence is documented).
DiagnosticCode PrimaryFailure(const internal::PlanningView& view, bool structural_reachable) {
  using internal::PlanningView;
  const internal::RejectionLog& log = view.rejections;
  if (!structural_reachable) {
    if (log.Contains(DiagnosticCode::kForbiddenLink)) {
      return DiagnosticCode::kForbiddenLink;
    }
    if (log.Contains(DiagnosticCode::kForbiddenPort)) {
      return DiagnosticCode::kForbiddenPort;
    }
    if (log.Contains(DiagnosticCode::kForbiddenNode)) {
      return DiagnosticCode::kForbiddenNode;
    }
    if (log.Contains(DiagnosticCode::kLayerMismatch)) {
      return DiagnosticCode::kLayerMismatch;
    }
    return DiagnosticCode::kNoStructuralPath;
  }
  const DiagnosticCode operational[] = {
      DiagnosticCode::kLinkStateDown,      DiagnosticCode::kLinkStateFaulted,
      DiagnosticCode::kLinkStateRetired,   DiagnosticCode::kLinkStateRevalidationRequired,
      DiagnosticCode::kLinkStateUnknown,   DiagnosticCode::kLinkStateDegradedDisallowed,
      DiagnosticCode::kPortAdminDisabled,  DiagnosticCode::kPortDraining,
      DiagnosticCode::kPortMaintenance,    DiagnosticCode::kPortRetired,
      DiagnosticCode::kPortSuperseded,     DiagnosticCode::kPortRevalidationRequired,
      DiagnosticCode::kPortUnknown,        DiagnosticCode::kCostOverflow};
  for (const DiagnosticCode code : operational) {
    if (log.Contains(code)) {
      return code;
    }
  }
  const DiagnosticCode capability[] = {DiagnosticCode::kCapabilityUnknown, DiagnosticCode::kCapabilityInsufficient};
  for (const DiagnosticCode code : capability) {
    if (log.Contains(code)) {
      return code;
    }
  }
  const DiagnosticCode domains[] = {DiagnosticCode::kFailureDomainForbidden,
                                    DiagnosticCode::kFailureDomainUnknown,
                                    DiagnosticCode::kFailureDomainClassForbidden,
                                    DiagnosticCode::kFailureDomainMemberLimitExceeded};
  for (const DiagnosticCode code : domains) {
    if (log.Contains(code)) {
      return code;
    }
  }
  if (log.Contains(DiagnosticCode::kForbiddenNode)) {
    return DiagnosticCode::kForbiddenNode;
  }
  if (log.Contains(DiagnosticCode::kForbiddenLink)) {
    return DiagnosticCode::kForbiddenLink;
  }
  if (log.Contains(DiagnosticCode::kForbiddenPort)) {
    return DiagnosticCode::kForbiddenPort;
  }
  return DiagnosticCode::kNoStructuralPath;
}

PlanStatus StatusForFailure(DiagnosticCode code) noexcept {
  switch (code) {
    case DiagnosticCode::kRequiredNodeMissing:
    case DiagnosticCode::kRequiredAnySetUnsatisfied:
    case DiagnosticCode::kMaxHopsExceeded:
    case DiagnosticCode::kZeroHopSelfPathDisallowed:
    case DiagnosticCode::kFailureDomainMemberLimitExceeded:
      return PlanStatus::kConstraintUnsatisfied;
    case DiagnosticCode::kCostOverflow:
    case DiagnosticCode::kWorkBudgetExhausted:
    case DiagnosticCode::kConstraintCountExceeded:
      return PlanStatus::kResourceLimit;
    case DiagnosticCode::kUnsupportedRequest:
      return PlanStatus::kUnsupported;
    default:
      return PlanStatus::kNoPath;
  }
}

std::string PlanKey(const PathPlanId& id) { return id.ToString(); }

}  // namespace

// ---------------------------------------------------------------------------
// Runtime implementation.
// ---------------------------------------------------------------------------
struct PlannerRuntime::Impl {
  struct RetainedPlan {
    PathPlan plan;
    Currentness currentness = Currentness::kCurrent;
  };

  struct RequestGeneration {
    Sha256Digest digest;
    PlanningGeneration generation;
  };

  mutable std::mutex mutex;
  ResourceLimits limits;
  std::shared_ptr<const FabricSnapshot> snapshot;
  std::shared_ptr<IPathAuthority> authority;
  PlanningHooks hooks;
  PlanPublishSequence publish_sequence;
  FabricEpoch epoch;
  PlannerStatistics stats;
  std::unordered_map<std::string, RetainedPlan> retained;
  std::vector<PathPlanId> retention_order;
  std::unordered_map<std::string, std::vector<std::string>> subject_index;
  std::unordered_map<std::string, std::vector<std::string>> capability_index;
  std::unordered_map<std::string, std::vector<std::string>> domain_index;
  std::unordered_map<std::string, RequestGeneration> request_generations;
  std::vector<std::string> request_generation_order;
  // Reverse dependency index accounting. When the configured ceiling is reached the
  // index is incomplete, and every invalidation falls back to the explicit conservative
  // path instead of pretending the dependency information is complete.
  std::size_t reverse_entries = 0;
  bool reverse_index_complete = true;

  void Notify(PlanningStage stage, const PlanningRequestId& request) const {
    if (hooks.on_stage) {
      hooks.on_stage(stage, request);
    }
  }

  void IndexPlan(const PathPlan& plan) {
    const std::string key = PlanKey(plan.id);
    const PlanDependencies dependencies = CollectPlanDependencies(plan);
    for (const SubjectKey& subject : dependencies.subjects) {
      if (reverse_entries >= static_cast<std::size_t>(limits.max_reverse_dependency_entries)) {
        reverse_index_complete = false;
        break;
      }
      subject_index[subject.ToString()].push_back(key);
      reverse_entries += 1;
    }
  }

  void UnindexPlan(const PathPlan& plan) {
    const std::string key = PlanKey(plan.id);
    const PlanDependencies dependencies = CollectPlanDependencies(plan);
    for (const SubjectKey& subject : dependencies.subjects) {
      auto it = subject_index.find(subject.ToString());
      if (it == subject_index.end()) {
        continue;
      }
      std::vector<std::string>& entries = it->second;
      const std::size_t before = entries.size();
      entries.erase(std::remove(entries.begin(), entries.end(), key), entries.end());
      const std::size_t removed = before - entries.size();
      reverse_entries = removed > reverse_entries ? 0 : reverse_entries - removed;
      if (entries.empty()) {
        subject_index.erase(it);
      }
    }
  }

  PlanningGeneration NextGeneration(const PlanningRequestId& request, const Sha256Digest& digest) {
    const std::string key = request.ToString();
    auto it = request_generations.find(key);
    if (it != request_generations.end() && it->second.digest == digest) {
      return it->second.generation;
    }
    PlanningGeneration next(1);
    if (it != request_generations.end()) {
      const std::optional<PlanningGeneration> incremented = CheckedAdd(it->second.generation, PlanningGeneration(1));
      next = incremented.has_value() ? *incremented : it->second.generation;
      it->second.digest = digest;
      it->second.generation = next;
      return next;
    }
    request_generations.emplace(key, RequestGeneration{digest, next});
    request_generation_order.push_back(key);
    while (request_generation_order.size() > static_cast<std::size_t>(limits.max_retained_plans)) {
      const std::string victim = request_generation_order.front();
      request_generation_order.erase(request_generation_order.begin());
      request_generations.erase(victim);
    }
    return next;
  }
};

PlannerRuntime::PlannerRuntime(PlannerConfig config) : impl_(std::make_unique<Impl>()) {
  impl_->limits = config.limits;
  impl_->snapshot = std::move(config.initial_snapshot);
  impl_->authority = std::move(config.path_authority);
  impl_->hooks = std::move(config.hooks);
  impl_->publish_sequence = PlanPublishSequence(0);
  if (impl_->snapshot != nullptr) {
    impl_->epoch = impl_->snapshot->Generations().epoch;
  }
}

PlannerRuntime::~PlannerRuntime() = default;

void PlannerRuntime::PublishSnapshot(std::shared_ptr<const FabricSnapshot> snapshot) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->snapshot = std::move(snapshot);
  impl_->publish_sequence = PlanPublishSequence(impl_->publish_sequence.Value() + 1);
  impl_->stats.snapshots_published += 1;
  if (impl_->snapshot != nullptr) {
    impl_->epoch = impl_->snapshot->Generations().epoch;
  }
}

std::shared_ptr<const FabricSnapshot> PlannerRuntime::CurrentSnapshot() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->snapshot;
}

FabricEpoch PlannerRuntime::CurrentEpoch() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->epoch;
}

PlanPublishSequence PlannerRuntime::PublishSequence() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->publish_sequence;
}

ResourceLimits PlannerRuntime::Limits() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->limits;
}

PlannerStatistics PlannerRuntime::Stats() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->stats;
}

void PlannerRuntime::ResetStats() {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->stats = PlannerStatistics{};
}

namespace {

struct ResolvedEndpoint {
  const EndpointRecord* record = nullptr;
  const NodeRecord* node = nullptr;
  bool ok = false;
  PlanStatus status = PlanStatus::kSourceUnknown;
  DiagnosticCode code = DiagnosticCode::kUnknownEndpoint;
  std::string detail;
};

ResolvedEndpoint ResolveEndpoint(const FabricSnapshot& snapshot, const EndpointRef& ref, bool is_source) {
  ResolvedEndpoint resolved;
  resolved.status = is_source ? PlanStatus::kSourceUnknown : PlanStatus::kDestinationUnknown;
  const EndpointRecord* record = snapshot.FindEndpoint(ref.id);
  if (record == nullptr) {
    resolved.code = DiagnosticCode::kUnknownEndpoint;
    resolved.detail = std::string(is_source ? "source" : "destination") +
                      " endpoint has no published binding: " + ref.id.ToString();
    return resolved;
  }
  if (record->endpoint_class != ref.endpoint_class) {
    resolved.status = PlanStatus::kUnsupported;
    resolved.code = DiagnosticCode::kUnsupportedEndpointClass;
    resolved.detail = std::string(is_source ? "source" : "destination") +
                      " endpoint class mismatch: requested " + std::string(ToString(ref.endpoint_class)) +
                      ", published " + std::string(ToString(record->endpoint_class));
    return resolved;
  }
  if (record->entity_generation != ref.generation) {
    resolved.status = is_source ? PlanStatus::kSourceStale : PlanStatus::kDestinationStale;
    resolved.code = DiagnosticCode::kEntityGenerationMismatch;
    resolved.detail = std::string(is_source ? "source" : "destination") + " endpoint generation " +
                      ref.generation.ToString() + " does not match published generation " +
                      record->entity_generation.ToString();
    return resolved;
  }
  const NodeRecord* node = snapshot.FindNode(record->node);
  if (node == nullptr) {
    resolved.code = DiagnosticCode::kUnknownEndpoint;
    resolved.detail = std::string(is_source ? "source" : "destination") +
                      " endpoint resolves to an unknown node";
    return resolved;
  }
  resolved.record = record;
  resolved.node = node;
  resolved.ok = true;
  return resolved;
}

void MergeStats(PlannerStatistics& target, const PlannerStatistics& source) {
  target.plans_computed += source.plans_computed;
  target.plans_published += source.plans_published;
  target.plans_publish_rejected_stale += source.plans_publish_rejected_stale;
  target.candidates_returned += source.candidates_returned;
  target.states_expanded += source.states_expanded;
  target.queue_pushes += source.queue_pushes;
  target.spur_searches += source.spur_searches;
  target.snapshots_published += source.snapshots_published;
  target.epochs_advanced += source.epochs_advanced;
  target.invalidations_applied += source.invalidations_applied;
  target.plans_retired += source.plans_retired;
}

}  // namespace

PlanningResult PlannerRuntime::Plan(const PlanningRequest& request) {
  PlanningResult result;
  PlannerStatistics local_stats;
  ResourceLimits limits;
  std::shared_ptr<const FabricSnapshot> snapshot;
  PlanPublishSequence captured_sequence;
  FabricEpoch epoch;
  std::shared_ptr<IPathAuthority> authority;
  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    limits = impl_->limits;
    snapshot = impl_->snapshot;
    captured_sequence = impl_->publish_sequence;
    epoch = impl_->epoch;
    authority = impl_->authority;
    impl_->stats.plans_computed += 1;
  }
  impl_->Notify(PlanningStage::kDecoded, request.id);

  const RequestValidation validation = ValidateRequest(request, limits);
  if (!validation.ok()) {
    result.status = StatusForValidationCode(*validation.code);
    result.primary_failure = validation.code;
    result.explanations.push_back(ExplanationEntry{*validation.code, validation.detail});
    return result;
  }

  if (request.authority.enforce_scope &&
      !HasScope(request.authority.scope_mask, AuthorityScope::kSubmitPlanRequest)) {
    result.status = PlanStatus::kUnauthorized;
    result.primary_failure = DiagnosticCode::kAuthorityScopeInsufficient;
    result.explanations.push_back(ExplanationEntry{DiagnosticCode::kAuthorityScopeInsufficient,
                                                   "caller authority does not include kSubmitPlanRequest"});
    return result;
  }
  impl_->Notify(PlanningStage::kAuthorityChecked, request.id);

  // The coordinator epoch a caller was issued is mirrored into the Fabric Epoch of the
  // snapshot that coordinator published, so the fence is a numeric comparison across
  // two identity domains. The conversion is explicit by design.
  const bool coordinator_epoch_matches =
      request.authority.coordinator_epoch.Value() == epoch.Value();
  if (request.authority.epoch_bound && !coordinator_epoch_matches) {
    result.status = PlanStatus::kEpochStale;
    result.primary_failure = DiagnosticCode::kEpochMismatch;
    result.explanations.push_back(ExplanationEntry{
        DiagnosticCode::kEpochMismatch, "request carries coordinator epoch " +
                                            request.authority.coordinator_epoch.ToString() +
                                            " but the runtime epoch is " + epoch.ToString()});
    return result;
  }

  if (snapshot == nullptr) {
    result.status = PlanStatus::kRevalidationRequired;
    result.primary_failure = DiagnosticCode::kSnapshotNotAvailable;
    result.explanations.push_back(ExplanationEntry{DiagnosticCode::kSnapshotNotAvailable,
                                                   "no fabric snapshot has been published to this runtime"});
    return result;
  }

  if (request.expect_epoch && request.expected_epoch != snapshot->Generations().epoch) {
    result.status = PlanStatus::kEpochStale;
    result.primary_failure = DiagnosticCode::kEpochMismatch;
    result.explanations.push_back(ExplanationEntry{
        DiagnosticCode::kEpochMismatch, "request expects fabric epoch " + request.expected_epoch.ToString() +
                                            " but the captured snapshot carries " +
                                            snapshot->Generations().epoch.ToString()});
    return result;
  }
  if (request.expect_topology && request.expected_topology != snapshot->Generations().topology) {
    result.status = PlanStatus::kTopologyStale;
    result.primary_failure = DiagnosticCode::kTopologyGenerationMismatch;
    result.explanations.push_back(ExplanationEntry{
        DiagnosticCode::kTopologyGenerationMismatch, "request expects topology generation " +
                                                         request.expected_topology.ToString() +
                                                         " but the captured snapshot carries " +
                                                         snapshot->Generations().topology.ToString()});
    return result;
  }
  if (request.expect_snapshot && request.expected_snapshot != snapshot->Id()) {
    result.status = PlanStatus::kRevalidationRequired;
    result.primary_failure = DiagnosticCode::kStaleEvidence;
    result.explanations.push_back(ExplanationEntry{
        DiagnosticCode::kStaleEvidence, "request expects snapshot " + request.expected_snapshot.ToString() +
                                            " but the captured snapshot is " + snapshot->Id().ToString()});
    return result;
  }

  const ResolvedEndpoint source = ResolveEndpoint(*snapshot, request.source, true);
  if (!source.ok) {
    result.status = source.status;
    result.primary_failure = source.code;
    result.explanations.push_back(ExplanationEntry{source.code, source.detail});
    return result;
  }
  const ResolvedEndpoint destination = ResolveEndpoint(*snapshot, request.destination, false);
  if (!destination.ok) {
    result.status = destination.status;
    result.primary_failure = destination.code;
    result.explanations.push_back(ExplanationEntry{destination.code, destination.detail});
    return result;
  }
  result.source_endpoint = source.record->id;
  result.destination_endpoint = destination.record->id;
  result.source_node = source.node->id;
  result.destination_node = destination.node->id;
  impl_->Notify(PlanningStage::kEndpointsResolved, request.id);

  result.evidence = snapshot->Evidence();
  result.evidence.publish_sequence = captured_sequence;
  result.requested_candidates = request.max_candidates;
  result.diagnostic_mode = request.mode == PlanningMode::kDiagnosticNonCurrent;
  impl_->Notify(PlanningStage::kSnapshotCaptured, request.id);

  std::uint32_t source_view = internal::kInvalidIndex;
  std::uint32_t destination_view = internal::kInvalidIndex;
  internal::PlanningViewBuild build = internal::BuildPlanningView(*snapshot, request, limits, source.node->id,
                                                                  destination.node->id, source_view,
                                                                  destination_view);
  for (const ExplanationEntry& entry : build.explanations) {
    result.explanations.push_back(entry);
  }
  if (!build.ok()) {
    result.status = PlanStatus::kConstraintUnsatisfied;
    result.primary_failure = build.fatal;
    result.explanations.push_back(ExplanationEntry{*build.fatal, build.detail});
    return result;
  }
  const internal::PlanningView& view = build.view;
  impl_->Notify(PlanningStage::kViewBuilt, request.id);

  // A caller-supplied max_hops is enforced exactly. Without one there is no hop bound:
  // limits.max_hops bounds the accepted request value, not the plan.
  const std::uint32_t max_hops = request.constraints.max_hops.has_value() ? request.constraints.max_hops->Value()
                                                                          : internal::kNoHopBound;
  const bool identity_request = source_view == destination_view;
  const bool transit_requested = !request.constraints.required_transit.empty();

  std::vector<Candidate> candidates;
  bool truncated = false;
  std::optional<DiagnosticCode> enumeration_failure;
  std::string enumeration_detail;
  bool enumeration_resource_limit = false;

  if (identity_request && !transit_requested && request.policy.allow_zero_hop_self_path) {
    internal::RawPath zero_hop;
    zero_hop.nodes.push_back(source_view);
    Candidate candidate;
    candidate.path = internal::BuildCandidatePath(view, zero_hop);
    candidate.cost = *internal::ComputeRawPathCost(view, zero_hop);
    candidate.id = candidate.path.Id();
    candidates.push_back(std::move(candidate));
  } else if (identity_request && !transit_requested) {
    enumeration_failure = DiagnosticCode::kZeroHopSelfPathDisallowed;
    enumeration_detail = "source and destination resolve to the same node and zero-hop self paths are disabled";
  } else {
    internal::EnumerationOptions options;
    options.source_view = source_view;
    options.destination_view = destination_view;
    options.max_candidates = request.max_candidates;
    options.max_hops = max_hops;
    options.domain_member_limit_active = request.constraints.max_members_per_failure_domain.has_value();
    options.enumeration_ceiling = options.domain_member_limit_active
                                      ? std::max(request.max_candidates, limits.max_enumeration_candidates)
                                      : request.max_candidates;
    internal::WorkBudget budget;
    budget.states_remaining = limits.max_expanded_states;
    budget.pushes_remaining = limits.max_queue_entries;
    budget.spur_remaining = limits.max_spur_searches;
    const internal::EnumerationResult enumeration =
        internal::EnumerateCandidatePaths(view, request, options, budget, local_stats);
    truncated = enumeration.truncated;
    if (enumeration.ok || enumeration.resource_limit) {
      for (const internal::RawPath& raw : enumeration.paths) {
        CandidatePath path = internal::BuildCandidatePath(view, raw);
        const std::optional<PathCost> cost = internal::ComputeRawPathCost(view, raw);
        if (!cost.has_value() || !path.IsWellFormed() || !path.IsSimple()) {
          continue;
        }
        Candidate candidate;
        candidate.path = std::move(path);
        candidate.cost = *cost;
        candidate.id = candidate.path.Id();
        candidates.push_back(std::move(candidate));
      }
    }
    if (!enumeration.ok) {
      enumeration_failure = enumeration.failure;
      enumeration_detail = enumeration.detail;
      enumeration_resource_limit = enumeration.resource_limit;
    }
    if (budget.exhausted) {
      enumeration_resource_limit = true;
      if (!enumeration_failure.has_value()) {
        enumeration_failure = DiagnosticCode::kWorkBudgetExhausted;
      }
      enumeration_detail = "deterministic work budget exhausted";
    }
  }

  std::sort(candidates.begin(), candidates.end(),
            [](const Candidate& lhs, const Candidate& rhs) { return RanksBefore(lhs, rhs); });
  candidates.erase(std::unique(candidates.begin(), candidates.end(),
                               [](const Candidate& lhs, const Candidate& rhs) { return lhs.id == rhs.id; }),
                   candidates.end());
  if (candidates.size() > request.max_candidates) {
    candidates.resize(request.max_candidates);
  }

  const Currentness baseline_currentness =
      view.provisional ? Currentness::kRevalidationRequired : Currentness::kCurrent;
  for (std::size_t index = 0; index < candidates.size(); ++index) {
    Candidate& candidate = candidates[index];
    candidate.rank = CandidateRank(static_cast<std::uint32_t>(index) + 1);
    candidate.evidence = result.evidence;
    candidate.currentness = baseline_currentness;
    candidate.provenance.constraint_set = request.constraints.id;
    candidate.provenance.constraint_generation = request.constraints.generation;
    candidate.provenance.policy_generation = request.policy.generation;
    candidate.provenance.source = snapshot->Source();
    candidate.provenance.planning_rule_version = kPlanningRuleVersion;
    candidate.provenance.path_encoding_version = kPathEncodingVersion;
    if (view.provisional) {
      candidate.notes.push_back(DiagnosticCode::kNonCurrentCandidate);
    }
  }
  impl_->Notify(PlanningStage::kSearchCompleted, request.id);

  // Path Authority integration is explicit and never implicit.
  if (request.policy.authority_validation != AuthorityValidationMode::kNone && !candidates.empty()) {
    if (authority == nullptr) {
      for (Candidate& candidate : candidates) {
        candidate.authority = AuthorityValidation::kUnavailable;
        candidate.notes.push_back(DiagnosticCode::kAuthorityValidationUnavailable);
      }
      if (request.policy.authority_validation == AuthorityValidationMode::kRequired) {
        result.status = PlanStatus::kUnsupported;
        result.primary_failure = DiagnosticCode::kAuthorityValidationUnavailable;
        result.explanations.push_back(ExplanationEntry{
            DiagnosticCode::kAuthorityValidationUnavailable,
            "authority validation is required but no Path Authority port is configured"});
        return result;
      }
    } else {
      std::vector<Candidate> validated;
      bool rejected_any = false;
      for (Candidate& candidate : candidates) {
        std::string reason;
        candidate.authority = authority->ValidatePath(candidate.path, result.evidence, reason);
        switch (candidate.authority) {
          case AuthorityValidation::kValidated:
            validated.push_back(std::move(candidate));
            break;
          case AuthorityValidation::kRejected:
            candidate.notes.push_back(DiagnosticCode::kAuthorityValidationRejected);
            rejected_any = true;
            break;
          case AuthorityValidation::kUnavailable:
          case AuthorityValidation::kNotRequested:
            candidate.notes.push_back(DiagnosticCode::kAuthorityValidationUnavailable);
            if (request.policy.authority_validation == AuthorityValidationMode::kBestEffort) {
              validated.push_back(std::move(candidate));
            }
            break;
        }
      }
      candidates = std::move(validated);
      if (candidates.empty() && rejected_any) {
        result.status = PlanStatus::kRevalidationRequired;
        result.primary_failure = DiagnosticCode::kAuthorityValidationRejected;
        result.explanations.push_back(
            ExplanationEntry{DiagnosticCode::kAuthorityValidationRejected,
                             "Path Authority rejected every computed candidate path"});
        result.rejections = view.rejections.Render();
        result.truncated = truncated;
        return result;
      }
      for (std::size_t index = 0; index < candidates.size(); ++index) {
        candidates[index].rank = CandidateRank(static_cast<std::uint32_t>(index) + 1);
      }
    }
  }
  impl_->Notify(PlanningStage::kScored, request.id);
  impl_->Notify(PlanningStage::kRanked, request.id);

  result.truncated = truncated;
  if (candidates.empty()) {
    const std::optional<std::uint32_t> structural_distance =
        StructuralHopDistance(*snapshot, source.node->id, destination.node->id, request);
    const bool structural = structural_distance.has_value();
    // A path can exist while the requested hop bound makes it unreachable: in that case the
    // hop bound is the reason, not missing connectivity.
    const bool hop_bound_exceeded = structural && request.constraints.max_hops.has_value() &&
                                     *structural_distance > request.constraints.max_hops->Value();
    DiagnosticCode primary = DiagnosticCode::kNoStructuralPath;
    if (enumeration_failure.has_value() && *enumeration_failure != DiagnosticCode::kNoStructuralPath) {
      primary = *enumeration_failure;
    } else if (hop_bound_exceeded) {
      primary = DiagnosticCode::kMaxHopsExceeded;
      result.explanations.push_back(ExplanationEntry{
          DiagnosticCode::kMaxHopsExceeded,
          "the shortest structural path needs " + std::to_string(*structural_distance) +
              " hops, which exceeds max_hops=" + request.constraints.max_hops->ToString()});
    } else if (enumeration_failure.has_value() && *enumeration_failure != DiagnosticCode::kNoStructuralPath) {
      primary = *enumeration_failure;
    } else {
      // A bare "no path" from the search is not a cause: PrimaryFailure names the exact
      // reason (forbidden entity, layer mismatch, link/port state, capability, failure
      // domain) and only falls back to NO_STRUCTURAL_PATH when nothing was excluded.
      primary = PrimaryFailure(view, structural);
    }
    result.status = enumeration_resource_limit ? PlanStatus::kResourceLimit : StatusForFailure(primary);
    result.primary_failure = primary;
    if (!enumeration_detail.empty()) {
      result.explanations.push_back(ExplanationEntry{primary, enumeration_detail});
    }
  } else {
    result.status = view.provisional ? PlanStatus::kRevalidationRequired : PlanStatus::kPlanned;
    if (truncated) {
      result.status = PlanStatus::kTruncatedByLimit;
      result.explanations.push_back(ExplanationEntry{
          DiagnosticCode::kTruncatedByLimit,
          "candidate enumeration stopped at the configured enumeration ceiling"});
    }
  }
  result.rejections = view.rejections.Render();
  result.candidates = std::move(candidates);

  // The pre-publication stage is notified before the compare-before-publish decision, so a
  // stage observer can act on the window in which the plan has been computed but not yet
  // published as current.
  impl_->Notify(PlanningStage::kBeforePublish, request.id);

  // Compare-before-publish: an in-flight plan must not become CURRENT after an
  // input was invalidated while it was being computed.
  bool watermark_changed = false;
  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->publish_sequence != captured_sequence) {
      watermark_changed = true;
    } else if (impl_->snapshot != nullptr && impl_->snapshot->Id() != snapshot->Id()) {
      watermark_changed = true;
    }
  }
  if (watermark_changed) {
    for (Candidate& candidate : result.candidates) {
      candidate.currentness = Currentness::kRevalidationRequired;
    }
    result.status = PlanStatus::kRevalidationRequired;
    result.explanations.push_back(ExplanationEntry{
        DiagnosticCode::kInvalidationWatermarkChanged,
        "the publication watermark changed while the plan was being computed; the result is not CURRENT"});
    local_stats.plans_publish_rejected_stale += 1;
  }

  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    const PathPlan provisional = MakePathPlan(request, result, captured_sequence);
    result.semantic_digest = provisional.semantic_digest;
    result.plan_id = provisional.id;
    const PlanningGeneration generation = impl_->NextGeneration(request.id, provisional.semantic_digest);
    result.planning_generation = generation;
    for (Candidate& candidate : result.candidates) {
      candidate.provenance.planning_generation = generation;
    }
    local_stats.plans_published += 1;
    local_stats.candidates_returned += result.candidates.size();
    MergeStats(impl_->stats, local_stats);
  }
  impl_->Notify(PlanningStage::kPublished, request.id);
  return result;
}

bool PlannerRuntime::Retain(const PathPlan& plan) {
  if (!plan.id.IsValid()) {
    return false;
  }
  std::lock_guard<std::mutex> lock(impl_->mutex);
  const std::string key = PlanKey(plan.id);
  const Currentness initial =
      plan.currentness_proven ? Currentness::kCurrent : Currentness::kRevalidationRequired;
  const auto existing = impl_->retained.find(key);
  if (existing != impl_->retained.end()) {
    existing->second.plan = plan;
    existing->second.currentness = initial;
    return true;
  }
  while (impl_->retained.size() >= static_cast<std::size_t>(impl_->limits.max_retained_plans) &&
         !impl_->retention_order.empty()) {
    const PathPlanId victim = impl_->retention_order.front();
    impl_->retention_order.erase(impl_->retention_order.begin());
    const auto victim_entry = impl_->retained.find(PlanKey(victim));
    if (victim_entry == impl_->retained.end()) {
      continue;
    }
    impl_->UnindexPlan(victim_entry->second.plan);
    impl_->retained.erase(victim_entry);
    impl_->stats.plans_retired += 1;
  }
  impl_->IndexPlan(plan);
  impl_->retained.emplace(key, Impl::RetainedPlan{plan, initial});
  impl_->retention_order.push_back(plan.id);
  return true;
}

std::optional<PathPlan> PlannerRuntime::FindPlan(const PathPlanId& id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto it = impl_->retained.find(PlanKey(id));
  if (it == impl_->retained.end()) {
    return std::nullopt;
  }
  return it->second.plan;
}

std::size_t PlannerRuntime::RetainedPlanCount() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->retained.size();
}

namespace {

bool SubjectStillPresent(const FabricSnapshot& snapshot, const SubjectKey& subject) {
  if (const std::optional<NodeId> node = subject.AsNode(); node.has_value()) {
    return snapshot.FindNode(*node) != nullptr;
  }
  if (const std::optional<LinkId> link = subject.AsLink(); link.has_value()) {
    return snapshot.FindEdge(*link) != nullptr;
  }
  if (const std::optional<PortId> port = subject.AsPort(); port.has_value()) {
    for (const NodeRecord& node : snapshot.Nodes()) {
      if (std::binary_search(node.ports.begin(), node.ports.end(), *port)) {
        return true;
      }
    }
    return false;
  }
  return false;
}

}  // namespace

InvalidationReport PlannerRuntime::ApplyInvalidation(const InvalidationNotice& notice) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  InvalidationReport report;
  report.conservative = notice.conservative_all;
  impl_->stats.invalidations_applied += 1;
  // An invalidation is an input change: the publication watermark advances so that
  // in-flight planning cannot publish as CURRENT.
  impl_->publish_sequence = PlanPublishSequence(impl_->publish_sequence.Value() + 1);

  std::vector<std::string> affected_keys;
  const bool conservative = notice.conservative_all || !notice.capabilities.empty() ||
                            !notice.failure_domains.empty() || !impl_->reverse_index_complete;
  if (conservative) {
    // Explicit conservative fallback: capability and failure-domain publications do
    // not carry per-plan dependency records, so every retained plan is invalidated.
    report.conservative = true;
    affected_keys.reserve(impl_->retained.size());
    for (const auto& entry : impl_->retained) {
      affected_keys.push_back(entry.first);
    }
  } else {
    auto collect = [this, &affected_keys](const std::string& subject_key) {
      const auto it = impl_->subject_index.find(subject_key);
      if (it == impl_->subject_index.end()) {
        return;
      }
      affected_keys.insert(affected_keys.end(), it->second.begin(), it->second.end());
    };
    for (const NodeId& id : notice.nodes) {
      collect(SubjectKey::ForNode(id).ToString());
    }
    for (const LinkId& id : notice.links) {
      collect(SubjectKey::ForLink(id).ToString());
    }
    for (const PortId& id : notice.ports) {
      collect(SubjectKey::ForPort(id).ToString());
    }
  }
  std::sort(affected_keys.begin(), affected_keys.end());
  affected_keys.erase(std::unique(affected_keys.begin(), affected_keys.end()), affected_keys.end());

  for (const std::string& key : affected_keys) {
    const auto it = impl_->retained.find(key);
    if (it == impl_->retained.end()) {
      continue;
    }
    bool retired = false;
    if (impl_->snapshot != nullptr) {
      for (const SubjectKey& subject : CollectPlanDependencies(it->second.plan).subjects) {
        if (!SubjectStillPresent(*impl_->snapshot, subject)) {
          retired = true;
          break;
        }
      }
    }
    it->second.currentness = retired ? Currentness::kRetired : Currentness::kRevalidationRequired;
    report.affected.push_back(it->second.plan.id);
    if (retired) {
      report.retired.push_back(it->second.plan.id);
      impl_->stats.plans_retired += 1;
    } else {
      report.marked_revalidation_required.push_back(it->second.plan.id);
    }
  }
  report.retained_plans = impl_->retained.size();
  return report;
}

bool PlannerRuntime::AdvanceEpoch(FabricEpoch epoch, bool conservative_recovery, std::string& reason) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  if (epoch <= impl_->epoch) {
    reason = "epoch " + epoch.ToString() + " is not greater than the current epoch " + impl_->epoch.ToString();
    return false;
  }
  impl_->epoch = epoch;
  impl_->publish_sequence = PlanPublishSequence(impl_->publish_sequence.Value() + 1);
  impl_->stats.epochs_advanced += 1;
  if (conservative_recovery) {
    for (auto& entry : impl_->retained) {
      entry.second.currentness = Currentness::kRevalidationRequired;
    }
    reason = "epoch advanced to " + epoch.ToString() +
             " with conservative recovery: every retained plan requires revalidation";
  } else {
    reason = "epoch advanced to " + epoch.ToString();
  }
  return true;
}

PlanCurrentnessReport PlannerRuntime::CheckCurrentness(const PathPlan& plan) const {
  PlanCurrentnessReport report;
  report.prior_evidence = plan.evidence;
  std::shared_ptr<const FabricSnapshot> snapshot;
  PlanPublishSequence sequence;
  std::optional<Currentness> retained_currentness;
  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    snapshot = impl_->snapshot;
    sequence = impl_->publish_sequence;
    const auto it = impl_->retained.find(PlanKey(plan.id));
    if (it != impl_->retained.end()) {
      retained_currentness = it->second.currentness;
    }
  }

  EvidenceVector current_evidence;
  if (snapshot != nullptr) {
    current_evidence = snapshot->Evidence();
  }
  current_evidence.publish_sequence = sequence;
  report.current_evidence = current_evidence;

  if (plan.diagnostic_mode) {
    report.currentness = Currentness::kRevalidationRequired;
    report.changes.push_back(ExplanationEntry{DiagnosticCode::kNonCurrentCandidate,
                                              "the plan was computed in diagnostic mode and is not CURRENT"});
  }
  if (snapshot == nullptr) {
    report.currentness = MoreSevere(report.currentness, Currentness::kRevalidationRequired);
    report.changes.push_back(ExplanationEntry{DiagnosticCode::kSnapshotNotAvailable,
                                              "no fabric snapshot is currently published"});
    return report;
  }

  for (const SubjectKey& subject : CollectPlanDependencies(plan).subjects) {
    if (!SubjectStillPresent(*snapshot, subject)) {
      report.currentness = Currentness::kRetired;
      report.changes.push_back(ExplanationEntry{DiagnosticCode::kPlanRetired,
                                                "dependency no longer exists: " + subject.ToString()});
      return report;
    }
  }

  if (retained_currentness.has_value()) {
    if (*retained_currentness == Currentness::kRetired) {
      report.currentness = Currentness::kRetired;
      report.changes.push_back(ExplanationEntry{DiagnosticCode::kPlanRetired,
                                                "the retained plan was invalidated by subject removal"});
      return report;
    }
    if (*retained_currentness == Currentness::kRevalidationRequired) {
      report.currentness = MoreSevere(report.currentness, Currentness::kRevalidationRequired);
      report.changes.push_back(ExplanationEntry{DiagnosticCode::kStaleEvidence,
                                                "the retained plan was invalidated by a targeted notice"});
    }
  }

  const std::vector<ExplanationEntry> differences = DiffEvidence(plan.evidence, current_evidence);
  for (const ExplanationEntry& entry : differences) {
    report.changes.push_back(entry);
  }
  const Currentness classified = ClassifyEvidence(plan.evidence, current_evidence);
  if (classified != Currentness::kCurrent) {
    report.currentness = MoreSevere(report.currentness, classified);
  } else if (plan.evidence.publish_sequence != current_evidence.publish_sequence &&
             report.currentness == Currentness::kCurrent) {
    report.currentness = Currentness::kRevalidationRequired;
  }
  return report;
}

bool PlannerRuntime::Replan(const PathPlan& prior, const PlanningRequest& request, PlanningResult& result,
                            ReplanReport& report) {
  result = Plan(request);
  report.prior_digest = prior.semantic_digest;
  report.current_digest = result.semantic_digest;
  report.same_semantic_plan = !prior.semantic_digest.IsZero() && prior.semantic_digest == result.semantic_digest;
  report.changes = DiffEvidence(prior.evidence, result.evidence);

  if (result.status == PlanStatus::kMalformedRequest || result.status == PlanStatus::kUnauthorized) {
    report.outcome = ReplanOutcome::kNoPath;
    return false;
  }
  if (result.status == PlanStatus::kRevalidationRequired) {
    report.outcome = ReplanOutcome::kRevalidationRequired;
    return true;
  }
  if (result.candidates.empty()) {
    report.outcome = ReplanOutcome::kNoPath;
    return true;
  }
  if (report.same_semantic_plan) {
    report.outcome = ReplanOutcome::kUnchanged;
    return true;
  }
  std::vector<CandidatePathId> prior_ids;
  std::vector<CandidatePathId> current_ids;
  for (const Candidate& candidate : prior.candidates) {
    prior_ids.push_back(candidate.id);
  }
  for (const Candidate& candidate : result.candidates) {
    current_ids.push_back(candidate.id);
  }
  if (prior_ids == current_ids) {
    report.outcome = ReplanOutcome::kUnchanged;
    return true;
  }
  std::vector<CandidatePathId> sorted_prior = prior_ids;
  std::vector<CandidatePathId> sorted_current = current_ids;
  std::sort(sorted_prior.begin(), sorted_prior.end());
  std::sort(sorted_current.begin(), sorted_current.end());
  report.outcome =
      sorted_prior == sorted_current ? ReplanOutcome::kOrderingChanged : ReplanOutcome::kCandidateSetChanged;
  return true;
}

}  // namespace summon::pathplanner



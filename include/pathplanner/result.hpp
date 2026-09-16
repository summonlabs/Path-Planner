#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "pathplanner/canonical.hpp"
#include "pathplanner/graph.hpp"
#include "pathplanner/ids.hpp"
#include "pathplanner/path.hpp"
#include "pathplanner/request.hpp"
#include "pathplanner/status.hpp"

namespace summon::pathplanner {

// Structured, renderable explanation entry.
struct ExplanationEntry {
  DiagnosticCode code;
  std::string detail;
};

// A hard-constraint rejection, aggregated deterministically by cause and subject.
struct RejectionExplanation {
  DiagnosticCode code;
  SubjectKey subject;
  std::string detail;
  std::uint64_t occurrences = 1;
};

// ---------------------------------------------------------------------------
// PlanningResult: structured outcome. Never an empty value that forces callers
// to guess why planning did not produce candidates.
// ---------------------------------------------------------------------------
struct PlanningResult {
  PlanStatus status = PlanStatus::kNoPath;
  // Deterministic primary failure classification when no candidate was produced.
  std::optional<DiagnosticCode> primary_failure;
  // Resolved endpoint bindings (nil when resolution failed).
  EndpointId source_endpoint;
  EndpointId destination_endpoint;
  NodeId source_node;
  NodeId destination_node;
  std::vector<Candidate> candidates;
  std::vector<RejectionExplanation> rejections;
  std::vector<ExplanationEntry> explanations;
  EvidenceVector evidence;
  PathPlanId plan_id;
  PlanningGeneration planning_generation;
  Sha256Digest semantic_digest;
  std::uint32_t requested_candidates = 0;
  bool truncated = false;
  bool diagnostic_mode = false;

  bool HasCandidates() const noexcept { return CarriesCandidates(status); }
  std::string_view StatusName() const noexcept { return ToString(status); }
};

// ---------------------------------------------------------------------------
// PathPlan: first-class immutable planning value.
// ---------------------------------------------------------------------------
struct PathPlan {
  PathPlanId id;
  PlanningRequestId request;
  PlanningGeneration generation;
  PlanPublishSequence publish_sequence;
  PlanStatus status = PlanStatus::kNoPath;
  NodeId source;
  NodeId destination;
  PathLayer layer = PathLayer::kPhysical;
  EvidenceVector evidence;
  PolicyGeneration policy_generation;
  ConstraintSetId constraint_set;
  ConstraintGeneration constraint_generation;
  bool diagnostic_mode = false;
  // False when the plan was published without proven currentness (for example
  // diagnostic mode or an invalidation watermark change).
  bool currentness_proven = true;
  std::vector<Candidate> candidates;
  Sha256Digest semantic_digest;

  // Semantic encoding: request identity, evidence generations, status and the
  // ordered candidate identities with their costs. Publication sequence and
  // runtime generation are deliberately excluded: an exact recomputation under
  // unchanged evidence yields the same semantic digest.
  void EncodeSemantic(ByteWriter& writer) const;
  Sha256Digest ComputeSemanticDigest() const;
  PathPlanId ComputePlanId() const;
  bool HasCandidate(const CandidatePathId& candidate) const noexcept;
};

PathPlan MakePathPlan(const PlanningRequest& request, const PlanningResult& result, PlanPublishSequence sequence);

// Dependencies consulted while computing a plan. Maintained as a reverse index so
// a targeted invalidation does not have to retire unrelated plans.
struct PlanDependencies {
  std::vector<SubjectKey> subjects;
  std::vector<CapabilityId> capabilities;
  std::vector<FailureDomainId> failure_domains;
};

PlanDependencies CollectPlanDependencies(const PathPlan& plan);

// ---------------------------------------------------------------------------
// Currentness.
// ---------------------------------------------------------------------------
struct PlanCurrentnessReport {
  Currentness currentness = Currentness::kCurrent;
  std::vector<ExplanationEntry> changes;
  EvidenceVector prior_evidence;
  EvidenceVector current_evidence;
  bool current() const noexcept { return currentness == Currentness::kCurrent; }
};

// ---------------------------------------------------------------------------
// Replanning.
// ---------------------------------------------------------------------------
struct ReplanReport {
  ReplanOutcome outcome = ReplanOutcome::kUnchanged;
  std::vector<ExplanationEntry> changes;
  Sha256Digest prior_digest;
  Sha256Digest current_digest;
  bool same_semantic_plan = false;
};

std::size_t HashCombinePlan(const PathPlan& plan) noexcept;

}  // namespace summon::pathplanner

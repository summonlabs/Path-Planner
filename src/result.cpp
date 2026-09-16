#include "pathplanner/result.hpp"

#include <algorithm>
#include <string>

#include "pathplanner/version.hpp"

namespace summon::pathplanner {

void PathPlan::EncodeSemantic(ByteWriter& writer) const {
  writer.U32(kPlanningRuleVersion);
  writer.U32(kPlanDigestSchemeVersion);
  writer.FixedBytes(request.Span());
  writer.FixedBytes(source.Span());
  writer.FixedBytes(destination.Span());
  writer.U32(static_cast<std::uint32_t>(layer));
  writer.U32(static_cast<std::uint32_t>(status));
  writer.Bool(diagnostic_mode);
  evidence.Encode(writer);
  writer.U64(policy_generation.Value());
  writer.FixedBytes(constraint_set.Span());
  writer.U64(constraint_generation.Value());
  writer.VarU64(candidates.size());
  for (const Candidate& candidate : candidates) {
    writer.FixedBytes(candidate.id.Span());
    writer.U64(candidate.cost.total.Value());
    writer.U32(candidate.cost.hops.Value());
    writer.U64(candidate.cost.static_cost.Value());
    writer.U64(candidate.cost.degraded_penalty.Value());
    writer.U64(candidate.cost.locality_penalty.Value());
    writer.U32(candidate.rank.Value());
  }
}

Sha256Digest PathPlan::ComputeSemanticDigest() const {
  const std::size_t ceiling = 4096 + candidates.size() * 256;
  ByteWriter writer(ceiling);
  EncodeSemantic(writer);
  if (writer.overflowed()) {
    return Sha256Digest{};
  }
  return Sha256::Hash(writer.span());
}

PathPlanId PathPlan::ComputePlanId() const {
  const Sha256Digest digest = ComputeSemanticDigest();
  if (digest.IsZero()) {
    return PathPlanId{};
  }
  return PathPlanId::FromDigest(digest);
}

bool PathPlan::HasCandidate(const CandidatePathId& candidate) const noexcept {
  for (const Candidate& existing : candidates) {
    if (existing.id == candidate) {
      return true;
    }
  }
  return false;
}

PathPlan MakePathPlan(const PlanningRequest& request, const PlanningResult& result, PlanPublishSequence sequence) {
  PathPlan plan;
  plan.request = request.id;
  plan.evidence = result.evidence;
  plan.generation = result.planning_generation;
  plan.publish_sequence = sequence;
  plan.status = result.status;
  plan.source = result.source_node;
  plan.destination = result.destination_node;
  plan.layer = request.constraints.layer;
  plan.policy_generation = request.policy.generation;
  plan.constraint_set = request.constraints.id;
  plan.constraint_generation = request.constraints.generation;
  plan.diagnostic_mode = request.mode == PlanningMode::kDiagnosticNonCurrent;
  plan.candidates = result.candidates;
  plan.currentness_proven = !plan.diagnostic_mode;
  plan.semantic_digest = plan.ComputeSemanticDigest();
  plan.id = plan.ComputePlanId();
  return plan;
}

PlanDependencies CollectPlanDependencies(const PathPlan& plan) {
  PlanDependencies dependencies;
  for (const Candidate& candidate : plan.candidates) {
    for (const NodeId& node : candidate.path.nodes) {
      dependencies.subjects.push_back(SubjectKey::ForNode(node));
    }
    for (const PathHop& hop : candidate.path.hops) {
      dependencies.subjects.push_back(SubjectKey::ForLink(hop.link));
      dependencies.subjects.push_back(SubjectKey::ForPort(hop.from_port));
      dependencies.subjects.push_back(SubjectKey::ForPort(hop.to_port));
    }
  }
  std::sort(dependencies.subjects.begin(), dependencies.subjects.end());
  dependencies.subjects.erase(std::unique(dependencies.subjects.begin(), dependencies.subjects.end()),
                              dependencies.subjects.end());
  return dependencies;
}

std::size_t HashCombinePlan(const PathPlan& plan) noexcept {
  std::size_t hash = 1469598103934665603ull;
  for (const std::byte b : plan.semantic_digest.bytes) {
    hash ^= static_cast<std::size_t>(static_cast<std::uint8_t>(b));
    hash *= 1099511628211ull;
  }
  return hash;
}

}  // namespace summon::pathplanner

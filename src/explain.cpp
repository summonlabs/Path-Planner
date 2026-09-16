#include "pathplanner/explain.hpp"

#include <string>

#include "pathplanner/version.hpp"

namespace summon::pathplanner {
namespace {

std::string Quote(const std::string& value) { return "\"" + value + "\""; }

void AppendCost(std::string& out, const char* prefix, const PathCost& cost) {
  out += prefix;
  out += " total=" + cost.total.ToString();
  out += " hops=" + cost.hops.ToString();
  out += " hops_cost=" + cost.hops_cost.ToString();
  out += " static_cost=" + cost.static_cost.ToString();
  out += " degraded_penalty=" + cost.degraded_penalty.ToString();
  out += " locality_penalty=" + cost.locality_penalty.ToString();
  out += " degraded_hops=" + std::to_string(cost.degraded_hops);
  out += " locality_breaches=" + std::to_string(cost.locality_breaches);
  out += "\n";
}

}  // namespace

std::string RenderEvidence(const EvidenceVector& evidence) {
  std::string out;
  out += "evidence snapshot=" + evidence.snapshot.ToString() + "\n";
  out += "evidence source=" + std::string(ToString(evidence.source)) + "\n";
  out += "evidence publish_sequence=" + evidence.publish_sequence.ToString() + "\n";
  out += "evidence topology_generation=" + evidence.generations.topology.ToString() + "\n";
  out += "evidence link_state_generation=" + evidence.generations.link_state.ToString() + "\n";
  out += "evidence port_generation=" + evidence.generations.ports.ToString() + "\n";
  out += "evidence capability_generation=" + evidence.generations.capabilities.ToString() + "\n";
  out += "evidence failure_domain_generation=" + evidence.generations.failure_domains.ToString() + "\n";
  out += "evidence fabric_epoch=" + evidence.generations.epoch.ToString() + "\n";
  out += "evidence policy_generation=" + evidence.generations.policy.ToString() + "\n";
  out += "evidence constraint_generation=" + evidence.generations.constraints.ToString() + "\n";
  return out;
}

std::string RenderCandidate(const Candidate& candidate, bool verbose) {
  std::string out;
  out += "candidate rank=" + candidate.rank.ToString() + " id=" + candidate.id.ToString();
  out += " status=" + std::string(CarriesCandidates(PlanStatus::kPlanned) ? "CANDIDATE" : "CANDIDATE");
  out += " currentness=" + std::string(ToString(candidate.currentness));
  out += " authority=" + std::string(ToString(candidate.authority));
  out += "\n";
  AppendCost(out, "candidate cost", candidate.cost);
  out += "candidate path " + candidate.path.Render() + "\n";
  out += "candidate planning_generation=" + candidate.provenance.planning_generation.ToString() +
         " constraint_set=" + candidate.provenance.constraint_set.ToString() +
         " constraint_generation=" + candidate.provenance.constraint_generation.ToString() +
         " policy_generation=" + candidate.provenance.policy_generation.ToString() + "\n";
  for (const DiagnosticCode note : candidate.notes) {
    out += "candidate note " + std::string(ToString(note)) + "\n";
  }
  if (verbose) {
    std::size_t hop_index = 0;
    for (const PathHop& hop : candidate.path.hops) {
      out += "candidate hop " + std::to_string(hop_index) + " link=" + hop.link.ToString() +
             " from=" + hop.from.ToString() + " to=" + hop.to.ToString() +
             " from_port=" + hop.from_port.ToString() + " to_port=" + hop.to_port.ToString() +
             " layer=" + std::string(ToString(hop.layer)) +
             " relationship=" + std::string(ToString(hop.relationship)) +
             " structural_generation=" + hop.structural_generation.ToString() +
             " static_cost=" + hop.static_cost.ToString() +
             " link_state=" + std::string(ToString(hop.link_state)) +
             " degraded=" + (hop.degraded ? "true" : "false") + "\n";
      hop_index += 1;
    }
  }
  return out;
}

std::string RenderRejections(const std::vector<RejectionExplanation>& rejections) {
  std::string out;
  for (const RejectionExplanation& rejection : rejections) {
    out += "rejection code=" + std::string(ToString(rejection.code));
    out += " occurrences=" + std::to_string(rejection.occurrences);
    if (!rejection.subject.ToString().empty()) {
      out += " subject=" + rejection.subject.ToString();
    }
    out += " detail=" + Quote(rejection.detail) + "\n";
  }
  return out;
}

std::string RenderResult(const PlanningResult& result, bool verbose) {
  std::string out;
  out += "status " + std::string(ToString(result.status)) + "\n";
  out += "plan_id " + result.plan_id.ToString() + "\n";
  out += "semantic_digest " + result.semantic_digest.ToHex() + "\n";
  out += "planning_generation " + result.planning_generation.ToString() + "\n";
  out += "requested_candidates " + std::to_string(result.requested_candidates) + "\n";
  out += "returned_candidates " + std::to_string(result.candidates.size()) + "\n";
  out += "truncated " + std::string(result.truncated ? "true" : "false") + "\n";
  out += "diagnostic_mode " + std::string(result.diagnostic_mode ? "true" : "false") + "\n";
  if (result.primary_failure.has_value()) {
    out += "primary_failure " + std::string(ToString(*result.primary_failure)) + "\n";
  }
  out += RenderEvidence(result.evidence);
  for (const Candidate& candidate : result.candidates) {
    out += RenderCandidate(candidate, verbose);
  }
  out += RenderRejections(result.rejections);
  for (const ExplanationEntry& entry : result.explanations) {
    out += "explanation code=" + std::string(ToString(entry.code)) + " detail=" + Quote(entry.detail) + "\n";
  }
  return out;
}

std::string RenderPlan(const PathPlan& plan, bool verbose) {
  std::string out;
  out += "plan_id " + plan.id.ToString() + "\n";
  out += "request " + plan.request.ToString() + "\n";
  out += "status " + std::string(ToString(plan.status)) + "\n";
  out += "planning_generation " + plan.generation.ToString() + "\n";
  out += "publish_sequence " + plan.publish_sequence.ToString() + "\n";
  out += "semantic_digest " + plan.semantic_digest.ToHex() + "\n";
  out += "source_node " + plan.source.ToString() + "\n";
  out += "destination_node " + plan.destination.ToString() + "\n";
  out += "layer " + std::string(ToString(plan.layer)) + "\n";
  out += "diagnostic_mode " + std::string(plan.diagnostic_mode ? "true" : "false") + "\n";
  out += "currentness_proven " + std::string(plan.currentness_proven ? "true" : "false") + "\n";
  out += "candidates " + std::to_string(plan.candidates.size()) + "\n";
  out += RenderEvidence(plan.evidence);
  for (const Candidate& candidate : plan.candidates) {
    out += RenderCandidate(candidate, verbose);
  }
  return out;
}

std::string RenderCurrentness(const PlanCurrentnessReport& report) {
  std::string out;
  out += "currentness " + std::string(ToString(report.currentness)) + "\n";
  for (const ExplanationEntry& entry : report.changes) {
    out += "change code=" + std::string(ToString(entry.code)) + " detail=" + Quote(entry.detail) + "\n";
  }
  return out;
}

std::string RenderReplanReport(const ReplanReport& report) {
  std::string out;
  out += "replan_outcome " + std::string(ToString(report.outcome)) + "\n";
  out += "replan_same_semantic_plan " + std::string(report.same_semantic_plan ? "true" : "false") + "\n";
  out += "replan_prior_digest " + report.prior_digest.ToHex() + "\n";
  out += "replan_current_digest " + report.current_digest.ToHex() + "\n";
  for (const ExplanationEntry& entry : report.changes) {
    out += "replan_change code=" + std::string(ToString(entry.code)) + " detail=" + Quote(entry.detail) + "\n";
  }
  return out;
}

std::string RenderStatistics(const PlannerStatistics& stats) {
  std::string out;
  out += "stat plans_computed=" + std::to_string(stats.plans_computed) + "\n";
  out += "stat plans_published=" + std::to_string(stats.plans_published) + "\n";
  out += "stat plans_publish_rejected_stale=" + std::to_string(stats.plans_publish_rejected_stale) + "\n";
  out += "stat candidates_returned=" + std::to_string(stats.candidates_returned) + "\n";
  out += "stat states_expanded=" + std::to_string(stats.states_expanded) + "\n";
  out += "stat queue_pushes=" + std::to_string(stats.queue_pushes) + "\n";
  out += "stat spur_searches=" + std::to_string(stats.spur_searches) + "\n";
  out += "stat snapshots_published=" + std::to_string(stats.snapshots_published) + "\n";
  out += "stat epochs_advanced=" + std::to_string(stats.epochs_advanced) + "\n";
  out += "stat invalidations_applied=" + std::to_string(stats.invalidations_applied) + "\n";
  out += "stat plans_retired=" + std::to_string(stats.plans_retired) + "\n";
  return out;
}

std::string RenderSnapshotSummary(const FabricSnapshot& snapshot) {
  std::string out;
  out += "snapshot id=" + snapshot.Id().ToString() + "\n";
  out += "snapshot digest=" + snapshot.Digest().ToHex() + "\n";
  out += "snapshot source=" + std::string(ToString(snapshot.Source())) + "\n";
  out += "snapshot nodes=" + std::to_string(snapshot.NodeCount()) + "\n";
  out += "snapshot edges=" + std::to_string(snapshot.EdgeCount()) + "\n";
  out += "snapshot endpoints=" + std::to_string(snapshot.Endpoints().size()) + "\n";
  out += "snapshot link_states=" + std::to_string(snapshot.LinkStates().Size()) + "\n";
  out += "snapshot port_states=" + std::to_string(snapshot.PortStates().Size()) + "\n";
  out += "snapshot capabilities=" + std::to_string(snapshot.Capabilities().Size()) + "\n";
  out += "snapshot failure_domains=" + std::to_string(snapshot.FailureDomains().Size()) + "\n";
  out += "snapshot membership_complete=" +
         std::string(snapshot.FailureDomains().MembershipComplete() ? "true" : "false") + "\n";
  out += RenderEvidence(snapshot.Evidence());
  return out;
}

std::string RenderRankExplanation(const Candidate& lhs, const Candidate& rhs) {
  std::string out;
  out += "compare lhs=" + lhs.id.ToString() + " rhs=" + rhs.id.ToString() + "\n";
  AppendCost(out, "compare lhs_cost", lhs.cost);
  AppendCost(out, "compare rhs_cost", rhs.cost);
  out += "compare ranks_before=" + std::string(RanksBefore(lhs, rhs) ? "lhs" : "rhs") + "\n";
  return out;
}

}  // namespace summon::pathplanner

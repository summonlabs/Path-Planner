// Path Planner 1.0.0 - example: quickstart.
//
// The smallest complete flow: build a synthetic fabric, plan candidate paths for
// one endpoint pair, and read the deterministic explanation back through the
// explain.hpp renderers.
//
// The fabric is a DIAMOND: exactly two node-disjoint routes of equal length
// between the reported source and destination. With static_cost_spread = 0 every
// link carries the same administrative cost, so the two routes tie on total cost
// and the canonical rank order is decided by path identity alone. That tie is
// pinned down twice: once directly, and once from the same graph rebuilt in
// reverse insertion order.
//
// Every value printed below was computed by this program; no timing is reported.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "pathplanner/explain.hpp"
#include "pathplanner/graph.hpp"
#include "pathplanner/ids.hpp"
#include "pathplanner/limits.hpp"
#include "pathplanner/planner.hpp"
#include "pathplanner/request.hpp"
#include "pathplanner/result.hpp"
#include "pathplanner/sha256.hpp"
#include "pathplanner/sources.hpp"
#include "pathplanner/status.hpp"

namespace pp = summon::pathplanner;

namespace {

int g_failures = 0;

void Check(const std::string& label, bool condition) {
  std::cout << "check " << label << " " << (condition ? "true" : "false") << "\n";
  if (!condition) {
    g_failures += 1;
  }
}

std::string Label(const std::string& scenario) { return "pathplanner:example:quickstart:" + scenario; }

// One request per scenario. Identity is derived from a label, never from a
// counter or the clock, so repeated runs produce byte-identical output.
pp::PlanningRequest MakeRequest(const pp::SyntheticFabric& fabric, const std::string& scenario,
                                std::uint32_t max_candidates) {
  pp::PlanningRequest request;
  request.id = pp::PlanningRequestId::FromDigest(pp::Sha256::Hash(Label(scenario)));
  request.source.id = fabric.source;
  request.source.endpoint_class = fabric.endpoint_class;
  request.source.generation = fabric.source_generation;
  request.destination.id = fabric.destination;
  request.destination.endpoint_class = fabric.endpoint_class;
  request.destination.generation = fabric.destination_generation;
  request.constraints.id = pp::ConstraintSetId::FromDigest(pp::Sha256::Hash(Label(scenario + ":constraints")));
  request.constraints.generation = pp::ConstraintGeneration(1);
  request.constraints.layer = pp::PathLayer::kPhysical;
  request.policy.generation = pp::PolicyGeneration(1);
  request.max_candidates = max_candidates;
  return request;
}

pp::PlannerConfig RuntimeConfig(const std::shared_ptr<const pp::FabricSnapshot>& snapshot) {
  pp::PlannerConfig config;
  config.initial_snapshot = snapshot;
  return config;
}

// Rebuilds the same fabric from the same records in reverse insertion order. The
// builder canonicalises every record set (sorting nodes, edges, endpoints and all
// consumed views) before the digest is computed, so an identical snapshot must
// come back out; the planner then has to produce the same ranked candidates.
std::shared_ptr<const pp::FabricSnapshot> RebuildInReverseOrder(const pp::FabricSnapshot& snapshot,
                                                               const pp::ResourceLimits& limits,
                                                               std::string& error) {
  pp::FabricSnapshotBuilder builder(limits);
  builder.SetGenerations(snapshot.Generations());
  builder.SetSource(snapshot.Source());

  const std::vector<pp::NodeRecord>& nodes = snapshot.Nodes();
  for (std::size_t index = nodes.size(); index > 0; --index) {
    if (!builder.AddNode(nodes[index - 1])) {
      error = "rebuilt snapshot rejected a node";
      return nullptr;
    }
  }
  const std::vector<pp::EdgeRecord>& edges = snapshot.Edges();
  for (std::size_t index = edges.size(); index > 0; --index) {
    if (!builder.AddEdge(edges[index - 1])) {
      error = "rebuilt snapshot rejected an edge";
      return nullptr;
    }
  }
  const std::vector<pp::EndpointRecord>& endpoints = snapshot.Endpoints();
  for (std::size_t index = endpoints.size(); index > 0; --index) {
    if (!builder.AddEndpoint(endpoints[index - 1])) {
      error = "rebuilt snapshot rejected an endpoint";
      return nullptr;
    }
  }

  std::vector<pp::LinkStateRecord> link_states = snapshot.LinkStates().Records();
  std::reverse(link_states.begin(), link_states.end());
  builder.SetLinkStates(std::move(link_states));

  std::vector<pp::PortStateRecord> port_states = snapshot.PortStates().Records();
  std::reverse(port_states.begin(), port_states.end());
  builder.SetPortStates(std::move(port_states));

  std::vector<pp::CapabilityBinding> capabilities = snapshot.Capabilities().Bindings();
  std::reverse(capabilities.begin(), capabilities.end());
  builder.SetCapabilities(std::move(capabilities));

  std::vector<pp::FailureDomainRecord> domains = snapshot.FailureDomains().Domains();
  std::reverse(domains.begin(), domains.end());
  builder.SetFailureDomains(std::move(domains), snapshot.FailureDomains().MembershipComplete());

  const pp::SnapshotBuildResult result = builder.Build();
  if (!result.ok()) {
    error = result.detail.empty() ? "rebuilt snapshot was rejected" : result.detail;
    return nullptr;
  }
  return result.snapshot;
}

std::vector<pp::CandidatePathId> CandidateIds(const pp::PlanningResult& result) {
  std::vector<pp::CandidatePathId> ids;
  ids.reserve(result.candidates.size());
  for (const pp::Candidate& candidate : result.candidates) {
    ids.push_back(candidate.id);
  }
  return ids;
}

std::string JoinIds(const std::vector<pp::CandidatePathId>& ids) {
  std::string text;
  for (std::size_t index = 0; index < ids.size(); ++index) {
    if (index != 0) {
      text += " ";
    }
    text += ids[index].ToString();
  }
  return text;
}

}  // namespace

int main() {
  const pp::ResourceLimits limits;

  pp::SyntheticOptions options;
  options.family = pp::SyntheticFamily::kDiamond;
  options.nodes = 8;
  options.seed = 20240517;
  options.static_cost_spread = 0;  // 0 => every link has the same static cost
  options.failure_domains = 2;
  options.limits = limits;

  std::string error;
  const std::optional<pp::SyntheticFabric> fabric = pp::MakeSyntheticFabric(options, error);
  if (!fabric.has_value()) {
    std::cout << "quickstart fabric_error=" << error << "\n";
    return 1;
  }

  std::cout << "quickstart family=" << pp::ToString(options.family) << " nodes=" << options.nodes
            << " seed=" << options.seed << " static_cost_spread=" << options.static_cost_spread << "\n";
  std::cout << pp::RenderSnapshotSummary(*fabric->snapshot);

  // -------------------------------------------------------------------------
  // A plan for the reported source/destination pair.
  // -------------------------------------------------------------------------
  pp::PlannerRuntime runtime(RuntimeConfig(fabric->snapshot));
  const pp::PlanningRequest request = MakeRequest(*fabric, "plan", 2);
  const pp::PlanningResult result = runtime.Plan(request);
  std::cout << pp::RenderResult(result, true);

  Check("plan_status_planned", result.status == pp::PlanStatus::kPlanned);
  Check("plan_two_candidates", result.candidates.size() == 2);
  if (result.candidates.size() == 2) {
    const pp::Candidate& first = result.candidates[0];
    const pp::Candidate& second = result.candidates[1];
    Check("tie_equal_total_cost", first.cost.total == second.cost.total);
    Check("tie_equal_hop_count", first.cost.hops == second.cost.hops);
    Check("tie_distinct_candidate_ids", first.id != second.id);
    Check("tie_rank_order", first.rank.Value() == 1 && second.rank.Value() == 2);
    std::cout << "tie rank=1 id=" << first.id.ToString() << " total=" << first.cost.total.ToString()
              << " hops=" << first.cost.hops.ToString() << "\n";
    std::cout << "tie rank=2 id=" << second.id.ToString() << " total=" << second.cost.total.ToString()
              << " hops=" << second.cost.hops.ToString() << "\n";
  }

  // -------------------------------------------------------------------------
  // The same graph, rebuilt in a different insertion order.
  // -------------------------------------------------------------------------
  const std::shared_ptr<const pp::FabricSnapshot> rebuilt =
      RebuildInReverseOrder(*fabric->snapshot, limits, error);
  Check("tie_rebuild_succeeded", rebuilt != nullptr);
  if (rebuilt != nullptr) {
    std::cout << "tie original_snapshot_id=" << fabric->snapshot->Id().ToString() << "\n";
    std::cout << "tie rebuilt_snapshot_id=" << rebuilt->Id().ToString() << "\n";
    Check("tie_snapshot_id_identical", rebuilt->Id() == fabric->snapshot->Id());
    Check("tie_snapshot_digest_identical", rebuilt->Digest() == fabric->snapshot->Digest());

    pp::PlannerRuntime rebuilt_runtime(RuntimeConfig(rebuilt));
    const pp::PlanningResult rebuilt_result = rebuilt_runtime.Plan(request);
    const std::vector<pp::CandidatePathId> original_ids = CandidateIds(result);
    const std::vector<pp::CandidatePathId> rebuilt_ids = CandidateIds(rebuilt_result);
    std::cout << "tie original_candidate_ids " << JoinIds(original_ids) << "\n";
    std::cout << "tie rebuilt_candidate_ids  " << JoinIds(rebuilt_ids) << "\n";
    Check("tie_rebuilt_status_planned", rebuilt_result.status == pp::PlanStatus::kPlanned);
    Check("tie_candidate_ids_identical", original_ids == rebuilt_ids);
    Check("tie_candidate_count_identical", original_ids.size() == rebuilt_ids.size());
  }

  // -------------------------------------------------------------------------
  // K = 4 candidate request.
  // -------------------------------------------------------------------------
  const pp::PlanningRequest k4 = MakeRequest(*fabric, "k4", 4);
  const pp::PlanningResult k4_result = runtime.Plan(k4);
  std::cout << pp::RenderResult(k4_result, false);
  Check("k4_requested_four", k4_result.requested_candidates == 4);
  Check("k4_returned_two", k4_result.candidates.size() == 2);
  Check("k4_not_truncated", !k4_result.truncated);

  // The request asks for more candidates than the family can produce. Asking for
  // the ceiling proves the two returned candidates are every route that exists,
  // not an enumeration that gave up early.
  const pp::PlanningRequest probe = MakeRequest(*fabric, "probe", 16);
  const pp::PlanningResult probe_result = runtime.Plan(probe);
  std::cout << "k4 probe_requested_candidates=" << probe_result.requested_candidates
            << " probe_returned_candidates=" << probe_result.candidates.size() << "\n";
  Check("k4_probe_confirms_two_routes", probe_result.candidates.size() == 2);
  Check("k4_probe_not_truncated", !probe_result.truncated);

  // -------------------------------------------------------------------------
  // max_hops bound below the length of every route: the destination is
  // structurally reachable, so the bound is the reason the plan fails.
  // -------------------------------------------------------------------------
  pp::PlanningRequest bounded = MakeRequest(*fabric, "max_hops_bound", 1);
  bounded.constraints.max_hops = pp::HopCount(3);  // every route needs 4 hops
  const pp::PlanningResult bounded_result = runtime.Plan(bounded);
  std::cout << "max_hops_bound requested=3 structural_hops=4\n";
  std::cout << pp::RenderResult(bounded_result, false);
  Check("max_hops_bound_status_constraint_unsatisfied",
        bounded_result.status == pp::PlanStatus::kConstraintUnsatisfied);
  Check("max_hops_bound_primary_failure",
        bounded_result.primary_failure.has_value() &&
            *bounded_result.primary_failure == pp::DiagnosticCode::kMaxHopsExceeded);
  Check("max_hops_bound_explained", !bounded_result.explanations.empty());
  Check("max_hops_bound_no_candidates", bounded_result.candidates.empty());

  // -------------------------------------------------------------------------
  // max_hops rejection: the bound breaches the configured ceiling.
  // -------------------------------------------------------------------------
  pp::PlanningRequest over_ceiling = MakeRequest(*fabric, "max_hops_ceiling", 1);
  over_ceiling.constraints.max_hops = pp::HopCount(limits.max_hops + 1);
  const pp::PlanningResult ceiling_result = runtime.Plan(over_ceiling);
  std::cout << "max_hops_ceiling requested=" << over_ceiling.constraints.max_hops->ToString()
            << " ceiling=" << limits.max_hops << "\n";
  std::cout << pp::RenderResult(ceiling_result, false);
  Check("max_hops_ceiling_status_constraint_unsatisfied",
        ceiling_result.status == pp::PlanStatus::kConstraintUnsatisfied);
  Check("max_hops_ceiling_primary_failure",
        ceiling_result.primary_failure.has_value() &&
            *ceiling_result.primary_failure == pp::DiagnosticCode::kMaxHopsExceeded);
  Check("max_hops_ceiling_explained", !ceiling_result.explanations.empty());

  std::cout << "quickstart report failures=" << g_failures << "\n";
  return g_failures == 0 ? 0 : 1;
}

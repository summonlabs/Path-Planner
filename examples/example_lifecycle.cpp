// Path Planner 1.0.0 - example: plan lifecycle.
//
// One runtime is walked through the whole lifecycle of a plan:
//
//   publish snapshot A -> plan -> retain -> CURRENT
//   publish snapshot B (identical records, bumped link-state generation)
//     -> STALE_LINK_STATE with the exact change lines -> Replan
//
// The distributed runtime is then exercised in-process: a Coordinator binds
// 127.0.0.1 on an ephemeral port (port 0), a DistributedPlannerClient submits a
// request with no worker registered, and the structured NO_WORKER_AVAILABLE
// failure is printed rather than smoothed over. The example finishes with the
// epoch hand-off and the worker publication acceptance check.
//
// Every step is proven by a printed value; any unexpected outcome exits non-zero.

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "pathplanner/dist.hpp"
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

std::string Label(const std::string& suffix) { return "pathplanner:example:lifecycle:" + suffix; }

// Rebuilds a snapshot with one generation replaced. The records are copied
// verbatim, so only the link-state generation (and therefore the snapshot
// identity) changes.
std::shared_ptr<const pp::FabricSnapshot> RebuildWithLinkStateGeneration(const pp::FabricSnapshot& source,
                                                                         std::uint64_t link_state_generation,
                                                                         const pp::ResourceLimits& limits,
                                                                         std::string& error) {
  pp::FabricSnapshotBuilder builder(limits);
  pp::SnapshotGenerations generations = source.Generations();
  generations.link_state = pp::LinkStateGeneration(link_state_generation);
  builder.SetGenerations(generations);
  builder.SetSource(source.Source());

  for (const pp::NodeRecord& node : source.Nodes()) {
    if (!builder.AddNode(node)) {
      error = "lifecycle rebuild rejected a node";
      return nullptr;
    }
  }
  for (const pp::EdgeRecord& edge : source.Edges()) {
    if (!builder.AddEdge(edge)) {
      error = "lifecycle rebuild rejected an edge";
      return nullptr;
    }
  }
  for (const pp::EndpointRecord& endpoint : source.Endpoints()) {
    if (!builder.AddEndpoint(endpoint)) {
      error = "lifecycle rebuild rejected an endpoint";
      return nullptr;
    }
  }
  builder.SetLinkStates(source.LinkStates().Records());
  builder.SetPortStates(source.PortStates().Records());
  builder.SetCapabilities(source.Capabilities().Bindings());
  builder.SetFailureDomains(source.FailureDomains().Domains(), source.FailureDomains().MembershipComplete());

  const pp::SnapshotBuildResult result = builder.Build();
  if (!result.ok()) {
    error = result.detail.empty() ? "lifecycle rebuild was rejected" : result.detail;
    return nullptr;
  }
  return result.snapshot;
}

pp::PlanningRequest MakeRequest(const pp::SyntheticFabric& fabric) {
  pp::PlanningRequest request;
  request.id = pp::PlanningRequestId::FromDigest(pp::Sha256::Hash(Label("request")));
  request.source.id = fabric.source;
  request.source.endpoint_class = fabric.endpoint_class;
  request.source.generation = fabric.source_generation;
  request.destination.id = fabric.destination;
  request.destination.endpoint_class = fabric.endpoint_class;
  request.destination.generation = fabric.destination_generation;
  request.constraints.id = pp::ConstraintSetId::FromDigest(pp::Sha256::Hash(Label("constraints")));
  request.constraints.generation = pp::ConstraintGeneration(1);
  request.constraints.layer = pp::PathLayer::kPhysical;
  request.policy.generation = pp::PolicyGeneration(1);
  request.max_candidates = 1;
  return request;
}

bool HasChangeDetail(const pp::PlanCurrentnessReport& report, const std::string& needle) {
  for (const pp::ExplanationEntry& entry : report.changes) {
    if (entry.detail.find(needle) != std::string::npos) {
      return true;
    }
  }
  return false;
}

bool HasChangeCode(const pp::PlanCurrentnessReport& report, pp::DiagnosticCode code) {
  for (const pp::ExplanationEntry& entry : report.changes) {
    if (entry.code == code) {
      return true;
    }
  }
  return false;
}

}  // namespace

int main() {
  const pp::ResourceLimits limits;

  // -------------------------------------------------------------------------
  // Snapshot A and the first plan.
  // -------------------------------------------------------------------------
  pp::SyntheticOptions options;
  options.family = pp::SyntheticFamily::kChain;
  options.nodes = 6;
  options.seed = 77;
  options.failure_domains = 2;
  options.limits = limits;

  std::string error;
  const std::optional<pp::SyntheticFabric> fabric = pp::MakeSyntheticFabric(options, error);
  if (!fabric.has_value()) {
    std::cout << "lifecycle fabric_error=" << error << "\n";
    return 1;
  }
  const std::shared_ptr<const pp::FabricSnapshot> snapshot_a = fabric->snapshot;

  pp::PlannerRuntime runtime;
  runtime.PublishSnapshot(snapshot_a);
  std::cout << "lifecycle snapshot_a link_state_generation="
            << runtime.CurrentSnapshot()->Generations().link_state.ToString()
            << " publish_sequence=" << runtime.PublishSequence().ToString() << "\n";
  Check("snapshot_a_published", runtime.CurrentSnapshot()->Id() == snapshot_a->Id());
  Check("snapshot_a_sequence_one", runtime.PublishSequence().Value() == 1);

  const pp::PlanningRequest request = MakeRequest(*fabric);
  const pp::PlanningResult result = runtime.Plan(request);
  std::cout << pp::RenderResult(result, false);
  Check("plan_status_planned", result.status == pp::PlanStatus::kPlanned);
  Check("plan_single_candidate", result.candidates.size() == 1);

  const pp::PathPlan plan = pp::MakePathPlan(request, result, runtime.PublishSequence());
  const bool retained = runtime.Retain(plan);
  const std::optional<pp::PathPlan> found = runtime.FindPlan(plan.id);
  std::cout << "lifecycle retained=" << (retained ? "true" : "false")
            << " retained_plan_count=" << runtime.RetainedPlanCount() << " plan_id=" << plan.id.ToString() << "\n";
  Check("plan_retained", retained && runtime.RetainedPlanCount() == 1);
  Check("plan_findable_by_id", found.has_value() && found->id == plan.id);

  const pp::PlanCurrentnessReport current = runtime.CheckCurrentness(plan);
  std::cout << "lifecycle scenario=currentness_before_change\n";
  std::cout << pp::RenderCurrentness(current);
  Check("currentness_current", current.currentness == pp::Currentness::kCurrent);
  Check("currentness_no_changes", current.changes.empty());

  // -------------------------------------------------------------------------
  // Snapshot B: identical records, bumped link-state generation.
  // -------------------------------------------------------------------------
  const std::shared_ptr<const pp::FabricSnapshot> snapshot_b =
      RebuildWithLinkStateGeneration(*snapshot_a, 2, limits, error);
  if (snapshot_b == nullptr) {
    std::cout << "lifecycle rebuild_error=" << error << "\n";
    return 1;
  }
  std::cout << "lifecycle snapshot_b link_state_generation=" << snapshot_b->Generations().link_state.ToString()
            << " snapshot_a_id=" << snapshot_a->Id().ToString()
            << " snapshot_b_id=" << snapshot_b->Id().ToString() << "\n";
  Check("snapshot_b_link_state_generation_two", snapshot_b->Generations().link_state.Value() == 2);
  Check("snapshot_b_identity_differs", snapshot_b->Id() != snapshot_a->Id());

  runtime.PublishSnapshot(snapshot_b);
  const pp::PlanCurrentnessReport stale = runtime.CheckCurrentness(plan);
  std::cout << "lifecycle scenario=currentness_after_link_state_change publish_sequence="
            << runtime.PublishSequence().ToString() << "\n";
  std::cout << pp::RenderCurrentness(stale);
  Check("currentness_stale_link_state", stale.currentness == pp::Currentness::kStaleLinkState);
  Check("currentness_change_names_link_state",
        HasChangeDetail(stale, "link-state generation changed: 1 -> 2"));
  Check("currentness_change_code_stale_evidence", HasChangeCode(stale, pp::DiagnosticCode::kStaleEvidence));

  // -------------------------------------------------------------------------
  // Replan against the new evidence.
  // -------------------------------------------------------------------------
  pp::PlanningResult replan_result;
  pp::ReplanReport replan_report;
  const bool replanned = runtime.Replan(plan, request, replan_result, replan_report);
  std::cout << "lifecycle scenario=replan replanned=" << (replanned ? "true" : "false") << "\n";
  std::cout << pp::RenderReplanReport(replan_report);
  std::cout << pp::RenderResult(replan_result, false);
  Check("replan_returned_true", replanned);
  Check("replan_outcome_unchanged", replan_report.outcome == pp::ReplanOutcome::kUnchanged);
  Check("replan_evidence_changed", !replan_report.same_semantic_plan);
  Check("replan_status_planned", replan_result.status == pp::PlanStatus::kPlanned);

  // -------------------------------------------------------------------------
  // Distributed runtime, in-process.
  // -------------------------------------------------------------------------
  pp::CoordinatorConfig coordinator_config;
  coordinator_config.bind_address = "127.0.0.1";
  coordinator_config.port = 0;  // ephemeral port: never a fixed TCP port
  coordinator_config.limits = limits;
  coordinator_config.snapshot = snapshot_b;
  coordinator_config.initial_epoch = pp::FabricEpoch(1);

  pp::Coordinator coordinator(coordinator_config);
  const bool started = coordinator.Start(error);
  std::cout << "lifecycle coordinator started=" << (started ? "true" : "false")
            << " endpoint=" << coordinator.Endpoint() << " port=" << coordinator.Port()
            << " epoch=" << coordinator.Epoch().ToString() << "\n";
  if (!started) {
    std::cout << "lifecycle coordinator_error=" << error << "\n";
    return 1;
  }
  Check("coordinator_started", started && coordinator.running());
  Check("coordinator_endpoint_is_loopback",
        coordinator.Endpoint() == "127.0.0.1:" + std::to_string(coordinator.Port()));
  Check("coordinator_port_is_ephemeral", coordinator.Port() != 0);
  Check("coordinator_epoch_one", coordinator.Epoch().Value() == 1);
  Check("coordinator_snapshot_matches_b",
        coordinator.Runtime().CurrentSnapshot() != nullptr &&
            coordinator.Runtime().CurrentSnapshot()->Id() == snapshot_b->Id());

  pp::DistributedPlannerClient client(coordinator.Endpoint(), limits);
  const bool connected = client.Connect(error);
  std::cout << "lifecycle client connected=" << (connected ? "true" : "false")
            << " workers=" << coordinator.Workers().size() << "\n";
  Check("client_connected", connected && client.connected());

  pp::SnapshotId coordinator_snapshot;
  pp::SnapshotGenerations coordinator_generations;
  const bool snapshot_ok = client.SnapshotInfo(coordinator_snapshot, coordinator_generations, error);
  std::cout << "lifecycle client snapshot_info ok=" << (snapshot_ok ? "true" : "false")
            << " snapshot=" << coordinator_snapshot.ToString()
            << " link_state_generation=" << coordinator_generations.link_state.ToString()
            << " sessions=" << coordinator.SessionCount() << " error=\"" << error << "\"\n";
  Check("client_snapshot_info_ok", snapshot_ok && coordinator_snapshot == snapshot_b->Id());

  pp::PlanningResult distributed_result;
  pp::PlanStatus distributed_status = pp::PlanStatus::kNoPath;
  std::string distributed_error;
  const bool submitted = client.Submit(request, distributed_result, distributed_status, distributed_error);
  std::cout << "lifecycle distributed submit_ok=" << (submitted ? "true" : "false")
            << " status=" << pp::ToString(distributed_status) << " error=\"" << distributed_error << "\"\n";
  Check("distributed_submit_rejected", !submitted);
  Check("distributed_no_worker_available",
        distributed_error.rfind("NO_WORKER_AVAILABLE", 0) == 0);
  Check("coordinator_has_no_workers", coordinator.Workers().empty());
  Check("distributed_status_is_revalidation_required",
        distributed_status == pp::PlanStatus::kRevalidationRequired);
  client.Close();

  // -------------------------------------------------------------------------
  // Epoch hand-off: a strictly greater epoch is accepted, a lower one is not.
  // -------------------------------------------------------------------------
  const bool advanced = coordinator.AdvanceEpoch(pp::FabricEpoch(3), error);
  std::cout << "lifecycle epoch_advance accepted=" << (advanced ? "true" : "false")
            << " epoch=" << coordinator.Epoch().ToString() << "\n";
  Check("epoch_advanced", advanced && coordinator.Epoch().Value() == 3);

  const bool lowered = coordinator.AdvanceEpoch(pp::FabricEpoch(2), error);
  std::cout << "lifecycle epoch_lower accepted=" << (lowered ? "true" : "false")
            << " epoch=" << coordinator.Epoch().ToString() << " error=\"" << error << "\"\n";
  Check("epoch_lower_rejected", !lowered);
  Check("epoch_unchanged_after_rejection", coordinator.Epoch().Value() == 3);

  // -------------------------------------------------------------------------
  // Worker publication acceptance. No worker incarnation has ever registered
  // with this coordinator, so the acceptance decision rejects on identity alone.
  // -------------------------------------------------------------------------
  const pp::WorkerBootId stale_boot = pp::MakeWorkerBootIdFromLabel(Label("worker:stale"));
  std::string detail;
  const pp::WireStatus current_epoch_acceptance = coordinator.ValidateWorkerPublication(
      stale_boot, pp::CoordinatorEpoch(coordinator.Epoch().Value()), snapshot_b->Id(), detail);
  std::cout << "lifecycle worker_acceptance epoch=current status=" << pp::ToString(current_epoch_acceptance)
            << " detail=\"" << detail << "\"\n";
  Check("stale_worker_rejected",
        current_epoch_acceptance == pp::WireStatus::kWorkerFenced ||
            current_epoch_acceptance == pp::WireStatus::kUnknownWorker);

  const pp::WireStatus stale_epoch_acceptance = coordinator.ValidateWorkerPublication(
      stale_boot, pp::CoordinatorEpoch(1), snapshot_b->Id(), detail);
  std::cout << "lifecycle worker_acceptance epoch=1 status=" << pp::ToString(stale_epoch_acceptance)
            << " detail=\"" << detail << "\"\n";
  Check("stale_worker_stale_epoch_rejected",
        stale_epoch_acceptance == pp::WireStatus::kWorkerFenced ||
            stale_epoch_acceptance == pp::WireStatus::kUnknownWorker);

  coordinator.Stop();
  Check("coordinator_stopped", !coordinator.running());
  std::cout << "lifecycle coordinator_stopped running=" << (coordinator.running() ? "true" : "false") << "\n";

  std::cout << pp::RenderStatistics(runtime.Stats());
  std::cout << "lifecycle report failures=" << g_failures << "\n";
  return g_failures == 0 ? 0 : 1;
}

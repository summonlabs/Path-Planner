// Path Planner 1.0.0 - guarded benchmark.
//
// pp_bench runs a fixed, modest workload and prints, per case, the number of
// operations that completed plus one machine-dependent observation labelled
// "measurement". It never asserts performance and never compares a duration
// against a threshold: every check verifies a structural fact (status, hop count,
// candidate count, invalidation scope) so a workload that silently stopped doing
// the work fails loudly.
//
// Usage:
//   pp_bench [--quick] [--scale <n>]
//
//   --quick       reduced workload: the 1k snapshot preparation case plus small
//                 operation fabrics. This is the guarded ctest workload.
//   --scale <n>   multiply every workload size by n (n >= 1, default 1).
//   --help        print this usage.
//
// Output grammar:
//   benchmark <case> ops=<completed operations> measurement_elapsed_us=<us> ...
//   benchmark <case> check <fact> true|false
//   benchmark summary cases=<n> failures=<n>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "pathplanner/graph.hpp"
#include "pathplanner/ids.hpp"
#include "pathplanner/limits.hpp"
#include "pathplanner/planner.hpp"
#include "pathplanner/request.hpp"
#include "pathplanner/result.hpp"
#include "pathplanner/sha256.hpp"
#include "pathplanner/sources.hpp"
#include "pathplanner/status.hpp"
#include "pathplanner/version.hpp"

namespace pp = summon::pathplanner;

namespace {

using Clock = std::chrono::steady_clock;

int g_failures = 0;
std::uint64_t g_cases = 0;

std::uint64_t ElapsedMicros(Clock::time_point start) {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count());
}

void Report(const std::string& name, std::uint64_t ops, std::uint64_t micros, const std::string& detail) {
  g_cases += 1;
  std::cout << "benchmark " << name << " ops=" << ops << " measurement_elapsed_us=" << micros;
  if (!detail.empty()) {
    std::cout << " " << detail;
  }
  std::cout << "\n";
}

void Verify(const std::string& name, const std::string& fact, bool condition) {
  std::cout << "benchmark " << name << " check " << fact << " " << (condition ? "true" : "false") << "\n";
  if (!condition) {
    g_failures += 1;
  }
}

// ---------------------------------------------------------------------------
// Workload
// ---------------------------------------------------------------------------
struct Workload {
  bool quick = false;
  std::uint32_t scale = 1;
  std::uint32_t chain_small = 1000;
  std::uint32_t chain_mid = 10000;
  std::uint32_t chain_large = 100000;
  std::uint32_t leaf_spine_nodes = 512;
  std::uint32_t path_chain_nodes = 512;
  std::uint32_t tie_storm_nodes = 256;
  std::uint32_t tree_nodes = 1024;
  std::uint32_t constraint_nodes = 256;
  std::uint32_t constraint_extra_edges = 8;
  std::uint32_t disconnected_nodes = 128;
};

enum class ArgOutcome { kRun, kHelp, kError };

void PrintUsage() {
  std::cout << "usage: pp_bench [--quick] [--scale <n>]\n"
            << "  --quick      reduced guarded workload (ctest uses this)\n"
            << "  --scale <n>  multiply every workload size by n (default 1)\n";
}

ArgOutcome ParseArgs(int argc, char** argv, Workload& workload, std::string& error) {
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--help" || argument == "-h") {
      return ArgOutcome::kHelp;
    }
    if (argument == "--quick") {
      workload.quick = true;
      continue;
    }
    if (argument == "--scale") {
      if (index + 1 >= argc) {
        error = "--scale requires a value";
        return ArgOutcome::kError;
      }
      const std::string value = argv[++index];
      std::uint64_t parsed = 0;
      for (const char digit : value) {
        if (digit < '0' || digit > '9') {
          error = "--scale must be a decimal integer";
          return ArgOutcome::kError;
        }
        parsed = parsed * 10u + static_cast<std::uint64_t>(digit - '0');
        if (parsed > 1000u) {
          error = "--scale above 1000 is refused";
          return ArgOutcome::kError;
        }
      }
      if (parsed == 0) {
        error = "--scale must be at least 1";
        return ArgOutcome::kError;
      }
      workload.scale = static_cast<std::uint32_t>(parsed);
      continue;
    }
    error = "unknown argument: " + argument;
    return ArgOutcome::kError;
  }
  if (workload.quick) {
    workload.chain_mid = 0;
    workload.chain_large = 0;
    workload.leaf_spine_nodes = 128;
    workload.path_chain_nodes = 128;
    workload.tie_storm_nodes = 64;
    workload.tree_nodes = 256;
    workload.constraint_nodes = 128;
    workload.disconnected_nodes = 64;
  }
  return ArgOutcome::kRun;
}

// Keeps every generated fabric inside the default max_nodes ceiling even for a
// large --scale. Per-family ceilings keep every case inside the product's snapshot
// and planning ceilings; every clamp is reported, never silently applied.
constexpr std::uint32_t kNodeCeiling = 1u << 19;
constexpr std::uint32_t kLeafSpineLayers = 8;

std::uint32_t Scaled(std::uint32_t base, std::uint32_t scale) {
  if (base == 0) {
    return 0;
  }
  const std::uint64_t scaled = static_cast<std::uint64_t>(base) * scale;
  return static_cast<std::uint32_t>(scaled > kNodeCeiling ? kNodeCeiling : scaled);
}

std::uint32_t Clamp(std::uint32_t value, std::uint32_t ceiling, bool& clamped) {
  if (value > ceiling) {
    clamped = true;
    return ceiling;
  }
  return value;
}

// The leaf-spine family is full bipartite: its edge count grows quadratically with
// the node count. The ceiling is the largest node count whose derived record counts
// still fit the default snapshot ceilings.
std::uint32_t LeafSpineNodeCeiling() {
  const std::uint32_t tiers = std::min<std::uint32_t>(std::max<std::uint32_t>(kLeafSpineLayers, 2u), 8u);
  const pp::ResourceLimits limits;
  std::uint32_t ceiling = 8;
  for (std::uint32_t nodes = 8; nodes <= kNodeCeiling; nodes += 8) {
    const std::uint32_t spines = std::max<std::uint32_t>(1u, nodes / tiers);
    const std::uint32_t leaves = nodes - spines;
    const std::uint64_t edges = static_cast<std::uint64_t>(leaves) * spines;
    if (edges > limits.max_edges || 2ull * edges + nodes > limits.max_port_state_records ||
        edges + nodes > limits.max_capability_bindings) {
      break;
    }
    ceiling = nodes;
  }
  return ceiling;
}

// Resource limits for a planning case whose workload is larger than the default
// budget covers. A larger --scale is a larger fabric, and the product ceilings are
// configuration rather than constants.
pp::ResourceLimits BenchLimits(std::uint64_t operation_hint) {
  pp::ResourceLimits limits;
  if (operation_hint > limits.max_search_states) {
    limits.max_search_states = operation_hint;
  }
  if (operation_hint > limits.max_expanded_states) {
    limits.max_expanded_states = operation_hint;
  }
  if (operation_hint > limits.max_queue_entries) {
    limits.max_queue_entries = operation_hint;
  }
  return limits;
}

struct Sizes {
  std::uint32_t chain_small = 0;
  std::uint32_t chain_mid = 0;
  std::uint32_t chain_large = 0;
  std::uint32_t leaf_spine_nodes = 0;
  std::uint32_t path_chain_nodes = 0;
  std::uint32_t tie_storm_nodes = 0;
  std::uint32_t tree_nodes = 0;
  std::uint32_t constraint_nodes = 0;
  std::uint32_t constraint_extra_edges = 0;
  std::uint32_t disconnected_nodes = 0;
  bool clamped = false;
};

Sizes EffectiveSizes(const Workload& workload) {
  Sizes sizes;
  const std::uint32_t scale = workload.scale;
  sizes.chain_small = Scaled(workload.chain_small, scale);
  sizes.chain_mid = Scaled(workload.chain_mid, scale);
  sizes.chain_large = Scaled(workload.chain_large, scale);
  sizes.leaf_spine_nodes = Clamp(Scaled(workload.leaf_spine_nodes, scale), LeafSpineNodeCeiling(), sizes.clamped);
  sizes.path_chain_nodes = Clamp(Scaled(workload.path_chain_nodes, scale), pp::kMaxHopCount, sizes.clamped);
  // The tie-storm source node owns one port per alternative route, so the family is
  // bounded by max_ports_per_node.
  const pp::ResourceLimits family_limits;
  sizes.tie_storm_nodes = Clamp(Scaled(workload.tie_storm_nodes, scale), family_limits.max_ports_per_node - 1u,
                                sizes.clamped);
  sizes.tree_nodes = Scaled(workload.tree_nodes, scale);
  sizes.constraint_nodes = Scaled(workload.constraint_nodes, scale);
  sizes.constraint_extra_edges = workload.constraint_extra_edges;
  sizes.disconnected_nodes = Scaled(workload.disconnected_nodes, scale);
  // Scaled() itself clamps at kNodeCeiling; report every size that hit it.
  const auto hit_node_ceiling = [scale](std::uint32_t base) {
    return base != 0 && static_cast<std::uint64_t>(base) * scale > kNodeCeiling;
  };
  sizes.clamped = sizes.clamped || hit_node_ceiling(workload.chain_small) || hit_node_ceiling(workload.chain_mid) ||
                  hit_node_ceiling(workload.chain_large) || hit_node_ceiling(workload.leaf_spine_nodes) ||
                  hit_node_ceiling(workload.path_chain_nodes) || hit_node_ceiling(workload.tie_storm_nodes) ||
                  hit_node_ceiling(workload.tree_nodes) || hit_node_ceiling(workload.constraint_nodes) ||
                  hit_node_ceiling(workload.disconnected_nodes);
  return sizes;
}

// Records the requested family will materialise, node records plus edge records.
// Deriving the failure-domain count from this estimate keeps (nodes + edges) per
// domain inside max_members_per_failure_domain for every family used here.
std::uint64_t EstimatedRecords(const pp::SyntheticOptions& options) {
  const std::uint64_t nodes = options.nodes;
  switch (options.family) {
    case pp::SyntheticFamily::kLeafSpine: {
      const std::uint32_t tiers = std::min<std::uint32_t>(std::max<std::uint32_t>(options.layers, 2u), 8u);
      const std::uint64_t spines = std::max<std::uint32_t>(1u, options.nodes / tiers);
      return nodes + (nodes - spines) * spines;
    }
    case pp::SyntheticFamily::kDenseBounded:
      return nodes + nodes * (8ull + options.extra_edges);
    case pp::SyntheticFamily::kTieStorm:
      return nodes + 2ull * (nodes > 1ull ? nodes - 1ull : 1ull);
    default:
      return 2ull * nodes;
  }
}

std::uint32_t DomainCount(std::uint64_t records) {
  const std::uint64_t needed = records / 60000ull + 2ull;
  const std::uint64_t clamped = needed < 8ull ? 8ull : needed;
  return static_cast<std::uint32_t>(clamped);
}

pp::SyntheticOptions MakeOptions(pp::SyntheticFamily family, std::uint32_t nodes, std::uint64_t seed,
                                 std::uint32_t layers, std::uint32_t extra_edges,
                                 std::uint32_t capability_bindings) {
  pp::SyntheticOptions options;
  options.family = family;
  options.nodes = nodes;
  options.seed = seed;
  options.layers = layers;
  options.extra_edges = extra_edges;
  options.capability_bindings = capability_bindings;
  options.failure_domains = DomainCount(EstimatedRecords(options));
  return options;
}

std::string ScenarioLabel(const std::string& scenario) { return "pathplanner:benchmark:" + scenario; }

pp::PlanningRequest MakeRequestFor(const std::string& scenario, const pp::EndpointId& source,
                                  const pp::EntityGeneration& source_generation,
                                  const pp::EndpointId& destination,
                                  const pp::EntityGeneration& destination_generation,
                                  std::uint32_t max_candidates) {
  pp::PlanningRequest request;
  request.id = pp::PlanningRequestId::FromDigest(pp::Sha256::Hash(ScenarioLabel(scenario)));
  request.source.id = source;
  request.source.endpoint_class = pp::EndpointClass::kEndpoint;
  request.source.generation = source_generation;
  request.destination.id = destination;
  request.destination.endpoint_class = pp::EndpointClass::kEndpoint;
  request.destination.generation = destination_generation;
  request.constraints.id =
      pp::ConstraintSetId::FromDigest(pp::Sha256::Hash(ScenarioLabel(scenario + ":constraints")));
  request.constraints.generation = pp::ConstraintGeneration(1);
  request.constraints.layer = pp::PathLayer::kPhysical;
  request.policy.generation = pp::PolicyGeneration(1);
  request.max_candidates = max_candidates;
  return request;
}

pp::PlanningRequest MakeRequest(const pp::SyntheticFabric& fabric, const std::string& scenario,
                                std::uint32_t max_candidates) {
  return MakeRequestFor(scenario, fabric.source, fabric.source_generation, fabric.destination,
                        fabric.destination_generation, max_candidates);
}

pp::PlannerConfig RuntimeConfig(const std::shared_ptr<const pp::FabricSnapshot>& snapshot,
                                          const pp::ResourceLimits& limits) {
  pp::PlannerConfig config;
  config.limits = limits;
  config.initial_snapshot = snapshot;
  return config;
}

pp::PlannerConfig RuntimeConfig(const std::shared_ptr<const pp::FabricSnapshot>& snapshot) {
  return RuntimeConfig(snapshot, pp::ResourceLimits{});
}

bool PathContainsNode(const pp::CandidatePath& path, const pp::NodeId& node) {
  return std::find(path.nodes.begin(), path.nodes.end(), node) != path.nodes.end();
}

bool PathContainsLink(const pp::CandidatePath& path, const pp::LinkId& link) {
  for (const pp::PathHop& hop : path.hops) {
    if (hop.link == link) {
      return true;
    }
  }
  return false;
}

bool PathContainsPort(const pp::CandidatePath& path, const pp::PortId& port) {
  for (const pp::PathHop& hop : path.hops) {
    if (hop.from_port == port || hop.to_port == port) {
      return true;
    }
  }
  return false;
}

const pp::RejectionExplanation* FindRejection(const pp::PlanningResult& result, pp::DiagnosticCode code) {
  for (const pp::RejectionExplanation& rejection : result.rejections) {
    if (rejection.code == code) {
      return &rejection;
    }
  }
  return nullptr;
}

bool HasChangeDetail(const pp::PlanCurrentnessReport& report, const std::string& needle) {
  for (const pp::ExplanationEntry& entry : report.changes) {
    if (entry.detail.find(needle) != std::string::npos) {
      return true;
    }
  }
  return false;
}

}  // namespace

int main(int argc, char** argv) {
  Workload workload;
  std::string error;
  const ArgOutcome outcome = ParseArgs(argc, argv, workload, error);
  if (outcome == ArgOutcome::kHelp) {
    PrintUsage();
    return 0;
  }
  if (outcome == ArgOutcome::kError) {
    std::cout << "pp_bench argument error: " << error << "\n";
    PrintUsage();
    return 2;
  }

  const Sizes sizes = EffectiveSizes(workload);
  std::cout << "benchmark configuration quick=" << (workload.quick ? "true" : "false")
            << " scale=" << workload.scale << " node_ceiling=" << kNodeCeiling
            << " leaf_spine_ceiling=" << LeafSpineNodeCeiling()
            << " sizes_clamped=" << (sizes.clamped ? "true" : "false") << "\n";
  std::cout << "benchmark configuration chains=" << sizes.chain_small << "," << sizes.chain_mid << ","
            << sizes.chain_large << " leaf_spine=" << sizes.leaf_spine_nodes
            << " path_chain=" << sizes.path_chain_nodes << " tie_storm=" << sizes.tie_storm_nodes
            << " tree=" << sizes.tree_nodes << " constraint=" << sizes.constraint_nodes
            << " disconnected=" << sizes.disconnected_nodes << "\n";
  std::cout << "benchmark configuration planner_rule_version=" << pp::kPlanningRuleVersion
            << " path_encoding_version=" << pp::kPathEncodingVersion << "\n";

  // -------------------------------------------------------------------------
  // Graph snapshot preparation: builder + digest for sparse chains.
  // -------------------------------------------------------------------------
  const std::uint32_t chain_sizes[3] = {sizes.chain_small, sizes.chain_mid, sizes.chain_large};
  for (const std::uint32_t nodes : chain_sizes) {
    if (nodes == 0) {
      continue;
    }
    const std::string name = "snapshot_prep_chain_" + std::to_string(nodes);
    const auto start = Clock::now();
    const std::optional<pp::SyntheticFabric> fabric = pp::MakeSyntheticFabric(
        MakeOptions(pp::SyntheticFamily::kChain, nodes, 5, 4, 0, 1), error);
    const std::uint64_t micros = ElapsedMicros(start);
    if (!fabric.has_value()) {
      Verify(name, "fabric_built", false);
      std::cout << "benchmark " << name << " error=\"" << error << "\"\n";
      continue;
    }
    Verify(name, "fabric_built", true);
    Verify(name, "node_count", fabric->snapshot->NodeCount() == nodes);
    Verify(name, "edge_count", fabric->snapshot->EdgeCount() == static_cast<std::size_t>(nodes) - 1u);
    Verify(name, "endpoint_count", fabric->snapshot->Endpoints().size() == nodes);
    Verify(name, "snapshot_identity_valid", fabric->snapshot->Id().IsValid());
    Verify(name, "capability_bindings",
           fabric->snapshot->Capabilities().Size() == 2ull * static_cast<std::size_t>(nodes) - 1u);
    const std::uint64_t ops = static_cast<std::uint64_t>(nodes) + static_cast<std::uint64_t>(nodes) - 1ull;
    Report(name, ops, micros,
           "nodes=" + std::to_string(nodes) + " edges=" + std::to_string(nodes - 1u) +
               " endpoints=" + std::to_string(fabric->snapshot->Endpoints().size()) +
               " link_states=" + std::to_string(fabric->snapshot->LinkStates().Size()));
  }

  // -------------------------------------------------------------------------
  // Graph snapshot preparation: leaf-spine fabric.
  // -------------------------------------------------------------------------
  {
    const std::uint32_t nodes = sizes.leaf_spine_nodes;
    const std::uint32_t layers = kLeafSpineLayers;
    const std::string name = "snapshot_prep_leaf_spine_" + std::to_string(nodes);
    const auto start = Clock::now();
    const std::optional<pp::SyntheticFabric> fabric = pp::MakeSyntheticFabric(
        MakeOptions(pp::SyntheticFamily::kLeafSpine, nodes, 9, layers, 0, 1), error);
    const std::uint64_t micros = ElapsedMicros(start);
    if (!fabric.has_value()) {
      Verify(name, "fabric_built", false);
      std::cout << "benchmark " << name << " error=\"" << error << "\"\n";
    } else {
      const std::uint32_t tiers = std::min<std::uint32_t>(std::max<std::uint32_t>(layers, 2u), 8u);
      const std::uint32_t spines = std::max<std::uint32_t>(1u, nodes / tiers);
      const std::uint32_t leaves = nodes - spines;
      const std::size_t expected_edges = static_cast<std::size_t>(leaves) * spines;
      Verify(name, "fabric_built", true);
      Verify(name, "node_count", fabric->snapshot->NodeCount() == nodes);
      Verify(name, "edge_count", fabric->snapshot->EdgeCount() == expected_edges);
      Verify(name, "snapshot_identity_valid", fabric->snapshot->Id().IsValid());
      const std::uint64_t ops = static_cast<std::uint64_t>(nodes) + static_cast<std::uint64_t>(expected_edges);
      Report(name, ops, micros,
             "nodes=" + std::to_string(nodes) + " leaves=" + std::to_string(leaves) +
                 " spines=" + std::to_string(spines) + " edges=" + std::to_string(expected_edges));
    }
  }

  // -------------------------------------------------------------------------
  // One shortest path: a chain forces exactly one route of nodes - 1 hops.
  // -------------------------------------------------------------------------
  {
    const std::uint32_t nodes = sizes.path_chain_nodes;
    const std::string name = "shortest_path_chain_" + std::to_string(nodes);
    const std::optional<pp::SyntheticFabric> fabric = pp::MakeSyntheticFabric(
        MakeOptions(pp::SyntheticFamily::kChain, nodes, 13, 4, 0, 1), error);
    if (!fabric.has_value()) {
      Verify(name, "fabric_built", false);
      std::cout << "benchmark " << name << " error=\"" << error << "\"\n";
    } else {
      // A chain route is nodes - 1 hops long. The case states that bound explicitly
      // (never above the largest representable hop count) so the run exercises a
      // caller-supplied hop ceiling rather than an open-ended search.
      const std::uint32_t hop_ceiling = std::min<std::uint32_t>(nodes, pp::kMaxHopCount);
      pp::ResourceLimits path_limits;
      path_limits.max_hops = std::max<std::uint32_t>(path_limits.max_hops, hop_ceiling);
      pp::PlannerRuntime runtime(RuntimeConfig(fabric->snapshot, path_limits));
      pp::PlanningRequest request = MakeRequest(*fabric, name, 1);
      request.constraints.max_hops = pp::HopCount(hop_ceiling);
      const auto start = Clock::now();
      const pp::PlanningResult result = runtime.Plan(request);
      const std::uint64_t micros = ElapsedMicros(start);
      const pp::PlannerStatistics stats = runtime.Stats();
      const std::uint64_t expected_hops = static_cast<std::uint64_t>(nodes) - 1ull;
      Verify(name, "status_planned", result.status == pp::PlanStatus::kPlanned);
      Verify(name, "one_candidate", result.candidates.size() == 1);
      Verify(name, "hop_count", !result.candidates.empty() &&
                                    result.candidates[0].cost.hops.Value() == expected_hops);
      Verify(name, "hops_cost", !result.candidates.empty() &&
                                    result.candidates[0].cost.hops_cost.Value() == expected_hops);
      Verify(name, "static_cost", !result.candidates.empty() &&
                                      result.candidates[0].cost.static_cost.Value() == expected_hops);
      Report(name, stats.states_expanded, micros,
             "nodes=" + std::to_string(nodes) + " hops=" + std::to_string(expected_hops) +
                 " hop_ceiling=" + std::to_string(path_limits.max_hops) +
                 " queue_pushes=" + std::to_string(stats.queue_pushes));
    }
  }

  // -------------------------------------------------------------------------
  // K = 4 and K = 8 candidates from an equal-cost tie storm.
  // -------------------------------------------------------------------------
  for (const std::uint32_t wanted : {4u, 8u}) {
    const std::uint32_t nodes = sizes.tie_storm_nodes;
    const std::string name = "candidates_k" + std::to_string(wanted) + "_tie_storm_" + std::to_string(nodes);
    const std::optional<pp::SyntheticFabric> fabric = pp::MakeSyntheticFabric(
        MakeOptions(pp::SyntheticFamily::kTieStorm, nodes, 17, 4, 0, 1), error);
    if (!fabric.has_value()) {
      Verify(name, "fabric_built", false);
      std::cout << "benchmark " << name << " error=\"" << error << "\"\n";
      continue;
    }
    pp::PlannerRuntime runtime(RuntimeConfig(fabric->snapshot));
    const pp::PlanningRequest request = MakeRequest(*fabric, name, wanted);
    const auto start = Clock::now();
    const pp::PlanningResult result = runtime.Plan(request);
    const std::uint64_t micros = ElapsedMicros(start);
    const pp::PlannerStatistics stats = runtime.Stats();
    bool equal_cost = !result.candidates.empty();
    bool all_two_hops = !result.candidates.empty();
    for (const pp::Candidate& candidate : result.candidates) {
      equal_cost = equal_cost && candidate.cost.total == result.candidates.front().cost.total;
      all_two_hops = all_two_hops && candidate.cost.hops.Value() == 2;
    }
    Verify(name, "fabric_built", true);
    Verify(name, "status_planned", result.status == pp::PlanStatus::kPlanned);
    Verify(name, "requested_candidates", result.requested_candidates == wanted);
    Verify(name, "returned_requested", result.candidates.size() == wanted);
    Verify(name, "all_equal_cost", equal_cost);
    Verify(name, "all_two_hops", all_two_hops);
    Report(name, result.candidates.size(), micros,
           "requested=" + std::to_string(wanted) + " routes=" + std::to_string(nodes - 2u) +
               " states_expanded=" + std::to_string(stats.states_expanded) +
               " spur_searches=" + std::to_string(stats.spur_searches));
  }

  // -------------------------------------------------------------------------
  // Constraint-heavy plan: forbidden nodes, links and ports plus a required
  // transit stage and a capability requirement, all consulted at once.
  // -------------------------------------------------------------------------
  {
    const std::uint32_t nodes = sizes.constraint_nodes;
    const std::uint32_t extra_edges = sizes.constraint_extra_edges;
    const std::string name = "constraint_heavy_dense_bounded_" + std::to_string(nodes);
    const std::optional<pp::SyntheticFabric> fabric = pp::MakeSyntheticFabric(
        MakeOptions(pp::SyntheticFamily::kDenseBounded, nodes, 23, 4, extra_edges, 2), error);
    if (!fabric.has_value()) {
      Verify(name, "fabric_built", false);
      std::cout << "benchmark " << name << " error=\"" << error << "\"\n";
    } else {
      // The dense circulant is far deeper than it is wide, so the search runs in the
      // hop-expanded form; the budget is derived from that label space.
      const pp::ResourceLimits default_limits;
      const std::uint64_t state_hint =
          (static_cast<std::uint64_t>(default_limits.max_hops) + 1ull) * static_cast<std::uint64_t>(nodes);
      pp::PlannerRuntime runtime(RuntimeConfig(fabric->snapshot, BenchLimits(state_hint)));
      const pp::PlanningResult baseline = runtime.Plan(MakeRequest(*fabric, name + ":baseline", 1));
      Verify(name, "fabric_built", true);
      Verify(name, "baseline_planned", baseline.status == pp::PlanStatus::kPlanned);
      if (!baseline.candidates.empty()) {
        const pp::CandidatePath& base_path = baseline.candidates[0].path;
        std::vector<pp::NodeId> forbidden_nodes;
        for (const pp::NodeRecord& node : fabric->snapshot->Nodes()) {
          if (forbidden_nodes.size() >= 3u) {
            break;
          }
          if (!PathContainsNode(base_path, node.id)) {
            forbidden_nodes.push_back(node.id);
          }
        }
        std::vector<pp::LinkId> forbidden_links;
        std::vector<pp::PortId> forbidden_ports;
        for (const pp::EdgeRecord& edge : fabric->snapshot->Edges()) {
          if (PathContainsLink(base_path, edge.id)) {
            continue;
          }
          if (forbidden_links.size() < 2u) {
            forbidden_links.push_back(edge.id);
          } else if (forbidden_ports.empty()) {
            // The eligibility view reports FORBIDDEN_LINK before it inspects ports, so
            // the port rejection has to come from an edge that is not itself forbidden.
            forbidden_ports.push_back(edge.from_port);
          }
        }
        const pp::NodeId transit = base_path.nodes.size() > 2u ? base_path.nodes[1] : base_path.nodes.front();
        const pp::CapabilityId capability = fabric->snapshot->Capabilities().Bindings().front().capability;

        pp::PlanningRequest request = MakeRequest(*fabric, name, 1);
        request.constraints.forbidden_nodes = forbidden_nodes;
        request.constraints.forbidden_links = forbidden_links;
        request.constraints.forbidden_ports = forbidden_ports;
        // The circulant route is deep, so the hop bound is derived from the baseline
        // route with slack for routing around the forbidden entities.
        const std::uint32_t baseline_hops =
            baseline.candidates.empty() ? 0u : baseline.candidates[0].cost.hops.Value();
        const std::uint32_t hop_bound =
            std::min<std::uint32_t>(baseline_hops + 8u, pp::kMaxHopCount);
        request.constraints.max_hops = pp::HopCount(hop_bound);
        request.constraints.max_members_per_failure_domain = 64;
        pp::TransitStage stage;
        stage.kind = pp::TransitKind::kExact;
        stage.alternatives.push_back(transit);
        request.constraints.required_transit.push_back(stage);
        pp::CapabilityRequirement requirement;
        requirement.capability = capability;
        requirement.scope = pp::CapabilityScope::kEveryLink;
        requirement.comparator = pp::CapabilityComparator::kAtLeast;
        requirement.value = pp::CapabilityValue(1);
        request.constraints.required_capabilities.push_back(requirement);

        const auto start = Clock::now();
        const pp::PlanningResult result = runtime.Plan(request);
        const std::uint64_t micros = ElapsedMicros(start);
        const pp::PlannerStatistics stats = runtime.Stats();
        bool avoids_forbidden_nodes = true;
        bool avoids_forbidden_links = true;
        bool avoids_forbidden_ports = true;
        bool transit_present = false;
        bool within_hop_bound = true;
        for (const pp::Candidate& candidate : result.candidates) {
          for (const pp::NodeId& forbidden : forbidden_nodes) {
            avoids_forbidden_nodes = avoids_forbidden_nodes && !PathContainsNode(candidate.path, forbidden);
          }
          for (const pp::LinkId& forbidden : forbidden_links) {
            avoids_forbidden_links = avoids_forbidden_links && !PathContainsLink(candidate.path, forbidden);
          }
          for (const pp::PortId& forbidden : forbidden_ports) {
            avoids_forbidden_ports = avoids_forbidden_ports && !PathContainsPort(candidate.path, forbidden);
          }
          transit_present = transit_present || PathContainsNode(candidate.path, transit);
          within_hop_bound = within_hop_bound && candidate.cost.hops.Value() <= hop_bound;
        }
        Verify(name, "status_planned", result.status == pp::PlanStatus::kPlanned);
        Verify(name, "has_candidate", !result.candidates.empty());
        Verify(name, "avoids_forbidden_nodes", avoids_forbidden_nodes);
        Verify(name, "avoids_forbidden_links", avoids_forbidden_links);
        Verify(name, "avoids_forbidden_ports", avoids_forbidden_ports);
        Verify(name, "transit_present", transit_present);
        Verify(name, "within_hop_bound", within_hop_bound);
        Verify(name, "forbidden_node_reported",
               FindRejection(result, pp::DiagnosticCode::kForbiddenNode) != nullptr);
        Verify(name, "forbidden_link_reported",
               FindRejection(result, pp::DiagnosticCode::kForbiddenLink) != nullptr);
        Verify(name, "forbidden_port_reported",
               FindRejection(result, pp::DiagnosticCode::kForbiddenPort) != nullptr);
        Report(name, stats.states_expanded, micros,
               "constraint_entries=" + std::to_string(request.constraints.EntryCount()) +
                   " forbidden_nodes=" + std::to_string(forbidden_nodes.size()) +
                   " forbidden_links=" + std::to_string(forbidden_links.size()) +
                   " forbidden_ports=" + std::to_string(forbidden_ports.size()) +
                   " hops=" + std::to_string(result.candidates.empty() ? 0u
                                                                       : result.candidates[0].cost.hops.Value()) +
                   " states_expanded=" + std::to_string(stats.states_expanded));
      }
    }
  }

  // -------------------------------------------------------------------------
  // No-path plan: the source and the destination sit in different components.
  // -------------------------------------------------------------------------
  {
    const std::uint32_t nodes = sizes.disconnected_nodes;
    const std::string name = "no_path_disconnected_" + std::to_string(nodes);
    const std::optional<pp::SyntheticFabric> fabric = pp::MakeSyntheticFabric(
        MakeOptions(pp::SyntheticFamily::kDisconnected, nodes, 29, 4, 0, 1), error);
    if (!fabric.has_value()) {
      Verify(name, "fabric_built", false);
      std::cout << "benchmark " << name << " error=\"" << error << "\"\n";
    } else {
      pp::PlannerRuntime runtime(RuntimeConfig(fabric->snapshot));
      const pp::PlanningRequest request = MakeRequest(*fabric, name, 1);
      const auto start = Clock::now();
      const pp::PlanningResult result = runtime.Plan(request);
      const std::uint64_t micros = ElapsedMicros(start);
      const pp::PlannerStatistics stats = runtime.Stats();
      Verify(name, "fabric_built", true);
      Verify(name, "status_no_path", result.status == pp::PlanStatus::kNoPath);
      Verify(name, "no_candidates", result.candidates.empty());
      Verify(name, "primary_failure_no_structural_path",
             result.primary_failure.has_value() &&
                 *result.primary_failure == pp::DiagnosticCode::kNoStructuralPath);
      Report(name, stats.states_expanded, micros,
             "nodes=" + std::to_string(nodes) + " candidates=0 states_expanded=" +
                 std::to_string(stats.states_expanded));
    }
  }

  // -------------------------------------------------------------------------
  // Currentness, unchanged replan and targeted invalidation on one tree fabric.
  // -------------------------------------------------------------------------
  {
    const std::uint32_t nodes = sizes.tree_nodes;
    const std::string name = "lifecycle_tree_" + std::to_string(nodes);
    const std::optional<pp::SyntheticFabric> fabric = pp::MakeSyntheticFabric(
        MakeOptions(pp::SyntheticFamily::kSparseLarge, nodes, 31, 4, 0, 1), error);
    if (!fabric.has_value()) {
      Verify(name, "fabric_built", false);
      std::cout << "benchmark " << name << " error=\"" << error << "\"\n";
    } else {
      Verify(name, "fabric_built", true);
      // The tree case states an explicit hop bound, so the planner runs the
      // hop-expanded search: (max_hops + 1) * nodes labels. The work budget is derived
      // from that state count so a larger --scale stays inside the limits the case
      // declares.
      const pp::ResourceLimits default_limits;
      const std::uint64_t state_hint =
          (static_cast<std::uint64_t>(default_limits.max_hops) + 1ull) * static_cast<std::uint64_t>(nodes);
      pp::PlannerRuntime runtime(RuntimeConfig(fabric->snapshot, BenchLimits(state_hint)));

      // A second leaf destination whose route cannot contain the first one's leaf.
      std::vector<pp::NodeId> parents;
      for (const pp::EdgeRecord& edge : fabric->snapshot->Edges()) {
        parents.push_back(edge.from);
      }
      std::sort(parents.begin(), parents.end());
      parents.erase(std::unique(parents.begin(), parents.end()), parents.end());
      pp::EndpointId second_destination;
      pp::EntityGeneration second_destination_generation = pp::EntityGeneration(1);
      bool second_found = false;
      for (const pp::NodeRecord& node : fabric->snapshot->Nodes()) {
        if (second_found || node.id == fabric->destination_node) {
          continue;
        }
        if (std::binary_search(parents.begin(), parents.end(), node.id)) {
          continue;
        }
        for (const pp::EndpointRecord& endpoint : fabric->snapshot->Endpoints()) {
          if (endpoint.node == node.id) {
            second_destination = endpoint.id;
            second_destination_generation = endpoint.entity_generation;
            second_found = true;
            break;
          }
        }
      }
      Verify(name, "second_leaf_endpoint_found", second_found);

      pp::PlanningRequest first_request = MakeRequest(*fabric, name + ":first", 1);
      first_request.constraints.max_hops = pp::HopCount(default_limits.max_hops);
      const pp::PlanningResult first_result = runtime.Plan(first_request);
      Verify(name, "first_status_planned", first_result.status == pp::PlanStatus::kPlanned);
      Verify(name, "first_has_candidate", !first_result.candidates.empty());
      const pp::PathPlan first_plan = pp::MakePathPlan(first_request, first_result, runtime.PublishSequence());
      const bool first_retained = runtime.Retain(first_plan);
      Verify(name, "first_retained", first_retained);

      pp::PathPlan second_plan;
      bool second_retained = false;
      if (second_found) {
        pp::PlanningRequest second_request =
            MakeRequestFor(name + ":second", fabric->source, fabric->source_generation, second_destination,
                           second_destination_generation, 1);
        second_request.constraints.max_hops = pp::HopCount(default_limits.max_hops);
        const pp::PlanningResult second_result = runtime.Plan(second_request);
        Verify(name, "second_status_planned", second_result.status == pp::PlanStatus::kPlanned);
        Verify(name, "second_has_candidate", !second_result.candidates.empty());
        second_plan = pp::MakePathPlan(second_request, second_result, runtime.PublishSequence());
        second_retained = runtime.Retain(second_plan);
        Verify(name, "second_retained", second_retained);
      }
      Verify(name, "retained_two_plans", runtime.RetainedPlanCount() == 2);

      // --- currentness check -----------------------------------------------
      {
        const auto start = Clock::now();
        const pp::PlanCurrentnessReport report = runtime.CheckCurrentness(first_plan);
        const std::uint64_t micros = ElapsedMicros(start);
        Verify(name + "_currentness", "currentness_current", report.currentness == pp::Currentness::kCurrent);
        Verify(name + "_currentness", "no_changes", report.changes.empty());
        const std::size_t dependencies = pp::CollectPlanDependencies(first_plan).subjects.size();
        Report(name + "_currentness", 1, micros,
               "dependencies=" + std::to_string(dependencies) + " currentness=" +
                   std::string(pp::ToString(report.currentness)));
      }

      // --- unchanged replan ------------------------------------------------
      {
        pp::PlanningResult replan_result;
        pp::ReplanReport replan_report;
        const auto start = Clock::now();
        const bool replanned = runtime.Replan(first_plan, first_request, replan_result, replan_report);
        const std::uint64_t micros = ElapsedMicros(start);
        Verify(name + "_replan", "replan_returned_true", replanned);
        Verify(name + "_replan", "outcome_unchanged",
               replan_report.outcome == pp::ReplanOutcome::kUnchanged);
        Verify(name + "_replan", "same_semantic_plan", replan_report.same_semantic_plan);
        Verify(name + "_replan", "status_planned", replan_result.status == pp::PlanStatus::kPlanned);
        Report(name + "_replan", 1, micros,
               "outcome=" + std::string(pp::ToString(replan_report.outcome)) +
                   " candidates=" + std::to_string(replan_result.candidates.size()));
      }

      // --- targeted invalidation -------------------------------------------
      {
        pp::InvalidationNotice notice;
        notice.nodes.push_back(fabric->destination_node);
        const auto start = Clock::now();
        const pp::InvalidationReport report = runtime.ApplyInvalidation(notice);
        const std::uint64_t micros = ElapsedMicros(start);
        const bool affected_first = std::find(report.affected.begin(), report.affected.end(), first_plan.id) !=
                                    report.affected.end();
        const bool affected_second = second_found &&
                                     std::find(report.affected.begin(), report.affected.end(), second_plan.id) !=
                                         report.affected.end();
        Verify(name + "_invalidation", "affected_first", affected_first);
        Verify(name + "_invalidation", "second_untouched", !affected_second);
        Verify(name + "_invalidation", "conservative_false", !report.conservative);
        Verify(name + "_invalidation", "no_retirements", report.retired.empty());
        Verify(name + "_invalidation", "retained_two", report.retained_plans == 2);
        const pp::PlanCurrentnessReport after = runtime.CheckCurrentness(first_plan);
        Verify(name + "_invalidation", "targeted_notice_recorded",
               HasChangeDetail(after, "invalidated by a targeted notice"));
        Report(name + "_invalidation", report.affected.size(), micros,
               "affected=" + std::to_string(report.affected.size()) + " retired=" +
                   std::to_string(report.retired.size()) + " retained=" +
                   std::to_string(report.retained_plans) + " currentness=" +
                   std::string(pp::ToString(after.currentness)));
      }
    }
  }

  std::cout << "benchmark summary cases=" << g_cases << " failures=" << g_failures << "\n";
  return g_failures == 0 ? 0 : 1;
}

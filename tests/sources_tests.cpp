// Suite: sources - deterministic synthetic generation and read-only real local discovery.

#include <algorithm>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "pathplanner/pathplanner.hpp"
#include "pathplanner/sources.hpp"
#include "test_framework.hpp"

namespace {

using namespace summon::pathplanner;

std::uint32_t CountComponents(const FabricSnapshot& snapshot) {
  std::vector<std::vector<std::uint32_t>> adjacency(snapshot.NodeCount());
  for (std::size_t index = 0; index < snapshot.Nodes().size(); ++index) {
    (void)index;
  }
  for (const EdgeRecord& edge : snapshot.Edges()) {
    const NodeRecord* from = snapshot.FindNode(edge.from);
    const NodeRecord* to = snapshot.FindNode(edge.to);
    if (from == nullptr || to == nullptr) {
      continue;
    }
    const std::size_t from_index = static_cast<std::size_t>(from - snapshot.Nodes().data());
    const std::size_t to_index = static_cast<std::size_t>(to - snapshot.Nodes().data());
    adjacency[from_index].push_back(static_cast<std::uint32_t>(to_index));
    adjacency[to_index].push_back(static_cast<std::uint32_t>(from_index));
  }
  std::vector<std::uint8_t> visited(snapshot.Nodes().size(), 0);
  std::uint32_t components = 0;
  for (std::size_t start = 0; start < snapshot.Nodes().size(); ++start) {
    if (visited[start] != 0) {
      continue;
    }
    components += 1;
    std::vector<std::uint32_t> stack;
    stack.push_back(static_cast<std::uint32_t>(start));
    visited[start] = 1;
    while (!stack.empty()) {
      const std::uint32_t node = stack.back();
      stack.pop_back();
      for (const std::uint32_t next : adjacency[node]) {
        if (visited[next] == 0) {
          visited[next] = 1;
          stack.push_back(next);
        }
      }
    }
  }
  return components;
}

bool HasReverseEdge(const FabricSnapshot& snapshot) {
  for (const EdgeRecord& edge : snapshot.Edges()) {
    for (const EdgeRecord& other : snapshot.Edges()) {
      if (other.from == edge.to && other.to == edge.from) {
        return true;
      }
    }
  }
  return false;
}

SyntheticOptions OptionsFor(SyntheticFamily family, std::uint32_t nodes, std::uint64_t seed) {
  SyntheticOptions options;
  options.family = family;
  options.nodes = nodes;
  options.seed = seed;
  return options;
}

const SyntheticFamily kAllFamilies[] = {
    SyntheticFamily::kChain,        SyntheticFamily::kRing,          SyntheticFamily::kDiamond,
    SyntheticFamily::kLeafSpine,    SyntheticFamily::kFatTree,       SyntheticFamily::kMesh,
    SyntheticFamily::kDisconnected, SyntheticFamily::kOneWay,        SyntheticFamily::kParallelEqualCost,
    SyntheticFamily::kTieStorm,     SyntheticFamily::kHighDegreeHub, SyntheticFamily::kDeepChain,
    SyntheticFamily::kSparseLarge,  SyntheticFamily::kDenseBounded};

}  // namespace

PP_TEST(sources, every_family_builds_and_is_well_formed) {
  for (const SyntheticFamily family : kAllFamilies) {
    for (const std::uint32_t nodes : {8u, 64u, 512u}) {
      const std::string error = std::string(ToString(family)) + "/" + std::to_string(nodes);
      const SnapshotBuildResult built = GenerateSyntheticFabric(OptionsFor(family, nodes, 1));
      PP_CHECK_MSG(built.ok(), error);
      if (!built.ok()) {
        continue;
      }
      const FabricSnapshot& snapshot = *built.snapshot;
      PP_CHECK_MSG(snapshot.NodeCount() == static_cast<std::size_t>(nodes), error);
      PP_CHECK_MSG(snapshot.Source() == EvidenceSource::kSynthetic, error);
      PP_CHECK(snapshot.EdgeCount() > 0);
      // Every edge references published nodes and ports, and never loops on itself.
      for (const EdgeRecord& edge : snapshot.Edges()) {
        PP_CHECK(edge.from != edge.to);
        const NodeRecord* from = snapshot.FindNode(edge.from);
        const NodeRecord* to = snapshot.FindNode(edge.to);
        PP_CHECK(from != nullptr);
        PP_CHECK(to != nullptr);
        if (from == nullptr || to == nullptr) {
          continue;
        }
        PP_CHECK(std::binary_search(from->ports.begin(), from->ports.end(), edge.from_port));
        PP_CHECK(std::binary_search(to->ports.begin(), to->ports.end(), edge.to_port));
        PP_CHECK(edge.from_port != edge.to_port);
        PP_CHECK(edge.structural_generation.Value() <= snapshot.Generations().topology.Value());
      }
      // Every endpoint resolves to a node that publishes its port.
      for (const EndpointRecord& endpoint : snapshot.Endpoints()) {
        const NodeRecord* node = snapshot.FindNode(endpoint.node);
        PP_CHECK(node != nullptr);
        if (node != nullptr) {
          PP_CHECK(std::binary_search(node->ports.begin(), node->ports.end(), endpoint.port));
        }
      }
    }
  }
}

PP_TEST(sources, generation_is_deterministic_and_seed_bound) {
  for (const SyntheticFamily family : kAllFamilies) {
    const SnapshotBuildResult first = GenerateSyntheticFabric(OptionsFor(family, 32, 4242));
    const SnapshotBuildResult second = GenerateSyntheticFabric(OptionsFor(family, 32, 4242));
    const SnapshotBuildResult other = GenerateSyntheticFabric(OptionsFor(family, 32, 4243));
    PP_REQUIRE(first.ok());
    PP_REQUIRE(second.ok());
    PP_REQUIRE(other.ok());
    PP_CHECK(first.snapshot->Id() == second.snapshot->Id());
    PP_CHECK(first.snapshot->Digest() == second.snapshot->Digest());
    PP_CHECK(first.snapshot->Id() != other.snapshot->Id());
  }
}

PP_TEST(sources, family_specific_structure) {
  const SnapshotBuildResult chain = GenerateSyntheticFabric(OptionsFor(SyntheticFamily::kChain, 16, 7));
  PP_REQUIRE(chain.ok());
  PP_CHECK(chain.snapshot->EdgeCount() == 15);
  PP_CHECK(!HasReverseEdge(*chain.snapshot));

  const SnapshotBuildResult disconnected =
      GenerateSyntheticFabric(OptionsFor(SyntheticFamily::kDisconnected, 16, 7));
  PP_REQUIRE(disconnected.ok());
  PP_CHECK(CountComponents(*disconnected.snapshot) >= 2);

  const SnapshotBuildResult one_way = GenerateSyntheticFabric(OptionsFor(SyntheticFamily::kOneWay, 16, 7));
  PP_REQUIRE(one_way.ok());
  PP_CHECK(!HasReverseEdge(*one_way.snapshot));

  const SnapshotBuildResult hub = GenerateSyntheticFabric(OptionsFor(SyntheticFamily::kHighDegreeHub, 16, 7));
  PP_REQUIRE(hub.ok());
  std::size_t max_degree = 0;
  for (const NodeRecord& node : hub.snapshot->Nodes()) {
    std::size_t degree = 0;
    for (const EdgeRecord& edge : hub.snapshot->Edges()) {
      if (edge.from == node.id || edge.to == node.id) {
        degree += 1;
      }
    }
    max_degree = std::max(max_degree, degree);
  }
  PP_CHECK(max_degree == hub.snapshot->NodeCount() - 1);

  // Parallel equal cost: at least two distinct links with equal cost between one node pair.
  const SnapshotBuildResult parallel =
      GenerateSyntheticFabric(OptionsFor(SyntheticFamily::kParallelEqualCost, 16, 7));
  PP_REQUIRE(parallel.ok());
  bool found_parallel = false;
  for (const EdgeRecord& lhs : parallel.snapshot->Edges()) {
    for (const EdgeRecord& rhs : parallel.snapshot->Edges()) {
      if (lhs.id == rhs.id) {
        continue;
      }
      if (lhs.from == rhs.from && lhs.to == rhs.to && lhs.static_cost == rhs.static_cost) {
        found_parallel = true;
      }
    }
  }
  PP_CHECK(found_parallel);
}

PP_TEST(sources, evidence_views_and_limits) {
  SyntheticOptions options = OptionsFor(SyntheticFamily::kLeafSpine, 16, 11);
  const SnapshotBuildResult built = GenerateSyntheticFabric(options);
  PP_REQUIRE(built.ok());
  PP_CHECK(built.snapshot->LinkStates().Size() == built.snapshot->EdgeCount());
  PP_CHECK(built.snapshot->PortStates().Size() >= built.snapshot->EdgeCount() * 2);
  PP_CHECK(built.snapshot->Capabilities().Size() > 0);
  PP_CHECK(built.snapshot->FailureDomains().Size() == options.failure_domains);
  PP_CHECK(built.snapshot->FailureDomains().MembershipComplete());

  // Removing every link-state record makes operational state UNKNOWN, which must fail closed.
  SyntheticOptions unknown = OptionsFor(SyntheticFamily::kChain, 8, 3);
  unknown.percent_without_link_state_record = 100;
  const SnapshotBuildResult absent = GenerateSyntheticFabric(unknown);
  PP_REQUIRE(absent.ok());
  for (const EdgeRecord& edge : absent.snapshot->Edges()) {
    PP_CHECK(absent.snapshot->LinkStates().StateOf(edge.id) == LinkState::kUnknown);
  }

  // A ceiling breach is reported, never silently truncated.
  SyntheticOptions tiny = OptionsFor(SyntheticFamily::kChain, 64, 5);
  tiny.limits.max_nodes = 16;
  const SnapshotBuildResult rejected = GenerateSyntheticFabric(tiny);
  PP_CHECK(!rejected.ok());
  PP_REQUIRE(rejected.error.has_value());
  PP_CHECK(*rejected.error == DiagnosticCode::kGraphTooLarge);

  SyntheticOptions edges = OptionsFor(SyntheticFamily::kMesh, 64, 5);
  edges.limits.max_edges = 8;
  const SnapshotBuildResult edge_rejected = GenerateSyntheticFabric(edges);
  PP_CHECK(!edge_rejected.ok());
}

PP_TEST(sources, unknown_family_is_rejected) {
  PP_CHECK(!ParseSyntheticFamily("NOT_A_FAMILY").has_value());
  PP_CHECK(!ParseSyntheticFamily("chain").has_value());
  PP_CHECK(ParseSyntheticFamily("CHAIN").has_value());
  for (const SyntheticFamily family : kAllFamilies) {
    const std::string_view name = ToString(family);
    PP_CHECK(name != "UNKNOWN_VALUE");
    const std::optional<SyntheticFamily> parsed = ParseSyntheticFamily(name);
    PP_REQUIRE(parsed.has_value());
    PP_CHECK(*parsed == family);
  }
}

PP_TEST(sources, synthetic_fabric_exposes_plannable_endpoints) {
  std::string error;
  const std::optional<SyntheticFabric> fabric =
      MakeSyntheticFabric(OptionsFor(SyntheticFamily::kLeafSpine, 16, 9), error);
  PP_REQUIRE(fabric.has_value());
  PP_CHECK(fabric->snapshot != nullptr);
  PP_CHECK(fabric->source.IsValid());
  PP_CHECK(fabric->destination.IsValid());
  PP_CHECK(fabric->source != fabric->destination);
  PP_CHECK(fabric->snapshot->FindEndpoint(fabric->source) != nullptr);
  PP_CHECK(fabric->snapshot->FindEndpoint(fabric->destination) != nullptr);

  PlanningRequest request;
  request.id = PlanningRequestId::FromDigest(Sha256::Hash("sources-suite-request"));
  request.source.id = fabric->source;
  request.source.endpoint_class = fabric->endpoint_class;
  request.source.generation = fabric->source_generation;
  request.destination.id = fabric->destination;
  request.destination.endpoint_class = fabric->endpoint_class;
  request.destination.generation = fabric->destination_generation;
  request.constraints.id = ConstraintSetId::FromDigest(Sha256::Hash("sources-suite-constraints"));
  request.constraints.generation = ConstraintGeneration(1);
  request.max_candidates = 1;

  PlannerConfig config;
  config.initial_snapshot = fabric->snapshot;
  PlannerRuntime runtime(config);
  const PlanningResult result = runtime.Plan(request);
  PP_CHECK(result.status == PlanStatus::kPlanned);
  PP_REQUIRE(!result.candidates.empty());
  PP_CHECK(result.candidates.front().path.source == fabric->source_node);
  PP_CHECK(result.candidates.front().path.destination == fabric->destination_node);
  PP_CHECK(result.candidates.front().currentness == Currentness::kCurrent);
}

PP_TEST(sources, large_sparse_and_dense_graphs_plan_correctly) {
  // Large sparse graph: a binary tree of 8192 nodes. The shortest path is unique, so the
  // candidate identity is a strong determinism check rather than a smoke test.
  std::string error;
  SyntheticOptions sparse_options = OptionsFor(SyntheticFamily::kSparseLarge, 8192, 21);
  const std::optional<SyntheticFabric> sparse = MakeSyntheticFabric(sparse_options, error);
  PP_REQUIRE(sparse.has_value());
  PP_CHECK(sparse->snapshot->NodeCount() == 8192);

  PlanningRequest request;
  request.id = PlanningRequestId::FromDigest(Sha256::Hash("sources-suite-sparse-request"));
  request.source.id = sparse->source;
  request.source.endpoint_class = sparse->endpoint_class;
  request.source.generation = sparse->source_generation;
  request.destination.id = sparse->destination;
  request.destination.endpoint_class = sparse->endpoint_class;
  request.destination.generation = sparse->destination_generation;
  request.constraints.id = ConstraintSetId::FromDigest(Sha256::Hash("sources-suite-sparse-constraints"));
  request.constraints.generation = ConstraintGeneration(1);
  request.max_candidates = 1;

  PlannerConfig config;
  config.initial_snapshot = sparse->snapshot;
  PlannerRuntime runtime(config);
  const PlanningResult first = runtime.Plan(request);
  PP_CHECK(first.status == PlanStatus::kPlanned);
  PP_REQUIRE(!first.candidates.empty());
  PP_CHECK(first.candidates.front().currentness == Currentness::kCurrent);
  PP_CHECK(first.candidates.front().path.IsSimple());
  PP_CHECK(first.candidates.front().cost.hops.Value() == first.candidates.front().path.HopCountValue());

  PlannerRuntime second_runtime(config);
  const PlanningResult second = second_runtime.Plan(request);
  PP_REQUIRE(!second.candidates.empty());
  PP_CHECK(first.candidates.front().id == second.candidates.front().id);
  PP_CHECK(first.semantic_digest == second.semantic_digest);
  PP_CHECK(first.plan_id == second.plan_id);

  // Dense bounded graph: many equal-cost alternatives, K = 4 unique candidates in a stable
  // order across two independent runtimes.
  SyntheticOptions dense_options = OptionsFor(SyntheticFamily::kDenseBounded, 256, 22);
  dense_options.extra_edges = 4;
  const std::optional<SyntheticFabric> dense = MakeSyntheticFabric(dense_options, error);
  PP_REQUIRE(dense.has_value());
  request.id = PlanningRequestId::FromDigest(Sha256::Hash("sources-suite-dense-request"));
  request.source.id = dense->source;
  request.source.endpoint_class = dense->endpoint_class;
  request.source.generation = dense->source_generation;
  request.destination.id = dense->destination;
  request.destination.endpoint_class = dense->endpoint_class;
  request.destination.generation = dense->destination_generation;
  request.constraints.id = ConstraintSetId::FromDigest(Sha256::Hash("sources-suite-dense-constraints"));
  request.max_candidates = 4;

  PlannerConfig dense_config;
  dense_config.initial_snapshot = dense->snapshot;
  PlannerRuntime dense_runtime(dense_config);
  const PlanningResult dense_result = dense_runtime.Plan(request);
  PP_CHECK(dense_result.status == PlanStatus::kPlanned || dense_result.status == PlanStatus::kResourceLimit);
  if (dense_result.status == PlanStatus::kPlanned) {
    PP_CHECK(!dense_result.candidates.empty());
    PP_CHECK(dense_result.candidates.size() <= 4);
    for (std::size_t index = 0; index < dense_result.candidates.size(); ++index) {
      PP_CHECK(dense_result.candidates[index].rank.Value() == index + 1);
      PP_CHECK(dense_result.candidates[index].path.IsSimple());
      if (index > 0) {
        PP_CHECK(dense_result.candidates[index - 1].cost.total <= dense_result.candidates[index].cost.total);
        PP_CHECK(dense_result.candidates[index - 1].id != dense_result.candidates[index].id);
      }
    }
    PlannerRuntime dense_second(dense_config);
    const PlanningResult repeat = dense_second.Plan(request);
    PP_REQUIRE(repeat.candidates.size() == dense_result.candidates.size());
    for (std::size_t index = 0; index < repeat.candidates.size(); ++index) {
      PP_CHECK(repeat.candidates[index].id == dense_result.candidates[index].id);
    }
  }
}

PP_TEST(sources, real_local_discovery_is_honest) {
  if (!LocalDiscoverySupported()) {
    // Unsupported platforms must report honestly rather than fabricate adapters.
    PP_CHECK(EnumerateLocalAdapters().empty());
    return;
  }
  const std::vector<LocalAdapter> adapters = EnumerateLocalAdapters();
  PP_CHECK(!adapters.empty());
  std::vector<std::uint64_t> indices;
  for (const LocalAdapter& adapter : adapters) {
    PP_CHECK(!adapter.name.empty());
    PP_CHECK(adapter.if_index != 0);
    indices.push_back(adapter.if_index);
    for (const char c : adapter.mac) {
      PP_CHECK((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
    PP_CHECK(adapter.mac.size() % 2 == 0);
  }
  std::vector<std::uint64_t> sorted = indices;
  std::sort(sorted.begin(), sorted.end());
  PP_CHECK(sorted == indices);
  PP_CHECK(std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end());

  std::string error;
  const std::optional<SyntheticFabric> host = MakeLocalHostFabric(ResourceLimits{}, error);
  PP_REQUIRE(host.has_value());
  PP_CHECK(host->snapshot->Source() == EvidenceSource::kReal);
  PP_CHECK(host->snapshot->NodeCount() == 1);
  PP_CHECK(host->snapshot->EdgeCount() == 0);
  PP_CHECK(host->snapshot->FindEndpoint(host->source) != nullptr);
}

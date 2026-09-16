// Evidence sources for the Path Planner: a deterministic synthetic fabric
// generator and read-only discovery of the local host's own adapters.
//
// Both producers build FabricSnapshot values exclusively through
// FabricSnapshotBuilder, derive identity from label strings (never from time or
// from a run-dependent counter), perform no network I/O and never modify host
// state.

#include "pathplanner/sources.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "pathplanner/canonical.hpp"
#include "pathplanner/sha256.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// winsock2.h must precede windows.h and iphlpapi.h: after windows.h the legacy
// winsock.h would conflict with the version 2 declarations.
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
// GetAdaptersAddresses is exported by iphlpapi. Declaring the dependency here
// keeps this source self-contained for build systems that do not add it.
#pragma comment(lib, "iphlpapi.lib")
#endif

namespace summon::pathplanner {
namespace {

// ---------------------------------------------------------------------------
// Deterministic primitives
// ---------------------------------------------------------------------------

// splitmix64. Small, fast and fully specified: the stream is a pure function of
// the seed, which is the only property this generator needs.
class SeededRandom {
 public:
  explicit SeededRandom(std::uint64_t seed) noexcept : state_(seed) {}

  std::uint64_t Next() noexcept {
    state_ += 0x9E3779B97F4A7C15ull;
    std::uint64_t value = state_;
    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
    value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
    return value ^ (value >> 31);
  }

  // Uniform in [0, bound). Rejection sampling: the accepted range is an exact
  // multiple of bound, so the result is unbiased.
  std::uint32_t Below(std::uint32_t bound) noexcept {
    if (bound <= 1u) {
      return 0u;
    }
    const std::uint64_t range = static_cast<std::uint64_t>(bound);
    const std::uint64_t highest = std::numeric_limits<std::uint64_t>::max();
    const std::uint64_t accept_below = highest - (highest % range);
    for (;;) {
      const std::uint64_t value = Next();
      if (value < accept_below) {
        return static_cast<std::uint32_t>(value % range);
      }
    }
  }

  // True with the requested percentage probability: 0 never fires, >= 100 always does.
  bool Percent(std::uint32_t percent) noexcept { return Below(100u) < percent; }

 private:
  std::uint64_t state_;
};

// "kind:family:seed:first:second". The family is encoded numerically so the
// label stays stable if a name is ever reworded.
std::string FabricLabel(std::string_view kind, std::uint32_t family, std::uint64_t seed, std::uint64_t first,
                        std::uint64_t second) {
  std::string label;
  label.reserve(kind.size() + 56u);
  label.append(kind);
  label.push_back(':');
  label.append(std::to_string(family));
  label.push_back(':');
  label.append(std::to_string(seed));
  label.push_back(':');
  label.append(std::to_string(first));
  label.push_back(':');
  label.append(std::to_string(second));
  return label;
}

template <class Id>
Id IdFromLabel(const std::string& label) {
  return Id::FromDigest(Sha256::Hash(std::string_view(label)));
}

SnapshotBuildResult Fail(DiagnosticCode code, std::string detail) {
  SnapshotBuildResult result;
  result.error = code;
  result.detail = std::move(detail);
  return result;
}

SnapshotBuildResult BuilderFailure(const FabricSnapshotBuilder& builder) {
  const std::vector<DiagnosticCode>& diagnostics = builder.Diagnostics();
  return Fail(diagnostics.empty() ? DiagnosticCode::kGraphTooLarge : diagnostics.back(),
              "synthetic fabric record was rejected by the snapshot builder");
}

// A synthetic fabric is only addressable when it has two distinct nodes.
std::uint32_t NormalizeNodeCount(std::uint64_t requested) noexcept {
  return static_cast<std::uint32_t>(requested < 2u ? 2u : requested);
}

// Relationship type is a pure function of the layer: the builder rejects any
// other combination, and PORT_PAIRING (also PHYSICAL) is reserved for host NIC
// pairing, which this generator does not emit.
std::optional<RelationshipType> RelationshipForLayer(PathLayer layer) noexcept {
  switch (layer) {
    case PathLayer::kPhysical:
      return RelationshipType::kDirectLink;
    case PathLayer::kLogical:
      return RelationshipType::kLogicalAdjacency;
    case PathLayer::kTunnel:
    case PathLayer::kOverlay:
      return RelationshipType::kTunnelEncapsulation;
  }
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// Topology planning
// ---------------------------------------------------------------------------

struct Failure {
  DiagnosticCode code = DiagnosticCode::kUnsupportedRequest;
  std::string detail;
};

struct EdgeDraft {
  std::uint32_t from = 0;
  std::uint32_t to = 0;
};

struct Topology {
  std::uint32_t node_count = 0;
  std::uint32_t source = 0;
  std::uint32_t destination = 0;
  bool uniform_cost = false;  // equal-cost families ignore static_cost_spread
  std::vector<EdgeDraft> edges;
  std::vector<std::uint32_t> degree;
};

// Every node carries one port per incident edge plus one dedicated access port,
// so an endpoint never has to share a port with a link. The ceilings are applied
// while edges are added, which keeps a rejected request from materialising an
// unbounded draft.
bool PushEdge(Topology& topology, std::uint32_t from, std::uint32_t to, const ResourceLimits& limits,
              Failure& failure) {
  if (topology.edges.size() >= static_cast<std::size_t>(limits.max_edges)) {
    failure.code = DiagnosticCode::kTooManyEdges;
    failure.detail = "synthetic fabric exceeds max_edges";
    return false;
  }
  if (static_cast<std::uint64_t>(topology.degree[from]) + 1u > limits.max_ports_per_node ||
      static_cast<std::uint64_t>(topology.degree[to]) + 1u > limits.max_ports_per_node) {
    failure.code = DiagnosticCode::kGraphTooLarge;
    failure.detail = "synthetic fabric exceeds max_ports_per_node";
    return false;
  }
  topology.edges.push_back(EdgeDraft{from, to});
  ++topology.degree[from];
  ++topology.degree[to];
  return true;
}

bool BuildChainEdges(Topology& topology, std::uint32_t count, const ResourceLimits& limits, Failure& failure) {
  for (std::uint32_t i = 0; i + 1u < count; ++i) {
    if (!PushEdge(topology, i, i + 1u, limits, failure)) {
      return false;
    }
  }
  return true;
}

bool BuildTopology(const SyntheticOptions& options, Topology& topology, Failure& failure) {
  const ResourceLimits& limits = options.limits;
  const std::uint32_t n = NormalizeNodeCount(options.nodes);
  if (static_cast<std::uint64_t>(n) > limits.max_nodes) {
    failure.code = DiagnosticCode::kGraphTooLarge;
    failure.detail = "synthetic fabric requires " + std::to_string(n) + " nodes but max_nodes is " +
                     std::to_string(limits.max_nodes);
    return false;
  }

  topology.node_count = n;
  topology.degree.assign(n, 0u);
  topology.edges.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(static_cast<std::uint64_t>(n) * 4u, 8192u)));

  switch (options.family) {
    case SyntheticFamily::kChain: {
      topology.source = 0u;
      topology.destination = n - 1u;
      if (!BuildChainEdges(topology, n, limits, failure)) {
        return false;
      }
      break;
    }

    case SyntheticFamily::kRing: {
      topology.source = 0u;
      topology.destination = n / 2u;
      for (std::uint32_t i = 0; i < n; ++i) {
        const std::uint32_t next = (i + 1u == n) ? 0u : i + 1u;
        if (!PushEdge(topology, i, next, limits, failure)) {
          return false;
        }
      }
      break;
    }

    case SyntheticFamily::kDiamond: {
      // Two node-disjoint routes source -> ... -> destination of near-equal length.
      topology.source = 0u;
      topology.destination = n - 1u;
      if (n < 4u) {
        if (!BuildChainEdges(topology, n, limits, failure)) {
          return false;
        }
        break;
      }
      const std::uint32_t middle = n - 2u;
      const std::uint32_t split = 1u + (middle + 1u) / 2u;  // first node of the second route
      const std::uint32_t bounds[3] = {1u, split, n - 1u};
      for (std::size_t route = 0; route + 1u < 3u; ++route) {
        std::uint32_t previous = 0u;
        for (std::uint32_t node = bounds[route]; node < bounds[route + 1u]; ++node) {
          if (!PushEdge(topology, previous, node, limits, failure)) {
            return false;
          }
          previous = node;
        }
        if (!PushEdge(topology, previous, n - 1u, limits, failure)) {
          return false;
        }
      }
      break;
    }

    case SyntheticFamily::kLeafSpine: {
      // Two tiers, full bipartite. The layers hint only sets the split ratio.
      const std::uint32_t tiers = std::min<std::uint32_t>(std::max<std::uint32_t>(options.layers, 2u), 8u);
      const std::uint32_t spines = std::max<std::uint32_t>(1u, n / tiers);
      const std::uint32_t leaves = n - spines;
      topology.source = 0u;
      topology.destination = leaves;
      for (std::uint32_t leaf = 0; leaf < leaves; ++leaf) {
        for (std::uint32_t spine = 0; spine < spines; ++spine) {
          if (!PushEdge(topology, leaf, leaves + spine, limits, failure)) {
            return false;
          }
        }
      }
      break;
    }

    case SyntheticFamily::kFatTree: {
      // Clos: leaves <-> aggregates, aggregates <-> spines, and (layers >= 4)
      // spines <-> cores. Tier sizes sum to exactly the requested node count.
      topology.source = 0u;
      topology.destination = n - 1u;
      if (n < 4u) {
        if (!BuildChainEdges(topology, n, limits, failure)) {
          return false;
        }
        break;
      }
      const bool core_tier = options.layers >= 4u;
      const std::uint32_t leaves = std::max<std::uint32_t>(1u, n / 4u);
      const std::uint32_t aggregates = std::max<std::uint32_t>(1u, n / 4u);
      const std::uint32_t spines =
          core_tier ? std::max<std::uint32_t>(1u, n / 4u) : (n - leaves - aggregates);
      const std::uint32_t cores = core_tier ? (n - leaves - aggregates - spines) : 0u;
      const std::uint32_t aggregate_base = leaves;
      const std::uint32_t spine_base = leaves + aggregates;
      const std::uint32_t core_base = spine_base + spines;
      for (std::uint32_t leaf = 0; leaf < leaves; ++leaf) {
        for (std::uint32_t aggregate = 0; aggregate < aggregates; ++aggregate) {
          if (!PushEdge(topology, leaf, aggregate_base + aggregate, limits, failure)) {
            return false;
          }
        }
      }
      for (std::uint32_t aggregate = 0; aggregate < aggregates; ++aggregate) {
        for (std::uint32_t spine = 0; spine < spines; ++spine) {
          if (!PushEdge(topology, aggregate_base + aggregate, spine_base + spine, limits, failure)) {
            return false;
          }
        }
      }
      for (std::uint32_t spine = 0; spine < spines; ++spine) {
        for (std::uint32_t core = 0; core < cores; ++core) {
          if (!PushEdge(topology, spine_base + spine, core_base + core, limits, failure)) {
            return false;
          }
        }
      }
      break;
    }

    case SyntheticFamily::kMesh: {
      // Cycle plus wrap-around chords of increasing distance. Distances stay at
      // or below (n - 1) / 2 so no undirected pair is emitted twice.
      topology.source = 0u;
      topology.destination = n / 2u;
      if (n < 4u) {
        if (!BuildChainEdges(topology, n, limits, failure)) {
          return false;
        }
        break;
      }
      const std::uint32_t max_distance = (n - 1u) / 2u;
      const std::uint64_t requested = 2u + static_cast<std::uint64_t>(options.extra_edges);
      const std::uint32_t distance = static_cast<std::uint32_t>(std::min<std::uint64_t>(requested, max_distance));
      for (std::uint32_t i = 0; i < n; ++i) {
        for (std::uint32_t step = 1u; step <= distance; ++step) {
          if (!PushEdge(topology, i, (i + step) % n, limits, failure)) {
            return false;
          }
        }
      }
      break;
    }

    case SyntheticFamily::kDisconnected: {
      // Contiguous components, each a chain. The source sits in the first
      // component and the destination in the second: no route can exist.
      const std::uint32_t components = std::min<std::uint32_t>(n, std::max<std::uint32_t>(2u, n / 4u));
      const std::uint32_t base = n / components;
      const std::uint32_t remainder = n % components;
      std::uint32_t start = 0u;
      std::uint32_t second_start = 0u;
      for (std::uint32_t component = 0; component < components; ++component) {
        const std::uint32_t size = base + (component < remainder ? 1u : 0u);
        if (component == 1u) {
          second_start = start;
        }
        for (std::uint32_t i = 0; i + 1u < size; ++i) {
          if (!PushEdge(topology, start + i, start + i + 1u, limits, failure)) {
            return false;
          }
        }
        start += size;
      }
      topology.source = 0u;
      topology.destination = second_start;
      break;
    }

    case SyntheticFamily::kOneWay: {
      // Forward-only chain: for every edge (u, v) no edge (v, u) is added.
      topology.source = 0u;
      topology.destination = n - 1u;
      if (!BuildChainEdges(topology, n, limits, failure)) {
        return false;
      }
      break;
    }

    case SyntheticFamily::kParallelEqualCost: {
      topology.source = 0u;
      topology.destination = n - 1u;
      topology.uniform_cost = true;
      const std::uint32_t parallel =
          (n == 2u) ? 2u : std::min<std::uint32_t>(8u, std::max<std::uint32_t>(2u, n / 4u));
      for (std::uint32_t link = 0; link < parallel; ++link) {
        if (!PushEdge(topology, 0u, 1u, limits, failure)) {
          return false;
        }
      }
      for (std::uint32_t i = 1u; i + 1u < n; ++i) {
        if (!PushEdge(topology, i, i + 1u, limits, failure)) {
          return false;
        }
      }
      break;
    }

    case SyntheticFamily::kTieStorm: {
      // Book graph: node_count - 2 alternative two-hop routes, all the same cost.
      topology.source = 0u;
      topology.destination = n - 1u;
      topology.uniform_cost = true;
      if (n == 2u) {
        if (!PushEdge(topology, 0u, 1u, limits, failure)) {
          return false;
        }
        break;
      }
      for (std::uint32_t middle = 1u; middle + 1u < n; ++middle) {
        if (!PushEdge(topology, 0u, middle, limits, failure)) {
          return false;
        }
        if (!PushEdge(topology, middle, n - 1u, limits, failure)) {
          return false;
        }
      }
      break;
    }

    case SyntheticFamily::kHighDegreeHub: {
      // Node 0 is the hub and the reported source: it publishes node_count - 1
      // links, so the search expands its whole fan-out. Edges point hub -> spoke,
      // which keeps the reported destination reachable in the consumed (directed)
      // edge model.
      topology.source = 0u;
      topology.destination = n - 1u;
      for (std::uint32_t spoke = 1u; spoke < n; ++spoke) {
        if (!PushEdge(topology, 0u, spoke, limits, failure)) {
          return false;
        }
      }
      break;
    }

    case SyntheticFamily::kDeepChain: {
      // Maximum-depth chain over a seeded permutation of the node indices: the
      // path visits every node, and node index order carries no structural hint.
      std::vector<std::uint32_t> order(n);
      for (std::uint32_t i = 0; i < n; ++i) {
        order[i] = i;
      }
      SeededRandom shuffle(options.seed ^ 0x5DEECE66Dull);
      for (std::size_t i = order.size() - 1u; i > 0u; --i) {
        const std::uint32_t j = shuffle.Below(static_cast<std::uint32_t>(i + 1u));
        std::swap(order[i], order[j]);
      }
      topology.source = order.front();
      topology.destination = order.back();
      for (std::size_t i = 0; i + 1u < order.size(); ++i) {
        if (!PushEdge(topology, order[i], order[i + 1u], limits, failure)) {
          return false;
        }
      }
      break;
    }

    case SyntheticFamily::kSparseLarge: {
      // Balanced binary tree: connected, exactly node_count - 1 edges.
      topology.source = 0u;
      topology.destination = n - 1u;
      for (std::uint32_t i = 1u; i < n; ++i) {
        if (!PushEdge(topology, (i - 1u) / 2u, i, limits, failure)) {
          return false;
        }
      }
      break;
    }

    case SyntheticFamily::kDenseBounded: {
      // Bounded-degree circulant: density grows with extra_edges but never past
      // the point where a pair would be emitted twice.
      topology.source = 0u;
      topology.destination = n / 2u;
      if (n < 4u) {
        if (!BuildChainEdges(topology, n, limits, failure)) {
          return false;
        }
        break;
      }
      const std::uint32_t max_distance = (n - 1u) / 2u;
      const std::uint64_t requested = 8u + static_cast<std::uint64_t>(options.extra_edges);
      const std::uint32_t distance = static_cast<std::uint32_t>(std::min<std::uint64_t>(requested, max_distance));
      for (std::uint32_t i = 0; i < n; ++i) {
        for (std::uint32_t step = 1u; step <= distance; ++step) {
          if (!PushEdge(topology, i, (i + step) % n, limits, failure)) {
            return false;
          }
        }
      }
      break;
    }

    default: {
      failure.code = DiagnosticCode::kUnsupportedRequest;
      failure.detail = "unsupported synthetic family " + std::to_string(static_cast<std::uint32_t>(options.family));
      return false;
    }
  }

  return true;
}

// ---------------------------------------------------------------------------
// Synthetic materialisation
// ---------------------------------------------------------------------------

std::uint32_t NextStaticCost(SeededRandom& random, const SyntheticOptions& options, bool uniform) noexcept {
  if (options.static_cost_spread == 0u || uniform) {
    return options.static_cost_base;
  }
  const std::uint32_t delta = random.Below(options.static_cost_spread);
  const std::uint32_t base = options.static_cost_base;
  const std::uint32_t room = std::numeric_limits<std::uint32_t>::max() - base;
  return delta > room ? std::numeric_limits<std::uint32_t>::max() : static_cast<std::uint32_t>(base + delta);
}

LinkState PickLinkState(bool down, bool degraded, bool unknown) noexcept {
  if (down) {
    return LinkState::kDown;
  }
  if (degraded) {
    return LinkState::kDegraded;
  }
  return unknown ? LinkState::kUnknown : LinkState::kUp;
}

SnapshotBuildResult BuildSyntheticFabric(const SyntheticOptions& options, SyntheticFabric* out) {
  const ResourceLimits& limits = options.limits;
  if (const std::optional<DiagnosticCode> limit_error = ValidateLimits(limits); limit_error.has_value()) {
    return Fail(*limit_error, "resource limits are incoherent");
  }
  if (!RelationshipForLayer(options.layer).has_value()) {
    return Fail(DiagnosticCode::kUnsupportedLayer,
                "unsupported path layer " + std::to_string(static_cast<std::uint32_t>(options.layer)));
  }

  Topology topology;
  Failure failure;
  if (!BuildTopology(options, topology, failure)) {
    return Fail(failure.code, std::move(failure.detail));
  }

  const std::uint32_t n = topology.node_count;
  const std::uint64_t edge_count = static_cast<std::uint64_t>(topology.edges.size());
  const std::uint64_t port_count = 2u * edge_count + n;  // one port per edge end plus one access port per node
  const std::uint32_t capability_count = std::max<std::uint32_t>(1u, options.capability_bindings);
  const std::uint32_t domain_count = std::max<std::uint32_t>(1u, options.failure_domains);

  // View ceilings are checked from the exact derived counts before anything is
  // materialised: a request that cannot fit is rejected, never truncated.
  if (static_cast<std::uint64_t>(n) > limits.max_endpoints) {
    return Fail(DiagnosticCode::kGraphTooLarge, "synthetic fabric exceeds max_endpoints");
  }
  if (port_count > limits.max_port_state_records) {
    return Fail(DiagnosticCode::kGraphTooLarge, "synthetic fabric exceeds max_port_state_records");
  }
  if ((static_cast<std::uint64_t>(n) + edge_count) * capability_count > limits.max_capability_bindings) {
    return Fail(DiagnosticCode::kGraphTooLarge, "synthetic fabric exceeds max_capability_bindings");
  }
  if (static_cast<std::uint64_t>(domain_count) > limits.max_failure_domains) {
    return Fail(DiagnosticCode::kGraphTooLarge, "synthetic fabric exceeds max_failure_domains");
  }

  const std::uint32_t family = static_cast<std::uint32_t>(options.family);
  const std::uint64_t seed = options.seed;
  const RelationshipType relationship = *RelationshipForLayer(options.layer);

  std::vector<NodeId> node_ids(n);
  std::vector<std::vector<PortId>> node_ports(n);
  for (std::uint32_t i = 0; i < n; ++i) {
    node_ids[i] = IdFromLabel<NodeId>(FabricLabel("n", family, seed, i, 0));
    const std::uint32_t port_total = topology.degree[i] + 1u;  // edges consume 0..degree-1
    node_ports[i].reserve(port_total);
    for (std::uint32_t port = 0; port < port_total; ++port) {
      node_ports[i].push_back(IdFromLabel<PortId>(FabricLabel("p", family, seed, i, port)));
    }
  }

  FabricSnapshotBuilder builder(limits);
  SnapshotGenerations generations;
  generations.topology = TopologyGeneration(1);
  generations.link_state = LinkStateGeneration(1);
  generations.ports = PortGeneration(1);
  generations.capabilities = CapabilityGeneration(1);
  generations.failure_domains = FailureDomainGeneration(1);
  generations.epoch = FabricEpoch(1);
  generations.policy = PolicyGeneration(1);
  generations.constraints = ConstraintGeneration(1);
  builder.SetGenerations(generations);
  builder.SetSource(EvidenceSource::kSynthetic);

  for (std::uint32_t i = 0; i < n; ++i) {
    NodeRecord node;
    node.id = node_ids[i];
    node.attachment = IdFromLabel<SwitchId>(FabricLabel("s", family, seed, i, 0));
    node.entity_generation = EntityGeneration(1);
    node.structural_generation = TopologyGeneration(1);
    node.ports = node_ports[i];
    if (!builder.AddNode(std::move(node))) {
      return BuilderFailure(builder);
    }
  }

  // One PRNG stream for every per-entity decision, consumed in a fixed order:
  // for each link the static cost then four state rolls, then two rolls per port.
  // The roll count per entity is independent of the configured percentages, so
  // the stream does not shift when an option is enabled.
  SeededRandom random(seed);
  std::vector<std::uint32_t> used_ports(n, 0u);
  std::vector<LinkId> link_ids;
  link_ids.reserve(topology.edges.size());
  std::vector<LinkStateRecord> link_states;
  link_states.reserve(topology.edges.size());

  for (const EdgeDraft& draft : topology.edges) {
    const std::uint32_t static_cost = NextStaticCost(random, options, topology.uniform_cost);
    const bool absent = random.Percent(options.percent_without_link_state_record);
    const bool down = random.Percent(options.percent_down);
    const bool degraded = random.Percent(options.percent_degraded);
    const bool unknown = random.Percent(options.percent_unknown);

    EdgeRecord edge;
    edge.id = IdFromLabel<LinkId>(FabricLabel("l", family, seed, link_ids.size(), 0));
    edge.from = node_ids[draft.from];
    edge.to = node_ids[draft.to];
    edge.from_port = node_ports[draft.from][used_ports[draft.from]++];
    edge.to_port = node_ports[draft.to][used_ports[draft.to]++];
    edge.layer = options.layer;
    edge.relationship = relationship;
    edge.static_cost = StaticCost(static_cost);
    edge.entity_generation = EntityGeneration(1);
    edge.structural_generation = TopologyGeneration(1);
    link_ids.push_back(edge.id);
    if (!absent) {
      // Absence of an authoritative record is UNKNOWN, which is never UP.
      link_states.push_back(LinkStateRecord{edge.id, PickLinkState(down, degraded, unknown)});
    }
    if (!builder.AddEdge(std::move(edge))) {
      return BuilderFailure(builder);
    }
  }
  if (static_cast<std::uint64_t>(link_states.size()) > limits.max_link_state_records) {
    return Fail(DiagnosticCode::kGraphTooLarge, "synthetic fabric exceeds max_link_state_records");
  }
  builder.SetLinkStates(std::move(link_states));

  std::vector<PortStateRecord> port_states;
  port_states.reserve(static_cast<std::size_t>(port_count));
  for (std::uint32_t i = 0; i < n; ++i) {
    for (const PortId& port : node_ports[i]) {
      const bool disabled = random.Percent(options.percent_port_disabled);
      const bool unknown = random.Percent(options.percent_unknown);
      PortStateRecord record;
      record.port = port;
      record.state = disabled ? PortState::kAdminDisabled : (unknown ? PortState::kUnknown : PortState::kUp);
      port_states.push_back(record);
    }
  }
  builder.SetPortStates(std::move(port_states));

  std::vector<CapabilityId> capabilities(capability_count);
  for (std::uint32_t capability = 0; capability < capability_count; ++capability) {
    capabilities[capability] = IdFromLabel<CapabilityId>(FabricLabel("c", family, seed, capability, 0));
  }
  std::vector<CapabilityBinding> bindings;
  bindings.reserve(static_cast<std::size_t>((static_cast<std::uint64_t>(n) + edge_count) * capability_count));
  for (std::uint32_t i = 0; i < n; ++i) {
    for (std::uint32_t capability = 0; capability < capability_count; ++capability) {
      bindings.push_back(CapabilityBinding{SubjectKey::ForNode(node_ids[i]), capabilities[capability],
                                           CapabilityValue(1u + capability)});
    }
  }
  for (const LinkId& link : link_ids) {
    for (std::uint32_t capability = 0; capability < capability_count; ++capability) {
      bindings.push_back(CapabilityBinding{SubjectKey::ForLink(link), capabilities[capability],
                                           CapabilityValue(1u + capability)});
    }
  }
  builder.SetCapabilities(std::move(bindings));

  // Nodes and links are assigned to domains round-robin by structural position;
  // membership is published by the registry, never inferred by a consumer.
  std::vector<std::uint64_t> domain_members(domain_count, 0u);
  for (std::uint32_t i = 0; i < n; ++i) {
    ++domain_members[i % domain_count];
  }
  for (const EdgeDraft& draft : topology.edges) {
    ++domain_members[draft.from % domain_count];
  }
  for (const std::uint64_t members : domain_members) {
    if (members > limits.max_members_per_failure_domain) {
      return Fail(DiagnosticCode::kGraphTooLarge, "synthetic fabric exceeds max_members_per_failure_domain");
    }
  }
  std::vector<FailureDomainRecord> domains(domain_count);
  for (std::uint32_t domain = 0; domain < domain_count; ++domain) {
    domains[domain].domain = IdFromLabel<FailureDomainId>(FabricLabel("f", family, seed, domain, 0));
    // Two risk classes: alternating domains never share a class with a neighbour
    // domain, which exercises class-level constraint checks.
    domains[domain].risk_class =
        IdFromLabel<FailureDomainClass>(FabricLabel("fc", family, seed, domain % 2u, 0));
  }
  for (std::uint32_t i = 0; i < n; ++i) {
    domains[i % domain_count].members.push_back(SubjectKey::ForNode(node_ids[i]));
  }
  for (std::size_t index = 0; index < topology.edges.size(); ++index) {
    const std::uint32_t domain = topology.edges[index].from % domain_count;
    domains[domain].members.push_back(SubjectKey::ForLink(link_ids[index]));
  }
  builder.SetFailureDomains(std::move(domains), options.membership_complete);

  for (std::uint32_t i = 0; i < n; ++i) {
    EndpointRecord endpoint;
    endpoint.id = IdFromLabel<EndpointId>(FabricLabel("e", family, seed, i, 0));
    endpoint.endpoint_class = EndpointClass::kEndpoint;
    endpoint.node = node_ids[i];
    endpoint.port = node_ports[i].back();  // the dedicated access port, never used by an edge
    endpoint.entity_generation = EntityGeneration(1);
    if (!builder.AddEndpoint(std::move(endpoint))) {
      return BuilderFailure(builder);
    }
  }

  SnapshotBuildResult result = builder.Build();
  if (!result.ok() || out == nullptr) {
    return result;
  }

  const EndpointId source_id = IdFromLabel<EndpointId>(FabricLabel("e", family, seed, topology.source, 0));
  const EndpointId destination_id =
      IdFromLabel<EndpointId>(FabricLabel("e", family, seed, topology.destination, 0));
  const EndpointRecord* source = result.snapshot->FindEndpoint(source_id);
  const EndpointRecord* destination = result.snapshot->FindEndpoint(destination_id);
  if (source == nullptr || destination == nullptr) {
    return Fail(DiagnosticCode::kUnknownEndpoint, "generated snapshot is missing its reported endpoints");
  }

  out->snapshot = result.snapshot;
  out->source = source->id;
  out->destination = destination->id;
  out->source_node = source->node;
  out->destination_node = destination->node;
  out->source_generation = source->entity_generation;
  out->destination_generation = destination->entity_generation;
  out->endpoint_class = source->endpoint_class;
  return result;
}

// ---------------------------------------------------------------------------
// Local host helpers
// ---------------------------------------------------------------------------
#ifdef _WIN32

std::string Utf8FromWide(const wchar_t* text) {
  std::string utf8;
  if (text == nullptr) {
    return utf8;
  }
  const std::size_t length = wcslen(text);
  if (length == 0u) {
    return utf8;
  }
  const int wide_length = static_cast<int>(length);
  const int required = WideCharToMultiByte(CP_UTF8, 0, text, wide_length, nullptr, 0, nullptr, nullptr);
  if (required <= 0) {
    return utf8;
  }
  utf8.resize(static_cast<std::size_t>(required));
  const int written = WideCharToMultiByte(CP_UTF8, 0, text, wide_length, utf8.data(), required, nullptr, nullptr);
  if (written <= 0) {
    utf8.clear();
    return utf8;
  }
  utf8.resize(static_cast<std::size_t>(written));
  return utf8;
}

// Lowercase colon-free hex. Empty when the adapter publishes no usable physical
// address, or publishes one that is not a hardware address at all.
std::string PhysicalAddressHex(const std::uint8_t* bytes, std::uint32_t length) {
  if (bytes == nullptr || length == 0u || length > 8u) {
    return std::string();
  }
  static constexpr char kHexDigits[] = "0123456789abcdef";
  std::string text;
  text.reserve(static_cast<std::size_t>(length) * 2u);
  for (std::uint32_t i = 0; i < length; ++i) {
    text.push_back(kHexDigits[(bytes[i] >> 4) & 0x0Fu]);
    text.push_back(kHexDigits[bytes[i] & 0x0Fu]);
  }
  return text;
}

#endif  // _WIN32

// The first two usable adapters, in enumeration order. Preference is explicit
// and staged so a down or loopback adapter is only used when nothing better
// exists: up non-loopback, then any non-loopback, then anything at all.
std::vector<std::size_t> SelectEndpointAdapters(const std::vector<LocalAdapter>& adapters) {
  std::vector<std::size_t> selected;
  for (std::uint32_t tier = 0; tier < 3u && selected.size() < 2u; ++tier) {
    for (std::size_t index = 0; index < adapters.size() && selected.size() < 2u; ++index) {
      if (std::find(selected.begin(), selected.end(), index) != selected.end()) {
        continue;
      }
      const LocalAdapter& adapter = adapters[index];
      const bool usable = (tier == 0u) ? (!adapter.loopback && adapter.up) : ((tier == 1u) ? !adapter.loopback : true);
      if (usable) {
        selected.push_back(index);
      }
    }
  }
  return selected;
}

std::string HostKey(const std::vector<LocalAdapter>& adapters) {
  std::string key;
  for (const LocalAdapter& adapter : adapters) {
    key.append(adapter.name);
    key.push_back('|');
    key.append(adapter.mac);
    key.push_back('|');
    key.append(std::to_string(adapter.if_index));
    key.push_back(';');
  }
  return key;
}

}  // namespace

// ---------------------------------------------------------------------------
// Synthetic fabric (public API)
// ---------------------------------------------------------------------------
SnapshotBuildResult GenerateSyntheticFabric(const SyntheticOptions& options) {
  return BuildSyntheticFabric(options, nullptr);
}

std::optional<SyntheticFabric> MakeSyntheticFabric(const SyntheticOptions& options, std::string& error) {
  error.clear();
  SyntheticFabric fabric;
  const SnapshotBuildResult result = BuildSyntheticFabric(options, &fabric);
  if (!result.ok()) {
    error = result.detail;
    if (error.empty() && result.error.has_value()) {
      error = std::string(ToString(*result.error));
    }
    return std::nullopt;
  }
  return fabric;
}

// ---------------------------------------------------------------------------
// Local host (public API)
// ---------------------------------------------------------------------------
bool LocalDiscoverySupported() {
#ifdef _WIN32
  return true;
#else
  return false;
#endif
}

std::vector<LocalAdapter> EnumerateLocalAdapters() {
  std::vector<LocalAdapter> adapters;
#ifdef _WIN32
  ULONG size = 16u * 1024u;
  std::vector<std::byte> buffer(static_cast<std::size_t>(size));
  ULONG status = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr,
                                     reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
  if (status == ERROR_BUFFER_OVERFLOW) {
    buffer.assign(static_cast<std::size_t>(size), std::byte{0});
    status = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr,
                                  reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
  }
  if (status != NO_ERROR) {
    // A failed or unsupported query reports nothing. It never invents adapters.
    return adapters;
  }
  const IP_ADAPTER_ADDRESSES* current = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buffer.data());
  while (current != nullptr) {
    LocalAdapter adapter;
    adapter.name = Utf8FromWide(current->FriendlyName);
    adapter.description = Utf8FromWide(current->Description);
    adapter.mac = PhysicalAddressHex(current->PhysicalAddress,
                                     static_cast<std::uint32_t>(current->PhysicalAddressLength));
    adapter.if_index =
        static_cast<std::uint64_t>(current->IfIndex != 0u ? current->IfIndex : current->Ipv6IfIndex);
    adapter.up = current->OperStatus == IfOperStatusUp;
    adapter.loopback = current->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
    adapter.layer = PathLayer::kPhysical;
    adapters.push_back(std::move(adapter));
    current = current->Next;
  }
  // Enumeration order is an implementation detail of the platform; ordering by
  // interface index keeps repeated queries and their snapshots identical.
  std::sort(adapters.begin(), adapters.end(), [](const LocalAdapter& lhs, const LocalAdapter& rhs) {
    if (lhs.if_index != rhs.if_index) {
      return lhs.if_index < rhs.if_index;
    }
    if (lhs.name != rhs.name) {
      return lhs.name < rhs.name;
    }
    return lhs.mac < rhs.mac;
  });
#endif
  return adapters;
}

std::optional<SyntheticFabric> MakeLocalHostFabric(const ResourceLimits& limits, std::string& error) {
  error.clear();
  if (!LocalDiscoverySupported()) {
    error = "local host discovery is unsupported on this platform";
    return std::nullopt;
  }
  const std::vector<LocalAdapter> adapters = EnumerateLocalAdapters();
  if (adapters.empty()) {
    error = "no local host adapter was discovered";
    return std::nullopt;
  }
  if (const std::optional<DiagnosticCode> limit_error = ValidateLimits(limits); limit_error.has_value()) {
    error = "resource limits are incoherent: " + std::string(ToString(*limit_error));
    return std::nullopt;
  }
  if (adapters.size() > static_cast<std::size_t>(limits.max_ports_per_node)) {
    error = "the local host publishes more adapters than max_ports_per_node allows";
    return std::nullopt;
  }
  if (adapters.size() > static_cast<std::size_t>(limits.max_port_state_records)) {
    error = "the local host publishes more adapters than max_port_state_records allows";
    return std::nullopt;
  }

  const std::vector<std::size_t> selected = SelectEndpointAdapters(adapters);
  if (selected.empty()) {
    error = "no local host adapter is usable as an endpoint";
    return std::nullopt;
  }
  const std::size_t endpoint_count = std::min<std::size_t>(2u, selected.size());
  if (endpoint_count > static_cast<std::size_t>(limits.max_endpoints)) {
    error = "the local host view needs more endpoints than max_endpoints allows";
    return std::nullopt;
  }

  // Real identity: the node and its ports are derived from the adapters the host
  // actually publishes, so the same host always yields the same snapshot.
  const std::string host_key = HostKey(adapters);
  const NodeId node_id = IdFromLabel<NodeId>("localhost:node:" + host_key);
  std::vector<PortId> ports;
  ports.reserve(adapters.size());
  for (std::size_t index = 0; index < adapters.size(); ++index) {
    ports.push_back(IdFromLabel<PortId>("localhost:port:" + std::to_string(index) + ":" + host_key));
  }

  FabricSnapshotBuilder builder(limits);
  SnapshotGenerations generations;
  generations.topology = TopologyGeneration(1);
  generations.link_state = LinkStateGeneration(1);
  generations.ports = PortGeneration(1);
  generations.capabilities = CapabilityGeneration(1);
  generations.failure_domains = FailureDomainGeneration(1);
  generations.epoch = FabricEpoch(1);
  generations.policy = PolicyGeneration(1);
  generations.constraints = ConstraintGeneration(1);
  builder.SetGenerations(generations);
  builder.SetSource(EvidenceSource::kReal);

  NodeRecord node;
  node.id = node_id;
  node.attachment = SwitchId{};  // host-level node: no owning switch
  node.entity_generation = EntityGeneration(1);
  node.structural_generation = TopologyGeneration(1);
  node.ports = ports;
  if (!builder.AddNode(std::move(node))) {
    error = "the local host node was rejected by the snapshot builder";
    return std::nullopt;
  }

  std::vector<PortStateRecord> port_states;
  port_states.reserve(adapters.size());
  for (std::size_t index = 0; index < adapters.size(); ++index) {
    PortStateRecord record;
    record.port = ports[index];
    // An adapter that is not operationally up has no proven usable state.
    record.state = adapters[index].up ? PortState::kUp : PortState::kUnknown;
    port_states.push_back(record);
  }
  builder.SetPortStates(std::move(port_states));
  // No links exist, and the local host publishes no capability or failure-domain
  // registry: absence means UNKNOWN, which never satisfies a requirement.
  builder.SetLinkStates({});
  builder.SetCapabilities({});
  builder.SetFailureDomains({}, false);

  std::vector<EndpointId> endpoint_ids;
  endpoint_ids.reserve(endpoint_count);
  for (std::size_t slot = 0; slot < endpoint_count; ++slot) {
    EndpointRecord endpoint;
    endpoint.id = IdFromLabel<EndpointId>("localhost:endpoint:" + std::to_string(selected[slot]) + ":" + host_key);
    endpoint.endpoint_class = EndpointClass::kNic;
    endpoint.node = node_id;
    endpoint.port = ports[selected[slot]];
    endpoint.entity_generation = EntityGeneration(1);
    endpoint_ids.push_back(endpoint.id);
    if (!builder.AddEndpoint(std::move(endpoint))) {
      error = "a local host endpoint was rejected by the snapshot builder";
      return std::nullopt;
    }
  }

  const SnapshotBuildResult result = builder.Build();
  if (!result.ok()) {
    error = result.detail.empty() ? "the local host snapshot could not be built" : result.detail;
    return std::nullopt;
  }

  SyntheticFabric fabric;
  fabric.snapshot = result.snapshot;
  fabric.source = endpoint_ids.front();
  fabric.destination = endpoint_ids.back();  // a single-adapter host plans a zero-hop self path
  fabric.source_node = node_id;
  fabric.destination_node = node_id;
  fabric.source_generation = EntityGeneration(1);
  fabric.destination_generation = EntityGeneration(1);
  fabric.endpoint_class = EndpointClass::kNic;  // adapters are NICs, not abstract endpoints
  return fabric;
}

}  // namespace summon::pathplanner

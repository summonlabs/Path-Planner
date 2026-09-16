// tests/oracle_tests.cpp
//
// Independent-oracle and property suite for Path Planner.
//
// The oracle is deliberately a DIFFERENT algorithm from production code: every
// simple path over the snapshot edges is enumerated by depth-first search with a
// visited set (brute force), filtered by the same documented hard constraints,
// costed by an independent checked-arithmetic implementation of the documented
// cost model, and ordered by the documented canonical comparator
// (total cost, then hop count, then NodeId sequence, then LinkId sequence).
// No production search entry point is used to build an expectation: production is
// asked for a result and that result is compared against the oracle.
//
// Identifiers are never invented here either: every node/link/port/endpoint id is
// the SHA-256 of a label string, so every graph is reproducible and independent of
// insertion order.
#include "pathplanner/pathplanner.hpp"

#include "test_framework.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using namespace summon::pathplanner;

constexpr std::uint64_t kU64Max = 0xFFFFFFFFFFFFFFFFull;

// ---------------------------------------------------------------------------
// Deterministic identifiers
// ---------------------------------------------------------------------------
template <class Id>
Id IdFromLabel(std::string_view label) {
  return Id::FromDigest(Sha256::Hash(label));
}

template <class Id>
std::string Id8(const Id& id) {
  const std::string text = id.ToString();
  return text.size() <= 8 ? text : text.substr(0, 8);
}

// ---------------------------------------------------------------------------
// Tiny deterministic graph builder. Nodes and links are added in the order given
// (or reversed on request); the snapshot builder sorts them, so the snapshot
// digest never depends on insertion order.
// ---------------------------------------------------------------------------
struct PendingLink {
  LinkId id;
  NodeId from;
  NodeId to;
  PortId from_port;
  PortId to_port;
  std::uint32_t static_cost = 0;
  LinkState state = LinkState::kUp;
  PortState from_state = PortState::kUp;
  PortState to_state = PortState::kUp;
  PathLayer layer = PathLayer::kPhysical;
};

struct NodeSpec {
  NodeId id;
  std::string label;
  PortId port;
};

struct BuiltFabric {
  std::shared_ptr<const FabricSnapshot> snapshot;
  std::vector<LinkId> links;
  std::map<std::string, NodeId> node_by_label;
  std::map<std::string, LinkId> link_by_label;
  std::map<std::string, PortId> port_by_label;
  std::map<std::string, EndpointId> endpoint_by_label;
  bool ok = false;
};

class GraphBuilder {
 public:
  explicit GraphBuilder(std::string name) : name_(std::move(name)) {}

  NodeId Node(std::string_view label) {
    NodeSpec spec;
    spec.id = IdFromLabel<NodeId>(name_ + "/node/" + std::string(label));
    spec.label = std::string(label);
    spec.port = IdFromLabel<PortId>(name_ + "/nodeport/" + std::string(label));
    nodes_.push_back(spec);
    return spec.id;
  }

  LinkId Link(std::string_view label, const NodeId& from, const NodeId& to, std::uint32_t cost,
              LinkState state = LinkState::kUp, PortState from_state = PortState::kUp,
              PortState to_state = PortState::kUp, PathLayer layer = PathLayer::kPhysical) {
    PendingLink link;
    link.id = IdFromLabel<LinkId>(name_ + "/link/" + std::string(label));
    link.from = from;
    link.to = to;
    link.from_port = IdFromLabel<PortId>(name_ + "/linkport/" + std::string(label) + "/from");
    link.to_port = IdFromLabel<PortId>(name_ + "/linkport/" + std::string(label) + "/to");
    link.static_cost = cost;
    link.state = state;
    link.from_state = from_state;
    link.to_state = to_state;
    link.layer = layer;
    links_.push_back(link);
    link_labels_[link.id] = std::string(label);
    port_labels_[link.from_port] = std::string(label) + "/from";
    port_labels_[link.to_port] = std::string(label) + "/to";
    return link.id;
  }

  EndpointId Endpoint(std::string_view label, const NodeId& node) {
    const EndpointId id = IdFromLabel<EndpointId>(name_ + "/endpoint/" + std::string(label));
    endpoint_labels_[id] = std::string(label);
    endpoint_nodes_[id] = node;
    return id;
  }

  void SetReverseInsertion(bool value) { reverse_ = value; }
  void SetMembershipComplete(bool value) { membership_complete_ = value; }

  void AddCapability(const SubjectKey& subject, const CapabilityId& capability, std::uint64_t value) {
    capabilities_.push_back(CapabilityBinding{subject, capability, CapabilityValue(value)});
  }

  void AddDomain(const FailureDomainId& domain, const FailureDomainClass& risk_class,
                 const std::vector<SubjectKey>& members) {
    FailureDomainRecord record;
    record.domain = domain;
    record.risk_class = risk_class;
    record.members = members;
    domains_.push_back(record);
  }

  BuiltFabric Build() {
    BuiltFabric out;
    for (const NodeSpec& spec : nodes_) {
      out.node_by_label[spec.label] = spec.id;
    }
    for (const PendingLink& link : links_) {
      out.links.push_back(link.id);
    }
    for (const auto& entry : link_labels_) {
      out.link_by_label[entry.second] = entry.first;
    }
    for (const auto& entry : port_labels_) {
      out.port_by_label[entry.second] = entry.first;
    }
    for (const auto& entry : endpoint_labels_) {
      out.endpoint_by_label[entry.second] = entry.first;
    }

    FabricSnapshotBuilder builder(ResourceLimits{});
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

    std::map<NodeId, std::vector<PortId>> ports;
    for (const NodeSpec& node : nodes_) {
      ports[node.id].push_back(node.port);
    }
    for (const PendingLink& link : links_) {
      ports[link.from].push_back(link.from_port);
      ports[link.to].push_back(link.to_port);
    }

    std::vector<std::size_t> node_order;
    for (std::size_t i = 0; i < nodes_.size(); ++i) {
      node_order.push_back(i);
    }
    std::vector<std::size_t> link_order;
    for (std::size_t i = 0; i < links_.size(); ++i) {
      link_order.push_back(i);
    }
    if (reverse_) {
      std::reverse(node_order.begin(), node_order.end());
      std::reverse(link_order.begin(), link_order.end());
    }

    for (const std::size_t index : node_order) {
      const NodeSpec& spec = nodes_[index];
      NodeRecord record;
      record.id = spec.id;
      record.attachment = SwitchId{};
      record.entity_generation = EntityGeneration(1);
      record.structural_generation = TopologyGeneration(1);
      record.ports = ports[spec.id];
      if (!builder.AddNode(std::move(record))) {
        return out;
      }
    }
    for (const std::size_t index : link_order) {
      const PendingLink& link = links_[index];
      EdgeRecord record;
      record.id = link.id;
      record.from = link.from;
      record.to = link.to;
      record.from_port = link.from_port;
      record.to_port = link.to_port;
      record.layer = link.layer;
      switch (link.layer) {
        case PathLayer::kLogical:
          record.relationship = RelationshipType::kLogicalAdjacency;
          break;
        case PathLayer::kOverlay:
        case PathLayer::kTunnel:
          record.relationship = RelationshipType::kTunnelEncapsulation;
          break;
        default:
          record.relationship = RelationshipType::kDirectLink;
          break;
      }
      record.static_cost = StaticCost(link.static_cost);
      record.entity_generation = EntityGeneration(1);
      record.structural_generation = TopologyGeneration(1);
      if (!builder.AddEdge(std::move(record))) {
        return out;
      }
    }

    std::vector<LinkStateRecord> link_states;
    std::vector<PortStateRecord> port_states;
    for (const PendingLink& link : links_) {
      link_states.push_back(LinkStateRecord{link.id, link.state});
      port_states.push_back(PortStateRecord{link.from_port, link.from_state});
      port_states.push_back(PortStateRecord{link.to_port, link.to_state});
    }
    builder.SetLinkStates(link_states);
    builder.SetPortStates(port_states);
    builder.SetCapabilities(capabilities_);
    builder.SetFailureDomains(domains_, membership_complete_);

    for (const auto& entry : endpoint_nodes_) {
      EndpointRecord record;
      record.id = entry.first;
      record.endpoint_class = EndpointClass::kEndpoint;
      record.node = entry.second;
      record.port = IdFromLabel<PortId>(name_ + "/nodeport/" + LabelOf(entry.second));
      record.entity_generation = EntityGeneration(1);
      if (!builder.AddEndpoint(std::move(record))) {
        return out;
      }
    }

    SnapshotBuildResult result = builder.Build();
    if (!result.ok()) {
      return out;
    }
    out.snapshot = result.snapshot;
    out.ok = true;
    return out;
  }

  std::string LabelOf(const NodeId& id) const {
    for (const NodeSpec& spec : nodes_) {
      if (spec.id == id) {
        return spec.label;
      }
    }
    return std::string("?");
  }

 private:
  std::string name_;
  std::vector<NodeSpec> nodes_;
  std::vector<PendingLink> links_;
  std::map<LinkId, std::string> link_labels_;
  std::map<PortId, std::string> port_labels_;
  std::map<EndpointId, std::string> endpoint_labels_;
  std::map<EndpointId, NodeId> endpoint_nodes_;
  std::vector<CapabilityBinding> capabilities_;
  std::vector<FailureDomainRecord> domains_;
  bool membership_complete_ = false;
  bool reverse_ = false;
};

// ---------------------------------------------------------------------------
// Tiny graph families. Every family below is <= 7 nodes unless it is a deliberate
// "long chain" probe, and every endpoint pair is registered as "src"/"dst".
// ---------------------------------------------------------------------------
std::uint32_t CostAt(std::uint64_t seed, int index) {
  return static_cast<std::uint32_t>(1 + ((seed + static_cast<std::uint64_t>(index) * 7ull) % 3ull));
}

BuiltFabric BuildChain(const std::string& name, int count, bool bidirectional, std::uint64_t seed) {
  GraphBuilder builder(name);
  std::vector<NodeId> nodes;
  for (int i = 0; i < count; ++i) {
    nodes.push_back(builder.Node("n" + std::to_string(i)));
  }
  for (int i = 0; i + 1 < count; ++i) {
    const std::uint32_t cost = CostAt(seed, i);
    builder.Link("f" + std::to_string(i), nodes[static_cast<std::size_t>(i)],
                 nodes[static_cast<std::size_t>(i) + 1], cost);
    if (bidirectional) {
      builder.Link("b" + std::to_string(i), nodes[static_cast<std::size_t>(i) + 1],
                   nodes[static_cast<std::size_t>(i)], cost);
    }
  }
  builder.Endpoint("src", nodes.front());
  builder.Endpoint("dst", nodes.back());
  return builder.Build();
}

BuiltFabric BuildRing(const std::string& name, int count, std::uint64_t seed) {
  GraphBuilder builder(name);
  std::vector<NodeId> nodes;
  for (int i = 0; i < count; ++i) {
    nodes.push_back(builder.Node("n" + std::to_string(i)));
  }
  for (int i = 0; i < count; ++i) {
    const int next = (i + 1) % count;
    builder.Link("f" + std::to_string(i), nodes[static_cast<std::size_t>(i)],
                 nodes[static_cast<std::size_t>(next)], CostAt(seed, i));
    builder.Link("b" + std::to_string(i), nodes[static_cast<std::size_t>(next)],
                 nodes[static_cast<std::size_t>(i)], CostAt(seed, i + 1));
  }
  builder.Endpoint("src", nodes.front());
  builder.Endpoint("dst", nodes[static_cast<std::size_t>(count) / 2]);
  return builder.Build();
}

BuiltFabric BuildDiamond(const std::string& name, bool equal_costs, std::uint64_t seed) {
  GraphBuilder builder(name);
  const NodeId s = builder.Node("s");
  const NodeId a = builder.Node("a");
  const NodeId b = builder.Node("b");
  const NodeId d = builder.Node("d");
  if (equal_costs) {
    const std::uint32_t cost = CostAt(seed, 0);
    builder.Link("s-a", s, a, cost);
    builder.Link("a-d", a, d, cost);
    builder.Link("s-b", s, b, cost);
    builder.Link("b-d", b, d, cost);
  } else if (seed % 2 == 0) {
    builder.Link("s-a", s, a, 1);
    builder.Link("a-d", a, d, 1);
    builder.Link("s-b", s, b, 4);
    builder.Link("b-d", b, d, 4);
  } else {
    builder.Link("s-a", s, a, 4);
    builder.Link("a-d", a, d, 4);
    builder.Link("s-b", s, b, 1);
    builder.Link("b-d", b, d, 1);
  }
  builder.Endpoint("src", s);
  builder.Endpoint("dst", d);
  return builder.Build();
}

BuiltFabric BuildLeafSpine(const std::string& name, int leaves, int spines, std::uint64_t seed) {
  GraphBuilder builder(name);
  std::vector<NodeId> leaf_nodes;
  std::vector<NodeId> spine_nodes;
  for (int i = 0; i < leaves; ++i) {
    leaf_nodes.push_back(builder.Node("leaf" + std::to_string(i)));
  }
  for (int i = 0; i < spines; ++i) {
    spine_nodes.push_back(builder.Node("spine" + std::to_string(i)));
  }
  for (int i = 0; i < leaves; ++i) {
    for (int j = 0; j < spines; ++j) {
      const std::string stem = std::to_string(i) + "_" + std::to_string(j);
      builder.Link("up" + stem, leaf_nodes[static_cast<std::size_t>(i)],
                   spine_nodes[static_cast<std::size_t>(j)], CostAt(seed, i + j));
      builder.Link("down" + stem, spine_nodes[static_cast<std::size_t>(j)],
                   leaf_nodes[static_cast<std::size_t>(i)], CostAt(seed, i + 2 * j));
    }
  }
  builder.Endpoint("src", leaf_nodes.front());
  builder.Endpoint("dst", leaf_nodes.back());
  return builder.Build();
}

BuiltFabric BuildFatTree(const std::string& name) {
  GraphBuilder builder(name);
  std::vector<NodeId> core;
  std::vector<NodeId> aggregation;
  std::vector<NodeId> edge;
  for (int i = 0; i < 2; ++i) {
    core.push_back(builder.Node("core" + std::to_string(i)));
  }
  for (int i = 0; i < 2; ++i) {
    aggregation.push_back(builder.Node("agg" + std::to_string(i)));
  }
  for (int i = 0; i < 2; ++i) {
    edge.push_back(builder.Node("edge" + std::to_string(i)));
  }
  for (int i = 0; i < 2; ++i) {
    for (int j = 0; j < 2; ++j) {
      const std::string stem = std::to_string(i) + "_" + std::to_string(j);
      builder.Link("ca" + stem, core[static_cast<std::size_t>(i)], aggregation[static_cast<std::size_t>(j)], 1);
      builder.Link("ac" + stem, aggregation[static_cast<std::size_t>(j)], core[static_cast<std::size_t>(i)], 2);
      builder.Link("ae" + stem, aggregation[static_cast<std::size_t>(i)], edge[static_cast<std::size_t>(j)], 1);
      builder.Link("ea" + stem, edge[static_cast<std::size_t>(j)], aggregation[static_cast<std::size_t>(i)], 1);
    }
  }
  builder.Endpoint("src", edge.front());
  builder.Endpoint("dst", edge.back());
  return builder.Build();
}

BuiltFabric BuildMesh(const std::string& name, int rows, int cols, std::uint64_t seed) {
  GraphBuilder builder(name);
  std::vector<NodeId> nodes;
  for (int r = 0; r < rows; ++r) {
    for (int c = 0; c < cols; ++c) {
      nodes.push_back(builder.Node("m" + std::to_string(r) + "_" + std::to_string(c)));
    }
  }
  const auto at = [&nodes, cols](int r, int c) { return nodes[static_cast<std::size_t>(r * cols + c)]; };
  for (int r = 0; r < rows; ++r) {
    for (int c = 0; c < cols; ++c) {
      const int east = (c + 1) % cols;
      const std::string stem = std::to_string(r) + "_" + std::to_string(c);
      builder.Link("e" + stem, at(r, c), at(r, east), CostAt(seed, r + c));
      builder.Link("w" + stem, at(r, east), at(r, c), CostAt(seed, r + c + 1));
      if (rows > 1) {
        const int south = (r + 1) % rows;
        builder.Link("s" + stem, at(r, c), at(south, c), CostAt(seed, r + 2 * c));
        builder.Link("n" + stem, at(south, c), at(r, c), CostAt(seed, r + 2 * c + 1));
      }
    }
  }
  builder.Endpoint("src", at(0, 0));
  builder.Endpoint("dst", at(rows - 1, cols - 1));
  return builder.Build();
}

BuiltFabric BuildDisconnected(const std::string& name) {
  GraphBuilder builder(name);
  std::vector<NodeId> left;
  std::vector<NodeId> right;
  for (int i = 0; i < 3; ++i) {
    left.push_back(builder.Node("l" + std::to_string(i)));
  }
  for (int i = 0; i < 3; ++i) {
    right.push_back(builder.Node("r" + std::to_string(i)));
  }
  for (int i = 0; i + 1 < 3; ++i) {
    builder.Link("lf" + std::to_string(i), left[static_cast<std::size_t>(i)],
                 left[static_cast<std::size_t>(i) + 1], 1);
    builder.Link("lb" + std::to_string(i), left[static_cast<std::size_t>(i) + 1],
                 left[static_cast<std::size_t>(i)], 1);
    builder.Link("rf" + std::to_string(i), right[static_cast<std::size_t>(i)],
                 right[static_cast<std::size_t>(i) + 1], 1);
    builder.Link("rb" + std::to_string(i), right[static_cast<std::size_t>(i) + 1],
                 right[static_cast<std::size_t>(i)], 1);
  }
  builder.Endpoint("src", left.front());
  builder.Endpoint("dst", right.back());
  return builder.Build();
}

BuiltFabric BuildOneWay(const std::string& name, int count) {
  GraphBuilder builder(name);
  std::vector<NodeId> nodes;
  for (int i = 0; i < count; ++i) {
    nodes.push_back(builder.Node("n" + std::to_string(i)));
  }
  for (int i = 0; i + 1 < count; ++i) {
    builder.Link("f" + std::to_string(i), nodes[static_cast<std::size_t>(i)],
                 nodes[static_cast<std::size_t>(i) + 1], 1);
  }
  builder.Endpoint("src", nodes.front());
  builder.Endpoint("dst", nodes.back());
  return builder.Build();
}

BuiltFabric BuildParallelEqualCost(const std::string& name, int parallel) {
  GraphBuilder builder(name);
  const NodeId s = builder.Node("s");
  const NodeId d = builder.Node("d");
  for (int i = 0; i < parallel; ++i) {
    builder.Link("p" + std::to_string(i), s, d, 1);
  }
  builder.Endpoint("src", s);
  builder.Endpoint("dst", d);
  return builder.Build();
}

BuiltFabric BuildTieStorm(const std::string& name, int middles) {
  GraphBuilder builder(name);
  const NodeId s = builder.Node("s");
  const NodeId d = builder.Node("d");
  for (int i = 0; i < middles; ++i) {
    const NodeId middle = builder.Node("m" + std::to_string(i));
    builder.Link("a" + std::to_string(i), s, middle, 1);
    builder.Link("b" + std::to_string(i), middle, d, 1);
  }
  builder.Endpoint("src", s);
  builder.Endpoint("dst", d);
  return builder.Build();
}

BuiltFabric BuildHighDegreeHub(const std::string& name, int spokes) {
  GraphBuilder builder(name);
  const NodeId hub = builder.Node("hub");
  std::vector<NodeId> leaves;
  for (int i = 0; i < spokes; ++i) {
    leaves.push_back(builder.Node("s" + std::to_string(i)));
  }
  for (int i = 0; i < spokes; ++i) {
    builder.Link("in" + std::to_string(i), leaves[static_cast<std::size_t>(i)], hub, 1);
    builder.Link("out" + std::to_string(i), hub, leaves[static_cast<std::size_t>(i)], 1);
  }
  builder.Endpoint("src", leaves.front());
  builder.Endpoint("dst", leaves.back());
  return builder.Build();
}

// Deep chain over a seeded node permutation: the two endpoints are the ends of the
// permutation, so the canonical path walks the whole chain.
BuiltFabric BuildDeepChain(const std::string& name, int count, std::uint64_t seed) {
  GraphBuilder builder(name);
  std::vector<int> order;
  for (int i = 0; i < count; ++i) {
    order.push_back(i);
  }
  std::uint64_t state = seed * 2654435761ull + 97ull;
  for (int i = count - 1; i > 0; --i) {
    state = state * 6364136223846793005ull + 1442695040888963407ull;
    const int pick = static_cast<int>((state >> 33) % static_cast<std::uint64_t>(i + 1));
    std::swap(order[static_cast<std::size_t>(i)], order[static_cast<std::size_t>(pick)]);
  }
  std::vector<NodeId> nodes;
  for (int i = 0; i < count; ++i) {
    nodes.push_back(builder.Node("p" + std::to_string(order[static_cast<std::size_t>(i)])));
  }
  for (int i = 0; i + 1 < count; ++i) {
    const std::uint32_t cost = CostAt(seed, i);
    builder.Link("f" + std::to_string(i), nodes[static_cast<std::size_t>(i)],
                 nodes[static_cast<std::size_t>(i) + 1], cost);
    builder.Link("b" + std::to_string(i), nodes[static_cast<std::size_t>(i) + 1],
                 nodes[static_cast<std::size_t>(i)], cost);
  }
  builder.Endpoint("src", nodes.front());
  builder.Endpoint("dst", nodes.back());
  return builder.Build();
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------
PlanningRequest MakeRequestBetween(const std::string& label, const BuiltFabric& fabric,
                                   const std::string& source_label, const std::string& destination_label,
                                   PathLayer layer = PathLayer::kPhysical) {
  PlanningRequest request;
  request.id = IdFromLabel<PlanningRequestId>("request/" + label);
  request.source.id = fabric.endpoint_by_label.at(source_label);
  request.source.endpoint_class = EndpointClass::kEndpoint;
  request.source.generation = EntityGeneration(1);
  request.destination = request.source;
  request.destination.id = fabric.endpoint_by_label.at(destination_label);
  request.constraints.id = IdFromLabel<ConstraintSetId>("constraints/" + label);
  request.constraints.generation = ConstraintGeneration(1);
  request.constraints.layer = layer;
  request.policy.generation = PolicyGeneration(1);
  request.max_candidates = 1;
  return request;
}

PlanningRequest MakeRequest(const std::string& label, const BuiltFabric& fabric,
                            PathLayer layer = PathLayer::kPhysical) {
  return MakeRequestBetween(label, fabric, "src", "dst", layer);
}

PlanningResult RunPlan(const std::shared_ptr<const FabricSnapshot>& snapshot, const PlanningRequest& request) {
  PlannerConfig config;
  config.initial_snapshot = snapshot;
  PlannerRuntime runtime(config);
  return runtime.Plan(request);
}

// ---------------------------------------------------------------------------
// Oracle: brute-force enumeration of every simple path over the snapshot edges.
// Independent of production search code: eligibility, cost and ordering are
// re-derived here from the documented rules.
// ---------------------------------------------------------------------------
struct OracleCost {
  std::uint64_t hops_cost = 0;
  std::uint64_t static_cost = 0;
  std::uint64_t degraded_penalty = 0;
  std::uint64_t locality_penalty = 0;
  std::uint64_t total = 0;
  std::uint32_t hops = 0;
  std::uint32_t degraded_hops = 0;
  std::uint32_t locality_breaches = 0;
};

struct OraclePath {
  std::vector<std::uint32_t> edges;
  std::vector<std::uint32_t> nodes;
  OracleCost cost;
};

struct OracleEdgeInfo {
  std::uint32_t from = 0;
  std::uint32_t to = 0;
  bool eligible = false;
  bool degraded = false;
  bool outside_locality = false;
  bool hop_fits = false;
  std::uint64_t traversal = 0;
};

struct Oracle {
  const FabricSnapshot* snapshot = nullptr;
  const PlanningRequest* request = nullptr;
  std::vector<OracleEdgeInfo> edges;
  std::vector<std::vector<std::uint32_t>> out_edges;
  std::vector<bool> node_eligible;
  std::uint32_t source = 0;
  std::uint32_t destination = 0;
  std::uint32_t hop_budget = 0;
  bool usable = false;
  std::vector<OraclePath> paths;
};

bool AddFits(std::uint64_t lhs, std::uint64_t rhs) { return lhs <= kU64Max - rhs; }
bool MulFits(std::uint64_t lhs, std::uint64_t rhs) { return rhs == 0 || lhs <= kU64Max / rhs; }

struct OracleDomainIndex {
  std::map<SubjectKey, std::vector<FailureDomainId>> by_subject;
  std::map<FailureDomainId, FailureDomainClass> classes;
  bool complete = false;

  std::vector<FailureDomainId> Membership(const SubjectKey& subject, bool& known) const {
    const auto it = by_subject.find(subject);
    if (it == by_subject.end()) {
      known = complete;
      return std::vector<FailureDomainId>{};
    }
    known = true;
    return it->second;
  }
};

OracleDomainIndex BuildDomainIndex(const FabricSnapshot& snapshot) {
  OracleDomainIndex index;
  index.complete = snapshot.FailureDomains().MembershipComplete();
  for (const FailureDomainRecord& record : snapshot.FailureDomains().Domains()) {
    index.classes[record.domain] = record.risk_class;
    for (const SubjectKey& member : record.members) {
      index.by_subject[member].push_back(record.domain);
    }
  }
  return index;
}

bool CapabilitySatisfiedByOracle(const FabricSnapshot& snapshot, const SubjectKey& subject,
                                 const CapabilityRequirement& requirement) {
  const std::optional<CapabilityValue> observed = snapshot.Capabilities().Lookup(subject, requirement.capability);
  if (!observed.has_value()) {
    return false;
  }
  switch (requirement.comparator) {
    case CapabilityComparator::kAtLeast:
      return observed->Value() >= requirement.value.Value();
    case CapabilityComparator::kAtMost:
      return observed->Value() <= requirement.value.Value();
    case CapabilityComparator::kEqual:
      return observed->Value() == requirement.value.Value();
  }
  return false;
}

bool DomainCompliantByOracle(const OracleDomainIndex& index, const std::vector<FailureDomainId>& forbidden_domains,
                             const std::vector<FailureDomainClass>& forbidden_classes, const SubjectKey& subject,
                             bool fail_closed) {
  const bool has_constraints = !forbidden_domains.empty() || !forbidden_classes.empty();
  bool known = false;
  const std::vector<FailureDomainId> domains = index.Membership(subject, known);
  if (!known) {
    return !(fail_closed && has_constraints);
  }
  for (const FailureDomainId& domain : domains) {
    if (std::binary_search(forbidden_domains.begin(), forbidden_domains.end(), domain)) {
      return false;
    }
    if (!forbidden_classes.empty()) {
      const auto it = index.classes.find(domain);
      if (it != index.classes.end() &&
          std::binary_search(forbidden_classes.begin(), forbidden_classes.end(), it->second)) {
        return false;
      }
    }
  }
  return true;
}

std::optional<OracleCost> OraclePathCost(const Oracle& oracle, const std::vector<std::uint32_t>& edges) {
  const CostModel& model = oracle.request->policy.cost_model;
  OracleCost cost;
  cost.hops = static_cast<std::uint32_t>(edges.size());
  if (!MulFits(model.hop_cost.Value(), edges.size())) {
    return std::nullopt;
  }
  cost.hops_cost = model.hop_cost.Value() * static_cast<std::uint64_t>(edges.size());
  for (const std::uint32_t edge_index : edges) {
    const std::uint64_t static_cost = oracle.snapshot->Edges()[edge_index].static_cost.Value();
    if (!AddFits(cost.static_cost, static_cost)) {
      return std::nullopt;
    }
    cost.static_cost += static_cost;
    if (oracle.edges[edge_index].degraded) {
      cost.degraded_hops += 1;
    }
    if (oracle.edges[edge_index].outside_locality) {
      cost.locality_breaches += 1;
    }
  }
  if (!MulFits(model.degraded_penalty.Value(), cost.degraded_hops)) {
    return std::nullopt;
  }
  cost.degraded_penalty = model.degraded_penalty.Value() * static_cast<std::uint64_t>(cost.degraded_hops);
  if (!MulFits(model.locality_penalty.Value(), cost.locality_breaches)) {
    return std::nullopt;
  }
  cost.locality_penalty = model.locality_penalty.Value() * static_cast<std::uint64_t>(cost.locality_breaches);
  cost.total = cost.hops_cost;
  if (!AddFits(cost.total, cost.static_cost)) {
    return std::nullopt;
  }
  cost.total += cost.static_cost;
  if (!AddFits(cost.total, cost.degraded_penalty)) {
    return std::nullopt;
  }
  cost.total += cost.degraded_penalty;
  if (!AddFits(cost.total, cost.locality_penalty)) {
    return std::nullopt;
  }
  cost.total += cost.locality_penalty;
  return cost;
}

void OracleDfs(const Oracle& oracle, std::uint32_t node, std::vector<std::uint32_t>& edges,
               std::vector<std::uint32_t>& nodes, std::vector<bool>& visited, std::vector<OraclePath>& out) {
  if (node == oracle.destination) {
    OraclePath path;
    path.edges = edges;
    path.nodes = nodes;
    const std::optional<OracleCost> cost = OraclePathCost(oracle, edges);
    if (cost.has_value()) {
      path.cost = *cost;
      out.push_back(std::move(path));
    }
    return;
  }
  if (edges.size() >= static_cast<std::size_t>(oracle.hop_budget)) {
    return;
  }
  for (const std::uint32_t edge_index : oracle.out_edges[node]) {
    const OracleEdgeInfo& info = oracle.edges[edge_index];
    if (!info.hop_fits || visited[info.to]) {
      continue;
    }
    visited[info.to] = true;
    edges.push_back(edge_index);
    nodes.push_back(info.to);
    OracleDfs(oracle, info.to, edges, nodes, visited, out);
    nodes.pop_back();
    edges.pop_back();
    visited[info.to] = false;
  }
}

// Documented canonical comparator: total cost, hop count, NodeId sequence,
// LinkId sequence.
bool CanonicalLess(const FabricSnapshot& snapshot, const OraclePath& lhs, const OraclePath& rhs) {
  if (lhs.cost.total != rhs.cost.total) {
    return lhs.cost.total < rhs.cost.total;
  }
  if (lhs.cost.hops != rhs.cost.hops) {
    return lhs.cost.hops < rhs.cost.hops;
  }
  const std::size_t shared_nodes = std::min(lhs.nodes.size(), rhs.nodes.size());
  for (std::size_t i = 0; i < shared_nodes; ++i) {
    const NodeId& left = snapshot.Nodes()[lhs.nodes[i]].id;
    const NodeId& right = snapshot.Nodes()[rhs.nodes[i]].id;
    if (left != right) {
      return left < right;
    }
  }
  if (lhs.nodes.size() != rhs.nodes.size()) {
    return lhs.nodes.size() < rhs.nodes.size();
  }
  const std::size_t shared_hops = std::min(lhs.edges.size(), rhs.edges.size());
  for (std::size_t i = 0; i < shared_hops; ++i) {
    const LinkId& left = snapshot.Edges()[lhs.edges[i]].id;
    const LinkId& right = snapshot.Edges()[rhs.edges[i]].id;
    if (left != right) {
      return left < right;
    }
  }
  return false;
}

Oracle BuildOracle(const FabricSnapshot& snapshot, const PlanningRequest& request) {
  Oracle oracle;
  oracle.snapshot = &snapshot;
  oracle.request = &request;

  const std::vector<NodeRecord>& nodes = snapshot.Nodes();
  const std::vector<EdgeRecord>& edges = snapshot.Edges();

  const EndpointRecord* source_endpoint = snapshot.FindEndpoint(request.source.id);
  const EndpointRecord* destination_endpoint = snapshot.FindEndpoint(request.destination.id);
  if (source_endpoint == nullptr || destination_endpoint == nullptr) {
    return oracle;
  }
  const NodeRecord* source_node = snapshot.FindNode(source_endpoint->node);
  const NodeRecord* destination_node = snapshot.FindNode(destination_endpoint->node);
  if (source_node == nullptr || destination_node == nullptr) {
    return oracle;
  }
  oracle.source = static_cast<std::uint32_t>(source_node - nodes.data());
  oracle.destination = static_cast<std::uint32_t>(destination_node - nodes.data());
  // An absent max_hops is documented as "no hop bound"; a simple path over N nodes never
  // exceeds N - 1 hops, so the node count is an exact independent bound.
  oracle.hop_budget = request.constraints.max_hops.has_value()
                          ? request.constraints.max_hops->Value()
                          : static_cast<std::uint32_t>(nodes.size());

  std::vector<NodeId> forbidden_nodes = request.constraints.forbidden_nodes;
  std::vector<LinkId> forbidden_links = request.constraints.forbidden_links;
  std::vector<PortId> forbidden_ports = request.constraints.forbidden_ports;
  std::vector<FailureDomainId> forbidden_domains = request.constraints.forbidden_failure_domains;
  std::vector<FailureDomainClass> forbidden_classes = request.constraints.forbidden_failure_domain_classes;
  std::vector<NodeId> locality = request.policy.locality_scope;
  std::sort(forbidden_nodes.begin(), forbidden_nodes.end());
  std::sort(forbidden_links.begin(), forbidden_links.end());
  std::sort(forbidden_ports.begin(), forbidden_ports.end());
  std::sort(forbidden_domains.begin(), forbidden_domains.end());
  std::sort(forbidden_classes.begin(), forbidden_classes.end());
  std::sort(locality.begin(), locality.end());

  const OracleDomainIndex domain_index = BuildDomainIndex(snapshot);
  const bool diagnostic = request.mode == PlanningMode::kDiagnosticNonCurrent;
  const bool require_proof = request.policy.require_operational_proof && !diagnostic;

  oracle.node_eligible.assign(nodes.size(), true);
  for (std::size_t i = 0; i < nodes.size(); ++i) {
    const NodeRecord& node = nodes[i];
    bool eligible = !std::binary_search(forbidden_nodes.begin(), forbidden_nodes.end(), node.id);
    for (const CapabilityRequirement& requirement : request.constraints.required_capabilities) {
      if (!eligible || requirement.scope != CapabilityScope::kEveryNode) {
        continue;
      }
      if (!CapabilitySatisfiedByOracle(snapshot, SubjectKey::ForNode(node.id), requirement)) {
        eligible = false;
      }
    }
    if (eligible && !DomainCompliantByOracle(domain_index, forbidden_domains, forbidden_classes,
                                             SubjectKey::ForNode(node.id),
                                             request.constraints.fail_closed_on_unknown_domains)) {
      eligible = false;
    }
    oracle.node_eligible[i] = eligible;
  }

  oracle.edges.assign(edges.size(), OracleEdgeInfo{});
  oracle.out_edges.assign(nodes.size(), std::vector<std::uint32_t>{});
  const NodeRecord* node_data = nodes.data();
  for (std::size_t edge_index = 0; edge_index < edges.size(); ++edge_index) {
    const EdgeRecord& edge = edges[edge_index];
    OracleEdgeInfo info;
    const NodeRecord* from_node = snapshot.FindNode(edge.from);
    const NodeRecord* to_node = snapshot.FindNode(edge.to);
    if (from_node == nullptr || to_node == nullptr) {
      oracle.edges[edge_index] = info;
      continue;
    }
    info.from = static_cast<std::uint32_t>(from_node - node_data);
    info.to = static_cast<std::uint32_t>(to_node - node_data);

    bool eligible = edge.layer == request.constraints.layer;
    if (eligible && std::binary_search(forbidden_links.begin(), forbidden_links.end(), edge.id)) {
      eligible = false;
    }
    if (eligible && (std::binary_search(forbidden_ports.begin(), forbidden_ports.end(), edge.from_port) ||
                     std::binary_search(forbidden_ports.begin(), forbidden_ports.end(), edge.to_port))) {
      eligible = false;
    }
    if (eligible && (!oracle.node_eligible[info.from] || !oracle.node_eligible[info.to])) {
      eligible = false;
    }

    bool degraded = false;
    if (eligible) {
      switch (snapshot.LinkStates().StateOf(edge.id)) {
        case LinkState::kUp:
          break;
        case LinkState::kDegraded:
          if (request.policy.allow_degraded_links) {
            degraded = true;
          } else {
            eligible = false;
          }
          break;
        case LinkState::kRevalidationRequired:
          eligible = diagnostic;
          break;
        case LinkState::kUnknown:
          eligible = !require_proof;
          break;
        default:
          eligible = false;
          break;
      }
    }
    if (eligible) {
      for (const PortId& port : {edge.from_port, edge.to_port}) {
        switch (snapshot.PortStates().StateOf(port)) {
          case PortState::kUp:
            break;
          case PortState::kDraining:
            eligible = request.policy.allow_draining_ports || diagnostic;
            break;
          case PortState::kMaintenance:
            eligible = request.policy.allow_maintenance_ports || diagnostic;
            break;
          case PortState::kRevalidationRequired:
            eligible = diagnostic;
            break;
          case PortState::kUnknown:
            eligible = !require_proof;
            break;
          default:
            eligible = false;
            break;
        }
        if (!eligible) {
          break;
        }
      }
    }
    if (eligible) {
      for (const CapabilityRequirement& requirement : request.constraints.required_capabilities) {
        if (requirement.scope == CapabilityScope::kEveryLink) {
          eligible = CapabilitySatisfiedByOracle(snapshot, SubjectKey::ForLink(edge.id), requirement);
        } else if (requirement.scope == CapabilityScope::kEveryPort) {
          eligible = CapabilitySatisfiedByOracle(snapshot, SubjectKey::ForPort(edge.from_port), requirement) &&
                     CapabilitySatisfiedByOracle(snapshot, SubjectKey::ForPort(edge.to_port), requirement);
        }
        if (!eligible) {
          break;
        }
      }
    }
    if (eligible) {
      const SubjectKey subjects[3] = {SubjectKey::ForLink(edge.id), SubjectKey::ForPort(edge.from_port),
                                      SubjectKey::ForPort(edge.to_port)};
      for (const SubjectKey& subject : subjects) {
        if (!DomainCompliantByOracle(domain_index, forbidden_domains, forbidden_classes, subject,
                                     request.constraints.fail_closed_on_unknown_domains)) {
          eligible = false;
          break;
        }
      }
    }
    bool outside_locality = false;
    if (eligible) {
      std::uint64_t traversal = edge.static_cost.Value();
      if (degraded) {
        if (!AddFits(traversal, request.policy.cost_model.degraded_penalty.Value())) {
          eligible = false;
        } else {
          traversal += request.policy.cost_model.degraded_penalty.Value();
        }
      }
      if (eligible && !locality.empty()) {
        outside_locality = !std::binary_search(locality.begin(), locality.end(), edge.to);
        if (outside_locality) {
          if (!AddFits(traversal, request.policy.cost_model.locality_penalty.Value())) {
            eligible = false;
          } else {
            traversal += request.policy.cost_model.locality_penalty.Value();
          }
        }
      }
      if (eligible) {
        info.traversal = traversal;
        info.hop_fits = AddFits(request.policy.cost_model.hop_cost.Value(), traversal);
      }
    }
    info.eligible = eligible;
    info.degraded = degraded;
    info.outside_locality = outside_locality;
    oracle.edges[edge_index] = info;
  }

  for (std::size_t edge_index = 0; edge_index < edges.size(); ++edge_index) {
    if (oracle.edges[edge_index].eligible) {
      oracle.out_edges[oracle.edges[edge_index].from].push_back(static_cast<std::uint32_t>(edge_index));
    }
  }
  for (std::vector<std::uint32_t>& list : oracle.out_edges) {
    std::sort(list.begin(), list.end(), [&edges](std::uint32_t lhs, std::uint32_t rhs) {
      if (edges[lhs].to != edges[rhs].to) {
        return edges[lhs].to < edges[rhs].to;
      }
      return edges[lhs].id < edges[rhs].id;
    });
  }

  std::vector<std::uint32_t> edge_path;
  std::vector<std::uint32_t> node_path;
  std::vector<bool> visited(nodes.size(), false);
  node_path.push_back(oracle.source);
  visited[oracle.source] = true;
  OracleDfs(oracle, oracle.source, edge_path, node_path, visited, oracle.paths);
  std::sort(oracle.paths.begin(), oracle.paths.end(),
            [&snapshot](const OraclePath& lhs, const OraclePath& rhs) { return CanonicalLess(snapshot, lhs, rhs); });
  oracle.usable = true;
  return oracle;
}

// The enumeration ceiling production uses: a path-level failure-domain member
// limit forces a wider enumeration before the canonical order is filtered.
std::vector<OraclePath> OracleExpectedPaths(const Oracle& oracle, const PlanningRequest& request,
                                            std::uint32_t wanted) {
  if (!request.constraints.max_members_per_failure_domain.has_value()) {
    std::vector<OraclePath> selected;
    for (const OraclePath& path : oracle.paths) {
      if (selected.size() >= static_cast<std::size_t>(wanted)) {
        break;
      }
      selected.push_back(path);
    }
    return selected;
  }
  const std::uint32_t ceiling = std::max(wanted, ResourceLimits{}.max_enumeration_candidates);
  std::vector<OraclePath> enumerated;
  for (const OraclePath& path : oracle.paths) {
    if (enumerated.size() >= static_cast<std::size_t>(ceiling)) {
      break;
    }
    enumerated.push_back(path);
  }
  const bool fail_closed = request.constraints.fail_closed_on_unknown_domains;
  const std::uint32_t limit = *request.constraints.max_members_per_failure_domain;
  const OracleDomainIndex index = BuildDomainIndex(*oracle.snapshot);
  std::vector<OraclePath> compliant;
  for (const OraclePath& path : enumerated) {
    std::map<FailureDomainId, std::uint32_t> counts;
    bool ok = true;
    for (const std::uint32_t edge_index : path.edges) {
      bool known = false;
      const std::vector<FailureDomainId> domains =
          index.Membership(SubjectKey::ForLink(oracle.snapshot->Edges()[edge_index].id), known);
      if (!known) {
        if (fail_closed) {
          ok = false;
          break;
        }
        continue;
      }
      for (const FailureDomainId& domain : domains) {
        counts[domain] += 1;
        if (counts[domain] > limit) {
          ok = false;
          break;
        }
      }
      if (!ok) {
        break;
      }
    }
    if (ok) {
      compliant.push_back(path);
    }
    if (compliant.size() >= static_cast<std::size_t>(wanted)) {
      break;
    }
  }
  return compliant;
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------
std::string StatusText(const PlanningResult& result) {
  std::string text = std::string(ToString(result.status));
  text += "/";
  text += result.primary_failure.has_value() ? std::string(ToString(*result.primary_failure)) : std::string("-");
  return text;
}

std::uint64_t RejectionOccurrences(const PlanningResult& result, DiagnosticCode code) {
  std::uint64_t total = 0;
  for (const RejectionExplanation& entry : result.rejections) {
    if (entry.code == code) {
      total += entry.occurrences;
    }
  }
  return total;
}

bool HasNote(const Candidate& candidate, DiagnosticCode code) {
  return std::find(candidate.notes.begin(), candidate.notes.end(), code) != candidate.notes.end();
}

bool HasDistinctKeys(const std::vector<OraclePath>& paths) {
  for (std::size_t i = 0; i < paths.size(); ++i) {
    for (std::size_t j = i + 1; j < paths.size(); ++j) {
      if (paths[i].cost.total == paths[j].cost.total && paths[i].cost.hops == paths[j].cost.hops) {
        return false;
      }
    }
  }
  return true;
}

bool IsFailureStatus(PlanStatus status) {
  switch (status) {
    case PlanStatus::kPlanned:
    case PlanStatus::kTruncatedByLimit:
    case PlanStatus::kRevalidationRequired:
      return false;
    default:
      return true;
  }
}

std::string NodeSeqText(const FabricSnapshot& snapshot, const std::vector<std::uint32_t>& nodes) {
  std::string text;
  for (const std::uint32_t node : nodes) {
    if (!text.empty()) {
      text += ">";
    }
    text += Id8(snapshot.Nodes()[node].id);
  }
  return text;
}

std::string LinkSeqText(const FabricSnapshot& snapshot, const std::vector<std::uint32_t>& edges) {
  std::string text;
  for (const std::uint32_t edge : edges) {
    if (!text.empty()) {
      text += ">";
    }
    text += Id8(snapshot.Edges()[edge].id);
  }
  return text;
}

std::string NodeSeqOfIds(const std::vector<NodeId>& nodes) {
  std::string text;
  for (const NodeId& node : nodes) {
    if (!text.empty()) {
      text += ">";
    }
    text += Id8(node);
  }
  return text;
}

std::string PathNodeSeq(const CandidatePath& path) {
  std::string text;
  for (const NodeId& node : path.nodes) {
    if (!text.empty()) {
      text += ">";
    }
    text += Id8(node);
  }
  return text;
}

std::string PathLinkSeq(const CandidatePath& path) {
  std::string text;
  for (const PathHop& hop : path.hops) {
    if (!text.empty()) {
      text += ">";
    }
    text += Id8(hop.link);
  }
  return text;
}

// Documented path identity of the oracle path: the same hop sequence rebuilt from
// topology records must yield the same CandidatePathId.
CandidatePathId OracleIdForPath(const FabricSnapshot& snapshot, const OraclePath& path, PathLayer layer) {
  CandidatePath typed;
  typed.layer = layer;
  typed.source = snapshot.Nodes()[path.nodes.front()].id;
  typed.destination = snapshot.Nodes()[path.nodes.back()].id;
  for (const std::uint32_t node : path.nodes) {
    typed.nodes.push_back(snapshot.Nodes()[node].id);
  }
  for (const std::uint32_t edge_index : path.edges) {
    const EdgeRecord& edge = snapshot.Edges()[edge_index];
    PathHop hop;
    hop.link = edge.id;
    hop.from = edge.from;
    hop.to = edge.to;
    hop.from_port = edge.from_port;
    hop.to_port = edge.to_port;
    hop.layer = edge.layer;
    hop.relationship = edge.relationship;
    hop.structural_generation = edge.structural_generation;
    hop.static_cost = edge.static_cost;
    hop.link_state = snapshot.LinkStates().StateOf(edge.id);
    typed.hops.push_back(hop);
  }
  return typed.Id();
}

// Compares a planning result with the oracle's expected path list. When the
// expected paths do not all share (total, hops) the order between equal keys is
// production's documented candidate-identity tie break, so identities are then
// compared as sets; otherwise the order is fully pinned and compared element by
// element.
void CheckCandidatesAgainstOracle(const BuiltFabric& fabric, const PlanningRequest& request,
                                  const PlanningResult& result, const std::vector<OraclePath>& expected,
                                  const std::string& context) {
  const FabricSnapshot& snapshot = *fabric.snapshot;
  const std::string prefix = context + ": ";
  PP_CHECK_MSG(result.candidates.size() == expected.size(),
               prefix + "candidate count " + std::to_string(result.candidates.size()) + " but oracle has " +
                   std::to_string(expected.size()) + " (status " + StatusText(result) + ")");
  if (result.candidates.size() != expected.size()) {
    return;
  }
  const bool tied = !HasDistinctKeys(expected);
  for (std::size_t index = 0; index < expected.size(); ++index) {
    const Candidate& candidate = result.candidates[index];
    const OraclePath& path = expected[index];
    const std::string where = prefix + "candidate " + std::to_string(index) + " ";
    PP_CHECK_MSG(candidate.cost.total.Value() == path.cost.total,
                 where + "total " + std::to_string(candidate.cost.total.Value()) + " but oracle has " +
                     std::to_string(path.cost.total));
    PP_CHECK_MSG(candidate.cost.hops.Value() == path.cost.hops,
                 where + "hop count " + std::to_string(candidate.cost.hops.Value()) + " but oracle has " +
                     std::to_string(path.cost.hops));
    PP_CHECK_MSG(candidate.cost.hops_cost.Value() == path.cost.hops_cost, where + "hops_cost differs from the oracle");
    PP_CHECK_MSG(candidate.cost.static_cost.Value() == path.cost.static_cost,
                 where + "static_cost " + std::to_string(candidate.cost.static_cost.Value()) + " but oracle has " +
                     std::to_string(path.cost.static_cost));
    PP_CHECK_MSG(candidate.cost.degraded_penalty.Value() == path.cost.degraded_penalty,
                 where + "degraded_penalty differs from the oracle");
    PP_CHECK_MSG(candidate.cost.locality_penalty.Value() == path.cost.locality_penalty,
                 where + "locality_penalty differs from the oracle");
    PP_CHECK_MSG(candidate.cost.degraded_hops == path.cost.degraded_hops, where + "degraded_hops differs from the oracle");
    PP_CHECK_MSG(candidate.cost.locality_breaches == path.cost.locality_breaches,
                 where + "locality_breaches differs from the oracle");
    PP_CHECK_MSG(candidate.id == candidate.path.Id(), where + "identity is not the path identity");
    if (!tied) {
      PP_CHECK_MSG(PathNodeSeq(candidate.path) == NodeSeqText(snapshot, path.nodes),
                   where + "node sequence " + PathNodeSeq(candidate.path) + " but oracle has " +
                       NodeSeqText(snapshot, path.nodes));
      PP_CHECK_MSG(PathLinkSeq(candidate.path) == LinkSeqText(snapshot, path.edges),
                   where + "link sequence " + PathLinkSeq(candidate.path) + " but oracle has " +
                       LinkSeqText(snapshot, path.edges));
      PP_CHECK_MSG(candidate.id == OracleIdForPath(snapshot, path, request.constraints.layer),
                   where + "identity " + Id8(candidate.id) + " but the oracle path identity is " +
                       Id8(OracleIdForPath(snapshot, path, request.constraints.layer)));
    }
  }
  if (tied) {
    std::vector<std::string> got_ids;
    std::vector<std::string> want_ids;
    std::vector<std::string> got_nodes;
    std::vector<std::string> want_nodes;
    for (const Candidate& candidate : result.candidates) {
      got_ids.push_back(Id8(candidate.id));
      got_nodes.push_back(PathNodeSeq(candidate.path));
    }
    for (const OraclePath& path : expected) {
      want_ids.push_back(Id8(OracleIdForPath(snapshot, path, request.constraints.layer)));
      want_nodes.push_back(NodeSeqText(snapshot, path.nodes));
    }
    std::sort(got_ids.begin(), got_ids.end());
    std::sort(want_ids.begin(), want_ids.end());
    std::sort(got_nodes.begin(), got_nodes.end());
    std::sort(want_nodes.begin(), want_nodes.end());
    PP_CHECK_MSG(got_ids == want_ids, prefix + "candidate identity set differs from the oracle set");
    PP_CHECK_MSG(got_nodes == want_nodes, prefix + "candidate node-sequence set differs from the oracle set");
  }
  for (std::size_t index = 1; index < result.candidates.size(); ++index) {
    PP_CHECK_MSG(!RanksBefore(result.candidates[index], result.candidates[index - 1]),
                 prefix + "candidates are not in canonical (cost, hops, identity) order");
  }
}

// Independent verification of every documented property of a returned candidate.
void CheckCandidateInvariants(const BuiltFabric& fabric, const PlanningRequest& request, const Oracle& oracle,
                              const PlanningResult& result, const std::string& context) {
  const FabricSnapshot& snapshot = *fabric.snapshot;
  const std::string prefix = context + ": ";
  const CostModel& model = request.policy.cost_model;
  const std::size_t hop_limit = request.constraints.max_hops.has_value()
                                    ? static_cast<std::size_t>(request.constraints.max_hops->Value())
                                    : snapshot.NodeCount();

  std::vector<NodeId> forbidden_nodes = request.constraints.forbidden_nodes;
  std::vector<LinkId> forbidden_links = request.constraints.forbidden_links;
  std::vector<PortId> forbidden_ports = request.constraints.forbidden_ports;
  std::sort(forbidden_nodes.begin(), forbidden_nodes.end());
  std::sort(forbidden_links.begin(), forbidden_links.end());
  std::sort(forbidden_ports.begin(), forbidden_ports.end());

  PP_CHECK_MSG(result.candidates.empty() == IsFailureStatus(result.status),
               prefix + "status " + StatusText(result) + " disagrees with candidate count " +
                   std::to_string(result.candidates.size()));
  PP_CHECK_MSG(result.candidates.empty() || CarriesCandidates(result.status),
               prefix + "status " + StatusText(result) + " carries no candidates");

  std::vector<std::uint32_t> ranks;
  std::vector<std::string> identities;
  for (std::size_t index = 0; index < result.candidates.size(); ++index) {
    const Candidate& candidate = result.candidates[index];
    const std::string where = prefix + "candidate " + std::to_string(index) + " ";
    ranks.push_back(candidate.rank.Value());
    identities.push_back(Id8(candidate.id));
    PP_CHECK_MSG(candidate.rank.Value() == static_cast<std::uint32_t>(index) + 1u,
                 where + "rank " + std::to_string(candidate.rank.Value()));
    PP_CHECK_MSG(candidate.path.IsWellFormed(), where + "path is not well formed");
    PP_CHECK_MSG(candidate.path.IsSimple(), where + "path is not simple");
    PP_CHECK_MSG(candidate.path.hops.size() + 1 == candidate.path.nodes.size(), where + "node/hop count mismatch");
    PP_CHECK_MSG(candidate.path.source == result.source_node, where + "path source is not the resolved source node");
    PP_CHECK_MSG(candidate.path.destination == result.destination_node,
                 where + "path destination is not the resolved destination node");
    PP_CHECK_MSG(candidate.path.layer == request.constraints.layer, where + "path layer differs from the request layer");
    PP_CHECK_MSG(candidate.path.hops.size() <= hop_limit,
                 where + "hop count " + std::to_string(candidate.path.hops.size()) + " exceeds the hop bound " +
                     std::to_string(hop_limit));
    PP_CHECK_MSG(static_cast<std::size_t>(candidate.cost.hops.Value()) == candidate.path.hops.size(),
                 where + "cost.hops disagrees with the hop sequence");
    PP_CHECK_MSG(candidate.id == candidate.path.Id(), where + "identity is not the path identity");

    std::uint64_t static_sum = 0;
    std::uint32_t degraded_hops = 0;
    std::uint32_t locality_breaches = 0;
    bool static_fits = true;
    for (std::size_t hop_index = 0; hop_index < candidate.path.hops.size(); ++hop_index) {
      const PathHop& hop = candidate.path.hops[hop_index];
      const std::string at = where + "hop " + std::to_string(hop_index) + " ";
      const EdgeRecord* edge = snapshot.FindEdge(hop.link);
      PP_CHECK_MSG(edge != nullptr, at + "link " + Id8(hop.link) + " is not present in the topology");
      if (edge == nullptr) {
        static_fits = false;
        continue;
      }
      const std::size_t edge_index = static_cast<std::size_t>(edge - snapshot.Edges().data());
      const OracleEdgeInfo& info = oracle.edges[edge_index];
      PP_CHECK_MSG(info.eligible, at + "uses link " + Id8(hop.link) + " which the documented constraints exclude");
      PP_CHECK_MSG(edge->from == hop.from && edge->to == hop.to, at + "hop endpoints disagree with the topology");
      PP_CHECK_MSG(edge->from_port == hop.from_port && edge->to_port == hop.to_port,
                   at + "hop ports disagree with the topology");
      PP_CHECK_MSG(edge->static_cost == hop.static_cost, at + "hop static cost disagrees with the topology");
      PP_CHECK_MSG(edge->layer == request.constraints.layer && hop.layer == request.constraints.layer,
                   at + "hop layer does not match the request layer");
      PP_CHECK_MSG(edge->structural_generation == hop.structural_generation,
                   at + "hop structural generation disagrees with the topology");
      PP_CHECK_MSG(candidate.path.nodes[hop_index] == hop.from && candidate.path.nodes[hop_index + 1] == hop.to,
                   at + "hop is not continuous with the node sequence");
      PP_CHECK_MSG(!std::binary_search(forbidden_links.begin(), forbidden_links.end(), hop.link),
                   at + "uses a forbidden link");
      PP_CHECK_MSG(!std::binary_search(forbidden_nodes.begin(), forbidden_nodes.end(), hop.from) &&
                       !std::binary_search(forbidden_nodes.begin(), forbidden_nodes.end(), hop.to),
                   at + "uses a forbidden node");
      PP_CHECK_MSG(!std::binary_search(forbidden_ports.begin(), forbidden_ports.end(), hop.from_port) &&
                       !std::binary_search(forbidden_ports.begin(), forbidden_ports.end(), hop.to_port),
                   at + "uses a forbidden port");
      if (!AddFits(static_sum, edge->static_cost.Value())) {
        static_fits = false;
      } else {
        static_sum += edge->static_cost.Value();
      }
      if (info.degraded) {
        degraded_hops += 1;
      }
      if (info.outside_locality) {
        locality_breaches += 1;
      }
    }
    PP_CHECK_MSG(static_fits, where + "static cost accumulation overflows");
    PP_CHECK_MSG(candidate.cost.static_cost.Value() == static_sum,
                 where + "static cost " + std::to_string(candidate.cost.static_cost.Value()) + " but the hop sum is " +
                     std::to_string(static_sum));
    PP_CHECK_MSG(candidate.cost.degraded_hops == degraded_hops,
                 where + "degraded hop count " + std::to_string(candidate.cost.degraded_hops) + " but the hops are " +
                     std::to_string(degraded_hops));
    PP_CHECK_MSG(candidate.cost.locality_breaches == locality_breaches,
                 where + "locality breach count " + std::to_string(candidate.cost.locality_breaches) +
                     " but the hops are " + std::to_string(locality_breaches));
    const std::uint64_t hop_count = static_cast<std::uint64_t>(candidate.path.hops.size());
    PP_CHECK_MSG(MulFits(model.hop_cost.Value(), hop_count) &&
                     candidate.cost.hops_cost.Value() == model.hop_cost.Value() * hop_count,
                 where + "hops_cost is not hop_count * hop_cost");
    PP_CHECK_MSG(MulFits(model.degraded_penalty.Value(), degraded_hops) &&
                     candidate.cost.degraded_penalty.Value() ==
                         model.degraded_penalty.Value() * static_cast<std::uint64_t>(degraded_hops),
                 where + "degraded_penalty is not degraded_hops * degraded_penalty");
    PP_CHECK_MSG(MulFits(model.locality_penalty.Value(), locality_breaches) &&
                     candidate.cost.locality_penalty.Value() ==
                         model.locality_penalty.Value() * static_cast<std::uint64_t>(locality_breaches),
                 where + "locality_penalty is not locality_breaches * locality_penalty");
    bool total_fits = AddFits(candidate.cost.hops_cost.Value(), candidate.cost.static_cost.Value());
    const std::uint64_t partial = total_fits ? candidate.cost.hops_cost.Value() + candidate.cost.static_cost.Value() : 0;
    total_fits = total_fits && AddFits(partial, candidate.cost.degraded_penalty.Value());
    const std::uint64_t partial2 = total_fits ? partial + candidate.cost.degraded_penalty.Value() : 0;
    total_fits = total_fits && AddFits(partial2, candidate.cost.locality_penalty.Value());
    const std::uint64_t recomputed_total = total_fits ? partial2 + candidate.cost.locality_penalty.Value() : 0;
    PP_CHECK_MSG(total_fits && recomputed_total == candidate.cost.total.Value(),
                 where + "total " + std::to_string(candidate.cost.total.Value()) +
                     " is not the checked sum of the documented components (" + std::to_string(recomputed_total) + ")");
  }

  std::vector<std::uint32_t> sorted_ranks = ranks;
  std::sort(sorted_ranks.begin(), sorted_ranks.end());
  PP_CHECK_MSG(std::adjacent_find(sorted_ranks.begin(), sorted_ranks.end()) == sorted_ranks.end(),
               prefix + "candidate ranks are not unique");
  std::vector<std::string> sorted_identities = identities;
  std::sort(sorted_identities.begin(), sorted_identities.end());
  PP_CHECK_MSG(std::adjacent_find(sorted_identities.begin(), sorted_identities.end()) == sorted_identities.end(),
               prefix + "candidate identities are not unique");
}

std::vector<NodeId> LabelOrder(const BuiltFabric& fabric, const std::string& prefix, int count) {
  std::vector<NodeId> nodes;
  for (int i = 0; i < count; ++i) {
    nodes.push_back(fabric.node_by_label.at(prefix + std::to_string(i)));
  }
  return nodes;
}

bool ContainsInOrder(const std::vector<NodeId>& nodes, const std::vector<NodeId>& waypoints) {
  std::size_t cursor = 0;
  for (const NodeId& node : nodes) {
    if (cursor < waypoints.size() && node == waypoints[cursor]) {
      cursor += 1;
    }
  }
  return cursor == waypoints.size();
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

// 1. Shortest-path exactness on tiny graphs across fixed seeds: PLANNED, exactly
//    one candidate, and its identity/cost/hop sequence equal to the oracle
//    minimum -- including graphs where several paths tie on (cost, hops).
PP_TEST(oracle, shortest_path_exactness_tiny_graphs) {
  const std::uint64_t seeds[8] = {1, 2, 3, 5, 8, 13, 21, 34};
  std::uint32_t comparisons = 0;
  std::uint32_t tie_observations = 0;
  for (std::size_t seed_index = 0; seed_index < 8; ++seed_index) {
    const std::uint64_t seed = seeds[seed_index];
    const std::string suffix = std::to_string(seed);
    std::vector<std::pair<std::string, BuiltFabric>> cases;
    cases.push_back(std::make_pair("chain/" + suffix, BuildChain("ex-chain-" + suffix, 5, true, seed)));
    cases.push_back(
        std::make_pair("diamond/" + suffix, BuildDiamond("ex-diamond-" + suffix, seed % 2 == 0, seed)));
    cases.push_back(std::make_pair("mesh/" + suffix, BuildMesh("ex-mesh-" + suffix, 2, 3, seed)));
    for (const auto& item : cases) {
      PP_REQUIRE(item.second.ok);
      const std::string context = item.first;
      PlanningRequest request = MakeRequest("exact-" + context, item.second);
      request.max_candidates = 1;
      const PlanningResult result = RunPlan(item.second.snapshot, request);
      const Oracle oracle = BuildOracle(*item.second.snapshot, request);
      PP_REQUIRE(oracle.usable);
      PP_REQUIRE(!oracle.paths.empty());
      PP_CHECK_MSG(result.status == PlanStatus::kPlanned, context + " status " + StatusText(result));
      PP_CHECK_MSG(result.candidates.size() == 1u,
                   context + " candidate count " + std::to_string(result.candidates.size()));
      const OraclePath& best = oracle.paths.front();
      for (const OraclePath& path : oracle.paths) {
        PP_CHECK_MSG(!CanonicalLess(*item.second.snapshot, path, best),
                     context + " the oracle minimum is not the canonical minimum");
      }
      std::vector<OraclePath> expected;
      expected.push_back(best);
      CheckCandidatesAgainstOracle(item.second, request, result, expected, context);
      CheckCandidateInvariants(item.second, request, oracle, result, context);
      comparisons += 1;
      std::size_t ties = 0;
      for (const OraclePath& path : oracle.paths) {
        if (path.cost.total == best.cost.total && path.cost.hops == best.cost.hops) {
          ties += 1;
        }
      }
      if (ties > 1) {
        tie_observations += 1;
      }
    }
  }
  PP_CHECK_MSG(comparisons == 24u, "comparisons " + std::to_string(comparisons));
  PP_CHECK_MSG(tie_observations >= 3u, "tie observations " + std::to_string(tie_observations));
}

// 2. Tie breaking on an equal-cost diamond, plus the insertion-order rebuild.
PP_TEST(oracle, tie_break_diamond_order_and_rebuild) {
  const BuiltFabric fabric = BuildDiamond("tie-diamond", true, 1);
  PP_REQUIRE(fabric.ok);
  const NodeId s = fabric.node_by_label.at("s");
  const NodeId a = fabric.node_by_label.at("a");
  const NodeId b = fabric.node_by_label.at("b");
  const NodeId d = fabric.node_by_label.at("d");
  PP_REQUIRE(a != b);
  const std::vector<NodeId> via_a{s, a, d};
  const std::vector<NodeId> via_b{s, b, d};
  const std::vector<NodeId> expected = a < b ? via_a : via_b;
  const std::vector<NodeId> other = a < b ? via_b : via_a;

  PlanningRequest request = MakeRequest("tie-diamond", fabric);
  request.max_candidates = 1;
  const PlanningResult one = RunPlan(fabric.snapshot, request);
  PP_CHECK_MSG(one.status == PlanStatus::kPlanned, "k=1 status " + StatusText(one));
  PP_REQUIRE(one.candidates.size() == 1u);
  PP_CHECK_MSG(one.candidates[0].path.nodes == expected,
               "k=1 chose " + PathNodeSeq(one.candidates[0].path) +
                   " rather than the lexicographically smallest node sequence " + NodeSeqOfIds(expected));
  const Oracle oracle = BuildOracle(*fabric.snapshot, request);
  PP_REQUIRE(oracle.usable);
  PP_REQUIRE(oracle.paths.size() == 2u);
  PP_CHECK_MSG(NodeSeqText(*fabric.snapshot, oracle.paths[0].nodes) == PathNodeSeq(one.candidates[0].path),
               "the oracle tie break disagrees with production");
  std::vector<OraclePath> expected_one;
  expected_one.push_back(oracle.paths.front());
  CheckCandidatesAgainstOracle(fabric, request, one, expected_one, "tie-diamond k=1");
  CheckCandidateInvariants(fabric, request, oracle, one, "tie-diamond k=1");

  request.max_candidates = 2;
  const PlanningResult two = RunPlan(fabric.snapshot, request);
  PP_REQUIRE(two.candidates.size() == 2u);
  // Equal (cost, hops) candidates are ordered by the documented canonical path order: the
  // lexicographic node-id sequence, then the link-id sequence.
  PP_CHECK_MSG(CompareCanonicalPaths(two.candidates[0].path, two.candidates[1].path) == std::strong_ordering::less,
               "equal-cost candidates are not ordered by the canonical path order");
  PP_CHECK_MSG(two.candidates[1].rank.Value() == 2u, "second rank is not 2");
  PP_CHECK_MSG(two.candidates[0].cost.total == two.candidates[1].cost.total,
               "the diamond routes do not tie on total cost");
  PP_CHECK_MSG(two.candidates[0].cost.hops == two.candidates[1].cost.hops,
               "the diamond routes do not tie on hop count");
  std::vector<std::vector<NodeId>> got_nodes;
  for (const Candidate& candidate : two.candidates) {
    got_nodes.push_back(candidate.path.nodes);
  }
  std::sort(got_nodes.begin(), got_nodes.end());
  std::vector<std::vector<NodeId>> want_nodes{via_a, via_b};
  std::sort(want_nodes.begin(), want_nodes.end());
  PP_CHECK_MSG(got_nodes == want_nodes, "k=2 did not return exactly the two diamond routes");
  PP_CHECK_MSG(ContainsInOrder(two.candidates[0].path.nodes, other) ||
                   ContainsInOrder(two.candidates[1].path.nodes, other),
               "the k=2 result does not contain the non-preferred route");
  CheckCandidatesAgainstOracle(fabric, request, two, OracleExpectedPaths(oracle, request, 2), "tie-diamond k=2");

  GraphBuilder reverse("tie-diamond");
  const NodeId rs = reverse.Node("s");
  const NodeId rb = reverse.Node("b");
  const NodeId ra = reverse.Node("a");
  const NodeId rd = reverse.Node("d");
  reverse.Link("b-d", rb, rd, 2);
  reverse.Link("s-b", rs, rb, 2);
  reverse.Link("a-d", ra, rd, 2);
  reverse.Link("s-a", rs, ra, 2);
  reverse.SetReverseInsertion(true);
  reverse.Endpoint("src", rs);
  reverse.Endpoint("dst", rd);
  const BuiltFabric rebuilt = reverse.Build();
  PP_REQUIRE(rebuilt.ok);
  PP_CHECK_MSG(rebuilt.snapshot->Digest() == fabric.snapshot->Digest(),
               "rebuilding the same graph in reverse insertion order changed the snapshot digest");
  PlanningRequest rebuilt_request = MakeRequest("tie-diamond", rebuilt);
  rebuilt_request.max_candidates = 2;
  const PlanningResult rebuilt_result = RunPlan(rebuilt.snapshot, rebuilt_request);
  PP_REQUIRE(rebuilt_result.candidates.size() == two.candidates.size());
  for (std::size_t index = 0; index < two.candidates.size(); ++index) {
    PP_CHECK_MSG(rebuilt_result.candidates[index].id == two.candidates[index].id,
                 "candidate " + std::to_string(index) + " identity changed with insertion order");
    PP_CHECK_MSG(rebuilt_result.candidates[index].cost.total == two.candidates[index].cost.total,
                 "candidate " + std::to_string(index) + " cost changed with insertion order");
    PP_CHECK_MSG(rebuilt_result.candidates[index].path.nodes == two.candidates[index].path.nodes,
                 "candidate " + std::to_string(index) + " node sequence changed with insertion order");
  }
}

// 3. K-shortest: for K in {1,2,3,4} and every tiny family the returned candidates
//    are exactly the first K oracle paths.
PP_TEST(oracle, k_shortest_matches_oracle_order) {
  struct Family {
    std::string tag;
    BuiltFabric fabric;
  };
  std::vector<Family> families;
  families.push_back(Family{"chain5-directed", BuildChain("k-chain5", 5, false, 3)});
  families.push_back(Family{"chain5-bidirectional", BuildChain("k-chain5bi", 5, true, 3)});
  families.push_back(Family{"ring5", BuildRing("k-ring5", 5, 4)});
  families.push_back(Family{"diamond-equal", BuildDiamond("k-diamond-eq", true, 2)});
  families.push_back(Family{"diamond-unequal", BuildDiamond("k-diamond-ne", false, 3)});
  families.push_back(Family{"leafspine-2x2", BuildLeafSpine("k-leafspine", 2, 2, 5)});
  families.push_back(Family{"fattree", BuildFatTree("k-fattree")});
  families.push_back(Family{"mesh-2x3", BuildMesh("k-mesh", 2, 3, 7)});
  families.push_back(Family{"disconnected", BuildDisconnected("k-disconnected")});
  families.push_back(Family{"oneway5", BuildOneWay("k-oneway", 5)});
  families.push_back(Family{"parallel-equal-cost", BuildParallelEqualCost("k-parallel", 3)});
  families.push_back(Family{"tie-storm", BuildTieStorm("k-tiestorm", 4)});
  families.push_back(Family{"high-degree-hub", BuildHighDegreeHub("k-hub", 5)});
  families.push_back(Family{"deep-chain", BuildDeepChain("k-deep", 7, 11)});

  std::uint32_t sweeps = 0;
  std::uint32_t exact_order_sweeps = 0;
  std::uint32_t tied_sweeps = 0;
  for (const Family& family : families) {
    PP_REQUIRE(family.fabric.ok);
    for (std::uint32_t k = 1; k <= 4; ++k) {
      const std::string context = family.tag + " K=" + std::to_string(k);
      PlanningRequest request = MakeRequest("kshort-" + context, family.fabric);
      request.max_candidates = k;
      const PlanningResult result = RunPlan(family.fabric.snapshot, request);
      const Oracle oracle = BuildOracle(*family.fabric.snapshot, request);
      PP_REQUIRE(oracle.usable);
      const std::vector<OraclePath> expected = OracleExpectedPaths(oracle, request, k);
      PP_CHECK_MSG(expected.size() == std::min<std::size_t>(k, oracle.paths.size()) ||
                       request.constraints.max_members_per_failure_domain.has_value(),
                   context + ": oracle expectation is short of min(K, paths)");
      CheckCandidatesAgainstOracle(family.fabric, request, result, expected, context);
      CheckCandidateInvariants(family.fabric, request, oracle, result, context);
      for (std::size_t index = 1; index < result.candidates.size(); ++index) {
        PP_CHECK_MSG(result.candidates[index - 1].id != result.candidates[index].id,
                     context + ": duplicate candidate identity");
        PP_CHECK_MSG(!(result.candidates[index].cost.total < result.candidates[index - 1].cost.total),
                     context + ": candidate cost decreased with rank");
        PP_CHECK_MSG(result.candidates[index].cost.hops >= result.candidates[index - 1].cost.hops ||
                         result.candidates[index].cost.total > result.candidates[index - 1].cost.total,
                     context + ": candidate hop count decreased without a cost increase");
        PP_CHECK_MSG(result.candidates[index - 1].rank.Value() + 1u == result.candidates[index].rank.Value(),
                     context + ": ranks are not consecutive");
      }
      sweeps += 1;
      if (HasDistinctKeys(expected)) {
        exact_order_sweeps += 1;
      } else {
        tied_sweeps += 1;
      }
    }
  }
  {
    const BuiltFabric disconnected = BuildDisconnected("k-disconnected-status");
    PP_REQUIRE(disconnected.ok);
    PlanningRequest request = MakeRequest("k-disconnected-status", disconnected);
    const PlanningResult result = RunPlan(disconnected.snapshot, request);
    PP_CHECK_MSG(result.status == PlanStatus::kNoPath, "disconnected status " + StatusText(result));
    PP_CHECK_MSG(result.primary_failure == DiagnosticCode::kNoStructuralPath,
                 "disconnected primary " + StatusText(result));  // genuinely no route exists
    PP_CHECK_MSG(result.candidates.empty(), "a disconnected request returned candidates");
  }
  PP_CHECK_MSG(sweeps == 56u, "family sweeps " + std::to_string(sweeps));
  PP_CHECK_MSG(exact_order_sweeps >= 14u, "fully ordered sweeps " + std::to_string(exact_order_sweeps));
  PP_CHECK_MSG(tied_sweeps >= 1u, "tied sweeps " + std::to_string(tied_sweeps));
}

// 4. Cost model: unequal static costs, degraded penalty under policy control,
//    locality penalty per hop leaving the scope, and an exact known total.
PP_TEST(oracle, cost_model_components_and_penalties) {
  {
    const BuiltFabric fabric = BuildDiamond("cost-unequal", false, 2);
    PP_REQUIRE(fabric.ok);
    const NodeId s = fabric.node_by_label.at("s");
    const NodeId a = fabric.node_by_label.at("a");
    const NodeId d = fabric.node_by_label.at("d");
    PlanningRequest request = MakeRequest("cost-unequal", fabric);
    request.policy.cost_model.hop_cost = CostValue(2);
    const PlanningResult result = RunPlan(fabric.snapshot, request);
    const Oracle oracle = BuildOracle(*fabric.snapshot, request);
    PP_REQUIRE(result.candidates.size() == 1u);
    const PathCost& cost = result.candidates[0].cost;
    PP_CHECK_MSG(cost.hops_cost.Value() == 4u, "hops_cost " + std::to_string(cost.hops_cost.Value()));
    PP_CHECK_MSG(cost.static_cost.Value() == 2u, "static_cost " + std::to_string(cost.static_cost.Value()));
    PP_CHECK_MSG(cost.degraded_penalty.Value() == 0u, "degraded_penalty is not zero");
    PP_CHECK_MSG(cost.locality_penalty.Value() == 0u, "locality_penalty is not zero");
    PP_CHECK_MSG(cost.total.Value() == 6u, "total " + std::to_string(cost.total.Value()));
    PP_CHECK_MSG(result.candidates[0].path.nodes == std::vector<NodeId>({s, a, d}),
                 "the cheaper route was not selected");
    CheckCandidatesAgainstOracle(fabric, request, result, OracleExpectedPaths(oracle, request, 1), "cost-unequal");
  }
  {
    GraphBuilder builder("cost-diamond");
    const NodeId s = builder.Node("s");
    const NodeId a = builder.Node("a");
    const NodeId b = builder.Node("b");
    const NodeId d = builder.Node("d");
    builder.Link("s-a", s, a, 3, LinkState::kDegraded);
    builder.Link("a-d", a, d, 5);
    builder.Link("s-b", s, b, 30);
    builder.Link("b-d", b, d, 40);
    const EndpointId es = builder.Endpoint("src", s);
    const EndpointId ed = builder.Endpoint("dst", d);
    const BuiltFabric fabric = builder.Build();
    PP_REQUIRE(fabric.ok);
    PlanningRequest request = MakeRequest("cost-diamond", fabric);
    request.policy.cost_model.hop_cost = CostValue(2);
    request.policy.cost_model.degraded_penalty = CostValue(7);
    request.policy.cost_model.locality_penalty = CostValue(3);
    request.policy.locality_scope.push_back(s);
    request.policy.allow_degraded_links = true;
    const PlanningResult result = RunPlan(fabric.snapshot, request);
    const Oracle oracle = BuildOracle(*fabric.snapshot, request);
    PP_REQUIRE(result.candidates.size() == 1u);
    const CandidatePath& path = result.candidates[0].path;
    const PathCost& cost = result.candidates[0].cost;
    PP_CHECK_MSG(path.nodes == std::vector<NodeId>({s, a, d}), "the degraded route was not selected");
    PP_CHECK_MSG(cost.hops_cost.Value() == 4u, "hops_cost " + std::to_string(cost.hops_cost.Value()));
    PP_CHECK_MSG(cost.static_cost.Value() == 8u, "static_cost " + std::to_string(cost.static_cost.Value()));
    PP_CHECK_MSG(cost.degraded_penalty.Value() == 7u, "degraded_penalty " + std::to_string(cost.degraded_penalty.Value()));
    PP_CHECK_MSG(cost.locality_penalty.Value() == 6u, "locality_penalty " + std::to_string(cost.locality_penalty.Value()));
    PP_CHECK_MSG(cost.total.Value() == 25u, "total " + std::to_string(cost.total.Value()));
    PP_CHECK_MSG(cost.hops.Value() == 2u, "hops " + std::to_string(cost.hops.Value()));
    PP_CHECK_MSG(cost.degraded_hops == 1u, "degraded_hops " + std::to_string(cost.degraded_hops));
    PP_CHECK_MSG(cost.locality_breaches == 2u, "locality_breaches " + std::to_string(cost.locality_breaches));
    CheckCandidatesAgainstOracle(fabric, request, result, OracleExpectedPaths(oracle, request, 1), "cost-diamond");
    request.policy.allow_degraded_links = false;
    const PlanningResult denied = RunPlan(fabric.snapshot, request);
    PP_CHECK_MSG(denied.status == PlanStatus::kPlanned, "degraded denial status " + StatusText(denied));
    PP_REQUIRE(denied.candidates.size() == 1u);
    PP_CHECK_MSG(denied.candidates[0].path.nodes == std::vector<NodeId>({s, b, d}),
                 "the non-degraded alternative route was not used: " + PathNodeSeq(denied.candidates[0].path));
    PP_CHECK_MSG(denied.candidates[0].cost.static_cost.Value() == 70u,
                 "denied static cost " + std::to_string(denied.candidates[0].cost.static_cost.Value()));
    PP_CHECK_MSG(denied.candidates[0].cost.degraded_penalty.Value() == 0u,
                 "a denied degraded hop was still charged");
    PP_CHECK_MSG(denied.candidates[0].cost.locality_penalty.Value() == 6u,
                 "denied locality penalty " + std::to_string(denied.candidates[0].cost.locality_penalty.Value()));
    PP_CHECK_MSG(denied.candidates[0].cost.total.Value() == 80u,
                 "denied total " + std::to_string(denied.candidates[0].cost.total.Value()));
    PP_CHECK_MSG(RejectionOccurrences(denied, DiagnosticCode::kLinkStateDegradedDisallowed) == 1u,
                 "degraded denial evidence " +
                     std::to_string(RejectionOccurrences(denied, DiagnosticCode::kLinkStateDegradedDisallowed)));
  }
  {
    GraphBuilder builder("cost-locality");
    const NodeId s = builder.Node("s");
    const NodeId a = builder.Node("a");
    const NodeId d = builder.Node("d");
    builder.Link("s-a", s, a, 1);
    builder.Link("a-d", a, d, 1);
    const EndpointId es = builder.Endpoint("src", s);
    const EndpointId ed = builder.Endpoint("dst", d);
    const BuiltFabric fabric = builder.Build();
    PP_REQUIRE(fabric.ok);
    PlanningRequest request = MakeRequest("cost-locality", fabric);
    request.policy.cost_model.locality_penalty = CostValue(5);
    request.policy.locality_scope.push_back(s);
    request.policy.locality_scope.push_back(a);
    const PlanningResult result = RunPlan(fabric.snapshot, request);
    PP_REQUIRE(result.candidates.size() == 1u);
    PP_CHECK_MSG(result.candidates[0].cost.locality_breaches == 1u,
                 "locality_breaches " + std::to_string(result.candidates[0].cost.locality_breaches));
    PP_CHECK_MSG(result.candidates[0].cost.locality_penalty.Value() == 5u,
                 "locality_penalty " + std::to_string(result.candidates[0].cost.locality_penalty.Value()));
    PP_CHECK_MSG(result.candidates[0].cost.total.Value() == 9u,
                 "total " + std::to_string(result.candidates[0].cost.total.Value()));
    PlanningRequest unscoped = MakeRequest("cost-locality-unscoped", fabric);
    unscoped.policy.cost_model.locality_penalty = CostValue(5);
    const PlanningResult rejected = RunPlan(fabric.snapshot, unscoped);
    PP_CHECK_MSG(rejected.status == PlanStatus::kUnsupported, "unscoped penalty status " + StatusText(rejected));
    PP_CHECK_MSG(rejected.primary_failure == DiagnosticCode::kUnsupportedRequest,
                 "unscoped penalty primary " + StatusText(rejected));
  }
  {
    const BuiltFabric fabric = BuildChain("cost-chain", 4, false, 6);
    PP_REQUIRE(fabric.ok);
    PlanningRequest request = MakeRequest("cost-chain", fabric);
    request.max_candidates = 1;
    request.policy.cost_model.hop_cost = CostValue(0);
    const PlanningResult result = RunPlan(fabric.snapshot, request);
    const Oracle oracle = BuildOracle(*fabric.snapshot, request);
    PP_REQUIRE(result.candidates.size() == 1u);
    PP_CHECK_MSG(result.candidates[0].cost.total.Value() == result.candidates[0].cost.static_cost.Value(),
                 "a zero hop cost did not make the total equal to the static sum");
    CheckCandidatesAgainstOracle(fabric, request, result, OracleExpectedPaths(oracle, request, 1), "cost-chain");
    CheckCandidateInvariants(fabric, request, oracle, result, "cost-chain");
  }
}

// 5. Hard constraints: exact status, exact primary failure and exact exclusion
//    evidence for every documented exclusion rule.
PP_TEST(oracle, hard_constraints_eligibility_matrix) {
  {
    struct LinkCase {
      LinkState state;
      DiagnosticCode code;
    };
    const LinkCase cases[5] = {
        {LinkState::kDown, DiagnosticCode::kLinkStateDown},
        {LinkState::kFaulted, DiagnosticCode::kLinkStateFaulted},
        {LinkState::kRetired, DiagnosticCode::kLinkStateRetired},
        {LinkState::kRevalidationRequired, DiagnosticCode::kLinkStateRevalidationRequired},
        {LinkState::kUnknown, DiagnosticCode::kLinkStateUnknown},
    };
    for (const LinkCase& item : cases) {
      const std::string tag = std::string(ToString(item.state));
      GraphBuilder builder("link-" + tag);
      const NodeId s = builder.Node("s");
      const NodeId d = builder.Node("d");
      builder.Link("s-d", s, d, 3, item.state, PortState::kUp, PortState::kUp);
      const EndpointId es = builder.Endpoint("src", s);
      const EndpointId ed = builder.Endpoint("dst", d);
      const BuiltFabric fabric = builder.Build();
      PP_REQUIRE(fabric.ok);
      PlanningRequest request = MakeRequest("link-" + tag, fabric);
      const PlanningResult result = RunPlan(fabric.snapshot, request);
      PP_CHECK_MSG(result.status == PlanStatus::kNoPath, "link " + tag + " status " + StatusText(result));
      // The cause is named exactly: the excluded link state, not a generic "no path".
      PP_CHECK_MSG(result.primary_failure == item.code,
                   "link " + tag + " primary " + StatusText(result));
      PP_CHECK_MSG(result.candidates.empty(), "link " + tag + " returned candidates");
      PP_CHECK_MSG(RejectionOccurrences(result, item.code) == 1u,
                   "link " + tag + " rejection " + std::string(ToString(item.code)) + " counted " +
                       std::to_string(RejectionOccurrences(result, item.code)));
    }
  }
  {
    GraphBuilder builder("link-degraded");
    const NodeId s = builder.Node("s");
    const NodeId d = builder.Node("d");
    builder.Link("s-d", s, d, 3, LinkState::kDegraded);
    const EndpointId es = builder.Endpoint("src", s);
    const EndpointId ed = builder.Endpoint("dst", d);
    const BuiltFabric fabric = builder.Build();
    PP_REQUIRE(fabric.ok);
    PlanningRequest request = MakeRequest("link-degraded", fabric);
    request.policy.cost_model.degraded_penalty = CostValue(11);
    const PlanningResult denied = RunPlan(fabric.snapshot, request);
    PP_CHECK_MSG(denied.status == PlanStatus::kNoPath, "degraded status " + StatusText(denied));
    PP_CHECK_MSG(denied.primary_failure == DiagnosticCode::kLinkStateDegradedDisallowed,
                 "degraded primary " + StatusText(denied));
    PP_CHECK_MSG(RejectionOccurrences(denied, DiagnosticCode::kLinkStateDegradedDisallowed) == 1u,
                 "degraded rejection counted " +
                     std::to_string(RejectionOccurrences(denied, DiagnosticCode::kLinkStateDegradedDisallowed)));
    request.policy.allow_degraded_links = true;
    const PlanningResult allowed = RunPlan(fabric.snapshot, request);
    const Oracle oracle = BuildOracle(*fabric.snapshot, request);
    PP_CHECK_MSG(allowed.status == PlanStatus::kPlanned, "degraded allowed status " + StatusText(allowed));
    PP_REQUIRE(allowed.candidates.size() == 1u);
    PP_CHECK_MSG(allowed.candidates[0].cost.total.Value() == 15u,
                 "degraded total " + std::to_string(allowed.candidates[0].cost.total.Value()));
    PP_CHECK_MSG(allowed.candidates[0].cost.degraded_penalty.Value() == 11u,
                 "degraded penalty " + std::to_string(allowed.candidates[0].cost.degraded_penalty.Value()));
    PP_CHECK_MSG(allowed.candidates[0].cost.degraded_hops == 1u, "degraded hop count is not 1");
    PP_CHECK_MSG(allowed.candidates[0].currentness == Currentness::kCurrent,
                 "degraded candidate is not CURRENT");
    CheckCandidatesAgainstOracle(fabric, request, allowed, OracleExpectedPaths(oracle, request, 1), "link-degraded");
  }
  {
    GraphBuilder builder("link-unknown-waived");
    const NodeId s = builder.Node("s");
    const NodeId d = builder.Node("d");
    builder.Link("s-d", s, d, 3, LinkState::kUnknown);
    const EndpointId es = builder.Endpoint("src", s);
    const EndpointId ed = builder.Endpoint("dst", d);
    const BuiltFabric fabric = builder.Build();
    PP_REQUIRE(fabric.ok);
    PlanningRequest request = MakeRequest("link-unknown-waived", fabric);
    request.policy.require_operational_proof = false;
    const PlanningResult result = RunPlan(fabric.snapshot, request);
    const Oracle oracle = BuildOracle(*fabric.snapshot, request);
    PP_CHECK_MSG(result.status == PlanStatus::kRevalidationRequired, "waived proof status " + StatusText(result));
    PP_REQUIRE(result.candidates.size() == 1u);
    PP_CHECK_MSG(result.candidates[0].currentness == Currentness::kRevalidationRequired,
                 "waived proof candidate is not REVALIDATION_REQUIRED");
    PP_CHECK_MSG(HasNote(result.candidates[0], DiagnosticCode::kNonCurrentCandidate),
                 "waived proof candidate carries no NON_CURRENT_CANDIDATE note");
    CheckCandidatesAgainstOracle(fabric, request, result, OracleExpectedPaths(oracle, request, 1),
                                 "link-unknown-waived");
    PlanningRequest diagnostic = MakeRequest("link-unknown-diagnostic", fabric);
    diagnostic.mode = PlanningMode::kDiagnosticNonCurrent;
    const PlanningResult diagnostic_result = RunPlan(fabric.snapshot, diagnostic);
    PP_CHECK_MSG(diagnostic_result.status == PlanStatus::kRevalidationRequired,
                 "diagnostic status " + StatusText(diagnostic_result));
    PP_REQUIRE(!diagnostic_result.candidates.empty());
    PP_CHECK_MSG(diagnostic_result.candidates[0].currentness != Currentness::kCurrent,
                 "a diagnostic candidate is CURRENT");
    PlanningRequest revalidating = MakeRequest("link-revalidating", fabric);
    revalidating.mode = PlanningMode::kDiagnosticNonCurrent;
    const PlanningResult revalidating_result = RunPlan(fabric.snapshot, revalidating);
    PP_CHECK_MSG(revalidating_result.status == PlanStatus::kRevalidationRequired,
                 "revalidating link status " + StatusText(revalidating_result));
  }
  {
    struct PortCase {
      PortState state;
      DiagnosticCode code;
      bool allow_draining;
      bool allow_maintenance;
    };
    const PortCase cases[4] = {
        {PortState::kAdminDisabled, DiagnosticCode::kPortAdminDisabled, false, false},
        {PortState::kDraining, DiagnosticCode::kPortDraining, false, false},
        {PortState::kMaintenance, DiagnosticCode::kPortMaintenance, false, false},
        {PortState::kSuperseded, DiagnosticCode::kPortSuperseded, false, false},
    };
    for (const PortCase& item : cases) {
      const std::string tag = std::string(ToString(item.state));
      GraphBuilder builder("port-" + tag);
      const NodeId s = builder.Node("s");
      const NodeId d = builder.Node("d");
      builder.Link("s-d", s, d, 1, LinkState::kUp, item.state, PortState::kUp);
      const EndpointId es = builder.Endpoint("src", s);
      const EndpointId ed = builder.Endpoint("dst", d);
      const BuiltFabric fabric = builder.Build();
      PP_REQUIRE(fabric.ok);
      PlanningRequest request = MakeRequest("port-" + tag, fabric);
      request.policy.allow_draining_ports = item.allow_draining;
      request.policy.allow_maintenance_ports = item.allow_maintenance;
      const PlanningResult result = RunPlan(fabric.snapshot, request);
      PP_CHECK_MSG(result.status == PlanStatus::kNoPath, "port " + tag + " status " + StatusText(result));
      PP_CHECK_MSG(result.primary_failure == item.code,
                   "port " + tag + " primary " + StatusText(result));
      PP_CHECK_MSG(result.candidates.empty(), "port " + tag + " returned candidates");
      PP_CHECK_MSG(RejectionOccurrences(result, item.code) == 1u,
                   "port " + tag + " rejection " + std::string(ToString(item.code)) + " counted " +
                       std::to_string(RejectionOccurrences(result, item.code)));
    }
    GraphBuilder builder("port-draining-allowed");
    const NodeId s = builder.Node("s");
    const NodeId d = builder.Node("d");
    builder.Link("s-d", s, d, 4, LinkState::kUp, PortState::kDraining, PortState::kUp);
    const EndpointId es = builder.Endpoint("src", s);
    const EndpointId ed = builder.Endpoint("dst", d);
    const BuiltFabric fabric = builder.Build();
    PP_REQUIRE(fabric.ok);
    PlanningRequest request = MakeRequest("port-draining-allowed", fabric);
    request.policy.allow_draining_ports = true;
    const PlanningResult allowed = RunPlan(fabric.snapshot, request);
    PP_CHECK_MSG(allowed.status == PlanStatus::kPlanned, "draining allowed status " + StatusText(allowed));
    PP_REQUIRE(allowed.candidates.size() == 1u);
    PP_CHECK_MSG(allowed.candidates[0].currentness == Currentness::kCurrent,
                 "draining-allowed candidate is not CURRENT");
    GraphBuilder maintenance_builder("port-maintenance-allowed");
    const NodeId ms = maintenance_builder.Node("s");
    const NodeId md = maintenance_builder.Node("d");
    maintenance_builder.Link("s-d", ms, md, 4, LinkState::kUp, PortState::kMaintenance, PortState::kUp);
    maintenance_builder.Endpoint("src", ms);
    maintenance_builder.Endpoint("dst", md);
    const BuiltFabric maintenance_fabric = maintenance_builder.Build();
    PP_REQUIRE(maintenance_fabric.ok);
    PlanningRequest maintenance_request = MakeRequest("port-maintenance-allowed", maintenance_fabric);
    maintenance_request.policy.allow_maintenance_ports = true;
    const PlanningResult maintenance_result = RunPlan(maintenance_fabric.snapshot, maintenance_request);
    PP_CHECK_MSG(maintenance_result.status == PlanStatus::kPlanned,
                 "maintenance allowed status " + StatusText(maintenance_result));
  }
  {
    GraphBuilder builder("capability");
    const NodeId s = builder.Node("s");
    const NodeId d = builder.Node("d");
    const LinkId link = builder.Link("s-d", s, d, 1);
    const EndpointId es = builder.Endpoint("src", s);
    const EndpointId ed = builder.Endpoint("dst", d);
    const CapabilityId bandwidth = IdFromLabel<CapabilityId>("cap/bandwidth");
    builder.AddCapability(SubjectKey::ForLink(link), bandwidth, 4);
    const BuiltFabric fabric = builder.Build();
    PP_REQUIRE(fabric.ok);
    CapabilityRequirement requirement;
    requirement.capability = bandwidth;
    requirement.scope = CapabilityScope::kEveryLink;
    requirement.comparator = CapabilityComparator::kAtLeast;
    requirement.value = CapabilityValue(4);
    PlanningRequest request = MakeRequest("capability-ok", fabric);
    request.constraints.required_capabilities.push_back(requirement);
    PP_CHECK_MSG(RunPlan(fabric.snapshot, request).status == PlanStatus::kPlanned,
                 "a satisfied every-link capability was not accepted");
    requirement.value = CapabilityValue(5);
    PlanningRequest insufficient = MakeRequest("capability-insufficient", fabric);
    insufficient.constraints.required_capabilities.push_back(requirement);
    const PlanningResult insufficient_result = RunPlan(fabric.snapshot, insufficient);
    PP_CHECK_MSG(insufficient_result.status == PlanStatus::kNoPath,
                 "insufficient capability status " + StatusText(insufficient_result));
    PP_CHECK_MSG(insufficient_result.primary_failure == DiagnosticCode::kCapabilityInsufficient,
                 "insufficient capability primary " + StatusText(insufficient_result));
    PP_CHECK_MSG(RejectionOccurrences(insufficient_result, DiagnosticCode::kCapabilityInsufficient) == 1u,
                 "insufficient capability counted " +
                     std::to_string(RejectionOccurrences(insufficient_result, DiagnosticCode::kCapabilityInsufficient)));
    requirement.capability = IdFromLabel<CapabilityId>("cap/absent");
    requirement.value = CapabilityValue(1);
    PlanningRequest absent = MakeRequest("capability-absent", fabric);
    absent.constraints.required_capabilities.push_back(requirement);
    const PlanningResult absent_result = RunPlan(fabric.snapshot, absent);
    PP_CHECK_MSG(absent_result.status == PlanStatus::kNoPath, "absent capability status " + StatusText(absent_result));
    PP_CHECK_MSG(RejectionOccurrences(absent_result, DiagnosticCode::kCapabilityUnknown) == 1u,
                 "absent capability counted " +
                     std::to_string(RejectionOccurrences(absent_result, DiagnosticCode::kCapabilityUnknown)));
    requirement.capability = bandwidth;
    requirement.comparator = CapabilityComparator::kEqual;
    requirement.value = CapabilityValue(4);
    PlanningRequest equal_ok = MakeRequest("capability-equal-ok", fabric);
    equal_ok.constraints.required_capabilities.push_back(requirement);
    PP_CHECK_MSG(RunPlan(fabric.snapshot, equal_ok).status == PlanStatus::kPlanned,
                 "an EQUAL capability match was not accepted");
    requirement.value = CapabilityValue(3);
    PlanningRequest equal_bad = MakeRequest("capability-equal-bad", fabric);
    equal_bad.constraints.required_capabilities.push_back(requirement);
    PP_CHECK_MSG(RejectionOccurrences(RunPlan(fabric.snapshot, equal_bad), DiagnosticCode::kCapabilityInsufficient) ==
                     1u,
                 "an EQUAL capability mismatch was not reported as insufficient");
    requirement.comparator = CapabilityComparator::kAtLeast;
    requirement.value = CapabilityValue(1);
    requirement.scope = CapabilityScope::kSourceNode;
    PlanningRequest node_scope = MakeRequest("capability-node-scope", fabric);
    node_scope.constraints.required_capabilities.push_back(requirement);
    const PlanningResult node_scope_result = RunPlan(fabric.snapshot, node_scope);
    PP_CHECK_MSG(node_scope_result.status == PlanStatus::kConstraintUnsatisfied,
                 "source-node capability status " + StatusText(node_scope_result));
    PP_CHECK_MSG(node_scope_result.primary_failure == DiagnosticCode::kCapabilityUnknown,
                 "source-node capability primary " + StatusText(node_scope_result));
    PP_CHECK_MSG(node_scope_result.candidates.empty(), "source-node capability returned candidates");
  }
  {
    GraphBuilder builder("forbidden");
    const NodeId s = builder.Node("s");
    const NodeId a = builder.Node("a");
    const NodeId d = builder.Node("d");
    const LinkId first = builder.Link("f0", s, a, 1);
    const LinkId second = builder.Link("f1", a, d, 1);
    const EndpointId es = builder.Endpoint("src", s);
    const EndpointId ed = builder.Endpoint("dst", d);
    const BuiltFabric fabric = builder.Build();
    PP_REQUIRE(fabric.ok);
    PlanningRequest request = MakeRequest("forbidden-link", fabric);
    request.constraints.forbidden_links.push_back(first);
    const PlanningResult link_result = RunPlan(fabric.snapshot, request);
    PP_CHECK_MSG(link_result.status == PlanStatus::kNoPath, "forbidden link status " + StatusText(link_result));
    PP_CHECK_MSG(link_result.primary_failure == DiagnosticCode::kForbiddenLink,
                 "forbidden link primary " + StatusText(link_result));
    PP_CHECK_MSG(RejectionOccurrences(link_result, DiagnosticCode::kForbiddenLink) == 1u,
                 "forbidden link evidence counted " +
                     std::to_string(RejectionOccurrences(link_result, DiagnosticCode::kForbiddenLink)));
    PlanningRequest both = MakeRequest("forbidden-both-links", fabric);
    both.constraints.forbidden_links.push_back(first);
    both.constraints.forbidden_links.push_back(second);
    const PlanningResult both_result = RunPlan(fabric.snapshot, both);
    PP_CHECK_MSG(both_result.status == PlanStatus::kNoPath, "two forbidden links status " + StatusText(both_result));
    PP_CHECK_MSG(RejectionOccurrences(both_result, DiagnosticCode::kForbiddenLink) == 2u,
                 "two forbidden links evidence counted " +
                     std::to_string(RejectionOccurrences(both_result, DiagnosticCode::kForbiddenLink)));
    PlanningRequest middle = MakeRequest("forbidden-node", fabric);
    middle.constraints.forbidden_nodes.push_back(a);
    const PlanningResult node_result = RunPlan(fabric.snapshot, middle);
    PP_CHECK_MSG(node_result.status == PlanStatus::kNoPath, "forbidden node status " + StatusText(node_result));
    PP_CHECK_MSG(node_result.primary_failure == DiagnosticCode::kForbiddenNode,
                 "forbidden node primary " + StatusText(node_result));
    PP_CHECK_MSG(RejectionOccurrences(node_result, DiagnosticCode::kForbiddenNode) == 1u,
                 "forbidden node evidence counted " +
                     std::to_string(RejectionOccurrences(node_result, DiagnosticCode::kForbiddenNode)));
    PlanningRequest source = MakeRequest("forbidden-source", fabric);
    source.constraints.forbidden_nodes.push_back(s);
    const PlanningResult source_result = RunPlan(fabric.snapshot, source);
    PP_CHECK_MSG(source_result.status == PlanStatus::kConstraintUnsatisfied,
                 "forbidden source status " + StatusText(source_result));
    PP_CHECK_MSG(source_result.primary_failure == DiagnosticCode::kForbiddenNode,
                 "forbidden source primary " + StatusText(source_result));
    PlanningRequest destination = MakeRequest("forbidden-destination", fabric);
    destination.constraints.forbidden_nodes.push_back(d);
    const PlanningResult destination_result = RunPlan(fabric.snapshot, destination);
    PP_CHECK_MSG(destination_result.status == PlanStatus::kConstraintUnsatisfied,
                 "forbidden destination status " + StatusText(destination_result));
    PP_CHECK_MSG(destination_result.primary_failure == DiagnosticCode::kForbiddenNode,
                 "forbidden destination primary " + StatusText(destination_result));
    PlanningRequest port = MakeRequest("forbidden-port", fabric);
    port.constraints.forbidden_ports.push_back(fabric.port_by_label.at("f0/from"));
    const PlanningResult port_result = RunPlan(fabric.snapshot, port);
    PP_CHECK_MSG(port_result.status == PlanStatus::kNoPath, "forbidden port status " + StatusText(port_result));
    PP_CHECK_MSG(RejectionOccurrences(port_result, DiagnosticCode::kForbiddenPort) == 1u,
                 "forbidden port evidence counted " +
                     std::to_string(RejectionOccurrences(port_result, DiagnosticCode::kForbiddenPort)));
  }
  {
    const BuiltFabric fabric = BuildDiamond("forbidden-domain", false, 2);
    PP_REQUIRE(fabric.ok);
    const NodeId s = fabric.node_by_label.at("s");
    const NodeId b = fabric.node_by_label.at("b");
    const NodeId d = fabric.node_by_label.at("d");
    PlanningRequest alternative = MakeRequest("forbidden-domain-alternative", fabric);
    alternative.constraints.forbidden_links.push_back(fabric.link_by_label.at("s-a"));
    const PlanningResult alternative_result = RunPlan(fabric.snapshot, alternative);
    PP_REQUIRE(alternative_result.candidates.size() == 1u);
    PP_CHECK_MSG(alternative_result.candidates[0].path.nodes == std::vector<NodeId>({s, b, d}),
                 "the surviving diamond route was not used");
    PP_CHECK_MSG(alternative_result.status == PlanStatus::kPlanned,
                 "forbidden link with an alternative status " + StatusText(alternative_result));
  }
  {
    GraphBuilder builder("domain-diamond");
    const NodeId s = builder.Node("s");
    const NodeId a = builder.Node("a");
    const NodeId b = builder.Node("b");
    const NodeId d = builder.Node("d");
    const LinkId sa = builder.Link("s-a", s, a, 1);
    const LinkId ad = builder.Link("a-d", a, d, 1);
    const LinkId sb = builder.Link("s-b", s, b, 1);
    const LinkId bd = builder.Link("b-d", b, d, 1);
    const EndpointId es = builder.Endpoint("src", s);
    const EndpointId ed = builder.Endpoint("dst", d);
    const FailureDomainId shared = IdFromLabel<FailureDomainId>("domain/shared");
    const FailureDomainClass shared_class = IdFromLabel<FailureDomainClass>("class/shared");
    const FailureDomainId isolated = IdFromLabel<FailureDomainId>("domain/isolated");
    builder.AddDomain(shared, shared_class,
                      {SubjectKey::ForLink(sa), SubjectKey::ForLink(ad), SubjectKey::ForLink(sb)});
    builder.AddDomain(isolated, IdFromLabel<FailureDomainClass>("class/isolated"), {SubjectKey::ForLink(bd)});
    builder.SetMembershipComplete(true);
    const BuiltFabric fabric = builder.Build();
    PP_REQUIRE(fabric.ok);
    PlanningRequest request = MakeRequest("domain-forbidden", fabric);
    request.constraints.forbidden_failure_domains.push_back(shared);
    const PlanningResult result = RunPlan(fabric.snapshot, request);
    PP_CHECK_MSG(result.status == PlanStatus::kNoPath, "forbidden domain status " + StatusText(result));
    PP_CHECK_MSG(result.primary_failure == DiagnosticCode::kFailureDomainForbidden,
                 "forbidden domain primary " + StatusText(result));
    PP_CHECK_MSG(RejectionOccurrences(result, DiagnosticCode::kFailureDomainForbidden) == 3u,
                 "forbidden domain evidence counted " +
                     std::to_string(RejectionOccurrences(result, DiagnosticCode::kFailureDomainForbidden)));
    PlanningRequest class_request = MakeRequest("domain-class-forbidden", fabric);
    class_request.constraints.forbidden_failure_domain_classes.push_back(shared_class);
    const PlanningResult class_result = RunPlan(fabric.snapshot, class_request);
    PP_CHECK_MSG(class_result.status == PlanStatus::kNoPath, "forbidden class status " + StatusText(class_result));
    PP_CHECK_MSG(RejectionOccurrences(class_result, DiagnosticCode::kFailureDomainClassForbidden) == 3u,
                 "forbidden class evidence counted " +
                     std::to_string(RejectionOccurrences(class_result, DiagnosticCode::kFailureDomainClassForbidden)));
    for (std::uint32_t limit = 1; limit <= 2; ++limit) {
      for (std::uint32_t k = 1; k <= 3; ++k) {
        const std::string context = "member-limit " + std::to_string(limit) + " K=" + std::to_string(k);
        PlanningRequest limited = MakeRequest(context, fabric);
        limited.max_candidates = k;
        limited.constraints.max_members_per_failure_domain = limit;
        const PlanningResult limited_result = RunPlan(fabric.snapshot, limited);
        const Oracle oracle = BuildOracle(*fabric.snapshot, limited);
        CheckCandidatesAgainstOracle(fabric, limited, limited_result, OracleExpectedPaths(oracle, limited, k),
                                     context);
        CheckCandidateInvariants(fabric, limited, oracle, limited_result, context);
      }
    }
    PlanningRequest limit_one = MakeRequest("member-limit-1", fabric);
    limit_one.max_candidates = 3;
    limit_one.constraints.max_members_per_failure_domain = 1;
    const PlanningResult limit_one_result = RunPlan(fabric.snapshot, limit_one);
    PP_REQUIRE(limit_one_result.candidates.size() == 1u);
    PP_CHECK_MSG(limit_one_result.candidates[0].path.nodes == std::vector<NodeId>({s, b, d}),
                 "the member limit did not keep the canonical surviving candidate");
    PlanningRequest limit_two = MakeRequest("member-limit-2", fabric);
    limit_two.max_candidates = 3;
    limit_two.constraints.max_members_per_failure_domain = 2;
    PP_CHECK_MSG(RunPlan(fabric.snapshot, limit_two).candidates.size() == 2u,
                 "the member limit filtered the canonical order incorrectly");
    PlanningRequest isolated_request = MakeRequest("domain-isolated", fabric);
    isolated_request.constraints.forbidden_failure_domains.push_back(isolated);
    const PlanningResult isolated_result = RunPlan(fabric.snapshot, isolated_request);
    PP_CHECK_MSG(isolated_result.status == PlanStatus::kPlanned, "isolated domain status " + StatusText(isolated_result));
    PP_REQUIRE(isolated_result.candidates.size() == 1u);
    PP_CHECK_MSG(isolated_result.candidates[0].path.nodes == std::vector<NodeId>({s, a, d}),
                 "forbidding an isolated domain displaced the canonical route");
    PP_CHECK_MSG(RejectionOccurrences(isolated_result, DiagnosticCode::kFailureDomainForbidden) == 1u,
                 "isolated domain evidence counted " +
                     std::to_string(RejectionOccurrences(isolated_result, DiagnosticCode::kFailureDomainForbidden)));
    GraphBuilder open_builder("domain-open");
    const NodeId os = open_builder.Node("s");
    const NodeId od = open_builder.Node("d");
    const LinkId olink = open_builder.Link("s-d", os, od, 1);
    const EndpointId oes = open_builder.Endpoint("src", os);
    const EndpointId oed = open_builder.Endpoint("dst", od);
    open_builder.AddDomain(IdFromLabel<FailureDomainId>("domain/elsewhere"),
                          IdFromLabel<FailureDomainClass>("class/elsewhere"),
                          {SubjectKey::ForNode(os), SubjectKey::ForNode(od), SubjectKey::ForLink(olink)});
    open_builder.SetMembershipComplete(false);
    const BuiltFabric open_fabric = open_builder.Build();
    PP_REQUIRE(open_fabric.ok);
    PlanningRequest open_request = MakeRequest("domain-open", open_fabric);
    open_request.constraints.forbidden_failure_domains.push_back(IdFromLabel<FailureDomainId>("domain/absent"));
    const PlanningResult open_closed = RunPlan(open_fabric.snapshot, open_request);
    PP_CHECK_MSG(open_closed.status == PlanStatus::kNoPath, "fail-closed status " + StatusText(open_closed));
    PP_CHECK_MSG(RejectionOccurrences(open_closed, DiagnosticCode::kFailureDomainUnknown) == 1u,
                 "fail-closed evidence counted " +
                     std::to_string(RejectionOccurrences(open_closed, DiagnosticCode::kFailureDomainUnknown)));
    open_request.constraints.fail_closed_on_unknown_domains = false;
    PP_CHECK_MSG(RunPlan(open_fabric.snapshot, open_request).status == PlanStatus::kPlanned,
                 "fail-open on unknown domains did not plan");
  }
}

// 6. max_hops boundaries, the zero-hop self path and long chains.
PP_TEST(oracle, max_hops_boundaries) {
  {
    const BuiltFabric fabric = BuildOneWay("hop-chain", 8);
    PP_REQUIRE(fabric.ok);
    const std::vector<NodeId> order = LabelOrder(fabric, "n", 8);
    PlanningRequest exact = MakeRequest("hop-exact", fabric);
    exact.constraints.max_hops = HopCount(7);
    const PlanningResult exact_result = RunPlan(fabric.snapshot, exact);
    PP_CHECK_MSG(exact_result.status == PlanStatus::kPlanned, "exact hop status " + StatusText(exact_result));
    PP_REQUIRE(exact_result.candidates.size() == 1u);
    PP_CHECK_MSG(exact_result.candidates[0].cost.hops.Value() == 7u,
                 "exact hop count " + std::to_string(exact_result.candidates[0].cost.hops.Value()));
    PP_CHECK_MSG(exact_result.candidates[0].path.nodes == order, "the chain was not walked end to end");
    PlanningRequest beyond = MakeRequest("hop-beyond", fabric);
    beyond.constraints.max_hops = HopCount(6);
    const PlanningResult beyond_result = RunPlan(fabric.snapshot, beyond);
    PP_CHECK_MSG(beyond_result.status == PlanStatus::kConstraintUnsatisfied,
                 "one-beyond status " + StatusText(beyond_result));
    PP_CHECK_MSG(beyond_result.primary_failure == DiagnosticCode::kMaxHopsExceeded,
                 "one-beyond primary " + StatusText(beyond_result));
    PP_CHECK_MSG(beyond_result.candidates.empty(), "one-beyond returned candidates");
    bool hop_detail = false;
    for (const ExplanationEntry& entry : beyond_result.explanations) {
      if (entry.code == DiagnosticCode::kMaxHopsExceeded && entry.detail.find("needs 7 hops") != std::string::npos) {
        hop_detail = true;
      }
    }
    PP_CHECK_MSG(hop_detail, "the hop-bound failure does not name the required hop count");
    PlanningRequest ceiling = MakeRequest("hop-ceiling", fabric);
    ceiling.constraints.max_hops = HopCount(ResourceLimits{}.max_hops + 1u);
    const PlanningResult ceiling_result = RunPlan(fabric.snapshot, ceiling);
    PP_CHECK_MSG(ceiling_result.status == PlanStatus::kConstraintUnsatisfied,
                 "above-ceiling status " + StatusText(ceiling_result));
    PP_CHECK_MSG(ceiling_result.primary_failure == DiagnosticCode::kMaxHopsExceeded,
                 "above-ceiling primary " + StatusText(ceiling_result));
    PP_CHECK_MSG(ceiling_result.candidates.empty(), "above-ceiling returned candidates");
  }
  {
    const BuiltFabric fabric = BuildOneWay("hop-ceiling-chain", 513);
    PP_REQUIRE(fabric.ok);
    PlanningRequest request = MakeRequest("hop-ceiling-chain", fabric);
    request.constraints.max_hops = HopCount(ResourceLimits{}.max_hops);
    const PlanningResult result = RunPlan(fabric.snapshot, request);
    PP_CHECK_MSG(result.status == PlanStatus::kPlanned, "ceiling chain status " + StatusText(result));
    PP_REQUIRE(result.candidates.size() == 1u);
    PP_CHECK_MSG(result.candidates[0].cost.hops.Value() == ResourceLimits{}.max_hops,
                 "ceiling chain hop count " + std::to_string(result.candidates[0].cost.hops.Value()));
    PP_CHECK_MSG(result.candidates[0].path.nodes.size() == 513u,
                 "ceiling chain node count " + std::to_string(result.candidates[0].path.nodes.size()));
    PP_CHECK_MSG(result.candidates[0].path.nodes.front() == fabric.node_by_label.at("n0") &&
                     result.candidates[0].path.nodes.back() == fabric.node_by_label.at("n512"),
                 "the ceiling chain does not run between its published endpoints");
  }
  {
    const BuiltFabric fabric = BuildOneWay("hop-deep", 64);
    PP_REQUIRE(fabric.ok);
    PlanningRequest request = MakeRequest("hop-deep", fabric);
    const PlanningResult result = RunPlan(fabric.snapshot, request);
    PP_REQUIRE(result.candidates.size() == 1u);
    PP_CHECK_MSG(result.candidates[0].cost.hops.Value() == 63u,
                 "deep chain hop count " + std::to_string(result.candidates[0].cost.hops.Value()));
    PP_CHECK_MSG(result.candidates[0].path.nodes == LabelOrder(fabric, "n", 64),
                 "the deep chain was not walked end to end");
  }
  {
    const BuiltFabric fabric = BuildChain("hop-transit", 4, false, 1);
    PP_REQUIRE(fabric.ok);
    TransitStage stage;
    stage.kind = TransitKind::kExact;
    stage.alternatives.push_back(fabric.node_by_label.at("n1"));
    PlanningRequest beyond = MakeRequest("hop-transit-beyond", fabric);
    beyond.constraints.required_transit.push_back(stage);
    beyond.constraints.max_hops = HopCount(2);
    const PlanningResult beyond_result = RunPlan(fabric.snapshot, beyond);
    PP_CHECK_MSG(beyond_result.status == PlanStatus::kConstraintUnsatisfied,
                 "transit one-beyond status " + StatusText(beyond_result));
    PP_CHECK_MSG(beyond_result.primary_failure == DiagnosticCode::kMaxHopsExceeded,
                 "transit one-beyond primary " + StatusText(beyond_result));
    PlanningRequest exact = MakeRequest("hop-transit-exact", fabric);
    exact.constraints.required_transit.push_back(stage);
    exact.constraints.max_hops = HopCount(3);
    const PlanningResult exact_result = RunPlan(fabric.snapshot, exact);
    PP_CHECK_MSG(exact_result.status == PlanStatus::kPlanned, "transit exact status " + StatusText(exact_result));
    PP_REQUIRE(exact_result.candidates.size() == 1u);
    PP_CHECK_MSG(exact_result.candidates[0].cost.hops.Value() == 3u,
                 "transit exact hop count " + std::to_string(exact_result.candidates[0].cost.hops.Value()));
  }
  {
    GraphBuilder builder("zero-hop");
    const NodeId a = builder.Node("a");
    const NodeId b = builder.Node("b");
    builder.Link("a-b", a, b, 1);
    const EndpointId first = builder.Endpoint("first", a);
    const EndpointId second = builder.Endpoint("second", a);
    const BuiltFabric fabric = builder.Build();
    PP_REQUIRE(fabric.ok);
    PlanningRequest request = MakeRequestBetween("zero-hop", fabric, "first", "second");
    const PlanningResult allowed = RunPlan(fabric.snapshot, request);
    PP_CHECK_MSG(allowed.status == PlanStatus::kPlanned, "zero-hop status " + StatusText(allowed));
    PP_REQUIRE(allowed.candidates.size() == 1u);
    PP_CHECK_MSG(allowed.candidates[0].cost.hops.Value() == 0u,
                 "zero-hop hop count " + std::to_string(allowed.candidates[0].cost.hops.Value()));
    PP_CHECK_MSG(allowed.candidates[0].cost.total.Value() == 0u,
                 "zero-hop total " + std::to_string(allowed.candidates[0].cost.total.Value()));
    PP_CHECK_MSG(allowed.candidates[0].path.nodes == std::vector<NodeId>({a}), "zero-hop path is not the source node");
    PP_CHECK_MSG(allowed.candidates[0].path.IsSimple(), "the zero-hop path is not simple");
    const Oracle oracle = BuildOracle(*fabric.snapshot, request);
    PP_REQUIRE(oracle.paths.size() == 1u);
    CheckCandidatesAgainstOracle(fabric, request, allowed, OracleExpectedPaths(oracle, request, 1), "zero-hop");
    PlanningRequest denied = MakeRequestBetween("zero-hop-denied", fabric, "first", "second");
    denied.policy.allow_zero_hop_self_path = false;
    const PlanningResult denied_result = RunPlan(fabric.snapshot, denied);
    PP_CHECK_MSG(denied_result.status == PlanStatus::kConstraintUnsatisfied,
                 "zero-hop denial status " + StatusText(denied_result));
    PP_CHECK_MSG(denied_result.primary_failure == DiagnosticCode::kZeroHopSelfPathDisallowed,
                 "zero-hop denial primary " + StatusText(denied_result));
    PP_CHECK_MSG(denied_result.candidates.empty(), "zero-hop denial returned candidates");
  }
}

// 7. Required transit: ordered exact waypoints, unreachable waypoints, K > 1 and
//    ANY_OF stages.
PP_TEST(oracle, required_transit_stages) {
  {
    const BuiltFabric fabric = BuildChain("transit-chain", 4, false, 1);
    PP_REQUIRE(fabric.ok);
    const NodeId n0 = fabric.node_by_label.at("n0");
    const NodeId n1 = fabric.node_by_label.at("n1");
    const NodeId n2 = fabric.node_by_label.at("n2");
    const NodeId n3 = fabric.node_by_label.at("n3");
    TransitStage first;
    first.kind = TransitKind::kExact;
    first.alternatives.push_back(n1);
    TransitStage second;
    second.kind = TransitKind::kExact;
    second.alternatives.push_back(n2);
    PlanningRequest request = MakeRequest("transit-chain", fabric);
    request.constraints.required_transit.push_back(first);
    request.constraints.required_transit.push_back(second);
    const PlanningResult result = RunPlan(fabric.snapshot, request);
    PP_CHECK_MSG(result.status == PlanStatus::kPlanned, "ordered transit status " + StatusText(result));
    PP_REQUIRE(result.candidates.size() == 1u);
    const CandidatePath& path = result.candidates[0].path;
    PP_CHECK_MSG(path.nodes == std::vector<NodeId>({n0, n1, n2, n3}), "ordered transit path " + PathNodeSeq(path));
    PP_CHECK_MSG(ContainsInOrder(path.nodes, std::vector<NodeId>({n1, n2})), "waypoints are not visited in order");
    PP_CHECK_MSG(path.IsSimple(), "the transit path is not simple");
    PP_CHECK_MSG(result.candidates[0].cost.hops.Value() == 3u, "ordered transit hop count");
    const Oracle oracle = BuildOracle(*fabric.snapshot, request);
    CheckCandidateInvariants(fabric, request, oracle, result, "ordered transit");
    PlanningRequest reversed = MakeRequest("transit-reversed", fabric);
    TransitStage late;
    late.kind = TransitKind::kExact;
    late.alternatives.push_back(n2);
    TransitStage early;
    early.kind = TransitKind::kExact;
    early.alternatives.push_back(n1);
    reversed.constraints.required_transit.push_back(late);
    reversed.constraints.required_transit.push_back(early);
    const PlanningResult reversed_result = RunPlan(fabric.snapshot, reversed);
    PP_CHECK_MSG(reversed_result.status == PlanStatus::kConstraintUnsatisfied,
                 "reversed transit status " + StatusText(reversed_result));
    PP_CHECK_MSG(reversed_result.primary_failure == DiagnosticCode::kRequiredNodeMissing,
                 "reversed transit primary " + StatusText(reversed_result));
    PP_CHECK_MSG(reversed_result.candidates.empty(), "reversed transit returned candidates");
    PlanningRequest missing = MakeRequest("transit-missing", fabric);
    TransitStage absent;
    absent.kind = TransitKind::kExact;
    absent.alternatives.push_back(IdFromLabel<NodeId>("nowhere/node"));
    missing.constraints.required_transit.push_back(absent);
    const PlanningResult missing_result = RunPlan(fabric.snapshot, missing);
    PP_CHECK_MSG(missing_result.status == PlanStatus::kConstraintUnsatisfied,
                 "missing waypoint status " + StatusText(missing_result));
    PP_CHECK_MSG(missing_result.primary_failure == DiagnosticCode::kRequiredNodeMissing,
                 "missing waypoint primary " + StatusText(missing_result));
    PlanningRequest multi = MakeRequest("transit-multi", fabric);
    multi.max_candidates = 2;
    multi.constraints.required_transit.push_back(first);
    const PlanningResult multi_result = RunPlan(fabric.snapshot, multi);
    PP_CHECK_MSG(multi_result.status == PlanStatus::kUnsupported,
                 "K > 1 transit status " + StatusText(multi_result));
    PP_CHECK_MSG(multi_result.primary_failure == DiagnosticCode::kUnsupportedRequest,
                 "K > 1 transit primary " + StatusText(multi_result));
    PP_CHECK_MSG(multi_result.candidates.empty(), "K > 1 transit returned candidates");
  }
  {
    GraphBuilder builder("transit-anyof");
    const NodeId s = builder.Node("s");
    const NodeId on_path = builder.Node("on_path");
    const NodeId dead_end = builder.Node("dead_end");
    const NodeId isolated = builder.Node("isolated");
    const NodeId d = builder.Node("d");
    builder.Link("s-a", s, on_path, 1);
    builder.Link("a-d", on_path, d, 1);
    builder.Link("s-x", s, dead_end, 1);
    const EndpointId es = builder.Endpoint("src", s);
    const EndpointId ed = builder.Endpoint("dst", d);
    const BuiltFabric fabric = builder.Build();
    PP_REQUIRE(fabric.ok);
    TransitStage any_of;
    any_of.kind = TransitKind::kAnyOf;
    any_of.alternatives.push_back(dead_end);
    any_of.alternatives.push_back(on_path);
    PlanningRequest request = MakeRequest("transit-anyof", fabric);
    request.constraints.required_transit.push_back(any_of);
    const PlanningResult result = RunPlan(fabric.snapshot, request);
    PP_CHECK_MSG(result.status == PlanStatus::kPlanned, "ANY_OF status " + StatusText(result));
    PP_REQUIRE(result.candidates.size() == 1u);
    const CandidatePath& path = result.candidates[0].path;
    PP_CHECK_MSG(ContainsInOrder(path.nodes, std::vector<NodeId>({on_path})),
                 "the satisfiable ANY_OF member was not visited: " + PathNodeSeq(path));
    PP_CHECK_MSG(!ContainsInOrder(path.nodes, std::vector<NodeId>({dead_end})),
                 "the dead-end ANY_OF member was visited: " + PathNodeSeq(path));
    PP_CHECK_MSG(path.IsSimple(), "the ANY_OF path is not simple");
    const Oracle oracle = BuildOracle(*fabric.snapshot, request);
    CheckCandidateInvariants(fabric, request, oracle, result, "ANY_OF transit");
    TransitStage unsatisfiable;
    unsatisfiable.kind = TransitKind::kAnyOf;
    unsatisfiable.alternatives.push_back(isolated);
    PlanningRequest unsat_request = MakeRequest("transit-anyof-unsat", fabric);
    unsat_request.constraints.required_transit.push_back(unsatisfiable);
    const PlanningResult unsat_result = RunPlan(fabric.snapshot, unsat_request);
    PP_CHECK_MSG(unsat_result.status == PlanStatus::kConstraintUnsatisfied,
                 "unsatisfiable ANY_OF status " + StatusText(unsat_result));
    PP_CHECK_MSG(unsat_result.primary_failure == DiagnosticCode::kRequiredAnySetUnsatisfied,
                 "unsatisfiable ANY_OF primary " + StatusText(unsat_result));
    TransitStage all_absent;
    all_absent.kind = TransitKind::kAnyOf;
    all_absent.alternatives.push_back(IdFromLabel<NodeId>("nowhere/a"));
    all_absent.alternatives.push_back(IdFromLabel<NodeId>("nowhere/b"));
    PlanningRequest absent_request = MakeRequest("transit-anyof-absent", fabric);
    absent_request.constraints.required_transit.push_back(all_absent);
    PP_CHECK_MSG(RunPlan(fabric.snapshot, absent_request).primary_failure ==
                     DiagnosticCode::kRequiredNodeMissing,
                 "unpublished ANY_OF alternatives are not reported as a missing required node");
  }
  {
    const BuiltFabric fabric = BuildMesh("transit-mesh", 2, 3, 5);
    PP_REQUIRE(fabric.ok);
    const NodeId waypoint = fabric.node_by_label.at("m0_1");
    TransitStage stage;
    stage.kind = TransitKind::kExact;
    stage.alternatives.push_back(waypoint);
    PlanningRequest request = MakeRequest("transit-mesh", fabric);
    request.constraints.required_transit.push_back(stage);
    const PlanningResult result = RunPlan(fabric.snapshot, request);
    const std::string context = "mesh transit";
    PP_CHECK_MSG(result.status == PlanStatus::kPlanned, context + " status " + StatusText(result));
    PP_REQUIRE(result.candidates.size() == 1u);
    const CandidatePath& path = result.candidates[0].path;
    PP_CHECK_MSG(ContainsInOrder(path.nodes, std::vector<NodeId>({waypoint})),
                 context + " waypoint missing from " + PathNodeSeq(path));
    PP_CHECK_MSG(path.IsSimple(), context + " path is not simple");
    PP_CHECK_MSG(path.nodes.front() == result.source_node && path.nodes.back() == result.destination_node,
                 context + " path endpoints are wrong");
    const Oracle oracle = BuildOracle(*fabric.snapshot, request);
    CheckCandidateInvariants(fabric, request, oracle, result, context);
  }
}

// 8. Cost overflow is structured, never a wrapped total.
PP_TEST(oracle, cost_overflow_is_structured) {
  const std::uint64_t huge_hop_cost = 1ull << 62;
  {
    const BuiltFabric fabric = BuildOneWay("overflow-short", 4);
    PP_REQUIRE(fabric.ok);
    PlanningRequest request = MakeRequest("overflow-short", fabric);
    request.policy.cost_model.hop_cost = CostValue(huge_hop_cost);
    const PlanningResult result = RunPlan(fabric.snapshot, request);
    const Oracle oracle = BuildOracle(*fabric.snapshot, request);
    PP_CHECK_MSG(result.status == PlanStatus::kPlanned, "short overflow status " + StatusText(result));
    PP_REQUIRE(result.candidates.size() == 1u);
    const PathCost& cost = result.candidates[0].cost;
    const std::uint64_t expected_hops_cost = huge_hop_cost * 3ull;
    const std::uint64_t expected_total = expected_hops_cost + 3ull;
    PP_CHECK_MSG(cost.hops_cost.Value() == expected_hops_cost,
                 "hops_cost " + std::to_string(cost.hops_cost.Value()) + " expected " +
                     std::to_string(expected_hops_cost));
    PP_CHECK_MSG(cost.static_cost.Value() == 3u, "static_cost " + std::to_string(cost.static_cost.Value()));
    PP_CHECK_MSG(cost.total.Value() == expected_total,
                 "total " + std::to_string(cost.total.Value()) + " expected " + std::to_string(expected_total));
    PP_CHECK_MSG(cost.total.Value() >= cost.hops_cost.Value() && cost.total.Value() >= cost.static_cost.Value(),
                 "the total wrapped below one of its components");
    CheckCandidatesAgainstOracle(fabric, request, result, OracleExpectedPaths(oracle, request, 1), "overflow-short");
    CheckCandidateInvariants(fabric, request, oracle, result, "overflow-short");
  }
  {
    const BuiltFabric fabric = BuildOneWay("overflow-long", 5);
    PP_REQUIRE(fabric.ok);
    PlanningRequest request = MakeRequest("overflow-long", fabric);
    request.policy.cost_model.hop_cost = CostValue(huge_hop_cost);
    const PlanningResult result = RunPlan(fabric.snapshot, request);
    PP_CHECK_MSG(result.status == PlanStatus::kResourceLimit, "overflow status " + StatusText(result));
    PP_CHECK_MSG(result.primary_failure == DiagnosticCode::kCostOverflow,
                 "overflow primary " + StatusText(result));
    PP_CHECK_MSG(result.candidates.empty(), "overflow returned candidates");
  }
  {
    const BuiltFabric fabric = BuildOneWay("overflow-max", 4);
    PP_REQUIRE(fabric.ok);
    PlanningRequest request = MakeRequest("overflow-max", fabric);
    request.policy.cost_model.hop_cost = CostValue(kU64Max);
    const PlanningResult result = RunPlan(fabric.snapshot, request);
    PP_CHECK_MSG(result.status == PlanStatus::kResourceLimit, "max hop cost status " + StatusText(result));
    PP_CHECK_MSG(result.primary_failure == DiagnosticCode::kCostOverflow,
                 "max hop cost primary " + StatusText(result));
  }
  {
    GraphBuilder builder("overflow-static");
    std::vector<NodeId> nodes;
    nodes.push_back(builder.Node("n0"));
    for (int i = 1; i < 4; ++i) {
      nodes.push_back(builder.Node("n" + std::to_string(i)));
      builder.Link("f" + std::to_string(i - 1), nodes[static_cast<std::size_t>(i) - 1],
                   nodes[static_cast<std::size_t>(i)], 0xFFFFFFF0u);
    }
    const EndpointId es = builder.Endpoint("src", nodes.front());
    const EndpointId ed = builder.Endpoint("dst", nodes.back());
    const BuiltFabric fabric = builder.Build();
    PP_REQUIRE(fabric.ok);
    PlanningRequest request = MakeRequest("overflow-static", fabric);
    request.policy.cost_model.hop_cost = CostValue(huge_hop_cost);
    const PlanningResult result = RunPlan(fabric.snapshot, request);
    const Oracle oracle = BuildOracle(*fabric.snapshot, request);
    PP_CHECK_MSG(result.status == PlanStatus::kPlanned, "static overflow status " + StatusText(result));
    PP_REQUIRE(result.candidates.size() == 1u);
    const PathCost& cost = result.candidates[0].cost;
    PP_CHECK_MSG(cost.static_cost.Value() == 12884901840ull,
                 "static_cost " + std::to_string(cost.static_cost.Value()));
    PP_CHECK_MSG(cost.total.Value() == 13835058068167065552ull,
                 "total " + std::to_string(cost.total.Value()));
    PP_CHECK_MSG(cost.total.Value() >= cost.static_cost.Value() && cost.total.Value() >= cost.hops_cost.Value(),
                 "the total wrapped below one of its components");
    CheckCandidatesAgainstOracle(fabric, request, result, OracleExpectedPaths(oracle, request, 1), "overflow-static");
  }
  {
    const BuiltFabric fabric = BuildOneWay("overflow-two", 4);
    PP_REQUIRE(fabric.ok);
    PlanningRequest request = MakeRequest("overflow-two", fabric);
    request.policy.cost_model.hop_cost = CostValue(1ull << 63);
    const PlanningResult result = RunPlan(fabric.snapshot, request);
    PP_CHECK_MSG(result.status == PlanStatus::kResourceLimit, "2^63 hop cost status " + StatusText(result));
    PP_CHECK_MSG(result.primary_failure == DiagnosticCode::kCostOverflow,
                 "2^63 hop cost primary " + StatusText(result));
  }
}

// 9. Layer separation: a logical edge is never used by a physical request (and the
//    reverse); no cross-layer composition happens.
PP_TEST(oracle, layer_separation) {
  {
    GraphBuilder builder("layer-logical");
    const NodeId s = builder.Node("s");
    const NodeId a = builder.Node("a");
    const NodeId d = builder.Node("d");
    builder.Link("s-a", s, a, 1, LinkState::kUp, PortState::kUp, PortState::kUp, PathLayer::kLogical);
    builder.Link("a-d", a, d, 1, LinkState::kUp, PortState::kUp, PortState::kUp, PathLayer::kLogical);
    const EndpointId es = builder.Endpoint("src", s);
    const EndpointId ed = builder.Endpoint("dst", d);
    const BuiltFabric fabric = builder.Build();
    PP_REQUIRE(fabric.ok);
    PlanningRequest physical = MakeRequest("layer-physical", fabric, PathLayer::kPhysical);
    const PlanningResult physical_result = RunPlan(fabric.snapshot, physical);
    PP_CHECK_MSG(physical_result.status == PlanStatus::kNoPath,
                 "physical request on a logical graph status " + StatusText(physical_result));
    PP_CHECK_MSG(physical_result.primary_failure == DiagnosticCode::kLayerMismatch,
                 "physical request on a logical graph primary " + StatusText(physical_result));
    PP_CHECK_MSG(physical_result.candidates.empty(), "a physical request returned logical hops");
    PP_CHECK_MSG(RejectionOccurrences(physical_result, DiagnosticCode::kLayerMismatch) == 2u,
                 "layer mismatch evidence counted " +
                     std::to_string(RejectionOccurrences(physical_result, DiagnosticCode::kLayerMismatch)));
    PlanningRequest logical = MakeRequest("layer-logical", fabric, PathLayer::kLogical);
    const PlanningResult logical_result = RunPlan(fabric.snapshot, logical);
    PP_CHECK_MSG(logical_result.status == PlanStatus::kPlanned, "logical status " + StatusText(logical_result));
    PP_REQUIRE(logical_result.candidates.size() == 1u);
    for (const PathHop& hop : logical_result.candidates[0].path.hops) {
      PP_CHECK_MSG(hop.layer == PathLayer::kLogical, "a logical request returned a non-logical hop");
    }
    const Oracle oracle = BuildOracle(*fabric.snapshot, logical);
    CheckCandidatesAgainstOracle(fabric, logical, logical_result, OracleExpectedPaths(oracle, logical, 1),
                                 "layer-logical");
  }
  {
    GraphBuilder builder("layer-mixed");
    const NodeId s = builder.Node("s");
    const NodeId physical_mid = builder.Node("physical_mid");
    const NodeId logical_mid = builder.Node("logical_mid");
    const NodeId d = builder.Node("d");
    const LinkId physical_first =
        builder.Link("p0", s, physical_mid, 1, LinkState::kUp, PortState::kUp, PortState::kUp, PathLayer::kPhysical);
    const LinkId physical_second = builder.Link("p1", physical_mid, d, 1, LinkState::kUp, PortState::kUp,
                                                PortState::kUp, PathLayer::kPhysical);
    const LinkId logical_first =
        builder.Link("l0", s, logical_mid, 1, LinkState::kUp, PortState::kUp, PortState::kUp, PathLayer::kLogical);
    const LinkId logical_second = builder.Link("l1", logical_mid, d, 1, LinkState::kUp, PortState::kUp,
                                               PortState::kUp, PathLayer::kLogical);
    const EndpointId es = builder.Endpoint("src", s);
    const EndpointId ed = builder.Endpoint("dst", d);
    const BuiltFabric fabric = builder.Build();
    PP_REQUIRE(fabric.ok);
    PlanningRequest physical = MakeRequest("layer-mixed-physical", fabric, PathLayer::kPhysical);
    const PlanningResult physical_result = RunPlan(fabric.snapshot, physical);
    PP_REQUIRE(physical_result.candidates.size() == 1u);
    PP_CHECK_MSG(physical_result.candidates[0].path.nodes ==
                     std::vector<NodeId>({s, physical_mid, d}),
                 "physical request did not stay on the physical layer");
    PlanningRequest logical = MakeRequest("layer-mixed-logical", fabric, PathLayer::kLogical);
    const PlanningResult logical_result = RunPlan(fabric.snapshot, logical);
    PP_REQUIRE(logical_result.candidates.size() == 1u);
    PP_CHECK_MSG(logical_result.candidates[0].path.nodes == std::vector<NodeId>({s, logical_mid, d}),
                 "logical request did not stay on the logical layer");
    for (const PathHop& hop : physical_result.candidates[0].path.hops) {
      PP_CHECK_MSG(hop.link != logical_first && hop.link != logical_second,
                   "a physical path used a logical link");
    }
    for (const PathHop& hop : logical_result.candidates[0].path.hops) {
      PP_CHECK_MSG(hop.link != physical_first && hop.link != physical_second,
                   "a logical path used a physical link");
    }
  }
  {
    FabricSnapshotBuilder builder(ResourceLimits{});
    SnapshotGenerations generations;
    generations.topology = TopologyGeneration(1);
    builder.SetGenerations(generations);
    const NodeId a = IdFromLabel<NodeId>("layer-contract/a");
    const NodeId b = IdFromLabel<NodeId>("layer-contract/b");
    const PortId a_port = IdFromLabel<PortId>("layer-contract/a/port");
    const PortId b_port = IdFromLabel<PortId>("layer-contract/b/port");
    NodeRecord node_a;
    node_a.id = a;
    node_a.ports.push_back(a_port);
    NodeRecord node_b;
    node_b.id = b;
    node_b.ports.push_back(b_port);
    PP_REQUIRE(builder.AddNode(node_a));
    PP_REQUIRE(builder.AddNode(node_b));
    EdgeRecord edge;
    edge.id = IdFromLabel<LinkId>("layer-contract/link");
    edge.from = a;
    edge.to = b;
    edge.from_port = a_port;
    edge.to_port = b_port;
    edge.layer = PathLayer::kLogical;
    edge.relationship = RelationshipType::kDirectLink;
    edge.static_cost = StaticCost(1);
    PP_CHECK_MSG(!builder.AddEdge(edge), "a logical edge with a DIRECT_LINK relationship was accepted");
    PP_CHECK_MSG(std::find(builder.Diagnostics().begin(), builder.Diagnostics().end(),
                           DiagnosticCode::kLayerMismatch) != builder.Diagnostics().end(),
                 "the layer/relationship mismatch was not reported as LAYER_MISMATCH");
    edge.layer = PathLayer::kPhysical;
    edge.relationship = RelationshipType::kDirectLink;
    PP_CHECK_MSG(builder.AddEdge(edge), "a physical edge with a DIRECT_LINK relationship was rejected");
  }
}

// ---------------------------------------------------------------------------
// 10. Randomized (seeded, deterministic) property test.
// ---------------------------------------------------------------------------
std::uint64_t NextRandom(std::uint64_t& state) {
  state = state * 6364136223846793005ull + 1442695040888963407ull;
  return state >> 11;
}

std::uint32_t RandomBelow(std::uint64_t& state, std::uint32_t bound) {
  return static_cast<std::uint32_t>(NextRandom(state) % bound);
}

struct RandomSetup {
  BuiltFabric fabric;
  PlanningRequest request;
  std::uint32_t wanted = 1;
};

RandomSetup BuildRandomSetup(std::uint64_t seed) {
  RandomSetup setup;
  std::uint64_t state = seed * 2654435761ull + 12345ull;
  const std::string name = "rand-" + std::to_string(seed);
  GraphBuilder builder(name);
  const std::uint32_t node_count = 3 + RandomBelow(state, 4);
  std::vector<NodeId> nodes;
  for (std::uint32_t i = 0; i < node_count; ++i) {
    nodes.push_back(builder.Node("n" + std::to_string(i)));
  }
  std::vector<LinkId> links;
  for (std::uint32_t i = 0; i < node_count; ++i) {
    for (std::uint32_t j = 0; j < node_count; ++j) {
      if (i == j || RandomBelow(state, 100) >= 35) {
        continue;
      }
      LinkState link_state = LinkState::kUp;
      const std::uint32_t link_roll = RandomBelow(state, 10);
      if (link_roll == 6) {
        link_state = LinkState::kDegraded;
      } else if (link_roll == 7) {
        link_state = LinkState::kDown;
      } else if (link_roll == 8) {
        link_state = LinkState::kUnknown;
      } else if (link_roll == 9) {
        link_state = LinkState::kFaulted;
      }
      PortState port_state = PortState::kUp;
      const std::uint32_t port_roll = RandomBelow(state, 12);
      if (port_roll == 9) {
        port_state = PortState::kDraining;
      } else if (port_roll == 10) {
        port_state = PortState::kMaintenance;
      } else if (port_roll == 11) {
        port_state = PortState::kAdminDisabled;
      }
      links.push_back(builder.Link("l" + std::to_string(i) + "_" + std::to_string(j), nodes[i], nodes[j],
                                   1 + RandomBelow(state, 3), link_state, port_state, port_state));
    }
  }
  const CapabilityId capability = IdFromLabel<CapabilityId>("cap/random");
  const bool use_capability = RandomBelow(state, 4) == 0;
  if (use_capability) {
    for (const NodeId& node : nodes) {
      builder.AddCapability(SubjectKey::ForNode(node), capability, RandomBelow(state, 3));
    }
  }
  std::vector<FailureDomainId> domains;
  std::vector<FailureDomainClass> domain_classes;
  const bool use_domains = !links.empty() && RandomBelow(state, 3) == 0;
  if (use_domains) {
    const std::uint32_t domain_count = 1 + RandomBelow(state, 2);
    for (std::uint32_t index = 0; index < domain_count; ++index) {
      const FailureDomainId domain = IdFromLabel<FailureDomainId>(name + "/domain/" + std::to_string(index));
      const FailureDomainClass risk_class =
          IdFromLabel<FailureDomainClass>(name + "/class/" + std::to_string(index));
      std::vector<SubjectKey> members;
      for (const LinkId& link : links) {
        if (RandomBelow(state, 2) == 0) {
          members.push_back(SubjectKey::ForLink(link));
        }
      }
      if (members.empty()) {
        members.push_back(SubjectKey::ForLink(links.front()));
      }
      builder.AddDomain(domain, risk_class, members);
      domains.push_back(domain);
      domain_classes.push_back(risk_class);
    }
    builder.SetMembershipComplete(RandomBelow(state, 2) == 0);
  }
  const bool reverse = RandomBelow(state, 4) == 0;
  builder.Endpoint("src", nodes[reverse ? node_count - 1u : 0u]);
  builder.Endpoint("dst", nodes[reverse ? 0u : node_count - 1u]);
  setup.fabric = builder.Build();
  if (!setup.fabric.ok) {
    return setup;
  }

  PlanningRequest request = MakeRequest(name, setup.fabric);
  setup.wanted = 1 + RandomBelow(state, 4);
  request.max_candidates = setup.wanted;
  request.policy.cost_model.hop_cost = CostValue(1 + RandomBelow(state, 3));
  request.policy.cost_model.degraded_penalty = CostValue(RandomBelow(state, 4));
  if (RandomBelow(state, 3) == 0) {
    std::vector<NodeId> scope;
    scope.push_back(nodes[RandomBelow(state, node_count)]);
    if (RandomBelow(state, 4) == 0) {
      scope.push_back(nodes[RandomBelow(state, node_count)]);
    }
    std::sort(scope.begin(), scope.end());
    scope.erase(std::unique(scope.begin(), scope.end()), scope.end());
    request.policy.locality_scope = scope;
    request.policy.cost_model.locality_penalty = CostValue(1 + RandomBelow(state, 4));
  }
  request.policy.allow_degraded_links = RandomBelow(state, 2) == 0;
  request.policy.allow_draining_ports = RandomBelow(state, 2) == 0;
  request.policy.allow_maintenance_ports = RandomBelow(state, 2) == 0;
  request.policy.require_operational_proof = RandomBelow(state, 3) != 0;
  request.constraints.fail_closed_on_unknown_domains = RandomBelow(state, 2) == 0;
  if (RandomBelow(state, 4) == 0) {
    request.constraints.max_hops = HopCount(1 + RandomBelow(state, 4));
  }
  if (RandomBelow(state, 5) == 0) {
    request.constraints.forbidden_nodes.push_back(nodes[RandomBelow(state, node_count)]);
  }
  if (RandomBelow(state, 5) == 0 && !links.empty()) {
    request.constraints.forbidden_links.push_back(
        links[RandomBelow(state, static_cast<std::uint32_t>(links.size()))]);
  }
  if (use_domains) {
    const std::uint32_t domain_roll = RandomBelow(state, 3);
    if (domain_roll == 0) {
      request.constraints.forbidden_failure_domains.push_back(
          domains[RandomBelow(state, static_cast<std::uint32_t>(domains.size()))]);
    } else if (domain_roll == 1) {
      request.constraints.forbidden_failure_domain_classes.push_back(
          domain_classes[RandomBelow(state, static_cast<std::uint32_t>(domain_classes.size()))]);
    }
  }
  if (use_capability) {
    CapabilityRequirement requirement;
    requirement.capability = capability;
    requirement.scope =
        RandomBelow(state, 2) == 0 ? CapabilityScope::kEveryNode : CapabilityScope::kEveryLink;
    requirement.comparator = CapabilityComparator::kAtLeast;
    requirement.value = CapabilityValue(RandomBelow(state, 3));
    request.constraints.required_capabilities.push_back(requirement);
  }
  setup.request = request;
  return setup;
}

PP_TEST(oracle, randomized_candidate_properties) {
  std::uint32_t graphs = 0;
  std::uint32_t planned_graphs = 0;
  std::uint32_t empty_graphs = 0;
  std::uint32_t candidates_seen = 0;
  for (std::uint64_t seed = 1; seed <= 200; ++seed) {
    const RandomSetup setup = BuildRandomSetup(seed);
    PP_REQUIRE(setup.fabric.ok);
    const std::string context = "random seed " + std::to_string(seed);
    const PlanningResult result = RunPlan(setup.fabric.snapshot, setup.request);
    const Oracle oracle = BuildOracle(*setup.fabric.snapshot, setup.request);
    PP_REQUIRE(oracle.usable);
    const std::vector<OraclePath> expected = OracleExpectedPaths(oracle, setup.request, setup.wanted);
    CheckCandidatesAgainstOracle(setup.fabric, setup.request, result, expected, context);
    CheckCandidateInvariants(setup.fabric, setup.request, oracle, result, context);
    if (expected.empty()) {
      empty_graphs += 1;
      PP_CHECK_MSG(result.candidates.empty(), context + " reported candidates without an oracle path");
    } else {
      planned_graphs += 1;
      const PlanStatus expected_status = setup.request.policy.require_operational_proof
                                             ? PlanStatus::kPlanned
                                             : PlanStatus::kRevalidationRequired;
      PP_CHECK_MSG(result.status == expected_status, context + " status " + StatusText(result));
      for (const Candidate& candidate : result.candidates) {
        PP_CHECK_MSG(candidate.currentness == (setup.request.policy.require_operational_proof
                                                   ? Currentness::kCurrent
                                                   : Currentness::kRevalidationRequired),
                     context + " candidate currentness " + std::string(ToString(candidate.currentness)));
      }
    }
    candidates_seen += static_cast<std::uint32_t>(result.candidates.size());
    graphs += 1;
  }
  PP_CHECK_MSG(graphs == 200u, "random graphs " + std::to_string(graphs));
  PP_CHECK_MSG(planned_graphs > 0u, "no random graph produced a path");
  PP_CHECK_MSG(empty_graphs > 0u, "every random graph produced a path");
  PP_CHECK_MSG(candidates_seen >= planned_graphs, "candidates observed " + std::to_string(candidates_seen));
}

}  // namespace


// Independent downstream consumer of the installed PathPlanner package.
//
// The program builds a tiny synthetic topology through the public API, submits a
// source/destination planning request, and verifies the exact ordered hops of the
// returned candidate path. It fails loudly if any expectation is not met.

#include <cstdio>
#include <string>
#include <vector>

#include <pathplanner/pathplanner.hpp>

using namespace summon::pathplanner;

namespace {

NodeId Node(const std::string& label) { return NodeId::FromDigest(Sha256::Hash("consumer-node:" + label)); }
PortId Port(const std::string& label) { return PortId::FromDigest(Sha256::Hash("consumer-port:" + label)); }
LinkId Link(const std::string& label) { return LinkId::FromDigest(Sha256::Hash("consumer-link:" + label)); }

int Fail(const char* message) {
  std::fprintf(stderr, "consumer check failed: %s\n", message);
  return 1;
}

}  // namespace

int main() {
  const NodeId a = Node("a");
  const NodeId b = Node("b");
  const NodeId c = Node("c");
  const NodeId d = Node("d");

  FabricSnapshotBuilder builder;
  SnapshotGenerations generations;
  generations.topology = TopologyGeneration(1);
  generations.link_state = LinkStateGeneration(1);
  generations.ports = PortGeneration(1);
  generations.capabilities = CapabilityGeneration(1);
  generations.failure_domains = FailureDomainGeneration(1);
  generations.epoch = FabricEpoch(7);
  builder.SetGenerations(generations);
  builder.SetSource(EvidenceSource::kSynthetic);

  const std::vector<NodeId> nodes = {a, b, c, d};
  for (std::size_t index = 0; index < nodes.size(); ++index) {
    NodeRecord node;
    node.id = nodes[index];
    node.entity_generation = EntityGeneration(1);
    node.structural_generation = TopologyGeneration(1);
    node.ports.push_back(Port(std::to_string(index) + ":0"));
    node.ports.push_back(Port(std::to_string(index) + ":1"));
    if (!builder.AddNode(node)) {
      return Fail("node rejected");
    }
  }

  struct LinkSpec {
    const char* label;
    std::size_t from;
    std::size_t to;
    std::uint32_t cost;
  };
  // Diamond: a-b-d (cost 1 + 1) and a-c-d (cost 5 + 5). The first path must win.
  const LinkSpec links[] = {{"ab", 0, 1, 1}, {"bd", 1, 3, 1}, {"ac", 0, 2, 5}, {"cd", 2, 3, 5}};
  std::vector<LinkStateRecord> link_states;
  std::vector<PortStateRecord> port_states;
  for (const LinkSpec& spec : links) {
    EdgeRecord edge;
    edge.id = Link(spec.label);
    edge.from = nodes[spec.from];
    edge.to = nodes[spec.to];
    edge.from_port = Port(std::to_string(spec.from) + ":1");
    edge.to_port = Port(std::to_string(spec.to) + ":0");
    edge.layer = PathLayer::kPhysical;
    edge.relationship = RelationshipType::kDirectLink;
    edge.static_cost = StaticCost(spec.cost);
    edge.entity_generation = EntityGeneration(1);
    edge.structural_generation = TopologyGeneration(1);
    if (!builder.AddEdge(edge)) {
      return Fail("edge rejected");
    }
    link_states.push_back(LinkStateRecord{edge.id, LinkState::kUp});
    port_states.push_back(PortStateRecord{edge.from_port, PortState::kUp});
    port_states.push_back(PortStateRecord{edge.to_port, PortState::kUp});
  }
  builder.SetLinkStates(link_states);
  builder.SetPortStates(port_states);

  EndpointRecord source_endpoint;
  source_endpoint.id = EndpointId::FromDigest(Sha256::Hash("consumer-endpoint:a"));
  source_endpoint.endpoint_class = EndpointClass::kEndpoint;
  source_endpoint.node = a;
  source_endpoint.port = Port("0:0");
  source_endpoint.entity_generation = EntityGeneration(1);
  EndpointRecord destination_endpoint;
  destination_endpoint.id = EndpointId::FromDigest(Sha256::Hash("consumer-endpoint:d"));
  destination_endpoint.endpoint_class = EndpointClass::kEndpoint;
  destination_endpoint.node = d;
  destination_endpoint.port = Port("3:1");
  destination_endpoint.entity_generation = EntityGeneration(1);
  builder.AddEndpoint(source_endpoint);
  builder.AddEndpoint(destination_endpoint);

  SnapshotBuildResult built = builder.Build();
  if (!built.ok()) {
    return Fail("snapshot build failed");
  }

  PlannerConfig config;
  config.initial_snapshot = built.snapshot;
  PlannerRuntime runtime(config);

  PlanningRequest request;
  request.id = PlanningRequestId::FromDigest(Sha256::Hash("consumer-request"));
  request.source.id = source_endpoint.id;
  request.source.endpoint_class = EndpointClass::kEndpoint;
  request.source.generation = EntityGeneration(1);
  request.destination.id = destination_endpoint.id;
  request.destination.endpoint_class = EndpointClass::kEndpoint;
  request.destination.generation = EntityGeneration(1);
  request.constraints.id = ConstraintSetId::FromDigest(Sha256::Hash("consumer-constraints"));
  request.constraints.generation = ConstraintGeneration(1);
  request.max_candidates = 1;

  const PlanningResult result = runtime.Plan(request);
  if (result.status != PlanStatus::kPlanned) {
    std::fprintf(stderr, "unexpected status: %s\n", std::string(ToString(result.status)).c_str());
    return 1;
  }
  if (result.candidates.size() != 1) {
    return Fail("expected exactly one candidate");
  }
  const CandidatePath& path = result.candidates.front().path;
  const std::vector<NodeId> expected = {a, b, d};
  if (path.nodes != expected) {
    return Fail("returned path does not have the expected ordered hops");
  }
  if (path.hops.size() != 2 || result.candidates.front().cost.total.Value() != 4) {
    return Fail("unexpected hop count or total cost");
  }
  std::printf("consumer_ok version=%s status=%s hops=%zu total_cost=%s\n", std::string(kProductVersion).c_str(),
              std::string(ToString(result.status)).c_str(), path.hops.size(),
              result.candidates.front().cost.total.ToString().c_str());
  std::printf("consumer_path %s\n", path.Render().c_str());
  return 0;
}

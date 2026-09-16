// Path Planner command line interface.
//
// Every command prints deterministic, line-oriented output built from the library
// renderers: no timings, no locale-dependent formatting, no unordered iteration.
// The CLI is a presentation and operations surface only; it performs no planning
// semantics of its own.

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "pathplanner/dist.hpp"
#include "pathplanner/explain.hpp"
#include "pathplanner/pathplanner.hpp"
#include "pathplanner/sources.hpp"
#include "pathplanner/store.hpp"

namespace {

using namespace summon::pathplanner;

FixedId<PlanningRequestIdTag, 16> IdFromLabel(const std::string& label) {
  return PlanningRequestId::FromDigest(Sha256::Hash(label));
}

NodeId NodeFromLabel(const std::string& label) { return NodeId::FromDigest(Sha256::Hash(label)); }
LinkId LinkFromLabel(const std::string& label) { return LinkId::FromDigest(Sha256::Hash(label)); }
PortId PortFromLabel(const std::string& label) { return PortId::FromDigest(Sha256::Hash(label)); }
EndpointId EndpointFromLabel(const std::string& label) { return EndpointId::FromDigest(Sha256::Hash(label)); }
CapabilityId CapabilityFromLabel(const std::string& label) {
  return CapabilityId::FromDigest(Sha256::Hash(label));
}
FailureDomainId DomainFromLabel(const std::string& label) {
  return FailureDomainId::FromDigest(Sha256::Hash(label));
}

// ---------------------------------------------------------------------------
// Argument parsing.
// ---------------------------------------------------------------------------
struct Args {
  std::vector<std::pair<std::string, std::string>> entries;

  bool Has(const std::string& name) const {
    for (const auto& entry : entries) {
      if (entry.first == name) {
        return true;
      }
    }
    return false;
  }

  std::optional<std::string> Get(const std::string& name) const {
    for (const auto& entry : entries) {
      if (entry.first == name) {
        return entry.second;
      }
    }
    return std::nullopt;
  }

  std::vector<std::string> All(const std::string& name) const {
    std::vector<std::string> values;
    for (const auto& entry : entries) {
      if (entry.first == name) {
        values.push_back(entry.second);
      }
    }
    return values;
  }

  std::string GetOr(const std::string& name, const std::string& fallback) const {
    const std::optional<std::string> value = Get(name);
    return value.has_value() ? *value : fallback;
  }

  std::uint64_t GetU64(const std::string& name, std::uint64_t fallback) const {
    const std::optional<std::string> value = Get(name);
    if (!value.has_value() || value->empty()) {
      return fallback;
    }
    std::uint64_t parsed = 0;
    for (const char c : *value) {
      if (c < '0' || c > '9') {
        return fallback;
      }
      parsed = parsed * 10 + static_cast<std::uint64_t>(c - '0');
    }
    return parsed;
  }

  std::uint32_t GetU32(const std::string& name, std::uint32_t fallback) const {
    const std::uint64_t value = GetU64(name, fallback);
    return value > 0xFFFFFFFFull ? fallback : static_cast<std::uint32_t>(value);
  }
};

Args ParseArgs(int argc, char** argv, int start) {
  Args args;
  for (int index = start; index < argc; ++index) {
    const std::string token = argv[index];
    if (token.size() > 2 && token[0] == '-' && token[1] == '-') {
      const std::string name = token.substr(2);
      std::string value;
      if (index + 1 < argc) {
        const std::string next = argv[index + 1];
        if (!(next.size() > 2 && next[0] == '-' && next[1] == '-')) {
          value = next;
          index += 1;
        }
      }
      args.entries.emplace_back(name, value);
    }
  }
  return args;
}

void Usage() {
  std::printf("%s\n", VersionBanner().c_str());
  std::printf("usage: pathplanner <command> [--option value]...\n");
  std::printf("commands:\n");
  std::printf("  version                 print versions (product, rules, encodings, wire, store)\n");
  std::printf("  snapshot                build and describe a snapshot (--source synthetic|local)\n");
  std::printf("  plan                    compute and render a plan (--max-candidates --max-hops ...)\n");
  std::printf("  replan                  plan, change state, replan and render the outcome\n");
  std::printf("  explain                 plan and render rejections and explanations only\n");
  std::printf("  compare                 plan with two candidates and render the rank explanation\n");
  std::printf("  currentness             plan, invalidate and render the currentness report\n");
  std::printf("  inspect-store           validate and describe a persisted planning store\n");
  std::printf("  coordinator             run a distributed coordinator (--port --epoch --store)\n");
  std::printf("  worker                  run a distributed worker (--coordinator host:port)\n");
}

// ---------------------------------------------------------------------------
// Deterministic demonstration fabric.
//
// The CLI needs explicit control over link state (to show replanning and stale-plan
// detection), so it builds a deterministic ladder with addressable links instead of
// relying on percentages. All identities are derived from label strings.
// ---------------------------------------------------------------------------
struct DemoFabric {
  std::shared_ptr<const FabricSnapshot> snapshot;
  std::vector<LinkId> links;  // index addressable, sorted
  EndpointId source;
  EndpointId destination;
  NodeId source_node;
  NodeId destination_node;
  EntityGeneration source_generation;
  EntityGeneration destination_generation;
  CapabilityId speed_capability;
  FailureDomainId primary_domain;
  FailureDomainId secondary_domain;
  std::vector<NodeId> nodes;
};

struct DemoOptions {
  std::uint32_t nodes = 6;
  FabricEpoch epoch{1};
  TopologyGeneration topology{1};
  LinkStateGeneration link_state{1};
  PortGeneration ports{1};
  CapabilityGeneration capabilities{1};
  FailureDomainGeneration failure_domains{1};
  PolicyGeneration policy{1};
  ConstraintGeneration constraints{1};
  std::vector<std::uint32_t> down_links;
  std::vector<std::uint32_t> degraded_links;
  ResourceLimits limits;
};

std::optional<DemoFabric> BuildDemoFabric(const DemoOptions& options, std::string& error) {
  if (options.nodes < 2) {
    error = "a demonstration fabric needs at least two nodes";
    return std::nullopt;
  }
  DemoFabric demo;
  demo.speed_capability = CapabilityFromLabel("demo.capability.speed");
  demo.primary_domain = DomainFromLabel("demo.domain.primary");
  demo.secondary_domain = DomainFromLabel("demo.domain.secondary");

  FabricSnapshotBuilder builder(options.limits);
  SnapshotGenerations generations;
  generations.topology = options.topology;
  generations.link_state = options.link_state;
  generations.ports = options.ports;
  generations.capabilities = options.capabilities;
  generations.failure_domains = options.failure_domains;
  generations.policy = options.policy;
  generations.constraints = options.constraints;
  generations.epoch = options.epoch;
  builder.SetGenerations(generations);
  builder.SetSource(EvidenceSource::kSynthetic);

  for (std::uint32_t index = 0; index < options.nodes; ++index) {
    NodeRecord node;
    node.id = NodeFromLabel("demo-node:" + std::to_string(index));
    node.attachment = SwitchId::FromDigest(Sha256::Hash("demo-switch:" + std::to_string(index / 2)));
    node.entity_generation = EntityGeneration(1);
    node.structural_generation = options.topology;
    node.ports.push_back(PortFromLabel("demo-port:" + std::to_string(index) + ":0"));
    node.ports.push_back(PortFromLabel("demo-port:" + std::to_string(index) + ":1"));
    demo.nodes.push_back(node.id);
    if (!builder.AddNode(node)) {
      error = "node rejected by the snapshot builder";
      return std::nullopt;
    }
  }

  struct PendingLink {
    LinkId id;
    std::uint32_t from = 0;
    std::uint32_t to = 0;
  };
  std::vector<PendingLink> pending;
  auto add_link = [&pending, &options](std::uint32_t from, std::uint32_t to, const std::string& label) {
    PendingLink link;
    link.id = LinkFromLabel(label);
    link.from = from;
    link.to = to;
    pending.push_back(link);
  };
  for (std::uint32_t index = 0; index + 1 < options.nodes; ++index) {
    add_link(index, index + 1, "demo-link:" + std::to_string(index) + "-" + std::to_string(index + 1));
  }
  for (std::uint32_t index = 0; index + 2 < options.nodes; ++index) {
    add_link(index, index + 2, "demo-chord:" + std::to_string(index) + "-" + std::to_string(index + 2));
  }
  std::sort(pending.begin(), pending.end(),
            [](const PendingLink& lhs, const PendingLink& rhs) { return lhs.id < rhs.id; });

  std::vector<LinkStateRecord> link_states;
  std::vector<PortStateRecord> port_states;
  std::vector<CapabilityBinding> capabilities;
  for (std::size_t index = 0; index < pending.size(); ++index) {
    const PendingLink& link = pending[index];
    EdgeRecord edge;
    edge.id = link.id;
    edge.from = NodeFromLabel("demo-node:" + std::to_string(link.from));
    edge.to = NodeFromLabel("demo-node:" + std::to_string(link.to));
    edge.from_port = PortFromLabel("demo-port:" + std::to_string(link.from) + ":1");
    edge.to_port = PortFromLabel("demo-port:" + std::to_string(link.to) + ":0");
    edge.layer = PathLayer::kPhysical;
    edge.relationship = RelationshipType::kDirectLink;
    edge.static_cost = StaticCost(1 + static_cast<std::uint32_t>(index % 3));
    edge.entity_generation = EntityGeneration(1);
    edge.structural_generation = options.topology;
    if (!builder.AddEdge(edge)) {
      error = "edge rejected by the snapshot builder";
      return std::nullopt;
    }
    demo.links.push_back(edge.id);

    LinkState state = LinkState::kUp;
    if (std::find(options.down_links.begin(), options.down_links.end(), static_cast<std::uint32_t>(index)) !=
        options.down_links.end()) {
      state = LinkState::kDown;
    } else if (std::find(options.degraded_links.begin(), options.degraded_links.end(),
                         static_cast<std::uint32_t>(index)) != options.degraded_links.end()) {
      state = LinkState::kDegraded;
    }
    link_states.push_back(LinkStateRecord{edge.id, state});
    for (const PortId& port : {edge.from_port, edge.to_port}) {
      port_states.push_back(PortStateRecord{port, PortState::kUp});
    }
    capabilities.push_back(
        CapabilityBinding{SubjectKey::ForLink(edge.id), demo.speed_capability,
                          CapabilityValue(index % 2 == 0 ? 100u : 10u)});
  }
  for (std::uint32_t index = 0; index < options.nodes; ++index) {
    const NodeId id = NodeFromLabel("demo-node:" + std::to_string(index));
    capabilities.push_back(
        CapabilityBinding{SubjectKey::ForNode(id), demo.speed_capability, CapabilityValue(100)});
    for (std::uint32_t port_index = 0; port_index < 2; ++port_index) {
      capabilities.push_back(CapabilityBinding{
          SubjectKey::ForPort(PortFromLabel("demo-port:" + std::to_string(index) + ":" + std::to_string(port_index))),
          demo.speed_capability, CapabilityValue(100)});
    }
  }
  for (const PortStateRecord& record : port_states) {
    capabilities.push_back(CapabilityBinding{SubjectKey::ForPort(record.port), demo.speed_capability,
                                             CapabilityValue(100)});
  }
  builder.SetLinkStates(link_states);
  builder.SetPortStates(port_states);
  builder.SetCapabilities(capabilities);

  std::vector<FailureDomainRecord> domains;
  FailureDomainRecord primary;
  primary.domain = demo.primary_domain;
  primary.risk_class = FixedId<FailureDomainClassTag, 8>::FromDigest(Sha256::Hash("demo.risk.rack"));
  FailureDomainRecord secondary;
  secondary.domain = demo.secondary_domain;
  secondary.risk_class = FixedId<FailureDomainClassTag, 8>::FromDigest(Sha256::Hash("demo.risk.site"));
  for (std::size_t index = 0; index < demo.nodes.size(); ++index) {
    const SubjectKey subject = SubjectKey::ForNode(demo.nodes[index]);
    if (index % 2 == 0) {
      primary.members.push_back(subject);
    } else {
      secondary.members.push_back(subject);
    }
  }
  for (std::size_t index = 0; index < demo.links.size(); ++index) {
    const SubjectKey subject = SubjectKey::ForLink(demo.links[index]);
    if (index % 2 == 0) {
      primary.members.push_back(subject);
    } else {
      secondary.members.push_back(subject);
    }
  }
  for (const PortStateRecord& record : port_states) {
    const SubjectKey subject = SubjectKey::ForPort(record.port);
    if (record.port < PortFromLabel("demo-port:0:0") || primary.members.size() <= secondary.members.size()) {
      primary.members.push_back(subject);
    } else {
      secondary.members.push_back(subject);
    }
  }
  // Failure-domain membership is deliberately omitted above a size where the published member
  // count would breach max_members_per_failure_domain; the ceiling is a real limit, so the
  // demonstration fabric stops publishing membership instead of pretending it was accepted.
  constexpr std::size_t kMaxDemoDomainMembers = 60000;
  if (primary.members.size() + secondary.members.size() <= kMaxDemoDomainMembers) {
    domains.push_back(std::move(primary));
    domains.push_back(std::move(secondary));
    builder.SetFailureDomains(std::move(domains), true);
  } else {
    builder.SetFailureDomains(std::vector<FailureDomainRecord>{}, false);
  }

  demo.source_node = demo.nodes.front();
  demo.destination_node = demo.nodes.back();
  demo.source_generation = EntityGeneration(1);
  demo.destination_generation = EntityGeneration(1);
  EndpointRecord source_endpoint;
  source_endpoint.id = EndpointFromLabel("demo-endpoint:source");
  source_endpoint.endpoint_class = EndpointClass::kEndpoint;
  source_endpoint.node = demo.source_node;
  source_endpoint.port = PortFromLabel("demo-port:0:0");
  source_endpoint.entity_generation = demo.source_generation;
  EndpointRecord destination_endpoint;
  destination_endpoint.id = EndpointFromLabel("demo-endpoint:destination");
  destination_endpoint.endpoint_class = EndpointClass::kEndpoint;
  destination_endpoint.node = demo.destination_node;
  destination_endpoint.port = PortFromLabel("demo-port:" + std::to_string(options.nodes - 1) + ":1");
  destination_endpoint.entity_generation = demo.destination_generation;
  builder.AddEndpoint(source_endpoint);
  builder.AddEndpoint(destination_endpoint);
  demo.source = source_endpoint.id;
  demo.destination = destination_endpoint.id;

  SnapshotBuildResult built = builder.Build();
  if (!built.ok()) {
    error = "snapshot build failed: " + std::string(ToString(*built.error)) + " " + built.detail;
    return std::nullopt;
  }
  demo.snapshot = built.snapshot;
  return demo;
}

DemoOptions DemoOptionsFromArgs(const Args& args) {
  DemoOptions options;
  options.nodes = args.GetU32("nodes", 6);
  options.epoch = FabricEpoch(args.GetU64("epoch", 1));
  options.topology = TopologyGeneration(args.GetU64("topology", 1));
  options.link_state = LinkStateGeneration(args.GetU64("link-state", 1));
  for (const std::string& value : args.All("down-link")) {
    options.down_links.push_back(static_cast<std::uint32_t>(std::strtoul(value.c_str(), nullptr, 10)));
  }
  for (const std::string& value : args.All("degraded-link")) {
    options.degraded_links.push_back(static_cast<std::uint32_t>(std::strtoul(value.c_str(), nullptr, 10)));
  }
  return options;
}

// ---------------------------------------------------------------------------
// Request construction from CLI options.
// ---------------------------------------------------------------------------
PlanningRequest BuildRequest(const Args& args, const DemoFabric& fabric) {
  PlanningRequest request;
  request.id = IdFromLabel("demo-request:" + args.GetOr("request", "default"));
  request.source.id = fabric.source;
  request.source.endpoint_class = EndpointClass::kEndpoint;
  request.source.generation = fabric.source_generation;
  request.destination.id = fabric.destination;
  request.destination.endpoint_class = EndpointClass::kEndpoint;
  request.destination.generation = fabric.destination_generation;
  request.max_candidates = args.GetU32("max-candidates", 1);
  request.constraints.id = ConstraintSetId::FromDigest(Sha256::Hash("demo-constraints:" + args.GetOr("request", "default")));
  request.constraints.generation = ConstraintGeneration(args.GetU64("constraint-generation", 1));
  request.constraints.layer = PathLayer::kPhysical;
  if (args.Has("max-hops")) {
    request.constraints.max_hops = HopCount(args.GetU32("max-hops", 1));
  }
  for (const std::string& value : args.All("forbid-link")) {
    request.constraints.forbidden_links.push_back(LinkId::FromDigest(Sha256::Hash(value)));
  }
  for (const std::string& value : args.All("forbid-node")) {
    request.constraints.forbidden_nodes.push_back(NodeId::FromDigest(Sha256::Hash(value)));
  }
  for (const std::string& value : args.All("forbid-port")) {
    request.constraints.forbidden_ports.push_back(PortId::FromDigest(Sha256::Hash(value)));
  }
  for (const std::string& value : args.All("avoid-domain")) {
    request.constraints.forbidden_failure_domains.push_back(FailureDomainId::FromDigest(Sha256::Hash(value)));
  }
  for (const std::string& value : args.All("avoid-domain-class")) {
    request.constraints.forbidden_failure_domain_classes.push_back(
        FixedId<FailureDomainClassTag, 8>::FromDigest(Sha256::Hash(value)));
  }
  for (const std::string& value : args.All("require-capability")) {
    // Accepted form: <label>=<value>[:SCOPE[:COMPARATOR]]
    const std::size_t equals = value.find('=');
    if (equals == std::string::npos) {
      continue;
    }
    CapabilityRequirement requirement;
    requirement.capability = CapabilityFromLabel(value.substr(0, equals));
    std::string remainder = value.substr(equals + 1);
    std::string scope_text;
    std::string comparator_text;
    const std::size_t first_colon = remainder.find(':');
    if (first_colon != std::string::npos) {
      const std::size_t second_colon = remainder.find(':', first_colon + 1);
      scope_text = remainder.substr(first_colon + 1, second_colon == std::string::npos
                                                         ? std::string::npos
                                                         : second_colon - first_colon - 1);
      if (second_colon != std::string::npos) {
        comparator_text = remainder.substr(second_colon + 1);
      }
      remainder = remainder.substr(0, first_colon);
    }
    requirement.value = CapabilityValue(std::strtoull(remainder.c_str(), nullptr, 10));
    if (!scope_text.empty()) {
      const std::optional<CapabilityScope> scope = ParseCapabilityScope(scope_text);
      if (scope.has_value()) {
        requirement.scope = *scope;
      }
    }
    if (!comparator_text.empty()) {
      const std::optional<CapabilityComparator> comparator = ParseCapabilityComparator(comparator_text);
      if (comparator.has_value()) {
        requirement.comparator = *comparator;
      }
    }
    request.constraints.required_capabilities.push_back(requirement);
  }
  for (const std::string& value : args.All("transit")) {
    TransitStage stage;
    stage.kind = TransitKind::kExact;
    stage.alternatives.push_back(NodeId::FromDigest(Sha256::Hash(value)));
    request.constraints.required_transit.push_back(std::move(stage));
  }
  for (const std::string& value : args.All("transit-index")) {
    const std::uint32_t index = static_cast<std::uint32_t>(std::strtoul(value.c_str(), nullptr, 10));
    if (index < fabric.nodes.size()) {
      TransitStage stage;
      stage.kind = TransitKind::kExact;
      stage.alternatives.push_back(fabric.nodes[index]);
      request.constraints.required_transit.push_back(std::move(stage));
    }
  }

  request.policy.generation = PolicyGeneration(args.GetU64("policy-generation", 1));
  request.policy.cost_model.hop_cost = CostValue(args.GetU64("hop-cost", 1));
  request.policy.allow_degraded_links = args.Has("allow-degraded");
  request.policy.cost_model.degraded_penalty = CostValue(args.GetU64("degraded-penalty", 0));
  request.policy.allow_draining_ports = args.Has("allow-draining");
  request.policy.allow_maintenance_ports = args.Has("allow-maintenance");
  if (args.Has("waive-operational-proof")) {
    request.policy.require_operational_proof = false;
  }
  if (args.Has("deny-zero-hop")) {
    request.policy.allow_zero_hop_self_path = false;
  }
  request.authority.publisher = PublisherId::FromDigest(Sha256::Hash("pathplanner-cli-publisher"));
  request.authority.worker_boot = WorkerBootId::FromDigest(Sha256::Hash("pathplanner-cli-client"));
  request.authority.attempt =
      MutationAttemptId::FromDigest(Sha256::Hash("pathplanner-cli-attempt:" + args.GetOr("request", "default")));
  request.authority.coordinator_epoch = CoordinatorEpoch(args.GetU64("epoch", 1));
  request.authority.scope_mask = ToMask(AuthorityScope::kSubmitPlanRequest);
  if (args.Has("enforce-scope")) {
    request.authority.enforce_scope = true;
    request.authority.scope_mask = args.Has("grant-scope") ? ToMask(AuthorityScope::kSubmitPlanRequest) : 0u;
  }
  if (args.Has("diagnostic")) {
    request.mode = PlanningMode::kDiagnosticNonCurrent;
  }
  if (args.Has("index-source")) {
    const std::uint32_t index = args.GetU32("index-source", 0);
    if (index < fabric.nodes.size()) {
      request.source.id = EndpointFromLabel("demo-index-endpoint:" + std::to_string(index));
      request.source.generation = EntityGeneration(1);
    }
  }
  return request;
}

PlannerConfig MakePlannerConfig(const DemoFabric& fabric) {
  PlannerConfig config;
  config.initial_snapshot = fabric.snapshot;
  return config;
}

// ---------------------------------------------------------------------------
// Commands.
// ---------------------------------------------------------------------------
std::uint64_t g_plan_exit_after = 0;

int CommandVersion() {
  std::printf("%s\n", VersionBanner().c_str());
  std::printf("product_version %s\n", std::string(kProductVersion).c_str());
  std::printf("planning_rule_version %u\n", kPlanningRuleVersion);
  std::printf("path_encoding_version %u\n", kPathEncodingVersion);
  std::printf("plan_digest_scheme_version %u\n", kPlanDigestSchemeVersion);
  std::printf("wire_protocol_version %u\n", kWireProtocolVersion);
  std::printf("persisted_format_version %u\n", kPersistedFormatVersion);
  return 0;
}

int CommandSnapshot(const Args& args) {
  std::string error;
  if (args.GetOr("source", "synthetic") == "local") {
    const std::optional<SyntheticFabric> fabric = MakeLocalHostFabric(ResourceLimits{}, error);
    if (!fabric.has_value()) {
      std::printf("status UNSUPPORTED\n");
      std::printf("detail \"%s\"\n", error.c_str());
      return 1;
    }
    std::fputs(RenderSnapshotSummary(*fabric->snapshot).c_str(), stdout);
    return 0;
  }
  DemoOptions options = DemoOptionsFromArgs(args);
  const std::optional<DemoFabric> fabric = BuildDemoFabric(options, error);
  if (!fabric.has_value()) {
    std::printf("status MALFORMED_REQUEST\n");
    std::printf("detail \"%s\"\n", error.c_str());
    return 1;
  }
  std::fputs(RenderSnapshotSummary(*fabric->snapshot).c_str(), stdout);
  std::printf("snapshot links=%zu\n", fabric->links.size());
  return 0;
}

int CommandPlan(const Args& args) {
  std::string error;
  DemoOptions options = DemoOptionsFromArgs(args);
  const std::optional<DemoFabric> fabric = BuildDemoFabric(options, error);
  if (!fabric.has_value()) {
    std::printf("status MALFORMED_REQUEST\n");
    std::printf("detail \"%s\"\n", error.c_str());
    return 1;
  }
  const PlanningRequest request = BuildRequest(args, *fabric);
  // With --endpoint the request is submitted through the distributed client instead of a
  // local runtime, which is what makes the CLI usable against a running coordinator.
  if (args.Has("endpoint")) {
    DistributedPlannerClient client(args.GetOr("endpoint", ""), ResourceLimits{});
    if (!client.Connect(error)) {
      std::printf("status UNAVAILABLE\n");
      std::printf("detail \"%s\"\n", error.c_str());
      return 1;
    }
    PlanningResult remote;
    PlanStatus status = PlanStatus::kUnsupported;
    const bool submitted = client.Submit(request, remote, status, error);
    if (!submitted) {
      std::printf("status %s\n", std::string(ToString(status)).c_str());
      if (!error.empty()) {
        std::printf("detail \"%s\"\n", error.c_str());
      }
      return 1;
    }
    std::fputs(RenderResult(remote, args.Has("verbose")).c_str(), stdout);
    return CarriesCandidates(remote.status) ? 0 : 1;
  }
  PlannerRuntime runtime(MakePlannerConfig(*fabric));
  const PlanningResult result = runtime.Plan(request);
  std::fputs(RenderResult(result, args.Has("verbose")).c_str(), stdout);
  if (args.Has("stats")) {
    std::fputs(RenderStatistics(runtime.Stats()).c_str(), stdout);
  }
  return CarriesCandidates(result.status) ? 0 : 1;
}

int CommandReplan(const Args& args) {
  std::string error;
  DemoOptions options = DemoOptionsFromArgs(args);
  options.down_links.clear();
  const std::optional<DemoFabric> first = BuildDemoFabric(options, error);
  if (!first.has_value()) {
    std::printf("status MALFORMED_REQUEST\n");
    return 1;
  }
  PlannerRuntime runtime(MakePlannerConfig(*first));
  const PlanningRequest request = BuildRequest(args, *first);
  // The initial plan is computed on the unchanged fabric: --down-link only applies to
  // the changed evidence used for the replan, so the demonstration is meaningful.
  const PlanningResult initial = runtime.Plan(request);
  const PathPlan prior = MakePathPlan(request, initial, runtime.PublishSequence());
  static_cast<void>(runtime.Retain(prior));
  std::fputs(RenderResult(initial, false).c_str(), stdout);
  std::printf("retained_plans %zu\n", runtime.RetainedPlanCount());

  DemoOptions changed = options;
  std::uint32_t down_index = args.GetU32("down-link", 0);
  if (!args.Has("down-link")) {
    // Default: take down a link the initial plan actually traverses, so the replan
    // demonstrates a real evidence change instead of an unrelated mutation.
    if (!initial.candidates.empty() && !initial.candidates.front().path.hops.empty()) {
      const LinkId traversed = initial.candidates.front().path.hops.front().link;
      const auto position = std::find(first->links.begin(), first->links.end(), traversed);
      if (position != first->links.end()) {
        down_index = static_cast<std::uint32_t>(position - first->links.begin());
      }
    }
  }
  changed.down_links.push_back(down_index);
  changed.link_state = LinkStateGeneration(changed.link_state.Value() + 1);
  const std::optional<DemoFabric> second = BuildDemoFabric(changed, error);
  if (!second.has_value()) {
    std::printf("status MALFORMED_REQUEST\n");
    return 1;
  }
  const PlanCurrentnessReport currentness = runtime.CheckCurrentness(prior);
  std::fputs(RenderCurrentness(currentness).c_str(), stdout);
  runtime.PublishSnapshot(second->snapshot);
  PlanningResult replanned;
  ReplanReport report;
  static_cast<void>(runtime.Replan(prior, request, replanned, report));
  std::fputs(RenderReplanReport(report).c_str(), stdout);
  std::fputs(RenderResult(replanned, false).c_str(), stdout);
  return 0;
}

int CommandExplain(const Args& args) {
  std::string error;
  DemoOptions options = DemoOptionsFromArgs(args);
  const std::optional<DemoFabric> fabric = BuildDemoFabric(options, error);
  if (!fabric.has_value()) {
    std::printf("status MALFORMED_REQUEST\n");
    return 1;
  }
  PlannerRuntime runtime(MakePlannerConfig(*fabric));
  const PlanningResult result = runtime.Plan(BuildRequest(args, *fabric));
  std::printf("status %s\n", std::string(ToString(result.status)).c_str());
  if (result.primary_failure.has_value()) {
    std::printf("primary_failure %s\n", std::string(ToString(*result.primary_failure)).c_str());
  }
  std::fputs(RenderRejections(result.rejections).c_str(), stdout);
  for (const ExplanationEntry& entry : result.explanations) {
    std::printf("explanation code=%s detail=\"%s\"\n", std::string(ToString(entry.code)).c_str(),
                entry.detail.c_str());
  }
  return 0;
}

int CommandCompare(const Args& args) {
  std::string error;
  DemoOptions options = DemoOptionsFromArgs(args);
  const std::optional<DemoFabric> fabric = BuildDemoFabric(options, error);
  if (!fabric.has_value()) {
    std::printf("status MALFORMED_REQUEST\n");
    return 1;
  }
  PlannerRuntime runtime(MakePlannerConfig(*fabric));
  PlanningRequest request = BuildRequest(args, *fabric);
  if (request.max_candidates < 2) {
    request.max_candidates = 2;
  }
  const PlanningResult result = runtime.Plan(request);
  std::fputs(RenderResult(result, false).c_str(), stdout);
  if (result.candidates.size() >= 2) {
    std::fputs(RenderRankExplanation(result.candidates[0], result.candidates[1]).c_str(), stdout);
  } else {
    std::printf("compare unavailable: fewer than two candidates\n");
  }
  return 0;
}

int CommandCurrentness(const Args& args) {
  std::string error;
  DemoOptions options = DemoOptionsFromArgs(args);
  const std::optional<DemoFabric> fabric = BuildDemoFabric(options, error);
  if (!fabric.has_value()) {
    std::printf("status MALFORMED_REQUEST\n");
    return 1;
  }
  PlannerRuntime runtime(MakePlannerConfig(*fabric));
  const PlanningRequest request = BuildRequest(args, *fabric);
  const PlanningResult result = runtime.Plan(request);
  const PathPlan plan = MakePathPlan(request, result, runtime.PublishSequence());
  static_cast<void>(runtime.Retain(plan));
  std::fputs(RenderCurrentness(runtime.CheckCurrentness(plan)).c_str(), stdout);

  DemoOptions changed = options;
  changed.link_state = LinkStateGeneration(changed.link_state.Value() + 1);
  const std::optional<DemoFabric> advanced = BuildDemoFabric(changed, error);
  if (advanced.has_value()) {
    runtime.PublishSnapshot(advanced->snapshot);
    std::fputs(RenderCurrentness(runtime.CheckCurrentness(plan)).c_str(), stdout);
  }
  InvalidationNotice notice;
  if (!result.candidates.empty() && !result.candidates.front().path.hops.empty()) {
    // Invalidate a link the plan actually depends on, not an arbitrary one.
    notice.links.push_back(result.candidates.front().path.hops.front().link);
  } else {
    notice.conservative_all = true;
  }
  const InvalidationReport invalidation = runtime.ApplyInvalidation(notice);
  std::printf("invalidation affected=%zu revalidation_required=%zu retired=%zu conservative=%s\n",
              invalidation.affected.size(), invalidation.marked_revalidation_required.size(),
              invalidation.retired.size(), invalidation.conservative ? "true" : "false");
  std::fputs(RenderCurrentness(runtime.CheckCurrentness(plan)).c_str(), stdout);
  return 0;
}

int CommandInspectStore(const Args& args) {
  const std::string path = args.GetOr("path", "");
  if (path.empty()) {
    std::printf("status MALFORMED_REQUEST\n");
    std::printf("detail \"--path is required\"\n");
    return 1;
  }
  std::vector<StoredPlanRecord> records;
  const StoreResult loaded = LoadPlanStore(path, ResourceLimits{}, records);
  std::printf("store_ok %s\n", loaded.ok ? "true" : "false");
  std::printf("store_code %s\n", loaded.ok ? "OK" : std::string(ToString(loaded.code)).c_str());
  if (!loaded.detail.empty()) {
    std::printf("store_detail \"%s\"\n", loaded.detail.c_str());
  }
  std::printf("store_records %zu\n", records.size());
  for (const StoredPlanRecord& record : records) {
    std::printf("record plan=%s request=%s generation=%s status=%s candidates=%zu\n",
                record.plan.ToString().c_str(), record.request.ToString().c_str(),
                record.generation.ToString().c_str(), std::string(ToString(record.status)).c_str(),
                record.candidates.size());
  }
  return loaded.ok ? 0 : 1;
}

int CommandCoordinator(const Args& args) {
  std::string error;
  DemoOptions options = DemoOptionsFromArgs(args);
  const std::optional<DemoFabric> fabric = BuildDemoFabric(options, error);
  if (!fabric.has_value()) {
    std::fprintf(stderr, "topology error: %s\n", error.c_str());
    return 1;
  }
  CoordinatorConfig config;
  config.bind_address = args.GetOr("bind", "127.0.0.1");
  config.port = static_cast<std::uint16_t>(args.GetU32("port", 0));
  config.snapshot = fabric->snapshot;
  config.initial_epoch = options.epoch;
  config.store_path = args.GetOr("store", "");
  Coordinator coordinator(config);
  if (!coordinator.Start(error)) {
    std::fprintf(stderr, "coordinator start failed: %s\n", error.c_str());
    return 1;
  }
  std::printf("endpoint %s\n", coordinator.Endpoint().c_str());
  std::printf("epoch %s\n", coordinator.Epoch().ToString().c_str());
  std::printf("recovered_plans %zu\n", coordinator.RecoveredPlanCount());
  std::fflush(stdout);
  const std::string endpoint_file = args.GetOr("endpoint-file", "");
  if (!endpoint_file.empty()) {
    std::ofstream endpoint_stream(endpoint_file, std::ios::binary | std::ios::trunc);
    if (endpoint_stream.is_open()) {
      endpoint_stream << coordinator.Endpoint() << "\n";
      endpoint_stream.flush();
    }
  }
  const std::uint64_t exit_after = args.GetU64("exit-after-plans", 0);
  const std::uint64_t advance_after = args.GetU64("advance-epoch-after-plans", 0);
  while (coordinator.running()) {
    if (exit_after != 0 && coordinator.AcceptedPublications() >= exit_after) {
      std::printf("accepted_publications %llu\n",
                  static_cast<unsigned long long>(coordinator.AcceptedPublications()));
      std::fflush(stdout);
      break;
    }
    if (advance_after != 0 && coordinator.AcceptedPublications() >= advance_after) {
      std::string reason;
      const bool advanced = coordinator.AdvanceEpoch(
          FabricEpoch(coordinator.Epoch().Value() + 1), reason);
      if (advanced) {
        std::printf("epoch_advanced %s\n", coordinator.Epoch().ToString().c_str());
        std::fflush(stdout);
      }
      if (!coordinator.SaveStore(reason)) {
        std::printf("store_save_failed \"%s\"\n", reason.c_str());
        std::fflush(stdout);
      }
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  std::string save_error;
  if (!args.GetOr("store", "").empty()) {
    if (!coordinator.SaveStore(save_error)) {
      std::printf("store_save_failed \"%s\"\n", save_error.c_str());
    } else {
      std::printf("store_saved %s\n", args.GetOr("store", "").c_str());
    }
  }
  coordinator.Stop();
  std::fflush(stdout);
  return 0;
}

int CommandWorker(const Args& args) {
  std::string error;
  DemoOptions options = DemoOptionsFromArgs(args);
  const std::optional<DemoFabric> fabric = BuildDemoFabric(options, error);
  if (!fabric.has_value()) {
    std::fprintf(stderr, "topology error: %s\n", error.c_str());
    return 1;
  }
  WorkerConfig config;
  config.coordinator_endpoint = args.GetOr("coordinator", "127.0.0.1:1");
  config.snapshot = fabric->snapshot;
  const std::string boot = args.GetOr("boot-id", "");
  config.boot = boot.empty() ? GenerateWorkerBootId() : MakeWorkerBootIdFromLabel(boot);
  const std::string publisher = args.GetOr("publisher", "");
  config.publisher = publisher.empty() ? GeneratePublisherId() : MakePublisherIdFromLabel(publisher);
  Worker worker(config);
  std::printf("worker_boot %s\n", worker.Boot().ToString().c_str());
  std::fflush(stdout);
  const std::uint64_t exit_after = args.GetU64("exit-after-plans", 0);
  std::thread monitor;
  if (exit_after != 0) {
    monitor = std::thread([&worker, exit_after]() {
      while (!worker.fenced()) {
        if (worker.PlansServed() >= exit_after) {
          worker.Stop();
          return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
    });
  }
  const bool ok = worker.Run(error);
  if (monitor.joinable()) {
    monitor.join();
  }
  std::printf("worker_registered %s\n", worker.registered() ? "true" : "false");
  std::printf("worker_plans_served %llu\n", static_cast<unsigned long long>(worker.PlansServed()));
  std::printf("worker_fenced %s\n", worker.fenced() ? "true" : "false");
  if (!ok && !worker.fenced() && !error.empty()) {
    std::printf("worker_error \"%s\"\n", error.c_str());
  }
  std::fflush(stdout);
  return ok ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    Usage();
    return 2;
  }
  const std::string command = argv[1];
  const Args args = ParseArgs(argc, argv, 2);
  if (command == "version" || command == "--version") {
    return CommandVersion();
  }
  if (command == "snapshot") {
    return CommandSnapshot(args);
  }
  if (command == "plan") {
    return CommandPlan(args);
  }
  if (command == "replan") {
    return CommandReplan(args);
  }
  if (command == "explain") {
    return CommandExplain(args);
  }
  if (command == "compare") {
    return CommandCompare(args);
  }
  if (command == "currentness") {
    return CommandCurrentness(args);
  }
  if (command == "inspect-store") {
    return CommandInspectStore(args);
  }
  if (command == "coordinator") {
    return CommandCoordinator(args);
  }
  if (command == "worker") {
    return CommandWorker(args);
  }
  Usage();
  return 2;
}

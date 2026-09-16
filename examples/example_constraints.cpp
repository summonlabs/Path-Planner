// Path Planner 1.0.0 - example: constraint handling.
//
// A four-node fabric with two parallel routes is materialised record by record so
// every constraint outcome is fixed by construction:
//
//   n0 --L1--> n1 --L2--> n3   static cost 1 + 1 = 2, the preferred route
//   n0 --L3--> n2 --L4--> n3   static cost 3 + 3 = 6, the alternate route
//
// Failure domain D1 owns {n1, L1, L2}; D2 owns {n2, L3, L4}. Capability C1 is
// published for every node and every link; capability C2 is never published, so a
// requirement on C2 is UNKNOWN rather than "insufficient".
//
// Five scenarios run against this fabric and every one of them is rendered by the
// explain.hpp renderers: nothing here formats a status by hand. All output is
// deterministic and free of timing data.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "pathplanner/explain.hpp"
#include "pathplanner/graph.hpp"
#include "pathplanner/ids.hpp"
#include "pathplanner/limits.hpp"
#include "pathplanner/planner.hpp"
#include "pathplanner/request.hpp"
#include "pathplanner/result.hpp"
#include "pathplanner/sha256.hpp"
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

std::string Label(const std::string& suffix) { return "pathplanner:example:constraints:" + suffix; }

template <class Id>
Id MakeId(const std::string& suffix) {
  return Id::FromDigest(pp::Sha256::Hash(Label(suffix)));
}

struct ConstraintFabric {
  std::shared_ptr<const pp::FabricSnapshot> snapshot;
  pp::EndpointId source_endpoint;
  pp::EndpointId destination_endpoint;
  std::array<pp::NodeId, 4> nodes{};
  std::array<pp::LinkId, 4> links{};
  pp::FailureDomainId domain_one;
  pp::CapabilityId published_capability;
  pp::CapabilityId absent_capability;
  bool link_two_down = false;
};

// Builds the fabric. link_two_down selects the second snapshot: identical records,
// a bumped link-state generation and L2 carrying the DOWN operational record.
std::optional<ConstraintFabric> BuildFabric(bool link_two_down, std::uint64_t link_state_generation,
                                            std::string& error) {
  ConstraintFabric fabric;
  fabric.link_two_down = link_two_down;
  fabric.domain_one = MakeId<pp::FailureDomainId>("domain:one");
  fabric.published_capability = MakeId<pp::CapabilityId>("capability:one");
  fabric.absent_capability = MakeId<pp::CapabilityId>("capability:two");
  for (std::size_t index = 0; index < fabric.nodes.size(); ++index) {
    fabric.nodes[index] = MakeId<pp::NodeId>("node:" + std::to_string(index));
    fabric.links[index] = MakeId<pp::LinkId>("link:" + std::to_string(index));
  }
  fabric.source_endpoint = MakeId<pp::EndpointId>("endpoint:source");
  fabric.destination_endpoint = MakeId<pp::EndpointId>("endpoint:destination");

  std::array<std::array<pp::PortId, 4>, 4> ports{};
  for (std::size_t node = 0; node < ports.size(); ++node) {
    for (std::size_t port = 0; port < ports[node].size(); ++port) {
      ports[node][port] = MakeId<pp::PortId>("port:" + std::to_string(node) + ":" + std::to_string(port));
    }
  }

  pp::FabricSnapshotBuilder builder(pp::ResourceLimits{});
  pp::SnapshotGenerations generations;
  generations.topology = pp::TopologyGeneration(1);
  generations.link_state = pp::LinkStateGeneration(link_state_generation);
  generations.ports = pp::PortGeneration(1);
  generations.capabilities = pp::CapabilityGeneration(1);
  generations.failure_domains = pp::FailureDomainGeneration(1);
  generations.epoch = pp::FabricEpoch(1);
  generations.policy = pp::PolicyGeneration(1);
  generations.constraints = pp::ConstraintGeneration(1);
  builder.SetGenerations(generations);
  builder.SetSource(pp::EvidenceSource::kSynthetic);

  for (std::size_t index = 0; index < fabric.nodes.size(); ++index) {
    pp::NodeRecord node;
    node.id = fabric.nodes[index];
    node.attachment = MakeId<pp::SwitchId>("switch:" + std::to_string(index));
    node.entity_generation = pp::EntityGeneration(1);
    node.structural_generation = pp::TopologyGeneration(1);
    node.ports = {ports[index][0], ports[index][1], ports[index][2], ports[index][3]};
    if (!builder.AddNode(std::move(node))) {
      error = "constraint fabric rejected a node record";
      return std::nullopt;
    }
  }

  struct EdgeDraft {
    std::size_t link = 0;
    std::size_t from = 0;
    std::size_t to = 0;
    std::size_t from_port = 0;
    std::size_t to_port = 0;
    std::uint32_t static_cost = 1;
  };
  const std::array<EdgeDraft, 4> drafts = {
      EdgeDraft{0, 0, 1, 0, 0, 1}, EdgeDraft{1, 1, 3, 1, 0, 1},
      EdgeDraft{2, 0, 2, 1, 0, 3}, EdgeDraft{3, 2, 3, 1, 1, 3}};

  for (const EdgeDraft& draft : drafts) {
    pp::EdgeRecord edge;
    edge.id = fabric.links[draft.link];
    edge.from = fabric.nodes[draft.from];
    edge.to = fabric.nodes[draft.to];
    edge.from_port = ports[draft.from][draft.from_port];
    edge.to_port = ports[draft.to][draft.to_port];
    edge.layer = pp::PathLayer::kPhysical;
    edge.relationship = pp::RelationshipType::kDirectLink;
    edge.static_cost = pp::StaticCost(draft.static_cost);
    edge.entity_generation = pp::EntityGeneration(1);
    edge.structural_generation = pp::TopologyGeneration(1);
    if (!builder.AddEdge(std::move(edge))) {
      error = "constraint fabric rejected an edge record";
      return std::nullopt;
    }
  }

  std::vector<pp::LinkStateRecord> link_states;
  link_states.reserve(fabric.links.size());
  for (std::size_t index = 0; index < fabric.links.size(); ++index) {
    const bool down = link_two_down && index == 1;
    link_states.push_back(pp::LinkStateRecord{fabric.links[index], down ? pp::LinkState::kDown : pp::LinkState::kUp});
  }
  builder.SetLinkStates(std::move(link_states));

  std::vector<pp::PortStateRecord> port_states;
  port_states.reserve(ports.size() * ports[0].size());
  for (const std::array<pp::PortId, 4>& node_ports : ports) {
    for (const pp::PortId& port : node_ports) {
      port_states.push_back(pp::PortStateRecord{port, pp::PortState::kUp});
    }
  }
  builder.SetPortStates(std::move(port_states));

  std::vector<pp::CapabilityBinding> bindings;
  bindings.reserve(fabric.nodes.size() + fabric.links.size());
  for (const pp::NodeId& node : fabric.nodes) {
    bindings.push_back(pp::CapabilityBinding{pp::SubjectKey::ForNode(node), fabric.published_capability,
                                             pp::CapabilityValue(1)});
  }
  for (const pp::LinkId& link : fabric.links) {
    bindings.push_back(pp::CapabilityBinding{pp::SubjectKey::ForLink(link), fabric.published_capability,
                                             pp::CapabilityValue(1)});
  }
  builder.SetCapabilities(std::move(bindings));

  pp::FailureDomainRecord first;
  first.domain = fabric.domain_one;
  first.risk_class = MakeId<pp::FailureDomainClass>("domain:class:one");
  first.members = {pp::SubjectKey::ForNode(fabric.nodes[1]), pp::SubjectKey::ForLink(fabric.links[0]),
                   pp::SubjectKey::ForLink(fabric.links[1])};
  pp::FailureDomainRecord second;
  second.domain = MakeId<pp::FailureDomainId>("domain:two");
  second.risk_class = MakeId<pp::FailureDomainClass>("domain:class:two");
  second.members = {pp::SubjectKey::ForNode(fabric.nodes[2]), pp::SubjectKey::ForLink(fabric.links[2]),
                    pp::SubjectKey::ForLink(fabric.links[3])};
  builder.SetFailureDomains({std::move(first), std::move(second)}, true);

  pp::EndpointRecord source;
  source.id = fabric.source_endpoint;
  source.endpoint_class = pp::EndpointClass::kEndpoint;
  source.node = fabric.nodes[0];
  source.port = ports[0][3];
  source.entity_generation = pp::EntityGeneration(1);
  if (!builder.AddEndpoint(std::move(source))) {
    error = "constraint fabric rejected the source endpoint";
    return std::nullopt;
  }
  pp::EndpointRecord destination;
  destination.id = fabric.destination_endpoint;
  destination.endpoint_class = pp::EndpointClass::kEndpoint;
  destination.node = fabric.nodes[3];
  destination.port = ports[3][3];
  destination.entity_generation = pp::EntityGeneration(1);
  if (!builder.AddEndpoint(std::move(destination))) {
    error = "constraint fabric rejected the destination endpoint";
    return std::nullopt;
  }

  const pp::SnapshotBuildResult built = builder.Build();
  if (!built.ok()) {
    error = built.detail.empty() ? "constraint fabric was rejected" : built.detail;
    return std::nullopt;
  }
  fabric.snapshot = built.snapshot;
  return fabric;
}

pp::PlanningRequest MakeRequest(const ConstraintFabric& fabric, const std::string& scenario) {
  pp::PlanningRequest request;
  request.id = pp::PlanningRequestId::FromDigest(pp::Sha256::Hash(Label("request:" + scenario)));
  request.source.id = fabric.source_endpoint;
  request.source.endpoint_class = pp::EndpointClass::kEndpoint;
  request.source.generation = pp::EntityGeneration(1);
  request.destination.id = fabric.destination_endpoint;
  request.destination.endpoint_class = pp::EndpointClass::kEndpoint;
  request.destination.generation = pp::EntityGeneration(1);
  request.constraints.id = pp::ConstraintSetId::FromDigest(pp::Sha256::Hash(Label("constraints:" + scenario)));
  request.constraints.generation = pp::ConstraintGeneration(1);
  request.constraints.layer = pp::PathLayer::kPhysical;
  request.policy.generation = pp::PolicyGeneration(1);
  request.max_candidates = 1;
  return request;
}

const pp::RejectionExplanation* FindRejection(const pp::PlanningResult& result, pp::DiagnosticCode code) {
  for (const pp::RejectionExplanation& rejection : result.rejections) {
    if (rejection.code == code) {
      return &rejection;
    }
  }
  return nullptr;
}

// Per-subject rejections (forbidden nodes) are reported one entry each, so the
// count of entries is the count of rejected subjects.
std::size_t CountRejectedNodes(const pp::PlanningResult& result, const std::vector<pp::NodeId>& nodes) {
  std::size_t matched = 0;
  for (const pp::NodeId& node : nodes) {
    for (const pp::RejectionExplanation& rejection : result.rejections) {
      if (rejection.code != pp::DiagnosticCode::kForbiddenNode) {
        continue;
      }
      const std::optional<pp::NodeId> subject = rejection.subject.AsNode();
      if (subject.has_value() && *subject == node) {
        matched += 1;
        break;
      }
    }
  }
  return matched;
}

bool PathUsesNode(const pp::PlanningResult& result, const pp::NodeId& node) {
  for (const pp::Candidate& candidate : result.candidates) {
    for (const pp::NodeId& visited : candidate.path.nodes) {
      if (visited == node) {
        return true;
      }
    }
  }
  return false;
}

bool PathUsesLink(const pp::PlanningResult& result, const pp::LinkId& link) {
  for (const pp::Candidate& candidate : result.candidates) {
    for (const pp::PathHop& hop : candidate.path.hops) {
      if (hop.link == link) {
        return true;
      }
    }
  }
  return false;
}

}  // namespace

int main() {
  const pp::ResourceLimits limits;
  std::string error;

  const std::optional<ConstraintFabric> link_up = BuildFabric(false, 1, error);
  if (!link_up.has_value()) {
    std::cout << "constraints fabric_error=" << error << "\n";
    return 1;
  }
  const std::optional<ConstraintFabric> link_down = BuildFabric(true, 2, error);
  if (!link_down.has_value()) {
    std::cout << "constraints fabric_error=" << error << "\n";
    return 1;
  }

  std::cout << "constraints fabric routes=2 cost_via_n1=2 cost_via_n2=6\n";
  std::cout << pp::RenderSnapshotSummary(*link_up->snapshot);
  std::cout << pp::RenderSnapshotSummary(*link_down->snapshot);

  // -------------------------------------------------------------------------
  // Baseline: the cheaper route wins.
  // -------------------------------------------------------------------------
  pp::PlannerRuntime up_runtime(pp::PlannerConfig{});
  up_runtime.PublishSnapshot(link_up->snapshot);
  const pp::PlanningResult baseline = up_runtime.Plan(MakeRequest(*link_up, "baseline"));
  std::cout << "constraints scenario=baseline\n";
  std::cout << pp::RenderResult(baseline, true);
  Check("baseline_status_planned", baseline.status == pp::PlanStatus::kPlanned);
  Check("baseline_hops_two", baseline.candidates.size() == 1 && baseline.candidates[0].cost.hops.Value() == 2);
  Check("baseline_uses_n1", PathUsesNode(baseline, link_up->nodes[1]));

  // -------------------------------------------------------------------------
  // Link down: L2 is DOWN, so the plan must avoid it and explain why.
  // -------------------------------------------------------------------------
  pp::PlannerRuntime down_runtime(pp::PlannerConfig{});
  down_runtime.PublishSnapshot(link_down->snapshot);
  const pp::PlanningResult avoided = down_runtime.Plan(MakeRequest(*link_down, "link_down"));
  std::cout << "constraints scenario=link_down down_link=" << link_down->links[1].ToString() << "\n";
  std::cout << pp::RenderResult(avoided, true);
  const pp::RejectionExplanation* down_rejection = FindRejection(avoided, pp::DiagnosticCode::kLinkStateDown);
  Check("link_down_status_planned", avoided.status == pp::PlanStatus::kPlanned);
  Check("link_down_rejection_present", down_rejection != nullptr);
  if (down_rejection != nullptr) {
    const std::optional<pp::LinkId> subject = down_rejection->subject.AsLink();
    Check("link_down_rejection_names_l2", subject.has_value() && *subject == link_down->links[1]);
  }
  Check("link_down_plan_avoids_l2", !PathUsesLink(avoided, link_down->links[1]));
  Check("link_down_plan_avoids_n1", !PathUsesNode(avoided, link_down->nodes[1]));
  Check("link_down_plan_hops_two",
        avoided.candidates.size() == 1 && avoided.candidates[0].cost.hops.Value() == 2);

  // -------------------------------------------------------------------------
  // Required capability whose binding is absent: UNKNOWN never satisfies.
  // -------------------------------------------------------------------------
  pp::CapabilityRequirement absent_requirement;
  absent_requirement.capability = link_up->absent_capability;
  absent_requirement.comparator = pp::CapabilityComparator::kAtLeast;
  absent_requirement.value = pp::CapabilityValue(1);

  // Scope EVERY_LINK: every link is rejected because no link publishes the
  // binding, and the rejection log accounts for all of them.
  pp::PlanningRequest link_scope_request = MakeRequest(*link_up, "capability_absent_links");
  absent_requirement.scope = pp::CapabilityScope::kEveryLink;
  link_scope_request.constraints.required_capabilities.push_back(absent_requirement);
  const pp::PlanningResult link_scope_result = up_runtime.Plan(link_scope_request);
  std::cout << "constraints scenario=capability_absent_link_scope capability="
            << link_up->absent_capability.ToString() << "\n";
  std::cout << pp::RenderResult(link_scope_result, false);
  const pp::RejectionExplanation* capability_rejection =
      FindRejection(link_scope_result, pp::DiagnosticCode::kCapabilityUnknown);
  Check("capability_link_scope_status_no_path", link_scope_result.status == pp::PlanStatus::kNoPath);
  Check("capability_link_scope_rejection_present", capability_rejection != nullptr);
  Check("capability_link_scope_covers_all_links",
        capability_rejection != nullptr && capability_rejection->occurrences == link_up->links.size());
  Check("capability_link_scope_no_candidates", link_scope_result.candidates.empty());

  // Scope SOURCE_NODE: the same absent binding is a hard failure of the request
  // and is reported as the primary diagnostic, with an explanation entry.
  pp::PlanningRequest source_scope_request = MakeRequest(*link_up, "capability_absent_source");
  absent_requirement.scope = pp::CapabilityScope::kSourceNode;
  source_scope_request.constraints.required_capabilities.push_back(absent_requirement);
  const pp::PlanningResult source_scope_result = up_runtime.Plan(source_scope_request);
  std::cout << "constraints scenario=capability_absent_source_scope capability="
            << link_up->absent_capability.ToString() << "\n";
  std::cout << pp::RenderResult(source_scope_result, false);
  Check("capability_source_scope_status_constraint_unsatisfied",
        source_scope_result.status == pp::PlanStatus::kConstraintUnsatisfied);
  Check("capability_source_scope_primary_failure_unknown",
        source_scope_result.primary_failure.has_value() &&
            *source_scope_result.primary_failure == pp::DiagnosticCode::kCapabilityUnknown);
  Check("capability_source_scope_explained", !source_scope_result.explanations.empty());

  // -------------------------------------------------------------------------
  // Failure domain avoidance: D1 owns the preferred route, so the plan moves.
  // -------------------------------------------------------------------------
  pp::PlanningRequest domain_request = MakeRequest(*link_up, "failure_domain");
  domain_request.constraints.forbidden_failure_domains.push_back(link_up->domain_one);
  const pp::PlanningResult domain_result = up_runtime.Plan(domain_request);
  std::cout << "constraints scenario=failure_domain forbidden_domain=" << link_up->domain_one.ToString() << "\n";
  std::cout << pp::RenderResult(domain_result, true);
  Check("domain_status_planned", domain_result.status == pp::PlanStatus::kPlanned);
  Check("domain_rejection_present", FindRejection(domain_result, pp::DiagnosticCode::kFailureDomainForbidden) != nullptr);
  Check("domain_plan_avoids_n1", !PathUsesNode(domain_result, link_up->nodes[1]));
  Check("domain_plan_avoids_l1", !PathUsesLink(domain_result, link_up->links[0]));
  Check("domain_plan_uses_n2", PathUsesNode(domain_result, link_up->nodes[2]));
  Check("domain_plan_hops_two",
        domain_result.candidates.size() == 1 && domain_result.candidates[0].cost.hops.Value() == 2);

  // -------------------------------------------------------------------------
  // Forbidden nodes: both intermediate nodes are removed, so no route remains.
  // -------------------------------------------------------------------------
  pp::PlanningRequest forbidden_request = MakeRequest(*link_up, "forbidden_nodes");
  forbidden_request.constraints.forbidden_nodes.push_back(link_up->nodes[1]);
  forbidden_request.constraints.forbidden_nodes.push_back(link_up->nodes[2]);
  // The eligibility view matches forbidden nodes with a binary search over the
  // vector as published, so the set is published in sorted (bytewise) order
  // rather than in the order the caller happened to collect it.
  std::sort(forbidden_request.constraints.forbidden_nodes.begin(),
            forbidden_request.constraints.forbidden_nodes.end());
  const pp::PlanningResult forbidden_result = up_runtime.Plan(forbidden_request);
  std::cout << "constraints scenario=forbidden_nodes forbidden=" << link_up->nodes[1].ToString() << " "
            << link_up->nodes[2].ToString() << "\n";
  std::cout << pp::RenderResult(forbidden_result, false);
  Check("forbidden_status_no_path", forbidden_result.status == pp::PlanStatus::kNoPath);
  Check("forbidden_no_candidates", forbidden_result.candidates.empty());
  Check("forbidden_rejection_present",
        FindRejection(forbidden_result, pp::DiagnosticCode::kForbiddenNode) != nullptr);
  Check("forbidden_rejections_name_both_nodes",
        CountRejectedNodes(forbidden_result, forbidden_request.constraints.forbidden_nodes) == 2);

  std::cout << "constraints limits max_candidates_per_request=" << limits.max_candidates_per_request << "\n";
  std::cout << "constraints report failures=" << g_failures << "\n";
  return g_failures == 0 ? 0 : 1;
}

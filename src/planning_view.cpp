#include "planning_view.hpp"

#include <algorithm>
#include <string>
#include <utility>

namespace summon::pathplanner::internal {
namespace {

bool ContainsNode(const std::vector<NodeId>& values, const NodeId& id) {
  return std::binary_search(values.begin(), values.end(), id);
}

bool ContainsLink(const std::vector<LinkId>& values, const LinkId& id) {
  return std::binary_search(values.begin(), values.end(), id);
}

bool ContainsPort(const std::vector<PortId>& values, const PortId& id) {
  return std::binary_search(values.begin(), values.end(), id);
}

bool ContainsDomain(const std::vector<FailureDomainId>& values, const FailureDomainId& id) {
  return std::binary_search(values.begin(), values.end(), id);
}

bool ContainsClass(const std::vector<FailureDomainClass>& values, const FailureDomainClass& id) {
  return std::binary_search(values.begin(), values.end(), id);
}

template <class Id>
std::vector<Id> SortedCopy(const std::vector<Id>& values) {
  std::vector<Id> sorted(values.begin(), values.end());
  std::sort(sorted.begin(), sorted.end());
  return sorted;
}

struct NodeVerdict {
  bool excluded = false;
  DiagnosticCode code = DiagnosticCode::kForbiddenNode;
  std::string detail;
};

NodeVerdict EvaluateNode(const PlanningView& view, const PlanningRequest& request,
                         const std::vector<NodeId>& forbidden_nodes, const NodeRecord& node) {
  NodeVerdict verdict;
  const SubjectKey subject = SubjectKey::ForNode(node.id);

  // forbidden_nodes is pre-sorted by the caller: the lookup is a binary search, so the
  // constraint set must never be searched in whatever order the caller published it.
  if (ContainsNode(forbidden_nodes, node.id)) {
    verdict.excluded = true;
    verdict.code = DiagnosticCode::kForbiddenNode;
    verdict.detail = "node is forbidden by the constraint set";
    return verdict;
  }

  for (const CapabilityRequirement& requirement : request.constraints.required_capabilities) {
    if (requirement.scope != CapabilityScope::kEveryNode) {
      continue;
    }
    DiagnosticCode failure = DiagnosticCode::kCapabilityUnknown;
    if (!CapabilitySatisfied(view, subject, requirement, failure)) {
      verdict.excluded = true;
      verdict.code = failure;
      verdict.detail = "node capability requirement not satisfied for " + requirement.capability.ToString();
      return verdict;
    }
  }

  DiagnosticCode domain_failure = DiagnosticCode::kFailureDomainUnknown;
  if (!FailureDomainCompliant(view, subject, request.constraints.fail_closed_on_unknown_domains, domain_failure)) {
    verdict.excluded = true;
    verdict.code = domain_failure;
    verdict.detail = "node failure-domain constraint violated";
    return verdict;
  }

  return verdict;
}

}  // namespace

RejectionLog::RejectionLog(std::uint32_t max_entries) : max_entries_(max_entries == 0 ? 1 : max_entries) {}

void RejectionLog::Aggregate(DiagnosticCode code, const SubjectKey& subject, std::string detail) {
  const std::size_t slot = static_cast<std::size_t>(code);
  if (slot >= aggregates_.size()) {
    return;
  }
  AggregateEntry& aggregate = aggregates_[slot];
  if (!aggregate.present) {
    aggregate.present = true;
    aggregate.detail = std::move(detail);
  }
  aggregate.count += 1;
  if (aggregate.examples.size() < kRejectionExampleLimit) {
    aggregate.examples.push_back(subject);
  }
}

void RejectionLog::Explicit(DiagnosticCode code, const SubjectKey& subject, std::string detail) {
  if (explicit_entries_.size() >= max_entries_) {
    return;
  }
  RejectionExplanation entry;
  entry.code = code;
  entry.subject = subject;
  entry.detail = std::move(detail);
  entry.occurrences = 1;
  explicit_entries_.push_back(std::move(entry));
}

// Explicit entries (constraint-driven exclusions) are recorded separately from the
// aggregated counters, so both stores must be consulted: a cause that appears only as an
// explicit entry is still a cause.
bool RejectionLog::Contains(DiagnosticCode code) const noexcept {
  const std::size_t slot = static_cast<std::size_t>(code);
  if (slot < aggregates_.size() && aggregates_[slot].present) {
    return true;
  }
  for (const RejectionExplanation& entry : explicit_entries_) {
    if (entry.code == code) {
      return true;
    }
  }
  return false;
}

std::uint64_t RejectionLog::Count(DiagnosticCode code) const noexcept {
  const std::size_t slot = static_cast<std::size_t>(code);
  std::uint64_t total = slot < aggregates_.size() ? aggregates_[slot].count : 0;
  for (const RejectionExplanation& entry : explicit_entries_) {
    if (entry.code == code) {
      total += entry.occurrences;
    }
  }
  return total;
}

bool RejectionLog::Empty() const noexcept {
  if (!explicit_entries_.empty()) {
    return false;
  }
  for (const AggregateEntry& aggregate : aggregates_) {
    if (aggregate.present) {
      return false;
    }
  }
  return true;
}

std::vector<RejectionExplanation> RejectionLog::Render() const {
  std::vector<RejectionExplanation> rendered;
  rendered.reserve(explicit_entries_.size() + aggregates_.size());
  for (std::size_t slot = 1; slot < aggregates_.size(); ++slot) {
    const AggregateEntry& aggregate = aggregates_[slot];
    if (!aggregate.present) {
      continue;
    }
    RejectionExplanation entry;
    entry.code = static_cast<DiagnosticCode>(slot);
    entry.occurrences = aggregate.count;
    entry.detail = aggregate.detail;
    if (!aggregate.examples.empty()) {
      entry.subject = aggregate.examples.front();
      entry.detail += " (examples:";
      for (const SubjectKey& example : aggregate.examples) {
        entry.detail += " " + example.ToString();
      }
      entry.detail += ")";
    }
    rendered.push_back(std::move(entry));
  }
  for (const RejectionExplanation& entry : explicit_entries_) {
    rendered.push_back(entry);
  }
  return rendered;
}

std::uint32_t PlanningView::ViewIndex(const NodeId& id) const noexcept {
  const NodeRecord* node = snapshot->FindNode(id);
  if (node == nullptr) {
    return kInvalidIndex;
  }
  const std::size_t index = static_cast<std::size_t>(node - snapshot->Nodes().data());
  return snapshot_to_view_node[index];
}

bool CapabilitySatisfied(const PlanningView& view, const SubjectKey& subject,
                         const CapabilityRequirement& requirement, DiagnosticCode& failure) {
  const std::optional<CapabilityValue> observed =
      view.snapshot->Capabilities().Lookup(subject, requirement.capability);
  if (!observed.has_value()) {
    failure = DiagnosticCode::kCapabilityUnknown;
    return false;
  }
  if (!requirement.SatisfiedBy(*observed)) {
    failure = DiagnosticCode::kCapabilityInsufficient;
    return false;
  }
  return true;
}

bool FailureDomainCompliant(const PlanningView& view, const SubjectKey& subject, bool fail_closed,
                            DiagnosticCode& failure) {
  const bool has_domain_constraints =
      !view.forbidden_failure_domains.empty() || !view.forbidden_failure_domain_classes.empty();
  const FailureDomainView::Membership membership = view.snapshot->FailureDomains().MembershipOf(subject);
  if (!membership.known) {
    if (fail_closed && has_domain_constraints) {
      failure = DiagnosticCode::kFailureDomainUnknown;
      return false;
    }
    return true;
  }
  for (const FailureDomainId& domain : membership.domains) {
    if (ContainsDomain(view.forbidden_failure_domains, domain)) {
      failure = DiagnosticCode::kFailureDomainForbidden;
      return false;
    }
    if (!view.forbidden_failure_domain_classes.empty()) {
      const FailureDomainRecord* record = view.snapshot->FailureDomains().FindDomain(domain);
      if (record != nullptr && ContainsClass(view.forbidden_failure_domain_classes, record->risk_class)) {
        failure = DiagnosticCode::kFailureDomainClassForbidden;
        return false;
      }
    }
  }
  return true;
}

PlanningViewBuild BuildPlanningView(const FabricSnapshot& snapshot, const PlanningRequest& request,
                                    const ResourceLimits& limits, const NodeId& source_node,
                                    const NodeId& destination_node, std::uint32_t& source_view,
                                    std::uint32_t& destination_view) {
  PlanningViewBuild build;
  PlanningView& view = build.view;
  view.snapshot = &snapshot;
  view.limits = limits;
  view.layer = request.constraints.layer;
  view.cost_model = request.policy.cost_model;
  view.diagnostic_mode = request.mode == PlanningMode::kDiagnosticNonCurrent;
  view.allow_degraded_links = request.policy.allow_degraded_links;
  view.allow_draining_ports = request.policy.allow_draining_ports;
  view.allow_maintenance_ports = request.policy.allow_maintenance_ports;
  view.locality_scope = SortedCopy(request.policy.locality_scope);
  view.forbidden_failure_domains = SortedCopy(request.constraints.forbidden_failure_domains);
  view.forbidden_failure_domain_classes = SortedCopy(request.constraints.forbidden_failure_domain_classes);
  view.fail_closed_on_unknown_domains = request.constraints.fail_closed_on_unknown_domains;
  view.provisional = view.diagnostic_mode || !request.policy.require_operational_proof;
  view.require_operational_proof = request.policy.require_operational_proof && !view.diagnostic_mode;
  view.rejections = RejectionLog(limits.max_explanation_entries);

  const std::vector<NodeId> forbidden_nodes = SortedCopy(request.constraints.forbidden_nodes);
  const std::vector<NodeRecord>& nodes = snapshot.Nodes();
  view.snapshot_to_view_node.assign(nodes.size(), kInvalidIndex);
  view.view_to_snapshot_node.reserve(nodes.size());

  for (std::size_t index = 0; index < nodes.size(); ++index) {
    const NodeVerdict verdict = EvaluateNode(view, request, forbidden_nodes, nodes[index]);
    if (verdict.excluded) {
      view.rejections.Explicit(verdict.code, SubjectKey::ForNode(nodes[index].id), verdict.detail);
      continue;
    }
    const std::uint32_t view_index = static_cast<std::uint32_t>(view.view_to_snapshot_node.size());
    view.snapshot_to_view_node[index] = view_index;
    view.view_to_snapshot_node.push_back(static_cast<std::uint32_t>(index));
  }

  if (view.view_to_snapshot_node.size() > static_cast<std::size_t>(limits.max_nodes)) {
    build.fatal = DiagnosticCode::kGraphTooLarge;
    build.detail = "eligible node count exceeds the configured limit";
    return build;
  }

  source_view = view.ViewIndex(source_node);
  destination_view = view.ViewIndex(destination_node);

  if (source_view == kInvalidIndex || destination_view == kInvalidIndex) {
    const bool source_excluded = source_view == kInvalidIndex;
    const NodeId& target = source_excluded ? source_node : destination_node;
    const NodeRecord* node = snapshot.FindNode(target);
    DiagnosticCode code = DiagnosticCode::kForbiddenNode;
    if (node != nullptr) {
      code = EvaluateNode(view, request, forbidden_nodes, *node).code;
    }
    build.fatal = code;
    build.detail = source_excluded ? "source node is excluded by a hard constraint"
                                   : "destination node is excluded by a hard constraint";
    build.explanations.push_back(
        ExplanationEntry{code, std::string(source_excluded ? "source" : "destination") + " node " +
                                   SubjectKey::ForNode(target).ToString() + " is not eligible"});
    return build;
  }

  for (const CapabilityRequirement& requirement : request.constraints.required_capabilities) {
    if (requirement.scope != CapabilityScope::kSourceNode && requirement.scope != CapabilityScope::kDestinationNode) {
      continue;
    }
    const bool is_source = requirement.scope == CapabilityScope::kSourceNode;
    const NodeId& target = is_source ? source_node : destination_node;
    DiagnosticCode failure = DiagnosticCode::kCapabilityUnknown;
    if (!CapabilitySatisfied(view, SubjectKey::ForNode(target), requirement, failure)) {
      build.fatal = failure;
      build.detail = std::string(is_source ? "source" : "destination") +
                     " node capability requirement not satisfied for " + requirement.capability.ToString();
      return build;
    }
  }

  const std::vector<LinkId> forbidden_links = SortedCopy(request.constraints.forbidden_links);
  const std::vector<PortId> forbidden_ports = SortedCopy(request.constraints.forbidden_ports);

  struct PendingAdjacency {
    std::uint32_t from = kInvalidIndex;
    Adjacency entry;
  };
  std::vector<PendingAdjacency> pending;

  const std::vector<EdgeRecord>& edges = snapshot.Edges();
  for (std::size_t edge_index = 0; edge_index < edges.size(); ++edge_index) {
    const EdgeRecord& edge = edges[edge_index];
    const NodeRecord* from_node = snapshot.FindNode(edge.from);
    const NodeRecord* to_node = snapshot.FindNode(edge.to);
    if (from_node == nullptr || to_node == nullptr) {
      continue;
    }
    const std::size_t from_snapshot_index = static_cast<std::size_t>(from_node - nodes.data());
    const std::size_t to_snapshot_index = static_cast<std::size_t>(to_node - nodes.data());
    const std::uint32_t from_index = view.snapshot_to_view_node[from_snapshot_index];
    const std::uint32_t to_index = view.snapshot_to_view_node[to_snapshot_index];
    const SubjectKey link_subject = SubjectKey::ForLink(edge.id);

    if (edge.layer != request.constraints.layer) {
      view.rejections.Aggregate(DiagnosticCode::kLayerMismatch, link_subject,
                                "link layer does not match the requested planning layer");
      continue;
    }
    if (ContainsLink(forbidden_links, edge.id)) {
      view.rejections.Explicit(DiagnosticCode::kForbiddenLink, link_subject,
                               "link is forbidden by the constraint set");
      continue;
    }
    if (ContainsPort(forbidden_ports, edge.from_port) || ContainsPort(forbidden_ports, edge.to_port)) {
      view.rejections.Explicit(DiagnosticCode::kForbiddenPort, link_subject,
                               "link port is forbidden by the constraint set");
      continue;
    }
    if (from_index == kInvalidIndex || to_index == kInvalidIndex) {
      continue;
    }

    const LinkState state = snapshot.LinkStates().StateOf(edge.id);
    bool degraded = false;
    bool link_ok = true;
    switch (state) {
      case LinkState::kUp:
        break;
      case LinkState::kDegraded:
        if (view.allow_degraded_links) {
          degraded = true;
        } else {
          view.rejections.Aggregate(DiagnosticCode::kLinkStateDegradedDisallowed, link_subject,
                                    "DEGRADED link excluded by planning policy");
          link_ok = false;
        }
        break;
      case LinkState::kDown:
        view.rejections.Aggregate(DiagnosticCode::kLinkStateDown, link_subject, "link is DOWN");
        link_ok = false;
        break;
      case LinkState::kFaulted:
        view.rejections.Aggregate(DiagnosticCode::kLinkStateFaulted, link_subject, "link is FAULTED");
        link_ok = false;
        break;
      case LinkState::kRetired:
        view.rejections.Aggregate(DiagnosticCode::kLinkStateRetired, link_subject, "link is RETIRED");
        link_ok = false;
        break;
      case LinkState::kRevalidationRequired:
        if (!view.diagnostic_mode) {
          view.rejections.Aggregate(DiagnosticCode::kLinkStateRevalidationRequired, link_subject,
                                    "link requires revalidation");
          link_ok = false;
        }
        break;
      case LinkState::kUnknown:
        if (view.require_operational_proof) {
          view.rejections.Aggregate(DiagnosticCode::kLinkStateUnknown, link_subject,
                                    "link operational state is UNKNOWN and proof is required");
          link_ok = false;
        }
        break;
    }
    if (!link_ok) {
      continue;
    }

    bool ports_ok = true;
    for (const PortId& port : {edge.from_port, edge.to_port}) {
      const SubjectKey subject = SubjectKey::ForPort(port);
      const PortState port_state = snapshot.PortStates().StateOf(port);
      bool eligible = true;
      switch (port_state) {
        case PortState::kUp:
          break;
        case PortState::kAdminDisabled:
          view.rejections.Aggregate(DiagnosticCode::kPortAdminDisabled, subject, "port is ADMIN_DISABLED");
          eligible = false;
          break;
        case PortState::kRetired:
          view.rejections.Aggregate(DiagnosticCode::kPortRetired, subject, "port is RETIRED");
          eligible = false;
          break;
        case PortState::kSuperseded:
          view.rejections.Aggregate(DiagnosticCode::kPortSuperseded, subject, "port is SUPERSEDED");
          eligible = false;
          break;
        case PortState::kDraining:
          if (!view.allow_draining_ports && !view.diagnostic_mode) {
            view.rejections.Aggregate(DiagnosticCode::kPortDraining, subject, "port is DRAINING");
            eligible = false;
          }
          break;
        case PortState::kMaintenance:
          if (!view.allow_maintenance_ports && !view.diagnostic_mode) {
            view.rejections.Aggregate(DiagnosticCode::kPortMaintenance, subject, "port is in MAINTENANCE");
            eligible = false;
          }
          break;
        case PortState::kRevalidationRequired:
          if (!view.diagnostic_mode) {
            view.rejections.Aggregate(DiagnosticCode::kPortRevalidationRequired, subject,
                                      "port requires revalidation");
            eligible = false;
          }
          break;
        case PortState::kUnknown:
          if (view.require_operational_proof) {
            view.rejections.Aggregate(DiagnosticCode::kPortUnknown, subject,
                                      "port state is UNKNOWN and proof is required");
            eligible = false;
          }
          break;
      }
      if (!eligible) {
        ports_ok = false;
        break;
      }
    }
    if (!ports_ok) {
      continue;
    }

    bool capability_ok = true;
    for (const CapabilityRequirement& requirement : request.constraints.required_capabilities) {
      DiagnosticCode failure = DiagnosticCode::kCapabilityUnknown;
      if (requirement.scope == CapabilityScope::kEveryLink) {
        if (!CapabilitySatisfied(view, link_subject, requirement, failure)) {
          view.rejections.Aggregate(failure, link_subject, "link capability requirement not satisfied");
          capability_ok = false;
          break;
        }
      } else if (requirement.scope == CapabilityScope::kEveryPort) {
        if (!CapabilitySatisfied(view, SubjectKey::ForPort(edge.from_port), requirement, failure) ||
            !CapabilitySatisfied(view, SubjectKey::ForPort(edge.to_port), requirement, failure)) {
          view.rejections.Aggregate(failure, link_subject, "port capability requirement not satisfied");
          capability_ok = false;
          break;
        }
      }
    }
    if (!capability_ok) {
      continue;
    }

    bool domain_ok = true;
    const SubjectKey subjects[3] = {link_subject, SubjectKey::ForPort(edge.from_port),
                                    SubjectKey::ForPort(edge.to_port)};
    for (const SubjectKey& subject : subjects) {
      DiagnosticCode failure = DiagnosticCode::kFailureDomainUnknown;
      if (!FailureDomainCompliant(view, subject, request.constraints.fail_closed_on_unknown_domains, failure)) {
        view.rejections.Aggregate(failure, link_subject, "failure-domain constraint violated");
        domain_ok = false;
        break;
      }
    }
    if (!domain_ok) {
      continue;
    }

    CostValue traversal = CostValue(edge.static_cost.Value());
    bool cost_ok = true;
    if (degraded) {
      const std::optional<CostValue> sum = CheckedAdd(traversal, view.cost_model.degraded_penalty);
      if (sum.has_value()) {
        traversal = *sum;
      } else {
        cost_ok = false;
      }
    }
    bool outside_locality = false;
    if (cost_ok && !view.locality_scope.empty()) {
      outside_locality = !ContainsNode(view.locality_scope, edge.to);
      if (outside_locality) {
        const std::optional<CostValue> sum = CheckedAdd(traversal, view.cost_model.locality_penalty);
        if (sum.has_value()) {
          traversal = *sum;
        } else {
          cost_ok = false;
        }
      }
    }
    if (!cost_ok) {
      view.rejections.Aggregate(DiagnosticCode::kCostOverflow, link_subject, "edge cost accumulation overflow");
      continue;
    }

    PendingAdjacency pending_entry;
    pending_entry.from = from_index;
    pending_entry.entry.to = to_index;
    pending_entry.entry.edge = static_cast<std::uint32_t>(edge_index);
    pending_entry.entry.traversal_cost = traversal;
    pending_entry.entry.degraded = degraded;
    pending_entry.entry.outside_locality = outside_locality;
    pending.push_back(pending_entry);
    view.eligible_edges += 1;
  }

  std::sort(pending.begin(), pending.end(), [&view, &snapshot](const PendingAdjacency& lhs,
                                                               const PendingAdjacency& rhs) {
    if (lhs.from != rhs.from) {
      return lhs.from < rhs.from;
    }
    const NodeId& lhs_to = snapshot.Nodes()[view.view_to_snapshot_node[lhs.entry.to]].id;
    const NodeId& rhs_to = snapshot.Nodes()[view.view_to_snapshot_node[rhs.entry.to]].id;
    if (lhs_to != rhs_to) {
      return lhs_to < rhs_to;
    }
    return snapshot.Edges()[lhs.entry.edge].id < snapshot.Edges()[rhs.entry.edge].id;
  });

  view.offsets.assign(view.view_to_snapshot_node.size() + 1, 0);
  for (const PendingAdjacency& entry : pending) {
    view.offsets[static_cast<std::size_t>(entry.from) + 1] += 1;
  }
  for (std::size_t i = 0; i < view.view_to_snapshot_node.size(); ++i) {
    view.offsets[i + 1] += view.offsets[i];
  }
  view.adjacency.reserve(pending.size());
  for (const PendingAdjacency& entry : pending) {
    view.adjacency.push_back(entry.entry);
  }

  return build;
}

}  // namespace summon::pathplanner::internal

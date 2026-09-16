#include "pathplanner/graph.hpp"

#include <algorithm>
#include <string>
#include <utility>

#include "pathplanner/version.hpp"

namespace summon::pathplanner {
namespace {

bool Exceeds(std::size_t count, std::uint32_t limit) noexcept {
  return count > static_cast<std::size_t>(limit);
}

template <class Record, class Key>
bool IsSortedUnique(const std::vector<Record>& records, Key key) {
  for (std::size_t i = 1; i < records.size(); ++i) {
    if (!(key(records[i - 1]) < key(records[i]))) {
      return false;
    }
  }
  return true;
}

// Relationship type and path layer must agree; cross-layer composition is not
// implicit in Path Planner 1.0.0.
bool RelationshipMatchesLayer(RelationshipType relationship, PathLayer layer) noexcept {
  switch (relationship) {
    case RelationshipType::kDirectLink:
      return layer == PathLayer::kPhysical;
    case RelationshipType::kPortPairing:
      return layer == PathLayer::kPhysical;
    case RelationshipType::kLogicalAdjacency:
      return layer == PathLayer::kLogical;
    case RelationshipType::kTunnelEncapsulation:
      return layer == PathLayer::kTunnel || layer == PathLayer::kOverlay;
  }
  return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// SubjectKey
// ---------------------------------------------------------------------------
SubjectKey SubjectKey::ForNode(const NodeId& id) noexcept {
  SubjectKey key;
  key.kind = SubjectKind::kNode;
  key.bytes = id.Bytes();
  return key;
}

SubjectKey SubjectKey::ForLink(const LinkId& id) noexcept {
  SubjectKey key;
  key.kind = SubjectKind::kLink;
  key.bytes = id.Bytes();
  return key;
}

SubjectKey SubjectKey::ForPort(const PortId& id) noexcept {
  SubjectKey key;
  key.kind = SubjectKind::kPort;
  key.bytes = id.Bytes();
  return key;
}

std::optional<NodeId> SubjectKey::AsNode() const noexcept {
  if (kind != SubjectKind::kNode) {
    return std::nullopt;
  }
  return NodeId::FromBytes(bytes);
}

std::optional<LinkId> SubjectKey::AsLink() const noexcept {
  if (kind != SubjectKind::kLink) {
    return std::nullopt;
  }
  return LinkId::FromBytes(bytes);
}

std::optional<PortId> SubjectKey::AsPort() const noexcept {
  if (kind != SubjectKind::kPort) {
    return std::nullopt;
  }
  return PortId::FromBytes(bytes);
}

std::string SubjectKey::ToString() const {
  return std::string(EnumName(kSubjectKindNames, kind)) + ":" +
         HexEncode(std::span<const std::byte>(bytes.data(), bytes.size()));
}

std::strong_ordering operator<=>(const SubjectKey& lhs, const SubjectKey& rhs) noexcept {
  if (lhs.kind != rhs.kind) {
    return lhs.kind < rhs.kind ? std::strong_ordering::less : std::strong_ordering::greater;
  }
  for (std::size_t i = 0; i < lhs.bytes.size(); ++i) {
    const auto left = static_cast<unsigned int>(static_cast<std::uint8_t>(lhs.bytes[i]));
    const auto right = static_cast<unsigned int>(static_cast<std::uint8_t>(rhs.bytes[i]));
    if (left < right) {
      return std::strong_ordering::less;
    }
    if (left > right) {
      return std::strong_ordering::greater;
    }
  }
  return std::strong_ordering::equal;
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------
LinkStateView::LinkStateView(std::vector<LinkStateRecord> records) : records_(std::move(records)) {
  std::sort(records_.begin(), records_.end(), [](const LinkStateRecord& lhs, const LinkStateRecord& rhs) {
    return lhs.link < rhs.link;
  });
}

const LinkStateRecord* LinkStateView::Find(const LinkId& link) const noexcept {
  const auto it = std::lower_bound(records_.begin(), records_.end(), link,
                                   [](const LinkStateRecord& record, const LinkId& value) {
                                     return record.link < value;
                                   });
  if (it == records_.end() || it->link != link) {
    return nullptr;
  }
  return &(*it);
}

LinkState LinkStateView::StateOf(const LinkId& link) const noexcept {
  const LinkStateRecord* record = Find(link);
  return record == nullptr ? LinkState::kUnknown : record->state;
}

PortStateView::PortStateView(std::vector<PortStateRecord> records) : records_(std::move(records)) {
  std::sort(records_.begin(), records_.end(), [](const PortStateRecord& lhs, const PortStateRecord& rhs) {
    return lhs.port < rhs.port;
  });
}

const PortStateRecord* PortStateView::Find(const PortId& port) const noexcept {
  const auto it = std::lower_bound(records_.begin(), records_.end(), port,
                                   [](const PortStateRecord& record, const PortId& value) {
                                     return record.port < value;
                                   });
  if (it == records_.end() || it->port != port) {
    return nullptr;
  }
  return &(*it);
}

PortState PortStateView::StateOf(const PortId& port) const noexcept {
  const PortStateRecord* record = Find(port);
  return record == nullptr ? PortState::kUnknown : record->state;
}

CapabilityView::CapabilityView(std::vector<CapabilityBinding> bindings) : bindings_(std::move(bindings)) {
  std::sort(bindings_.begin(), bindings_.end(), [](const CapabilityBinding& lhs, const CapabilityBinding& rhs) {
    if (lhs.subject != rhs.subject) {
      return lhs.subject < rhs.subject;
    }
    return lhs.capability < rhs.capability;
  });
}

std::optional<CapabilityValue> CapabilityView::Lookup(const SubjectKey& subject,
                                                      const CapabilityId& capability) const noexcept {
  const auto it = std::lower_bound(
      bindings_.begin(), bindings_.end(), std::pair<SubjectKey, CapabilityId>(subject, capability),
      [](const CapabilityBinding& binding, const std::pair<SubjectKey, CapabilityId>& key) {
        if (binding.subject != key.first) {
          return binding.subject < key.first;
        }
        return binding.capability < key.second;
      });
  if (it == bindings_.end() || it->subject != subject || it->capability != capability) {
    return std::nullopt;
  }
  return it->value;
}

FailureDomainView::FailureDomainView(std::vector<FailureDomainRecord> domains, bool membership_complete)
    : domains_(std::move(domains)), membership_complete_(membership_complete) {
  std::sort(domains_.begin(), domains_.end(), [](const FailureDomainRecord& lhs, const FailureDomainRecord& rhs) {
    return lhs.domain < rhs.domain;
  });
  membership_.reserve(domains_.size() * 2);
  for (const FailureDomainRecord& record : domains_) {
    for (const SubjectKey& member : record.members) {
      membership_.emplace_back(member, record.domain);
    }
  }
  std::sort(membership_.begin(), membership_.end(),
            [](const std::pair<SubjectKey, FailureDomainId>& lhs, const std::pair<SubjectKey, FailureDomainId>& rhs) {
              if (lhs.first != rhs.first) {
                return lhs.first < rhs.first;
              }
              return lhs.second < rhs.second;
            });
  membership_.erase(std::unique(membership_.begin(), membership_.end()), membership_.end());
}

const FailureDomainRecord* FailureDomainView::FindDomain(const FailureDomainId& domain) const noexcept {
  const auto it = std::lower_bound(domains_.begin(), domains_.end(), domain,
                                   [](const FailureDomainRecord& record, const FailureDomainId& value) {
                                     return record.domain < value;
                                   });
  if (it == domains_.end() || it->domain != domain) {
    return nullptr;
  }
  return &(*it);
}

FailureDomainView::Membership FailureDomainView::MembershipOf(const SubjectKey& subject) const noexcept {
  Membership result;
  const auto it = std::lower_bound(membership_.begin(), membership_.end(), subject,
                                   [](const std::pair<SubjectKey, FailureDomainId>& entry, const SubjectKey& value) {
                                     return entry.first < value;
                                   });
  bool found = false;
  for (auto cursor = it; cursor != membership_.end() && cursor->first == subject; ++cursor) {
    found = true;
    result.domains.push_back(cursor->second);
  }
  result.known = found || membership_complete_;
  return result;
}

// ---------------------------------------------------------------------------
// Generations and evidence
// ---------------------------------------------------------------------------
void SnapshotGenerations::Encode(ByteWriter& writer) const {
  writer.U64(topology.Value());
  writer.U64(link_state.Value());
  writer.U64(ports.Value());
  writer.U64(capabilities.Value());
  writer.U64(failure_domains.Value());
  writer.U64(epoch.Value());
  writer.U64(policy.Value());
  writer.U64(constraints.Value());
}

void EvidenceVector::Encode(ByteWriter& writer) const {
  writer.FixedBytes(snapshot.Span());
  generations.Encode(writer);
  writer.U32(static_cast<std::uint32_t>(source));
  writer.U64(publish_sequence.Value());
}

Currentness ClassifyEvidence(const EvidenceVector& prior, const EvidenceVector& current) noexcept {
  Currentness worst = Currentness::kCurrent;
  if (prior.generations.topology != current.generations.topology) {
    worst = MoreSevere(worst, Currentness::kStaleTopology);
  }
  if (prior.generations.link_state != current.generations.link_state) {
    worst = MoreSevere(worst, Currentness::kStaleLinkState);
  }
  if (prior.generations.ports != current.generations.ports) {
    worst = MoreSevere(worst, Currentness::kStalePortState);
  }
  if (prior.generations.capabilities != current.generations.capabilities) {
    worst = MoreSevere(worst, Currentness::kStaleCapability);
  }
  if (prior.generations.failure_domains != current.generations.failure_domains) {
    worst = MoreSevere(worst, Currentness::kStaleFailureDomain);
  }
  if (prior.generations.policy != current.generations.policy) {
    worst = MoreSevere(worst, Currentness::kStalePolicy);
  }
  if (prior.generations.epoch != current.generations.epoch) {
    worst = MoreSevere(worst, Currentness::kStaleEpoch);
  }
  return worst;
}

// ---------------------------------------------------------------------------
// FabricSnapshot
// ---------------------------------------------------------------------------
const NodeRecord* FabricSnapshot::FindNode(const NodeId& id) const noexcept {
  const auto it = std::lower_bound(nodes_.begin(), nodes_.end(), id,
                                   [](const NodeRecord& record, const NodeId& value) { return record.id < value; });
  if (it == nodes_.end() || it->id != id) {
    return nullptr;
  }
  return &(*it);
}

const EdgeRecord* FabricSnapshot::FindEdge(const LinkId& id) const noexcept {
  const auto it = std::lower_bound(edges_.begin(), edges_.end(), id,
                                   [](const EdgeRecord& record, const LinkId& value) { return record.id < value; });
  if (it == edges_.end() || it->id != id) {
    return nullptr;
  }
  return &(*it);
}

const EndpointRecord* FabricSnapshot::FindEndpoint(const EndpointId& id) const noexcept {
  const auto it = std::lower_bound(endpoints_.begin(), endpoints_.end(), id,
                                   [](const EndpointRecord& record, const EndpointId& value) {
                                     return record.id < value;
                                   });
  if (it == endpoints_.end() || it->id != id) {
    return nullptr;
  }
  return &(*it);
}

EvidenceVector FabricSnapshot::Evidence() const noexcept {
  EvidenceVector evidence;
  evidence.snapshot = Id();
  evidence.generations = generations_;
  evidence.source = source_;
  evidence.publish_sequence = PlanPublishSequence(0);
  return evidence;
}

void FabricSnapshot::Encode(ByteWriter& writer) const {
  writer.U32(kPathEncodingVersion);
  generations_.Encode(writer);
  writer.U32(static_cast<std::uint32_t>(source_));

  writer.VarU64(nodes_.size());
  for (const NodeRecord& node : nodes_) {
    writer.FixedBytes(node.id.Span());
    writer.FixedBytes(node.attachment.Span());
    writer.U64(node.entity_generation.Value());
    writer.U64(node.structural_generation.Value());
    writer.VarU64(node.ports.size());
    for (const PortId& port : node.ports) {
      writer.FixedBytes(port.Span());
    }
  }

  writer.VarU64(edges_.size());
  for (const EdgeRecord& edge : edges_) {
    writer.FixedBytes(edge.id.Span());
    writer.FixedBytes(edge.from.Span());
    writer.FixedBytes(edge.to.Span());
    writer.FixedBytes(edge.from_port.Span());
    writer.FixedBytes(edge.to_port.Span());
    writer.U32(static_cast<std::uint32_t>(edge.layer));
    writer.U32(static_cast<std::uint32_t>(edge.relationship));
    writer.U32(edge.static_cost.Value());
    writer.U64(edge.entity_generation.Value());
    writer.U64(edge.structural_generation.Value());
  }

  writer.VarU64(endpoints_.size());
  for (const EndpointRecord& endpoint : endpoints_) {
    writer.FixedBytes(endpoint.id.Span());
    writer.U32(static_cast<std::uint32_t>(endpoint.endpoint_class));
    writer.FixedBytes(endpoint.node.Span());
    writer.FixedBytes(endpoint.port.Span());
    writer.U64(endpoint.entity_generation.Value());
  }

  writer.VarU64(link_states_.Records().size());
  for (const LinkStateRecord& record : link_states_.Records()) {
    writer.FixedBytes(record.link.Span());
    writer.U32(static_cast<std::uint32_t>(record.state));
  }

  writer.VarU64(port_states_.Records().size());
  for (const PortStateRecord& record : port_states_.Records()) {
    writer.FixedBytes(record.port.Span());
    writer.U32(static_cast<std::uint32_t>(record.state));
  }

  writer.VarU64(capabilities_.Bindings().size());
  for (const CapabilityBinding& binding : capabilities_.Bindings()) {
    writer.U32(static_cast<std::uint32_t>(binding.subject.kind));
    writer.FixedBytes(std::span<const std::byte>(binding.subject.bytes.data(), binding.subject.bytes.size()));
    writer.FixedBytes(binding.capability.Span());
    writer.U64(binding.value.Value());
  }

  writer.VarU64(failure_domains_.Domains().size());
  writer.Bool(failure_domains_.MembershipComplete());
  for (const FailureDomainRecord& record : failure_domains_.Domains()) {
    writer.FixedBytes(record.domain.Span());
    writer.FixedBytes(record.risk_class.Span());
    writer.VarU64(record.members.size());
    for (const SubjectKey& member : record.members) {
      writer.U32(static_cast<std::uint32_t>(member.kind));
      writer.FixedBytes(std::span<const std::byte>(member.bytes.data(), member.bytes.size()));
    }
  }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------
FabricSnapshotBuilder::FabricSnapshotBuilder(ResourceLimits limits) : limits_(limits) {}

void FabricSnapshotBuilder::Reject(DiagnosticCode code) { diagnostics_.push_back(code); }

bool FabricSnapshotBuilder::AddNode(NodeRecord node) {
  if (Exceeds(nodes_.size() + 1, limits_.max_nodes)) {
    Reject(DiagnosticCode::kGraphTooLarge);
    return false;
  }
  if (!node.id.IsValid()) {
    Reject(DiagnosticCode::kMalformedIdentifier);
    return false;
  }
  for (const PortId& port : node.ports) {
    if (!port.IsValid()) {
      Reject(DiagnosticCode::kMalformedIdentifier);
      return false;
    }
  }
  if (Exceeds(node.ports.size(), limits_.max_ports_per_node)) {
    Reject(DiagnosticCode::kGraphTooLarge);
    return false;
  }
  std::vector<PortId> ports = node.ports;
  std::sort(ports.begin(), ports.end());
  for (std::size_t i = 1; i < ports.size(); ++i) {
    if (ports[i - 1] == ports[i]) {
      Reject(DiagnosticCode::kDuplicateIdentifier);
      return false;
    }
  }
  node.ports = std::move(ports);
  if (node.structural_generation.Value() > generations_.topology.Value()) {
    Reject(DiagnosticCode::kTopologyGenerationMismatch);
    return false;
  }
  nodes_.push_back(std::move(node));
  return true;
}

bool FabricSnapshotBuilder::AddEdge(EdgeRecord edge) {
  if (Exceeds(edges_.size() + 1, limits_.max_edges)) {
    Reject(DiagnosticCode::kTooManyEdges);
    return false;
  }
  if (!edge.id.IsValid() || !edge.from.IsValid() || !edge.to.IsValid() || !edge.from_port.IsValid() ||
      !edge.to_port.IsValid()) {
    Reject(DiagnosticCode::kMalformedIdentifier);
    return false;
  }
  if (edge.from == edge.to) {
    Reject(DiagnosticCode::kSelfLoopRejected);
    return false;
  }
  if (!RelationshipMatchesLayer(edge.relationship, edge.layer)) {
    Reject(DiagnosticCode::kLayerMismatch);
    return false;
  }
  if (edge.structural_generation.Value() > generations_.topology.Value()) {
    Reject(DiagnosticCode::kTopologyGenerationMismatch);
    return false;
  }
  edges_.push_back(std::move(edge));
  return true;
}

bool FabricSnapshotBuilder::AddEndpoint(EndpointRecord endpoint) {
  if (Exceeds(endpoints_.size() + 1, limits_.max_endpoints)) {
    Reject(DiagnosticCode::kGraphTooLarge);
    return false;
  }
  if (!endpoint.id.IsValid() || !endpoint.node.IsValid() || !endpoint.port.IsValid()) {
    Reject(DiagnosticCode::kMalformedIdentifier);
    return false;
  }
  endpoints_.push_back(std::move(endpoint));
  return true;
}

void FabricSnapshotBuilder::SetLinkStates(std::vector<LinkStateRecord> records) {
  link_states_ = std::move(records);
}

void FabricSnapshotBuilder::SetPortStates(std::vector<PortStateRecord> records) {
  port_states_ = std::move(records);
}

void FabricSnapshotBuilder::SetCapabilities(std::vector<CapabilityBinding> bindings) {
  capabilities_ = std::move(bindings);
}

void FabricSnapshotBuilder::SetFailureDomains(std::vector<FailureDomainRecord> domains, bool membership_complete) {
  failure_domains_ = std::move(domains);
  membership_complete_ = membership_complete;
}

SnapshotBuildResult FabricSnapshotBuilder::Build() {
  SnapshotBuildResult result;

  if (const std::optional<DiagnosticCode> limit_error = ValidateLimits(limits_); limit_error.has_value()) {
    result.error = limit_error;
    result.detail = "resource limits are incoherent";
    return result;
  }

  std::sort(nodes_.begin(), nodes_.end(), [](const NodeRecord& lhs, const NodeRecord& rhs) {
    return lhs.id < rhs.id;
  });
  if (!IsSortedUnique(nodes_, [](const NodeRecord& record) { return record.id; })) {
    result.error = DiagnosticCode::kDuplicateIdentifier;
    result.detail = "duplicate node identity";
    return result;
  }

  std::sort(edges_.begin(), edges_.end(), [](const EdgeRecord& lhs, const EdgeRecord& rhs) {
    return lhs.id < rhs.id;
  });
  if (!IsSortedUnique(edges_, [](const EdgeRecord& record) { return record.id; })) {
    result.error = DiagnosticCode::kDuplicateIdentifier;
    result.detail = "duplicate link identity";
    return result;
  }

  for (const EdgeRecord& edge : edges_) {
    const auto from_it = std::lower_bound(nodes_.begin(), nodes_.end(), edge.from,
                                          [](const NodeRecord& record, const NodeId& value) {
                                            return record.id < value;
                                          });
    if (from_it == nodes_.end() || from_it->id != edge.from) {
      result.error = DiagnosticCode::kNoStructuralPath;
      result.detail = "edge " + edge.id.ToString() + " references unknown source node";
      return result;
    }
    if (!std::binary_search(from_it->ports.begin(), from_it->ports.end(), edge.from_port)) {
      result.error = DiagnosticCode::kNoStructuralPath;
      result.detail = "edge " + edge.id.ToString() + " references a port not published by its source node";
      return result;
    }
    const auto to_it = std::lower_bound(nodes_.begin(), nodes_.end(), edge.to,
                                        [](const NodeRecord& record, const NodeId& value) {
                                          return record.id < value;
                                        });
    if (to_it == nodes_.end() || to_it->id != edge.to) {
      result.error = DiagnosticCode::kNoStructuralPath;
      result.detail = "edge " + edge.id.ToString() + " references unknown destination node";
      return result;
    }
    if (!std::binary_search(to_it->ports.begin(), to_it->ports.end(), edge.to_port)) {
      result.error = DiagnosticCode::kNoStructuralPath;
      result.detail = "edge " + edge.id.ToString() + " references a port not published by its destination node";
      return result;
    }
  }

  std::sort(endpoints_.begin(), endpoints_.end(), [](const EndpointRecord& lhs, const EndpointRecord& rhs) {
    return lhs.id < rhs.id;
  });
  if (!IsSortedUnique(endpoints_, [](const EndpointRecord& record) { return record.id; })) {
    result.error = DiagnosticCode::kAmbiguousEndpoint;
    result.detail = "duplicate endpoint identity";
    return result;
  }
  for (const EndpointRecord& endpoint : endpoints_) {
    const auto node_it = std::lower_bound(nodes_.begin(), nodes_.end(), endpoint.node,
                                          [](const NodeRecord& record, const NodeId& value) {
                                            return record.id < value;
                                          });
    if (node_it == nodes_.end() || node_it->id != endpoint.node) {
      result.error = DiagnosticCode::kUnknownEndpoint;
      result.detail = "endpoint " + endpoint.id.ToString() + " references an unknown node";
      return result;
    }
    if (!std::binary_search(node_it->ports.begin(), node_it->ports.end(), endpoint.port)) {
      result.error = DiagnosticCode::kUnknownEndpoint;
      result.detail = "endpoint " + endpoint.id.ToString() + " references a port not published by its node";
      return result;
    }
  }

  if (Exceeds(link_states_.size(), limits_.max_link_state_records)) {
    result.error = DiagnosticCode::kGraphTooLarge;
    result.detail = "link state record limit exceeded";
    return result;
  }
  if (Exceeds(port_states_.size(), limits_.max_port_state_records)) {
    result.error = DiagnosticCode::kGraphTooLarge;
    result.detail = "port state record limit exceeded";
    return result;
  }
  if (Exceeds(capabilities_.size(), limits_.max_capability_bindings)) {
    result.error = DiagnosticCode::kGraphTooLarge;
    result.detail = "capability binding limit exceeded";
    return result;
  }
  if (Exceeds(failure_domains_.size(), limits_.max_failure_domains)) {
    result.error = DiagnosticCode::kGraphTooLarge;
    result.detail = "failure domain limit exceeded";
    return result;
  }

  // Duplicate rejection in the consumed views. Silently dropping a duplicate would
  // let two owners disagree about the same subject.
  for (std::size_t i = 1; i < link_states_.size(); ++i) {
    if (link_states_[i - 1].link == link_states_[i].link) {
      result.error = DiagnosticCode::kDuplicateIdentifier;
      result.detail = "duplicate link state record";
      return result;
    }
  }
  for (std::size_t i = 1; i < port_states_.size(); ++i) {
    if (port_states_[i - 1].port == port_states_[i].port) {
      result.error = DiagnosticCode::kDuplicateIdentifier;
      result.detail = "duplicate port state record";
      return result;
    }
  }
  for (std::size_t i = 1; i < capabilities_.size(); ++i) {
    if (capabilities_[i - 1].subject == capabilities_[i].subject &&
        capabilities_[i - 1].capability == capabilities_[i].capability) {
      result.error = DiagnosticCode::kDuplicateIdentifier;
      result.detail = "duplicate capability binding";
      return result;
    }
  }
  for (std::size_t i = 1; i < failure_domains_.size(); ++i) {
    if (failure_domains_[i - 1].domain == failure_domains_[i].domain) {
      result.error = DiagnosticCode::kDuplicateIdentifier;
      result.detail = "duplicate failure domain";
      return result;
    }
  }
  for (FailureDomainRecord& record : failure_domains_) {
    if (!record.domain.IsValid()) {
      result.error = DiagnosticCode::kMalformedIdentifier;
      result.detail = "failure domain identity is nil";
      return result;
    }
    if (Exceeds(record.members.size(), limits_.max_members_per_failure_domain)) {
      result.error = DiagnosticCode::kGraphTooLarge;
      result.detail = "failure domain member limit exceeded";
      return result;
    }
    std::sort(record.members.begin(), record.members.end());
    record.members.erase(std::unique(record.members.begin(), record.members.end()), record.members.end());
  }

  const std::size_t record_count = nodes_.size() + edges_.size() + endpoints_.size() + link_states_.size() +
                                   port_states_.size() + capabilities_.size() + failure_domains_.size();
  const std::size_t ceiling = 1024 + record_count * 128;

  auto snapshot = std::make_shared<FabricSnapshot>();
  snapshot->generations_ = generations_;
  snapshot->source_ = source_;
  snapshot->limits_ = limits_;
  snapshot->nodes_ = std::move(nodes_);
  snapshot->edges_ = std::move(edges_);
  snapshot->endpoints_ = std::move(endpoints_);
  snapshot->link_states_ = LinkStateView(std::move(link_states_));
  snapshot->port_states_ = PortStateView(std::move(port_states_));
  snapshot->capabilities_ = CapabilityView(std::move(capabilities_));
  snapshot->failure_domains_ = FailureDomainView(std::move(failure_domains_), membership_complete_);

  ByteWriter writer(ceiling);
  snapshot->Encode(writer);
  if (writer.overflowed()) {
    result.error = DiagnosticCode::kGraphTooLarge;
    result.detail = "snapshot encoding exceeded its ceiling";
    return result;
  }
  snapshot->digest_ = Sha256::Hash(writer.span());
  if (snapshot->digest_.IsZero()) {
    result.error = DiagnosticCode::kPersistenceCorrupt;
    result.detail = "snapshot digest is degenerate";
    return result;
  }

  result.snapshot = std::move(snapshot);
  return result;
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------
std::optional<DiagnosticCode> ValidateLimits(const ResourceLimits& limits) noexcept {
  if (limits.max_nodes == 0 || limits.max_edges == 0 || limits.max_endpoints == 0 ||
      limits.max_ports_per_node == 0) {
    return DiagnosticCode::kGraphTooLarge;
  }
  if (limits.max_candidates_per_request == 0 || limits.max_candidates_per_request > kMaxCandidateRank) {
    return DiagnosticCode::kCandidateLimitExceeded;
  }
  if (limits.max_hops == 0 || limits.max_hops > kMaxHopCount) {
    return DiagnosticCode::kMaxHopsExceeded;
  }
  if (limits.max_frame_bytes < 64u || limits.max_frame_bytes > (256u << 20)) {
    return DiagnosticCode::kProtocolMalformedFrame;
  }
  if (limits.max_sessions == 0 || limits.max_workers == 0 || limits.max_concurrent_requests == 0) {
    return DiagnosticCode::kProtocolSessionLimit;
  }
  if (limits.receive_bound_ms == 0 || limits.connect_bound_ms == 0 || limits.send_bound_ms == 0) {
    return DiagnosticCode::kProtocolReceiveBoundExceeded;
  }
  if (limits.max_expanded_states == 0 || limits.max_spur_searches == 0 || limits.max_queue_entries == 0) {
    return DiagnosticCode::kWorkBudgetExhausted;
  }
  if (limits.max_retained_plans == 0 || limits.max_history_entries == 0 || limits.max_explanation_entries == 0) {
    return DiagnosticCode::kPersistenceLimitExceeded;
  }
  if (limits.max_constraints_total == 0 || limits.max_forbidden_ids == 0 || limits.max_required_ids == 0) {
    return DiagnosticCode::kConstraintCountExceeded;
  }
  if (limits.max_required_any_sets == 0 || limits.max_members_in_any_set == 0) {
    return DiagnosticCode::kConstraintCountExceeded;
  }
  return std::nullopt;
}

std::optional<DiagnosticCode> ResourceLimits::Validate() const noexcept { return ValidateLimits(*this); }

}  // namespace summon::pathplanner

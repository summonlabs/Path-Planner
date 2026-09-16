#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "pathplanner/canonical.hpp"
#include "pathplanner/ids.hpp"
#include "pathplanner/limits.hpp"
#include "pathplanner/sha256.hpp"
#include "pathplanner/status.hpp"

namespace summon::pathplanner {

// ---------------------------------------------------------------------------
// Subject kinds: which authoritative runtime owns a record.
// ---------------------------------------------------------------------------
enum class SubjectKind : std::uint32_t {
  kNode = 1,
  kLink = 2,
  kPort = 3,
};

inline constexpr EnumEntry kSubjectKindNames[] = {
    {"NODE", 1},
    {"LINK", 2},
    {"PORT", 3},
};

inline std::string_view ToString(SubjectKind value) { return EnumName(kSubjectKindNames, value); }
inline std::optional<SubjectKind> ParseSubjectKind(std::string_view name) { return ParseEnum<SubjectKind>(kSubjectKindNames, name); }

// A subject key is a typed 16-byte identifier plus its kind. Fabric Topology
// issues node/link/port identities; Path Planner only consumes them.
struct SubjectKey {
  SubjectKind kind = SubjectKind::kNode;
  std::array<std::byte, 16> bytes{};

  static SubjectKey ForNode(const NodeId& id) noexcept;
  static SubjectKey ForLink(const LinkId& id) noexcept;
  static SubjectKey ForPort(const PortId& id) noexcept;
  std::optional<NodeId> AsNode() const noexcept;
  std::optional<LinkId> AsLink() const noexcept;
  std::optional<PortId> AsPort() const noexcept;
  std::string ToString() const;

  friend bool operator==(const SubjectKey& lhs, const SubjectKey& rhs) noexcept {
    return lhs.kind == rhs.kind && lhs.bytes == rhs.bytes;
  }
  friend bool operator!=(const SubjectKey& lhs, const SubjectKey& rhs) noexcept { return !(lhs == rhs); }
  friend std::strong_ordering operator<=>(const SubjectKey& lhs, const SubjectKey& rhs) noexcept;
};

// ---------------------------------------------------------------------------
// Fabric Topology records (consumed, never issued here).
// ---------------------------------------------------------------------------
struct NodeRecord {
  NodeId id;
  SwitchId attachment;                 // owning switch/router; nil for host-level nodes
  EntityGeneration entity_generation;
  TopologyGeneration structural_generation;
  std::vector<PortId> ports;           // sorted, unique
};

struct EdgeRecord {
  LinkId id;
  NodeId from;
  NodeId to;
  PortId from_port;
  PortId to_port;
  PathLayer layer = PathLayer::kPhysical;
  RelationshipType relationship = RelationshipType::kDirectLink;
  StaticCost static_cost{};            // administrative static cost (topology owned)
  EntityGeneration entity_generation;
  TopologyGeneration structural_generation;
};

// Endpoint binding resolved by Fabric Registry and published as planning input.
// A missing binding rejects explicitly; nothing is inferred from naming.
struct EndpointRecord {
  EndpointId id;
  EndpointClass endpoint_class = EndpointClass::kEndpoint;
  NodeId node;
  PortId port;
  EntityGeneration entity_generation;
};

// ---------------------------------------------------------------------------
// Link State Fabric view.
// ---------------------------------------------------------------------------
struct LinkStateRecord {
  LinkId link;
  LinkState state = LinkState::kUnknown;
};

class LinkStateView {
 public:
  LinkStateView() = default;
  explicit LinkStateView(std::vector<LinkStateRecord> records);

  const std::vector<LinkStateRecord>& Records() const noexcept { return records_; }
  const LinkStateRecord* Find(const LinkId& link) const noexcept;
  // Absence means "no authoritative operational record" => UNKNOWN, which is
  // never treated as UP.
  LinkState StateOf(const LinkId& link) const noexcept;
  std::size_t Size() const noexcept { return records_.size(); }

 private:
  std::vector<LinkStateRecord> records_;
};

// ---------------------------------------------------------------------------
// Port Fabric view.
// ---------------------------------------------------------------------------
struct PortStateRecord {
  PortId port;
  PortState state = PortState::kUnknown;
};

class PortStateView {
 public:
  PortStateView() = default;
  explicit PortStateView(std::vector<PortStateRecord> records);

  const std::vector<PortStateRecord>& Records() const noexcept { return records_; }
  const PortStateRecord* Find(const PortId& port) const noexcept;
  PortState StateOf(const PortId& port) const noexcept;
  std::size_t Size() const noexcept { return records_.size(); }

 private:
  std::vector<PortStateRecord> records_;
};

// ---------------------------------------------------------------------------
// Fabric Capability Registry view.
//
// Absence of a binding means UNKNOWN. UNKNOWN never satisfies a requirement;
// capabilities are never inferred from device names or vendors.
// ---------------------------------------------------------------------------
struct CapabilityBinding {
  SubjectKey subject;
  CapabilityId capability;
  CapabilityValue value;
};

class CapabilityView {
 public:
  CapabilityView() = default;
  explicit CapabilityView(std::vector<CapabilityBinding> bindings);

  const std::vector<CapabilityBinding>& Bindings() const noexcept { return bindings_; }
  // nullopt == UNKNOWN.
  std::optional<CapabilityValue> Lookup(const SubjectKey& subject, const CapabilityId& capability) const noexcept;
  std::size_t Size() const noexcept { return bindings_.size(); }

 private:
  std::vector<CapabilityBinding> bindings_;
};

// ---------------------------------------------------------------------------
// Failure Domain Registry view.
// ---------------------------------------------------------------------------
struct FailureDomainRecord {
  FailureDomainId domain;
  FailureDomainClass risk_class;
  // Members are published by the registry; membership is never inferred.
  std::vector<SubjectKey> members;
};

class FailureDomainView {
 public:
  FailureDomainView() = default;
  FailureDomainView(std::vector<FailureDomainRecord> domains, bool membership_complete);

  const std::vector<FailureDomainRecord>& Domains() const noexcept { return domains_; }
  std::size_t Size() const noexcept { return domains_.size(); }

  // True when the registry published complete membership. When false, an entity
  // without a membership record has UNKNOWN membership and constraint checks
  // that need proof fail closed.
  bool MembershipComplete() const noexcept { return membership_complete_; }

  const FailureDomainRecord* FindDomain(const FailureDomainId& domain) const noexcept;

  // Membership lookup result: known list, or unknown.
  struct Membership {
    bool known = false;
    std::vector<FailureDomainId> domains;
  };
  Membership MembershipOf(const SubjectKey& subject) const noexcept;

 private:
  std::vector<FailureDomainRecord> domains_;   // sorted by domain id
  // Sorted (subject, domain) pairs for deterministic lookup.
  std::vector<std::pair<SubjectKey, FailureDomainId>> membership_;
  bool membership_complete_ = false;
};

// ---------------------------------------------------------------------------
// Snapshot generation binding.
// ---------------------------------------------------------------------------
struct SnapshotGenerations {
  TopologyGeneration topology;
  LinkStateGeneration link_state;
  PortGeneration ports;
  CapabilityGeneration capabilities;
  FailureDomainGeneration failure_domains;
  FabricEpoch epoch;
  PolicyGeneration policy;
  ConstraintGeneration constraints;

  friend bool operator==(const SnapshotGenerations& lhs, const SnapshotGenerations& rhs) noexcept {
    return lhs.topology == rhs.topology && lhs.link_state == rhs.link_state && lhs.ports == rhs.ports &&
           lhs.capabilities == rhs.capabilities && lhs.failure_domains == rhs.failure_domains &&
           lhs.epoch == rhs.epoch && lhs.policy == rhs.policy && lhs.constraints == rhs.constraints;
  }
  friend bool operator!=(const SnapshotGenerations& lhs, const SnapshotGenerations& rhs) noexcept {
    return !(lhs == rhs);
  }
  void Encode(ByteWriter& writer) const;
};

// ---------------------------------------------------------------------------
// Evidence vector: the exact input generations a plan was computed from.
// ---------------------------------------------------------------------------
struct EvidenceVector {
  SnapshotId snapshot;
  SnapshotGenerations generations;
  EvidenceSource source = EvidenceSource::kSynthetic;
  // Runtime-level monotonic publication sequence at snapshot capture time. Used
  // as an invalidation watermark so an in-flight plan cannot publish as CURRENT
  // after a newer snapshot was published.
  PlanPublishSequence publish_sequence;

  friend bool operator==(const EvidenceVector& lhs, const EvidenceVector& rhs) noexcept {
    return lhs.snapshot == rhs.snapshot && lhs.generations == rhs.generations && lhs.source == rhs.source &&
           lhs.publish_sequence == rhs.publish_sequence;
  }
  void Encode(ByteWriter& writer) const;
};

// Classification of how a prior evidence vector relates to a current one.
Currentness ClassifyEvidence(const EvidenceVector& prior, const EvidenceVector& current) noexcept;

// ---------------------------------------------------------------------------
// FabricSnapshot: immutable, coherent, generation-bound planning input.
//
// The value is produced by FabricSnapshotBuilder, is deeply immutable once
// built, and may be shared across threads by const reference.
// ---------------------------------------------------------------------------
class FabricSnapshot {
 public:
  const SnapshotGenerations& Generations() const noexcept { return generations_; }
  const std::vector<NodeRecord>& Nodes() const noexcept { return nodes_; }
  const std::vector<EdgeRecord>& Edges() const noexcept { return edges_; }
  const std::vector<EndpointRecord>& Endpoints() const noexcept { return endpoints_; }
  const LinkStateView& LinkStates() const noexcept { return link_states_; }
  const PortStateView& PortStates() const noexcept { return port_states_; }
  const CapabilityView& Capabilities() const noexcept { return capabilities_; }
  const FailureDomainView& FailureDomains() const noexcept { return failure_domains_; }
  EvidenceSource Source() const noexcept { return source_; }
  const ResourceLimits& Limits() const noexcept { return limits_; }

  const Sha256Digest& Digest() const noexcept { return digest_; }
  SnapshotId Id() const noexcept { return SnapshotId::FromDigest(digest_); }

  std::size_t NodeCount() const noexcept { return nodes_.size(); }
  std::size_t EdgeCount() const noexcept { return edges_.size(); }

  const NodeRecord* FindNode(const NodeId& id) const noexcept;
  const EdgeRecord* FindEdge(const LinkId& id) const noexcept;
  const EndpointRecord* FindEndpoint(const EndpointId& id) const noexcept;

  EvidenceVector Evidence() const noexcept;

  // Canonical encoding used for the snapshot digest.
  void Encode(ByteWriter& writer) const;

 private:
  friend class FabricSnapshotBuilder;

  SnapshotGenerations generations_;
  EvidenceSource source_ = EvidenceSource::kSynthetic;
  ResourceLimits limits_;
  std::vector<NodeRecord> nodes_;
  std::vector<EdgeRecord> edges_;
  std::vector<EndpointRecord> endpoints_;
  LinkStateView link_states_;
  PortStateView port_states_;
  CapabilityView capabilities_;
  FailureDomainView failure_domains_;
  Sha256Digest digest_;
};

// ---------------------------------------------------------------------------
// Builder. Rejects duplicates, dangling references, self loops, layer
// violations, impossible generations and limit breaches.
// ---------------------------------------------------------------------------
struct SnapshotBuildResult {
  std::shared_ptr<const FabricSnapshot> snapshot;
  std::optional<DiagnosticCode> error;
  // Subject of the rejected record when the error is about a specific record.
  std::string detail;

  bool ok() const noexcept { return snapshot != nullptr; }
};

class FabricSnapshotBuilder {
 public:
  explicit FabricSnapshotBuilder(ResourceLimits limits = ResourceLimits{});

  void SetGenerations(const SnapshotGenerations& generations) noexcept { generations_ = generations; }
  void SetSource(EvidenceSource source) noexcept { source_ = source; }

  // Each Add returns false when the record is rejected; the diagnostics vector
  // then holds the structured reason.
  bool AddNode(NodeRecord node);
  bool AddEdge(EdgeRecord edge);
  bool AddEndpoint(EndpointRecord endpoint);
  void SetLinkStates(std::vector<LinkStateRecord> records);
  void SetPortStates(std::vector<PortStateRecord> records);
  void SetCapabilities(std::vector<CapabilityBinding> bindings);
  void SetFailureDomains(std::vector<FailureDomainRecord> domains, bool membership_complete);

  const std::vector<DiagnosticCode>& Diagnostics() const noexcept { return diagnostics_; }
  void ClearDiagnostics() noexcept { diagnostics_.clear(); }

  SnapshotBuildResult Build();

 private:
  void Reject(DiagnosticCode code);

  ResourceLimits limits_;
  SnapshotGenerations generations_;
  EvidenceSource source_ = EvidenceSource::kSynthetic;
  std::vector<NodeRecord> nodes_;
  std::vector<EdgeRecord> edges_;
  std::vector<EndpointRecord> endpoints_;
  std::vector<LinkStateRecord> link_states_;
  std::vector<PortStateRecord> port_states_;
  std::vector<CapabilityBinding> capabilities_;
  std::vector<FailureDomainRecord> failure_domains_;
  bool membership_complete_ = false;
  std::vector<DiagnosticCode> diagnostics_;
};

}  // namespace summon::pathplanner

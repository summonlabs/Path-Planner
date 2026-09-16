#include "pathplanner/proto.hpp"

#include <array>
#include <string>
#include <type_traits>
#include <utility>

namespace summon::pathplanner {
namespace {

constexpr std::size_t kHeaderIntegrityOffset = kWireHeaderBytes - kWireIntegrityBytes;

template <class Enum, std::size_t N>
bool DecodeEnumValue(ByteReader& reader, const EnumEntry (&table)[N], Enum& out, std::string& detail,
                     const char* name) {
  const std::optional<std::uint32_t> raw = reader.U32();
  if (!raw.has_value()) {
    detail = std::string(name) + ": missing value";
    return false;
  }
  if (!IsKnownEnumValue<Enum>(table, *raw)) {
    detail = std::string(name) + ": unknown enumeration value " + std::to_string(*raw);
    return false;
  }
  out = static_cast<Enum>(*raw);
  return true;
}

template <class Id>
void EncodeId(ByteWriter& writer, const Id& id) {
  writer.FixedBytes(id.Span());
}

template <class Id>
bool DecodeId(ByteReader& reader, Id& id, std::string& detail, const char* name) {
  std::array<std::byte, Id::kByteCount> bytes{};
  if (!reader.FixedBytes(std::span<std::byte>(bytes.data(), bytes.size()))) {
    detail = std::string(name) + ": truncated identifier";
    return false;
  }
  id = Id::FromBytes(bytes);
  if (!id.IsValid()) {
    detail = std::string(name) + ": nil identifier rejected";
    return false;
  }
  return true;
}

template <class Strong>
bool DecodeStrong(ByteReader& reader, Strong& out, std::string& detail, const char* name) {
  const std::optional<std::uint64_t> raw = reader.U64();
  if (!raw.has_value()) {
    detail = std::string(name) + ": missing value";
    return false;
  }
  const std::optional<Strong> typed = Strong::TryFrom(*raw);
  if (!typed.has_value()) {
    detail = std::string(name) + ": value out of range";
    return false;
  }
  out = *typed;
  return true;
}

template <class Strong>
void EncodeStrong(ByteWriter& writer, Strong value) {
  writer.U64(value.Value());
}

void EncodeGenerations(ByteWriter& writer, const SnapshotGenerations& generations) { generations.Encode(writer); }

bool DecodeGenerations(ByteReader& reader, SnapshotGenerations& generations, std::string& detail) {
  return DecodeStrong(reader, generations.topology, detail, "topology generation") &&
         DecodeStrong(reader, generations.link_state, detail, "link-state generation") &&
         DecodeStrong(reader, generations.ports, detail, "port generation") &&
         DecodeStrong(reader, generations.capabilities, detail, "capability generation") &&
         DecodeStrong(reader, generations.failure_domains, detail, "failure-domain generation") &&
         DecodeStrong(reader, generations.epoch, detail, "fabric epoch") &&
         DecodeStrong(reader, generations.policy, detail, "policy generation") &&
         DecodeStrong(reader, generations.constraints, detail, "constraint generation");
}

void EncodeEvidence(ByteWriter& writer, const EvidenceVector& evidence) { evidence.Encode(writer); }

bool DecodeEvidence(ByteReader& reader, EvidenceVector& evidence, std::string& detail) {
  if (!DecodeId(reader, evidence.snapshot, detail, "snapshot identity")) {
    return false;
  }
  if (!DecodeGenerations(reader, evidence.generations, detail)) {
    return false;
  }
  if (!DecodeEnumValue(reader, kEvidenceSourceNames, evidence.source, detail, "evidence source")) {
    return false;
  }
  return DecodeStrong(reader, evidence.publish_sequence, detail, "publish sequence");
}

bool DecodePath(ByteReader& reader, const ResourceLimits& limits, CandidatePath& path, std::string& detail) {
  const std::optional<std::uint32_t> encoding_version = reader.U32();
  if (!encoding_version.has_value() || *encoding_version != kPathEncodingVersion) {
    detail = "path encoding version mismatch";
    return false;
  }
  if (!DecodeId(reader, path.source, detail, "path source") ||
      !DecodeId(reader, path.destination, detail, "path destination")) {
    return false;
  }
  if (!DecodeEnumValue(reader, kPathLayerNames, path.layer, detail, "path layer")) {
    return false;
  }
  const std::optional<std::uint64_t> hop_count = reader.VarU64();
  if (!hop_count.has_value() || *hop_count > static_cast<std::uint64_t>(limits.max_hops)) {
    detail = "path hop count exceeds the configured limit";
    return false;
  }
  path.hops.clear();
  path.hops.reserve(static_cast<std::size_t>(*hop_count));
  for (std::uint64_t index = 0; index < *hop_count; ++index) {
    PathHop hop;
    if (!DecodeId(reader, hop.link, detail, "hop link") || !DecodeId(reader, hop.from, detail, "hop source") ||
        !DecodeId(reader, hop.to, detail, "hop destination") ||
        !DecodeId(reader, hop.from_port, detail, "hop source port") ||
        !DecodeId(reader, hop.to_port, detail, "hop destination port")) {
      return false;
    }
    if (!DecodeEnumValue(reader, kPathLayerNames, hop.layer, detail, "hop layer") ||
        !DecodeEnumValue(reader, kRelationshipTypeNames, hop.relationship, detail, "hop relationship")) {
      return false;
    }
    if (!DecodeStrong(reader, hop.structural_generation, detail, "hop structural generation")) {
      return false;
    }
    const std::optional<std::uint32_t> static_cost = reader.U32();
    if (!static_cost.has_value()) {
      detail = "hop static cost is missing";
      return false;
    }
    hop.static_cost = StaticCost(*static_cost);
    hop.link_state = LinkState::kUnknown;
    path.hops.push_back(hop);
  }
  path.nodes.assign(path.hops.size() + 1, NodeId{});
  path.nodes.front() = path.source;
  for (std::size_t index = 0; index < path.hops.size(); ++index) {
    path.nodes[index + 1] = path.hops[index].to;
  }
  if (!path.IsWellFormed()) {
    detail = "decoded path is not well formed";
    return false;
  }
  if (!path.IsSimple()) {
    detail = "decoded path is not simple";
    return false;
  }
  return true;
}

void EncodePath(ByteWriter& writer, const CandidatePath& path) { path.Encode(writer); }

void EncodeCost(ByteWriter& writer, const PathCost& cost) {
  writer.U64(cost.total.Value());
  writer.U64(cost.hops_cost.Value());
  writer.U64(cost.static_cost.Value());
  writer.U64(cost.degraded_penalty.Value());
  writer.U64(cost.locality_penalty.Value());
  writer.U32(cost.hops.Value());
  writer.U32(cost.degraded_hops);
  writer.U32(cost.locality_breaches);
}

bool DecodeCost(ByteReader& reader, PathCost& cost, std::string& detail) {
  const std::optional<std::uint64_t> total = reader.U64();
  const std::optional<std::uint64_t> hops_cost = reader.U64();
  const std::optional<std::uint64_t> static_cost = reader.U64();
  const std::optional<std::uint64_t> degraded = reader.U64();
  const std::optional<std::uint64_t> locality = reader.U64();
  const std::optional<std::uint32_t> hops = reader.U32();
  const std::optional<std::uint32_t> degraded_hops = reader.U32();
  const std::optional<std::uint32_t> locality_breaches = reader.U32();
  if (!total.has_value() || !hops_cost.has_value() || !static_cost.has_value() || !degraded.has_value() ||
      !locality.has_value() || !hops.has_value() || !degraded_hops.has_value() || !locality_breaches.has_value()) {
    detail = "path cost is truncated";
    return false;
  }
  const std::optional<HopCount> typed_hops = HopCount::TryFrom(*hops);
  if (!typed_hops.has_value()) {
    detail = "path cost hop count out of range";
    return false;
  }
  cost.total = CostValue(*total);
  cost.hops_cost = CostValue(*hops_cost);
  cost.static_cost = CostValue(*static_cost);
  cost.degraded_penalty = CostValue(*degraded);
  cost.locality_penalty = CostValue(*locality);
  cost.hops = *typed_hops;
  cost.degraded_hops = *degraded_hops;
  cost.locality_breaches = *locality_breaches;
  const std::optional<CostValue> sum = CheckedAdd(cost.hops_cost, cost.static_cost);
  if (!sum.has_value()) {
    detail = "path cost components overflow";
    return false;
  }
  std::optional<CostValue> accumulated = sum;
  accumulated = CheckedAdd(*accumulated, cost.degraded_penalty);
  if (!accumulated.has_value()) {
    detail = "path cost components overflow";
    return false;
  }
  accumulated = CheckedAdd(*accumulated, cost.locality_penalty);
  if (!accumulated.has_value() || *accumulated != cost.total) {
    detail = "path cost does not equal the sum of its documented components";
    return false;
  }
  if (cost.degraded_hops > cost.hops.Value() || cost.locality_breaches > cost.hops.Value()) {
    detail = "path cost penalty counts exceed the hop count";
    return false;
  }
  return true;
}

}  // namespace

DiagnosticCode DiagnosticForWireStatus(WireStatus status) noexcept {
  switch (status) {
    case WireStatus::kVersionMismatch:
      return DiagnosticCode::kProtocolVersionMismatch;
    case WireStatus::kIntegrityMismatch:
      return DiagnosticCode::kProtocolIntegrityMismatch;
    case WireStatus::kUnknownMessage:
      return DiagnosticCode::kProtocolUnknownMessage;
    case WireStatus::kTrailingBytes:
      return DiagnosticCode::kProtocolTrailingBytes;
    case WireStatus::kTooLarge:
      return DiagnosticCode::kProtocolMalformedFrame;
    case WireStatus::kReceiveBoundExceeded:
      return DiagnosticCode::kProtocolReceiveBoundExceeded;
    case WireStatus::kSessionLimit:
      return DiagnosticCode::kProtocolSessionLimit;
    case WireStatus::kWorkerFenced:
      return DiagnosticCode::kWorkerBootFenced;
    case WireStatus::kEpochStale:
      return DiagnosticCode::kCoordinatorEpochStale;
    default:
      return DiagnosticCode::kProtocolMalformedFrame;
  }
}

std::vector<std::byte> EncodeFrame(const WireFrame& frame) {
  const std::size_t payload_bytes = frame.payload.size();
  ByteWriter header(kWireHeaderBytes);
  header.U32(kWireMagicValue);
  header.U16(kWireProtocolVersion);
  header.U16(frame.flags);
  header.U32(static_cast<std::uint32_t>(frame.type));
  header.U64(frame.coordinator_epoch.Value());
  header.U64(frame.sequence);
  header.FixedBytes(frame.worker_boot.Span());
  header.FixedBytes(frame.request.Span());
  header.U32(static_cast<std::uint32_t>(payload_bytes));
  header.U32(0);  // reserved, always zero

  Sha256 hasher;
  hasher.Update(header.span());
  hasher.Update(std::span<const std::byte>(frame.payload.data(), frame.payload.size()));
  const Sha256Digest digest = hasher.Finish();

  std::vector<std::byte> out;
  out.reserve(kWireHeaderBytes + payload_bytes);
  out.insert(out.end(), header.data().begin(), header.data().end());
  out.insert(out.end(), digest.bytes.begin(), digest.bytes.begin() + static_cast<std::ptrdiff_t>(kWireIntegrityBytes));
  out.insert(out.end(), frame.payload.begin(), frame.payload.end());
  return out;
}

WireStatus DecodeFrame(std::span<const std::byte> bytes, std::uint32_t max_frame_bytes, WireFrame& out,
                       std::string& detail) {
  if (bytes.size() < kWireHeaderBytes) {
    detail = "frame shorter than the fixed header";
    return WireStatus::kMalformed;
  }
  ByteReader reader(bytes);
  const std::optional<std::uint32_t> magic = reader.U32();
  if (!magic.has_value() || *magic != kWireMagicValue) {
    detail = "frame magic mismatch";
    return WireStatus::kMalformed;
  }
  const std::optional<std::uint16_t> protocol = reader.U16();
  if (!protocol.has_value() || *protocol != kWireProtocolVersion) {
    detail = "unsupported wire protocol version";
    return WireStatus::kVersionMismatch;
  }
  const std::optional<std::uint16_t> flags = reader.U16();
  if (!flags.has_value() || (*flags & ~kWireKnownFlags) != 0) {
    detail = "unknown frame flag bits";
    return WireStatus::kMalformed;
  }
  const std::optional<std::uint32_t> type = reader.U32();
  if (!type.has_value() || !IsKnownEnumValue<WireMessage>(kWireMessageNames, *type)) {
    detail = "unknown message type";
    return WireStatus::kUnknownMessage;
  }
  WireFrame frame;
  frame.flags = *flags;
  frame.type = static_cast<WireMessage>(*type);

  const std::optional<std::uint64_t> epoch = reader.U64();
  const std::optional<std::uint64_t> sequence = reader.U64();
  if (!epoch.has_value() || !sequence.has_value()) {
    detail = "frame epoch or sequence is truncated";
    return WireStatus::kMalformed;
  }
  frame.coordinator_epoch = CoordinatorEpoch(*epoch);
  frame.sequence = *sequence;
  // The worker boot identity is absent (nil) on frames that do not originate from a
  // worker, so the frame codec accepts nil here; every worker publication path treats a
  // nil or unregistered identity as UNKNOWN_WORKER.
  std::array<std::byte, WorkerBootId::kByteCount> worker_boot_bytes{};
  if (!reader.FixedBytes(std::span<std::byte>(worker_boot_bytes.data(), worker_boot_bytes.size()))) {
    detail = "frame worker boot identity is truncated";
    return WireStatus::kMalformed;
  }
  frame.worker_boot = WorkerBootId::FromBytes(worker_boot_bytes);
  PlanningRequestId request_id;
  std::array<std::byte, PlanningRequestId::kByteCount> request_bytes{};
  if (!reader.FixedBytes(std::span<std::byte>(request_bytes.data(), request_bytes.size()))) {
    detail = "frame request identity is truncated";
    return WireStatus::kMalformed;
  }
  frame.request = PlanningRequestId::FromBytes(request_bytes);
  const std::optional<std::uint32_t> payload_bytes = reader.U32();
  const std::optional<std::uint32_t> reserved = reader.U32();
  if (!payload_bytes.has_value() || !reserved.has_value()) {
    detail = "frame length fields are truncated";
    return WireStatus::kMalformed;
  }
  if (*reserved != 0) {
    detail = "reserved header field must be zero";
    return WireStatus::kMalformed;
  }
  if (*payload_bytes > max_frame_bytes) {
    detail = "frame payload exceeds the configured ceiling";
    return WireStatus::kTooLarge;
  }
  const std::size_t declared_size = kWireHeaderBytes + static_cast<std::size_t>(*payload_bytes);
  if (bytes.size() < declared_size) {
    detail = "frame is shorter than the declared payload size";
    return WireStatus::kMalformed;
  }
  if (bytes.size() > declared_size) {
    detail = "frame carries trailing bytes";
    return WireStatus::kTrailingBytes;
  }

  Sha256 hasher;
  hasher.Update(bytes.subspan(0, kHeaderIntegrityOffset));
  hasher.Update(bytes.subspan(kWireHeaderBytes, *payload_bytes));
  const Sha256Digest expected = hasher.Finish();
  for (std::size_t index = 0; index < kWireIntegrityBytes; ++index) {
    if (bytes[kHeaderIntegrityOffset + index] != expected.bytes[index]) {
      detail = "frame integrity check failed";
      return WireStatus::kIntegrityMismatch;
    }
  }

  frame.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(kWireHeaderBytes), bytes.end());
  out = std::move(frame);
  return WireStatus::kOk;
}

void EncodeHelloPayload(ByteWriter& writer, const HelloPayload& payload) {
  EncodeId(writer, payload.publisher);
  EncodeId(writer, payload.boot);
  EncodeStrong(writer, payload.coordinator_epoch);
  EncodeId(writer, payload.snapshot);
  EncodeGenerations(writer, payload.generations);
  writer.U32(payload.node_count);
  writer.U32(payload.edge_count);
}

WireStatus DecodeHelloPayload(std::span<const std::byte> bytes, HelloPayload& payload, std::string& detail) {
  ByteReader reader(bytes);
  if (!DecodeId(reader, payload.publisher, detail, "publisher identity") ||
      !DecodeId(reader, payload.boot, detail, "worker boot identity") ||
      !DecodeStrong(reader, payload.coordinator_epoch, detail, "coordinator epoch") ||
      !DecodeId(reader, payload.snapshot, detail, "snapshot identity") ||
      !DecodeGenerations(reader, payload.generations, detail)) {
    return WireStatus::kMalformed;
  }
  const std::optional<std::uint32_t> nodes = reader.U32();
  const std::optional<std::uint32_t> edges = reader.U32();
  if (!nodes.has_value() || !edges.has_value()) {
    detail = "hello payload is truncated";
    return WireStatus::kMalformed;
  }
  payload.node_count = *nodes;
  payload.edge_count = *edges;
  if (!reader.AtEnd()) {
    detail = "hello payload carries trailing bytes";
    return WireStatus::kTrailingBytes;
  }
  return WireStatus::kOk;
}

void EncodePlanningRequestPayload(ByteWriter& writer, const PlanningRequest& request) {
  EncodeId(writer, request.id);
  EncodeId(writer, request.source.id);
  writer.U32(static_cast<std::uint32_t>(request.source.endpoint_class));
  EncodeStrong(writer, request.source.generation);
  EncodeId(writer, request.destination.id);
  writer.U32(static_cast<std::uint32_t>(request.destination.endpoint_class));
  EncodeStrong(writer, request.destination.generation);

  const ConstraintSet& constraints = request.constraints;
  EncodeId(writer, constraints.id);
  EncodeStrong(writer, constraints.generation);
  writer.U32(static_cast<std::uint32_t>(constraints.layer));
  writer.VarU64(constraints.forbidden_nodes.size());
  for (const NodeId& id : constraints.forbidden_nodes) {
    EncodeId(writer, id);
  }
  writer.VarU64(constraints.forbidden_links.size());
  for (const LinkId& id : constraints.forbidden_links) {
    EncodeId(writer, id);
  }
  writer.VarU64(constraints.forbidden_ports.size());
  for (const PortId& id : constraints.forbidden_ports) {
    EncodeId(writer, id);
  }
  writer.VarU64(constraints.forbidden_failure_domains.size());
  for (const FailureDomainId& id : constraints.forbidden_failure_domains) {
    EncodeId(writer, id);
  }
  writer.VarU64(constraints.forbidden_failure_domain_classes.size());
  for (const FailureDomainClass& id : constraints.forbidden_failure_domain_classes) {
    EncodeId(writer, id);
  }
  writer.VarU64(constraints.required_transit.size());
  for (const TransitStage& stage : constraints.required_transit) {
    writer.U32(static_cast<std::uint32_t>(stage.kind));
    writer.VarU64(stage.alternatives.size());
    for (const NodeId& id : stage.alternatives) {
      EncodeId(writer, id);
    }
  }
  writer.VarU64(constraints.required_capabilities.size());
  for (const CapabilityRequirement& requirement : constraints.required_capabilities) {
    EncodeId(writer, requirement.capability);
    writer.U32(static_cast<std::uint32_t>(requirement.scope));
    writer.U32(static_cast<std::uint32_t>(requirement.comparator));
    EncodeStrong(writer, requirement.value);
  }
  writer.Bool(constraints.max_hops.has_value());
  if (constraints.max_hops.has_value()) {
    writer.U32(constraints.max_hops->Value());
  }
  writer.Bool(constraints.max_members_per_failure_domain.has_value());
  if (constraints.max_members_per_failure_domain.has_value()) {
    writer.U32(*constraints.max_members_per_failure_domain);
  }
  writer.Bool(constraints.fail_closed_on_unknown_domains);

  const PlanningPolicy& policy = request.policy;
  EncodeStrong(writer, policy.generation);
  EncodeStrong(writer, policy.cost_model.hop_cost);
  EncodeStrong(writer, policy.cost_model.degraded_penalty);
  EncodeStrong(writer, policy.cost_model.locality_penalty);
  writer.Bool(policy.allow_degraded_links);
  writer.Bool(policy.allow_draining_ports);
  writer.Bool(policy.allow_maintenance_ports);
  writer.Bool(policy.require_operational_proof);
  writer.Bool(policy.allow_zero_hop_self_path);
  writer.VarU64(policy.locality_scope.size());
  for (const NodeId& id : policy.locality_scope) {
    EncodeId(writer, id);
  }
  writer.U32(static_cast<std::uint32_t>(policy.authority_validation));

  writer.U32(request.max_candidates);
  writer.U32(static_cast<std::uint32_t>(request.mode));
  writer.U32(request.authority.scope_mask);
  EncodeId(writer, request.authority.publisher);
  EncodeId(writer, request.authority.worker_boot);
  EncodeStrong(writer, request.authority.coordinator_epoch);
  EncodeId(writer, request.authority.attempt);
  writer.Bool(request.authority.epoch_bound);
  writer.Bool(request.authority.enforce_scope);
  writer.Bool(request.expect_epoch);
  EncodeStrong(writer, request.expected_epoch);
  writer.Bool(request.expect_topology);
  EncodeStrong(writer, request.expected_topology);
  writer.Bool(request.expect_snapshot);
  EncodeId(writer, request.expected_snapshot);
}

namespace {

bool DecodeIdVector(ByteReader& reader, std::uint64_t count, std::uint32_t limit, std::vector<NodeId>& out,
                    std::string& detail, const char* name) {
  if (count > static_cast<std::uint64_t>(limit)) {
    detail = std::string(name) + ": count exceeds the configured limit";
    return false;
  }
  out.clear();
  out.reserve(static_cast<std::size_t>(count));
  for (std::uint64_t index = 0; index < count; ++index) {
    NodeId id;
    if (!DecodeId(reader, id, detail, name)) {
      return false;
    }
    out.push_back(id);
  }
  return true;
}

template <class Id>
bool DecodeTypedIdVector(ByteReader& reader, std::uint64_t count, std::uint32_t limit, std::vector<Id>& out,
                         std::string& detail, const char* name) {
  if (count > static_cast<std::uint64_t>(limit)) {
    detail = std::string(name) + ": count exceeds the configured limit";
    return false;
  }
  out.clear();
  out.reserve(static_cast<std::size_t>(count));
  for (std::uint64_t index = 0; index < count; ++index) {
    Id id;
    if (!DecodeId(reader, id, detail, name)) {
      return false;
    }
    out.push_back(id);
  }
  return true;
}

}  // namespace

WireStatus DecodePlanningRequestPayload(std::span<const std::byte> bytes, const ResourceLimits& limits,
                                        PlanningRequest& request, std::string& detail) {
  ByteReader reader(bytes);
  PlanningRequest decoded;
  if (!DecodeId(reader, decoded.id, detail, "planning request identity") ||
      !DecodeId(reader, decoded.source.id, detail, "source endpoint") ||
      !DecodeEnumValue(reader, kEndpointClassNames, decoded.source.endpoint_class, detail, "source class") ||
      !DecodeStrong(reader, decoded.source.generation, detail, "source generation") ||
      !DecodeId(reader, decoded.destination.id, detail, "destination endpoint") ||
      !DecodeEnumValue(reader, kEndpointClassNames, decoded.destination.endpoint_class, detail,
                       "destination class") ||
      !DecodeStrong(reader, decoded.destination.generation, detail, "destination generation")) {
    return WireStatus::kMalformed;
  }
  ConstraintSet& constraints = decoded.constraints;
  if (!DecodeId(reader, constraints.id, detail, "constraint set identity") ||
      !DecodeStrong(reader, constraints.generation, detail, "constraint generation") ||
      !DecodeEnumValue(reader, kPathLayerNames, constraints.layer, detail, "planning layer")) {
    return WireStatus::kMalformed;
  }
  const auto forbidden_nodes = reader.VarU64();
  if (!forbidden_nodes.has_value() ||
      !DecodeTypedIdVector(reader, *forbidden_nodes, limits.max_forbidden_ids, constraints.forbidden_nodes, detail,
                           "forbidden node")) {
    return WireStatus::kMalformed;
  }
  const auto forbidden_links = reader.VarU64();
  if (!forbidden_links.has_value() ||
      !DecodeTypedIdVector(reader, *forbidden_links, limits.max_forbidden_ids, constraints.forbidden_links, detail,
                           "forbidden link")) {
    return WireStatus::kMalformed;
  }
  const auto forbidden_ports = reader.VarU64();
  if (!forbidden_ports.has_value() ||
      !DecodeTypedIdVector(reader, *forbidden_ports, limits.max_forbidden_ids, constraints.forbidden_ports, detail,
                           "forbidden port")) {
    return WireStatus::kMalformed;
  }
  const auto forbidden_domains = reader.VarU64();
  if (!forbidden_domains.has_value() ||
      !DecodeTypedIdVector(reader, *forbidden_domains, limits.max_forbidden_ids,
                           constraints.forbidden_failure_domains, detail, "forbidden failure domain")) {
    return WireStatus::kMalformed;
  }
  const auto forbidden_classes = reader.VarU64();
  if (!forbidden_classes.has_value() ||
      !DecodeTypedIdVector(reader, *forbidden_classes, limits.max_forbidden_domain_classes,
                           constraints.forbidden_failure_domain_classes, detail, "forbidden failure domain class")) {
    return WireStatus::kMalformed;
  }
  const auto stages = reader.VarU64();
  if (!stages.has_value() || *stages > static_cast<std::uint64_t>(limits.max_required_ids)) {
    detail = "transit stage count exceeds the configured limit";
    return WireStatus::kMalformed;
  }
  constraints.required_transit.clear();
  for (std::uint64_t index = 0; index < *stages; ++index) {
    TransitStage stage;
    if (!DecodeEnumValue(reader, kTransitKindNames, stage.kind, detail, "transit kind")) {
      return WireStatus::kMalformed;
    }
    const auto alternatives = reader.VarU64();
    if (!alternatives.has_value() ||
        !DecodeTypedIdVector(reader, *alternatives, limits.max_members_in_any_set, stage.alternatives, detail,
                             "transit alternative")) {
      return WireStatus::kMalformed;
    }
    constraints.required_transit.push_back(std::move(stage));
  }
  const auto capabilities = reader.VarU64();
  if (!capabilities.has_value() || *capabilities > static_cast<std::uint64_t>(limits.max_capability_requirements)) {
    detail = "capability requirement count exceeds the configured limit";
    return WireStatus::kMalformed;
  }
  constraints.required_capabilities.clear();
  for (std::uint64_t index = 0; index < *capabilities; ++index) {
    CapabilityRequirement requirement;
    if (!DecodeId(reader, requirement.capability, detail, "capability identity") ||
        !DecodeEnumValue(reader, kCapabilityScopeNames, requirement.scope, detail, "capability scope") ||
        !DecodeEnumValue(reader, kCapabilityComparatorNames, requirement.comparator, detail,
                         "capability comparator") ||
        !DecodeStrong(reader, requirement.value, detail, "capability value")) {
      return WireStatus::kMalformed;
    }
    constraints.required_capabilities.push_back(requirement);
  }
  const std::optional<bool> has_max_hops = reader.Bool();
  if (!has_max_hops.has_value()) {
    detail = "constraint max_hops flag is missing";
    return WireStatus::kMalformed;
  }
  if (*has_max_hops) {
    const std::optional<std::uint32_t> value = reader.U32();
    const std::optional<HopCount> typed = value.has_value() ? HopCount::TryFrom(*value) : std::nullopt;
    if (!typed.has_value()) {
      detail = "max_hops is out of range";
      return WireStatus::kMalformed;
    }
    constraints.max_hops = *typed;
  }
  const std::optional<bool> has_domain_limit = reader.Bool();
  if (!has_domain_limit.has_value()) {
    detail = "constraint failure-domain limit flag is missing";
    return WireStatus::kMalformed;
  }
  if (*has_domain_limit) {
    const std::optional<std::uint32_t> value = reader.U32();
    if (!value.has_value()) {
      detail = "failure-domain member limit is missing";
      return WireStatus::kMalformed;
    }
    constraints.max_members_per_failure_domain = *value;
  }
  const std::optional<bool> fail_closed = reader.Bool();
  if (!fail_closed.has_value()) {
    detail = "failure-domain fail-closed flag is missing";
    return WireStatus::kMalformed;
  }
  constraints.fail_closed_on_unknown_domains = *fail_closed;

  PlanningPolicy& policy = decoded.policy;
  if (!DecodeStrong(reader, policy.generation, detail, "policy generation") ||
      !DecodeStrong(reader, policy.cost_model.hop_cost, detail, "hop cost") ||
      !DecodeStrong(reader, policy.cost_model.degraded_penalty, detail, "degraded penalty") ||
      !DecodeStrong(reader, policy.cost_model.locality_penalty, detail, "locality penalty")) {
    return WireStatus::kMalformed;
  }
  const std::optional<bool> allow_degraded = reader.Bool();
  const std::optional<bool> allow_draining = reader.Bool();
  const std::optional<bool> allow_maintenance = reader.Bool();
  const std::optional<bool> require_proof = reader.Bool();
  const std::optional<bool> allow_zero_hop = reader.Bool();
  if (!allow_degraded.has_value() || !allow_draining.has_value() || !allow_maintenance.has_value() ||
      !require_proof.has_value() || !allow_zero_hop.has_value()) {
    detail = "policy flags are truncated";
    return WireStatus::kMalformed;
  }
  policy.allow_degraded_links = *allow_degraded;
  policy.allow_draining_ports = *allow_draining;
  policy.allow_maintenance_ports = *allow_maintenance;
  policy.require_operational_proof = *require_proof;
  policy.allow_zero_hop_self_path = *allow_zero_hop;
  const auto locality = reader.VarU64();
  if (!locality.has_value() ||
      !DecodeTypedIdVector(reader, *locality, limits.max_forbidden_ids, policy.locality_scope, detail,
                           "locality scope node")) {
    return WireStatus::kMalformed;
  }
  if (!DecodeEnumValue(reader, kAuthorityValidationModeNames, policy.authority_validation, detail,
                       "authority validation mode")) {
    return WireStatus::kMalformed;
  }

  const std::optional<std::uint32_t> max_candidates = reader.U32();
  if (!max_candidates.has_value() ||
      !DecodeEnumValue(reader, kPlanningModeNames, decoded.mode, detail, "planning mode")) {
    return WireStatus::kMalformed;
  }
  decoded.max_candidates = *max_candidates;
  const std::optional<std::uint32_t> scope_mask = reader.U32();
  if (!scope_mask.has_value()) {
    detail = "authority scope mask is missing";
    return WireStatus::kMalformed;
  }
  decoded.authority.scope_mask = *scope_mask;
  // Caller identity fields are optional on the wire: a request that does not carry them is
  // still well formed, and authority enforcement is decided by the scope mask and the
  // epoch binding, not by the mere presence of an identity.
  const auto read_optional_id = [&reader, &detail](auto& id, const char* name) {
    using IdType = std::remove_reference_t<decltype(id)>;
    std::array<std::byte, IdType::kByteCount> bytes{};
    if (!reader.FixedBytes(std::span<std::byte>(bytes.data(), bytes.size()))) {
      detail = std::string(name) + " is truncated";
      return false;
    }
    id = IdType::FromBytes(bytes);
    return true;
  };
  if (!read_optional_id(decoded.authority.publisher, "publisher identity") ||
      !read_optional_id(decoded.authority.worker_boot, "worker boot identity") ||
      !DecodeStrong(reader, decoded.authority.coordinator_epoch, detail, "coordinator epoch") ||
      !read_optional_id(decoded.authority.attempt, "mutation attempt identity")) {
    return WireStatus::kMalformed;
  }
  const std::optional<bool> epoch_bound = reader.Bool();
  const std::optional<bool> enforce_scope = reader.Bool();
  const std::optional<bool> expect_epoch = reader.Bool();
  if (!epoch_bound.has_value() || !enforce_scope.has_value() || !expect_epoch.has_value() ||
      !DecodeStrong(reader, decoded.expected_epoch, detail, "expected epoch")) {
    return WireStatus::kMalformed;
  }
  decoded.authority.epoch_bound = *epoch_bound;
  decoded.authority.enforce_scope = *enforce_scope;
  decoded.expect_epoch = *expect_epoch;
  const std::optional<bool> expect_topology = reader.Bool();
  if (!expect_topology.has_value() || !DecodeStrong(reader, decoded.expected_topology, detail,
                                                   "expected topology generation")) {
    return WireStatus::kMalformed;
  }
  decoded.expect_topology = *expect_topology;
  const std::optional<bool> expect_snapshot = reader.Bool();
  if (!expect_snapshot.has_value()) {
    detail = "expected snapshot flag is missing";
    return WireStatus::kMalformed;
  }
  decoded.expect_snapshot = *expect_snapshot;
  // The encoder always writes the expected snapshot identity; the decoder must consume it
  // unconditionally or the frame would appear to carry trailing bytes.
  std::array<std::byte, SnapshotId::kByteCount> expected_snapshot_bytes{};
  if (!reader.FixedBytes(std::span<std::byte>(expected_snapshot_bytes.data(), expected_snapshot_bytes.size()))) {
    detail = "expected snapshot identity is truncated";
    return WireStatus::kMalformed;
  }
  const SnapshotId expected_snapshot = SnapshotId::FromBytes(expected_snapshot_bytes);
  if (*expect_snapshot && !expected_snapshot.IsValid()) {
    detail = "expected snapshot identity is nil";
    return WireStatus::kMalformed;
  }
  decoded.expected_snapshot = expected_snapshot;
  if (!reader.AtEnd()) {
    detail = "planning request payload carries trailing bytes";
    return WireStatus::kTrailingBytes;
  }
  const RequestValidation validation = ValidateRequest(decoded, limits);
  if (!validation.ok()) {
    detail = "planning request failed validation: " + validation.detail;
    return WireStatus::kMalformed;
  }
  request = std::move(decoded);
  return WireStatus::kOk;
}

void EncodePlanningResultPayload(ByteWriter& writer, const PlanningResult& result) {
  writer.U32(static_cast<std::uint32_t>(result.status));
  writer.Bool(result.primary_failure.has_value());
  if (result.primary_failure.has_value()) {
    writer.U32(static_cast<std::uint32_t>(*result.primary_failure));
  }
  EncodeId(writer, result.source_endpoint);
  EncodeId(writer, result.destination_endpoint);
  EncodeId(writer, result.source_node);
  EncodeId(writer, result.destination_node);
  EncodeId(writer, result.plan_id);
  EncodeStrong(writer, result.planning_generation);
  writer.FixedBytes(std::span<const std::byte>(result.semantic_digest.bytes.data(), result.semantic_digest.bytes.size()));
  EncodeEvidence(writer, result.evidence);
  writer.U32(result.requested_candidates);
  writer.Bool(result.truncated);
  writer.Bool(result.diagnostic_mode);
  writer.VarU64(result.candidates.size());
  for (const Candidate& candidate : result.candidates) {
    EncodeId(writer, candidate.id);
    EncodePath(writer, candidate.path);
    EncodeCost(writer, candidate.cost);
    writer.U32(candidate.rank.Value());
    writer.U32(static_cast<std::uint32_t>(candidate.currentness));
    writer.U32(static_cast<std::uint32_t>(candidate.authority));
    writer.VarU64(candidate.notes.size());
    for (const DiagnosticCode note : candidate.notes) {
      writer.U32(static_cast<std::uint32_t>(note));
    }
  }
  writer.VarU64(result.explanations.size());
  for (const ExplanationEntry& entry : result.explanations) {
    writer.U32(static_cast<std::uint32_t>(entry.code));
    writer.Text(entry.detail);
  }
  writer.VarU64(result.rejections.size());
  for (const RejectionExplanation& rejection : result.rejections) {
    writer.U32(static_cast<std::uint32_t>(rejection.code));
    writer.U32(static_cast<std::uint32_t>(rejection.subject.kind));
    writer.FixedBytes(std::span<const std::byte>(rejection.subject.bytes.data(), rejection.subject.bytes.size()));
    writer.U64(rejection.occurrences);
    writer.Text(rejection.detail);
  }
}

WireStatus DecodePlanningResultPayload(std::span<const std::byte> bytes, const ResourceLimits& limits,
                                       PlanningResult& result, std::string& detail) {
  ByteReader reader(bytes);
  PlanningResult decoded;
  if (!DecodeEnumValue(reader, kPlanStatusNames, decoded.status, detail, "plan status")) {
    return WireStatus::kMalformed;
  }
  const std::optional<bool> has_failure = reader.Bool();
  if (!has_failure.has_value()) {
    detail = "primary failure flag is missing";
    return WireStatus::kMalformed;
  }
  if (*has_failure) {
    DiagnosticCode code = DiagnosticCode::kUnknownSourceEntity;
    if (!DecodeEnumValue(reader, kDiagnosticCodeNames, code, detail, "primary failure")) {
      return WireStatus::kMalformed;
    }
    decoded.primary_failure = code;
  }
  if (!DecodeId(reader, decoded.source_endpoint, detail, "source endpoint") ||
      !DecodeId(reader, decoded.destination_endpoint, detail, "destination endpoint") ||
      !DecodeId(reader, decoded.source_node, detail, "source node") ||
      !DecodeId(reader, decoded.destination_node, detail, "destination node") ||
      !DecodeId(reader, decoded.plan_id, detail, "plan identity") ||
      !DecodeStrong(reader, decoded.planning_generation, detail, "planning generation")) {
    return WireStatus::kMalformed;
  }
  if (!reader.FixedBytes(std::span<std::byte>(decoded.semantic_digest.bytes.data(),
                                              decoded.semantic_digest.bytes.size()))) {
    detail = "semantic digest is truncated";
    return WireStatus::kMalformed;
  }
  if (!DecodeEvidence(reader, decoded.evidence, detail)) {
    return WireStatus::kMalformed;
  }
  const std::optional<std::uint32_t> requested = reader.U32();
  const std::optional<bool> truncated = reader.Bool();
  const std::optional<bool> diagnostic_mode = reader.Bool();
  if (!requested.has_value() || !truncated.has_value() || !diagnostic_mode.has_value()) {
    detail = "result flags are truncated";
    return WireStatus::kMalformed;
  }
  decoded.requested_candidates = *requested;
  decoded.truncated = *truncated;
  decoded.diagnostic_mode = *diagnostic_mode;

  const auto candidate_count = reader.VarU64();
  if (!candidate_count.has_value() ||
      *candidate_count > static_cast<std::uint64_t>(limits.max_candidates_per_request)) {
    detail = "candidate count exceeds the configured limit";
    return WireStatus::kMalformed;
  }
  decoded.candidates.clear();
  for (std::uint64_t index = 0; index < *candidate_count; ++index) {
    Candidate candidate;
    if (!DecodeId(reader, candidate.id, detail, "candidate identity") ||
        !DecodePath(reader, limits, candidate.path, detail) || !DecodeCost(reader, candidate.cost, detail)) {
      return WireStatus::kMalformed;
    }
    const std::optional<std::uint32_t> rank = reader.U32();
    const std::optional<CandidateRank> typed_rank = rank.has_value() ? CandidateRank::TryFrom(*rank) : std::nullopt;
    if (!typed_rank.has_value() || typed_rank->Value() == 0) {
      detail = "candidate rank is invalid";
      return WireStatus::kMalformed;
    }
    candidate.rank = *typed_rank;
    if (!DecodeEnumValue(reader, kCurrentnessNames, candidate.currentness, detail, "candidate currentness") ||
        !DecodeEnumValue(reader, kAuthorityValidationNames, candidate.authority, detail,
                         "candidate authority validation")) {
      return WireStatus::kMalformed;
    }
    const auto note_count = reader.VarU64();
    if (!note_count.has_value() || *note_count > static_cast<std::uint64_t>(limits.max_explanation_entries)) {
      detail = "candidate note count exceeds the configured limit";
      return WireStatus::kMalformed;
    }
    for (std::uint64_t note_index = 0; note_index < *note_count; ++note_index) {
      DiagnosticCode note = DiagnosticCode::kCancelled;
      if (!DecodeEnumValue(reader, kDiagnosticCodeNames, note, detail, "candidate note")) {
        return WireStatus::kMalformed;
      }
      candidate.notes.push_back(note);
    }
    if (candidate.id != candidate.path.Id()) {
      detail = "candidate identity does not match its canonical path encoding";
      return WireStatus::kMalformed;
    }
    candidate.evidence = decoded.evidence;
    decoded.candidates.push_back(std::move(candidate));
  }

  const auto explanation_count = reader.VarU64();
  if (!explanation_count.has_value() ||
      *explanation_count > static_cast<std::uint64_t>(limits.max_explanation_entries)) {
    detail = "explanation count exceeds the configured limit";
    return WireStatus::kMalformed;
  }
  for (std::uint64_t index = 0; index < *explanation_count; ++index) {
    ExplanationEntry entry;
    if (!DecodeEnumValue(reader, kDiagnosticCodeNames, entry.code, detail, "explanation code")) {
      return WireStatus::kMalformed;
    }
    const std::optional<std::string_view> text = reader.Text();
    if (!text.has_value()) {
      detail = "explanation text is truncated";
      return WireStatus::kMalformed;
    }
    entry.detail.assign(*text);
    decoded.explanations.push_back(std::move(entry));
  }

  const auto rejection_count = reader.VarU64();
  if (!rejection_count.has_value() ||
      *rejection_count > static_cast<std::uint64_t>(limits.max_explanation_entries)) {
    detail = "rejection count exceeds the configured limit";
    return WireStatus::kMalformed;
  }
  for (std::uint64_t index = 0; index < *rejection_count; ++index) {
    RejectionExplanation rejection;
    if (!DecodeEnumValue(reader, kDiagnosticCodeNames, rejection.code, detail, "rejection code")) {
      return WireStatus::kMalformed;
    }
    SubjectKey subject;
    if (!DecodeEnumValue(reader, kSubjectKindNames, subject.kind, detail, "rejection subject kind")) {
      return WireStatus::kMalformed;
    }
    if (!reader.FixedBytes(std::span<std::byte>(subject.bytes.data(), subject.bytes.size()))) {
      detail = "rejection subject is truncated";
      return WireStatus::kMalformed;
    }
    const std::optional<std::uint64_t> occurrences = reader.U64();
    const std::optional<std::string_view> text = reader.Text();
    if (!occurrences.has_value() || !text.has_value()) {
      detail = "rejection entry is truncated";
      return WireStatus::kMalformed;
    }
    rejection.subject = subject;
    rejection.occurrences = *occurrences;
    rejection.detail.assign(*text);
    decoded.rejections.push_back(std::move(rejection));
  }
  if (!reader.AtEnd()) {
    detail = "planning result payload carries trailing bytes";
    return WireStatus::kTrailingBytes;
  }
  result = std::move(decoded);
  return WireStatus::kOk;
}

void EncodePlanErrorPayload(ByteWriter& writer, const PlanErrorPayload& payload) {
  EncodeId(writer, payload.request);
  writer.U32(static_cast<std::uint32_t>(payload.status));
  writer.U32(static_cast<std::uint32_t>(payload.plan_status));
  writer.U32(static_cast<std::uint32_t>(payload.code));
  writer.Text(payload.detail);
}

WireStatus DecodePlanErrorPayload(std::span<const std::byte> bytes, PlanErrorPayload& payload, std::string& detail) {
  ByteReader reader(bytes);
  PlanErrorPayload decoded;
  if (!DecodeId(reader, decoded.request, detail, "request identity") ||
      !DecodeEnumValue(reader, kWireStatusNames, decoded.status, detail, "wire status") ||
      !DecodeEnumValue(reader, kPlanStatusNames, decoded.plan_status, detail, "plan status") ||
      !DecodeEnumValue(reader, kDiagnosticCodeNames, decoded.code, detail, "diagnostic code")) {
    return WireStatus::kMalformed;
  }
  const std::optional<std::string_view> text = reader.Text();
  if (!text.has_value()) {
    detail = "error detail is truncated";
    return WireStatus::kMalformed;
  }
  decoded.detail.assign(*text);
  if (!reader.AtEnd()) {
    detail = "error payload carries trailing bytes";
    return WireStatus::kTrailingBytes;
  }
  payload = std::move(decoded);
  return WireStatus::kOk;
}

void EncodeFenceNoticePayload(ByteWriter& writer, const FenceNoticePayload& payload) {
  EncodeId(writer, payload.boot);
  writer.U32(static_cast<std::uint32_t>(payload.status));
  writer.U32(static_cast<std::uint32_t>(payload.code));
  writer.Text(payload.detail);
}

WireStatus DecodeFenceNoticePayload(std::span<const std::byte> bytes, FenceNoticePayload& payload,
                                    std::string& detail) {
  ByteReader reader(bytes);
  FenceNoticePayload decoded;
  if (!DecodeId(reader, decoded.boot, detail, "worker boot identity") ||
      !DecodeEnumValue(reader, kWireStatusNames, decoded.status, detail, "wire status") ||
      !DecodeEnumValue(reader, kDiagnosticCodeNames, decoded.code, detail, "diagnostic code")) {
    return WireStatus::kMalformed;
  }
  const std::optional<std::string_view> text = reader.Text();
  if (!text.has_value()) {
    detail = "fence detail is truncated";
    return WireStatus::kMalformed;
  }
  decoded.detail.assign(*text);
  if (!reader.AtEnd()) {
    detail = "fence payload carries trailing bytes";
    return WireStatus::kTrailingBytes;
  }
  payload = std::move(decoded);
  return WireStatus::kOk;
}

void EncodeSnapshotResponsePayload(ByteWriter& writer, const SnapshotResponsePayload& payload) {
  EncodeId(writer, payload.snapshot);
  EncodeGenerations(writer, payload.generations);
  writer.U32(payload.node_count);
  writer.U32(payload.edge_count);
}

WireStatus DecodeSnapshotResponsePayload(std::span<const std::byte> bytes, SnapshotResponsePayload& payload,
                                         std::string& detail) {
  ByteReader reader(bytes);
  SnapshotResponsePayload decoded;
  if (!DecodeId(reader, decoded.snapshot, detail, "snapshot identity") ||
      !DecodeGenerations(reader, decoded.generations, detail)) {
    return WireStatus::kMalformed;
  }
  const std::optional<std::uint32_t> nodes = reader.U32();
  const std::optional<std::uint32_t> edges = reader.U32();
  if (!nodes.has_value() || !edges.has_value()) {
    detail = "snapshot response is truncated";
    return WireStatus::kMalformed;
  }
  decoded.node_count = *nodes;
  decoded.edge_count = *edges;
  if (!reader.AtEnd()) {
    detail = "snapshot response carries trailing bytes";
    return WireStatus::kTrailingBytes;
  }
  payload = decoded;
  return WireStatus::kOk;
}

void EncodeCurrentnessQueryPayload(ByteWriter& writer, const CurrentnessQueryPayload& payload) {
  EncodeId(writer, payload.plan);
  EncodeId(writer, payload.request);
  EncodeEvidence(writer, payload.evidence);
}

WireStatus DecodeCurrentnessQueryPayload(std::span<const std::byte> bytes, CurrentnessQueryPayload& payload,
                                         std::string& detail) {
  ByteReader reader(bytes);
  CurrentnessQueryPayload decoded;
  if (!DecodeId(reader, decoded.plan, detail, "plan identity") ||
      !DecodeId(reader, decoded.request, detail, "request identity") ||
      !DecodeEvidence(reader, decoded.evidence, detail)) {
    return WireStatus::kMalformed;
  }
  if (!reader.AtEnd()) {
    detail = "currentness query carries trailing bytes";
    return WireStatus::kTrailingBytes;
  }
  payload = decoded;
  return WireStatus::kOk;
}

void EncodeCurrentnessResultPayload(ByteWriter& writer, const CurrentnessResultPayload& payload) {
  EncodeId(writer, payload.plan);
  writer.U32(static_cast<std::uint32_t>(payload.currentness));
  writer.VarU64(payload.changes.size());
  for (const ExplanationEntry& entry : payload.changes) {
    writer.U32(static_cast<std::uint32_t>(entry.code));
    writer.Text(entry.detail);
  }
}

WireStatus DecodeCurrentnessResultPayload(std::span<const std::byte> bytes, const ResourceLimits& limits,
                                          CurrentnessResultPayload& payload, std::string& detail) {
  ByteReader reader(bytes);
  CurrentnessResultPayload decoded;
  if (!DecodeId(reader, decoded.plan, detail, "plan identity") ||
      !DecodeEnumValue(reader, kCurrentnessNames, decoded.currentness, detail, "currentness")) {
    return WireStatus::kMalformed;
  }
  const auto change_count = reader.VarU64();
  if (!change_count.has_value() ||
      *change_count > static_cast<std::uint64_t>(limits.max_explanation_entries)) {
    detail = "change count exceeds the configured limit";
    return WireStatus::kMalformed;
  }
  for (std::uint64_t index = 0; index < *change_count; ++index) {
    ExplanationEntry entry;
    if (!DecodeEnumValue(reader, kDiagnosticCodeNames, entry.code, detail, "change code")) {
      return WireStatus::kMalformed;
    }
    const std::optional<std::string_view> text = reader.Text();
    if (!text.has_value()) {
      detail = "change detail is truncated";
      return WireStatus::kMalformed;
    }
    entry.detail.assign(*text);
    decoded.changes.push_back(std::move(entry));
  }
  if (!reader.AtEnd()) {
    detail = "currentness result carries trailing bytes";
    return WireStatus::kTrailingBytes;
  }
  payload = std::move(decoded);
  return WireStatus::kOk;
}

}  // namespace summon::pathplanner

// tests/adversarial_tests.cpp -- suite "adversarial".
//
// Hostile-input coverage of the public Path Planner surface. Every case drives the
// library through published entry points only; nothing here reaches into internals.
//
//   * malformed identifiers and canonical codecs (FixedId / StrongUInt / ByteReader /
//     ByteWriter) including truncation, non-canonical varints and ceiling overflow;
//   * malformed planning requests (nil identities, candidate ceilings, duplicate
//     constraints, unsupported policy shapes, enum values injected into an encoded
//     payload) and the well-formed empty constraint set;
//   * authority and currentness attacks (scope, coordinator epoch, topology and
//     snapshot expectations);
//   * wire-protocol attacks: exhaustive single-bit frame mutation, a raw loopback
//     client that registers, publishes as an unregistered boot and is fenced, and a
//     partial frame that must not pin a session;
//   * persistence attacks: truncation, corruption, duplicated identity, reordered
//     hops, absurd counts and trailing garbage;
//   * resource limits: work budget, retention eviction, hop ceiling and cost overflow.
//
// Determinism: no sleeps, no wall-clock ordering assumptions, no fixed ports. The two
// loopback cases use bounded polls whose exhaustion is a hard check failure.
// tests/test_main.cpp owns main().

#include "test_framework.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "pathplanner/canonical.hpp"
#include "pathplanner/dist.hpp"
#include "pathplanner/graph.hpp"
#include "pathplanner/ids.hpp"
#include "pathplanner/limits.hpp"
#include "pathplanner/path.hpp"
#include "pathplanner/planner.hpp"
#include "pathplanner/proto.hpp"
#include "pathplanner/request.hpp"
#include "pathplanner/result.hpp"
#include "pathplanner/sha256.hpp"
#include "pathplanner/status.hpp"
#include "pathplanner/store.hpp"
#include "pathplanner/version.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
// <winsock2.h> pulls in <windows.h>, which otherwise defines min/max as macros and
// breaks std::numeric_limits<...>::max().
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace adversarial {

using namespace summon::pathplanner;

namespace {

// ---------------------------------------------------------------------------
// Failure helpers. PP_REQUIRE cannot be used inside a value-returning helper
// (it expands to a bare "return;"), so helpers fail by throwing through Fail().
// ---------------------------------------------------------------------------
void Require(bool condition, const std::string& message) {
  if (!condition) {
    ::pp_test::Fail(__FILE__, __LINE__, message);
  }
}

std::size_t Count(std::size_t value) { return value; }

template <class Id>
Id TestId(std::string_view label) {
  return Id::FromDigest(Sha256::Hash(label));
}

std::vector<std::byte> BytesOf(std::string_view text) {
  std::vector<std::byte> bytes;
  bytes.reserve(text.size());
  for (const char character : text) {
    bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
  }
  return bytes;
}

std::span<const std::byte> SpanOf(const std::vector<std::byte>& bytes) {
  return std::span<const std::byte>(bytes.data(), bytes.size());
}

std::uint32_t ReadU32LE(std::span<const std::byte> bytes, std::size_t offset) {
  Require(offset + 4 <= bytes.size(), "little-endian read is out of range");
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes[offset + index]))
             << (static_cast<int>(index) * 8);
  }
  return value;
}

void WriteU32LE(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
  Require(offset + 4 <= bytes.size(), "little-endian write is out of range");
  for (std::size_t index = 0; index < 4; ++index) {
    bytes[offset + index] = static_cast<std::byte>((value >> (static_cast<int>(index) * 8)) & 0xFFu);
  }
}

// ---------------------------------------------------------------------------
// Fabric fixture.
//
//   node A (ports a1, a2) --ab--> node B (ports b1..b3) --bc--> node C (port c1)
//                          --ab2->
//
// A -> B has two one-hop candidates; A -> C has exactly two two-hop candidates, which
// is what the store identity and candidate-count probes rely on.
// ---------------------------------------------------------------------------
constexpr std::uint64_t kGenerationA = 3;
constexpr std::uint64_t kGenerationB = 1;
constexpr std::uint64_t kGenerationC = 5;
constexpr std::uint32_t kAbCost = 1;
constexpr std::uint32_t kAb2Cost = 2;
constexpr std::uint32_t kBcCost = 4;

struct Fabric {
  NodeId a;
  NodeId b;
  NodeId c;
  PortId a1;
  PortId a2;
  PortId b1;
  PortId b2;
  PortId b3;
  PortId c1;
  LinkId ab;
  LinkId ab2;
  LinkId bc;
  EndpointId ea;
  EndpointId eb;
  EndpointId ec;
  std::shared_ptr<const FabricSnapshot> snapshot;
};

SnapshotGenerations DefaultGenerations() {
  SnapshotGenerations generations;
  generations.topology = TopologyGeneration(1);
  generations.link_state = LinkStateGeneration(1);
  generations.ports = PortGeneration(1);
  generations.capabilities = CapabilityGeneration(1);
  generations.failure_domains = FailureDomainGeneration(1);
  generations.epoch = FabricEpoch(1);
  generations.policy = PolicyGeneration(1);
  generations.constraints = ConstraintGeneration(1);
  return generations;
}

NodeRecord MakeNode(const NodeId& id, std::vector<PortId> ports) {
  NodeRecord node;
  node.id = id;
  node.entity_generation = EntityGeneration(1);
  node.structural_generation = TopologyGeneration(1);
  node.ports = std::move(ports);
  return node;
}

EdgeRecord MakeEdge(const LinkId& id, const NodeId& from, const NodeId& to, const PortId& from_port,
                    const PortId& to_port, std::uint32_t static_cost) {
  EdgeRecord edge;
  edge.id = id;
  edge.from = from;
  edge.to = to;
  edge.from_port = from_port;
  edge.to_port = to_port;
  edge.layer = PathLayer::kPhysical;
  edge.relationship = RelationshipType::kDirectLink;
  edge.static_cost = StaticCost(static_cost);
  edge.entity_generation = EntityGeneration(1);
  edge.structural_generation = TopologyGeneration(1);
  return edge;
}

EndpointRecord MakeEndpoint(const EndpointId& id, const NodeId& node, const PortId& port,
                            std::uint64_t generation) {
  EndpointRecord endpoint;
  endpoint.id = id;
  endpoint.endpoint_class = EndpointClass::kEndpoint;
  endpoint.node = node;
  endpoint.port = port;
  endpoint.entity_generation = EntityGeneration(generation);
  return endpoint;
}

Fabric MakeFabric() {
  Fabric fabric;
  fabric.a = TestId<NodeId>("adversarial.node.a");
  fabric.b = TestId<NodeId>("adversarial.node.b");
  fabric.c = TestId<NodeId>("adversarial.node.c");
  fabric.a1 = TestId<PortId>("adversarial.port.a1");
  fabric.a2 = TestId<PortId>("adversarial.port.a2");
  fabric.b1 = TestId<PortId>("adversarial.port.b1");
  fabric.b2 = TestId<PortId>("adversarial.port.b2");
  fabric.b3 = TestId<PortId>("adversarial.port.b3");
  fabric.c1 = TestId<PortId>("adversarial.port.c1");
  fabric.ab = TestId<LinkId>("adversarial.link.ab");
  fabric.ab2 = TestId<LinkId>("adversarial.link.ab2");
  fabric.bc = TestId<LinkId>("adversarial.link.bc");
  fabric.ea = TestId<EndpointId>("adversarial.endpoint.a");
  fabric.eb = TestId<EndpointId>("adversarial.endpoint.b");
  fabric.ec = TestId<EndpointId>("adversarial.endpoint.c");

  FabricSnapshotBuilder builder;
  builder.SetGenerations(DefaultGenerations());
  builder.SetSource(EvidenceSource::kSynthetic);
  Require(builder.AddNode(MakeNode(fabric.a, {fabric.a1, fabric.a2})), "node A was rejected");
  Require(builder.AddNode(MakeNode(fabric.b, {fabric.b1, fabric.b2, fabric.b3})), "node B was rejected");
  Require(builder.AddNode(MakeNode(fabric.c, {fabric.c1})), "node C was rejected");
  Require(builder.AddEdge(MakeEdge(fabric.ab, fabric.a, fabric.b, fabric.a1, fabric.b1, kAbCost)),
          "link ab was rejected");
  Require(builder.AddEdge(MakeEdge(fabric.ab2, fabric.a, fabric.b, fabric.a2, fabric.b2, kAb2Cost)),
          "link ab2 was rejected");
  Require(builder.AddEdge(MakeEdge(fabric.bc, fabric.b, fabric.c, fabric.b3, fabric.c1, kBcCost)),
          "link bc was rejected");
  Require(builder.AddEndpoint(MakeEndpoint(fabric.ea, fabric.a, fabric.a1, kGenerationA)),
          "endpoint A was rejected");
  Require(builder.AddEndpoint(MakeEndpoint(fabric.eb, fabric.b, fabric.b1, kGenerationB)),
          "endpoint B was rejected");
  Require(builder.AddEndpoint(MakeEndpoint(fabric.ec, fabric.c, fabric.c1, kGenerationC)),
          "endpoint C was rejected");
  builder.SetLinkStates(std::vector<LinkStateRecord>{
      {fabric.ab, LinkState::kUp}, {fabric.ab2, LinkState::kUp}, {fabric.bc, LinkState::kUp}});
  builder.SetPortStates(std::vector<PortStateRecord>{{fabric.a1, PortState::kUp},
                                                     {fabric.a2, PortState::kUp},
                                                     {fabric.b1, PortState::kUp},
                                                     {fabric.b2, PortState::kUp},
                                                     {fabric.b3, PortState::kUp},
                                                     {fabric.c1, PortState::kUp}});
  const SnapshotBuildResult build = builder.Build();
  Require(build.ok(), build.detail.empty() ? std::string("fabric snapshot build failed") : build.detail);
  fabric.snapshot = build.snapshot;
  return fabric;
}

// A straight chain of node_count nodes with a caller-controlled static cost on every
// edge. Used for the hop ceiling and cost overflow cases.
struct ChainFabric {
  std::vector<NodeId> nodes;
  std::vector<PortId> ports;
  std::vector<LinkId> links;
  EndpointId source;
  EndpointId destination;
  std::shared_ptr<const FabricSnapshot> snapshot;
};

ChainFabric MakeChain(std::size_t node_count, std::uint32_t static_cost) {
  Require(node_count >= 2, "a chain needs at least two nodes");
  ChainFabric chain;
  FabricSnapshotBuilder builder;
  builder.SetGenerations(DefaultGenerations());
  builder.SetSource(EvidenceSource::kSynthetic);
  for (std::size_t index = 0; index < node_count; ++index) {
    chain.nodes.push_back(TestId<NodeId>("adversarial.chain.node." + std::to_string(index)));
    chain.ports.push_back(TestId<PortId>("adversarial.chain.port." + std::to_string(index)));
    Require(builder.AddNode(MakeNode(chain.nodes.back(), {chain.ports.back()})), "chain node was rejected");
  }
  for (std::size_t index = 0; index + 1 < node_count; ++index) {
    chain.links.push_back(TestId<LinkId>("adversarial.chain.link." + std::to_string(index)));
    Require(builder.AddEdge(MakeEdge(chain.links.back(), chain.nodes[index], chain.nodes[index + 1],
                                     chain.ports[index], chain.ports[index + 1], static_cost)),
            "chain edge was rejected");
  }
  std::vector<LinkStateRecord> link_states;
  for (const LinkId& link : chain.links) {
    link_states.push_back(LinkStateRecord{link, LinkState::kUp});
  }
  builder.SetLinkStates(std::move(link_states));
  std::vector<PortStateRecord> port_states;
  for (const PortId& port : chain.ports) {
    port_states.push_back(PortStateRecord{port, PortState::kUp});
  }
  builder.SetPortStates(std::move(port_states));
  chain.source = TestId<EndpointId>("adversarial.chain.endpoint.source");
  chain.destination = TestId<EndpointId>("adversarial.chain.endpoint.destination");
  Require(builder.AddEndpoint(MakeEndpoint(chain.source, chain.nodes.front(), chain.ports.front(), 1)),
          "chain source endpoint was rejected");
  Require(builder.AddEndpoint(MakeEndpoint(chain.destination, chain.nodes.back(), chain.ports.back(), 1)),
          "chain destination endpoint was rejected");
  const SnapshotBuildResult build = builder.Build();
  Require(build.ok(), build.detail.empty() ? std::string("chain snapshot build failed") : build.detail);
  chain.snapshot = build.snapshot;
  return chain;
}

PlanningRequest MakeRequest(const EndpointId& source, EntityGeneration source_generation,
                            const EndpointId& destination, EntityGeneration destination_generation,
                            std::uint32_t max_candidates, std::string_view label) {
  PlanningRequest request;
  request.id = TestId<PlanningRequestId>(label);
  request.source.id = source;
  request.source.endpoint_class = EndpointClass::kEndpoint;
  request.source.generation = source_generation;
  request.destination.id = destination;
  request.destination.endpoint_class = EndpointClass::kEndpoint;
  request.destination.generation = destination_generation;
  request.constraints.id = TestId<ConstraintSetId>(label);
  request.constraints.generation = ConstraintGeneration(1);
  request.constraints.layer = PathLayer::kPhysical;
  request.policy.generation = PolicyGeneration(1);
  request.max_candidates = max_candidates;
  request.mode = PlanningMode::kStandard;
  return request;
}

PlanningRequest MakeAToBRequest(const Fabric& fabric, std::uint32_t max_candidates, std::string_view label) {
  return MakeRequest(fabric.ea, EntityGeneration(kGenerationA), fabric.eb, EntityGeneration(kGenerationB),
                     max_candidates, label);
}

PlanningRequest MakeAToCRequest(const Fabric& fabric, std::uint32_t max_candidates, std::string_view label) {
  return MakeRequest(fabric.ea, EntityGeneration(kGenerationA), fabric.ec, EntityGeneration(kGenerationC),
                     max_candidates, label);
}

PlanningRequest MakeChainRequest(const ChainFabric& chain, std::uint32_t max_candidates, std::string_view label) {
  return MakeRequest(chain.source, EntityGeneration(1), chain.destination, EntityGeneration(1), max_candidates,
                     label);
}

PlannerConfig ConfigFor(const std::shared_ptr<const FabricSnapshot>& snapshot) {
  PlannerConfig config;
  config.initial_snapshot = snapshot;
  return config;
}

PathPlan PlanOnce(PlannerRuntime& runtime, const PlanningRequest& request, PlanningResult& result) {
  result = runtime.Plan(request);
  return MakePathPlan(request, result, runtime.PublishSequence());
}

// ---------------------------------------------------------------------------
// Store helpers.
// ---------------------------------------------------------------------------
std::vector<std::byte> EncodeImage(const std::vector<StoredPlanRecord>& records) {
  StoreOptions options;
  std::vector<std::byte> image;
  const StoreResult encoded = EncodePlanStore(records, options, image);
  Require(encoded.ok, "store encoding failed: " + encoded.detail);
  return image;
}

// Recomputes the transport digest of a store image after its payload was mutated, so a
// targeted payload attack reaches the payload decoder instead of stopping at the digest.
void RepairStoreDigest(std::vector<std::byte>& image) {
  Require(image.size() >= kStoreHeaderBytes + kStoreDigestBytes, "store image is too small to repair");
  Sha256 hasher;
  hasher.Update(std::span<const std::byte>(image.data(), kStoreHeaderBytes));
  hasher.Update(std::span<const std::byte>(image.data() + kStoreHeaderBytes + kStoreDigestBytes,
                                           image.size() - kStoreHeaderBytes - kStoreDigestBytes));
  const Sha256Digest digest = hasher.Finish();
  for (std::size_t index = 0; index < kStoreDigestBytes; ++index) {
    image[kStoreHeaderBytes + index] = digest.bytes[index];
  }
}

void DecodeExpect(std::span<const std::byte> image, DiagnosticCode expected, const std::string& context) {
  std::vector<StoredPlanRecord> records;
  const StoreResult result = DecodePlanStore(image, ResourceLimits{}, records);
  PP_CHECK_MSG(!result.ok, context + ": corrupted image was accepted");
  PP_CHECK_MSG(result.code == expected, context + ": unexpected diagnostic " +
                                              std::string(ToString(result.code)) + " (" + result.detail + ")");
  PP_CHECK_MSG(!result.detail.empty(), context + ": failure detail is empty");
}

// ---------------------------------------------------------------------------
// Raw loopback client. Winsock on Windows, BSD sockets elsewhere; frames are built and
// parsed with the library's own proto.hpp codec.
// ---------------------------------------------------------------------------
constexpr std::uint32_t kFrameCeiling = 1u << 20;

#ifdef _WIN32
using RawSocket = SOCKET;
inline constexpr RawSocket kInvalidRawSocket = INVALID_SOCKET;
using SockLen = int;
#else
using RawSocket = int;
inline constexpr RawSocket kInvalidRawSocket = -1;
using SockLen = socklen_t;
#endif

class SocketRuntime {
 public:
  SocketRuntime() {
#ifdef _WIN32
    WSADATA data;
    ready_ = WSAStartup(MAKEWORD(2, 2), &data) == 0;
#else
    ready_ = true;
#endif
  }
  ~SocketRuntime() {
#ifdef _WIN32
    if (ready_) {
      WSACleanup();
    }
#endif
  }
  SocketRuntime(const SocketRuntime&) = delete;
  SocketRuntime& operator=(const SocketRuntime&) = delete;

  bool ready() const { return ready_; }

 private:
  bool ready_ = false;
};

class RawClient {
 public:
  RawClient() = default;
  ~RawClient() { Close(); }
  RawClient(const RawClient&) = delete;
  RawClient& operator=(const RawClient&) = delete;

  bool Connect(const std::string& address, std::uint16_t port, std::string& error) {
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(port);
    if (::inet_pton(AF_INET, address.c_str(), &endpoint.sin_addr) != 1) {
      error = "peer address is not a numeric IPv4 literal";
      return false;
    }
    socket_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == kInvalidRawSocket) {
      error = "socket creation failed";
      return false;
    }
    if (::connect(socket_, reinterpret_cast<const sockaddr*>(&endpoint),
                  static_cast<SockLen>(sizeof(endpoint))) != 0) {
      error = "connect failed";
      Close();
      return false;
    }
    const std::uint32_t timeout_ms = 5000;
#ifdef _WIN32
    const DWORD timeout = static_cast<DWORD>(timeout_ms);
    static_cast<void>(::setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout),
                                   static_cast<int>(sizeof(timeout))));
#else
    timeval timeout{};
    timeout.tv_sec = static_cast<time_t>(timeout_ms / 1000u);
    timeout.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000u) * 1000u);
    static_cast<void>(::setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
#endif
    return true;
  }

  void Close() {
    if (socket_ == kInvalidRawSocket) {
      return;
    }
#ifdef _WIN32
    ::closesocket(socket_);
#else
    ::close(socket_);
#endif
    socket_ = kInvalidRawSocket;
  }

  bool SendBytes(std::span<const std::byte> bytes, std::string& error) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
      const int sent = ::send(socket_, reinterpret_cast<const char*>(bytes.data() + offset),
                              static_cast<int>(bytes.size() - offset), 0);
      if (sent <= 0) {
        error = "send failed";
        return false;
      }
      offset += static_cast<std::size_t>(sent);
    }
    return true;
  }

  // Reads one complete frame and runs it through the library decoder.
  bool ReadFrame(WireFrame& frame, std::string& error) {
    std::array<std::byte, kWireHeaderBytes> header{};
    if (!ReceiveExact(std::span<std::byte>(header.data(), header.size()), error)) {
      return false;
    }
    const std::uint32_t payload_bytes = ReadU32LE(std::span<const std::byte>(header.data(), header.size()), 52);
    if (payload_bytes > kFrameCeiling) {
      error = "coordinator declared an oversized payload";
      return false;
    }
    std::vector<std::byte> bytes(kWireHeaderBytes + static_cast<std::size_t>(payload_bytes));
    std::copy(header.begin(), header.end(), bytes.begin());
    if (payload_bytes > 0) {
      if (!ReceiveExact(std::span<std::byte>(bytes.data() + kWireHeaderBytes, payload_bytes), error)) {
        return false;
      }
    }
    std::string detail;
    const WireStatus status =
        DecodeFrame(std::span<const std::byte>(bytes.data(), bytes.size()), kFrameCeiling, frame, detail);
    if (status != WireStatus::kOk) {
      error = "coordinator frame was rejected: " + detail;
      return false;
    }
    return true;
  }

 private:
  bool ReceiveExact(std::span<std::byte> out, std::string& error) {
    std::size_t offset = 0;
    while (offset < out.size()) {
      const int received = static_cast<int>(::recv(socket_, reinterpret_cast<char*>(out.data() + offset),
                                                   static_cast<int>(out.size() - offset), 0));
      if (received <= 0) {
        error = "receive failed or timed out";
        return false;
      }
      offset += static_cast<std::size_t>(received);
    }
    return true;
  }

  RawSocket socket_ = kInvalidRawSocket;
};

// ---------------------------------------------------------------------------
// Frame helpers.
// ---------------------------------------------------------------------------
std::vector<std::byte> MakeFrame(WireMessage type, std::uint16_t flags, CoordinatorEpoch epoch,
                                 const WorkerBootId& boot, const PlanningRequestId& request,
                                 std::span<const std::byte> payload) {
  WireFrame frame;
  frame.type = type;
  frame.flags = flags;
  frame.coordinator_epoch = epoch;
  frame.sequence = 0;
  frame.worker_boot = boot;
  frame.request = request;
  frame.payload.assign(payload.begin(), payload.end());
  return EncodeFrame(frame);
}

std::vector<std::byte> MakeHelloFrame(const HelloPayload& hello, const WorkerBootId& boot,
                                      const PlanningRequestId& request, CoordinatorEpoch epoch) {
  ByteWriter writer(kDefaultEncodingCeiling);
  EncodeHelloPayload(writer, hello);
  Require(!writer.overflowed(), "hello payload overflowed its ceiling");
  return MakeFrame(WireMessage::kHello, 0, epoch, boot, request, writer.span());
}

WireStatus DecodeFrameOf(const std::vector<std::byte>& bytes, WireFrame& out) {
  std::string detail;
  return DecodeFrame(SpanOf(bytes), kFrameCeiling, out, detail);
}

std::vector<std::byte> EncodePlanError(const PlanErrorPayload& payload) {
  ByteWriter writer(kDefaultEncodingCeiling);
  EncodePlanErrorPayload(writer, payload);
  Require(!writer.overflowed(), "plan error payload overflowed its ceiling");
  return std::vector<std::byte>(writer.data().begin(), writer.data().end());
}

// Guarantees that a worker thread is stopped and joined even when a bounded poll or a
// check fails: the harness reports failures by throwing, and unwinding through a joinable
// std::thread would terminate the process instead of reporting the case.
class WorkerRunGuard {
 public:
  WorkerRunGuard(Worker& worker, std::thread& thread) : worker_(worker), thread_(thread) {}
  ~WorkerRunGuard() {
    worker_.Stop();
    if (thread_.joinable()) {
      thread_.join();
    }
  }
  WorkerRunGuard(const WorkerRunGuard&) = delete;
  WorkerRunGuard& operator=(const WorkerRunGuard&) = delete;

 private:
  Worker& worker_;
  std::thread& thread_;
};

// Bounded poll. Exhausting the bound is a hard check failure at the call site (the
// caller asserts the returned flag), never a silent skip.
template <class Predicate>
bool PollUntil(Predicate predicate, std::chrono::milliseconds bound) {
  const std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::now() + bound;
  while (true) {
    if (predicate()) {
      return true;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      return false;
    }
    std::this_thread::yield();
  }
}

}  // namespace

// ===========================================================================
// A. Malformed identifiers and codecs.
// ===========================================================================

PP_TEST(adversarial, identity_parsing_rejects_malformed_text) {
  struct MalformedId {
    std::string text;
    std::string label;
  };
  const std::string zeros(32, '0');
  const std::vector<MalformedId> malformed = {
      {std::string(), "empty"},
      {std::string(31, '0'), "one character short"},
      {std::string(33, '0'), "one character long"},
      {std::string(32, 'A'), "uppercase hex"},
      {"0A" + std::string(30, '0'), "uppercase mixed with lowercase"},
      {"0x" + std::string(30, '0'), "0x prefixed"},
      {"-" + std::string(31, '0'), "signed"},
      {" " + std::string(31, '0'), "leading whitespace"},
      {std::string(31, '0') + " ", "trailing whitespace"},
      {std::string(16, '0') + "\t" + std::string(15, '0'), "embedded whitespace"},
      {"g" + std::string(31, '0'), "non hex character"},
      {zeros, "nil identity"},
  };
  for (const MalformedId& item : malformed) {
    PP_CHECK_MSG(!NodeId::Parse(item.text).has_value(), item.label);
    PP_CHECK_MSG(!LinkId::Parse(item.text).has_value(), item.label);
    PP_CHECK_MSG(!PortId::Parse(item.text).has_value(), item.label);
  }

  const std::string thousand(1000, 'a');
  PP_CHECK(!NodeId::Parse(thousand).has_value());
  PP_CHECK(!PortId::Parse(thousand).has_value());
  PP_CHECK(!LinkId::Parse(thousand).has_value());

  const std::string valid_text = std::string(31, '0') + "1";
  const std::optional<NodeId> parsed = NodeId::Parse(valid_text);
  PP_REQUIRE(parsed.has_value());
  PP_CHECK(parsed->IsValid());
  PP_CHECK_EQ(parsed->ToString(), valid_text);
  PP_CHECK_EQ(parsed->Span().size(), Count(16));
  PP_CHECK_EQ(parsed->Bytes().back(), std::byte{0x01});
  PP_CHECK(NodeId::Parse(parsed->ToString()).has_value());

  // Short identifiers use the same strict rules.
  const std::string short_valid = std::string(15, '0') + "1";
  const std::optional<FailureDomainId> short_parsed = FailureDomainId::Parse(short_valid);
  PP_REQUIRE(short_parsed.has_value());
  PP_CHECK_EQ(short_parsed->ToString(), short_valid);
  PP_CHECK(!FailureDomainId::Parse(std::string(16, '0')).has_value());
  PP_CHECK(!FailureDomainId::Parse(std::string(17, '0')).has_value());
  PP_CHECK(!FailureDomainId::Parse(zeros).has_value());
  PP_CHECK(!CapabilityId::Parse(std::string(15, '0') + "A").has_value());
  PP_CHECK(CapabilityId::Parse(std::string(15, '0') + "a").has_value());
}

PP_TEST(adversarial, identity_strong_uint_parse_bounds_and_checked_arithmetic) {
  const std::string thousand(1000, '1');
  const std::string twenty_one(21, '1');
  PP_CHECK(!HopCount::Parse(std::string_view()).has_value());
  PP_CHECK(!HopCount::Parse("00").has_value());
  PP_CHECK(!HopCount::Parse("01").has_value());
  PP_CHECK(!HopCount::Parse("+1").has_value());
  PP_CHECK(!HopCount::Parse("-1").has_value());
  PP_CHECK(!HopCount::Parse(" 1").has_value());
  PP_CHECK(!HopCount::Parse("1 ").has_value());
  PP_CHECK(!HopCount::Parse("0x1").has_value());
  PP_CHECK(!HopCount::Parse("1_0").has_value());
  PP_CHECK(!HopCount::Parse("1.0").has_value());
  PP_CHECK(!HopCount::Parse(twenty_one).has_value());
  PP_CHECK(!HopCount::Parse(thousand).has_value());
  PP_CHECK(!HopCount::Parse("65536").has_value());
  PP_CHECK(!HopCount::Parse("99999999999999999999").has_value());

  const std::optional<HopCount> zero = HopCount::Parse("0");
  PP_REQUIRE(zero.has_value());
  PP_CHECK_EQ(zero->Value(), 0u);
  const std::optional<HopCount> ceiling = HopCount::Parse("65535");
  PP_REQUIRE(ceiling.has_value());
  PP_CHECK_EQ(ceiling->Value(), 65535u);
  PP_CHECK(!CandidateRank::Parse("4096").has_value());
  PP_CHECK(CandidateRank::Parse("4095").has_value());
  const std::optional<CostValue> maximum = CostValue::Parse("18446744073709551615");
  PP_REQUIRE(maximum.has_value());
  PP_CHECK_EQ(maximum->Value(), std::numeric_limits<std::uint64_t>::max());
  PP_CHECK(!CostValue::Parse("18446744073709551616").has_value());

  PP_CHECK(!HopCount::TryFrom(65536).has_value());
  PP_CHECK(HopCount::TryFrom(65535).has_value());
  PP_CHECK(!CandidateRank::TryFrom(4096).has_value());
  PP_CHECK(CandidateRank::TryFrom(4095).has_value());

  PP_CHECK(!CheckedAdd(HopCount(65535), HopCount(1)).has_value());
  const std::optional<HopCount> exact = CheckedAdd(HopCount(65534), HopCount(1));
  PP_REQUIRE(exact.has_value());
  PP_CHECK_EQ(exact->Value(), 65535u);
  PP_CHECK(!CheckedAdd(CostValue::Max(), CostValue(1)).has_value());
  const std::optional<CostValue> saturated = CheckedAdd(CostValue(0), CostValue::Max());
  PP_REQUIRE(saturated.has_value());
  PP_CHECK_EQ(*saturated, CostValue::Max());

  PP_CHECK(!CheckedMul(HopCount(1000), 100u).has_value());
  const std::optional<HopCount> product = CheckedMul(HopCount(1000), 65u);
  PP_REQUIRE(product.has_value());
  PP_CHECK_EQ(product->Value(), 65000u);
  const std::optional<HopCount> zero_product = CheckedMul(HopCount(0), 0u);
  PP_REQUIRE(zero_product.has_value());
  PP_CHECK_EQ(zero_product->Value(), 0u);

  PP_CHECK(!ToU32(CostValue(0x100000000ull)).has_value());
  const std::optional<std::uint32_t> narrowed = ToU32(CostValue(0xFFFFFFFFull));
  PP_REQUIRE(narrowed.has_value());
  PP_CHECK_EQ(*narrowed, 0xFFFFFFFFu);
  const std::optional<std::uint64_t> widened = ToU64(CostValue(7));
  PP_REQUIRE(widened.has_value());
  PP_CHECK_EQ(*widened, 7ull);
}

PP_TEST(adversarial, canonical_reader_rejects_malformed_input) {
  {
    const std::vector<std::byte> truncated = {std::byte{0x80}};
    ByteReader reader(SpanOf(truncated));
    PP_CHECK(!reader.VarU64().has_value());
    PP_CHECK(reader.failed());
    PP_CHECK(!reader.U8().has_value());
    PP_CHECK_EQ(reader.Position(), Count(1));
  }
  {
    const std::vector<std::byte> over_long = {std::byte{0x80}, std::byte{0x00}};
    ByteReader reader(SpanOf(over_long));
    PP_CHECK(!reader.VarU64().has_value());
    PP_CHECK(reader.failed());
  }
  {
    const std::vector<std::byte> over_long_one = {std::byte{0x81}, std::byte{0x00}};
    ByteReader reader(SpanOf(over_long_one));
    PP_CHECK(!reader.VarU64().has_value());
  }
  {
    const std::vector<std::byte> ten(10, std::byte{0xFF});
    ByteReader reader(SpanOf(ten));
    PP_CHECK(!reader.VarU64().has_value());
    PP_CHECK(reader.failed());
  }
  {
    std::vector<std::byte> ten(9, std::byte{0xFF});
    ten.push_back(std::byte{0x02});
    ByteReader reader(SpanOf(ten));
    PP_CHECK(!reader.VarU64().has_value());
  }
  {
    std::vector<std::byte> ten(9, std::byte{0xFF});
    ten.push_back(std::byte{0x01});
    ByteReader reader(SpanOf(ten));
    const std::optional<std::uint64_t> value = reader.VarU64();
    PP_REQUIRE(value.has_value());
    PP_CHECK_EQ(*value, std::numeric_limits<std::uint64_t>::max());
    PP_CHECK(reader.AtEnd());
  }
  {
    const std::vector<std::byte> canonical = {std::byte{0x81}, std::byte{0x01}};
    ByteReader reader(SpanOf(canonical));
    const std::optional<std::uint64_t> value = reader.VarU64();
    PP_REQUIRE(value.has_value());
    PP_CHECK_EQ(*value, 129ull);
  }
  {
    const std::vector<std::byte> bad_true = {std::byte{0x02}};
    ByteReader reader(SpanOf(bad_true));
    PP_CHECK(!reader.Bool().has_value());
    PP_CHECK(reader.failed());
  }
  {
    const std::vector<std::byte> bad_max = {std::byte{0xFF}};
    ByteReader reader(SpanOf(bad_max));
    PP_CHECK(!reader.Bool().has_value());
    PP_CHECK(reader.failed());
  }
  {
    const std::vector<std::byte> flags = {std::byte{0x00}, std::byte{0x01}};
    ByteReader reader(SpanOf(flags));
    const std::optional<bool> first = reader.Bool();
    PP_REQUIRE(first.has_value());
    PP_CHECK_EQ(*first, false);
    const std::optional<bool> second = reader.Bool();
    PP_REQUIRE(second.has_value());
    PP_CHECK_EQ(*second, true);
  }
  {
    const std::vector<std::byte> nothing;
    ByteReader reader(SpanOf(nothing));
    PP_CHECK(!reader.U8().has_value());
    PP_CHECK(!reader.U16().has_value());
    PP_CHECK(!reader.U32().has_value());
    PP_CHECK(!reader.U64().has_value());
    PP_CHECK(!reader.View(1).has_value());
    PP_CHECK(!reader.Text().has_value());
    std::array<std::byte, 4> out{};
    PP_CHECK(!reader.FixedBytes(std::span<std::byte>(out.data(), out.size())));
    PP_CHECK(reader.failed());
    PP_CHECK(reader.AtEnd());
    PP_CHECK_EQ(reader.Remaining(), Count(0));
  }
  {
    const std::vector<std::byte> short_text = {std::byte{0x05}, std::byte{'a'}, std::byte{'b'}};
    ByteReader reader(SpanOf(short_text));
    PP_CHECK(!reader.Text().has_value());
    PP_CHECK(reader.failed());
  }
  {
    const std::vector<std::byte> tiny = {std::byte{0x01}, std::byte{0x02}};
    ByteReader reader(SpanOf(tiny));
    std::array<std::byte, 4> out{};
    PP_CHECK(!reader.FixedBytes(std::span<std::byte>(out.data(), out.size())));
    PP_CHECK(reader.failed());
    // A failed read latches the reader: the two readable bytes must not become visible.
    PP_CHECK_EQ(reader.Remaining(), Count(2));
    PP_CHECK_EQ(reader.Position(), Count(0));
    PP_CHECK(!reader.U8().has_value());
    PP_CHECK(!reader.Bool().has_value());
    PP_CHECK(!reader.View(1).has_value());
    PP_CHECK_EQ(reader.Position(), Count(0));
  }
}

PP_TEST(adversarial, canonical_writer_ceiling_latches_overflow) {
  {
    ByteWriter writer(8);
    writer.U64(0x0102030405060708ull);
    PP_CHECK(!writer.overflowed());
    PP_CHECK_EQ(writer.size(), Count(8));
    writer.U8(0x09);
    PP_CHECK(writer.overflowed());
    PP_CHECK_EQ(writer.size(), Count(8));
    const std::size_t frozen = writer.size();
    writer.U32(0xDEADBEEFu);
    writer.Text("adversarial");
    writer.VarU64(1);
    writer.Bool(true);
    PP_CHECK_EQ(writer.size(), frozen);
    PP_CHECK_EQ(writer.data().at(7), std::byte{0x01});
  }
  {
    ByteWriter writer(8);
    const std::vector<std::byte> first = {std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const std::vector<std::byte> second = {std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}, std::byte{9}};
    writer.FixedBytes(SpanOf(first));
    PP_CHECK_EQ(writer.size(), Count(4));
    writer.FixedBytes(SpanOf(second));
    PP_CHECK(writer.overflowed());
    PP_CHECK_EQ(writer.size(), Count(4));
  }
  {
    ByteWriter writer(0);
    writer.U8(0x01);
    PP_CHECK(writer.overflowed());
    PP_CHECK_EQ(writer.size(), Count(0));
    PP_CHECK(writer.data().empty());
  }
  {
    ByteWriter writer(1);
    writer.VarU64(128);
    PP_CHECK(writer.overflowed());
    PP_CHECK_EQ(writer.size(), Count(1));
    PP_CHECK_EQ(writer.data().at(0), std::byte{0x80});
  }
}

// ===========================================================================
// B. Malformed requests.
// ===========================================================================

PP_TEST(adversarial, request_nil_identities_are_malformed) {
  const Fabric fabric = MakeFabric();
  PlannerRuntime runtime(ConfigFor(fabric.snapshot));
  const ResourceLimits limits;

  const PlanningRequest base = MakeAToCRequest(fabric, 1, "adversarial.nil.base");
  PP_CHECK(ValidateRequest(base, limits).ok());

  PlanningRequest nil_request = base;
  nil_request.id = PlanningRequestId{};
  RequestValidation validation = ValidateRequest(nil_request, limits);
  PP_REQUIRE(validation.code.has_value());
  PP_CHECK_EQ(*validation.code, DiagnosticCode::kMalformedIdentifier);
  PlanningResult result = runtime.Plan(nil_request);
  PP_CHECK_EQ(result.status, PlanStatus::kMalformedRequest);
  PP_REQUIRE(result.primary_failure.has_value());
  PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kMalformedIdentifier);
  PP_CHECK(result.candidates.empty());

  PlanningRequest nil_source = base;
  nil_source.source.id = EndpointId{};
  validation = ValidateRequest(nil_source, limits);
  PP_REQUIRE(validation.code.has_value());
  PP_CHECK_EQ(*validation.code, DiagnosticCode::kMalformedIdentifier);
  result = runtime.Plan(nil_source);
  PP_CHECK_EQ(result.status, PlanStatus::kMalformedRequest);
  PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kMalformedIdentifier);

  PlanningRequest nil_destination = base;
  nil_destination.destination.id = EndpointId{};
  validation = ValidateRequest(nil_destination, limits);
  PP_REQUIRE(validation.code.has_value());
  PP_CHECK_EQ(*validation.code, DiagnosticCode::kMalformedIdentifier);
  result = runtime.Plan(nil_destination);
  PP_CHECK_EQ(result.status, PlanStatus::kMalformedRequest);
  PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kMalformedIdentifier);

  PlanningRequest nil_constraint_set = base;
  nil_constraint_set.constraints.id = ConstraintSetId{};
  validation = ValidateRequest(nil_constraint_set, limits);
  PP_REQUIRE(validation.code.has_value());
  PP_CHECK_EQ(*validation.code, DiagnosticCode::kMalformedIdentifier);
}

PP_TEST(adversarial, request_candidate_ceiling_and_zero_are_resource_limits) {
  const Fabric fabric = MakeFabric();
  PlannerRuntime runtime(ConfigFor(fabric.snapshot));
  const ResourceLimits limits;
  PP_CHECK_EQ(limits.max_candidates_per_request, 64u);

  PlanningRequest zero = MakeAToCRequest(fabric, 0, "adversarial.candidates.zero");
  RequestValidation validation = ValidateRequest(zero, limits);
  PP_REQUIRE(validation.code.has_value());
  PP_CHECK_EQ(*validation.code, DiagnosticCode::kCandidateLimitExceeded);
  // A zero candidate count is classified as an invalid value (MALFORMED_REQUEST); only a
  // count above the configured ceiling is a resource-shape breach (RESOURCE_LIMIT).
  PP_CHECK_EQ(StatusForValidationCode(DiagnosticCode::kCandidateLimitExceeded),
              PlanStatus::kMalformedRequest);
  const PlanningResult zero_result = runtime.Plan(zero);
  PP_CHECK_MSG(zero_result.status == PlanStatus::kMalformedRequest,
               std::string("expected MALFORMED_REQUEST, observed ") + std::string(ToString(zero_result.status)));
  PP_REQUIRE(zero_result.primary_failure.has_value());
  PP_CHECK_EQ(*zero_result.primary_failure, DiagnosticCode::kCandidateLimitExceeded);
  PP_CHECK(zero_result.candidates.empty());

  PlanningRequest absurd = MakeAToCRequest(fabric, 100000, "adversarial.candidates.absurd");
  validation = ValidateRequest(absurd, limits);
  PP_REQUIRE(validation.code.has_value());
  PP_CHECK_EQ(*validation.code, DiagnosticCode::kRequestedCandidatesAboveCeiling);
  const PlanningResult absurd_result = runtime.Plan(absurd);
  PP_CHECK_EQ(absurd_result.status, PlanStatus::kResourceLimit);
  PP_REQUIRE(absurd_result.primary_failure.has_value());
  PP_CHECK_EQ(*absurd_result.primary_failure, DiagnosticCode::kRequestedCandidatesAboveCeiling);
  PP_CHECK(absurd_result.candidates.empty());

  const PlanningRequest at_ceiling =
      MakeAToCRequest(fabric, limits.max_candidates_per_request, "adversarial.candidates.ceiling");
  PP_CHECK_EQ(runtime.Plan(at_ceiling).status, PlanStatus::kPlanned);
}

PP_TEST(adversarial, request_duplicate_and_unsupported_policy_shapes) {
  const Fabric fabric = MakeFabric();
  PlannerRuntime runtime(ConfigFor(fabric.snapshot));
  const ResourceLimits limits;

  PlanningRequest duplicate = MakeAToCRequest(fabric, 1, "adversarial.constraints.duplicate");
  duplicate.constraints.forbidden_links = {fabric.ab, fabric.ab};
  RequestValidation validation = ValidateRequest(duplicate, limits);
  PP_REQUIRE(validation.code.has_value());
  PP_CHECK_EQ(*validation.code, DiagnosticCode::kDuplicateConstraintEntry);
  const PlanningResult duplicate_result = runtime.Plan(duplicate);
  PP_CHECK_EQ(duplicate_result.status, PlanStatus::kMalformedRequest);
  PP_REQUIRE(duplicate_result.primary_failure.has_value());
  PP_CHECK_EQ(*duplicate_result.primary_failure, DiagnosticCode::kDuplicateConstraintEntry);
  PP_CHECK(duplicate_result.candidates.empty());

  PlanningRequest duplicate_nodes = MakeAToCRequest(fabric, 1, "adversarial.constraints.duplicate.nodes");
  duplicate_nodes.constraints.forbidden_nodes = {fabric.b, fabric.b};
  validation = ValidateRequest(duplicate_nodes, limits);
  PP_REQUIRE(validation.code.has_value());
  PP_CHECK_EQ(*validation.code, DiagnosticCode::kDuplicateConstraintEntry);

  PlanningRequest locality = MakeAToCRequest(fabric, 1, "adversarial.policy.locality");
  locality.policy.cost_model.locality_penalty = CostValue(5);
  PP_CHECK(locality.policy.locality_scope.empty());
  validation = ValidateRequest(locality, limits);
  PP_REQUIRE(validation.code.has_value());
  PP_CHECK_EQ(*validation.code, DiagnosticCode::kUnsupportedRequest);
  const PlanningResult locality_result = runtime.Plan(locality);
  PP_CHECK_EQ(locality_result.status, PlanStatus::kUnsupported);
  PP_REQUIRE(locality_result.primary_failure.has_value());
  PP_CHECK_EQ(*locality_result.primary_failure, DiagnosticCode::kUnsupportedRequest);

  // The same penalty with a real scope is supported and stays PLANNED.
  PlanningRequest scoped = MakeAToCRequest(fabric, 1, "adversarial.policy.locality.scoped");
  scoped.policy.cost_model.locality_penalty = CostValue(5);
  scoped.policy.locality_scope = {fabric.a, fabric.b, fabric.c};
  PP_CHECK(ValidateRequest(scoped, limits).ok());
  PP_CHECK_EQ(runtime.Plan(scoped).status, PlanStatus::kPlanned);

  PlanningRequest nil_locality = MakeAToCRequest(fabric, 1, "adversarial.policy.locality.nil");
  nil_locality.policy.cost_model.locality_penalty = CostValue(1);
  nil_locality.policy.locality_scope = {NodeId{}};
  validation = ValidateRequest(nil_locality, limits);
  PP_REQUIRE(validation.code.has_value());
  PP_CHECK_EQ(*validation.code, DiagnosticCode::kMalformedIdentifier);
}

PP_TEST(adversarial, request_unknown_enum_survives_wire_decoding_as_malformed) {
  const Fabric fabric = MakeFabric();
  const ResourceLimits limits;
  const PlanningRequest request = MakeAToCRequest(fabric, 2, "adversarial.wire.enum");

  ByteWriter writer(kDefaultEncodingCeiling);
  EncodePlanningRequestPayload(writer, request);
  PP_REQUIRE(!writer.overflowed());
  std::vector<std::byte> payload(writer.data().begin(), writer.data().end());

  PlanningRequest decoded;
  std::string detail;
  PP_CHECK_EQ(DecodePlanningRequestPayload(SpanOf(payload), limits, decoded, detail), WireStatus::kOk);
  PP_CHECK_EQ(decoded.id, request.id);
  PP_CHECK_EQ(decoded.constraints.layer, PathLayer::kPhysical);
  PP_CHECK_EQ(decoded.max_candidates, request.max_candidates);
  PP_CHECK(decoded.constraints.forbidden_links.empty());

  // Layout: request id (16), source id (16), source class (4), source generation (8),
  // destination id (16), destination class (4), destination generation (8), constraint
  // set id (16), constraint generation (8); the layer enumeration follows.
  const std::size_t layer_offset = 16 + 16 + 4 + 8 + 16 + 4 + 8 + 16 + 8;
  PP_CHECK_EQ(layer_offset, Count(96));

  payload[layer_offset + 3] ^= std::byte{0x01};
  PlanningRequest mutated;
  std::string mutated_detail;
  PP_CHECK_EQ(DecodePlanningRequestPayload(SpanOf(payload), limits, mutated, mutated_detail),
              WireStatus::kMalformed);
  PP_CHECK(!mutated_detail.empty());
  PP_CHECK(mutated_detail.find("layer") != std::string::npos);

  payload[layer_offset + 3] ^= std::byte{0x01};
  payload[layer_offset + 1] ^= std::byte{0x01};
  std::string second_detail;
  PP_CHECK_EQ(DecodePlanningRequestPayload(SpanOf(payload), limits, mutated, second_detail),
              WireStatus::kMalformed);
  PP_CHECK(!second_detail.empty());

  // Restoring the injected bits restores a decodable payload: the rejection is caused by
  // the unknown enumeration value and nothing else.
  payload[layer_offset + 1] ^= std::byte{0x01};
  PlanningRequest restored;
  std::string restored_detail;
  PP_CHECK_EQ(DecodePlanningRequestPayload(SpanOf(payload), limits, restored, restored_detail), WireStatus::kOk);
  PP_CHECK_EQ(restored.id, request.id);
}

PP_TEST(adversarial, request_empty_constraint_set_still_plans) {
  const Fabric fabric = MakeFabric();
  PlannerRuntime runtime(ConfigFor(fabric.snapshot));
  const PlanningRequest request = MakeAToCRequest(fabric, 2, "adversarial.empty.constraints");
  PP_CHECK_EQ(request.constraints.EntryCount(), Count(0));
  PP_CHECK(request.constraints.forbidden_nodes.empty());
  PP_CHECK(request.constraints.forbidden_links.empty());
  PP_CHECK(request.constraints.required_transit.empty());
  PP_CHECK(!request.constraints.max_hops.has_value());

  const PlanningResult result = runtime.Plan(request);
  PP_CHECK_EQ(result.status, PlanStatus::kPlanned);
  PP_CHECK_EQ(result.candidates.size(), Count(2));
  PP_CHECK(!result.truncated);
  PP_CHECK_EQ(result.requested_candidates, 2u);
}

// ===========================================================================
// C. Authority and currentness attacks.
// ===========================================================================

PP_TEST(adversarial, authority_scope_epoch_topology_and_snapshot_attacks) {
  const Fabric fabric = MakeFabric();
  PlannerRuntime runtime(ConfigFor(fabric.snapshot));
  const FabricEpoch runtime_epoch = runtime.CurrentEpoch();
  PP_CHECK_EQ(runtime_epoch.Value(), 1ull);

  // 1. enforce_scope without kSubmitPlanRequest.
  PlanningRequest unauthorized = MakeAToCRequest(fabric, 1, "adversarial.authority.scope");
  unauthorized.authority.enforce_scope = true;
  unauthorized.authority.scope_mask = ToMask(AuthorityScope::kReadPlan);
  PlanningResult result = runtime.Plan(unauthorized);
  PP_CHECK_EQ(result.status, PlanStatus::kUnauthorized);
  PP_REQUIRE(result.primary_failure.has_value());
  PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kAuthorityScopeInsufficient);
  PP_CHECK(result.candidates.empty());

  PlanningRequest authorized = MakeAToCRequest(fabric, 1, "adversarial.authority.scope.ok");
  authorized.authority.enforce_scope = true;
  authorized.authority.scope_mask =
      CombineScopes(AuthorityScope::kReadPlan, AuthorityScope::kSubmitPlanRequest);
  PP_CHECK_EQ(runtime.Plan(authorized).status, PlanStatus::kPlanned);

  // 2. epoch_bound with a mismatched coordinator epoch.
  PlanningRequest stale_epoch = MakeAToCRequest(fabric, 1, "adversarial.authority.epoch");
  stale_epoch.authority.epoch_bound = true;
  stale_epoch.authority.coordinator_epoch = CoordinatorEpoch(runtime_epoch.Value() + 1);
  result = runtime.Plan(stale_epoch);
  PP_CHECK_EQ(result.status, PlanStatus::kEpochStale);
  PP_REQUIRE(result.primary_failure.has_value());
  PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kEpochMismatch);
  PP_CHECK(result.candidates.empty());

  PlanningRequest bound_epoch = MakeAToCRequest(fabric, 1, "adversarial.authority.epoch.ok");
  bound_epoch.authority.epoch_bound = true;
  bound_epoch.authority.coordinator_epoch = CoordinatorEpoch(runtime_epoch.Value());
  PP_CHECK_EQ(runtime.Plan(bound_epoch).status, PlanStatus::kPlanned);

  // 3. expect_topology with a wrong generation.
  PlanningRequest stale_topology = MakeAToCRequest(fabric, 1, "adversarial.authority.topology");
  stale_topology.expect_topology = true;
  stale_topology.expected_topology = TopologyGeneration(fabric.snapshot->Generations().topology.Value() + 1);
  result = runtime.Plan(stale_topology);
  PP_CHECK_EQ(result.status, PlanStatus::kTopologyStale);
  PP_REQUIRE(result.primary_failure.has_value());
  PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kTopologyGenerationMismatch);

  PlanningRequest expected_topology = MakeAToCRequest(fabric, 1, "adversarial.authority.topology.ok");
  expected_topology.expect_topology = true;
  expected_topology.expected_topology = fabric.snapshot->Generations().topology;
  PP_CHECK_EQ(runtime.Plan(expected_topology).status, PlanStatus::kPlanned);

  // 4. expect_snapshot with a wrong identity.
  PlanningRequest stale_snapshot = MakeAToCRequest(fabric, 1, "adversarial.authority.snapshot");
  stale_snapshot.expect_snapshot = true;
  stale_snapshot.expected_snapshot = TestId<SnapshotId>("adversarial.other.snapshot");
  PP_CHECK(stale_snapshot.expected_snapshot != fabric.snapshot->Id());
  result = runtime.Plan(stale_snapshot);
  PP_CHECK_EQ(result.status, PlanStatus::kRevalidationRequired);
  PP_REQUIRE(result.primary_failure.has_value());
  PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kStaleEvidence);
  PP_CHECK(result.candidates.empty());

  PlanningRequest expected_snapshot = MakeAToCRequest(fabric, 1, "adversarial.authority.snapshot.ok");
  expected_snapshot.expect_snapshot = true;
  expected_snapshot.expected_snapshot = fabric.snapshot->Id();
  PP_CHECK_EQ(runtime.Plan(expected_snapshot).status, PlanStatus::kPlanned);

  // A nil expected snapshot is malformed rather than silently ignored.
  PlanningRequest nil_snapshot = MakeAToCRequest(fabric, 1, "adversarial.authority.snapshot.nil");
  nil_snapshot.expect_snapshot = true;
  nil_snapshot.expected_snapshot = SnapshotId{};
  const RequestValidation nil_validation = ValidateRequest(nil_snapshot, runtime.Limits());
  PP_REQUIRE(nil_validation.code.has_value());
  PP_CHECK_EQ(*nil_validation.code, DiagnosticCode::kMalformedIdentifier);
  PP_CHECK_EQ(runtime.Plan(nil_snapshot).status, PlanStatus::kMalformedRequest);
}

// ===========================================================================
// D. Protocol attacks.
// ===========================================================================

PP_TEST(adversarial, protocol_frame_decoder_rejects_every_mutation) {
  const WorkerBootId boot = TestId<WorkerBootId>("adversarial.frame.boot");
  const PlanningRequestId request = TestId<PlanningRequestId>("adversarial.frame.request");
  const std::vector<std::byte> payload = BytesOf("adversarial.payload");
  const std::vector<std::byte> frame =
      MakeFrame(WireMessage::kPlanRequest, kWireFlagResponse, CoordinatorEpoch(9), boot, request, SpanOf(payload));
  PP_CHECK_EQ(frame.size(), kWireHeaderBytes + payload.size());

  WireFrame decoded;
  PP_CHECK_EQ(DecodeFrameOf(frame, decoded), WireStatus::kOk);
  PP_CHECK_EQ(decoded.type, WireMessage::kPlanRequest);
  PP_CHECK_EQ(decoded.flags, kWireFlagResponse);
  PP_CHECK_EQ(decoded.coordinator_epoch.Value(), 9ull);
  PP_CHECK_EQ(decoded.worker_boot, boot);
  PP_CHECK_EQ(decoded.request, request);
  PP_CHECK_EQ(decoded.payload.size(), payload.size());

  // Targeted structural rejections.
  {
    std::vector<std::byte> bad_magic = frame;
    WriteU32LE(bad_magic, 0, 0xDEADBEEFu);
    PP_CHECK_EQ(DecodeFrameOf(bad_magic, decoded), WireStatus::kMalformed);
  }
  {
    std::vector<std::byte> bad_version = frame;
    bad_version[4] = std::byte{0x02};
    PP_CHECK_EQ(DecodeFrameOf(bad_version, decoded), WireStatus::kVersionMismatch);
  }
  {
    std::vector<std::byte> bad_message = frame;
    WriteU32LE(bad_message, 8, 0x7FFFFFFFu);
    PP_CHECK_EQ(DecodeFrameOf(bad_message, decoded), WireStatus::kUnknownMessage);
  }
  {
    std::vector<std::byte> bad_flags = frame;
    bad_flags[7] = std::byte{0x01};
    PP_CHECK_EQ(DecodeFrameOf(bad_flags, decoded), WireStatus::kMalformed);
  }
  {
    std::vector<std::byte> bad_reserved = frame;
    WriteU32LE(bad_reserved, 56, 1u);
    PP_CHECK_EQ(DecodeFrameOf(bad_reserved, decoded), WireStatus::kMalformed);
  }
  {
    std::vector<std::byte> short_payload = frame;
    short_payload.pop_back();
    PP_CHECK_EQ(DecodeFrameOf(short_payload, decoded), WireStatus::kMalformed);
  }
  {
    std::vector<std::byte> extra_bytes = frame;
    extra_bytes.push_back(std::byte{0x00});
    PP_CHECK_EQ(DecodeFrameOf(extra_bytes, decoded), WireStatus::kTrailingBytes);
  }
  {
    std::vector<std::byte> short_header = frame;
    short_header.resize(kWireHeaderBytes - 1);
    PP_CHECK_EQ(DecodeFrameOf(short_header, decoded), WireStatus::kMalformed);
  }
  {
    std::vector<std::byte> empty;
    PP_CHECK_EQ(DecodeFrameOf(empty, decoded), WireStatus::kMalformed);
  }
  {
    std::vector<std::byte> too_large = frame;
    WriteU32LE(too_large, 52, kFrameCeiling + 1);
    PP_CHECK_EQ(DecodeFrameOf(too_large, decoded), WireStatus::kTooLarge);
  }

  // Exhaustive single-bit mutation: no single flipped bit may yield an accepted frame.
  for (std::size_t index = 0; index < frame.size(); ++index) {
    for (unsigned bit = 0; bit < 8; ++bit) {
      std::vector<std::byte> mutated = frame;
      mutated[index] ^= static_cast<std::byte>(1u << bit);
      WireFrame mutated_frame;
      const WireStatus status = DecodeFrameOf(mutated, mutated_frame);
      const bool classified = status == WireStatus::kMalformed || status == WireStatus::kVersionMismatch ||
                              status == WireStatus::kUnknownMessage ||
                              status == WireStatus::kIntegrityMismatch ||
                              status == WireStatus::kTrailingBytes || status == WireStatus::kTooLarge;
      PP_CHECK_MSG(status != WireStatus::kOk, "a single flipped bit produced an accepted frame");
      PP_CHECK_MSG(classified,
                   "a single flipped bit produced an unclassified status " + std::string(ToString(status)));
    }
  }

  // A mutated integrity field is detected even when the header and payload are intact.
  {
    std::vector<std::byte> bad_integrity = frame;
    bad_integrity[kWireHeaderBytes - kWireIntegrityBytes] ^= std::byte{0x01};
    PP_CHECK_EQ(DecodeFrameOf(bad_integrity, decoded), WireStatus::kIntegrityMismatch);
  }
}

PP_TEST(adversarial, protocol_worker_publication_authority_matrix) {
  SocketRuntime socket_runtime;
  PP_REQUIRE(socket_runtime.ready());
  const Fabric fabric = MakeFabric();

  CoordinatorConfig config;
  config.bind_address = "127.0.0.1";
  config.port = 0;
  config.snapshot = fabric.snapshot;
  config.initial_epoch = FabricEpoch(1);
  config.limits.receive_bound_ms = 2000;
  Coordinator coordinator(config);
  std::string error;
  PP_REQUIRE(coordinator.Start(error));
  PP_REQUIRE(coordinator.running());
  PP_REQUIRE(coordinator.Port() != 0);
  PP_CHECK_EQ(coordinator.SessionCount(), Count(0));

  const WorkerBootId boot = MakeWorkerBootIdFromLabel("adversarial.worker.boot");
  const WorkerBootId never_registered = MakeWorkerBootIdFromLabel("adversarial.worker.never-registered");
  const SnapshotId other_snapshot = TestId<SnapshotId>("adversarial.other.snapshot");
  const PlanningRequestId request = TestId<PlanningRequestId>("adversarial.wire.publication");
  PP_CHECK(boot != never_registered);
  PP_CHECK(other_snapshot != fabric.snapshot->Id());

  RawClient client;
  Require(client.Connect("127.0.0.1", coordinator.Port(), error), "client connect failed: " + error);

  HelloPayload hello;
  hello.publisher = MakePublisherIdFromLabel("adversarial.publisher");
  hello.boot = boot;
  hello.coordinator_epoch = CoordinatorEpoch(1);
  hello.snapshot = fabric.snapshot->Id();
  hello.generations = fabric.snapshot->Generations();
  hello.node_count = static_cast<std::uint32_t>(fabric.snapshot->NodeCount());
  hello.edge_count = static_cast<std::uint32_t>(fabric.snapshot->EdgeCount());
  Require(client.SendBytes(MakeHelloFrame(hello, boot, request, CoordinatorEpoch(1)), error),
          "hello frame was not sent: " + error);

  WireFrame response;
  Require(client.ReadFrame(response, error), "the handshake response was not readable: " + error);
  PP_CHECK_EQ(response.type, WireMessage::kSnapshotResponse);
  PP_CHECK((response.flags & kWireFlagResponse) != 0);
  SnapshotResponsePayload snapshot_response;
  std::string detail;
  PP_CHECK_EQ(DecodeSnapshotResponsePayload(SpanOf(response.payload), snapshot_response, detail), WireStatus::kOk);
  PP_CHECK_EQ(snapshot_response.snapshot, fabric.snapshot->Id());

  // The handshake registered the boot identity; the registry is public API.
  const std::vector<WorkerRegistration> workers = coordinator.Workers();
  PP_CHECK_EQ(workers.size(), Count(1));
  PP_REQUIRE(!workers.empty());
  PP_CHECK_EQ(workers.front().boot, boot);
  PP_CHECK(!workers.front().fenced);

  detail.clear();
  PP_CHECK_EQ(coordinator.ValidateWorkerPublication(boot, CoordinatorEpoch(1), fabric.snapshot->Id(), detail),
              WireStatus::kOk);
  detail.clear();
  PP_CHECK_EQ(coordinator.ValidateWorkerPublication(boot, CoordinatorEpoch(2), fabric.snapshot->Id(), detail),
              WireStatus::kEpochStale);
  PP_CHECK(!detail.empty());
  detail.clear();
  PP_CHECK_EQ(coordinator.ValidateWorkerPublication(boot, CoordinatorEpoch(1), other_snapshot, detail),
              WireStatus::kSnapshotMismatch);
  PP_CHECK(!detail.empty());
  detail.clear();
  PP_CHECK_EQ(
      coordinator.ValidateWorkerPublication(never_registered, CoordinatorEpoch(1), fabric.snapshot->Id(), detail),
      WireStatus::kUnknownWorker);
  PP_CHECK(!detail.empty());

  // A PLAN_RESULT from a boot that never registered is refused on the wire.
  PlanErrorPayload stub;
  stub.request = request;
  stub.detail = "unregistered publication";
  const std::vector<std::byte> stub_payload = EncodePlanError(stub);
  Require(client.SendBytes(MakeFrame(WireMessage::kPlanResult, 0, CoordinatorEpoch(1), never_registered, request,
                                     SpanOf(stub_payload)),
                           error),
          "rogue publication was not sent: " + error);
  WireFrame refusal;
  Require(client.ReadFrame(refusal, error), "the refusal was not readable: " + error);
  PP_CHECK_EQ(refusal.type, WireMessage::kFenceNotice);
  PP_CHECK((refusal.flags & kWireFlagFenced) != 0);
  FenceNoticePayload notice;
  std::string notice_detail;
  PP_CHECK_EQ(DecodeFenceNoticePayload(SpanOf(refusal.payload), notice, notice_detail), WireStatus::kOk);
  PP_CHECK(notice.status == WireStatus::kWorkerFenced || notice.status == WireStatus::kUnknownWorker);
  PP_CHECK_EQ(notice.boot, never_registered);

  // Administrative fencing of a registered boot.
  Require(coordinator.FenceWorker(boot, error), "fencing the registered boot failed: " + error);
  WireFrame fence;
  Require(client.ReadFrame(fence, error), "the fence notice was not readable: " + error);
  PP_CHECK_EQ(fence.type, WireMessage::kFenceNotice);
  FenceNoticePayload fence_payload;
  std::string fence_detail;
  PP_CHECK_EQ(DecodeFenceNoticePayload(SpanOf(fence.payload), fence_payload, fence_detail), WireStatus::kOk);
  PP_CHECK_EQ(fence_payload.status, WireStatus::kWorkerFenced);
  PP_CHECK_EQ(fence_payload.boot, boot);
  detail.clear();
  PP_CHECK_EQ(coordinator.ValidateWorkerPublication(boot, CoordinatorEpoch(1), fabric.snapshot->Id(), detail),
              WireStatus::kWorkerFenced);

  // A fenced boot that publishes anyway is refused again.
  Require(client.SendBytes(MakeFrame(WireMessage::kPlanResult, 0, CoordinatorEpoch(1), boot, request,
                                     SpanOf(stub_payload)),
                           error),
          "fenced publication was not sent: " + error);
  WireFrame second_fence;
  Require(client.ReadFrame(second_fence, error), "the second fence notice was not readable: " + error);
  PP_CHECK_EQ(second_fence.type, WireMessage::kFenceNotice);
  FenceNoticePayload second_payload;
  std::string second_detail;
  PP_CHECK_EQ(DecodeFenceNoticePayload(SpanOf(second_fence.payload), second_payload, second_detail),
              WireStatus::kOk);
  PP_CHECK_EQ(second_payload.status, WireStatus::kWorkerFenced);
  PP_CHECK_EQ(second_payload.boot, boot);
  PP_CHECK_EQ(coordinator.AcceptedPublications(), 0ull);

  client.Close();
  coordinator.Stop();
  const bool drained = PollUntil([&coordinator]() { return coordinator.SessionCount() == 0; },
                                 std::chrono::milliseconds(5000));
  PP_CHECK_MSG(drained, "the worker session did not drain after Stop()");
}

PP_TEST(adversarial, protocol_real_worker_registration_and_fence) {
  SocketRuntime socket_runtime;
  PP_REQUIRE(socket_runtime.ready());
  const Fabric fabric = MakeFabric();

  CoordinatorConfig config;
  config.bind_address = "127.0.0.1";
  config.port = 0;
  config.snapshot = fabric.snapshot;
  config.initial_epoch = FabricEpoch(1);
  config.limits.receive_bound_ms = 2000;
  Coordinator coordinator(config);
  std::string error;
  PP_REQUIRE(coordinator.Start(error));
  PP_REQUIRE(coordinator.Port() != 0);

  // A production Worker registers through the public registration handshake.
  const WorkerBootId boot = MakeWorkerBootIdFromLabel("adversarial.real.worker");
  WorkerConfig worker_config;
  worker_config.coordinator_endpoint = coordinator.Endpoint();
  worker_config.snapshot = fabric.snapshot;
  worker_config.publisher = MakePublisherIdFromLabel("adversarial.real.publisher");
  worker_config.boot = boot;
  worker_config.limits = config.limits;
  Worker worker(worker_config);

  bool run_result = true;
  std::string run_error;
  std::thread worker_thread([&worker, &run_result, &run_error]() { run_result = worker.Run(run_error); });

  {
    WorkerRunGuard guard(worker, worker_thread);
    const bool registered =
        PollUntil([&worker]() { return worker.registered(); }, std::chrono::milliseconds(5000));
    PP_CHECK_MSG(registered, "the worker never completed its registration handshake");
    const std::vector<WorkerRegistration> workers = coordinator.Workers();
    PP_CHECK_EQ(workers.size(), Count(1));
    if (!workers.empty()) {
      PP_CHECK_EQ(workers.front().boot, boot);
      PP_CHECK(!workers.front().fenced);
    }
    std::string detail;
    PP_CHECK_EQ(coordinator.ValidateWorkerPublication(boot, CoordinatorEpoch(1), fabric.snapshot->Id(), detail),
                WireStatus::kOk);
    std::string fence_error;
    Require(coordinator.FenceWorker(boot, fence_error),
            "fencing a registered worker failed: " + fence_error);
    const bool observed = PollUntil([&worker]() { return worker.fenced(); }, std::chrono::milliseconds(5000));
    PP_CHECK_MSG(observed, "the registered worker never observed its fence notice");
    detail.clear();
    PP_CHECK_EQ(coordinator.ValidateWorkerPublication(boot, CoordinatorEpoch(1), fabric.snapshot->Id(), detail),
                WireStatus::kWorkerFenced);
  }

  PP_CHECK(!run_result);
  PP_CHECK(!run_error.empty());
  PP_CHECK(worker.fenced());
  PP_CHECK_EQ(coordinator.AcceptedPublications(), 0ull);
  coordinator.Stop();
}

PP_TEST(adversarial, protocol_partial_frame_does_not_pin_a_session) {
  SocketRuntime socket_runtime;
  PP_REQUIRE(socket_runtime.ready());
  const Fabric fabric = MakeFabric();

  CoordinatorConfig config;
  config.bind_address = "127.0.0.1";
  config.port = 0;
  config.snapshot = fabric.snapshot;
  config.limits.receive_bound_ms = 250;
  Coordinator coordinator(config);
  std::string error;
  PP_REQUIRE(coordinator.Start(error));
  PP_REQUIRE(coordinator.Port() != 0);

  RawClient client;
  Require(client.Connect("127.0.0.1", coordinator.Port(), error), "client connect failed: " + error);

  // Ten bytes of a header and then silence: the receive bound must end the session.
  std::array<std::byte, 10> partial{};
  partial[0] = std::byte{0x50};  // 'P': the first magic byte, and then nothing
  Require(client.SendBytes(std::span<const std::byte>(partial.data(), partial.size()), error),
          "the partial frame was not sent: " + error);

  const bool admitted =
      PollUntil([&coordinator]() { return coordinator.SessionCount() >= 1; }, std::chrono::milliseconds(5000));
  PP_CHECK_MSG(admitted, "the coordinator never admitted the partial-frame session");

  const bool drained =
      PollUntil([&coordinator]() { return coordinator.SessionCount() == 0; }, std::chrono::milliseconds(10000));
  PP_CHECK_MSG(drained, "a partial frame pinned the session past the configured receive bound");

  // The peer is still connected; the bound, not the peer, ended the session.
  PP_CHECK_EQ(coordinator.SessionCount(), Count(0));
  client.Close();
  coordinator.Stop();
}

// ===========================================================================
// E. Persistence attacks.
// ===========================================================================

PP_TEST(adversarial, persistence_decoder_rejects_every_corruption) {
  const Fabric fabric = MakeFabric();
  PlannerRuntime runtime(ConfigFor(fabric.snapshot));
  PlanningResult result;
  const PlanningRequest request = MakeAToCRequest(fabric, 2, "adversarial.store.record");
  const PathPlan plan = PlanOnce(runtime, request, result);
  PP_REQUIRE(result.status == PlanStatus::kPlanned);
  PP_REQUIRE(result.candidates.size() == Count(2));
  PP_REQUIRE(plan.id.IsValid());

  const StoredPlanRecord record = ToStoredRecord(plan);
  PP_CHECK_EQ(record.plan, plan.id);
  PP_REQUIRE(record.candidates.size() == Count(2));
  PP_REQUIRE(record.candidates.front().hops.size() == Count(2));

  const std::vector<std::byte> image = EncodeImage({record});
  PP_CHECK(image.size() > kStoreHeaderBytes + kStoreDigestBytes);

  // Baseline: the untouched image decodes.
  {
    std::vector<StoredPlanRecord> decoded;
    const StoreResult baseline = DecodePlanStore(SpanOf(image), ResourceLimits{}, decoded);
    PP_CHECK_MSG(baseline.ok, "the pristine store image was rejected: " + baseline.detail);
    PP_CHECK_EQ(decoded.size(), Count(1));
  }

  // Empty image and bad magic.
  DecodeExpect(std::span<const std::byte>(), DiagnosticCode::kPersistenceCorrupt, "empty image");
  {
    std::vector<std::byte> bad_magic = image;
    bad_magic[0] ^= std::byte{0x01};
    DecodeExpect(SpanOf(bad_magic), DiagnosticCode::kPersistenceCorrupt, "bad magic");
  }

  // Unsupported representation versions.
  {
    std::vector<std::byte> bad_version = image;
    WriteU32LE(bad_version, 8, kPersistedFormatVersion + 1);
    DecodeExpect(SpanOf(bad_version), DiagnosticCode::kPersistenceVersionUnsupported, "format version");
  }
  {
    std::vector<std::byte> bad_rule_version = image;
    WriteU32LE(bad_rule_version, 12, kPlanningRuleVersion + 1);
    DecodeExpect(SpanOf(bad_rule_version), DiagnosticCode::kPersistenceVersionUnsupported,
                 "planning rule version");
  }

  // Every truncation length of a valid image.
  for (std::size_t length = 0; length < image.size(); ++length) {
    const std::span<const std::byte> truncated(image.data(), length);
    std::vector<StoredPlanRecord> decoded;
    const StoreResult outcome = DecodePlanStore(truncated, ResourceLimits{}, decoded);
    PP_CHECK_MSG(!outcome.ok, "a truncated store image was accepted at length " + std::to_string(length));
    PP_CHECK_MSG(outcome.code == DiagnosticCode::kPersistenceCorrupt,
                 "unexpected diagnostic at truncation length " + std::to_string(length) + ": " +
                     std::string(ToString(outcome.code)));
  }

  // Single flipped bit in the payload, then in the digest.
  {
    std::vector<std::byte> payload_flip = image;
    payload_flip[kStoreHeaderBytes + kStoreDigestBytes] ^= std::byte{0x01};
    DecodeExpect(SpanOf(payload_flip), DiagnosticCode::kPersistenceDigestMismatch, "payload bit flip");
  }
  {
    std::vector<std::byte> digest_flip = image;
    digest_flip[kStoreHeaderBytes] ^= std::byte{0x01};
    DecodeExpect(SpanOf(digest_flip), DiagnosticCode::kPersistenceDigestMismatch, "digest bit flip");
  }

  // Trailing garbage.
  {
    std::vector<std::byte> trailing = image;
    trailing.push_back(std::byte{0x00});
    trailing.push_back(std::byte{0x00});
    DecodeExpect(SpanOf(trailing), DiagnosticCode::kPersistenceTrailingBytes, "trailing bytes");
  }

  // Duplicate plan identity.
  DecodeExpect(SpanOf(EncodeImage({record, record})), DiagnosticCode::kPersistenceDuplicatePlan,
               "duplicate plan identity");

  // Swapped candidate hop order.
  {
    StoredPlanRecord swapped = record;
    std::swap(swapped.candidates.front().hops[0], swapped.candidates.front().hops[1]);
    DecodeExpect(SpanOf(EncodeImage({swapped})), DiagnosticCode::kPersistenceCorrupt, "swapped hop order");
  }

  // Absurd candidate count. The count field is located by diffing a one-candidate image
  // against the two-candidate image, then the transport digest is repaired so the attack
  // reaches the count check instead of stopping at the digest.
  {
    StoredPlanRecord single = record;
    single.candidates.resize(1);
    single.costs.resize(1);
    single.ranks.resize(1);
    const std::vector<std::byte> single_image = EncodeImage({single});
    std::size_t count_offset = 0;
    bool located = false;
    for (std::size_t index = kStoreHeaderBytes + kStoreDigestBytes; index < single_image.size(); ++index) {
      if (single_image[index] != image[index]) {
        count_offset = index;
        located = true;
        break;
      }
    }
    Require(located, "the candidate count field could not be located");
    PP_CHECK_EQ(single_image[count_offset], std::byte{0x01});
    PP_CHECK_EQ(image[count_offset], std::byte{0x02});

    std::vector<std::byte> absurd = single_image;
    absurd[count_offset] = std::byte{0x7F};
    RepairStoreDigest(absurd);
    DecodeExpect(SpanOf(absurd), DiagnosticCode::kPersistenceLimitExceeded, "absurd candidate count");
  }

  // A repaired digest over an otherwise valid image still decodes: the case above is
  // caught by the count check, not by the digest.
  {
    std::vector<std::byte> repaired = image;
    RepairStoreDigest(repaired);
    std::vector<StoredPlanRecord> decoded;
    PP_CHECK(DecodePlanStore(SpanOf(repaired), ResourceLimits{}, decoded).ok);
  }
}

// ===========================================================================
// F. Resource limits.
// ===========================================================================

PP_TEST(adversarial, resource_limits_work_budget_hops_and_cost_overflow) {
  const Fabric fabric = MakeFabric();

  // A tiny deterministic work budget stops a larger plan with WORK_BUDGET_EXHAUSTED.
  PlannerConfig tight_config = ConfigFor(fabric.snapshot);
  tight_config.limits.max_expanded_states = 1;
  PlannerRuntime tight_runtime(tight_config);
  const PlanningRequest budgeted = MakeAToCRequest(fabric, 1, "adversarial.budget");
  const PlanningResult budget_result = tight_runtime.Plan(budgeted);
  PP_CHECK_EQ(budget_result.status, PlanStatus::kResourceLimit);
  PP_REQUIRE(budget_result.primary_failure.has_value());
  PP_CHECK_EQ(*budget_result.primary_failure, DiagnosticCode::kWorkBudgetExhausted);
  PP_CHECK(budget_result.candidates.empty());
  PP_CHECK(tight_runtime.Stats().states_expanded >= 1ull);

  // The only structural path A -> B -> C needs two hops; a one-hop ceiling rejects it.
  PlannerRuntime runtime(ConfigFor(fabric.snapshot));
  PlanningRequest narrow = MakeAToCRequest(fabric, 1, "adversarial.max.hops");
  narrow.constraints.max_hops = HopCount(1);
  TransitStage via_b;
  via_b.kind = TransitKind::kExact;
  via_b.alternatives = {fabric.b};
  narrow.constraints.required_transit = {via_b};
  const PlanningResult narrow_result = runtime.Plan(narrow);
  PP_CHECK_EQ(narrow_result.status, PlanStatus::kConstraintUnsatisfied);
  PP_REQUIRE(narrow_result.primary_failure.has_value());
  PP_CHECK_EQ(*narrow_result.primary_failure, DiagnosticCode::kMaxHopsExceeded);
  PP_CHECK(narrow_result.candidates.empty());

  // The same request without the ceiling plans through B.
  PlanningRequest roomy = MakeAToCRequest(fabric, 1, "adversarial.max.hops.roomy");
  roomy.constraints.required_transit = {via_b};
  PP_CHECK_EQ(runtime.Plan(roomy).status, PlanStatus::kPlanned);

  // Near-UINT32_MAX static costs on a four node chain: the total is exact, never wrapped.
  const ChainFabric chain = MakeChain(4, 0xFFFFFFFFu);
  PlannerRuntime chain_runtime(ConfigFor(chain.snapshot));
  const PlanningRequest plain = MakeChainRequest(chain, 1, "adversarial.cost.control");
  const PlanningResult planned = chain_runtime.Plan(plain);
  PP_CHECK_EQ(planned.status, PlanStatus::kPlanned);
  PP_REQUIRE(!planned.candidates.empty());
  const PathCost& cost = planned.candidates.front().cost;
  PP_CHECK_EQ(cost.hops.Value(), 3u);
  const CostValue expected_static = CostValue(0xFFFFFFFFull * 3ull);
  PP_CHECK_EQ(cost.static_cost, expected_static);
  PP_CHECK_EQ(cost.hops_cost, CostValue(3));
  const std::optional<CostValue> expected_total = CheckedAdd(cost.hops_cost, cost.static_cost);
  PP_REQUIRE(expected_total.has_value());
  PP_CHECK_EQ(cost.total, *expected_total);
  PP_CHECK_EQ(cost.total.Value(), 0xFFFFFFFFull * 3ull + 3ull);

  // A cost model whose per-hop increment cannot be represented is never wrapped: the plan
  // is refused with COST_OVERFLOW instead of returning a truncated total.
  PlanningRequest overflowing = MakeChainRequest(chain, 1, "adversarial.cost.overflow");
  overflowing.policy.cost_model.hop_cost = CostValue::Max();
  const PlanningResult overflow_result = chain_runtime.Plan(overflowing);
  PP_CHECK_EQ(overflow_result.status, PlanStatus::kResourceLimit);
  PP_REQUIRE(overflow_result.primary_failure.has_value());
  PP_CHECK_EQ(*overflow_result.primary_failure, DiagnosticCode::kCostOverflow);
  PP_CHECK(overflow_result.candidates.empty());
}

PP_TEST(adversarial, resource_limits_retention_evicts_deterministically) {
  const Fabric fabric = MakeFabric();
  PlannerConfig config = ConfigFor(fabric.snapshot);
  config.limits.max_retained_plans = 2;
  PlannerRuntime runtime(config);

  const PlanningRequest first = MakeAToBRequest(fabric, 1, "adversarial.retain.one");
  const PlanningRequest second = MakeAToBRequest(fabric, 2, "adversarial.retain.two");
  const PlanningRequest third = MakeAToCRequest(fabric, 2, "adversarial.retain.three");

  std::vector<PathPlanId> ids;
  for (const PlanningRequest& request : {first, second, third}) {
    PlanningResult result;
    const PathPlan plan = PlanOnce(runtime, request, result);
    PP_CHECK_EQ(result.status, PlanStatus::kPlanned);
    PP_REQUIRE(plan.id.IsValid());
    PP_CHECK(runtime.Retain(plan));
    ids.push_back(plan.id);
    PP_CHECK_MSG(runtime.RetainedPlanCount() <= 2, "retention exceeded max_retained_plans");
  }

  PP_CHECK_EQ(ids.size(), Count(3));
  PP_CHECK(ids[0] != ids[1]);
  PP_CHECK(ids[1] != ids[2]);
  PP_CHECK(ids[0] != ids[2]);
  PP_CHECK_EQ(runtime.RetainedPlanCount(), Count(2));
  // Deterministic FIFO eviction: the oldest plan is gone, the two newest survive.
  PP_CHECK(!runtime.FindPlan(ids[0]).has_value());
  PP_CHECK(runtime.FindPlan(ids[1]).has_value());
  PP_CHECK(runtime.FindPlan(ids[2]).has_value());
  PP_CHECK_EQ(runtime.Stats().plans_retired, 1ull);
}

}  // namespace adversarial

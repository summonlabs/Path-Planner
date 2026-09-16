// tests/core_tests.cpp -- suite "core".
//
// Deterministic, public-API-only coverage of:
//   * typed identities (FixedId / StrongUInt) and their canonical text forms;
//   * SHA-256 against the published vectors;
//   * the canonical codec (little endian integers, LEB128 varints, text, ceilings);
//   * the fabric snapshot builder (validity, duplicates, structural rejections, digest stability);
//   * planning request validation;
//   * the planner runtime (zero hop, endpoint resolution, evidence expectations, authority);
//   * deterministic candidate identity, cost components and ranking;
//   * retention, currentness, targeted invalidation, epoch hand-off and replanning;
//   * persistence (store.hpp) including every truncation and single-bit corruption;
//   * the framed wire protocol (proto.hpp) including every single-bit header/payload flip;
//   * deterministic rendering (explain.hpp).
//
// The suite never sleeps, never uses wall-clock time, never opens sockets and never
// depends on hash-map iteration order. tests/test_main.cpp owns main().

#include "test_framework.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "pathplanner/canonical.hpp"
#include "pathplanner/explain.hpp"
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

namespace core {

using namespace summon::pathplanner;

namespace {

// ---------------------------------------------------------------------------
// Small helpers. PP_REQUIRE cannot be used inside a value-returning helper (it
// expands to a bare "return;"), so helpers fail through pp_test::Fail directly.
// ---------------------------------------------------------------------------

void Require(bool condition, const char* message) {
  if (!condition) {
    ::pp_test::Fail(__FILE__, __LINE__, message);
  }
}

// Deterministic test identity: the leading bytes of SHA-256(label). Distinct
// labels give distinct identities; the value never depends on addresses, clocks
// or iteration order.
template <class Id>
Id TestId(std::string_view label) {
  return Id::FromDigest(Sha256::Hash(label));
}

// Canonical 32 character text for a short suffix, e.g. ZeroPadded("01") ->
// "00000000000000000000000000000001".
std::string ZeroPadded(std::string_view tail) {
  Require(tail.size() <= 32, "test identity suffix is too long");
  return std::string(32 - tail.size(), '0') + std::string(tail);
}

// Canonical 32 character text for a short prefix, e.g. FrontPadded("01") ->
// "01000000000000000000000000000000".
std::string FrontPadded(std::string_view head) {
  Require(head.size() <= 32, "test identity prefix is too long");
  return std::string(head) + std::string(32 - head.size(), '0');
}

template <class Id>
Id IdOf(std::string_view text) {
  const std::optional<Id> parsed = Id::Parse(text);
  if (!parsed.has_value()) {
    ::pp_test::Fail(__FILE__, __LINE__, "test identity literal is not a valid canonical identifier");
  }
  return *parsed;
}

std::vector<std::byte> BytesOf(std::string_view text) {
  std::vector<std::byte> bytes;
  bytes.reserve(text.size());
  for (const char character : text) {
    bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
  }
  return bytes;
}

std::string TextOf(std::span<const std::byte> bytes) {
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::span<const std::byte> SpanOf(const std::vector<std::byte>& bytes) {
  return std::span<const std::byte>(bytes.data(), bytes.size());
}

std::vector<std::byte> HexBytes(std::string_view hex) {
  std::vector<std::byte> bytes(hex.size() / 2);
  Require(HexDecodeStrict(hex, std::span<std::byte>(bytes.data(), bytes.size())), "invalid hex literal in test");
  return bytes;
}

// ---------------------------------------------------------------------------
// Explanation / change list helpers.
// ---------------------------------------------------------------------------

bool HasCode(const std::vector<ExplanationEntry>& changes, DiagnosticCode code) {
  return std::any_of(changes.begin(), changes.end(),
                     [code](const ExplanationEntry& entry) { return entry.code == code; });
}

bool HasDetail(const std::vector<ExplanationEntry>& changes, std::string_view detail) {
  return std::any_of(changes.begin(), changes.end(),
                     [detail](const ExplanationEntry& entry) { return entry.detail == detail; });
}

std::string DescribeChanges(const std::vector<ExplanationEntry>& changes) {
  std::string text;
  for (const ExplanationEntry& entry : changes) {
    text += std::string(ToString(entry.code));
    text += "=";
    text += entry.detail;
    text += "; ";
  }
  return text;
}

bool SamePath(const CandidatePath& lhs, const CandidatePath& rhs) {
  return lhs.source == rhs.source && lhs.destination == rhs.destination && lhs.layer == rhs.layer &&
         lhs.nodes == rhs.nodes && lhs.hops == rhs.hops;
}

// Equality over the fields a canonical path encoding actually carries (defined with
// the wire-codec helpers below).
bool SameEncodedPath(const CandidatePath& lhs, const CandidatePath& rhs);

CostValue SumCostComponents(const PathCost& cost) {
  std::optional<CostValue> total = CheckedAdd(cost.hops_cost, cost.static_cost);
  Require(total.has_value(), "cost components overflowed while summing");
  total = CheckedAdd(*total, cost.degraded_penalty);
  Require(total.has_value(), "cost components overflowed while summing");
  total = CheckedAdd(*total, cost.locality_penalty);
  Require(total.has_value(), "cost components overflowed while summing");
  return *total;
}

// ---------------------------------------------------------------------------
// Fabric fixture.
//
//   node A (ports a1, a2) --ab-->  node B (ports b1, b2, b3) --bc--> node C (port c1)
//                          --ab2->
//
// Physical DIRECT_LINK edges only; A -> C has exactly two simple routes:
//   route 1: ab  (static 1) then bc (static 4) => hops_cost 2, static 5, total 7
//   route 2: ab2 (static 2) then bc (static 4) => hops_cost 2, static 6, total 8
// A -> B has two simple one hop routes (ab total 2, ab2 total 3).
// ---------------------------------------------------------------------------

constexpr std::uint64_t kGenerationA = 3;
constexpr std::uint64_t kGenerationB = 1;
constexpr std::uint64_t kGenerationC = 5;

inline constexpr std::uint8_t kAbStaticCost = 1;
inline constexpr std::uint8_t kAb2StaticCost = 2;
inline constexpr std::uint8_t kBcStaticCost = 4;

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

SnapshotGenerations DefaultGenerations();

struct FabricOptions {
  SnapshotGenerations generations = DefaultGenerations();
  bool include_ab = true;
  bool include_ab2 = true;
  bool include_bc = true;
  bool publish_link_states = true;
  bool publish_port_states = true;
  LinkState ab_state = LinkState::kUp;
  LinkState ab2_state = LinkState::kUp;
  LinkState bc_state = LinkState::kUp;
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

Fabric MakeFabricIdentities() {
  Fabric fabric;
  fabric.a = TestId<NodeId>("core.node.a");
  fabric.b = TestId<NodeId>("core.node.b");
  fabric.c = TestId<NodeId>("core.node.c");
  fabric.a1 = TestId<PortId>("core.port.a1");
  fabric.a2 = TestId<PortId>("core.port.a2");
  fabric.b1 = TestId<PortId>("core.port.b1");
  fabric.b2 = TestId<PortId>("core.port.b2");
  fabric.b3 = TestId<PortId>("core.port.b3");
  fabric.c1 = TestId<PortId>("core.port.c1");
  fabric.ab = TestId<LinkId>("core.link.ab");
  fabric.ab2 = TestId<LinkId>("core.link.ab2");
  fabric.bc = TestId<LinkId>("core.link.bc");
  fabric.ea = TestId<EndpointId>("core.endpoint.a");
  fabric.eb = TestId<EndpointId>("core.endpoint.b");
  fabric.ec = TestId<EndpointId>("core.endpoint.c");
  return fabric;
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

NodeRecord MakeNode(const NodeId& id, std::vector<PortId> ports) {
  NodeRecord node;
  node.id = id;
  node.entity_generation = EntityGeneration(1);
  node.structural_generation = TopologyGeneration(1);
  node.ports = std::move(ports);
  return node;
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

// Adds every node, edge and endpoint of the fixture shape (respecting the options
// that remove links) to a caller supplied builder.
void AddFabricRecords(FabricSnapshotBuilder& builder, const Fabric& fabric, const FabricOptions& options) {
  PP_CHECK(builder.AddNode(MakeNode(fabric.a, {fabric.a1, fabric.a2})));
  PP_CHECK(builder.AddNode(MakeNode(fabric.b, {fabric.b1, fabric.b2, fabric.b3})));
  PP_CHECK(builder.AddNode(MakeNode(fabric.c, {fabric.c1})));
  if (options.include_ab) {
    PP_CHECK(builder.AddEdge(
        MakeEdge(fabric.ab, fabric.a, fabric.b, fabric.a1, fabric.b1, kAbStaticCost)));
  }
  if (options.include_ab2) {
    PP_CHECK(builder.AddEdge(
        MakeEdge(fabric.ab2, fabric.a, fabric.b, fabric.a2, fabric.b2, kAb2StaticCost)));
  }
  if (options.include_bc) {
    PP_CHECK(builder.AddEdge(
        MakeEdge(fabric.bc, fabric.b, fabric.c, fabric.b3, fabric.c1, kBcStaticCost)));
  }
  PP_CHECK(builder.AddEndpoint(MakeEndpoint(fabric.ea, fabric.a, fabric.a1, kGenerationA)));
  PP_CHECK(builder.AddEndpoint(MakeEndpoint(fabric.eb, fabric.b, fabric.b1, kGenerationB)));
  PP_CHECK(builder.AddEndpoint(MakeEndpoint(fabric.ec, fabric.c, fabric.c1, kGenerationC)));
}

Fabric MakeFabric(const FabricOptions& options) {
  Fabric fabric = MakeFabricIdentities();
  FabricSnapshotBuilder builder;
  builder.SetGenerations(options.generations);
  builder.SetSource(EvidenceSource::kSynthetic);
  AddFabricRecords(builder, fabric, options);
  if (options.publish_link_states) {
    std::vector<LinkStateRecord> states;
    if (options.include_ab) {
      states.push_back(LinkStateRecord{fabric.ab, options.ab_state});
    }
    if (options.include_ab2) {
      states.push_back(LinkStateRecord{fabric.ab2, options.ab2_state});
    }
    if (options.include_bc) {
      states.push_back(LinkStateRecord{fabric.bc, options.bc_state});
    }
    builder.SetLinkStates(std::move(states));
  }
  if (options.publish_port_states) {
    std::vector<PortStateRecord> states;
    for (const PortId& port : {fabric.a1, fabric.a2, fabric.b1, fabric.b2, fabric.b3, fabric.c1}) {
      states.push_back(PortStateRecord{port, PortState::kUp});
    }
    builder.SetPortStates(std::move(states));
  }
  const SnapshotBuildResult build = builder.Build();
  PP_CHECK_MSG(build.ok(), build.detail);
  fabric.snapshot = build.snapshot;
  return fabric;
}

PlanningRequest MakeRequest(const EndpointId& source, EntityGeneration source_generation,
                            const EndpointId& destination, EntityGeneration destination_generation,
                            std::uint32_t max_candidates) {
  PlanningRequest request;
  request.id = TestId<PlanningRequestId>("core.request");
  request.source.id = source;
  request.source.endpoint_class = EndpointClass::kEndpoint;
  request.source.generation = source_generation;
  request.destination.id = destination;
  request.destination.endpoint_class = EndpointClass::kEndpoint;
  request.destination.generation = destination_generation;
  request.constraints.id = TestId<ConstraintSetId>("core.constraints");
  request.constraints.generation = ConstraintGeneration(1);
  request.constraints.layer = PathLayer::kPhysical;
  request.policy.generation = PolicyGeneration(1);
  request.max_candidates = max_candidates;
  request.mode = PlanningMode::kStandard;
  return request;
}

PlanningRequest MakeAToCRequest(const Fabric& fabric, std::uint32_t max_candidates) {
  return MakeRequest(fabric.ea, EntityGeneration(kGenerationA), fabric.ec, EntityGeneration(kGenerationC),
                     max_candidates);
}

PlanningRequest MakeAToBRequest(const Fabric& fabric, std::uint32_t max_candidates) {
  return MakeRequest(fabric.ea, EntityGeneration(kGenerationA), fabric.eb, EntityGeneration(kGenerationB),
                     max_candidates);
}

PlannerConfig ConfigFor(const Fabric& fabric) {
  PlannerConfig config;
  config.initial_snapshot = fabric.snapshot;
  return config;
}

PathPlan PlanOnce(PlannerRuntime& runtime, const PlanningRequest& request, PlanningResult& result) {
  result = runtime.Plan(request);
  return MakePathPlan(request, result, runtime.PublishSequence());
}

// Builds a store record whose semantic digest matches its own content.
StoredPlanRecord MakeStoreRecord(const Fabric& fabric, PlanningResult& result, PathPlan& plan) {
  PlannerRuntime runtime(ConfigFor(fabric));
  const PlanningRequest request = MakeAToCRequest(fabric, 2);
  plan = PlanOnce(runtime, request, result);
  Require(result.status == PlanStatus::kPlanned, "fixture plan did not succeed");
  return ToStoredRecord(plan);
}

std::vector<std::byte> EncodeStoreImage(const std::vector<StoredPlanRecord>& records,
                                        const StoreOptions& options) {
  std::vector<std::byte> image;
  const StoreResult encoded = EncodePlanStore(records, options, image);
  PP_CHECK_MSG(encoded.ok, encoded.detail);
  return image;
}

// A distinct, non-existent store path derived from a hash of the test case name.
std::filesystem::path ScratchStorePath(std::string_view label) {
  const std::string digest = Sha256::Hash(label).ToHex().substr(0, 16);
  return std::filesystem::temp_directory_path() / ("pp_core_" + digest + ".ppstore");
}

}  // namespace

// ===========================================================================
// 1. Typed identities.
// ===========================================================================

PP_TEST(core, identity_fixed_id_parse_roundtrip_and_order) {
  const std::string sevens(32, '7');
  const std::optional<NodeId> parsed = NodeId::Parse(sevens);
  PP_REQUIRE(parsed.has_value());
  PP_CHECK(parsed->IsValid());
  PP_CHECK_EQ(parsed->ToString(), sevens);
  PP_CHECK_EQ(parsed->Bytes().size(), static_cast<std::size_t>(16));
  PP_CHECK_EQ(parsed->Span().size(), static_cast<std::size_t>(16));
  for (const std::byte value : parsed->Bytes()) {
    PP_CHECK_EQ(value, std::byte{0x77});
  }

  // Exact byte layout of a mixed canonical text form.
  const std::optional<NodeId> mixed = NodeId::Parse("0123456789abcdef0123456789abcdef");
  PP_REQUIRE(mixed.has_value());
  PP_CHECK_EQ(mixed->Bytes()[0], std::byte{0x01});
  PP_CHECK_EQ(mixed->Bytes()[1], std::byte{0x23});
  PP_CHECK_EQ(mixed->Bytes()[2], std::byte{0x45});
  PP_CHECK_EQ(mixed->Bytes()[7], std::byte{0xef});
  PP_CHECK_EQ(mixed->Bytes()[15], std::byte{0xef});
  PP_CHECK_EQ(mixed->ToString(), std::string("0123456789abcdef0123456789abcdef"));

  // A distinct Tag/width is a distinct type: the same text is not a valid 8 byte id.
  PP_CHECK(!FailureDomainId::Parse(sevens).has_value());
  const std::string sixteens(16, 'c');
  const std::optional<CapabilityId> capability = CapabilityId::Parse(sixteens);
  PP_REQUIRE(capability.has_value());
  PP_CHECK_EQ(capability->ToString(), sixteens);
  PP_CHECK_EQ(capability->Bytes().size(), static_cast<std::size_t>(8));

  // Rejections: empty, wrong length, uppercase, non-hex, whitespace, nil.
  PP_CHECK(!NodeId::Parse(std::string_view()).has_value());
  PP_CHECK(!NodeId::Parse(std::string(31, '7')).has_value());
  PP_CHECK(!NodeId::Parse(std::string(33, '7')).has_value());
  PP_CHECK(!NodeId::Parse(std::string(32, 'A')).has_value());
  PP_CHECK(!NodeId::Parse(std::string(32, 'g')).has_value());
  PP_CHECK(!NodeId::Parse(std::string(32, '0')).has_value());
  PP_CHECK(!NodeId::Parse(" " + std::string(31, '7')).has_value());
  PP_CHECK(!NodeId::Parse(std::string(31, '7') + " ").has_value());
  PP_CHECK(!NodeId::Parse("0x23456789abcdef0123456789abcdef").has_value());
  PP_CHECK(!NodeId::Parse("0123456789abcde-0123456789abcdef").has_value());

  // Derivation from a digest uses the leading N bytes.
  const Sha256Digest digest = Sha256::Hash(std::string_view("core.identity.digest"));
  const NodeId from_digest = NodeId::FromDigest(digest);
  for (std::size_t index = 0; index < 16; ++index) {
    PP_CHECK_EQ(from_digest.Bytes()[index], digest.bytes[index]);
  }
  // The derived identifier is bound to a named value first: Bytes() returns a reference into
  // the object, so dereferencing it on a temporary would outlive that temporary.
  const FailureDomainId derived_domain = FailureDomainId::FromDigest(digest);
  PP_CHECK_EQ(derived_domain.Bytes()[7], digest.bytes[7]);
  PP_CHECK_EQ(NodeId::FromBytes(from_digest.Bytes()), from_digest);

  // Bytewise ordering: the first differing byte decides, not the integer it spells.
  const NodeId leading = IdOf<NodeId>(FrontPadded("01"));
  const NodeId trailing = IdOf<NodeId>(ZeroPadded("02"));
  PP_CHECK(leading > trailing);
  PP_CHECK(trailing < leading);
  PP_CHECK_EQ(leading, IdOf<NodeId>(FrontPadded("01")));
  PP_CHECK(leading != trailing);

  const NodeId low = IdOf<NodeId>(ZeroPadded("01"));
  const NodeId middle = IdOf<NodeId>(ZeroPadded("0100"));
  const NodeId high = IdOf<NodeId>(ZeroPadded("010000"));
  PP_CHECK(low < middle);
  PP_CHECK(middle < high);
  PP_CHECK(low < high);
  PP_CHECK(!(high < low));
  PP_CHECK_EQ((low < middle), (low.ToString() < middle.ToString()));
  PP_CHECK_EQ((middle < high), (middle.ToString() < high.ToString()));
  PP_CHECK_EQ((leading > trailing), (leading.ToString() > trailing.ToString()));

  // Total order over a shuffled set: strictly increasing and duplicate free.
  std::vector<NodeId> ids = {high, low, trailing, middle, leading, IdOf<NodeId>(ZeroPadded("ff"))};
  std::sort(ids.begin(), ids.end());
  for (std::size_t index = 1; index < ids.size(); ++index) {
    PP_CHECK(ids[index - 1] < ids[index]);
    PP_CHECK(ids[index - 1] != ids[index]);
  }
  PP_CHECK_EQ(ids.front(), low);
  PP_CHECK_EQ(ids.back(), leading);
}

PP_TEST(core, identity_strong_uint_parse_and_checked_arithmetic) {
  PP_CHECK_EQ(HopCount::Bound(), 65535u);
  PP_CHECK_EQ(kMaxHopCount, 65535u);
  PP_CHECK_EQ(CandidateRank::Bound(), 4095u);
  PP_CHECK_EQ(CostValue::Bound(), std::numeric_limits<std::uint64_t>::max());

  const std::optional<HopCount> zero = HopCount::Parse("0");
  PP_REQUIRE(zero.has_value());
  PP_CHECK_EQ(zero->Value(), 0u);
  PP_CHECK_EQ(zero->ToString(), std::string("0"));
  const std::optional<HopCount> maximum = HopCount::Parse("65535");
  PP_REQUIRE(maximum.has_value());
  PP_CHECK_EQ(maximum->Value(), 65535u);
  PP_CHECK_EQ(maximum->ToString(), std::string("65535"));
  const std::optional<HopCount> fifteen = HopCount::Parse("15");
  PP_REQUIRE(fifteen.has_value());
  PP_CHECK_EQ(fifteen->Value(), 15u);
  PP_CHECK_EQ(HopCount::Parse(maximum->ToString()).value(), *maximum);

  PP_CHECK(!HopCount::Parse(std::string_view()).has_value());
  PP_CHECK(!HopCount::Parse("00").has_value());
  PP_CHECK(!HopCount::Parse("01").has_value());
  PP_CHECK(!HopCount::Parse("+1").has_value());
  PP_CHECK(!HopCount::Parse("-1").has_value());
  PP_CHECK(!HopCount::Parse(" 1").has_value());
  PP_CHECK(!HopCount::Parse("1 ").has_value());
  PP_CHECK(!HopCount::Parse("1\t").has_value());
  PP_CHECK(!HopCount::Parse("0x1").has_value());
  PP_CHECK(!HopCount::Parse("1a").has_value());
  PP_CHECK(!HopCount::Parse("65536").has_value());
  PP_CHECK(!HopCount::Parse(std::string(20, '9')).has_value());
  PP_CHECK(!HopCount::Parse(std::string(21, '1')).has_value());

  const std::optional<CostValue> huge = CostValue::Parse("18446744073709551615");
  PP_REQUIRE(huge.has_value());
  PP_CHECK_EQ(huge->Value(), std::numeric_limits<std::uint64_t>::max());
  PP_CHECK(!CostValue::Parse("18446744073709551616").has_value());

  PP_CHECK(HopCount::TryFrom(65535u).has_value());
  PP_CHECK(!HopCount::TryFrom(65536u).has_value());
  PP_CHECK(CandidateRank::TryFrom(4095u).has_value());
  PP_CHECK(!CandidateRank::TryFrom(4096u).has_value());
  const std::optional<CandidateRank> rank_zero = CandidateRank::TryFrom(0u);
  PP_REQUIRE(rank_zero.has_value());
  PP_CHECK_EQ(rank_zero->Value(), 0u);
  PP_CHECK(HopCount(1) < HopCount(2));
  PP_CHECK(HopCount(2) > HopCount(1));
  PP_CHECK_EQ(HopCount::Max().Value(), 65535u);

  const std::optional<HopCount> sum_ok = CheckedAdd(HopCount(65534), HopCount(1));
  PP_REQUIRE(sum_ok.has_value());
  PP_CHECK_EQ(sum_ok->Value(), 65535u);
  PP_CHECK(!CheckedAdd(HopCount(65535), HopCount(1)).has_value());
  PP_CHECK(!CheckedAdd(HopCount(60000), HopCount(6000)).has_value());
  const std::optional<CostValue> sum_max = CheckedAdd(CostValue::Max(), CostValue(0));
  PP_REQUIRE(sum_max.has_value());
  PP_CHECK_EQ(sum_max->Value(), std::numeric_limits<std::uint64_t>::max());
  PP_CHECK(!CheckedAdd(CostValue::Max(), CostValue(1)).has_value());

  const std::optional<HopCount> mul_ok = CheckedMul(HopCount(100), 655u);
  PP_REQUIRE(mul_ok.has_value());
  PP_CHECK_EQ(mul_ok->Value(), 65500u);
  PP_CHECK(!CheckedMul(HopCount(100), 656u).has_value());
  PP_CHECK(!CheckedMul(HopCount(65535), 65535u).has_value());
  const std::optional<HopCount> mul_zero = CheckedMul(HopCount(65535), 0u);
  PP_REQUIRE(mul_zero.has_value());
  PP_CHECK_EQ(mul_zero->Value(), 0u);
  const std::optional<CostValue> mul_one = CheckedMul(CostValue::Max(), static_cast<std::uint64_t>(1));
  PP_REQUIRE(mul_one.has_value());
  PP_CHECK_EQ(mul_one->Value(), std::numeric_limits<std::uint64_t>::max());
  PP_CHECK(!CheckedMul(CostValue::Max(), static_cast<std::uint64_t>(2)).has_value());
}

// ===========================================================================
// 2. SHA-256.
// ===========================================================================

PP_TEST(core, sha256_published_vectors) {
  // FIPS 180-4 published vectors.
  PP_CHECK_EQ(Sha256::Hash(std::string_view()).ToHex(),
              std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  PP_CHECK_EQ(Sha256::Hash(std::string_view("abc")).ToHex(),
              std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  const std::string two_block = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  PP_CHECK_EQ(two_block.size(), static_cast<std::size_t>(56));
  PP_CHECK_EQ(Sha256::Hash(two_block).ToHex(),
              std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));

  // Incremental hashing is identical to the one-shot form.
  Sha256 incremental;
  incremental.Update(std::string_view("ab"));
  incremental.Update(std::string_view("c"));
  PP_CHECK_EQ(incremental.Finish().ToHex(), Sha256::Hash(std::string_view("abc")).ToHex());

  // The 448 bit vector fed as bytes rather than text.
  const std::vector<std::byte> two_block_bytes = BytesOf(two_block);
  PP_CHECK_EQ(Sha256::Hash(SpanOf(two_block_bytes)).ToHex(), Sha256::Hash(two_block).ToHex());

  // 1,000,000 x 'a' derived here in 1000 chunks of 1000 bytes, then verified
  // against the published value cdc76e5c...
  Sha256 million;
  const std::vector<std::byte> chunk(1000, std::byte{0x61});
  for (int index = 0; index < 1000; ++index) {
    million.Update(SpanOf(chunk));
  }
  const Sha256Digest million_digest = million.Finish();
  PP_CHECK_MSG(million_digest.ToHex() == std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
               million_digest.ToHex());

  // Digest plumbing.
  PP_CHECK_EQ(Sha256Digest{}.IsZero(), true);
  PP_CHECK_EQ(million_digest.IsZero(), false);
  const std::optional<Sha256Digest> parsed = Sha256Digest::FromHex(million_digest.ToHex());
  PP_REQUIRE(parsed.has_value());
  PP_CHECK_EQ(*parsed, million_digest);
  PP_CHECK_EQ(parsed->ToHex().size(), static_cast<std::size_t>(64));
  PP_CHECK(!Sha256Digest::FromHex("zz").has_value());
  PP_CHECK(!Sha256Digest::FromHex(million_digest.ToHex().substr(1)).has_value());
  PP_CHECK(Sha256Digest{} < million_digest);
  PP_CHECK(million_digest != Sha256Digest{});
}

// ===========================================================================
// 3. Canonical codec.
// ===========================================================================

PP_TEST(core, canonical_integer_and_varint_roundtrip) {
  ByteWriter writer(64);
  writer.U8(0x12);
  writer.U16(0x1234);
  writer.U32(0x12345678u);
  writer.U64(0x0102030405060708ull);
  writer.Bool(true);
  writer.Bool(false);
  PP_CHECK(!writer.overflowed());
  PP_CHECK_EQ(writer.size(), static_cast<std::size_t>(17));
  const std::vector<std::byte>& data = writer.data();
  PP_CHECK_EQ(data[0], std::byte{0x12});
  PP_CHECK_EQ(data[1], std::byte{0x34});
  PP_CHECK_EQ(data[2], std::byte{0x12});
  PP_CHECK_EQ(data[3], std::byte{0x78});
  PP_CHECK_EQ(data[4], std::byte{0x56});
  PP_CHECK_EQ(data[5], std::byte{0x34});
  PP_CHECK_EQ(data[6], std::byte{0x12});
  PP_CHECK_EQ(data[7], std::byte{0x08});
  PP_CHECK_EQ(data[8], std::byte{0x07});
  PP_CHECK_EQ(data[9], std::byte{0x06});
  PP_CHECK_EQ(data[10], std::byte{0x05});
  PP_CHECK_EQ(data[11], std::byte{0x04});
  PP_CHECK_EQ(data[12], std::byte{0x03});
  PP_CHECK_EQ(data[13], std::byte{0x02});
  PP_CHECK_EQ(data[14], std::byte{0x01});
  PP_CHECK_EQ(data[15], std::byte{0x01});
  PP_CHECK_EQ(data[16], std::byte{0x00});

  ByteReader reader(writer.span());
  PP_CHECK_EQ(reader.U8().value(), 0x12u);
  PP_CHECK_EQ(reader.U16().value(), 0x1234u);
  PP_CHECK_EQ(reader.U32().value(), 0x12345678u);
  PP_CHECK_EQ(reader.U64().value(), 0x0102030405060708ull);
  PP_CHECK_EQ(reader.Bool().value(), true);
  PP_CHECK_EQ(reader.Bool().value(), false);
  PP_CHECK(reader.AtEnd());
  PP_CHECK(!reader.failed());
  PP_CHECK_EQ(reader.Position(), static_cast<std::size_t>(17));

  // Canonical LEB128: shortest form only.
  struct VarIntCase {
    std::uint64_t value;
    const char* hex;
  };
  const VarIntCase kVarIntCases[] = {
      {0ull, "00"},
      {1ull, "01"},
      {127ull, "7f"},
      {128ull, "8001"},
      {300ull, "ac02"},
      {16383ull, "ff7f"},
      {16384ull, "808001"},
      {std::numeric_limits<std::uint64_t>::max(), "ffffffffffffffffff01"},
  };
  for (const VarIntCase& test_case : kVarIntCases) {
    ByteWriter varint_writer(16);
    varint_writer.VarU64(test_case.value);
    PP_CHECK(!varint_writer.overflowed());
    PP_CHECK_MSG(varint_writer.data() == HexBytes(test_case.hex), TextOf(varint_writer.span()));
    ByteReader varint_reader(varint_writer.span());
    const std::optional<std::uint64_t> decoded = varint_reader.VarU64();
    PP_REQUIRE(decoded.has_value());
    PP_CHECK_EQ(*decoded, test_case.value);
    PP_CHECK(varint_reader.AtEnd());
    PP_CHECK(!varint_reader.failed());
  }

  // Over-long (non-canonical) and unterminated varints are rejected and latch the reader.
  const char* kBadVarInts[] = {"8000", "818000", "ffffffffffffffffff7f", "80808080808080808080"};
  for (const char* hex : kBadVarInts) {
    const std::vector<std::byte> bytes = HexBytes(hex);
    ByteReader bad_reader(SpanOf(bytes));
    PP_CHECK_MSG(!bad_reader.VarU64().has_value(), hex);
    PP_CHECK(bad_reader.failed());
  }

  // Text: varint length prefix then raw bytes.
  ByteWriter text_writer(16);
  text_writer.Text("abc");
  text_writer.Text(std::string_view());
  PP_CHECK(!text_writer.overflowed());
  PP_CHECK(text_writer.data() == HexBytes("0361626300"));
  ByteReader text_reader(text_writer.span());
  const std::optional<std::string_view> first_text = text_reader.Text();
  PP_REQUIRE(first_text.has_value());
  PP_CHECK_EQ(*first_text, std::string_view("abc"));
  const std::optional<std::string_view> second_text = text_reader.Text();
  PP_REQUIRE(second_text.has_value());
  PP_CHECK_EQ(second_text->size(), static_cast<std::size_t>(0));
  PP_CHECK(text_reader.AtEnd());

  // A length prefix that cannot be satisfied is a hard failure.
  const std::vector<std::byte> over_declared = HexBytes("05616263");
  ByteReader over_reader(SpanOf(over_declared));
  PP_CHECK(!over_reader.Text().has_value());
  PP_CHECK(over_reader.failed());
  const std::vector<std::byte> short_view = HexBytes("0261");
  ByteReader short_text_reader(SpanOf(short_view));
  PP_CHECK(!short_text_reader.Text().has_value());
  PP_CHECK(short_text_reader.failed());

  // Bool accepts exactly 0 and 1.
  const std::vector<std::byte> false_byte = HexBytes("00");
  const std::vector<std::byte> true_byte = HexBytes("01");
  const std::vector<std::byte> two_byte = HexBytes("02");
  ByteReader false_reader(SpanOf(false_byte));
  PP_CHECK_EQ(false_reader.Bool().value(), false);
  ByteReader true_reader(SpanOf(true_byte));
  PP_CHECK_EQ(true_reader.Bool().value(), true);
  ByteReader two_reader(SpanOf(two_byte));
  PP_CHECK(!two_reader.Bool().has_value());
  PP_CHECK(two_reader.failed());

  // Unconsumed bytes are visible through AtEnd()/Remaining().
  const std::vector<std::byte> pair = HexBytes("0102");
  ByteReader pair_reader(SpanOf(pair));
  PP_CHECK_EQ(pair_reader.U8().value(), 0x01u);
  PP_CHECK(!pair_reader.AtEnd());
  PP_CHECK_EQ(pair_reader.Remaining(), static_cast<std::size_t>(1));
  PP_CHECK_EQ(pair_reader.U8().value(), 0x02u);
  PP_CHECK(pair_reader.AtEnd());
}

PP_TEST(core, canonical_writer_ceiling_and_reader_rejections) {
  // A write that would exceed the ceiling is reported and never partially applied.
  ByteWriter exhausted(4);
  exhausted.U32(0xAABBCCDDu);
  PP_CHECK(!exhausted.overflowed());
  PP_CHECK_EQ(exhausted.size(), static_cast<std::size_t>(4));
  exhausted.U8(0x01);
  PP_CHECK(exhausted.overflowed());
  PP_CHECK_EQ(exhausted.size(), static_cast<std::size_t>(4));
  exhausted.U64(0);
  PP_CHECK_EQ(exhausted.size(), static_cast<std::size_t>(4));
  PP_CHECK(exhausted.data() == HexBytes("ddccbbaa"));

  ByteWriter atomic(4);
  atomic.U16(0x0001);
  atomic.U16(0x0002);
  PP_CHECK(!atomic.overflowed());
  const std::vector<std::byte> three = BytesOf("abc");
  atomic.FixedBytes(SpanOf(three));
  PP_CHECK(atomic.overflowed());
  PP_CHECK_EQ(atomic.size(), static_cast<std::size_t>(4));
  PP_CHECK(atomic.data() == HexBytes("01000200"));

  ByteWriter exact(4);
  exact.U32(7u);
  PP_CHECK(!exact.overflowed());
  PP_CHECK(exact.data() == HexBytes("07000000"));

  // Short reads fail and latch; the position does not advance.
  const std::vector<std::byte> one = HexBytes("01");
  ByteReader truncated_reader(SpanOf(one));
  PP_CHECK(!truncated_reader.U16().has_value());
  PP_CHECK(truncated_reader.failed());
  PP_CHECK_EQ(truncated_reader.Position(), static_cast<std::size_t>(0));
  PP_CHECK_EQ(truncated_reader.Remaining(), static_cast<std::size_t>(1));
  PP_CHECK(!truncated_reader.AtEnd());
  PP_CHECK(!truncated_reader.U8().has_value());
  PP_CHECK(!truncated_reader.U64().has_value());
  PP_CHECK(!truncated_reader.View(1).has_value());

  const std::span<const std::byte> nothing;
  ByteReader empty_reader(nothing);
  PP_CHECK(empty_reader.AtEnd());
  PP_CHECK_EQ(empty_reader.Remaining(), static_cast<std::size_t>(0));
  PP_CHECK_EQ(empty_reader.Position(), static_cast<std::size_t>(0));
  PP_CHECK(!empty_reader.U8().has_value());
  PP_CHECK(empty_reader.failed());
  PP_CHECK(!empty_reader.Text().has_value());

  const std::vector<std::byte> four = HexBytes("61626364");
  ByteReader view_reader(SpanOf(four));
  PP_CHECK(!view_reader.View(5).has_value());
  PP_CHECK(view_reader.failed());

  std::array<std::byte, 2> out{};
  ByteReader fixed_reader(SpanOf(four));
  PP_CHECK(fixed_reader.FixedBytes(std::span<std::byte>(out.data(), out.size())));
  PP_CHECK_EQ(out[0], std::byte{0x61});
  PP_CHECK_EQ(out[1], std::byte{0x62});
  PP_CHECK(fixed_reader.FixedBytes(std::span<std::byte>(out.data(), out.size())));
  PP_CHECK_EQ(out[0], std::byte{0x63});
  PP_CHECK_EQ(out[1], std::byte{0x64});
  PP_CHECK(!fixed_reader.FixedBytes(std::span<std::byte>(out.data(), out.size())));
  PP_CHECK(fixed_reader.failed());

  // Hex helpers: canonical form is exactly two lowercase digits per byte.
  const std::vector<std::byte> pattern = HexBytes("00ff10");
  PP_CHECK_EQ(HexEncode(SpanOf(pattern)), std::string("00ff10"));
  PP_CHECK_EQ(HexEncode(std::span<const std::byte>()), std::string());
  std::array<std::byte, 3> decoded{};
  const std::span<std::byte> decoded_span(decoded.data(), decoded.size());
  PP_CHECK(HexDecodeStrict("00ff10", decoded_span));
  PP_CHECK_EQ(decoded[0], std::byte{0x00});
  PP_CHECK_EQ(decoded[1], std::byte{0xff});
  PP_CHECK_EQ(decoded[2], std::byte{0x10});
  PP_CHECK(!HexDecodeStrict("00FF10", decoded_span));
  PP_CHECK(!HexDecodeStrict("00ff1", decoded_span));
  PP_CHECK(!HexDecodeStrict("00ff1000", decoded_span));
  PP_CHECK(!HexDecodeStrict("00 ff10", decoded_span));
  PP_CHECK(!HexDecodeStrict("00ff1g", decoded_span));
  PP_CHECK(!HexDecodeStrict("", decoded_span));
}
// ===========================================================================
// 4. Fabric snapshot builder.
// ===========================================================================

PP_TEST(core, snapshot_builder_valid_fabric_and_stable_identity) {
  const Fabric first = MakeFabric(FabricOptions{});
  const Fabric second = MakeFabric(FabricOptions{});
  PP_CHECK(first.snapshot != nullptr);
  PP_CHECK_EQ(first.snapshot->NodeCount(), static_cast<std::size_t>(3));
  PP_CHECK_EQ(first.snapshot->EdgeCount(), static_cast<std::size_t>(3));
  PP_CHECK_EQ(first.snapshot->Endpoints().size(), static_cast<std::size_t>(3));
  PP_CHECK_EQ(first.snapshot->LinkStates().Size(), static_cast<std::size_t>(3));
  PP_CHECK_EQ(first.snapshot->PortStates().Size(), static_cast<std::size_t>(6));
  PP_CHECK_EQ(first.snapshot->Capabilities().Size(), static_cast<std::size_t>(0));
  PP_CHECK_EQ(first.snapshot->FailureDomains().Size(), static_cast<std::size_t>(0));
  PP_CHECK_EQ(first.snapshot->FailureDomains().MembershipComplete(), false);
  PP_CHECK_EQ(first.snapshot->Source(), EvidenceSource::kSynthetic);
  PP_CHECK_EQ(first.snapshot->Generations(), DefaultGenerations());
  PP_CHECK(static_cast<bool>(first.snapshot->Digest() == second.snapshot->Digest()));
  PP_CHECK_EQ(first.snapshot->Id(), second.snapshot->Id());
  PP_CHECK(!first.snapshot->Digest().IsZero());

  PP_REQUIRE(first.snapshot->FindNode(first.a) != nullptr);
  PP_CHECK_EQ(first.snapshot->FindNode(first.a)->ports.size(), static_cast<std::size_t>(2));
  PP_CHECK(first.snapshot->FindNode(first.b) != nullptr);
  PP_CHECK(first.snapshot->FindNode(first.c) != nullptr);
  PP_CHECK(first.snapshot->FindNode(TestId<NodeId>("core.node.absent")) == nullptr);
  PP_REQUIRE(first.snapshot->FindEdge(first.ab) != nullptr);
  PP_CHECK_EQ(first.snapshot->FindEdge(first.ab)->static_cost.Value(), 1u);
  PP_CHECK_EQ(first.snapshot->FindEdge(first.ab2)->static_cost.Value(), 2u);
  PP_CHECK_EQ(first.snapshot->FindEdge(first.bc)->static_cost.Value(), 4u);
  PP_CHECK(first.snapshot->FindEdge(TestId<LinkId>("core.link.absent")) == nullptr);
  PP_REQUIRE(first.snapshot->FindEndpoint(first.ea) != nullptr);
  PP_CHECK_EQ(first.snapshot->FindEndpoint(first.ea)->entity_generation.Value(), kGenerationA);
  PP_CHECK_EQ(first.snapshot->FindEndpoint(first.ea)->node, first.a);
  PP_CHECK_EQ(first.snapshot->FindEndpoint(first.ea)->port, first.a1);
  PP_CHECK_EQ(first.snapshot->FindEndpoint(first.eb)->entity_generation.Value(), kGenerationB);
  PP_CHECK_EQ(first.snapshot->FindEndpoint(first.ec)->entity_generation.Value(), kGenerationC);
  PP_CHECK(first.snapshot->FindEndpoint(TestId<EndpointId>("core.endpoint.absent")) == nullptr);

  PP_CHECK_EQ(first.snapshot->LinkStates().StateOf(first.ab), LinkState::kUp);
  PP_CHECK_EQ(first.snapshot->LinkStates().StateOf(first.ab2), LinkState::kUp);
  PP_CHECK_EQ(first.snapshot->LinkStates().StateOf(first.bc), LinkState::kUp);
  PP_CHECK_EQ(first.snapshot->LinkStates().StateOf(TestId<LinkId>("core.link.absent")), LinkState::kUnknown);
  PP_CHECK_EQ(first.snapshot->PortStates().StateOf(first.b3), PortState::kUp);
  PP_CHECK_EQ(first.snapshot->PortStates().StateOf(TestId<PortId>("core.port.absent")), PortState::kUnknown);
  PP_CHECK(first.snapshot->LinkStates().Find(first.bc) != nullptr);
  PP_CHECK(first.snapshot->PortStates().Find(first.c1) != nullptr);
  PP_CHECK(first.snapshot->LinkStates().Find(TestId<LinkId>("core.link.absent")) == nullptr);

  const EvidenceVector evidence = first.snapshot->Evidence();
  PP_CHECK_EQ(evidence.snapshot, first.snapshot->Id());
  PP_CHECK_EQ(evidence.generations, first.snapshot->Generations());
  PP_CHECK_EQ(evidence.source, EvidenceSource::kSynthetic);
  PP_CHECK_EQ(evidence.publish_sequence.Value(), 0ull);
  PP_CHECK_EQ(EvidenceVector{}.snapshot, SnapshotId{});
  PP_CHECK(evidence != EvidenceVector{});

  // Content changes change the identity; a pure generation change does too.
  FabricOptions cheaper;
  cheaper.ab_state = LinkState::kUp;
  const Fabric changed_content = MakeFabric(cheaper);
  PP_CHECK(changed_content.snapshot->Id() == first.snapshot->Id());
  FabricOptions bumped;
  bumped.generations.link_state = LinkStateGeneration(2);
  const Fabric changed_generation = MakeFabric(bumped);
  PP_CHECK(changed_generation.snapshot->Id() != first.snapshot->Id());
  PP_CHECK(changed_generation.snapshot->Digest() != first.snapshot->Digest());
  FabricOptions down;
  down.ab_state = LinkState::kDown;
  PP_CHECK(MakeFabric(down).snapshot->Id() != first.snapshot->Id());
  FabricOptions without_link;
  without_link.include_ab2 = false;
  PP_CHECK(MakeFabric(without_link).snapshot->Id() != first.snapshot->Id());
}

PP_TEST(core, snapshot_builder_rejects_duplicate_records) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  const FabricOptions options;
  const SnapshotGenerations generations = DefaultGenerations();

  // Duplicate node identity is detected while building, not while adding.
  {
    FabricSnapshotBuilder builder;
    builder.SetGenerations(generations);
    const NodeRecord node = MakeNode(fabric.a, {fabric.a1});
    PP_CHECK(builder.AddNode(node));
    PP_CHECK(builder.AddNode(node));
    const SnapshotBuildResult build = builder.Build();
    PP_CHECK(!build.ok());
    PP_REQUIRE(build.error.has_value());
    PP_CHECK_EQ(*build.error, DiagnosticCode::kDuplicateIdentifier);
    PP_CHECK_EQ(build.detail, std::string("duplicate node identity"));
    PP_CHECK(build.snapshot == nullptr);
  }
  // Duplicate link identity.
  {
    FabricSnapshotBuilder builder;
    builder.SetGenerations(generations);
    AddFabricRecords(builder, fabric, options);
    PP_CHECK(builder.AddEdge(MakeEdge(fabric.ab, fabric.a, fabric.b, fabric.a1, fabric.b1, 1)));
    const SnapshotBuildResult build = builder.Build();
    PP_CHECK(!build.ok());
    PP_REQUIRE(build.error.has_value());
    PP_CHECK_EQ(*build.error, DiagnosticCode::kDuplicateIdentifier);
    PP_CHECK_EQ(build.detail, std::string("duplicate link identity"));
  }
  // Duplicate endpoint identity.
  {
    FabricSnapshotBuilder builder;
    builder.SetGenerations(generations);
    AddFabricRecords(builder, fabric, options);
    PP_CHECK(builder.AddEndpoint(MakeEndpoint(fabric.ea, fabric.a, fabric.a1, kGenerationA)));
    const SnapshotBuildResult build = builder.Build();
    PP_CHECK(!build.ok());
    PP_REQUIRE(build.error.has_value());
    PP_CHECK_EQ(*build.error, DiagnosticCode::kAmbiguousEndpoint);
    PP_CHECK_EQ(build.detail, std::string("duplicate endpoint identity"));
  }
  // Duplicate consumed view records.
  {
    FabricSnapshotBuilder builder;
    builder.SetGenerations(generations);
    AddFabricRecords(builder, fabric, options);
    builder.SetLinkStates({LinkStateRecord{fabric.ab, LinkState::kUp}, LinkStateRecord{fabric.ab, LinkState::kUp}});
    const SnapshotBuildResult build = builder.Build();
    PP_CHECK(!build.ok());
    PP_REQUIRE(build.error.has_value());
    PP_CHECK_EQ(*build.error, DiagnosticCode::kDuplicateIdentifier);
    PP_CHECK_EQ(build.detail, std::string("duplicate link state record"));
  }
  {
    FabricSnapshotBuilder builder;
    builder.SetGenerations(generations);
    AddFabricRecords(builder, fabric, options);
    builder.SetPortStates(
        {PortStateRecord{fabric.a1, PortState::kUp}, PortStateRecord{fabric.a1, PortState::kAdminDisabled}});
    const SnapshotBuildResult build = builder.Build();
    PP_CHECK(!build.ok());
    PP_REQUIRE(build.error.has_value());
    PP_CHECK_EQ(*build.error, DiagnosticCode::kDuplicateIdentifier);
    PP_CHECK_EQ(build.detail, std::string("duplicate port state record"));
  }
  {
    FabricSnapshotBuilder builder;
    builder.SetGenerations(generations);
    AddFabricRecords(builder, fabric, options);
    const SubjectKey subject = SubjectKey::ForNode(fabric.a);
    const CapabilityId capability = TestId<CapabilityId>("core.capability");
    builder.SetCapabilities({CapabilityBinding{subject, capability, CapabilityValue(1)},
                             CapabilityBinding{subject, capability, CapabilityValue(2)}});
    const SnapshotBuildResult build = builder.Build();
    PP_CHECK(!build.ok());
    PP_REQUIRE(build.error.has_value());
    PP_CHECK_EQ(*build.error, DiagnosticCode::kDuplicateIdentifier);
    PP_CHECK_EQ(build.detail, std::string("duplicate capability binding"));
  }
  {
    FabricSnapshotBuilder builder;
    builder.SetGenerations(generations);
    AddFabricRecords(builder, fabric, options);
    FailureDomainRecord domain;
    domain.domain = TestId<FailureDomainId>("core.domain.1");
    domain.risk_class = TestId<FailureDomainClass>("core.domain.class");
    domain.members = {SubjectKey::ForNode(fabric.a)};
    builder.SetFailureDomains({domain, domain}, true);
    const SnapshotBuildResult build = builder.Build();
    PP_CHECK(!build.ok());
    PP_REQUIRE(build.error.has_value());
    PP_CHECK_EQ(*build.error, DiagnosticCode::kDuplicateIdentifier);
    PP_CHECK_EQ(build.detail, std::string("duplicate failure domain"));
  }
  // A duplicate identifier inside one node's port list is rejected on add.
  {
    FabricSnapshotBuilder builder;
    builder.SetGenerations(generations);
    PP_CHECK(!builder.AddNode(MakeNode(fabric.a, {fabric.a1, fabric.a1})));
    PP_REQUIRE(builder.Diagnostics().size() == static_cast<std::size_t>(1));
    PP_CHECK_EQ(builder.Diagnostics()[0], DiagnosticCode::kDuplicateIdentifier);
    builder.ClearDiagnostics();
    PP_CHECK(builder.Diagnostics().empty());
  }
}

PP_TEST(core, snapshot_builder_rejects_structural_violations) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  const SnapshotGenerations generations = DefaultGenerations();

  // Self loop.
  {
    FabricSnapshotBuilder builder;
    builder.SetGenerations(generations);
    PP_CHECK(!builder.AddEdge(MakeEdge(fabric.ab, fabric.a, fabric.a, fabric.a1, fabric.a1, 1)));
    PP_REQUIRE(builder.Diagnostics().size() == static_cast<std::size_t>(1));
    PP_CHECK_EQ(builder.Diagnostics()[0], DiagnosticCode::kSelfLoopRejected);
  }
  // Relationship type that disagrees with the layer.
  {
    FabricSnapshotBuilder builder;
    builder.SetGenerations(generations);
    EdgeRecord wrong = MakeEdge(fabric.ab, fabric.a, fabric.b, fabric.a1, fabric.b1, 1);
    wrong.layer = PathLayer::kLogical;
    PP_CHECK(!builder.AddEdge(wrong));
    PP_REQUIRE(builder.Diagnostics().size() == static_cast<std::size_t>(1));
    PP_CHECK_EQ(builder.Diagnostics()[0], DiagnosticCode::kLayerMismatch);
    builder.ClearDiagnostics();
    EdgeRecord tunnel = MakeEdge(fabric.ab, fabric.a, fabric.b, fabric.a1, fabric.b1, 1);
    tunnel.layer = PathLayer::kOverlay;
    tunnel.relationship = RelationshipType::kTunnelEncapsulation;
    PP_CHECK(builder.AddEdge(tunnel));
    PP_CHECK(builder.Diagnostics().empty());
  }
  // Nil identities.
  {
    FabricSnapshotBuilder builder;
    builder.SetGenerations(generations);
    PP_CHECK(!builder.AddNode(MakeNode(NodeId{}, {fabric.a1})));
    PP_REQUIRE(builder.Diagnostics().size() == static_cast<std::size_t>(1));
    PP_CHECK_EQ(builder.Diagnostics()[0], DiagnosticCode::kMalformedIdentifier);
    builder.ClearDiagnostics();
    PP_CHECK(!builder.AddNode(MakeNode(fabric.a, {PortId{}})));
    PP_REQUIRE(builder.Diagnostics().size() == static_cast<std::size_t>(1));
    PP_CHECK_EQ(builder.Diagnostics()[0], DiagnosticCode::kMalformedIdentifier);
    builder.ClearDiagnostics();
    EdgeRecord nil_edge = MakeEdge(fabric.ab, fabric.a, fabric.b, fabric.a1, fabric.b1, 1);
    nil_edge.id = LinkId{};
    PP_CHECK(!builder.AddEdge(nil_edge));
    PP_REQUIRE(builder.Diagnostics().size() == static_cast<std::size_t>(1));
    PP_CHECK_EQ(builder.Diagnostics()[0], DiagnosticCode::kMalformedIdentifier);
    builder.ClearDiagnostics();
    PP_CHECK(!builder.AddEndpoint(MakeEndpoint(EndpointId{}, fabric.a, fabric.a1, 1)));
    PP_REQUIRE(builder.Diagnostics().size() == static_cast<std::size_t>(1));
    PP_CHECK_EQ(builder.Diagnostics()[0], DiagnosticCode::kMalformedIdentifier);
  }
  // Structural generation ahead of the topology generation.
  {
    FabricSnapshotBuilder builder;
    builder.SetGenerations(generations);
    NodeRecord ahead = MakeNode(fabric.a, {fabric.a1});
    ahead.structural_generation = TopologyGeneration(2);
    PP_CHECK(!builder.AddNode(ahead));
    PP_REQUIRE(builder.Diagnostics().size() == static_cast<std::size_t>(1));
    PP_CHECK_EQ(builder.Diagnostics()[0], DiagnosticCode::kTopologyGenerationMismatch);
    builder.ClearDiagnostics();
    EdgeRecord ahead_edge = MakeEdge(fabric.ab, fabric.a, fabric.b, fabric.a1, fabric.b1, 1);
    ahead_edge.structural_generation = TopologyGeneration(2);
    PP_CHECK(!builder.AddEdge(ahead_edge));
    PP_REQUIRE(builder.Diagnostics().size() == static_cast<std::size_t>(1));
    PP_CHECK_EQ(builder.Diagnostics()[0], DiagnosticCode::kTopologyGenerationMismatch);
  }
  // Edge referencing a port that its endpoint node never published.
  {
    FabricSnapshotBuilder builder;
    builder.SetGenerations(generations);
    PP_CHECK(builder.AddNode(MakeNode(fabric.a, {fabric.a1})));
    PP_CHECK(builder.AddNode(MakeNode(fabric.b, {fabric.b1})));
    PP_CHECK(builder.AddEdge(MakeEdge(fabric.ab, fabric.a, fabric.b, fabric.a2, fabric.b1, 1)));
    const SnapshotBuildResult build = builder.Build();
    PP_CHECK(!build.ok());
    PP_REQUIRE(build.error.has_value());
    PP_CHECK_EQ(*build.error, DiagnosticCode::kNoStructuralPath);
    PP_CHECK_EQ(build.detail,
                std::string("edge ") + fabric.ab.ToString() + " references a port not published by its source node");
  }
  // Edge referencing an unpublished node.
  {
    FabricSnapshotBuilder builder;
    builder.SetGenerations(generations);
    PP_CHECK(builder.AddNode(MakeNode(fabric.b, {fabric.b1})));
    PP_CHECK(builder.AddEdge(MakeEdge(fabric.ab, fabric.a, fabric.b, fabric.a1, fabric.b1, 1)));
    const SnapshotBuildResult build = builder.Build();
    PP_CHECK(!build.ok());
    PP_REQUIRE(build.error.has_value());
    PP_CHECK_EQ(*build.error, DiagnosticCode::kNoStructuralPath);
    PP_CHECK_EQ(build.detail, std::string("edge ") + fabric.ab.ToString() + " references unknown source node");
  }
  // Endpoint referencing a node or port that is not published.
  {
    FabricSnapshotBuilder builder;
    builder.SetGenerations(generations);
    PP_CHECK(builder.AddNode(MakeNode(fabric.a, {fabric.a1})));
    PP_CHECK(builder.AddEndpoint(MakeEndpoint(fabric.ea, fabric.b, fabric.a1, 1)));
    const SnapshotBuildResult build = builder.Build();
    PP_CHECK(!build.ok());
    PP_REQUIRE(build.error.has_value());
    PP_CHECK_EQ(*build.error, DiagnosticCode::kUnknownEndpoint);
    PP_CHECK_EQ(build.detail, std::string("endpoint ") + fabric.ea.ToString() + " references an unknown node");
  }
  // Snapshot shape limits are enforced on add.
  {
    ResourceLimits tight;
    tight.max_nodes = 2;
    FabricSnapshotBuilder builder(tight);
    builder.SetGenerations(generations);
    PP_CHECK(builder.AddNode(MakeNode(fabric.a, {fabric.a1})));
    PP_CHECK(builder.AddNode(MakeNode(fabric.b, {fabric.b1})));
    PP_CHECK(!builder.AddNode(MakeNode(fabric.c, {fabric.c1})));
    PP_REQUIRE(builder.Diagnostics().size() == static_cast<std::size_t>(1));
    PP_CHECK_EQ(builder.Diagnostics()[0], DiagnosticCode::kGraphTooLarge);
  }
}

// ===========================================================================
// 5. Planning requests.
// ===========================================================================

PP_TEST(core, request_validation_rejections) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  const ResourceLimits limits;
  const PlanningRequest base = MakeAToCRequest(fabric, 2);
  PP_CHECK(ValidateRequest(base, limits).ok());
  PP_CHECK(ValidateConstraintSet(base.constraints, limits).ok());
  PP_CHECK(ValidatePolicy(base.policy, limits).ok());

  const auto expect_validation = [](const PlanningRequest& request, const ResourceLimits& used_limits,
                                    DiagnosticCode code, PlanStatus status) {
    const RequestValidation validation = ValidateRequest(request, used_limits);
    PP_CHECK_MSG(validation.code.has_value(), "expected a validation diagnostic but the request validated");
    if (validation.code.has_value()) {
      PP_CHECK_MSG(*validation.code == code, std::string("expected ") + std::string(ToString(code)) +
                                                   " but got " + std::string(ToString(*validation.code)) + " (" +
                                                   validation.detail + ")");
    }
    PP_CHECK(!validation.ok());
    PP_CHECK(!validation.detail.empty());
    PP_CHECK_EQ(StatusForValidationCode(code), status);
  };

  {  // nil identities
    PlanningRequest request = base;
    request.id = PlanningRequestId{};
    expect_validation(request, limits, DiagnosticCode::kMalformedIdentifier, PlanStatus::kMalformedRequest);
    PlanningRequest no_source = base;
    no_source.source.id = EndpointId{};
    expect_validation(no_source, limits, DiagnosticCode::kMalformedIdentifier, PlanStatus::kMalformedRequest);
    PlanningRequest no_destination = base;
    no_destination.destination.id = EndpointId{};
    expect_validation(no_destination, limits, DiagnosticCode::kMalformedIdentifier, PlanStatus::kMalformedRequest);
    PlanningRequest no_constraints = base;
    no_constraints.constraints.id = ConstraintSetId{};
    expect_validation(no_constraints, limits, DiagnosticCode::kMalformedIdentifier, PlanStatus::kMalformedRequest);
  }
  {  // candidate count
    PlanningRequest none = base;
    none.max_candidates = 0;
    expect_validation(none, limits, DiagnosticCode::kCandidateLimitExceeded, PlanStatus::kMalformedRequest);
    PlanningRequest above = base;
    above.max_candidates = limits.max_candidates_per_request + 1;
    expect_validation(above, limits, DiagnosticCode::kRequestedCandidatesAboveCeiling, PlanStatus::kResourceLimit);
    PlanningRequest ceiling = base;
    ceiling.max_candidates = limits.max_candidates_per_request;
    PP_CHECK(ValidateRequest(ceiling, limits).ok());
  }
  {  // duplicate and malformed constraint entries
    PlanningRequest duplicate_node = base;
    duplicate_node.constraints.forbidden_nodes = {fabric.a, fabric.b, fabric.a};
    expect_validation(duplicate_node, limits, DiagnosticCode::kDuplicateConstraintEntry,
                      PlanStatus::kMalformedRequest);
    PlanningRequest duplicate_link = base;
    duplicate_link.constraints.forbidden_links = {fabric.ab, fabric.ab};
    expect_validation(duplicate_link, limits, DiagnosticCode::kDuplicateConstraintEntry,
                      PlanStatus::kMalformedRequest);
    PlanningRequest nil_node = base;
    nil_node.constraints.forbidden_nodes = {NodeId{}};
    expect_validation(nil_node, limits, DiagnosticCode::kMalformedIdentifier, PlanStatus::kMalformedRequest);
    PlanningRequest empty_stage = base;
    TransitStage stage;
    stage.kind = TransitKind::kExact;
    empty_stage.constraints.required_transit = {stage};
    expect_validation(empty_stage, limits, DiagnosticCode::kMalformedIdentifier, PlanStatus::kMalformedRequest);
    PlanningRequest wide_exact = base;
    TransitStage two_alternatives;
    two_alternatives.kind = TransitKind::kExact;
    two_alternatives.alternatives = {fabric.b, fabric.c};
    wide_exact.constraints.required_transit = {two_alternatives};
    expect_validation(wide_exact, limits, DiagnosticCode::kConstraintCountExceeded, PlanStatus::kResourceLimit);
    PlanningRequest duplicate_alternative = base;
    TransitStage repeated;
    repeated.kind = TransitKind::kAnyOf;
    repeated.alternatives = {fabric.b, fabric.b};
    duplicate_alternative.constraints.required_transit = {repeated};
    expect_validation(duplicate_alternative, limits, DiagnosticCode::kDuplicateConstraintEntry,
                      PlanStatus::kMalformedRequest);
    PlanningRequest unknown_scope = base;
    CapabilityRequirement requirement;
    requirement.capability = TestId<CapabilityId>("core.capability");
    requirement.scope = static_cast<CapabilityScope>(99);
    unknown_scope.constraints.required_capabilities = {requirement};
    expect_validation(unknown_scope, limits, DiagnosticCode::kUnsupportedRequest, PlanStatus::kUnsupported);
    PlanningRequest unknown_comparator = base;
    requirement.scope = CapabilityScope::kEveryLink;
    requirement.comparator = static_cast<CapabilityComparator>(99);
    unknown_comparator.constraints.required_capabilities = {requirement};
    expect_validation(unknown_comparator, limits, DiagnosticCode::kUnsupportedRequest, PlanStatus::kUnsupported);
  }
  {  // policy
    PlanningRequest penalty = base;
    penalty.policy.cost_model.locality_penalty = CostValue(5);
    expect_validation(penalty, limits, DiagnosticCode::kUnsupportedRequest, PlanStatus::kUnsupported);
    PlanningRequest scoped = penalty;
    scoped.policy.locality_scope = {fabric.a, fabric.b};
    PP_CHECK(ValidateRequest(scoped, limits).ok());
    PlanningRequest duplicate_scope = scoped;
    duplicate_scope.policy.locality_scope = {fabric.a, fabric.a};
    expect_validation(duplicate_scope, limits, DiagnosticCode::kDuplicateConstraintEntry,
                      PlanStatus::kMalformedRequest);
    PlanningRequest nil_scope = scoped;
    nil_scope.policy.locality_scope = {NodeId{}};
    expect_validation(nil_scope, limits, DiagnosticCode::kMalformedIdentifier, PlanStatus::kMalformedRequest);
    PlanningRequest unknown_layer = base;
    unknown_layer.constraints.layer = static_cast<PathLayer>(99);
    expect_validation(unknown_layer, limits, DiagnosticCode::kUnsupportedLayer, PlanStatus::kUnsupported);
    PlanningRequest unknown_mode = base;
    unknown_mode.mode = static_cast<PlanningMode>(99);
    expect_validation(unknown_mode, limits, DiagnosticCode::kUnsupportedRequest, PlanStatus::kUnsupported);
    PlanningRequest unknown_authority = base;
    unknown_authority.policy.authority_validation = static_cast<AuthorityValidationMode>(99);
    expect_validation(unknown_authority, limits, DiagnosticCode::kUnsupportedRequest, PlanStatus::kUnsupported);
  }
  {  // hop ceiling and expectations
    PlanningRequest too_many_hops = base;
    too_many_hops.constraints.max_hops = HopCount(limits.max_hops + 1);
    expect_validation(too_many_hops, limits, DiagnosticCode::kMaxHopsExceeded, PlanStatus::kConstraintUnsatisfied);
    PlanningRequest zero_domain_limit = base;
    zero_domain_limit.constraints.max_members_per_failure_domain = 0;
    expect_validation(zero_domain_limit, limits, DiagnosticCode::kConstraintCountExceeded, PlanStatus::kResourceLimit);
    PlanningRequest zero_topology = base;
    zero_topology.expect_topology = true;
    zero_topology.expected_topology = TopologyGeneration(0);
    expect_validation(zero_topology, limits, DiagnosticCode::kMalformedIdentifier, PlanStatus::kMalformedRequest);
    PlanningRequest nil_snapshot = base;
    nil_snapshot.expect_snapshot = true;
    nil_snapshot.expected_snapshot = SnapshotId{};
    expect_validation(nil_snapshot, limits, DiagnosticCode::kMalformedIdentifier, PlanStatus::kMalformedRequest);
  }
  {  // reduced limits: per-vector, total and per-stage ceilings
    ResourceLimits tight;
    tight.max_forbidden_ids = 2;
    tight.max_required_ids = 2;
    tight.max_capability_requirements = 2;
    tight.max_members_in_any_set = 2;
    tight.max_constraints_total = 3;
    PlanningRequest many_nodes = base;
    many_nodes.constraints.forbidden_nodes = {fabric.a, fabric.b, fabric.c};
    expect_validation(many_nodes, tight, DiagnosticCode::kConstraintCountExceeded, PlanStatus::kResourceLimit);
    PlanningRequest many_entries = base;
    many_entries.constraints.forbidden_nodes = {fabric.a, fabric.b};
    many_entries.constraints.forbidden_links = {fabric.ab, fabric.ab2};
    expect_validation(many_entries, tight, DiagnosticCode::kConstraintCountExceeded, PlanStatus::kResourceLimit);
    PlanningRequest wide_stage = base;
    TransitStage wide;
    wide.kind = TransitKind::kAnyOf;
    wide.alternatives = {fabric.a, fabric.b, fabric.c};
    wide_stage.constraints.required_transit = {wide};
    expect_validation(wide_stage, tight, DiagnosticCode::kConstraintCountExceeded, PlanStatus::kResourceLimit);
    PlanningRequest many_capabilities = base;
    CapabilityRequirement requirement;
    requirement.capability = TestId<CapabilityId>("core.capability");
    many_capabilities.constraints.required_capabilities = {requirement, requirement, requirement};
    expect_validation(many_capabilities, tight, DiagnosticCode::kConstraintCountExceeded,
                      PlanStatus::kResourceLimit);
    PlanningRequest ok_within_tight = base;
    ok_within_tight.constraints.forbidden_nodes = {fabric.a, fabric.b};
    PP_CHECK(ValidateRequest(ok_within_tight, tight).ok());
  }
}

// ===========================================================================
// 6. Planner runtime.
// ===========================================================================

PP_TEST(core, planner_zero_hop_self_path) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  PlannerRuntime runtime(ConfigFor(fabric));
  PlanningRequest request =
      MakeRequest(fabric.eb, EntityGeneration(kGenerationB), fabric.eb, EntityGeneration(kGenerationB), 1);
  PP_CHECK_EQ(request.policy.allow_zero_hop_self_path, true);

  const PlanningResult allowed = runtime.Plan(request);
  PP_CHECK_EQ(allowed.status, PlanStatus::kPlanned);
  PP_CHECK_EQ(allowed.source_endpoint, fabric.eb);
  PP_CHECK_EQ(allowed.destination_endpoint, fabric.eb);
  PP_CHECK_EQ(allowed.source_node, fabric.b);
  PP_CHECK_EQ(allowed.destination_node, fabric.b);
  PP_CHECK_EQ(allowed.requested_candidates, 1u);
  PP_CHECK_EQ(allowed.truncated, false);
  PP_CHECK_EQ(allowed.diagnostic_mode, false);
  PP_CHECK(!allowed.primary_failure.has_value());
  PP_REQUIRE(allowed.candidates.size() == static_cast<std::size_t>(1));
  const Candidate& zero_hop = allowed.candidates.front();
  PP_CHECK_EQ(zero_hop.path.nodes.size(), static_cast<std::size_t>(1));
  PP_CHECK_EQ(zero_hop.path.nodes.front(), fabric.b);
  PP_CHECK_EQ(zero_hop.path.hops.size(), static_cast<std::size_t>(0));
  PP_CHECK_EQ(zero_hop.path.source, fabric.b);
  PP_CHECK_EQ(zero_hop.path.destination, fabric.b);
  PP_CHECK(zero_hop.path.IsWellFormed());
  PP_CHECK(zero_hop.path.IsSimple());
  PP_CHECK_EQ(zero_hop.cost.hops.Value(), 0u);
  PP_CHECK_EQ(zero_hop.cost.hops_cost.Value(), 0ull);
  PP_CHECK_EQ(zero_hop.cost.static_cost.Value(), 0ull);
  PP_CHECK_EQ(zero_hop.cost.total.Value(), 0ull);
  PP_CHECK_EQ(zero_hop.cost.degraded_hops, 0u);
  PP_CHECK_EQ(zero_hop.cost.locality_breaches, 0u);
  PP_CHECK_EQ(zero_hop.rank.Value(), 1u);
  PP_CHECK_EQ(zero_hop.id, zero_hop.path.Id());
  PP_CHECK_EQ(zero_hop.currentness, Currentness::kCurrent);
  PP_CHECK_EQ(zero_hop.authority, AuthorityValidation::kNotRequested);
  PP_CHECK(zero_hop.notes.empty());
  PP_CHECK_EQ(zero_hop.provenance.constraint_set, request.constraints.id);
  PP_CHECK_EQ(zero_hop.provenance.policy_generation, request.policy.generation);
  PP_CHECK_EQ(zero_hop.provenance.planning_rule_version, kPlanningRuleVersion);
  PP_CHECK_EQ(zero_hop.provenance.path_encoding_version, kPathEncodingVersion);
  PP_CHECK_EQ(zero_hop.provenance.source, EvidenceSource::kSynthetic);

  request.policy.allow_zero_hop_self_path = false;
  const PlanningResult denied = runtime.Plan(request);
  PP_CHECK_EQ(denied.status, PlanStatus::kConstraintUnsatisfied);
  PP_REQUIRE(denied.primary_failure.has_value());
  PP_CHECK_EQ(*denied.primary_failure, DiagnosticCode::kZeroHopSelfPathDisallowed);
  PP_CHECK(denied.candidates.empty());
  PP_CHECK_EQ(denied.source_node, fabric.b);
  PP_CHECK_EQ(denied.destination_node, fabric.b);
  PP_CHECK(HasCode(denied.explanations, DiagnosticCode::kZeroHopSelfPathDisallowed));
}

PP_TEST(core, planner_endpoint_resolution_statuses) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  PlannerRuntime runtime(ConfigFor(fabric));

  {
    PlanningRequest request = MakeAToCRequest(fabric, 1);
    request.source.id = TestId<EndpointId>("core.endpoint.absent");
    const PlanningResult result = runtime.Plan(request);
    PP_CHECK_EQ(result.status, PlanStatus::kSourceUnknown);
    PP_REQUIRE(result.primary_failure.has_value());
    PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kUnknownEndpoint);
    PP_CHECK(result.candidates.empty());
    PP_CHECK_EQ(result.source_node, NodeId{});
    PP_CHECK(HasCode(result.explanations, DiagnosticCode::kUnknownEndpoint));
  }
  {
    PlanningRequest request = MakeAToCRequest(fabric, 1);
    request.destination.id = TestId<EndpointId>("core.endpoint.absent");
    const PlanningResult result = runtime.Plan(request);
    PP_CHECK_EQ(result.status, PlanStatus::kDestinationUnknown);
    PP_REQUIRE(result.primary_failure.has_value());
    PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kUnknownEndpoint);
    PP_CHECK(result.candidates.empty());
  }
  {
    PlanningRequest request =
        MakeRequest(fabric.ea, EntityGeneration(kGenerationA + 1), fabric.ec, EntityGeneration(kGenerationC), 1);
    const PlanningResult result = runtime.Plan(request);
    PP_CHECK_EQ(result.status, PlanStatus::kSourceStale);
    PP_REQUIRE(result.primary_failure.has_value());
    PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kEntityGenerationMismatch);
    PP_CHECK(result.candidates.empty());
    PP_CHECK(HasDetail(result.explanations,
                       "source endpoint generation " + EntityGeneration(kGenerationA + 1).ToString() +
                           " does not match published generation " + EntityGeneration(kGenerationA).ToString()));
  }
  {
    PlanningRequest request =
        MakeRequest(fabric.ea, EntityGeneration(kGenerationA), fabric.ec, EntityGeneration(kGenerationC + 1), 1);
    const PlanningResult result = runtime.Plan(request);
    PP_CHECK_EQ(result.status, PlanStatus::kDestinationStale);
    PP_REQUIRE(result.primary_failure.has_value());
    PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kEntityGenerationMismatch);
    PP_CHECK(result.candidates.empty());
  }
  {
    // A published binding whose class does not match the request is UNSUPPORTED.
    PlanningRequest request = MakeAToCRequest(fabric, 1);
    request.source.endpoint_class = EndpointClass::kNic;
    const PlanningResult result = runtime.Plan(request);
    PP_CHECK_EQ(result.status, PlanStatus::kUnsupported);
    PP_REQUIRE(result.primary_failure.has_value());
    PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kUnsupportedEndpointClass);
    PP_CHECK(result.candidates.empty());
    PP_CHECK(HasDetail(result.explanations,
                       "source endpoint class mismatch: requested NIC, published ENDPOINT"));
  }
  {
    // An endpoint class outside the enumeration is never silently accepted, and the
    // rejection is reported with the exact status/diagnostic.
    PlanningRequest request = MakeAToCRequest(fabric, 1);
    request.source.endpoint_class = static_cast<EndpointClass>(99);
    PP_CHECK(ValidateRequest(request, ResourceLimits{}).ok());
    const PlanningResult result = runtime.Plan(request);
    PP_CHECK_EQ(result.status, PlanStatus::kUnsupported);
    PP_REQUIRE(result.primary_failure.has_value());
    PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kUnsupportedEndpointClass);
    PP_CHECK(result.candidates.empty());
  }
  {
    // A wrong destination class is rejected with the destination detail.
    PlanningRequest request = MakeAToCRequest(fabric, 1);
    request.destination.endpoint_class = EndpointClass::kPort;
    const PlanningResult result = runtime.Plan(request);
    PP_CHECK_EQ(result.status, PlanStatus::kUnsupported);
    PP_REQUIRE(result.primary_failure.has_value());
    PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kUnsupportedEndpointClass);
  }
}

PP_TEST(core, planner_evidence_expectations) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  PlannerRuntime runtime(ConfigFor(fabric));
  const PlanningRequest base = MakeAToCRequest(fabric, 1);
  PP_CHECK_EQ(runtime.CurrentEpoch().Value(), 1ull);
  PP_CHECK_EQ(runtime.PublishSequence().Value(), 0ull);
  PP_CHECK(runtime.CurrentSnapshot() != nullptr);

  const PlanningResult plain = runtime.Plan(base);
  PP_CHECK_EQ(plain.status, PlanStatus::kPlanned);
  PP_CHECK_EQ(plain.evidence.snapshot, fabric.snapshot->Id());
  PP_CHECK_EQ(plain.evidence.generations, fabric.snapshot->Generations());
  PP_CHECK_EQ(plain.evidence.publish_sequence.Value(), 0ull);

  {
    PlanningRequest request = base;
    request.expect_epoch = true;
    request.expected_epoch = FabricEpoch(1);
    PP_CHECK_EQ(runtime.Plan(request).status, PlanStatus::kPlanned);
    request.expected_epoch = FabricEpoch(2);
    const PlanningResult stale = runtime.Plan(request);
    PP_CHECK_EQ(stale.status, PlanStatus::kEpochStale);
    PP_REQUIRE(stale.primary_failure.has_value());
    PP_CHECK_EQ(*stale.primary_failure, DiagnosticCode::kEpochMismatch);
    PP_CHECK(stale.candidates.empty());
    PP_CHECK(HasDetail(stale.explanations,
                       "request expects fabric epoch 2 but the captured snapshot carries 1"));
  }
  {
    PlanningRequest request = base;
    request.expect_topology = true;
    request.expected_topology = TopologyGeneration(1);
    PP_CHECK_EQ(runtime.Plan(request).status, PlanStatus::kPlanned);
    request.expected_topology = TopologyGeneration(2);
    const PlanningResult stale = runtime.Plan(request);
    PP_CHECK_EQ(stale.status, PlanStatus::kTopologyStale);
    PP_REQUIRE(stale.primary_failure.has_value());
    PP_CHECK_EQ(*stale.primary_failure, DiagnosticCode::kTopologyGenerationMismatch);
    PP_CHECK(stale.candidates.empty());
    PP_CHECK(HasDetail(stale.explanations,
                       "request expects topology generation 2 but the captured snapshot carries 1"));
  }
  {
    PlanningRequest request = base;
    request.expect_snapshot = true;
    request.expected_snapshot = fabric.snapshot->Id();
    PP_CHECK_EQ(runtime.Plan(request).status, PlanStatus::kPlanned);
    const SnapshotId other = TestId<SnapshotId>("core.snapshot.other");
    request.expected_snapshot = other;
    const PlanningResult mismatch = runtime.Plan(request);
    PP_CHECK_EQ(mismatch.status, PlanStatus::kRevalidationRequired);
    PP_REQUIRE(mismatch.primary_failure.has_value());
    PP_CHECK_EQ(*mismatch.primary_failure, DiagnosticCode::kStaleEvidence);
    PP_CHECK(mismatch.candidates.empty());
    PP_CHECK(HasDetail(mismatch.explanations, "request expects snapshot " + other.ToString() +
                                                  " but the captured snapshot is " +
                                                  fabric.snapshot->Id().ToString()));
  }
}

PP_TEST(core, planner_authority_scope_epoch_and_missing_snapshot) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  const PlanningRequest base = MakeAToCRequest(fabric, 1);

  // No snapshot has ever been published to this runtime.
  PlannerRuntime bare;
  PP_CHECK(bare.CurrentSnapshot() == nullptr);
  const PlanningResult no_snapshot = bare.Plan(base);
  PP_CHECK_EQ(no_snapshot.status, PlanStatus::kRevalidationRequired);
  PP_REQUIRE(no_snapshot.primary_failure.has_value());
  PP_CHECK_EQ(*no_snapshot.primary_failure, DiagnosticCode::kSnapshotNotAvailable);
  PP_CHECK(no_snapshot.candidates.empty());
  PP_CHECK_EQ(no_snapshot.source_endpoint, EndpointId{});
  PP_CHECK(HasDetail(no_snapshot.explanations, "no fabric snapshot has been published to this runtime"));

  PlannerRuntime runtime(ConfigFor(fabric));
  {
    PlanningRequest request = base;
    request.authority.enforce_scope = true;
    request.authority.scope_mask = 0;
    const PlanningResult result = runtime.Plan(request);
    PP_CHECK_EQ(result.status, PlanStatus::kUnauthorized);
    PP_REQUIRE(result.primary_failure.has_value());
    PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kAuthorityScopeInsufficient);
    PP_CHECK(result.candidates.empty());
    PP_CHECK(HasDetail(result.explanations, "caller authority does not include kSubmitPlanRequest"));
  }
  {
    PlanningRequest request = base;
    request.authority.enforce_scope = true;
    request.authority.scope_mask = ToMask(AuthorityScope::kReadPlan);
    PP_CHECK_EQ(runtime.Plan(request).status, PlanStatus::kUnauthorized);
  }
  {
    PlanningRequest request = base;
    request.authority.enforce_scope = true;
    request.authority.scope_mask = ToMask(AuthorityScope::kSubmitPlanRequest);
    PP_CHECK_EQ(runtime.Plan(request).status, PlanStatus::kPlanned);
    PP_CHECK(HasScope(request.authority.scope_mask, AuthorityScope::kSubmitPlanRequest));
    PP_CHECK(!HasScope(request.authority.scope_mask, AuthorityScope::kReadPlan));
  }
  {
    PlanningRequest request = base;
    request.authority.enforce_scope = true;
    request.authority.scope_mask =
        CombineScopes(AuthorityScope::kSubmitPlanRequest, AuthorityScope::kReadPlan);
    PP_CHECK(HasScope(request.authority.scope_mask, AuthorityScope::kReadPlan));
    PP_CHECK_EQ(runtime.Plan(request).status, PlanStatus::kPlanned);
  }
  {
    PlanningRequest request = base;
    request.authority.enforce_scope = false;
    request.authority.scope_mask = 0;
    PP_CHECK_EQ(runtime.Plan(request).status, PlanStatus::kPlanned);
  }
  {
    PlanningRequest request = base;
    request.authority.epoch_bound = true;
    request.authority.coordinator_epoch = CoordinatorEpoch(1);
    PP_CHECK_EQ(runtime.Plan(request).status, PlanStatus::kPlanned);
    request.authority.coordinator_epoch = CoordinatorEpoch(2);
    const PlanningResult result = runtime.Plan(request);
    PP_CHECK_EQ(result.status, PlanStatus::kEpochStale);
    PP_REQUIRE(result.primary_failure.has_value());
    PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kEpochMismatch);
    PP_CHECK(HasDetail(result.explanations,
                       "request carries coordinator epoch 2 but the runtime epoch is 1"));
  }
  {
    // Malformed requests never throw and are reported as MALFORMED_REQUEST.
    PlanningRequest request = base;
    request.max_candidates = 0;
    const PlanningResult result = runtime.Plan(request);
    PP_CHECK_EQ(result.status, PlanStatus::kMalformedRequest);
    PP_REQUIRE(result.primary_failure.has_value());
    PP_CHECK_EQ(*result.primary_failure, DiagnosticCode::kCandidateLimitExceeded);
    PP_CHECK_EQ(StatusForValidationCode(DiagnosticCode::kCandidateLimitExceeded), PlanStatus::kMalformedRequest);
  }
}

// ===========================================================================
// 7. Deterministic candidate identity and ranking.
// ===========================================================================

PP_TEST(core, candidate_identity_cost_and_ranking) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  PlannerRuntime runtime(ConfigFor(fabric));
  const PlanningRequest request = MakeAToCRequest(fabric, 2);
  const PlanningResult result = runtime.Plan(request);
  PP_CHECK_EQ(result.status, PlanStatus::kPlanned);
  PP_REQUIRE(result.candidates.size() == static_cast<std::size_t>(2));

  const Candidate& best = result.candidates[0];
  const Candidate& next = result.candidates[1];

  // Identity is recomputed from the exact canonical path.
  PP_CHECK_EQ(best.id, best.path.Id());
  PP_CHECK_EQ(next.id, next.path.Id());
  PP_CHECK(best.id != next.id);
  PP_CHECK_EQ(best.rank.Value(), 1u);
  PP_CHECK_EQ(next.rank.Value(), 2u);
  PP_CHECK(RanksBefore(best, next));
  PP_CHECK(!RanksBefore(next, best));
  PP_CHECK(best.cost.total <= next.cost.total);

  // Exact route shape and cost decomposition (hop_cost 1, ab 1, ab2 2, bc 4).
  PP_CHECK_EQ(best.path.nodes.size(), static_cast<std::size_t>(3));
  PP_CHECK_EQ(best.path.nodes[0], fabric.a);
  PP_CHECK_EQ(best.path.nodes[1], fabric.b);
  PP_CHECK_EQ(best.path.nodes[2], fabric.c);
  PP_CHECK_EQ(best.path.hops.size(), static_cast<std::size_t>(2));
  PP_CHECK_EQ(best.path.hops[0].link, fabric.ab);
  PP_CHECK_EQ(best.path.hops[0].from, fabric.a);
  PP_CHECK_EQ(best.path.hops[0].to, fabric.b);
  PP_CHECK_EQ(best.path.hops[0].from_port, fabric.a1);
  PP_CHECK_EQ(best.path.hops[0].to_port, fabric.b1);
  PP_CHECK_EQ(best.path.hops[0].layer, PathLayer::kPhysical);
  PP_CHECK_EQ(best.path.hops[0].relationship, RelationshipType::kDirectLink);
  PP_CHECK_EQ(best.path.hops[0].static_cost.Value(), 1u);
  PP_CHECK_EQ(best.path.hops[0].structural_generation.Value(), 1ull);
  PP_CHECK_EQ(best.path.hops[0].link_state, LinkState::kUp);
  PP_CHECK_EQ(best.path.hops[0].degraded, false);
  PP_CHECK_EQ(best.path.hops[1].link, fabric.bc);
  PP_CHECK_EQ(next.path.hops[0].link, fabric.ab2);
  PP_CHECK_EQ(next.path.hops[1].link, fabric.bc);
  PP_CHECK(best.path.IsWellFormed());
  PP_CHECK(next.path.IsWellFormed());
  PP_CHECK(best.path.IsSimple());
  PP_CHECK(next.path.IsSimple());

  PP_CHECK_EQ(best.cost.hops.Value(), 2u);
  PP_CHECK_EQ(best.cost.hops_cost.Value(), 2ull);
  PP_CHECK_EQ(best.cost.static_cost.Value(), 5ull);
  PP_CHECK_EQ(best.cost.degraded_penalty.Value(), 0ull);
  PP_CHECK_EQ(best.cost.locality_penalty.Value(), 0ull);
  PP_CHECK_EQ(best.cost.total.Value(), 7ull);
  PP_CHECK_EQ(next.cost.hops.Value(), 2u);
  PP_CHECK_EQ(next.cost.static_cost.Value(), 6ull);
  PP_CHECK_EQ(next.cost.total.Value(), 8ull);

  // Documented cost identity: total == hops_cost + static_cost + penalties, and
  // hops_cost == hop_count * hop_cost.
  const auto static_cost_of = [](const CandidatePath& path) {
    CostValue total(0);
    for (const PathHop& hop : path.hops) {
      const std::optional<CostValue> sum = CheckedAdd(total, CostValue(hop.static_cost.Value()));
      Require(sum.has_value(), "static cost accumulation overflowed");
      total = *sum;
    }
    return total;
  };
  for (const Candidate& candidate : result.candidates) {
    PP_CHECK_EQ(candidate.cost.total, SumCostComponents(candidate.cost));
    PP_CHECK_EQ(candidate.cost.static_cost, static_cost_of(candidate.path));
    const std::optional<CostValue> expected_hops_cost = CheckedMul(
        CostValue(candidate.cost.hops.Value()), request.policy.cost_model.hop_cost.Value());
    PP_REQUIRE(expected_hops_cost.has_value());
    PP_CHECK_EQ(candidate.cost.hops_cost, *expected_hops_cost);
    PP_CHECK_EQ(candidate.cost.hops.Value(), static_cast<std::uint32_t>(candidate.path.hops.size()));
    PP_CHECK_EQ(candidate.evidence.snapshot, result.evidence.snapshot);
  }
  // Ranks are exactly 1..n and costs are non-decreasing.
  for (std::size_t index = 0; index < result.candidates.size(); ++index) {
    PP_CHECK_EQ(result.candidates[index].rank.Value(), static_cast<std::uint32_t>(index + 1));
    if (index > 0) {
      PP_CHECK(result.candidates[index - 1].cost.total <= result.candidates[index].cost.total);
    }
  }

  // Re-running the same request produces the same candidate identities.
  const PlanningResult repeated = runtime.Plan(request);
  PP_REQUIRE(repeated.candidates.size() == result.candidates.size());
  for (std::size_t index = 0; index < result.candidates.size(); ++index) {
    PP_CHECK_EQ(repeated.candidates[index].id, result.candidates[index].id);
    PP_CHECK(SamePath(repeated.candidates[index].path, result.candidates[index].path));
    PP_CHECK(repeated.candidates[index].cost == result.candidates[index].cost);
  }

  // The canonical identity is hop-order sensitive: a permuted hop vector encodes
  // differently even though it no longer describes a valid continuation.
  CandidatePath permuted;
  permuted.source = best.path.source;
  permuted.destination = best.path.destination;
  permuted.layer = best.path.layer;
  permuted.nodes = best.path.nodes;
  permuted.hops.push_back(best.path.hops[1]);
  permuted.hops.push_back(best.path.hops[0]);
  PP_CHECK(!permuted.IsWellFormed());
  PP_CHECK(permuted.Id() != best.path.Id());
  PP_CHECK(permuted.Digest() != best.path.Digest());
  ByteWriter original_writer(512);
  best.path.Encode(original_writer);
  ByteWriter permuted_writer(512);
  permuted.Encode(permuted_writer);
  PP_CHECK(!original_writer.overflowed());
  PP_CHECK(!permuted_writer.overflowed());
  PP_CHECK(original_writer.data() != permuted_writer.data());

  // A different source identity yields a different candidate identity.
  CandidatePath moved = best.path;
  moved.source = fabric.b;
  PP_CHECK(moved.Id() != best.path.Id());

  // Ranking precedence: total cost, then hop count, then the canonical path order (the
  // lexicographic node sequence, then the link sequence). The candidate identity is an
  // identity, not an ordering key, so changing it alone does not reorder anything.
  Candidate cheaper = best;
  cheaper.cost.total = CostValue(1);
  PP_CHECK(RanksBefore(cheaper, best));
  Candidate more_hops = best;
  more_hops.cost.hops = HopCount(9);
  PP_CHECK(RanksBefore(best, more_hops));
  Candidate lower_id = best;
  lower_id.id = IdOf<CandidatePathId>(ZeroPadded("01"));
  PP_CHECK(!RanksBefore(lower_id, best));
  PP_CHECK(!RanksBefore(best, lower_id));
  PP_CHECK(CompareCanonicalPaths(best.path, best.path) == std::strong_ordering::equal);
  PP_CHECK(!RanksBefore(best, best));

  // An earlier first-hop node id ranks first when cost and hops tie.
  CandidatePath earlier = best.path;
  CandidatePath later = best.path;
  if (earlier.nodes.size() >= 2 && later.nodes.size() >= 2) {
    later.nodes[1] = earlier.nodes[1] < later.nodes[1] ? NodeId{} : later.nodes[1];
    if (earlier.nodes[1] < later.nodes[1]) {
      Candidate earlier_candidate = best;
      earlier_candidate.path = earlier;
      Candidate later_candidate = best;
      later_candidate.path = later;
      PP_CHECK(RanksBefore(earlier_candidate, later_candidate));
    }
  }
}
// ===========================================================================
// 8. Currentness and lifecycle.
// ===========================================================================

namespace {

SnapshotGenerations AdvanceDimension(std::uint32_t dimension, std::uint64_t value) {
  SnapshotGenerations generations = DefaultGenerations();
  switch (dimension) {
    case 0:
      generations.topology = TopologyGeneration(value);
      break;
    case 1:
      generations.link_state = LinkStateGeneration(value);
      break;
    case 2:
      generations.ports = PortGeneration(value);
      break;
    case 3:
      generations.capabilities = CapabilityGeneration(value);
      break;
    case 4:
      generations.failure_domains = FailureDomainGeneration(value);
      break;
    case 5:
      generations.epoch = FabricEpoch(value);
      break;
    default:
      generations.policy = PolicyGeneration(value);
      break;
  }
  return generations;
}

}  // namespace

PP_TEST(core, currentness_reports_each_generation_dimension) {
  struct DimensionCase {
    std::uint32_t index;
    Currentness expected;
    DiagnosticCode code;
    const char* keyword;
  };
  const DimensionCase kDimensions[] = {
      {0, Currentness::kStaleTopology, DiagnosticCode::kTopologyGenerationMismatch, "topology"},
      {1, Currentness::kStaleLinkState, DiagnosticCode::kStaleEvidence, "link-state"},
      {2, Currentness::kStalePortState, DiagnosticCode::kStaleEvidence, "port"},
      {3, Currentness::kStaleCapability, DiagnosticCode::kStaleEvidence, "capability"},
      {4, Currentness::kStaleFailureDomain, DiagnosticCode::kStaleEvidence, "failure-domain"},
      {5, Currentness::kStaleEpoch, DiagnosticCode::kEpochMismatch, "fabric epoch"},
      {6, Currentness::kStalePolicy, DiagnosticCode::kStaleEvidence, "policy"},
  };

  for (const DimensionCase& dimension : kDimensions) {
    const Fabric base = MakeFabric(FabricOptions{});
    PlannerRuntime runtime(ConfigFor(base));
    const PlanningRequest request = MakeAToCRequest(base, 1);
    PlanningResult result;
    const PathPlan plan = PlanOnce(runtime, request, result);
    PP_REQUIRE(result.status == PlanStatus::kPlanned);
    PP_CHECK(runtime.Retain(plan));
    PP_CHECK_EQ(runtime.CheckCurrentness(plan).currentness, Currentness::kCurrent);

    FabricOptions advanced;
    advanced.generations = AdvanceDimension(dimension.index, 2);
    const Fabric next = MakeFabric(advanced);
    runtime.PublishSnapshot(next.snapshot);
    PP_CHECK_EQ(runtime.PublishSequence().Value(), 1ull);
    PP_CHECK_EQ(runtime.CurrentSnapshot()->Id(), next.snapshot->Id());

    const PlanCurrentnessReport report = runtime.CheckCurrentness(plan);
    const std::string expected_detail =
        std::string(dimension.keyword) + " generation changed: 1 -> 2";
    PP_CHECK_MSG(report.currentness == dimension.expected, DescribeChanges(report.changes));
    PP_CHECK_MSG(HasDetail(report.changes, expected_detail), DescribeChanges(report.changes));
    PP_CHECK_MSG(HasCode(report.changes, dimension.code), DescribeChanges(report.changes));
    PP_CHECK(HasDetail(report.changes, "snapshot identity changed: " + base.snapshot->Id().ToString() +
                                           " -> " + next.snapshot->Id().ToString()));
    PP_CHECK_EQ(report.current(), false);
    PP_CHECK_EQ(report.prior_evidence, plan.evidence);
    PP_CHECK_EQ(report.current_evidence.snapshot, next.snapshot->Id());
    PP_CHECK_EQ(report.current_evidence.generations, next.snapshot->Generations());
    PP_CHECK_EQ(ClassifyEvidence(plan.evidence, report.current_evidence), dimension.expected);
  }

  // Precedence: the most severe (lowest rank) changed dimension wins, a named
  // stale dimension outranks generic revalidation, and revalidation outranks current.
  PP_CHECK_EQ(MoreSevere(Currentness::kCurrent, Currentness::kStalePolicy), Currentness::kStalePolicy);
  PP_CHECK_EQ(MoreSevere(Currentness::kRevalidationRequired, Currentness::kCurrent),
              Currentness::kRevalidationRequired);
  PP_CHECK_EQ(MoreSevere(Currentness::kStaleLinkState, Currentness::kRevalidationRequired),
              Currentness::kStaleLinkState);
  PP_CHECK_EQ(MoreSevere(Currentness::kStalePolicy, Currentness::kStaleTopology), Currentness::kStaleTopology);
  PP_CHECK_EQ(MoreSevere(Currentness::kStaleTopology, Currentness::kStaleEpoch), Currentness::kStaleEpoch);
  PP_CHECK_EQ(MoreSevere(Currentness::kStaleTopology, Currentness::kRetired), Currentness::kRetired);
  PP_CHECK(CurrentnessSeverity(Currentness::kRetired) < CurrentnessSeverity(Currentness::kStaleEpoch));
  PP_CHECK(CurrentnessSeverity(Currentness::kStaleEpoch) < CurrentnessSeverity(Currentness::kStaleTopology));
  PP_CHECK(CurrentnessSeverity(Currentness::kStalePolicy) <
           CurrentnessSeverity(Currentness::kRevalidationRequired));
  PP_CHECK(CurrentnessSeverity(Currentness::kRevalidationRequired) <
           CurrentnessSeverity(Currentness::kCurrent));

  // Several dimensions at once: every changed dimension is reported and the most
  // severe one classifies the plan.
  {
    const Fabric base = MakeFabric(FabricOptions{});
    PlannerRuntime runtime(ConfigFor(base));
    const PlanningRequest request = MakeAToCRequest(base, 1);
    PlanningResult result;
    const PathPlan plan = PlanOnce(runtime, request, result);
    PP_REQUIRE(result.status == PlanStatus::kPlanned);
    PP_CHECK(runtime.Retain(plan));
    SnapshotGenerations generations = DefaultGenerations();
    generations.topology = TopologyGeneration(2);
    generations.link_state = LinkStateGeneration(3);
    FabricOptions advanced;
    advanced.generations = generations;
    runtime.PublishSnapshot(MakeFabric(advanced).snapshot);
    const PlanCurrentnessReport report = runtime.CheckCurrentness(plan);
    PP_CHECK_EQ(report.currentness, Currentness::kStaleTopology);
    PP_CHECK(HasDetail(report.changes, "topology generation changed: 1 -> 2"));
    PP_CHECK(HasDetail(report.changes, "link-state generation changed: 1 -> 3"));
    PP_CHECK_EQ(report.current_evidence.generations.topology.Value(), 2ull);
    PP_CHECK_EQ(report.current_evidence.generations.link_state.Value(), 3ull);
  }
}

PP_TEST(core, retention_find_plan_and_count) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  PlannerRuntime runtime(ConfigFor(fabric));
  const PlanningRequest request = MakeAToCRequest(fabric, 2);
  PlanningResult result;
  const PathPlan plan = PlanOnce(runtime, request, result);
  PP_REQUIRE(result.status == PlanStatus::kPlanned);
  PP_CHECK(plan.id.IsValid());
  PP_CHECK_EQ(plan.id, plan.ComputePlanId());
  PP_CHECK_EQ(plan.semantic_digest, plan.ComputeSemanticDigest());
  PP_CHECK_EQ(plan.publish_sequence.Value(), 0ull);
  PP_CHECK_EQ(plan.request, request.id);
  PP_CHECK_EQ(plan.status, PlanStatus::kPlanned);
  PP_CHECK_EQ(plan.currentness_proven, true);
  PP_CHECK_EQ(plan.diagnostic_mode, false);
  PP_CHECK_EQ(runtime.RetainedPlanCount(), static_cast<std::size_t>(0));
  PP_CHECK(!runtime.FindPlan(plan.id).has_value());

  PP_CHECK(runtime.Retain(plan));
  PP_CHECK_EQ(runtime.RetainedPlanCount(), static_cast<std::size_t>(1));
  const std::optional<PathPlan> found = runtime.FindPlan(plan.id);
  PP_REQUIRE(found.has_value());
  PP_CHECK_EQ(found->id, plan.id);
  PP_CHECK_EQ(found->semantic_digest, plan.semantic_digest);
  PP_CHECK_EQ(found->request, plan.request);
  PP_CHECK_EQ(found->evidence, plan.evidence);
  PP_CHECK_EQ(found->candidates.size(), plan.candidates.size());
  PP_CHECK(found->HasCandidate(plan.candidates[0].id));
  PP_CHECK(!found->HasCandidate(TestId<CandidatePathId>("core.candidate.absent")));
  PP_CHECK_EQ(runtime.Retain(plan), true);
  PP_CHECK_EQ(runtime.RetainedPlanCount(), static_cast<std::size_t>(1));
  PP_CHECK(!runtime.FindPlan(TestId<PathPlanId>("core.plan.absent")).has_value());
  PP_CHECK(!runtime.Retain(PathPlan{}));

  // A second, distinct plan is retained alongside the first.
  PlanningResult second_result;
  const PathPlan second = PlanOnce(runtime, MakeAToBRequest(fabric, 1), second_result);
  PP_REQUIRE(second_result.status == PlanStatus::kPlanned);
  PP_CHECK(second.id != plan.id);
  PP_CHECK(runtime.Retain(second));
  PP_CHECK_EQ(runtime.RetainedPlanCount(), static_cast<std::size_t>(2));
  PP_CHECK(runtime.FindPlan(second.id).has_value());
  PP_CHECK(runtime.FindPlan(plan.id).has_value());
  PP_CHECK_EQ(runtime.Stats().plans_computed, 2ull);
  PP_CHECK_EQ(runtime.Stats().plans_published, 2ull);
}

PP_TEST(core, invalidation_targeted_notice_distinguishes_dependencies) {
  const Fabric fabric = MakeFabric(FabricOptions{});

  {  // A notice naming a link the plan does not traverse leaves it untouched.
    PlannerRuntime runtime(ConfigFor(fabric));
    const PlanningRequest request = MakeAToBRequest(fabric, 1);
    PlanningResult result;
    const PathPlan plan = PlanOnce(runtime, request, result);
    PP_REQUIRE(result.status == PlanStatus::kPlanned);
    PP_REQUIRE(result.candidates.size() == static_cast<std::size_t>(1));
    PP_CHECK_EQ(result.candidates[0].path.hops[0].link, fabric.ab);
    PP_CHECK(runtime.Retain(plan));
    PP_CHECK_EQ(runtime.CheckCurrentness(plan).currentness, Currentness::kCurrent);

    InvalidationNotice notice;
    notice.links = {fabric.bc};
    const InvalidationReport report = runtime.ApplyInvalidation(notice);
    PP_CHECK_EQ(report.conservative, false);
    PP_CHECK(report.affected.empty());
    PP_CHECK(report.marked_revalidation_required.empty());
    PP_CHECK(report.retired.empty());
    PP_CHECK_EQ(report.retained_plans, static_cast<std::size_t>(1));
    PP_CHECK_EQ(runtime.RetainedPlanCount(), static_cast<std::size_t>(1));
    PP_REQUIRE(runtime.FindPlan(plan.id).has_value());
    PP_CHECK_EQ(runtime.PublishSequence().Value(), 1ull);
    // The plan itself was not marked: the only reported change is the publication
    // watermark that every invalidation advances.
    const PlanCurrentnessReport after = runtime.CheckCurrentness(plan);
    PP_CHECK_MSG(!HasDetail(after.changes, "the retained plan was invalidated by a targeted notice"),
                 DescribeChanges(after.changes));
    PP_CHECK_EQ(after.changes.size(), static_cast<std::size_t>(1));
    PP_CHECK_EQ(after.changes[0].code, DiagnosticCode::kInvalidationWatermarkChanged);
    PP_CHECK_EQ(after.currentness, Currentness::kRevalidationRequired);
  }

  {  // A notice naming a traversed link marks exactly that plan.
    PlannerRuntime runtime(ConfigFor(fabric));
    const PlanningRequest request = MakeAToBRequest(fabric, 1);
    PlanningResult result;
    const PathPlan plan = PlanOnce(runtime, request, result);
    PP_REQUIRE(result.status == PlanStatus::kPlanned);
    PP_CHECK(runtime.Retain(plan));

    InvalidationNotice notice;
    notice.links = {fabric.ab};
    const InvalidationReport report = runtime.ApplyInvalidation(notice);
    PP_CHECK_EQ(report.conservative, false);
    PP_REQUIRE(report.affected.size() == static_cast<std::size_t>(1));
    PP_CHECK_EQ(report.affected[0], plan.id);
    PP_REQUIRE(report.marked_revalidation_required.size() == static_cast<std::size_t>(1));
    PP_CHECK_EQ(report.marked_revalidation_required[0], plan.id);
    PP_CHECK(report.retired.empty());
    const PlanCurrentnessReport after = runtime.CheckCurrentness(plan);
    PP_CHECK_EQ(after.currentness, Currentness::kRevalidationRequired);
    PP_CHECK(HasDetail(after.changes, "the retained plan was invalidated by a targeted notice"));
    PP_CHECK(HasCode(after.changes, DiagnosticCode::kStaleEvidence));
  }

  {  // A node notice is also precise: an unrelated node leaves the plan alone.
    PlannerRuntime runtime(ConfigFor(fabric));
    const PlanningRequest request = MakeAToBRequest(fabric, 1);
    PlanningResult result;
    const PathPlan plan = PlanOnce(runtime, request, result);
    PP_REQUIRE(result.status == PlanStatus::kPlanned);
    PP_CHECK(runtime.Retain(plan));
    InvalidationNotice unrelated;
    unrelated.nodes = {fabric.c};
    PP_CHECK(runtime.ApplyInvalidation(unrelated).affected.empty());
    InvalidationNotice traversed;
    traversed.nodes = {fabric.a};
    const InvalidationReport report = runtime.ApplyInvalidation(traversed);
    PP_REQUIRE(report.affected.size() == static_cast<std::size_t>(1));
    PP_CHECK_EQ(report.affected[0], plan.id);
  }

  {  // Conservative notices touch every retained plan by construction.
    PlannerRuntime runtime(ConfigFor(fabric));
    PlanningResult result;
    const PathPlan plan = PlanOnce(runtime, MakeAToBRequest(fabric, 1), result);
    PP_REQUIRE(result.status == PlanStatus::kPlanned);
    PP_CHECK(runtime.Retain(plan));
    InvalidationNotice conservative;
    conservative.conservative_all = true;
    const InvalidationReport report = runtime.ApplyInvalidation(conservative);
    PP_CHECK_EQ(report.conservative, true);
    PP_REQUIRE(report.affected.size() == static_cast<std::size_t>(1));
    PP_CHECK_EQ(report.affected[0], plan.id);
    PP_CHECK_EQ(report.marked_revalidation_required.size(), static_cast<std::size_t>(1));

    InvalidationNotice capability_notice;
    capability_notice.capabilities = {TestId<CapabilityId>("core.capability")};
    const InvalidationReport capability_report = runtime.ApplyInvalidation(capability_notice);
    PP_CHECK_EQ(capability_report.conservative, true);
    PP_CHECK_EQ(capability_report.affected.size(), static_cast<std::size_t>(1));
    InvalidationNotice domain_notice;
    domain_notice.failure_domains = {TestId<FailureDomainId>("core.domain")};
    const InvalidationReport domain_report = runtime.ApplyInvalidation(domain_notice);
    PP_CHECK_EQ(domain_report.conservative, true);
    PP_CHECK_EQ(domain_report.affected.size(), static_cast<std::size_t>(1));
    PP_CHECK_EQ(runtime.Stats().invalidations_applied, 3ull);
  }
}

PP_TEST(core, currentness_retires_a_plan_whose_link_disappears) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  PlannerRuntime runtime(ConfigFor(fabric));
  const PlanningRequest request = MakeAToBRequest(fabric, 1);
  PlanningResult result;
  const PathPlan plan = PlanOnce(runtime, request, result);
  PP_REQUIRE(result.status == PlanStatus::kPlanned);
  PP_REQUIRE(result.candidates.size() == static_cast<std::size_t>(1));
  PP_CHECK_EQ(result.candidates[0].path.hops[0].link, fabric.ab);
  PP_CHECK(runtime.Retain(plan));
  PP_CHECK_EQ(runtime.CheckCurrentness(plan).currentness, Currentness::kCurrent);

  FabricOptions removed;
  removed.include_ab = false;
  const Fabric next = MakeFabric(removed);
  PP_CHECK(next.snapshot->FindEdge(fabric.ab) == nullptr);
  runtime.PublishSnapshot(next.snapshot);

  const PlanCurrentnessReport report = runtime.CheckCurrentness(plan);
  PP_CHECK_EQ(report.currentness, Currentness::kRetired);
  PP_CHECK(HasCode(report.changes, DiagnosticCode::kPlanRetired));
  PP_CHECK(HasDetail(report.changes,
                     "dependency no longer exists: " + SubjectKey::ForLink(fabric.ab).ToString()));
  PP_CHECK_EQ(report.current(), false);
  PP_CHECK_EQ(MoreSevere(Currentness::kCurrent, report.currentness), Currentness::kRetired);
}

PP_TEST(core, advance_epoch_requires_a_strictly_greater_epoch) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  PlannerRuntime runtime(ConfigFor(fabric));
  const PlanningRequest request = MakeAToCRequest(fabric, 1);
  PlanningResult result;
  const PathPlan plan = PlanOnce(runtime, request, result);
  PP_REQUIRE(result.status == PlanStatus::kPlanned);
  PP_CHECK(runtime.Retain(plan));
  PP_CHECK_EQ(runtime.CurrentEpoch().Value(), 1ull);

  std::string reason;
  PP_CHECK(!runtime.AdvanceEpoch(FabricEpoch(1), true, reason));
  PP_CHECK_EQ(reason, std::string("epoch 1 is not greater than the current epoch 1"));
  PP_CHECK_EQ(runtime.CurrentEpoch().Value(), 1ull);
  PP_CHECK_EQ(runtime.Stats().epochs_advanced, 0ull);
  reason.clear();
  PP_CHECK(!runtime.AdvanceEpoch(FabricEpoch(0), true, reason));
  PP_CHECK_EQ(reason, std::string("epoch 0 is not greater than the current epoch 1"));
  PP_CHECK_EQ(runtime.CurrentEpoch().Value(), 1ull);

  reason.clear();
  PP_CHECK(runtime.AdvanceEpoch(FabricEpoch(2), true, reason));
  PP_CHECK_EQ(reason, std::string("epoch advanced to 2 with conservative recovery: every retained plan "
                                  "requires revalidation"));
  PP_CHECK_EQ(runtime.CurrentEpoch().Value(), 2ull);
  PP_CHECK_EQ(runtime.PublishSequence().Value(), 1ull);
  PP_CHECK_EQ(runtime.Stats().epochs_advanced, 1ull);
  const PlanCurrentnessReport report = runtime.CheckCurrentness(plan);
  PP_CHECK_EQ(report.currentness, Currentness::kRevalidationRequired);
  PP_CHECK(HasDetail(report.changes, "the retained plan was invalidated by a targeted notice"));
  PP_CHECK_EQ(runtime.CurrentSnapshot()->Id(), fabric.snapshot->Id());

  // Without conservative recovery a greater epoch is still accepted, and retained
  // plans are not downgraded by the hand-off itself.
  PlannerRuntime relaxed(ConfigFor(fabric));
  PlanningResult relaxed_result;
  const PathPlan relaxed_plan = PlanOnce(relaxed, request, relaxed_result);
  PP_REQUIRE(relaxed_result.status == PlanStatus::kPlanned);
  PP_CHECK(relaxed.Retain(relaxed_plan));
  std::string relaxed_reason;
  PP_CHECK(relaxed.AdvanceEpoch(FabricEpoch(3), false, relaxed_reason));
  PP_CHECK_EQ(relaxed_reason, std::string("epoch advanced to 3"));
  PP_CHECK_EQ(relaxed.CurrentEpoch().Value(), 3ull);
  const PlanCurrentnessReport relaxed_report = relaxed.CheckCurrentness(relaxed_plan);
  PP_CHECK_MSG(!HasDetail(relaxed_report.changes, "the retained plan was invalidated by a targeted notice"),
               DescribeChanges(relaxed_report.changes));
  PP_CHECK_EQ(relaxed_report.changes[0].code, DiagnosticCode::kInvalidationWatermarkChanged);
  PP_CHECK_EQ(relaxed_report.currentness, Currentness::kRevalidationRequired);
}

PP_TEST(core, replan_reports_unchanged_and_candidate_set_changes) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  PlannerRuntime runtime(ConfigFor(fabric));
  const PlanningRequest request = MakeAToBRequest(fabric, 2);
  PlanningResult result;
  const PathPlan plan = PlanOnce(runtime, request, result);
  PP_REQUIRE(result.status == PlanStatus::kPlanned);
  PP_REQUIRE(result.candidates.size() == static_cast<std::size_t>(2));

  PlanningResult repeated_result;
  ReplanReport unchanged;
  PP_CHECK(runtime.Replan(plan, request, repeated_result, unchanged));
  PP_CHECK_EQ(unchanged.outcome, ReplanOutcome::kUnchanged);
  PP_CHECK_EQ(unchanged.same_semantic_plan, true);
  PP_CHECK_EQ(unchanged.prior_digest, plan.semantic_digest);
  PP_CHECK_EQ(unchanged.current_digest, repeated_result.semantic_digest);
  PP_CHECK(unchanged.changes.empty());
  PP_CHECK_EQ(repeated_result.status, PlanStatus::kPlanned);
  PP_REQUIRE(repeated_result.candidates.size() == static_cast<std::size_t>(2));
  PP_CHECK_EQ(repeated_result.candidates[0].id, result.candidates[0].id);
  PP_CHECK_EQ(repeated_result.candidates[1].id, result.candidates[1].id);

  // The traversed link goes DOWN: the candidate set is no longer the same.
  FabricOptions down;
  down.ab_state = LinkState::kDown;
  down.generations.link_state = LinkStateGeneration(2);
  const Fabric next = MakeFabric(down);
  runtime.PublishSnapshot(next.snapshot);

  PlanningResult down_result;
  ReplanReport changed;
  PP_CHECK(runtime.Replan(plan, request, down_result, changed));
  PP_CHECK_EQ(changed.outcome, ReplanOutcome::kCandidateSetChanged);
  PP_CHECK_EQ(changed.same_semantic_plan, false);
  PP_CHECK_EQ(changed.prior_digest, plan.semantic_digest);
  PP_CHECK_EQ(changed.current_digest, down_result.semantic_digest);
  PP_CHECK(changed.prior_digest != changed.current_digest);
  PP_CHECK_EQ(down_result.status, PlanStatus::kPlanned);
  PP_REQUIRE(down_result.candidates.size() == static_cast<std::size_t>(1));
  PP_CHECK_EQ(down_result.candidates[0].path.hops[0].link, fabric.ab2);
  PP_CHECK_EQ(down_result.candidates[0].path.hops[0].link_state, LinkState::kUp);
  PP_CHECK(HasDetail(changed.changes, "link-state generation changed: 1 -> 2"));
  PP_CHECK(HasCode(changed.changes, DiagnosticCode::kStaleEvidence));

  // Replanning a request that can no longer be satisfied reports NO_PATH.
  FabricOptions cut;
  cut.include_bc = false;
  cut.include_ab2 = false;
  const Fabric severed = MakeFabric(cut);
  PlannerRuntime no_path_runtime(ConfigFor(severed));
  PlanningResult first_result;
  const PathPlan first_plan = PlanOnce(no_path_runtime, MakeAToCRequest(severed, 1), first_result);
  PP_CHECK_EQ(first_result.status, PlanStatus::kNoPath);
  PlanningResult empty_result;
  ReplanReport no_path_report;
  PP_CHECK(no_path_runtime.Replan(first_plan, MakeAToCRequest(severed, 1), empty_result, no_path_report));
  PP_CHECK_EQ(no_path_report.outcome, ReplanOutcome::kNoPath);
  PP_CHECK(empty_result.candidates.empty());
}

// ===========================================================================
// 9. Persistence.
// ===========================================================================

PP_TEST(core, store_record_roundtrip_and_encoding_stability) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  PlanningResult plan_result;
  PathPlan plan;
  const StoredPlanRecord record = MakeStoreRecord(fabric, plan_result, plan);
  PP_REQUIRE(plan_result.status == PlanStatus::kPlanned);
  PP_REQUIRE(plan.candidates.size() == static_cast<std::size_t>(2));

  // PathPlan -> StoredPlanRecord.
  PP_CHECK_EQ(record.request, plan.request);
  PP_CHECK_EQ(record.plan, plan.id);
  PP_CHECK_EQ(record.generation, plan.generation);
  PP_CHECK_EQ(record.publish_sequence, plan.publish_sequence);
  PP_CHECK_EQ(record.status, plan.status);
  PP_CHECK_EQ(record.evidence, plan.evidence);
  PP_CHECK_EQ(record.constraint_set, plan.constraint_set);
  PP_CHECK_EQ(record.constraint_generation, plan.constraint_generation);
  PP_CHECK_EQ(record.policy_generation, plan.policy_generation);
  PP_CHECK_EQ(record.source, plan.source);
  PP_CHECK_EQ(record.destination, plan.destination);
  PP_CHECK_EQ(record.layer, plan.layer);
  PP_CHECK_EQ(record.diagnostic_mode, plan.diagnostic_mode);
  PP_CHECK_EQ(record.semantic_digest, plan.semantic_digest);
  PP_CHECK_EQ(record.candidates.size(), plan.candidates.size());
  PP_CHECK_EQ(record.costs.size(), plan.candidates.size());
  PP_CHECK_EQ(record.ranks.size(), plan.candidates.size());
  for (std::size_t index = 0; index < plan.candidates.size(); ++index) {
    PP_CHECK(SamePath(record.candidates[index], plan.candidates[index].path));
    PP_CHECK(record.costs[index] == plan.candidates[index].cost);
    PP_CHECK_EQ(record.ranks[index], plan.candidates[index].rank);
  }

  // StoredPlanRecord -> PathPlan.
  const PathPlan recovered = FromStoredRecord(record);
  PP_CHECK_EQ(recovered.id, plan.id);
  PP_CHECK_EQ(recovered.request, plan.request);
  PP_CHECK_EQ(recovered.generation, plan.generation);
  PP_CHECK_EQ(recovered.publish_sequence, plan.publish_sequence);
  PP_CHECK_EQ(recovered.status, plan.status);
  PP_CHECK_EQ(recovered.evidence, plan.evidence);
  PP_CHECK_EQ(recovered.policy_generation, plan.policy_generation);
  PP_CHECK_EQ(recovered.constraint_set, plan.constraint_set);
  PP_CHECK_EQ(recovered.constraint_generation, plan.constraint_generation);
  PP_CHECK_EQ(recovered.source, plan.source);
  PP_CHECK_EQ(recovered.destination, plan.destination);
  PP_CHECK_EQ(recovered.layer, plan.layer);
  PP_CHECK_EQ(recovered.diagnostic_mode, plan.diagnostic_mode);
  PP_CHECK_EQ(recovered.semantic_digest, plan.semantic_digest);
  PP_CHECK_EQ(recovered.currentness_proven, false);
  PP_CHECK_EQ(recovered.candidates.size(), plan.candidates.size());
  for (std::size_t index = 0; index < plan.candidates.size(); ++index) {
    PP_CHECK(SamePath(recovered.candidates[index].path, plan.candidates[index].path));
    PP_CHECK_EQ(recovered.candidates[index].id, plan.candidates[index].id);
    PP_CHECK_EQ(recovered.candidates[index].id, recovered.candidates[index].path.Id());
    PP_CHECK(recovered.candidates[index].cost == plan.candidates[index].cost);
    PP_CHECK_EQ(recovered.candidates[index].rank, plan.candidates[index].rank);
    PP_CHECK_EQ(recovered.candidates[index].currentness, Currentness::kRevalidationRequired);
    PP_CHECK_EQ(recovered.candidates[index].authority, AuthorityValidation::kNotRequested);
  }
  PP_CHECK_EQ(recovered.ComputeSemanticDigest(), plan.semantic_digest);
  PP_CHECK_EQ(recovered.ComputePlanId(), plan.id);
  PP_CHECK_EQ(recovered.ComputeSemanticDigest(), record.semantic_digest);

  // Encoding is byte-identical for identical input.
  const ResourceLimits limits;
  StoreOptions options;
  options.publish_sequence = PlanPublishSequence(7);
  const std::vector<StoredPlanRecord> records{record};
  const std::vector<std::byte> first_image = EncodeStoreImage(records, options);
  const std::vector<std::byte> second_image = EncodeStoreImage(records, options);
  PP_CHECK(first_image == second_image);
  PP_CHECK(first_image.size() > kStoreHeaderBytes + kStoreDigestBytes);

  // Header layout is fixed and explicit.
  ByteReader header(std::span<const std::byte>(first_image.data(), kStoreHeaderBytes));
  std::array<std::byte, 8> magic{};
  PP_CHECK(header.FixedBytes(std::span<std::byte>(magic.data(), magic.size())));
  PP_CHECK_EQ(std::string_view(reinterpret_cast<const char*>(magic.data()), magic.size()), kStoreMagic);
  const std::optional<std::uint32_t> format_version = header.U32();
  const std::optional<std::uint32_t> rule_version = header.U32();
  const std::optional<std::uint32_t> encoding_version = header.U32();
  const std::optional<std::uint64_t> record_count = header.U64();
  const std::optional<std::uint64_t> payload_length = header.U64();
  PP_REQUIRE(format_version.has_value());
  PP_REQUIRE(rule_version.has_value());
  PP_REQUIRE(encoding_version.has_value());
  PP_REQUIRE(record_count.has_value());
  PP_REQUIRE(payload_length.has_value());
  PP_CHECK_EQ(*format_version, kPersistedFormatVersion);
  PP_CHECK_EQ(*rule_version, kPlanningRuleVersion);
  PP_CHECK_EQ(*encoding_version, kPathEncodingVersion);
  PP_CHECK_EQ(*record_count, 1ull);
  PP_CHECK_EQ(*payload_length, first_image.size() - kStoreHeaderBytes - kStoreDigestBytes);
  PP_CHECK(header.AtEnd());

  // Decoding returns the same record.
  std::vector<StoredPlanRecord> decoded;
  const StoreResult decode = DecodePlanStore(SpanOf(first_image), limits, decoded);
  PP_CHECK_MSG(decode.ok, decode.detail);
  PP_REQUIRE(decoded.size() == static_cast<std::size_t>(1));
  PP_CHECK_EQ(decoded[0].plan, record.plan);
  PP_CHECK_EQ(decoded[0].request, record.request);
  PP_CHECK_EQ(decoded[0].status, record.status);
  PP_CHECK_EQ(decoded[0].evidence, record.evidence);
  PP_CHECK_EQ(decoded[0].semantic_digest, record.semantic_digest);
  PP_CHECK_EQ(decoded[0].candidates.size(), record.candidates.size());
  PP_CHECK_EQ(decoded[0].costs.size(), record.costs.size());
  for (std::size_t index = 0; index < record.candidates.size(); ++index) {
    PP_CHECK(SameEncodedPath(decoded[0].candidates[index], record.candidates[index]));
    PP_CHECK(decoded[0].costs[index] == record.costs[index]);
    PP_CHECK_EQ(decoded[0].ranks[index], record.ranks[index]);
  }
}

PP_TEST(core, store_decode_rejections) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  PlanningResult plan_result;
  PathPlan plan;
  const StoredPlanRecord record = MakeStoreRecord(fabric, plan_result, plan);
  const ResourceLimits limits;
  StoreOptions options;
  options.publish_sequence = PlanPublishSequence(7);
  const std::vector<std::byte> image = EncodeStoreImage({record}, options);

  {  // Positive control: the untampered image decodes.
    std::vector<StoredPlanRecord> decoded;
    const StoreResult result = DecodePlanStore(SpanOf(image), limits, decoded);
    PP_CHECK_MSG(result.ok, result.detail);
    PP_REQUIRE(decoded.size() == static_cast<std::size_t>(1));
    PP_CHECK_EQ(decoded[0].plan, record.plan);
  }
  {  // Empty image.
    std::vector<StoredPlanRecord> out;
    const StoreResult result = DecodePlanStore(std::span<const std::byte>(), limits, out);
    PP_CHECK(!result.ok);
    PP_CHECK_EQ(result.code, DiagnosticCode::kPersistenceCorrupt);
    PP_CHECK(!result.detail.empty());
    PP_CHECK(out.empty());
  }
  {  // Bad magic.
    std::vector<std::byte> corrupted = image;
    corrupted[0] ^= std::byte{0x01};
    std::vector<StoredPlanRecord> out;
    const StoreResult result = DecodePlanStore(SpanOf(corrupted), limits, out);
    PP_CHECK(!result.ok);
    PP_CHECK_EQ(result.code, DiagnosticCode::kPersistenceCorrupt);
    PP_CHECK_EQ(result.detail, std::string("store magic mismatch"));
  }
  {  // Unsupported persisted format version.
    std::vector<std::byte> corrupted = image;
    corrupted[8] = std::byte{0x02};
    std::vector<StoredPlanRecord> out;
    const StoreResult result = DecodePlanStore(SpanOf(corrupted), limits, out);
    PP_CHECK(!result.ok);
    PP_CHECK_EQ(result.code, DiagnosticCode::kPersistenceVersionUnsupported);
  }
  {  // Every truncation length is rejected.
    for (std::size_t length = 0; length < image.size(); ++length) {
      std::vector<StoredPlanRecord> out;
      const StoreResult result = DecodePlanStore(std::span<const std::byte>(image.data(), length), limits, out);
      PP_CHECK_MSG(!result.ok, "store image truncated to " + std::to_string(length) + " bytes decoded as valid");
      PP_CHECK(out.empty());
    }
  }
  {  // A single flipped bit anywhere in the payload is an integrity failure.
    for (std::size_t offset = kStoreHeaderBytes + kStoreDigestBytes; offset < image.size(); ++offset) {
      for (unsigned int bit = 0; bit < 8u; ++bit) {
        std::vector<std::byte> corrupted = image;
        corrupted[offset] ^= static_cast<std::byte>(1u << bit);
        std::vector<StoredPlanRecord> out;
        const StoreResult result = DecodePlanStore(SpanOf(corrupted), limits, out);
        PP_CHECK_MSG(!result.ok, "flipped payload bit " + std::to_string(bit) + " at offset " +
                                     std::to_string(offset) + " decoded as valid");
        PP_CHECK_EQ(result.code, DiagnosticCode::kPersistenceDigestMismatch);
      }
    }
  }
  {  // A single flipped bit in the digest is an integrity failure.
    for (std::size_t offset = kStoreHeaderBytes; offset < kStoreHeaderBytes + kStoreDigestBytes; ++offset) {
      std::vector<std::byte> corrupted = image;
      corrupted[offset] ^= std::byte{0x80};
      std::vector<StoredPlanRecord> out;
      const StoreResult result = DecodePlanStore(SpanOf(corrupted), limits, out);
      PP_CHECK_MSG(!result.ok, "flipped digest byte at offset " + std::to_string(offset) + " decoded as valid");
      PP_CHECK_EQ(result.code, DiagnosticCode::kPersistenceDigestMismatch);
    }
  }
  {  // Duplicate plan identity.
    const std::vector<std::byte> duplicated = EncodeStoreImage({record, record}, options);
    std::vector<StoredPlanRecord> out;
    const StoreResult result = DecodePlanStore(SpanOf(duplicated), limits, out);
    PP_CHECK(!result.ok);
    PP_CHECK_EQ(result.code, DiagnosticCode::kPersistenceDuplicatePlan);
    PP_CHECK_EQ(result.detail, std::string("duplicate plan identity in the store"));
  }
  {  // A tampered candidate path whose recomputed semantic digest no longer matches.
    StoredPlanRecord tampered = record;
    PP_REQUIRE(!tampered.candidates.empty());
    PP_REQUIRE(!tampered.candidates[0].hops.empty());
    const std::uint32_t original = tampered.candidates[0].hops[0].static_cost.Value();
    tampered.candidates[0].hops[0].static_cost = StaticCost(original + 1);
    const std::vector<std::byte> tampered_image = EncodeStoreImage({tampered}, options);
    PP_CHECK(tampered_image != image);
    std::vector<StoredPlanRecord> out;
    const StoreResult result = DecodePlanStore(SpanOf(tampered_image), limits, out);
    PP_CHECK(!result.ok);
    PP_CHECK_EQ(result.code, DiagnosticCode::kPersistenceDigestMismatch);
    PP_CHECK_EQ(result.detail, std::string("record semantic digest does not match its content"));
    PP_CHECK(out.empty());
  }
  {  // Trailing bytes.
    std::vector<std::byte> extended = image;
    extended.push_back(std::byte{0x00});
    std::vector<StoredPlanRecord> out;
    const StoreResult result = DecodePlanStore(SpanOf(extended), limits, out);
    PP_CHECK(!result.ok);
    PP_CHECK_EQ(result.code, DiagnosticCode::kPersistenceTrailingBytes);
    PP_CHECK_EQ(result.detail, std::string("store image carries trailing bytes"));
  }
  {  // A record with a nil identity is refused by the encoder.
    StoredPlanRecord nil = record;
    nil.plan = PathPlanId{};
    std::vector<std::byte> out_image;
    const StoreResult encode = EncodePlanStore({nil}, options, out_image);
    PP_CHECK(!encode.ok);
    PP_CHECK_EQ(encode.code, DiagnosticCode::kMalformedIdentifier);
    PP_CHECK(out_image.empty());
  }
  {  // Candidate and cost counts must agree.
    StoredPlanRecord mismatched = record;
    mismatched.costs.pop_back();
    std::vector<std::byte> out_image;
    const StoreResult encode = EncodePlanStore({mismatched}, options, out_image);
    PP_CHECK(!encode.ok);
    PP_CHECK_EQ(encode.code, DiagnosticCode::kPersistenceCorrupt);
  }
}

PP_TEST(core, store_file_roundtrip_and_missing_file) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  PlanningResult plan_result;
  PathPlan plan;
  const StoredPlanRecord record = MakeStoreRecord(fabric, plan_result, plan);
  const ResourceLimits limits;
  StoreOptions options;
  options.publish_sequence = PlanPublishSequence(3);
  const std::vector<StoredPlanRecord> records{record};

  const std::filesystem::path path = ScratchStorePath("core.store_file_roundtrip_and_missing_file");
  const std::filesystem::path missing = ScratchStorePath("core.store_file_roundtrip_and_missing_file/missing");
  PP_CHECK(path != missing);
  std::error_code error;
  std::filesystem::remove(path, error);
  std::filesystem::remove(missing, error);
  PP_CHECK(!std::filesystem::exists(missing));

  const StoreResult saved = SavePlanStore(path.string(), records, options);
  PP_CHECK_MSG(saved.ok, saved.detail);
  PP_CHECK(std::filesystem::exists(path));
  std::vector<StoredPlanRecord> loaded;
  const StoreResult load = LoadPlanStore(path.string(), limits, loaded);
  PP_CHECK_MSG(load.ok, load.detail);
  PP_REQUIRE(loaded.size() == static_cast<std::size_t>(1));
  PP_CHECK_EQ(loaded[0].plan, record.plan);
  PP_CHECK_EQ(loaded[0].request, record.request);
  PP_CHECK_EQ(loaded[0].status, record.status);
  PP_CHECK_EQ(loaded[0].evidence, record.evidence);
  PP_CHECK_EQ(loaded[0].semantic_digest, record.semantic_digest);
  PP_CHECK_EQ(loaded[0].candidates.size(), record.candidates.size());
  for (std::size_t index = 0; index < record.candidates.size(); ++index) {
    PP_CHECK(SameEncodedPath(loaded[0].candidates[index], record.candidates[index]));
    PP_CHECK(loaded[0].costs[index] == record.costs[index]);
  }
  // A file that is not there fails cleanly.
  std::vector<StoredPlanRecord> missing_out;
  const StoreResult absent = LoadPlanStore(missing.string(), limits, missing_out);
  PP_CHECK(!absent.ok);
  PP_CHECK_EQ(absent.code, DiagnosticCode::kPersistenceCorrupt);
  PP_CHECK_EQ(absent.detail, std::string("store file not found or not readable"));
  PP_CHECK(missing_out.empty());
  // An empty path is refused without touching the filesystem.
  std::vector<StoredPlanRecord> empty_out;
  std::vector<std::byte> empty_image;
  PP_CHECK(!LoadPlanStore(std::string(), limits, empty_out).ok);
  PP_CHECK(!SavePlanStore(std::string(), records, options).ok);
  PP_CHECK(empty_out.empty());
  // An empty record set has a valid, decodable image.
  const StoreResult empty_encode = EncodePlanStore({}, StoreOptions{}, empty_image);
  PP_CHECK_MSG(empty_encode.ok, empty_encode.detail);
  PP_CHECK(!empty_image.empty());
  std::vector<StoredPlanRecord> empty_records;
  const StoreResult empty_decode = DecodePlanStore(SpanOf(empty_image), limits, empty_records);
  PP_CHECK_MSG(empty_decode.ok, empty_decode.detail);
  PP_CHECK(empty_records.empty());

  // Scratch artifacts are removed again.
  std::filesystem::remove(path, error);
  std::filesystem::remove(path.string() + ".tmp", error);
  PP_CHECK(!std::filesystem::exists(path));
  PP_CHECK(!std::filesystem::exists(missing));
}
// ===========================================================================
// 10. Wire protocol.
// ===========================================================================

namespace {

// A request that exercises every field the wire codec carries.
PlanningRequest MakeRichRequest(const Fabric& fabric) {
  PlanningRequest request = MakeAToCRequest(fabric, 3);
  request.constraints.generation = ConstraintGeneration(9);
  request.constraints.forbidden_nodes = {fabric.a, fabric.b};
  request.constraints.forbidden_links = {fabric.bc};
  request.constraints.forbidden_ports = {fabric.a2};
  request.constraints.forbidden_failure_domains = {TestId<FailureDomainId>("core.domain.1")};
  request.constraints.forbidden_failure_domain_classes = {TestId<FailureDomainClass>("core.domain.class")};
  TransitStage exact_stage;
  exact_stage.kind = TransitKind::kExact;
  exact_stage.alternatives = {fabric.b};
  TransitStage any_stage;
  any_stage.kind = TransitKind::kAnyOf;
  any_stage.alternatives = {fabric.b, fabric.c};
  request.constraints.required_transit = {exact_stage, any_stage};
  CapabilityRequirement requirement;
  requirement.capability = TestId<CapabilityId>("core.capability");
  requirement.scope = CapabilityScope::kEveryLink;
  requirement.comparator = CapabilityComparator::kAtLeast;
  requirement.value = CapabilityValue(7);
  request.constraints.required_capabilities = {requirement};
  request.constraints.max_hops = HopCount(9);
  request.constraints.max_members_per_failure_domain = 4;
  request.constraints.fail_closed_on_unknown_domains = false;
  request.policy.generation = PolicyGeneration(5);
  request.policy.cost_model.hop_cost = CostValue(3);
  request.policy.cost_model.degraded_penalty = CostValue(5);
  request.policy.cost_model.locality_penalty = CostValue(0);
  request.policy.locality_scope = {fabric.a, fabric.b};
  request.policy.allow_degraded_links = true;
  request.policy.allow_draining_ports = true;
  request.policy.allow_maintenance_ports = false;
  request.policy.require_operational_proof = true;
  request.policy.allow_zero_hop_self_path = false;
  request.policy.authority_validation = AuthorityValidationMode::kBestEffort;
  request.max_candidates = 3;
  request.mode = PlanningMode::kDiagnosticNonCurrent;
  request.authority.scope_mask = CombineScopes(AuthorityScope::kSubmitPlanRequest, AuthorityScope::kReadPlan);
  request.authority.publisher = TestId<PublisherId>("core.publisher");
  request.authority.worker_boot = TestId<WorkerBootId>("core.worker");
  request.authority.coordinator_epoch = CoordinatorEpoch(11);
  request.authority.attempt = TestId<MutationAttemptId>("core.attempt");
  request.authority.epoch_bound = true;
  request.authority.enforce_scope = true;
  request.expect_epoch = true;
  request.expected_epoch = FabricEpoch(3);
  request.expect_topology = true;
  request.expected_topology = TopologyGeneration(2);
  request.expect_snapshot = true;
  request.expected_snapshot = fabric.snapshot->Id();
  return request;
}

void CheckSameRequest(const PlanningRequest& decoded, const PlanningRequest& expected) {
  PP_CHECK_EQ(decoded.id, expected.id);
  PP_CHECK_EQ(decoded.source.id, expected.source.id);
  PP_CHECK_EQ(decoded.source.endpoint_class, expected.source.endpoint_class);
  PP_CHECK_EQ(decoded.source.generation, expected.source.generation);
  PP_CHECK_EQ(decoded.destination.id, expected.destination.id);
  PP_CHECK_EQ(decoded.destination.endpoint_class, expected.destination.endpoint_class);
  PP_CHECK_EQ(decoded.destination.generation, expected.destination.generation);
  PP_CHECK_EQ(decoded.constraints.id, expected.constraints.id);
  PP_CHECK_EQ(decoded.constraints.generation, expected.constraints.generation);
  PP_CHECK_EQ(decoded.constraints.layer, expected.constraints.layer);
  PP_CHECK(decoded.constraints.forbidden_nodes == expected.constraints.forbidden_nodes);
  PP_CHECK(decoded.constraints.forbidden_links == expected.constraints.forbidden_links);
  PP_CHECK(decoded.constraints.forbidden_ports == expected.constraints.forbidden_ports);
  PP_CHECK(decoded.constraints.forbidden_failure_domains == expected.constraints.forbidden_failure_domains);
  PP_CHECK(decoded.constraints.forbidden_failure_domain_classes ==
           expected.constraints.forbidden_failure_domain_classes);
  PP_CHECK_EQ(decoded.constraints.required_transit.size(), expected.constraints.required_transit.size());
  for (std::size_t index = 0; index < expected.constraints.required_transit.size(); ++index) {
    PP_CHECK_EQ(decoded.constraints.required_transit[index].kind,
                expected.constraints.required_transit[index].kind);
    PP_CHECK(decoded.constraints.required_transit[index].alternatives ==
             expected.constraints.required_transit[index].alternatives);
  }
  PP_CHECK_EQ(decoded.constraints.required_capabilities.size(),
              expected.constraints.required_capabilities.size());
  for (std::size_t index = 0; index < expected.constraints.required_capabilities.size(); ++index) {
    PP_CHECK_EQ(decoded.constraints.required_capabilities[index].capability,
                expected.constraints.required_capabilities[index].capability);
    PP_CHECK_EQ(decoded.constraints.required_capabilities[index].scope,
                expected.constraints.required_capabilities[index].scope);
    PP_CHECK_EQ(decoded.constraints.required_capabilities[index].comparator,
                expected.constraints.required_capabilities[index].comparator);
    PP_CHECK_EQ(decoded.constraints.required_capabilities[index].value,
                expected.constraints.required_capabilities[index].value);
  }
  PP_CHECK_EQ(decoded.constraints.max_hops.has_value(), expected.constraints.max_hops.has_value());
  if (expected.constraints.max_hops.has_value()) {
    PP_CHECK_EQ(*decoded.constraints.max_hops, *expected.constraints.max_hops);
  }
  PP_CHECK_EQ(decoded.constraints.max_members_per_failure_domain.has_value(),
              expected.constraints.max_members_per_failure_domain.has_value());
  if (expected.constraints.max_members_per_failure_domain.has_value()) {
    PP_CHECK_EQ(*decoded.constraints.max_members_per_failure_domain,
                *expected.constraints.max_members_per_failure_domain);
  }
  PP_CHECK_EQ(decoded.constraints.fail_closed_on_unknown_domains,
              expected.constraints.fail_closed_on_unknown_domains);
  PP_CHECK_EQ(decoded.policy.generation, expected.policy.generation);
  PP_CHECK_EQ(decoded.policy.cost_model.hop_cost, expected.policy.cost_model.hop_cost);
  PP_CHECK_EQ(decoded.policy.cost_model.degraded_penalty, expected.policy.cost_model.degraded_penalty);
  PP_CHECK_EQ(decoded.policy.cost_model.locality_penalty, expected.policy.cost_model.locality_penalty);
  PP_CHECK_EQ(decoded.policy.allow_degraded_links, expected.policy.allow_degraded_links);
  PP_CHECK_EQ(decoded.policy.allow_draining_ports, expected.policy.allow_draining_ports);
  PP_CHECK_EQ(decoded.policy.allow_maintenance_ports, expected.policy.allow_maintenance_ports);
  PP_CHECK_EQ(decoded.policy.require_operational_proof, expected.policy.require_operational_proof);
  PP_CHECK_EQ(decoded.policy.allow_zero_hop_self_path, expected.policy.allow_zero_hop_self_path);
  PP_CHECK(decoded.policy.locality_scope == expected.policy.locality_scope);
  PP_CHECK_EQ(decoded.policy.authority_validation, expected.policy.authority_validation);
  PP_CHECK_EQ(decoded.max_candidates, expected.max_candidates);
  PP_CHECK_EQ(decoded.mode, expected.mode);
  PP_CHECK_EQ(decoded.authority.scope_mask, expected.authority.scope_mask);
  PP_CHECK_EQ(decoded.authority.publisher, expected.authority.publisher);
  PP_CHECK_EQ(decoded.authority.worker_boot, expected.authority.worker_boot);
  PP_CHECK_EQ(decoded.authority.coordinator_epoch, expected.authority.coordinator_epoch);
  PP_CHECK_EQ(decoded.authority.attempt, expected.authority.attempt);
  PP_CHECK_EQ(decoded.authority.epoch_bound, expected.authority.epoch_bound);
  PP_CHECK_EQ(decoded.authority.enforce_scope, expected.authority.enforce_scope);
  PP_CHECK_EQ(decoded.expect_epoch, expected.expect_epoch);
  PP_CHECK_EQ(decoded.expected_epoch, expected.expected_epoch);
  PP_CHECK_EQ(decoded.expect_topology, expected.expect_topology);
  PP_CHECK_EQ(decoded.expected_topology, expected.expected_topology);
  PP_CHECK_EQ(decoded.expect_snapshot, expected.expect_snapshot);
  PP_CHECK_EQ(decoded.expected_snapshot, expected.expected_snapshot);
}

// Equality over the fields a canonical path encoding actually carries. The
// operational hop fields (link_state, degraded) are consumed evidence, not part of
// the persisted/wire representation, so a decoded path reports them as UNKNOWN.
bool SameEncodedPath(const CandidatePath& lhs, const CandidatePath& rhs) {
  if (lhs.source != rhs.source || lhs.destination != rhs.destination || lhs.layer != rhs.layer) {
    return false;
  }
  if (lhs.nodes != rhs.nodes || lhs.hops.size() != rhs.hops.size()) {
    return false;
  }
  for (std::size_t index = 0; index < lhs.hops.size(); ++index) {
    const PathHop& left = lhs.hops[index];
    const PathHop& right = rhs.hops[index];
    if (left.link != right.link || left.from != right.from || left.to != right.to ||
        left.from_port != right.from_port || left.to_port != right.to_port || left.layer != right.layer ||
        left.relationship != right.relationship ||
        left.structural_generation != right.structural_generation || left.static_cost != right.static_cost) {
      return false;
    }
  }
  return true;
}

void CheckSameCandidate(const Candidate& decoded, const Candidate& expected) {
  PP_CHECK_EQ(decoded.id, expected.id);
  PP_CHECK(SameEncodedPath(decoded.path, expected.path));
  PP_CHECK(decoded.cost == expected.cost);
  PP_CHECK_EQ(decoded.rank, expected.rank);
  PP_CHECK_EQ(decoded.currentness, expected.currentness);
  PP_CHECK_EQ(decoded.authority, expected.authority);
  PP_CHECK(decoded.notes == expected.notes);
  PP_CHECK_EQ(decoded.evidence, expected.evidence);
  for (const PathHop& hop : decoded.path.hops) {
    PP_CHECK_EQ(hop.link_state, LinkState::kUnknown);
    PP_CHECK_EQ(hop.degraded, false);
  }
}

}  // namespace

PP_TEST(core, proto_frame_roundtrip_and_exact_layout) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  const ResourceLimits limits;
  const PlanningRequest request = MakeRichRequest(fabric);
  ByteWriter payload_writer;
  EncodePlanningRequestPayload(payload_writer, request);
  PP_CHECK(!payload_writer.overflowed());

  WireFrame frame;
  frame.type = WireMessage::kPlanRequest;
  frame.flags = static_cast<std::uint16_t>(kWireFlagResponse | kWireFlagFenced);
  frame.coordinator_epoch = CoordinatorEpoch(7);
  frame.sequence = 42;
  frame.worker_boot = TestId<WorkerBootId>("core.worker.boot");
  frame.request = request.id;
  frame.payload = payload_writer.data();

  const std::vector<std::byte> bytes = EncodeFrame(frame);
  PP_CHECK_EQ(kWireHeaderBytes, static_cast<std::size_t>(76));
  PP_CHECK_EQ(kWireIntegrityBytes, static_cast<std::size_t>(16));
  PP_CHECK_EQ(kWirePayloadOffset, kWireHeaderBytes);
  PP_CHECK_EQ(kWireMagicValue, 0x4E4C5050u);
  PP_CHECK_EQ(bytes.size(), kWireHeaderBytes + frame.payload.size());
  PP_CHECK_EQ(bytes[0], std::byte{0x50});
  PP_CHECK_EQ(bytes[1], std::byte{0x50});
  PP_CHECK_EQ(bytes[2], std::byte{0x4C});
  PP_CHECK_EQ(bytes[3], std::byte{0x4E});
  PP_CHECK_EQ(bytes[4], std::byte{0x01});
  PP_CHECK_EQ(bytes[5], std::byte{0x00});
  PP_CHECK_EQ(bytes[6], std::byte{0x03});
  PP_CHECK_EQ(bytes[7], std::byte{0x00});
  PP_CHECK_EQ(bytes[8], std::byte{0x03});
  PP_CHECK_EQ(bytes[9], std::byte{0x00});
  PP_CHECK_EQ(bytes[10], std::byte{0x00});
  PP_CHECK_EQ(bytes[11], std::byte{0x00});
  PP_CHECK_EQ(bytes[12], std::byte{0x07});
  PP_CHECK_EQ(bytes[19], std::byte{0x00});
  PP_CHECK_EQ(bytes[20], std::byte{42});
  PP_CHECK_EQ(bytes[27], std::byte{0x00});
  for (std::size_t index = 0; index < 8; ++index) {
    PP_CHECK_EQ(bytes[28 + index], frame.worker_boot.Bytes()[index]);
  }
  for (std::size_t index = 0; index < 16; ++index) {
    PP_CHECK_EQ(bytes[36 + index], frame.request.Bytes()[index]);
  }
  PP_CHECK(frame.payload.size() > 255u);
  PP_CHECK_EQ(bytes[52], static_cast<std::byte>(frame.payload.size() & 0xFFu));
  PP_CHECK_EQ(bytes[53], static_cast<std::byte>((frame.payload.size() >> 8) & 0xFFu));
  PP_CHECK_EQ(bytes[54], static_cast<std::byte>((frame.payload.size() >> 16) & 0xFFu));
  PP_CHECK_EQ(bytes[55], static_cast<std::byte>((frame.payload.size() >> 24) & 0xFFu));
  PP_CHECK_EQ(bytes[56], std::byte{0x00});
  PP_CHECK_EQ(bytes[57], std::byte{0x00});
  PP_CHECK_EQ(bytes[58], std::byte{0x00});
  PP_CHECK_EQ(bytes[59], std::byte{0x00});
  for (std::size_t index = 0; index < frame.payload.size(); ++index) {
    PP_CHECK_EQ(bytes[kWirePayloadOffset + index], frame.payload[index]);
  }

  WireFrame decoded_frame;
  std::string detail;
  PP_CHECK_EQ(DecodeFrame(SpanOf(bytes), limits.max_frame_bytes, decoded_frame, detail), WireStatus::kOk);
  PP_CHECK(detail.empty());
  PP_CHECK_EQ(decoded_frame.type, WireMessage::kPlanRequest);
  PP_CHECK_EQ(decoded_frame.flags, frame.flags);
  PP_CHECK_EQ(decoded_frame.coordinator_epoch.Value(), 7ull);
  PP_CHECK_EQ(decoded_frame.sequence, 42ull);
  PP_CHECK_EQ(decoded_frame.worker_boot, frame.worker_boot);
  PP_CHECK_EQ(decoded_frame.request, frame.request);
  PP_CHECK(decoded_frame.payload == frame.payload);
  PlanningRequest decoded_request;
  PP_CHECK_EQ(DecodePlanningRequestPayload(decoded_frame.payload, limits, decoded_request, detail),
              WireStatus::kOk);
  CheckSameRequest(decoded_request, request);

  // A result payload travels through the same framing.
  PlannerRuntime runtime(ConfigFor(fabric));
  const PlanningResult result = runtime.Plan(MakeAToCRequest(fabric, 2));
  PP_REQUIRE(result.status == PlanStatus::kPlanned);
  ByteWriter result_writer;
  EncodePlanningResultPayload(result_writer, result);
  PP_CHECK(!result_writer.overflowed());
  WireFrame result_frame;
  result_frame.type = WireMessage::kPlanResult;
  result_frame.flags = kWireFlagResponse;
  result_frame.coordinator_epoch = CoordinatorEpoch(1);
  result_frame.sequence = 7;
  result_frame.worker_boot = TestId<WorkerBootId>("core.worker.boot");
  result_frame.request = request.id;
  result_frame.payload = result_writer.data();
  const std::vector<std::byte> result_bytes = EncodeFrame(result_frame);
  WireFrame decoded_result_frame;
  PP_CHECK_EQ(DecodeFrame(SpanOf(result_bytes), limits.max_frame_bytes, decoded_result_frame, detail),
              WireStatus::kOk);
  PP_CHECK_EQ(decoded_result_frame.type, WireMessage::kPlanResult);
  PP_CHECK_EQ(decoded_result_frame.flags, kWireFlagResponse);
  PlanningResult decoded_result;
  PP_CHECK_EQ(DecodePlanningResultPayload(decoded_result_frame.payload, limits, decoded_result, detail),
              WireStatus::kOk);
  PP_CHECK_EQ(decoded_result.status, result.status);
  PP_CHECK_EQ(decoded_result.plan_id, result.plan_id);
  PP_CHECK_EQ(decoded_result.semantic_digest, result.semantic_digest);
  PP_CHECK_EQ(decoded_result.planning_generation, result.planning_generation);
  PP_CHECK_EQ(decoded_result.source_endpoint, result.source_endpoint);
  PP_CHECK_EQ(decoded_result.destination_endpoint, result.destination_endpoint);
  PP_CHECK_EQ(decoded_result.source_node, result.source_node);
  PP_CHECK_EQ(decoded_result.destination_node, result.destination_node);
  PP_CHECK_EQ(decoded_result.evidence, result.evidence);
  PP_CHECK_EQ(decoded_result.requested_candidates, result.requested_candidates);
  PP_CHECK_EQ(decoded_result.truncated, result.truncated);
  PP_CHECK_EQ(decoded_result.diagnostic_mode, result.diagnostic_mode);
  PP_CHECK_EQ(decoded_result.primary_failure.has_value(), result.primary_failure.has_value());
  PP_CHECK_EQ(decoded_result.candidates.size(), result.candidates.size());
  for (std::size_t index = 0; index < result.candidates.size(); ++index) {
    CheckSameCandidate(decoded_result.candidates[index], result.candidates[index]);
  }
  PP_CHECK_EQ(decoded_result.explanations.size(), result.explanations.size());
  PP_CHECK_EQ(decoded_result.rejections.size(), result.rejections.size());
}

PP_TEST(core, proto_frame_rejections) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  const ResourceLimits limits;
  const PlanningRequest request = MakeRichRequest(fabric);
  ByteWriter payload_writer;
  EncodePlanningRequestPayload(payload_writer, request);
  WireFrame frame;
  frame.type = WireMessage::kPlanRequest;
  frame.flags = static_cast<std::uint16_t>(kWireFlagResponse);
  frame.coordinator_epoch = CoordinatorEpoch(7);
  frame.sequence = 42;
  frame.worker_boot = TestId<WorkerBootId>("core.worker.boot");
  frame.request = request.id;
  frame.payload = payload_writer.data();
  const std::vector<std::byte> bytes = EncodeFrame(frame);

  const auto decode_with = [](const std::vector<std::byte>& patched, std::uint32_t ceiling) {
    WireFrame out;
    std::string reason;
    return DecodeFrame(SpanOf(patched), ceiling, out, reason);
  };

  {  // positive control
    WireFrame out;
    std::string reason;
    PP_CHECK_EQ(DecodeFrame(SpanOf(bytes), limits.max_frame_bytes, out, reason), WireStatus::kOk);
  }
  {  // bad magic
    std::vector<std::byte> corrupted = bytes;
    corrupted[0] ^= std::byte{0x01};
    WireFrame out;
    std::string reason;
    PP_CHECK_EQ(DecodeFrame(SpanOf(corrupted), limits.max_frame_bytes, out, reason), WireStatus::kMalformed);
    PP_CHECK_EQ(reason, std::string("frame magic mismatch"));
  }
  {  // wrong protocol version
    std::vector<std::byte> corrupted = bytes;
    corrupted[4] = std::byte{0x02};
    PP_CHECK_EQ(decode_with(corrupted, limits.max_frame_bytes), WireStatus::kVersionMismatch);
  }
  {  // unknown message type
    std::vector<std::byte> corrupted = bytes;
    corrupted[8] = std::byte{99};
    PP_CHECK_EQ(decode_with(corrupted, limits.max_frame_bytes), WireStatus::kUnknownMessage);
  }
  {  // unknown flag bits
    std::vector<std::byte> corrupted = bytes;
    corrupted[6] ^= std::byte{0x80};
    PP_CHECK_EQ(decode_with(corrupted, limits.max_frame_bytes), WireStatus::kMalformed);
  }
  {  // non-zero reserved field
    std::vector<std::byte> corrupted = bytes;
    corrupted[56] = std::byte{0x01};
    WireFrame out;
    std::string reason;
    PP_CHECK_EQ(DecodeFrame(SpanOf(corrupted), limits.max_frame_bytes, out, reason), WireStatus::kMalformed);
    PP_CHECK_EQ(reason, std::string("reserved header field must be zero"));
  }
  {  // declared payload length disagrees with the frame
    std::vector<std::byte> corrupted = bytes;
    const std::size_t declared = frame.payload.size() + 1;
    corrupted[52] = static_cast<std::byte>(declared & 0xFFu);
    corrupted[53] = static_cast<std::byte>((declared >> 8) & 0xFFu);
    corrupted[54] = static_cast<std::byte>((declared >> 16) & 0xFFu);
    corrupted[55] = static_cast<std::byte>((declared >> 24) & 0xFFu);
    PP_CHECK_EQ(decode_with(corrupted, limits.max_frame_bytes), WireStatus::kMalformed);
  }
  {  // above the configured frame ceiling
    PP_CHECK_EQ(decode_with(bytes, static_cast<std::uint32_t>(kWireHeaderBytes)), WireStatus::kTooLarge);
  }
  {  // trailing bytes after the declared payload
    std::vector<std::byte> extended = bytes;
    extended.push_back(std::byte{0x00});
    WireFrame out;
    std::string reason;
    PP_CHECK_EQ(DecodeFrame(SpanOf(extended), limits.max_frame_bytes, out, reason), WireStatus::kTrailingBytes);
    PP_CHECK_EQ(reason, std::string("frame carries trailing bytes"));
  }
  {  // every truncation is rejected as malformed
    for (std::size_t length = 0; length < bytes.size(); ++length) {
      std::vector<std::byte> truncated(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(length));
      PP_CHECK_MSG(decode_with(truncated, limits.max_frame_bytes) == WireStatus::kMalformed,
                   "truncated frame of " + std::to_string(length) + " bytes was not rejected as malformed");
    }
  }
  {  // a single flipped bit anywhere in the frame is rejected
    for (std::size_t offset = 0; offset < bytes.size(); ++offset) {
      for (unsigned int bit = 0; bit < 8u; ++bit) {
        std::vector<std::byte> corrupted = bytes;
        corrupted[offset] ^= static_cast<std::byte>(1u << bit);
        PP_CHECK_MSG(decode_with(corrupted, limits.max_frame_bytes) != WireStatus::kOk,
                     "flipped bit " + std::to_string(bit) + " at offset " + std::to_string(offset) +
                         " was accepted");
      }
    }
  }
  {  // specific single-bit flips keep their exact status
    std::vector<std::byte> epoch_flip = bytes;
    epoch_flip[12] ^= std::byte{0x01};
    PP_CHECK_EQ(decode_with(epoch_flip, limits.max_frame_bytes), WireStatus::kIntegrityMismatch);
    std::vector<std::byte> sequence_flip = bytes;
    sequence_flip[20] ^= std::byte{0x01};
    PP_CHECK_EQ(decode_with(sequence_flip, limits.max_frame_bytes), WireStatus::kIntegrityMismatch);
    std::vector<std::byte> boot_flip = bytes;
    boot_flip[28] ^= std::byte{0x01};
    PP_CHECK_EQ(decode_with(boot_flip, limits.max_frame_bytes), WireStatus::kIntegrityMismatch);
    std::vector<std::byte> request_flip = bytes;
    request_flip[36] ^= std::byte{0x01};
    PP_CHECK_EQ(decode_with(request_flip, limits.max_frame_bytes), WireStatus::kIntegrityMismatch);
    std::vector<std::byte> integrity_flip = bytes;
    integrity_flip[60] ^= std::byte{0x01};
    PP_CHECK_EQ(decode_with(integrity_flip, limits.max_frame_bytes), WireStatus::kIntegrityMismatch);
    std::vector<std::byte> payload_flip = bytes;
    payload_flip[kWirePayloadOffset] ^= std::byte{0x01};
    PP_CHECK_EQ(decode_with(payload_flip, limits.max_frame_bytes), WireStatus::kIntegrityMismatch);
  }
  {  // a frame shorter than the fixed header
    const std::vector<std::byte> tiny(10, std::byte{0x00});
    WireFrame out;
    std::string reason;
    PP_CHECK_EQ(DecodeFrame(SpanOf(tiny), limits.max_frame_bytes, out, reason), WireStatus::kMalformed);
    PP_CHECK_EQ(reason, std::string("frame shorter than the fixed header"));
  }
}

PP_TEST(core, proto_request_payload_roundtrip_and_rejections) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  const ResourceLimits limits;
  const PlanningRequest rich = MakeRichRequest(fabric);
  PP_CHECK(ValidateRequest(rich, limits).ok());

  {  // expect_snapshot == true
    ByteWriter writer;
    EncodePlanningRequestPayload(writer, rich);
    PP_CHECK(!writer.overflowed());
    PlanningRequest decoded;
    std::string detail;
    PP_CHECK_EQ(DecodePlanningRequestPayload(writer.span(), limits, decoded, detail), WireStatus::kOk);
    CheckSameRequest(decoded, rich);
  }
  {  // expect_snapshot == false with a nil identity
    PlanningRequest plain = rich;
    plain.expect_snapshot = false;
    plain.expected_snapshot = SnapshotId{};
    PP_CHECK(ValidateRequest(plain, limits).ok());
    ByteWriter writer;
    EncodePlanningRequestPayload(writer, plain);
    PlanningRequest decoded;
    std::string detail;
    PP_CHECK_EQ(DecodePlanningRequestPayload(writer.span(), limits, decoded, detail), WireStatus::kOk);
    CheckSameRequest(decoded, plain);
    PP_CHECK_EQ(decoded.expected_snapshot, SnapshotId{});
  }
  {  // expect_snapshot == false with a carried identity is still preserved
    PlanningRequest carried = rich;
    carried.expect_snapshot = false;
    ByteWriter writer;
    EncodePlanningRequestPayload(writer, carried);
    PlanningRequest decoded;
    std::string detail;
    PP_CHECK_EQ(DecodePlanningRequestPayload(writer.span(), limits, decoded, detail), WireStatus::kOk);
    CheckSameRequest(decoded, carried);
    PP_CHECK_EQ(decoded.expected_snapshot, rich.expected_snapshot);
  }
  {  // unknown enumeration value inside the payload
    ByteWriter writer;
    EncodePlanningRequestPayload(writer, rich);
    std::vector<std::byte> corrupted = writer.data();
    PP_REQUIRE(corrupted.size() > 32u);
    PP_CHECK_EQ(corrupted[32], std::byte{0x01});  // published endpoint class
    corrupted[32] = std::byte{99};
    PlanningRequest decoded;
    std::string detail;
    PP_CHECK_EQ(DecodePlanningRequestPayload(SpanOf(corrupted), limits, decoded, detail), WireStatus::kMalformed);
    PP_CHECK(detail.find("source class") != std::string::npos);
  }
  {  // forbidden-node count above the configured limit
    PlanningRequest many = rich;
    many.constraints.forbidden_nodes = {fabric.a, fabric.b, fabric.c};
    ByteWriter writer;
    EncodePlanningRequestPayload(writer, many);
    PlanningRequest decoded;
    std::string detail;
    PP_CHECK_EQ(DecodePlanningRequestPayload(writer.span(), limits, decoded, detail), WireStatus::kOk);
    PP_CHECK_EQ(decoded.constraints.forbidden_nodes.size(), static_cast<std::size_t>(3));
    ResourceLimits tight;
    tight.max_forbidden_ids = 2;
    PlanningRequest rejected;
    std::string rejected_detail;
    PP_CHECK_EQ(DecodePlanningRequestPayload(writer.span(), tight, rejected, rejected_detail),
                WireStatus::kMalformed);
    PP_CHECK(rejected_detail.find("forbidden node") != std::string::npos);
  }
  {  // trailing bytes
    ByteWriter writer;
    EncodePlanningRequestPayload(writer, rich);
    std::vector<std::byte> extended = writer.data();
    extended.push_back(std::byte{0x00});
    PlanningRequest decoded;
    std::string detail;
    PP_CHECK_EQ(DecodePlanningRequestPayload(SpanOf(extended), limits, decoded, detail),
                WireStatus::kTrailingBytes);
  }
  {  // truncation
    ByteWriter writer;
    EncodePlanningRequestPayload(writer, rich);
    std::vector<std::byte> truncated = writer.data();
    truncated.resize(truncated.size() / 2);
    PlanningRequest decoded;
    std::string detail;
    PP_CHECK_EQ(DecodePlanningRequestPayload(SpanOf(truncated), limits, decoded, detail), WireStatus::kMalformed);
    PlanningRequest empty_decoded;
    std::string empty_detail;
    PP_CHECK_EQ(DecodePlanningRequestPayload(std::span<const std::byte>(), limits, empty_decoded, empty_detail),
                WireStatus::kMalformed);
  }
  {  // a nil expected snapshot that the request claims to expect is refused
    PlanningRequest nil = rich;
    nil.expect_snapshot = true;
    nil.expected_snapshot = SnapshotId{};
    ByteWriter writer;
    EncodePlanningRequestPayload(writer, nil);
    PlanningRequest decoded;
    std::string detail;
    PP_CHECK_EQ(DecodePlanningRequestPayload(writer.span(), limits, decoded, detail), WireStatus::kMalformed);
  }
  {  // a structurally valid payload that fails request validation is refused
    PlanningRequest invalid = rich;
    invalid.max_candidates = 0;
    ByteWriter writer;
    EncodePlanningRequestPayload(writer, invalid);
    PlanningRequest decoded;
    std::string detail;
    PP_CHECK_EQ(DecodePlanningRequestPayload(writer.span(), limits, decoded, detail), WireStatus::kMalformed);
    PP_CHECK(detail.find("failed validation") != std::string::npos);
  }
}

// ===========================================================================
// 11. Rendering.
// ===========================================================================

PP_TEST(core, rendering_is_deterministic_and_complete) {
  const Fabric fabric = MakeFabric(FabricOptions{});
  PlannerRuntime runtime(ConfigFor(fabric));
  const PlanningRequest request = MakeAToCRequest(fabric, 2);
  PlanningResult result;
  const PathPlan plan = PlanOnce(runtime, request, result);
  PP_REQUIRE(result.status == PlanStatus::kPlanned);
  PP_REQUIRE(result.candidates.size() == static_cast<std::size_t>(2));

  const std::string verbose = RenderResult(result, true);
  const std::string quiet = RenderResult(result, false);
  PP_CHECK_EQ(verbose, RenderResult(result, true));
  PP_CHECK_EQ(quiet, RenderResult(result, false));
  PP_CHECK(verbose.size() > quiet.size());
  PP_CHECK(verbose.compare(0, std::string("status PLANNED\n").size(), "status PLANNED\n") == 0);
  PP_CHECK(verbose.find("plan_id " + result.plan_id.ToString()) != std::string::npos);
  PP_CHECK(verbose.find("semantic_digest " + result.semantic_digest.ToHex()) != std::string::npos);
  PP_CHECK(verbose.find("planning_generation 1") != std::string::npos);
  PP_CHECK(verbose.find("requested_candidates 2") != std::string::npos);
  PP_CHECK(verbose.find("returned_candidates 2") != std::string::npos);
  PP_CHECK(verbose.find("truncated false") != std::string::npos);
  PP_CHECK(verbose.find("diagnostic_mode false") != std::string::npos);
  PP_CHECK(verbose.find("evidence snapshot=" + fabric.snapshot->Id().ToString()) != std::string::npos);
  PP_CHECK(verbose.find("evidence source=SYNTHETIC") != std::string::npos);
  const std::string exact_cost_line =
      "candidate cost total=7 hops=2 hops_cost=2 static_cost=5 degraded_penalty=0 locality_penalty=0 "
      "degraded_hops=0 locality_breaches=0\n";
  PP_CHECK_MSG(verbose.find(exact_cost_line) != std::string::npos, verbose);
  PP_CHECK(quiet.find(exact_cost_line) != std::string::npos);
  const std::string second_cost_line =
      "candidate cost total=8 hops=2 hops_cost=2 static_cost=6 degraded_penalty=0 locality_penalty=0 "
      "degraded_hops=0 locality_breaches=0\n";
  PP_CHECK(verbose.find(second_cost_line) != std::string::npos);
  PP_CHECK(verbose.find("candidate rank=1 id=" + result.candidates[0].id.ToString()) != std::string::npos);
  PP_CHECK(verbose.find("candidate rank=2 id=" + result.candidates[1].id.ToString()) != std::string::npos);
  PP_CHECK(verbose.find("candidate path " + result.candidates[0].path.Render()) != std::string::npos);
  PP_CHECK(verbose.find("candidate path " + result.candidates[1].path.Render()) != std::string::npos);
  for (const NodeId& node : result.candidates[0].path.nodes) {
    PP_CHECK_MSG(verbose.find(node.ToString()) != std::string::npos, node.ToString());
  }
  PP_CHECK(verbose.find("currentness=CURRENT") != std::string::npos);
  PP_CHECK(verbose.find("authority=NOT_REQUESTED") != std::string::npos);
  PP_CHECK(verbose.find("candidate hop 0 link=" + fabric.ab.ToString()) != std::string::npos);
  PP_CHECK(verbose.find("candidate hop 1 link=" + fabric.bc.ToString()) != std::string::npos);
  PP_CHECK(quiet.find("candidate hop 0 link=") == std::string::npos);

  const std::string plan_verbose = RenderPlan(plan, true);
  const std::string plan_quiet = RenderPlan(plan, false);
  PP_CHECK_EQ(plan_verbose, RenderPlan(plan, true));
  PP_CHECK_EQ(plan_quiet, RenderPlan(plan, false));
  PP_CHECK(plan_verbose.compare(0, std::string("plan_id " + plan.id.ToString() + "\n").size(),
                                "plan_id " + plan.id.ToString() + "\n") == 0);
  PP_CHECK(plan_verbose.find("request " + plan.request.ToString()) != std::string::npos);
  PP_CHECK(plan_verbose.find("status PLANNED") != std::string::npos);
  PP_CHECK(plan_verbose.find("source_node " + fabric.a.ToString()) != std::string::npos);
  PP_CHECK(plan_verbose.find("destination_node " + fabric.c.ToString()) != std::string::npos);
  PP_CHECK(plan_verbose.find("layer PHYSICAL") != std::string::npos);
  PP_CHECK(plan_verbose.find("currentness_proven true") != std::string::npos);
  PP_CHECK(plan_verbose.find("candidates 2") != std::string::npos);
  PP_CHECK(plan_verbose.find(exact_cost_line) != std::string::npos);
  PP_CHECK(plan_verbose.find("candidate path " + plan.candidates[0].path.Render()) != std::string::npos);
  for (const NodeId& node : plan.candidates[0].path.nodes) {
    PP_CHECK_MSG(plan_verbose.find(node.ToString()) != std::string::npos, node.ToString());
  }

  // Deterministic renderers carry no timing data.
  const char* kTimingTokens[] = {"elapsed",  "duration",     "timestamp", "millisecond", "nanosecond",
                                 "microsecond", "clock",    "wall",      "latency",     "seconds"};
  for (const char* token : kTimingTokens) {
    PP_CHECK_MSG(verbose.find(token) == std::string::npos, token);
    PP_CHECK_MSG(plan_verbose.find(token) == std::string::npos, token);
  }
  // The evidence renderer is stable and self-describing.
  PP_CHECK_EQ(RenderEvidence(result.evidence), RenderEvidence(result.evidence));
  PP_CHECK(RenderEvidence(result.evidence).find("evidence fabric_epoch=1") != std::string::npos);
  PP_CHECK(RenderSnapshotSummary(*fabric.snapshot) == RenderSnapshotSummary(*fabric.snapshot));
  PP_CHECK(RenderSnapshotSummary(*fabric.snapshot).find("snapshot nodes=3") != std::string::npos);
  PP_CHECK(RenderSnapshotSummary(*fabric.snapshot).find("snapshot edges=3") != std::string::npos);
  PP_CHECK(RenderStatistics(runtime.Stats()) == RenderStatistics(runtime.Stats()));
  PP_CHECK(RenderRejections(result.rejections) == RenderRejections(result.rejections));
  PP_CHECK(RenderCandidate(result.candidates[0], true) == RenderCandidate(result.candidates[0], true));
  PP_CHECK(RenderRankExplanation(result.candidates[0], result.candidates[1]) ==
           RenderRankExplanation(result.candidates[0], result.candidates[1]));
  PP_CHECK(RenderRankExplanation(result.candidates[0], result.candidates[1]).find("ranks_before=lhs") !=
           std::string::npos);
}

}  // namespace core

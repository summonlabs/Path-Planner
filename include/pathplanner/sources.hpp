#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "pathplanner/graph.hpp"
#include "pathplanner/ids.hpp"
#include "pathplanner/limits.hpp"
#include "pathplanner/status.hpp"

namespace summon::pathplanner {

// ===========================================================================
// Evidence sources
//
// Two independent producers of FabricSnapshot values:
//
//   * a deterministic SYNTHETIC fabric generator (EvidenceSource::kSynthetic),
//     used to exercise the planner against structurally hostile topologies;
//   * read-only REAL discovery of the local host's own adapters
//     (EvidenceSource::kReal), a single-node host-local planning view.
//
// Both build exclusively through FabricSnapshotBuilder, so every snapshot obeys
// the same structural contract as production evidence. Neither producer invents
// identity: synthetic identifiers are derived from a label string and the
// requested seed, real identifiers are derived from the host's own adapter
// identities. Nothing here reads the clock, allocates identity from a counter,
// performs network I/O or resolves names.
// ===========================================================================

// ---------------------------------------------------------------------------
// Synthetic topologies.
//
// Each family is a deliberate structural probe, not a random graph:
//   CHAIN               single path; exactly one simple route
//   RING                cycle; two simple routes between any pair
//   DIAMOND             two disjoint parallel routes between source/destination
//   LEAF_SPINE          two-tier full bipartite leaves <-> spines
//   FAT_TREE            three-tier (four-tier when layers >= 4) Clos
//   MESH                cyclic mesh with wrap-around chords
//   DISCONNECTED        several components; source and destination are apart
//   ONE_WAY             forward-only chain; no reverse edge exists
//   PARALLEL_EQUAL_COST at least two distinct equal-cost links on one node pair
//   TIE_STORM           many equal-cost two-hop alternatives source -> dest
//   HIGH_DEGREE_HUB     single hub of degree node_count - 1
//   DEEP_CHAIN          maximum-depth chain over a seeded node permutation
//   SPARSE_LARGE        connected, exactly node_count - 1 edges (binary tree)
//   DENSE_BOUNDED       bounded-degree circulant; density via extra_edges
//
// Edge orientation: an EdgeRecord is consumed as a directed adjacency (from ->
// to). Every family therefore emits its links in the direction that follows the
// family's intended route, and the reported source/destination pair is chosen so
// that the source can reach the destination in that directed model. The
// deliberate exceptions are DISCONNECTED (the destination sits in another
// component) and ONE_WAY (a forward-only chain, so no reverse edge exists at all).
// ---------------------------------------------------------------------------
enum class SyntheticFamily : std::uint32_t {
  kChain = 1,
  kRing = 2,
  kDiamond = 3,
  kLeafSpine = 4,
  kFatTree = 5,
  kMesh = 6,
  kDisconnected = 7,
  kOneWay = 8,
  kParallelEqualCost = 9,
  kTieStorm = 10,
  kHighDegreeHub = 11,
  kDeepChain = 12,
  kSparseLarge = 13,
  kDenseBounded = 14,
};

inline constexpr EnumEntry kSyntheticFamilyNames[] = {
    {"CHAIN", 1},
    {"RING", 2},
    {"DIAMOND", 3},
    {"LEAF_SPINE", 4},
    {"FAT_TREE", 5},
    {"MESH", 6},
    {"DISCONNECTED", 7},
    {"ONE_WAY", 8},
    {"PARALLEL_EQUAL_COST", 9},
    {"TIE_STORM", 10},
    {"HIGH_DEGREE_HUB", 11},
    {"DEEP_CHAIN", 12},
    {"SPARSE_LARGE", 13},
    {"DENSE_BOUNDED", 14},
};

inline std::string_view ToString(SyntheticFamily value) { return EnumName(kSyntheticFamilyNames, value); }
inline std::optional<SyntheticFamily> ParseSyntheticFamily(std::string_view name) {
  return ParseEnum<SyntheticFamily>(kSyntheticFamilyNames, name);
}

// ---------------------------------------------------------------------------
// Synthetic fabric request.
//
// Determinism: identical options produce a byte-identical snapshot, including
// SnapshotId(). Percentages are drawn from a seeded PRNG in a fixed order, so
// the same seed replays exactly.
// ---------------------------------------------------------------------------
struct SyntheticOptions {
  SyntheticFamily family = SyntheticFamily::kLeafSpine;
  std::uint64_t seed = 1;              // deterministic PRNG seed; same seed => byte-identical snapshot
  std::uint32_t nodes = 16;            // requested node count (families may round up)
  std::uint32_t extra_edges = 0;       // for mesh/dense families
  std::uint32_t layers = 4;            // leaf-spine/fat-tree depth hint
  PathLayer layer = PathLayer::kPhysical;
  std::uint32_t static_cost_base = 1;  // administrative static cost base
  std::uint32_t static_cost_spread = 1;  // 0 => all equal cost
  // Fractions expressed as percentages, applied deterministically by the seeded PRNG.
  std::uint32_t percent_down = 0;
  std::uint32_t percent_degraded = 0;
  std::uint32_t percent_unknown = 0;
  std::uint32_t percent_port_disabled = 0;
  std::uint32_t percent_without_link_state_record = 0;  // exercised the UNKNOWN-by-absence path
  std::uint32_t capability_bindings = 1;  // distinct capabilities published per node/link (>=1)
  std::uint32_t failure_domains = 2;      // number of failure domains
  bool membership_complete = true;        // passes through to FailureDomainView
  ResourceLimits limits;
};

// Generates a SYNTHETIC snapshot. EvidenceSource::kSynthetic. Deterministic for a given seed.
//
// Every link/port/capability/failure-domain view is published for every entity
// except the records the options explicitly remove. A request that would breach
// any ceiling in options.limits is rejected with the corresponding diagnostic
// instead of being truncated.
SnapshotBuildResult GenerateSyntheticFabric(const SyntheticOptions& options);

// Same, but reports the endpoints the caller can use as source/destination.
struct SyntheticFabric {
  std::shared_ptr<const FabricSnapshot> snapshot;
  EndpointId source;
  EndpointId destination;
  NodeId source_node;
  NodeId destination_node;
  EntityGeneration source_generation;
  EntityGeneration destination_generation;
  EndpointClass endpoint_class = EndpointClass::kEndpoint;
};

// nullopt plus a human-readable error when the request is rejected (an unsupported
// family, incoherent limits, or a breached ceiling). The error string is always set
// on failure.
std::optional<SyntheticFabric> MakeSyntheticFabric(const SyntheticOptions& options, std::string& error);

// ---------------------------------------------------------------------------
// Real local host.
// ---------------------------------------------------------------------------
struct LocalAdapter {
  std::string name;            // adapter friendly name (UTF-8)
  std::string description;
  std::string mac;             // lowercase colon-free hex, empty when the adapter has none
  std::uint64_t if_index = 0;
  bool up = false;
  bool loopback = false;
  PathLayer layer = PathLayer::kPhysical;
};

// Read-only enumeration of local host adapters (Windows IP Helper GetAdaptersAddresses).
// Returns an empty vector when the platform is unsupported: never fabricates data.
std::vector<LocalAdapter> EnumerateLocalAdapters();
bool LocalDiscoverySupported();

// Builds a host-local, single-node planning view. REAL identities only: the graph contains the
// local host node and its adapters as ports. It is NOT fabric topology and must be labelled as
// EvidenceSource::kReal with a single node. Returns nullopt with an error when unsupported or when
// no adapter is present.
//
// Published records: one node (nil switch attachment, generation 1), one port per adapter, one
// port-state record per adapter, and endpoints for the first two usable adapters (loopback only as
// a last resort; a single-adapter host uses that adapter for both endpoints). No edges, no link
// states, no capability bindings and no failure domains are published: the local host has no
// authoritative registry for them, and absence means UNKNOWN, which never satisfies a requirement.
std::optional<SyntheticFabric> MakeLocalHostFabric(const ResourceLimits& limits, std::string& error);

}  // namespace summon::pathplanner

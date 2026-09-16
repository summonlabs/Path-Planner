#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "pathplanner/canonical.hpp"
#include "pathplanner/graph.hpp"
#include "pathplanner/ids.hpp"
#include "pathplanner/status.hpp"

namespace summon::pathplanner {

// ---------------------------------------------------------------------------
// PathHop: one traversed adjacency with every identity needed to reconstruct it.
// ---------------------------------------------------------------------------
struct PathHop {
  LinkId link;
  NodeId from;
  NodeId to;
  PortId from_port;
  PortId to_port;
  PathLayer layer = PathLayer::kPhysical;
  RelationshipType relationship = RelationshipType::kDirectLink;
  TopologyGeneration structural_generation;
  StaticCost static_cost;
  // Operational evidence observed when the hop was accepted.
  LinkState link_state = LinkState::kUnknown;
  bool degraded = false;

  friend bool operator==(const PathHop& lhs, const PathHop& rhs) noexcept;
};

// ---------------------------------------------------------------------------
// CandidatePath: ordered typed sequence of nodes and hops.
//
// Well formed when nodes.size() == hops.size() + 1 and every hop continues from
// the previous node.
// ---------------------------------------------------------------------------
struct CandidatePath {
  NodeId source;
  NodeId destination;
  PathLayer layer = PathLayer::kPhysical;
  std::vector<NodeId> nodes;
  std::vector<PathHop> hops;

  bool Empty() const noexcept { return nodes.empty(); }
  std::size_t HopCountValue() const noexcept { return hops.size(); }
  HopCount Hops() const noexcept { return HopCount(static_cast<std::uint32_t>(hops.size())); }

  bool IsWellFormed() const noexcept;
  // No repeated structural node: ordinary forwarding paths must be simple.
  bool IsSimple() const noexcept;
  // Versioned canonical encoding. Semantically equivalent paths encode
  // identically; a different hop order produces different bytes.
  void Encode(ByteWriter& writer) const;
  Sha256Digest Digest() const;
  CandidatePathId Id() const;
  // Deterministic stable rendering.
  std::string Render() const;
  std::string RenderHops() const;
};

// ---------------------------------------------------------------------------
// Cost model. All arithmetic is checked; overflow never wraps.
// ---------------------------------------------------------------------------
struct CostModel {
  CostValue hop_cost{1};          // charged once per traversed hop
  CostValue degraded_penalty{0};  // charged once per DEGRADED hop
  CostValue locality_penalty{0};  // charged once per hop leaving the locality scope
};

struct PathCost {
  CostValue hops_cost;         // hop_count * hop_cost
  CostValue static_cost;       // sum of administrative static edge costs
  CostValue degraded_penalty;  // degraded_hops * degraded_penalty
  CostValue locality_penalty;  // locality_breaches * locality_penalty
  CostValue total;
  HopCount hops;
  std::uint32_t degraded_hops = 0;
  std::uint32_t locality_breaches = 0;

  friend bool operator==(const PathCost& lhs, const PathCost& rhs) noexcept;
};

// Per-hop cost inputs resolved from the eligible planning view.
struct HopCostInput {
  StaticCost static_cost;
  bool degraded = false;
  bool outside_locality = false;
};

// Checked accumulation of a path cost. Returns nullopt when any component or the
// total would overflow, or when the hop count exceeds kMaxHopCount.
std::optional<PathCost> AccumulatePathCost(const std::vector<HopCostInput>& hops, const CostModel& model);

// ---------------------------------------------------------------------------
// Candidate: a ranked planning output with full provenance.
// ---------------------------------------------------------------------------
struct CandidateProvenance {
  PlanningGeneration planning_generation;
  ConstraintSetId constraint_set;
  ConstraintGeneration constraint_generation;
  PolicyGeneration policy_generation;
  EvidenceSource source = EvidenceSource::kSynthetic;
  std::uint32_t planning_rule_version = 0;
  std::uint32_t path_encoding_version = 0;
};

struct Candidate {
  CandidatePathId id;
  CandidatePath path;
  PathCost cost;
  CandidateRank rank;
  EvidenceVector evidence;
  CandidateProvenance provenance;
  // Path Authority integration is explicit; NOT_REQUESTED means Path Planner is
  // making no legality claim about this candidate.
  AuthorityValidation authority = AuthorityValidation::kNotRequested;
  // CURRENT only when the evidence is proven current; diagnostic mode results
  // are REVALIDATION_REQUIRED.
  Currentness currentness = Currentness::kCurrent;
  std::vector<DiagnosticCode> notes;
};

// Canonical path comparison used for ordering: the lexicographic node-id sequence, then the
// lexicographic link-id sequence. CandidatePathId is an identity (used for uniqueness and
// provenance), never an ordering key.
std::strong_ordering CompareCanonicalPaths(const CandidatePath& lhs, const CandidatePath& rhs) noexcept;

// Canonical ranking comparator: total cost, then hop count, then the canonical path order.
bool RanksBefore(const Candidate& lhs, const Candidate& rhs) noexcept;

}  // namespace summon::pathplanner

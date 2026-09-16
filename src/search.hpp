#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "pathplanner/planner.hpp"
#include "planning_view.hpp"

namespace summon::pathplanner::internal {

// No hop bound was requested: the search runs over nodes directly (exact, and the only
// mode that scales to large graphs). The hop dimension exists solely to enforce an
// explicit caller-supplied bound.
inline constexpr std::uint32_t kNoHopBound = 0xFFFFFFFFu;

// ---------------------------------------------------------------------------
// Deterministic work budget. Counts are product resource bounds; exhaustion is
// reported as RESOURCE_LIMIT rather than being retried or ignored.
// ---------------------------------------------------------------------------
struct WorkBudget {
  std::uint64_t states_remaining = 0;
  std::uint64_t pushes_remaining = 0;
  std::uint64_t spur_remaining = 0;
  bool exhausted = false;
  bool state_space_exceeded = false;
};

// ---------------------------------------------------------------------------
// BanSet: nodes and adjacency entries excluded from one search (Yen spurs and
// staged transit legs). Membership tests are ordered and deterministic.
// ---------------------------------------------------------------------------
class BanSet {
 public:
  void AddNode(std::uint32_t view_index);
  void AddAdjacency(std::uint32_t adjacency_index);
  bool NodeBanned(std::uint32_t view_index) const noexcept;
  bool AdjacencyBanned(std::uint32_t adjacency_index) const noexcept;
  bool Empty() const noexcept { return nodes_.empty() && adjacency_.empty(); }

 private:
  void Normalize() const;

  mutable std::vector<std::uint32_t> nodes_;
  mutable std::vector<std::uint32_t> adjacency_;
  mutable bool normalized_ = true;
};

// A path in eligible-view coordinates.
struct RawPath {
  std::vector<std::uint32_t> nodes;      // view node indices, hops + 1 entries
  std::vector<std::uint32_t> adjacency;  // adjacency entry indices, hops entries

  bool Empty() const noexcept { return nodes.empty(); }
  std::size_t HopCount() const noexcept { return adjacency.size(); }
};

bool SameRawPath(const RawPath& lhs, const RawPath& rhs) noexcept;

struct SearchOutcome {
  bool found = false;
  bool resource_limit = false;
  bool cost_overflow = false;
  RawPath path;
};

// ---------------------------------------------------------------------------
// Searcher: canonical-minimum path under (total cost, hop count, node sequence,
// link sequence). Both search modes are exact for that objective:
//
//  * when the hop bound cannot bind, plain Dijkstra over nodes with
//    lexicographic (cost, hops) labels;
//  * otherwise Dijkstra over (hops, node) states, which is exact under a hop
//    bound.
//
// Reconstruction is a greedy walk over the exact-cost DAG restricted to the
// chosen hop count, which yields the lexicographically smallest node sequence.
// ---------------------------------------------------------------------------
class Searcher {
 public:
  Searcher(const PlanningView& view, WorkBudget& budget, PlannerStatistics& stats);

  SearchOutcome ShortestPath(std::uint32_t source, std::uint32_t dest, std::uint32_t hop_budget,
                             const BanSet& bans);

 private:
  SearchOutcome PlainSearch(std::uint32_t source, std::uint32_t dest, std::uint32_t hop_budget,
                            const BanSet& bans);
  SearchOutcome ExpandedSearch(std::uint32_t source, std::uint32_t dest, std::uint32_t hop_budget,
                               const BanSet& bans);
  bool SpendState();
  bool SpendPush();

  const PlanningView& view_;
  WorkBudget& budget_;
  PlannerStatistics& stats_;
};

// ---------------------------------------------------------------------------
// Candidate enumeration.
// ---------------------------------------------------------------------------
struct EnumerationOptions {
  std::uint32_t source_view = kInvalidIndex;
  std::uint32_t destination_view = kInvalidIndex;
  std::uint32_t max_candidates = 1;
  std::uint32_t enumeration_ceiling = 1;
  std::uint32_t max_hops = 0;
  bool domain_member_limit_active = false;
};

struct EnumerationResult {
  bool ok = false;
  DiagnosticCode failure = DiagnosticCode::kNoStructuralPath;
  bool resource_limit = false;
  bool truncated = false;
  std::vector<RawPath> paths;
  std::string detail;
};

EnumerationResult EnumerateCandidatePaths(const PlanningView& view, const PlanningRequest& request,
                                          const EnumerationOptions& options, WorkBudget& budget,
                                          PlannerStatistics& stats);

// Converts a raw path into the canonical typed path representation.
CandidatePath BuildCandidatePath(const PlanningView& view, const RawPath& raw);

// Cost of a raw path under the view cost model (checked arithmetic).
std::optional<PathCost> ComputeRawPathCost(const PlanningView& view, const RawPath& raw);

// Canonical ordering predicate over raw paths: cost, hops, node sequence, link sequence.
bool RawPathRanksBefore(const PlanningView& view, const RawPath& lhs, const RawPath& rhs);

// Path-level failure-domain member limit: no failure domain may appear on more than
// the allowed number of traversed links.
bool DomainMemberLimitCompliant(const PlanningView& view, const RawPath& raw, std::uint32_t limit,
                                bool fail_closed);

}  // namespace summon::pathplanner::internal

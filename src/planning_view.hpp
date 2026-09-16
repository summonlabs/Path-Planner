#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "pathplanner/graph.hpp"
#include "pathplanner/ids.hpp"
#include "pathplanner/limits.hpp"
#include "pathplanner/path.hpp"
#include "pathplanner/request.hpp"
#include "pathplanner/result.hpp"
#include "pathplanner/status.hpp"

namespace summon::pathplanner::internal {

inline constexpr std::uint32_t kInvalidIndex = 0xFFFFFFFFu;
inline constexpr std::size_t kRejectionExampleLimit = 4;
inline constexpr std::size_t kDiagnosticCodeSlots = 96;

// ---------------------------------------------------------------------------
// RejectionLog
//
// Bounded, deterministic aggregation of why elements were excluded. Rejections
// are aggregated per diagnostic code (with a few example subjects) so a large
// graph cannot inflate the explanation, and constraint-driven exclusions are
// additionally recorded explicitly because they are bounded by the constraint set.
// ---------------------------------------------------------------------------
class RejectionLog {
 public:
  RejectionLog() = default;
  explicit RejectionLog(std::uint32_t max_entries);

  void Aggregate(DiagnosticCode code, const SubjectKey& subject, std::string detail);
  void Explicit(DiagnosticCode code, const SubjectKey& subject, std::string detail);

  bool Contains(DiagnosticCode code) const noexcept;
  std::uint64_t Count(DiagnosticCode code) const noexcept;
  bool Empty() const noexcept;

  // Deterministic rendering: aggregates first (ordered by code), then explicit
  // entries in the order they were recorded (which follows sorted snapshot order).
  std::vector<RejectionExplanation> Render() const;

 private:
  struct AggregateEntry {
    bool present = false;
    std::uint64_t count = 0;
    std::vector<SubjectKey> examples;
    std::string detail;
  };

  std::array<AggregateEntry, kDiagnosticCodeSlots> aggregates_{};
  std::vector<RejectionExplanation> explicit_entries_;
  std::uint32_t max_entries_ = 256;
};

// ---------------------------------------------------------------------------
// PlanningView: the eligible, cost-resolved graph for one request.
// ---------------------------------------------------------------------------
struct Adjacency {
  std::uint32_t to = kInvalidIndex;        // view node index
  std::uint32_t edge = kInvalidIndex;      // snapshot edge index
  CostValue traversal_cost;                // static cost plus policy penalties
  bool degraded = false;
  bool outside_locality = false;
};

class PlanningView {
 public:
  const FabricSnapshot* snapshot = nullptr;
  ResourceLimits limits;

  PathLayer layer = PathLayer::kPhysical;
  CostModel cost_model;
  bool diagnostic_mode = false;
  bool require_operational_proof = true;
  bool allow_degraded_links = false;
  bool allow_draining_ports = false;
  bool allow_maintenance_ports = false;
  std::vector<NodeId> locality_scope;
  std::vector<FailureDomainId> forbidden_failure_domains;
  std::vector<FailureDomainClass> forbidden_failure_domain_classes;
  bool fail_closed_on_unknown_domains = true;
  // True when the request intentionally plans from non-current evidence
  // (diagnostic mode, or operational proof explicitly waived). Candidates from a
  // provisional view are never CURRENT.
  bool provisional = false;

  // CSR adjacency over view node indices. Each node list is sorted by
  // (destination NodeId, LinkId) so reconstruction is deterministic.
  std::vector<std::uint32_t> offsets;
  std::vector<Adjacency> adjacency;
  std::vector<std::uint32_t> view_to_snapshot_node;
  std::vector<std::uint32_t> snapshot_to_view_node;

  RejectionLog rejections;
  std::uint64_t eligible_edges = 0;

  std::uint32_t NodeCount() const noexcept {
    return static_cast<std::uint32_t>(view_to_snapshot_node.size());
  }
  const NodeRecord& NodeAt(std::uint32_t view_index) const noexcept {
    return snapshot->Nodes()[view_to_snapshot_node[view_index]];
  }
  const EdgeRecord& EdgeAt(std::uint32_t snapshot_edge_index) const noexcept {
    return snapshot->Edges()[snapshot_edge_index];
  }
  std::uint32_t ViewIndex(const NodeId& id) const noexcept;
};

// ---------------------------------------------------------------------------
// View construction.
// ---------------------------------------------------------------------------
struct PlanningViewBuild {
  PlanningView view;
  // Set when the request cannot be satisfied regardless of graph search, for
  // example a capability requirement that the source node itself violates.
  std::optional<DiagnosticCode> fatal;
  std::string detail;
  std::vector<ExplanationEntry> explanations;
  bool ok() const noexcept { return !fatal.has_value(); }
};

// Builds the eligible view. Source/destination view indices are returned through
// the out parameters; kInvalidIndex means the resolved node is excluded by a
// hard constraint.
PlanningViewBuild BuildPlanningView(const FabricSnapshot& snapshot, const PlanningRequest& request,
                                    const ResourceLimits& limits, const NodeId& source_node,
                                    const NodeId& destination_node, std::uint32_t& source_view,
                                    std::uint32_t& destination_view);

// Shared capability / failure-domain evaluation helpers (also used by oracles).
bool CapabilitySatisfied(const PlanningView& view, const SubjectKey& subject,
                         const CapabilityRequirement& requirement, DiagnosticCode& failure);
bool FailureDomainCompliant(const PlanningView& view, const SubjectKey& subject, bool fail_closed,
                            DiagnosticCode& failure);

}  // namespace summon::pathplanner::internal

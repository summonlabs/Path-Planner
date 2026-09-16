#pragma once

#include <cstdint>
#include <functional>
#include <memory>
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

namespace summon::pathplanner {

// ---------------------------------------------------------------------------
// Path Authority port.
//
// Path Planner never claims that a candidate is legally usable. When a caller
// supplies a Path Authority implementation the outcome is recorded per candidate
// as VALIDATED / REJECTED / UNAVAILABLE; without one, candidates are reported as
// NOT_REQUESTED.
// ---------------------------------------------------------------------------
class IPathAuthority {
 public:
  virtual ~IPathAuthority() = default;
  IPathAuthority(const IPathAuthority&) = delete;
  IPathAuthority& operator=(const IPathAuthority&) = delete;

  // Evaluates one exact candidate path under the supplied evidence. The reason
  // string is included in the candidate notes when the verdict is not VALIDATED.
  virtual AuthorityValidation ValidatePath(const CandidatePath& path, const EvidenceVector& evidence,
                                           std::string& reason) = 0;

 protected:
  IPathAuthority() = default;
};

// ---------------------------------------------------------------------------
// Instrumentation. Stage notifications are observational: they never change the
// planning result and exist for benchmarks, diagnostics and test synchronization.
// ---------------------------------------------------------------------------
enum class PlanningStage : std::uint32_t {
  kDecoded = 1,
  kAuthorityChecked = 2,
  kEndpointsResolved = 3,
  kSnapshotCaptured = 4,
  kViewBuilt = 5,
  kSearchCompleted = 6,
  kScored = 7,
  kRanked = 8,
  kBeforePublish = 9,
  kPublished = 10,
};

inline constexpr EnumEntry kPlanningStageNames[] = {
    {"DECODED", 1},
    {"AUTHORITY_CHECKED", 2},
    {"ENDPOINTS_RESOLVED", 3},
    {"SNAPSHOT_CAPTURED", 4},
    {"VIEW_BUILT", 5},
    {"SEARCH_COMPLETED", 6},
    {"SCORED", 7},
    {"RANKED", 8},
    {"BEFORE_PUBLISH", 9},
    {"PUBLISHED", 10},
};

inline std::string_view ToString(PlanningStage value) { return EnumName(kPlanningStageNames, value); }

struct PlanningHooks {
  std::function<void(PlanningStage, const PlanningRequestId&)> on_stage;
};

// ---------------------------------------------------------------------------
// Runtime configuration and statistics.
// ---------------------------------------------------------------------------
struct PlannerConfig {
  ResourceLimits limits;
  std::shared_ptr<const FabricSnapshot> initial_snapshot;
  std::shared_ptr<IPathAuthority> path_authority;
  PlanningHooks hooks;
};

struct PlannerStatistics {
  std::uint64_t plans_computed = 0;
  std::uint64_t plans_published = 0;
  std::uint64_t plans_publish_rejected_stale = 0;
  std::uint64_t candidates_returned = 0;
  std::uint64_t states_expanded = 0;
  std::uint64_t queue_pushes = 0;
  std::uint64_t spur_searches = 0;
  std::uint64_t snapshots_published = 0;
  std::uint64_t epochs_advanced = 0;
  std::uint64_t invalidations_applied = 0;
  std::uint64_t plans_retired = 0;
};

// ---------------------------------------------------------------------------
// Targeted invalidation notice.
//
// A notice names the changed authoritative subjects. Retained plans that depend
// on them are marked REVALIDATION_REQUIRED; plans that do not depend on them are
// left untouched. conservative_all is the explicit fallback used when precise
// dependency information is unavailable.
// ---------------------------------------------------------------------------
struct InvalidationNotice {
  std::vector<NodeId> nodes;
  std::vector<LinkId> links;
  std::vector<PortId> ports;
  std::vector<CapabilityId> capabilities;
  std::vector<FailureDomainId> failure_domains;
  bool conservative_all = false;
};

struct InvalidationReport {
  std::vector<PathPlanId> affected;
  std::vector<PathPlanId> marked_revalidation_required;
  std::vector<PathPlanId> retired;
  bool conservative = false;
  std::size_t retained_plans = 0;
};

// ---------------------------------------------------------------------------
// PlannerRuntime.
//
// Thread safety: every public member is safe to call concurrently. Planning runs
// against an immutable snapshot captured under a short lock; graph search never
// holds a lock. Publication re-checks the invalidation watermark so an in-flight
// plan cannot become CURRENT after its inputs changed.
// ---------------------------------------------------------------------------
class PlannerRuntime {
 public:
  explicit PlannerRuntime(PlannerConfig config = PlannerConfig{});
  ~PlannerRuntime();

  PlannerRuntime(const PlannerRuntime&) = delete;
  PlannerRuntime& operator=(const PlannerRuntime&) = delete;

  // Publishes a new snapshot. The publish sequence advances monotonically and is
  // captured by every plan as an invalidation watermark.
  void PublishSnapshot(std::shared_ptr<const FabricSnapshot> snapshot);
  std::shared_ptr<const FabricSnapshot> CurrentSnapshot() const;

  FabricEpoch CurrentEpoch() const;
  PlanPublishSequence PublishSequence() const;
  ResourceLimits Limits() const;

  // Computes a plan. Never throws for malformed input; malformed input is reported
  // as MALFORMED_REQUEST.
  PlanningResult Plan(const PlanningRequest& request);

  // Currentness of a previously produced plan against current evidence. Reports
  // the exact dependency dimensions that changed.
  PlanCurrentnessReport CheckCurrentness(const PathPlan& plan) const;

  // Replans a prior plan under current evidence. Does not alter any other runtime.
  bool Replan(const PathPlan& prior, const PlanningRequest& request, PlanningResult& result,
              ReplanReport& report);

  // Retention and reverse dependencies.
  bool Retain(const PathPlan& plan);
  std::optional<PathPlan> FindPlan(const PathPlanId& id) const;
  std::size_t RetainedPlanCount() const;
  InvalidationReport ApplyInvalidation(const InvalidationNotice& notice);

  // Epoch hand-off. Only a strictly greater epoch is accepted. conservative_recovery
  // marks every retained plan REVALIDATION_REQUIRED, which is the required behaviour
  // after a coordinator restart.
  bool AdvanceEpoch(FabricEpoch epoch, bool conservative_recovery, std::string& reason);

  PlannerStatistics Stats() const;
  void ResetStats();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace summon::pathplanner

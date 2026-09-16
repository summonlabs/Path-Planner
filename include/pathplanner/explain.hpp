#pragma once

#include <string>
#include <vector>

#include "pathplanner/graph.hpp"
#include "pathplanner/planner.hpp"
#include "pathplanner/result.hpp"
#include "pathplanner/status.hpp"

namespace summon::pathplanner {

// ---------------------------------------------------------------------------
// Deterministic rendering.
//
// Every renderer emits stable, line-oriented text suitable for scripts: fixed
// keyword order, no floating point, no locale-dependent formatting, no timing
// data, and a trailing newline on every line. Values are facts taken from the
// structures passed in; nothing is inferred.
// ---------------------------------------------------------------------------
std::string RenderEvidence(const EvidenceVector& evidence);
std::string RenderCandidate(const Candidate& candidate, bool verbose);
std::string RenderRejections(const std::vector<RejectionExplanation>& rejections);
std::string RenderResult(const PlanningResult& result, bool verbose);
std::string RenderPlan(const PathPlan& plan, bool verbose);
std::string RenderCurrentness(const PlanCurrentnessReport& report);
std::string RenderReplanReport(const ReplanReport& report);
std::string RenderStatistics(const PlannerStatistics& stats);
std::string RenderSnapshotSummary(const FabricSnapshot& snapshot);
// Rank explanation: the real cost components of one candidate against another.
std::string RenderRankExplanation(const Candidate& lhs, const Candidate& rhs);

}  // namespace summon::pathplanner

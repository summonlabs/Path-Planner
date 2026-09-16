#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <vector>

#include "pathplanner/canonical.hpp"
#include "pathplanner/graph.hpp"
#include "pathplanner/ids.hpp"
#include "pathplanner/limits.hpp"
#include "pathplanner/path.hpp"
#include "pathplanner/result.hpp"
#include "pathplanner/status.hpp"

namespace summon::pathplanner {

// ---------------------------------------------------------------------------
// Bounded, checksummed persistence for retained planning records.
//
// The store holds planning history only: requests, canonical candidate paths,
// costs, evidence vectors and digests. It never holds live worker authority,
// sockets, thread state or transient search state, and a recovered record is never
// treated as current fabric truth.
// ---------------------------------------------------------------------------
inline constexpr std::string_view kStoreMagic = "PPLNPLAN";
inline constexpr std::size_t kStoreHeaderBytes = 36;
inline constexpr std::size_t kStoreDigestBytes = kSha256Bytes;

struct StoredPlanRecord {
  PlanningRequestId request;
  PathPlanId plan;
  PlanningGeneration generation;
  PlanPublishSequence publish_sequence;
  PlanStatus status = PlanStatus::kNoPath;
  EvidenceVector evidence;
  ConstraintSetId constraint_set;
  ConstraintGeneration constraint_generation;
  PolicyGeneration policy_generation;
  NodeId source;
  NodeId destination;
  PathLayer layer = PathLayer::kPhysical;
  bool diagnostic_mode = false;
  std::vector<CandidatePath> candidates;
  std::vector<PathCost> costs;  // parallel to candidates
  std::vector<CandidateRank> ranks;
  Sha256Digest semantic_digest;
};

struct StoreOptions {
  ResourceLimits limits;
  PlanPublishSequence publish_sequence;
};

struct StoreResult {
  bool ok = false;
  DiagnosticCode code = DiagnosticCode::kPersistenceCorrupt;
  std::string detail;
};

// Deterministic encoding of a record set. The same records always produce the same
// bytes; encoding is bounded and reports overflow instead of truncating.
StoreResult EncodePlanStore(const std::vector<StoredPlanRecord>& records, const StoreOptions& options,
                            std::vector<std::byte>& out);

// Strict decoding. Rejects bad magic, unsupported versions, truncation at any point,
// digest mismatch, duplicate plan identity, duplicate candidate identity, impossible
// generations, non-monotonic costs, cost components that do not sum to the total,
// malformed path encodings, nil identifiers, over-limit counts and trailing bytes.
StoreResult DecodePlanStore(std::span<const std::byte> image, const ResourceLimits& limits,
                            std::vector<StoredPlanRecord>& out);

// Atomic replacement: the destination is only ever observed complete.
StoreResult SavePlanStore(const std::string& path, const std::vector<StoredPlanRecord>& records,
                          const StoreOptions& options);
StoreResult LoadPlanStore(const std::string& path, const ResourceLimits& limits,
                          std::vector<StoredPlanRecord>& out);

StoredPlanRecord ToStoredRecord(const PathPlan& plan);
PathPlan FromStoredRecord(const StoredPlanRecord& record);

}  // namespace summon::pathplanner

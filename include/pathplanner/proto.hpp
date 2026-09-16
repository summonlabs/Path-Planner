#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "pathplanner/canonical.hpp"
#include "pathplanner/graph.hpp"
#include "pathplanner/ids.hpp"
#include "pathplanner/limits.hpp"
#include "pathplanner/request.hpp"
#include "pathplanner/result.hpp"
#include "pathplanner/status.hpp"
#include "pathplanner/version.hpp"

namespace summon::pathplanner {

// ---------------------------------------------------------------------------
// Framed wire protocol.
//
// Every frame is: fixed header (76 bytes) || payload. The header carries stable
// explicit field encodings and a truncated SHA-256 integrity value computed over
// the semantic header fields plus the payload. Integrity is not authentication:
// Path Planner does not perform cryptographic peer authentication, and the
// protocol must only be exposed on a trusted transport.
// ---------------------------------------------------------------------------
inline constexpr std::uint32_t kWireMagicValue = 0x4E4C5050u;  // "PPLN"
inline constexpr std::size_t kWireHeaderBytes = 76;
inline constexpr std::size_t kWireIntegrityBytes = 16;
inline constexpr std::size_t kWirePayloadOffset = kWireHeaderBytes;

enum class WireMessage : std::uint32_t {
  kHello = 1,
  kRegisterWorker = 2,
  kPlanRequest = 3,
  kPlanResult = 4,
  kPlanError = 5,
  kValidateCurrentness = 6,
  kCurrentnessResult = 7,
  kSnapshotRequest = 8,
  kSnapshotResponse = 9,
  kFenceNotice = 10,
  kError = 11,
  kShutdownWorker = 12,
};

inline constexpr EnumEntry kWireMessageNames[] = {
    {"HELLO", 1},
    {"REGISTER_WORKER", 2},
    {"PLAN_REQUEST", 3},
    {"PLAN_RESULT", 4},
    {"PLAN_ERROR", 5},
    {"VALIDATE_CURRENTNESS", 6},
    {"CURRENTNESS_RESULT", 7},
    {"SNAPSHOT_REQUEST", 8},
    {"SNAPSHOT_RESPONSE", 9},
    {"FENCE_NOTICE", 10},
    {"ERROR", 11},
    {"SHUTDOWN_WORKER", 12},
};

inline std::string_view ToString(WireMessage value) { return EnumName(kWireMessageNames, value); }
inline std::optional<WireMessage> ParseWireMessage(std::string_view name) {
  return ParseEnum<WireMessage>(kWireMessageNames, name);
}

enum class WireStatus : std::uint32_t {
  kOk = 1,
  kMalformed = 2,
  kVersionMismatch = 3,
  kIntegrityMismatch = 4,
  kUnknownMessage = 5,
  kTooLarge = 6,
  kTrailingBytes = 7,
  kEpochStale = 8,
  kWorkerFenced = 9,
  kUnknownWorker = 10,
  kSnapshotMismatch = 11,
  kReceiveBoundExceeded = 12,
  kSessionLimit = 13,
  kNoWorkerAvailable = 14,
  kInternal = 15,
  kRequestMismatch = 16,
  kUnsupported = 17,
};

inline constexpr EnumEntry kWireStatusNames[] = {
    {"OK", 1},
    {"MALFORMED", 2},
    {"VERSION_MISMATCH", 3},
    {"INTEGRITY_MISMATCH", 4},
    {"UNKNOWN_MESSAGE", 5},
    {"TOO_LARGE", 6},
    {"TRAILING_BYTES", 7},
    {"EPOCH_STALE", 8},
    {"WORKER_FENCED", 9},
    {"UNKNOWN_WORKER", 10},
    {"SNAPSHOT_MISMATCH", 11},
    {"RECEIVE_BOUND_EXCEEDED", 12},
    {"SESSION_LIMIT", 13},
    {"NO_WORKER_AVAILABLE", 14},
    {"INTERNAL", 15},
    {"REQUEST_MISMATCH", 16},
    {"UNSUPPORTED", 17},
};

inline std::string_view ToString(WireStatus value) { return EnumName(kWireStatusNames, value); }

// Maps a wire status onto the closest planning diagnostic for reporting.
DiagnosticCode DiagnosticForWireStatus(WireStatus status) noexcept;

inline constexpr std::uint16_t kWireFlagResponse = 0x0001u;
inline constexpr std::uint16_t kWireFlagFenced = 0x0002u;
inline constexpr std::uint16_t kWireKnownFlags = kWireFlagResponse | kWireFlagFenced;

struct WireFrame {
  WireMessage type = WireMessage::kHello;
  std::uint16_t flags = 0;
  CoordinatorEpoch coordinator_epoch;
  std::uint64_t sequence = 0;
  WorkerBootId worker_boot;
  PlanningRequestId request;
  std::vector<std::byte> payload;
};

// Deterministic frame encoding.
std::vector<std::byte> EncodeFrame(const WireFrame& frame);

// Strict frame decoding. Rejects wrong magic, wrong protocol version, unknown
// message values, non-zero reserved fields, unknown flag bits, payload length
// disagreement, integrity mismatch and frames above max_frame_bytes.
WireStatus DecodeFrame(std::span<const std::byte> bytes, std::uint32_t max_frame_bytes, WireFrame& out,
                       std::string& detail);

// ---------------------------------------------------------------------------
// Payload codecs. Every decoder validates enumeration values, identifier
// encodings, counts against the supplied limits and rejects trailing bytes.
// ---------------------------------------------------------------------------
struct HelloPayload {
  PublisherId publisher;
  WorkerBootId boot;
  CoordinatorEpoch coordinator_epoch;
  SnapshotId snapshot;
  SnapshotGenerations generations;
  std::uint32_t node_count = 0;
  std::uint32_t edge_count = 0;
};

struct PlanErrorPayload {
  PlanningRequestId request;
  WireStatus status = WireStatus::kInternal;
  PlanStatus plan_status = PlanStatus::kNoPath;
  DiagnosticCode code = DiagnosticCode::kUnknownSourceEntity;
  std::string detail;
};

struct FenceNoticePayload {
  WorkerBootId boot;
  WireStatus status = WireStatus::kWorkerFenced;
  DiagnosticCode code = DiagnosticCode::kWorkerBootFenced;
  std::string detail;
};

struct SnapshotResponsePayload {
  SnapshotId snapshot;
  SnapshotGenerations generations;
  std::uint32_t node_count = 0;
  std::uint32_t edge_count = 0;
};

struct CurrentnessQueryPayload {
  PathPlanId plan;
  EvidenceVector evidence;
  PlanningRequestId request;
};

struct CurrentnessResultPayload {
  PathPlanId plan;
  Currentness currentness = Currentness::kRevalidationRequired;
  std::vector<ExplanationEntry> changes;
};

void EncodeHelloPayload(ByteWriter& writer, const HelloPayload& payload);
WireStatus DecodeHelloPayload(std::span<const std::byte> bytes, HelloPayload& payload, std::string& detail);

void EncodePlanningRequestPayload(ByteWriter& writer, const PlanningRequest& request);
WireStatus DecodePlanningRequestPayload(std::span<const std::byte> bytes, const ResourceLimits& limits,
                                        PlanningRequest& request, std::string& detail);

void EncodePlanningResultPayload(ByteWriter& writer, const PlanningResult& result);
WireStatus DecodePlanningResultPayload(std::span<const std::byte> bytes, const ResourceLimits& limits,
                                       PlanningResult& result, std::string& detail);

void EncodePlanErrorPayload(ByteWriter& writer, const PlanErrorPayload& payload);
WireStatus DecodePlanErrorPayload(std::span<const std::byte> bytes, PlanErrorPayload& payload, std::string& detail);

void EncodeFenceNoticePayload(ByteWriter& writer, const FenceNoticePayload& payload);
WireStatus DecodeFenceNoticePayload(std::span<const std::byte> bytes, FenceNoticePayload& payload,
                                    std::string& detail);

void EncodeSnapshotResponsePayload(ByteWriter& writer, const SnapshotResponsePayload& payload);
WireStatus DecodeSnapshotResponsePayload(std::span<const std::byte> bytes, SnapshotResponsePayload& payload,
                                         std::string& detail);

void EncodeCurrentnessQueryPayload(ByteWriter& writer, const CurrentnessQueryPayload& payload);
WireStatus DecodeCurrentnessQueryPayload(std::span<const std::byte> bytes, CurrentnessQueryPayload& payload,
                                         std::string& detail);

void EncodeCurrentnessResultPayload(ByteWriter& writer, const CurrentnessResultPayload& payload);
WireStatus DecodeCurrentnessResultPayload(std::span<const std::byte> bytes, const ResourceLimits& limits,
                                          CurrentnessResultPayload& payload, std::string& detail);

}  // namespace summon::pathplanner

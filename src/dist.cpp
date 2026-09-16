#include "pathplanner/dist.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "net.hpp"
#include "pathplanner/store.hpp"

namespace summon::pathplanner {
namespace {

using internal::kInvalidSocket;
using internal::RecvOutcome;
using internal::SocketHandle;

// Reads one complete framed message. The fixed header and the payload are each read
// under the configured receive bound, so a peer that stalls mid-frame produces an
// explicit bound failure instead of pinning the session thread.
RecvOutcome ReadFrame(SocketHandle socket, std::uint32_t max_frame_bytes, std::uint32_t bound_ms, WireFrame& frame,
                      std::string& detail) {
  std::vector<std::byte> header(kWireHeaderBytes);
  const RecvOutcome header_outcome =
      internal::RecvExact(socket, std::span<std::byte>(header.data(), header.size()), bound_ms, detail);
  if (header_outcome != RecvOutcome::kOk) {
    return header_outcome;
  }
  // payload_bytes sits at a fixed header offset and is validated before allocation.
  const std::size_t payload_length_offset = 4 + 2 + 2 + 4 + 8 + 8 + 8 + 16;
  std::uint32_t payload_bytes = 0;
  for (int index = 0; index < 4; ++index) {
    const std::size_t offset = payload_length_offset + static_cast<std::size_t>(index);
    payload_bytes |= static_cast<std::uint32_t>(static_cast<std::uint8_t>(header[offset])) << (8 * index);
  }
  if (payload_bytes > max_frame_bytes) {
    detail = "declared payload length exceeds the configured frame ceiling";
    return RecvOutcome::kError;
  }
  std::vector<std::byte> bytes(kWireHeaderBytes + static_cast<std::size_t>(payload_bytes));
  std::copy(header.begin(), header.end(), bytes.begin());
  if (payload_bytes > 0) {
    const RecvOutcome payload_outcome = internal::RecvExact(
        socket, std::span<std::byte>(bytes.data() + kWireHeaderBytes, payload_bytes), bound_ms, detail);
    if (payload_outcome != RecvOutcome::kOk) {
      return payload_outcome;
    }
  }
  std::string decode_detail;
  const WireStatus status = DecodeFrame(std::span<const std::byte>(bytes.data(), bytes.size()), max_frame_bytes, frame,
                                        decode_detail);
  if (status != WireStatus::kOk) {
    detail = "frame rejected: " + decode_detail;
    return RecvOutcome::kError;
  }
  return RecvOutcome::kOk;
}

bool SendFrame(SocketHandle socket, WireMessage type, std::uint16_t flags, CoordinatorEpoch epoch, std::uint64_t sequence,
               const WorkerBootId& boot, const PlanningRequestId& request, std::span<const std::byte> payload,
               std::string& error) {
  WireFrame frame;
  frame.type = type;
  frame.flags = flags;
  frame.coordinator_epoch = epoch;
  frame.sequence = sequence;
  frame.worker_boot = boot;
  frame.request = request;
  frame.payload.assign(payload.begin(), payload.end());
  const std::vector<std::byte> bytes = EncodeFrame(frame);
  return internal::SendAll(socket, std::span<const std::byte>(bytes.data(), bytes.size()), error);
}

std::string BootKey(const WorkerBootId& boot) { return boot.ToString(); }
std::string RequestKey(const PlanningRequestId& request) { return request.ToString(); }

std::array<std::byte, 8> EntropyBytes() {
  std::random_device device;
  std::array<std::byte, 8> bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    bytes[index] = static_cast<std::byte>(device() & 0xFFu);
  }
  bool any = false;
  for (const std::byte value : bytes) {
    if (value != std::byte{0}) {
      any = true;
      break;
    }
  }
  if (!any) {
    bytes[0] = std::byte{1};
  }
  return bytes;
}

}  // namespace

WorkerBootId MakeWorkerBootIdFromLabel(const std::string& label) {
  return WorkerBootId::FromDigest(Sha256::Hash(label));
}

PublisherId MakePublisherIdFromLabel(const std::string& label) {
  return PublisherId::FromDigest(Sha256::Hash(label));
}

WorkerBootId GenerateWorkerBootId() { return WorkerBootId::FromBytes(EntropyBytes()); }
PublisherId GeneratePublisherId() { return PublisherId::FromBytes(EntropyBytes()); }

// ---------------------------------------------------------------------------
// Coordinator.
// ---------------------------------------------------------------------------
struct Coordinator::Impl {
  struct Pending {
    bool ready = false;
    WireStatus status = WireStatus::kInternal;
    std::vector<std::byte> payload;
    std::vector<std::byte> request_payload;
    std::string detail;
    std::string worker_key;
  };

  struct Session {
    SocketHandle socket = kInvalidSocket;
    std::thread thread;
    std::atomic<bool> finished{false};
    bool worker_role = false;
    std::string boot_key;
    std::string outstanding_request;
  };

  explicit Impl(CoordinatorConfig configuration)
      : config(std::move(configuration)), runtime(MakeRuntimeConfig(config)), epoch(config.initial_epoch) {}

  static PlannerConfig MakeRuntimeConfig(const CoordinatorConfig& configuration) {
    PlannerConfig runtime_config;
    runtime_config.limits = configuration.limits;
    runtime_config.initial_snapshot = configuration.snapshot;
    return runtime_config;
  }

  CoordinatorConfig config;
  PlannerRuntime runtime;
  mutable std::mutex mutex;
  std::condition_variable pending_cv;
  SocketHandle listener = kInvalidSocket;
  std::thread accept_thread;
  std::atomic<bool> running{false};
  std::atomic<bool> stopping{false};
  std::vector<std::unique_ptr<Session>> sessions;
  std::map<std::string, WorkerRegistration> workers;
  std::set<std::string> fenced_boots;
  std::map<std::string, Pending> pending;
  std::uint64_t next_sequence = 1;
  FabricEpoch epoch;
  std::atomic<std::size_t> session_count{0};
  std::atomic<std::uint16_t> bound_port{0};
  std::atomic<std::uint64_t> accepted_publications{0};
  std::atomic<std::size_t> recovered_plans{0};

  // Retains an accepted publication and, when a store path is configured, persists the
  // bounded planning history atomically.
  void RetainAccepted(const std::vector<std::byte>& request_payload, const std::vector<std::byte>& result_payload,
                      PlanPublishSequence sequence) {
    PlanningRequest request;
    PlanningResult result;
    std::string detail;
    if (DecodePlanningRequestPayload(std::span<const std::byte>(request_payload.data(), request_payload.size()),
                                     config.limits, request, detail) != WireStatus::kOk) {
      return;
    }
    if (DecodePlanningResultPayload(std::span<const std::byte>(result_payload.data(), result_payload.size()),
                                    config.limits, result, detail) != WireStatus::kOk) {
      return;
    }
    const PathPlan plan = MakePathPlan(request, result, sequence);
    if (runtime.Retain(plan)) {
      std::lock_guard<std::mutex> lock(mutex);
      retained_ids.push_back(plan.id);
    }
    if (!config.store_path.empty()) {
      std::string store_error;
      static_cast<void>(SaveStore(store_error));
    }
  }

  bool SaveStore(std::string& error) const {
    if (config.store_path.empty()) {
      error = "no store path is configured";
      return false;
    }
    std::vector<StoredPlanRecord> records;
    for (const auto& entry : retained_snapshot()) {
      records.push_back(ToStoredRecord(entry));
    }
    StoreOptions options;
    options.limits = config.limits;
    options.publish_sequence = runtime.PublishSequence();
    const StoreResult saved = SavePlanStore(config.store_path, records, options);
    if (!saved.ok) {
      error = saved.detail;
      return false;
    }
    return true;
  }

  // Snapshot of the retained plans (deterministic order by plan id).
  std::vector<PathPlan> retained_snapshot() const {
    std::vector<PathPlanId> ids;
    {
      std::lock_guard<std::mutex> lock(mutex);
      ids = retained_ids;
    }
    std::vector<PathPlan> plans;
    for (const PathPlanId& id : ids) {
      const std::optional<PathPlan> plan = runtime.FindPlan(id);
      if (plan.has_value()) {
        plans.push_back(*plan);
      }
    }
    return plans;
  }

  void RecoverStore() {
    if (config.store_path.empty()) {
      return;
    }
    std::vector<StoredPlanRecord> records;
    const StoreResult loaded = LoadPlanStore(config.store_path, config.limits, records);
    if (!loaded.ok) {
      return;
    }
    for (const StoredPlanRecord& record : records) {
      PathPlan plan = FromStoredRecord(record);
      // Conservative recovery: recovered authority is never resumed blindly.
      plan.currentness_proven = false;
      for (Candidate& candidate : plan.candidates) {
        candidate.currentness = Currentness::kRevalidationRequired;
      }
      if (runtime.Retain(plan)) {
        retained_ids.push_back(plan.id);
        recovered_plans.fetch_add(1);
      }
    }
  }

  mutable std::vector<PathPlanId> retained_ids;

  SnapshotId CurrentSnapshotId() const {
    const std::shared_ptr<const FabricSnapshot> snapshot = runtime.CurrentSnapshot();
    return snapshot == nullptr ? SnapshotId{} : snapshot->Id();
  }

  // The Fabric Epoch the coordinator consumes is mirrored onto the wire as a
  // CoordinatorEpoch. The conversion is explicit because the two are separate
  // identity domains that must never be interchangeable implicitly.
  CoordinatorEpoch SendEpoch() const {
    std::lock_guard<std::mutex> lock(mutex);
    return CoordinatorEpoch(epoch.Value());
  }

  WireStatus ValidatePublication(const WorkerBootId& boot, CoordinatorEpoch epoch_value, const SnapshotId& snapshot,
                                 std::string& detail) const;

  SnapshotGenerations CurrentGenerations() const {
    const std::shared_ptr<const FabricSnapshot> snapshot = runtime.CurrentSnapshot();
    return snapshot == nullptr ? SnapshotGenerations{} : snapshot->Generations();
  }

  void SendFenceNotice(SocketHandle socket, const WorkerBootId& boot, CoordinatorEpoch send_epoch, WireStatus status,
                       DiagnosticCode code, const std::string& detail) {
    FenceNoticePayload payload;
    payload.boot = boot;
    payload.status = status;
    payload.code = code;
    payload.detail = detail;
    ByteWriter writer(config.limits.max_frame_bytes);
    EncodeFenceNoticePayload(writer, payload);
    std::string error;
    static_cast<void>(SendFrame(socket, WireMessage::kFenceNotice, kWireFlagFenced, send_epoch, 0, boot,
                                PlanningRequestId{}, writer.span(), error));
  }

  void SendError(SocketHandle socket, CoordinatorEpoch send_epoch, const PlanningRequestId& request, WireStatus status,
                 PlanStatus plan_status, DiagnosticCode code, const std::string& detail) {
    PlanErrorPayload payload;
    payload.request = request;
    payload.status = status;
    payload.plan_status = plan_status;
    payload.code = code;
    payload.detail = detail;
    ByteWriter writer(config.limits.max_frame_bytes);
    EncodePlanErrorPayload(writer, payload);
    std::string error;
    static_cast<void>(SendFrame(socket, WireMessage::kPlanError, kWireFlagResponse, send_epoch, 0, WorkerBootId{},
                                request, writer.span(), error));
  }

  void HandleHandshake(Session& session, const WireFrame& frame);

  void HandleWorkerPublication(Session& session, const WireFrame& frame);
  void HandleClientFrame(Session& session, const WireFrame& frame);
  void HandleSnapshotRequest(Session& session, const WireFrame& frame, CoordinatorEpoch send_epoch,
                             const WorkerBootId& boot);
  // The session loop borrows a session owned by the sessions vector; it never deletes it.
  void SessionLoop(Session& session);
  void AcceptLoop();
  void ReleaseSession(Session& session);
};

WireStatus Coordinator::Impl::ValidatePublication(const WorkerBootId& boot, CoordinatorEpoch epoch_value,
                                                  const SnapshotId& snapshot, std::string& detail) const {
  std::lock_guard<std::mutex> lock(mutex);
  const std::string key = BootKey(boot);
  if (fenced_boots.count(key) != 0) {
    detail = "worker boot identity is fenced";
    return WireStatus::kWorkerFenced;
  }
  const auto registration = workers.find(key);
  if (registration == workers.end() || registration->second.fenced) {
    detail = "worker boot identity is not registered";
    return WireStatus::kUnknownWorker;
  }
  if (epoch_value.Value() != epoch.Value()) {
    detail = "worker coordinator epoch " + epoch_value.ToString() + " is stale (current " + epoch.ToString() + ")";
    return WireStatus::kEpochStale;
  }
  const std::shared_ptr<const FabricSnapshot> current = runtime.CurrentSnapshot();
  const SnapshotId current_id = current == nullptr ? SnapshotId{} : current->Id();
  if (!current_id.IsValid() || snapshot != current_id) {
    detail = "worker evidence does not match the current coordinator snapshot";
    return WireStatus::kSnapshotMismatch;
  }
  return WireStatus::kOk;
}

void Coordinator::Impl::ReleaseSession(Session& session) {
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (session.worker_role && !session.boot_key.empty()) {
      const auto registration = workers.find(session.boot_key);
      if (registration != workers.end()) {
        workers.erase(registration);
      }
      // Session loss fences the boot identity: a late publication from the same boot
      // can never be accepted again, and a restarted process receives a fresh boot id.
      fenced_boots.insert(session.boot_key);
    }
    const std::string outstanding = session.outstanding_request;
    if (!outstanding.empty()) {
      const auto slot = pending.find(outstanding);
      if (slot != pending.end() && !slot->second.ready) {
        slot->second.ready = true;
        slot->second.status = WireStatus::kUnknownWorker;
        slot->second.detail = "worker session ended before it published a result";
      }
    }
  }
  pending_cv.notify_all();
}

void Coordinator::Impl::HandleHandshake(Session& session, const WireFrame& frame) {
  HelloPayload hello;
  std::string detail;
  const WireStatus decode = DecodeHelloPayload(std::span<const std::byte>(frame.payload.data(), frame.payload.size()),
                                               hello, detail);
  if (decode != WireStatus::kOk) {
    SendError(session.socket, SendEpoch(), frame.request, decode, PlanStatus::kMalformedRequest,
              DiagnosticForWireStatus(decode), detail);
    return;
  }
  if (hello.boot != frame.worker_boot) {
    SendError(session.socket, SendEpoch(), frame.request, WireStatus::kMalformed, PlanStatus::kMalformedRequest,
              DiagnosticCode::kWorkerBootFenced,
              "handshake boot identity does not match the frame worker identity");
    return;
  }

  SnapshotId snapshot_id;
  SnapshotGenerations generations;
  FabricEpoch current_fabric_epoch;
  {
    std::lock_guard<std::mutex> lock(mutex);
    snapshot_id = CurrentSnapshotId();
    generations = CurrentGenerations();
    current_fabric_epoch = epoch;
  }

  const std::string key = BootKey(hello.boot);
  WireStatus acceptance = WireStatus::kOk;
  std::string fence_detail;
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (fenced_boots.count(key) != 0) {
      acceptance = WireStatus::kWorkerFenced;
      fence_detail = "worker boot identity was fenced by session loss or an administrative fence";
    } else if (hello.coordinator_epoch.Value() != current_fabric_epoch.Value()) {
      acceptance = WireStatus::kEpochStale;
      fence_detail = "worker coordinator epoch " + hello.coordinator_epoch.ToString() +
                     " does not match the current epoch " + current_fabric_epoch.ToString();
    } else if (!snapshot_id.IsValid() || hello.snapshot != snapshot_id) {
      acceptance = WireStatus::kSnapshotMismatch;
      fence_detail = "worker evidence does not match the coordinator snapshot";
    }
  }
  if (acceptance != WireStatus::kOk) {
    const CoordinatorEpoch wire_epoch(current_fabric_epoch.Value());
    if (acceptance == WireStatus::kSnapshotMismatch) {
      SendError(session.socket, wire_epoch, frame.request, acceptance, PlanStatus::kRevalidationRequired,
                DiagnosticCode::kStaleEvidence, fence_detail);
    } else {
      SendFenceNotice(session.socket, hello.boot, wire_epoch, acceptance, DiagnosticForWireStatus(acceptance),
                      fence_detail);
    }
    return;
  }

  {
    std::lock_guard<std::mutex> lock(mutex);
    WorkerRegistration registration;
    registration.boot = hello.boot;
    registration.publisher = hello.publisher;
    registration.snapshot = hello.snapshot;
    registration.generations = hello.generations;
    registration.registered_epoch = CoordinatorEpoch(current_fabric_epoch.Value());
    workers[key] = registration;
    session.worker_role = true;
    session.boot_key = key;
  }

  SnapshotResponsePayload response;
  response.snapshot = snapshot_id;
  response.generations = generations;
  response.node_count = 0;
  response.edge_count = 0;
  ByteWriter writer(config.limits.max_frame_bytes);
  EncodeSnapshotResponsePayload(writer, response);
  std::string error;
  static_cast<void>(SendFrame(session.socket, WireMessage::kSnapshotResponse, kWireFlagResponse,
                              CoordinatorEpoch(current_fabric_epoch.Value()), 0, hello.boot, frame.request,
                              writer.span(), error));
}

void Coordinator::Impl::HandleWorkerPublication(Session& session, const WireFrame& frame) {
  const std::string key = BootKey(frame.worker_boot);
  SnapshotId worker_snapshot;
  {
    std::lock_guard<std::mutex> lock(mutex);
    const auto registration = workers.find(key);
    if (registration != workers.end()) {
      worker_snapshot = registration->second.snapshot;
    }
  }
  std::string detail;
  const WireStatus acceptance = ValidatePublication(frame.worker_boot, frame.coordinator_epoch, worker_snapshot, detail);
  const std::string request_key = RequestKey(frame.request);
  bool retain = false;
  std::vector<std::byte> request_payload;
  {
    std::lock_guard<std::mutex> lock(mutex);
    const auto registration = workers.find(key);
    if (acceptance != WireStatus::kOk) {
      if (registration != workers.end()) {
        workers[key].publications_rejected += 1;
      }
    } else if (registration != workers.end()) {
      workers[key].plans_completed += 1;
    }
    const auto slot = pending.find(request_key);
    if (slot != pending.end() && !slot->second.ready) {
      if (acceptance == WireStatus::kOk) {
        slot->second.status = WireStatus::kOk;
        slot->second.payload = frame.payload;
        request_payload = slot->second.request_payload;
        accepted_publications.fetch_add(1);
        retain = true;
      } else {
        slot->second.status = acceptance;
        slot->second.detail = detail;
      }
      slot->second.ready = true;
    }
  }
  pending_cv.notify_all();
  // Retention runs outside the session lock: it re-enters the runtime and, when a store is
  // configured, the persistence layer, neither of which may be called under this lock.
  if (retain) {
    RetainAccepted(request_payload, frame.payload, runtime.PublishSequence());
  }
  if (acceptance != WireStatus::kOk) {
    SendFenceNotice(session.socket, frame.worker_boot, CoordinatorEpoch(epoch.Value()), acceptance,
                    DiagnosticForWireStatus(acceptance), detail);
  }
}

void Coordinator::Impl::HandleSnapshotRequest(Session& session, const WireFrame& frame, CoordinatorEpoch send_epoch,
                                              const WorkerBootId& boot) {
  SnapshotResponsePayload response;
  {
    std::lock_guard<std::mutex> lock(mutex);
    response.snapshot = CurrentSnapshotId();
    response.generations = CurrentGenerations();
  }
  ByteWriter writer(config.limits.max_frame_bytes);
  EncodeSnapshotResponsePayload(writer, response);
  std::string error;
  static_cast<void>(SendFrame(session.socket, WireMessage::kSnapshotResponse, kWireFlagResponse, send_epoch, 0, boot,
                              frame.request, writer.span(), error));
}

void Coordinator::Impl::HandleClientFrame(Session& session, const WireFrame& frame) {
  const CoordinatorEpoch send_epoch = SendEpoch();
  switch (frame.type) {
    case WireMessage::kSnapshotRequest:
      HandleSnapshotRequest(session, frame, send_epoch, WorkerBootId{});
      return;
    case WireMessage::kValidateCurrentness: {
      CurrentnessQueryPayload query;
      std::string detail;
      const WireStatus decode = DecodeCurrentnessQueryPayload(
          std::span<const std::byte>(frame.payload.data(), frame.payload.size()), query, detail);
      if (decode != WireStatus::kOk) {
        SendError(session.socket, send_epoch, frame.request, decode, PlanStatus::kMalformedRequest,
                  DiagnosticForWireStatus(decode), detail);
        return;
      }
      CurrentnessResultPayload answer;
      answer.plan = query.plan;
      const std::shared_ptr<const FabricSnapshot> snapshot = runtime.CurrentSnapshot();
      if (snapshot != nullptr) {
        answer.currentness = ClassifyEvidence(query.evidence, snapshot->Evidence());
      } else {
        answer.currentness = Currentness::kRevalidationRequired;
      }
      if (answer.currentness == Currentness::kCurrent &&
          query.evidence.publish_sequence != runtime.PublishSequence()) {
        answer.currentness = Currentness::kRevalidationRequired;
        answer.changes.push_back(ExplanationEntry{DiagnosticCode::kInvalidationWatermarkChanged,
                                                  "the coordinator publication watermark advanced"});
      }
      ByteWriter writer(config.limits.max_frame_bytes);
      EncodeCurrentnessResultPayload(writer, answer);
      std::string error;
      static_cast<void>(SendFrame(session.socket, WireMessage::kCurrentnessResult, kWireFlagResponse, send_epoch, 0,
                                  WorkerBootId{}, frame.request, writer.span(), error));
      return;
    }
    case WireMessage::kPlanRequest: {
      PlanningRequest request;
      std::string detail;
      const WireStatus decode = DecodePlanningRequestPayload(
          std::span<const std::byte>(frame.payload.data(), frame.payload.size()), config.limits, request, detail);
      if (decode != WireStatus::kOk) {
        SendError(session.socket, send_epoch, frame.request, decode, PlanStatus::kMalformedRequest,
                  DiagnosticForWireStatus(decode), detail);
        return;
      }
      if (request.id != frame.request) {
        SendError(session.socket, send_epoch, frame.request, WireStatus::kRequestMismatch,
                  PlanStatus::kMalformedRequest, DiagnosticCode::kProtocolMalformedFrame,
                  "frame request identity does not match the decoded request");
        return;
      }

      const std::string request_key = RequestKey(request.id);
      SocketHandle worker_socket = kInvalidSocket;
      WireFrame relayed;
      {
        std::lock_guard<std::mutex> lock(mutex);
        Session* chosen = nullptr;
        for (const std::unique_ptr<Session>& candidate : sessions) {
          if (!candidate->worker_role || candidate->finished.load() || !candidate->outstanding_request.empty()) {
            continue;
          }
          const auto registration = workers.find(candidate->boot_key);
          if (registration == workers.end() || registration->second.fenced) {
            continue;
          }
          chosen = candidate.get();
          break;
        }
        if (chosen == nullptr) {
          Pending slot;
          slot.ready = true;
          slot.status = WireStatus::kNoWorkerAvailable;
          slot.detail = "no registered worker is available for this request";
          // The dispatch below sees a nil worker socket and leaves this verdict intact.
          pending[request_key] = slot;
        } else {
          Pending slot;
          slot.worker_key = chosen->boot_key;
          slot.request_payload.assign(frame.payload.begin(), frame.payload.end());
          pending[request_key] = slot;
          chosen->outstanding_request = request_key;
          worker_socket = chosen->socket;
          relayed.type = WireMessage::kPlanRequest;
          relayed.coordinator_epoch = CoordinatorEpoch(epoch.Value());
          relayed.sequence = next_sequence;
          next_sequence += 1;
          relayed.worker_boot = WorkerBootId{};
          relayed.request = request.id;
          relayed.payload.assign(frame.payload.begin(), frame.payload.end());
        }
      }

      bool relayed_ok = worker_socket != kInvalidSocket;
      if (relayed_ok) {
        const std::vector<std::byte> relay_bytes = EncodeFrame(relayed);
        std::string send_error;
        relayed_ok = internal::SendAll(
            worker_socket, std::span<const std::byte>(relay_bytes.data(), relay_bytes.size()), send_error);
      }
      if (!relayed_ok && worker_socket != kInvalidSocket) {
        std::lock_guard<std::mutex> lock(mutex);
        pending[request_key].ready = true;
        pending[request_key].status = WireStatus::kNoWorkerAvailable;
        pending[request_key].detail = "worker session is not writable";
      }

      WireStatus status = WireStatus::kInternal;
      std::vector<std::byte> payload;
      std::string pending_detail;
      {
        std::unique_lock<std::mutex> lock(mutex);
        static_cast<void>(pending_cv.wait_for(
            lock, std::chrono::milliseconds(config.limits.receive_bound_ms), [this, &request_key]() {
              const auto entry = pending.find(request_key);
              return entry == pending.end() || entry->second.ready;
            }));
        const auto entry = pending.find(request_key);
        if (entry == pending.end()) {
          status = WireStatus::kInternal;
          pending_detail = "internal dispatch state was lost";
        } else if (!entry->second.ready) {
          status = WireStatus::kReceiveBoundExceeded;
          pending_detail = "worker did not publish a result within the receive bound";
          pending.erase(entry);
        } else {
          status = entry->second.status;
          payload = entry->second.payload;
          pending_detail = entry->second.detail;
          pending.erase(entry);
        }
        for (const std::unique_ptr<Session>& candidate : sessions) {
          if (candidate->outstanding_request == request_key) {
            candidate->outstanding_request.clear();
          }
        }
      }
      if (status == WireStatus::kOk) {
        std::string error;
        static_cast<void>(SendFrame(session.socket, WireMessage::kPlanResult, kWireFlagResponse, send_epoch, 0,
                                    WorkerBootId{}, frame.request,
                                    std::span<const std::byte>(payload.data(), payload.size()), error));
      } else {
        SendError(session.socket, send_epoch, frame.request, status, PlanStatus::kRevalidationRequired,
                  DiagnosticForWireStatus(status), pending_detail);
      }
      return;
    }
    default:
      SendError(session.socket, send_epoch, frame.request, WireStatus::kUnsupported, PlanStatus::kUnsupported,
                DiagnosticCode::kUnsupportedRequest, "unsupported message for a client session");
      return;
  }
}

void Coordinator::Impl::SessionLoop(Session& session) {
  std::string detail;
  WireFrame frame;
  while (!stopping.load()) {
    const RecvOutcome outcome = ReadFrame(session.socket, config.limits.max_frame_bytes,
                                          config.limits.receive_bound_ms, frame, detail);
    if (outcome != RecvOutcome::kOk) {
      break;
    }
    const CoordinatorEpoch send_epoch = SendEpoch();
    if (frame.type == WireMessage::kHello || frame.type == WireMessage::kRegisterWorker) {
      HandleHandshake(session, frame);
      if (!session.worker_role) {
        break;  // registration refused: the coordinator already sent the reason
      }
      continue;
    }
    if (session.worker_role) {
      if (frame.type == WireMessage::kPlanResult) {
        HandleWorkerPublication(session, frame);
      } else if (frame.type == WireMessage::kSnapshotRequest) {
        HandleSnapshotRequest(session, frame, send_epoch, WorkerBootId{});
      } else if (frame.type == WireMessage::kValidateCurrentness) {
        HandleClientFrame(session, frame);
      }
      continue;
    }
    HandleClientFrame(session, frame);
  }
  session.finished.store(true);
  internal::ShutdownSocket(session.socket);
  ReleaseSession(session);
  internal::CloseSocket(session.socket);
  session.socket = kInvalidSocket;
  session_count.fetch_sub(1);
}

void Coordinator::Impl::AcceptLoop() {
  while (!stopping.load()) {
    std::string error;
    const SocketHandle accepted = internal::AcceptConnection(listener, error);
    if (accepted == kInvalidSocket) {
      if (stopping.load()) {
        return;
      }
      continue;
    }
    internal::SetNoDelay(accepted);
    internal::SetSendTimeout(accepted, config.limits.send_bound_ms);
    if (session_count.load() >= static_cast<std::size_t>(config.limits.max_sessions)) {
      internal::ShutdownSocket(accepted);
      internal::CloseSocket(accepted);
      continue;
    }
    auto session = std::make_unique<Session>();
    session->socket = accepted;
    session_count.fetch_add(1);
    {
      // The session object is owned by the sessions vector and borrowed by its thread.
      // Starting the thread while holding the lock guarantees that a concurrent Stop()
      // either observes a joinable thread or observes no session at all.
      std::lock_guard<std::mutex> lock(mutex);
      sessions.push_back(std::move(session));
      Session* borrowed = sessions.back().get();
      borrowed->thread = std::thread([this, borrowed]() { SessionLoop(*borrowed); });
    }
  }
}

Coordinator::Coordinator(CoordinatorConfig config) : impl_(std::make_unique<Impl>(std::move(config))) {}

Coordinator::~Coordinator() { Stop(); }

bool Coordinator::Start(std::string& error) {
  if (impl_->running.load()) {
    error = "coordinator is already running";
    return false;
  }
  if (!internal::SocketRuntimeEnsure(error)) {
    return false;
  }
  if (const std::optional<DiagnosticCode> limits = ValidateLimits(impl_->config.limits); limits.has_value()) {
    error = "invalid resource limits: " + std::string(ToString(*limits));
    return false;
  }
  if (!internal::ValidateHostString(impl_->config.bind_address)) {
    error = "invalid bind address";
    return false;
  }
  impl_->stopping.store(false);
  impl_->listener = internal::CreateListener(impl_->config.bind_address, impl_->config.port, error);
  if (impl_->listener == kInvalidSocket) {
    return false;
  }
  std::uint16_t bound = 0;
  if (!internal::ListenerBoundPort(impl_->listener, bound)) {
    error = "cannot determine the bound listener port";
    internal::CloseSocket(impl_->listener);
    impl_->listener = kInvalidSocket;
    return false;
  }
  impl_->bound_port.store(bound);
  impl_->RecoverStore();
  impl_->running.store(true);
  impl_->accept_thread = std::thread([this]() { impl_->AcceptLoop(); });
  return true;
}

void Coordinator::Stop() {
  if (!impl_) {
    return;
  }
  if (!impl_->running.exchange(false)) {
    return;
  }
  impl_->stopping.store(true);
  if (impl_->listener != kInvalidSocket) {
    internal::ShutdownSocket(impl_->listener);
    internal::CloseSocket(impl_->listener);
    impl_->listener = kInvalidSocket;
  }
  if (impl_->accept_thread.joinable()) {
    impl_->accept_thread.join();
  }
  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    for (const std::unique_ptr<Impl::Session>& session : impl_->sessions) {
      internal::ShutdownSocket(session->socket);
    }
  }
  impl_->pending_cv.notify_all();
  std::vector<std::thread> threads;
  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    for (const std::unique_ptr<Impl::Session>& session : impl_->sessions) {
      if (session->thread.joinable()) {
        threads.push_back(std::move(session->thread));
      }
    }
  }
  for (std::thread& thread : threads) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->sessions.clear();
    impl_->workers.clear();
    impl_->pending.clear();
  }
}

bool Coordinator::running() const { return impl_->running.load(); }

std::uint16_t Coordinator::Port() const { return impl_->bound_port.load(); }

std::string Coordinator::Endpoint() const {
  return internal::FormatEndpoint(impl_->config.bind_address, Port());
}

FabricEpoch Coordinator::Epoch() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->epoch;
}

bool Coordinator::AdvanceEpoch(FabricEpoch new_epoch, std::string& error) {
  std::vector<SocketHandle> sockets;
  std::vector<WorkerBootId> boots;
  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (new_epoch <= impl_->epoch) {
      error =
          "epoch " + new_epoch.ToString() + " is not greater than the current epoch " + impl_->epoch.ToString();
      return false;
    }
    impl_->epoch = new_epoch;
    for (const auto& entry : impl_->workers) {
      boots.push_back(entry.second.boot);
    }
    for (const std::unique_ptr<Impl::Session>& session : impl_->sessions) {
      if (session->worker_role) {
        sockets.push_back(session->socket);
        if (!session->boot_key.empty()) {
          impl_->fenced_boots.insert(session->boot_key);
        }
      }
    }
    impl_->workers.clear();
  }
  std::string runtime_reason;
  // Conservative recovery: every retained plan requires revalidation and no prior live
  // worker authority survives.
  static_cast<void>(impl_->runtime.AdvanceEpoch(new_epoch, true, runtime_reason));
  for (std::size_t index = 0; index < sockets.size(); ++index) {
    const WorkerBootId boot = index < boots.size() ? boots[index] : WorkerBootId{};
    impl_->SendFenceNotice(sockets[index], boot, CoordinatorEpoch(new_epoch.Value()), WireStatus::kEpochStale,
                           DiagnosticCode::kCoordinatorEpochStale,
                           "the coordinator epoch advanced; this worker incarnation must restart");
  }
  return true;
}

void Coordinator::PublishSnapshot(std::shared_ptr<const FabricSnapshot> snapshot, FabricEpoch epoch) {
  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (epoch > impl_->epoch) {
      impl_->epoch = epoch;
    }
  }
  impl_->runtime.PublishSnapshot(std::move(snapshot));
}

bool Coordinator::FenceWorker(const WorkerBootId& boot, std::string& error) {
  SocketHandle socket = kInvalidSocket;
  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    const std::string key = BootKey(boot);
    const auto entry = impl_->workers.find(key);
    if (entry == impl_->workers.end()) {
      error = "worker boot identity is not registered";
      return false;
    }
    entry->second.fenced = true;
    impl_->fenced_boots.insert(key);
    for (const std::unique_ptr<Impl::Session>& session : impl_->sessions) {
      if (session->boot_key == key) {
        socket = session->socket;
      }
    }
  }
  if (socket == kInvalidSocket) {
    error = "worker session is no longer present";
    return false;
  }
  impl_->SendFenceNotice(socket, boot, CoordinatorEpoch(Epoch().Value()), WireStatus::kWorkerFenced,
                         DiagnosticCode::kWorkerBootFenced,
                         "the coordinator fenced this worker boot identity");
  return true;
}

std::vector<WorkerRegistration> Coordinator::Workers() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  std::vector<WorkerRegistration> result;
  result.reserve(impl_->workers.size());
  for (const auto& entry : impl_->workers) {
    result.push_back(entry.second);
  }
  return result;
}

std::size_t Coordinator::SessionCount() const { return impl_->session_count.load(); }

PlannerStatistics Coordinator::Stats() const { return impl_->runtime.Stats(); }

std::uint64_t Coordinator::AcceptedPublications() const { return impl_->accepted_publications.load(); }

std::size_t Coordinator::RecoveredPlanCount() const { return impl_->recovered_plans.load(); }

bool Coordinator::SaveStore(std::string& error) const {
  error.clear();
  if (impl_->config.store_path.empty()) {
    error = "no store path is configured";
    return false;
  }
  std::vector<StoredPlanRecord> records;
  for (const PathPlan& plan : impl_->retained_snapshot()) {
    records.push_back(ToStoredRecord(plan));
  }
  StoreOptions options;
  options.limits = impl_->config.limits;
  options.publish_sequence = impl_->runtime.PublishSequence();
  const StoreResult saved = SavePlanStore(impl_->config.store_path, records, options);
  if (!saved.ok) {
    error = saved.detail;
    return false;
  }
  return true;
}

WireStatus Coordinator::ValidateWorkerPublication(const WorkerBootId& boot, CoordinatorEpoch epoch,
                                                  const SnapshotId& snapshot, std::string& detail) const {
  return impl_->ValidatePublication(boot, epoch, snapshot, detail);
}

const PlannerRuntime& Coordinator::Runtime() const { return impl_->runtime; }
PlannerRuntime& Coordinator::Runtime() { return impl_->runtime; }

// ---------------------------------------------------------------------------
// Worker.
// ---------------------------------------------------------------------------
struct Worker::Impl {
  explicit Impl(WorkerConfig configuration)
      : config(std::move(configuration)), runtime(MakeRuntimeConfig(config)) {}

  static PlannerConfig MakeRuntimeConfig(const WorkerConfig& configuration) {
    PlannerConfig runtime_config;
    runtime_config.limits = configuration.limits;
    runtime_config.initial_snapshot = configuration.snapshot;
    return runtime_config;
  }

  WorkerConfig config;
  PlannerRuntime runtime;
  std::atomic<bool> stopping{false};
  std::atomic<bool> fenced_flag{false};
  std::atomic<bool> registered_flag{false};
  std::atomic<std::uint64_t> plans_served{0};
  std::atomic<std::uint64_t> results_rejected{0};
  mutable std::mutex mutex;
  SocketHandle socket = kInvalidSocket;

  void CloseSocketLocked() {
    std::lock_guard<std::mutex> lock(mutex);
    if (socket != kInvalidSocket) {
      internal::ShutdownSocket(socket);
      internal::CloseSocket(socket);
      socket = kInvalidSocket;
    }
  }
};

Worker::Worker(WorkerConfig config) : impl_(std::make_unique<Impl>(std::move(config))) {
  if (!impl_->config.boot.IsValid()) {
    impl_->config.boot = GenerateWorkerBootId();
  }
  if (!impl_->config.publisher.IsValid()) {
    impl_->config.publisher = GeneratePublisherId();
  }
}

Worker::~Worker() {
  Stop();
  impl_->CloseSocketLocked();
}

void Worker::Stop() {
  impl_->stopping.store(true);
  impl_->CloseSocketLocked();
}

bool Worker::fenced() const { return impl_->fenced_flag.load(); }
bool Worker::registered() const { return impl_->registered_flag.load(); }
WorkerBootId Worker::Boot() const { return impl_->config.boot; }
std::uint64_t Worker::PlansServed() const { return impl_->plans_served.load(); }
std::uint64_t Worker::ResultsRejected() const { return impl_->results_rejected.load(); }

bool Worker::Run(std::string& error) {
  std::string host;
  std::uint16_t port = 0;
  if (!internal::ParseEndpoint(impl_->config.coordinator_endpoint, host, port)) {
    error = "invalid coordinator endpoint: " + impl_->config.coordinator_endpoint;
    return false;
  }
  if (!internal::SocketRuntimeEnsure(error)) {
    return false;
  }
  const SocketHandle socket =
      internal::ConnectTo(host, port, impl_->config.limits.connect_bound_ms, error);
  if (socket == kInvalidSocket) {
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->socket = socket;
  }
  internal::SetNoDelay(socket);
  internal::SetSendTimeout(socket, impl_->config.limits.send_bound_ms);

  const std::shared_ptr<const FabricSnapshot> snapshot = impl_->runtime.CurrentSnapshot();
  HelloPayload hello;
  hello.publisher = impl_->config.publisher;
  hello.boot = impl_->config.boot;
  hello.coordinator_epoch = CoordinatorEpoch(snapshot == nullptr ? 0 : snapshot->Generations().epoch.Value());
  hello.snapshot = snapshot == nullptr ? SnapshotId{} : snapshot->Id();
  hello.generations = snapshot == nullptr ? SnapshotGenerations{} : snapshot->Generations();
  hello.node_count = snapshot == nullptr ? 0 : static_cast<std::uint32_t>(snapshot->NodeCount());
  hello.edge_count = snapshot == nullptr ? 0 : static_cast<std::uint32_t>(snapshot->EdgeCount());

  ByteWriter hello_writer(impl_->config.limits.max_frame_bytes);
  EncodeHelloPayload(hello_writer, hello);
  std::string send_error;
  if (!SendFrame(socket, WireMessage::kHello, 0, hello.coordinator_epoch, 0, impl_->config.boot,
                 PlanningRequestId{}, hello_writer.span(), send_error)) {
    error = "cannot register with the coordinator: " + send_error;
    impl_->CloseSocketLocked();
    return false;
  }

  WireFrame response;
  std::string detail;
  const RecvOutcome handshake = ReadFrame(socket, impl_->config.limits.max_frame_bytes,
                                          impl_->config.limits.receive_bound_ms, response, detail);
  if (handshake != RecvOutcome::kOk) {
    error = "registration handshake failed: " + detail;
    impl_->CloseSocketLocked();
    return false;
  }
  if (response.type == WireMessage::kFenceNotice) {
    FenceNoticePayload notice;
    std::string notice_detail;
    static_cast<void>(DecodeFenceNoticePayload(
        std::span<const std::byte>(response.payload.data(), response.payload.size()), notice, notice_detail));
    impl_->fenced_flag.store(true);
    error = "worker registration was fenced: " + std::string(ToString(notice.status)) + " " + notice.detail;
    impl_->CloseSocketLocked();
    return false;
  }
  if (response.type == WireMessage::kPlanError) {
    PlanErrorPayload plan_error;
    std::string error_detail;
    static_cast<void>(DecodePlanErrorPayload(
        std::span<const std::byte>(response.payload.data(), response.payload.size()), plan_error, error_detail));
    error = "worker registration was rejected: " + std::string(ToString(plan_error.status)) + " " + plan_error.detail;
    impl_->CloseSocketLocked();
    return false;
  }
  if (response.type != WireMessage::kSnapshotResponse) {
    error = "unexpected registration response: " + std::string(ToString(response.type));
    impl_->CloseSocketLocked();
    return false;
  }
  SnapshotResponsePayload registered;
  std::string registered_detail;
  if (DecodeSnapshotResponsePayload(std::span<const std::byte>(response.payload.data(), response.payload.size()),
                                    registered, registered_detail) != WireStatus::kOk) {
    error = "malformed registration response: " + registered_detail;
    impl_->CloseSocketLocked();
    return false;
  }
  impl_->registered_flag.store(true);

  CoordinatorEpoch coordinator_epoch = response.coordinator_epoch;
  WireFrame frame;
  while (!impl_->stopping.load()) {
    const RecvOutcome outcome = ReadFrame(socket, impl_->config.limits.max_frame_bytes,
                                          impl_->config.limits.receive_bound_ms, frame, detail);
    if (outcome != RecvOutcome::kOk) {
      if (impl_->stopping.load()) {
        impl_->CloseSocketLocked();
        return true;
      }
      error = outcome == RecvOutcome::kPeerClosed ? "coordinator session closed" : detail;
      impl_->CloseSocketLocked();
      return false;
    }
    if (frame.coordinator_epoch > coordinator_epoch) {
      coordinator_epoch = frame.coordinator_epoch;
    }
    switch (frame.type) {
      case WireMessage::kPlanRequest: {
        PlanningRequest request;
        std::string request_detail;
        const WireStatus decode = DecodePlanningRequestPayload(
            std::span<const std::byte>(frame.payload.data(), frame.payload.size()), impl_->config.limits, request,
            request_detail);
        if (decode != WireStatus::kOk) {
          PlanErrorPayload plan_error;
          plan_error.request = frame.request;
          plan_error.status = decode;
          plan_error.plan_status = PlanStatus::kMalformedRequest;
          plan_error.code = DiagnosticForWireStatus(decode);
          plan_error.detail = request_detail;
          ByteWriter writer(impl_->config.limits.max_frame_bytes);
          EncodePlanErrorPayload(writer, plan_error);
          std::string error_text;
          static_cast<void>(SendFrame(socket, WireMessage::kPlanError, kWireFlagResponse, coordinator_epoch, 0,
                                      impl_->config.boot, frame.request, writer.span(), error_text));
          break;
        }
        const PlanningResult result = impl_->runtime.Plan(request);
        ByteWriter writer(impl_->config.limits.max_frame_bytes);
        EncodePlanningResultPayload(writer, result);
        if (writer.overflowed()) {
          PlanErrorPayload plan_error;
          plan_error.request = frame.request;
          plan_error.status = WireStatus::kTooLarge;
          plan_error.plan_status = PlanStatus::kResourceLimit;
          plan_error.code = DiagnosticCode::kProtocolMalformedFrame;
          plan_error.detail = "planning result exceeds the configured frame ceiling";
          ByteWriter error_writer(impl_->config.limits.max_frame_bytes);
          EncodePlanErrorPayload(error_writer, plan_error);
          std::string error_text;
          static_cast<void>(SendFrame(socket, WireMessage::kPlanError, kWireFlagResponse, coordinator_epoch, 0,
                                      impl_->config.boot, frame.request, error_writer.span(), error_text));
          break;
        }
        std::string error_text;
        if (!SendFrame(socket, WireMessage::kPlanResult, kWireFlagResponse, coordinator_epoch, 0, impl_->config.boot,
                       frame.request, writer.span(), error_text)) {
          error = "cannot publish a planning result: " + error_text;
          impl_->CloseSocketLocked();
          return false;
        }
        impl_->plans_served.fetch_add(1);
        break;
      }
      case WireMessage::kSnapshotRequest: {
        SnapshotResponsePayload snapshot_response;
        const std::shared_ptr<const FabricSnapshot> held = impl_->runtime.CurrentSnapshot();
        snapshot_response.snapshot = held == nullptr ? SnapshotId{} : held->Id();
        snapshot_response.generations = held == nullptr ? SnapshotGenerations{} : held->Generations();
        snapshot_response.node_count = held == nullptr ? 0 : static_cast<std::uint32_t>(held->NodeCount());
        snapshot_response.edge_count = held == nullptr ? 0 : static_cast<std::uint32_t>(held->EdgeCount());
        ByteWriter writer(impl_->config.limits.max_frame_bytes);
        EncodeSnapshotResponsePayload(writer, snapshot_response);
        std::string error_text;
        static_cast<void>(SendFrame(socket, WireMessage::kSnapshotResponse, kWireFlagResponse, coordinator_epoch, 0,
                                    impl_->config.boot, frame.request, writer.span(), error_text));
        break;
      }
      case WireMessage::kFenceNotice: {
        FenceNoticePayload notice;
        std::string notice_detail;
        static_cast<void>(DecodeFenceNoticePayload(
            std::span<const std::byte>(frame.payload.data(), frame.payload.size()), notice, notice_detail));
        impl_->fenced_flag.store(true);
        impl_->results_rejected.fetch_add(1);
        error = "worker fenced by the coordinator: " + std::string(ToString(notice.status)) + " " + notice.detail;
        impl_->CloseSocketLocked();
        return false;
      }
      case WireMessage::kShutdownWorker:
        impl_->CloseSocketLocked();
        return true;
      default: {
        PlanErrorPayload plan_error;
        plan_error.request = frame.request;
        plan_error.status = WireStatus::kUnsupported;
        plan_error.plan_status = PlanStatus::kUnsupported;
        plan_error.code = DiagnosticCode::kUnsupportedRequest;
        plan_error.detail = "unsupported message for a worker session";
        ByteWriter writer(impl_->config.limits.max_frame_bytes);
        EncodePlanErrorPayload(writer, plan_error);
        std::string error_text;
        static_cast<void>(SendFrame(socket, WireMessage::kPlanError, kWireFlagResponse, coordinator_epoch, 0,
                                    impl_->config.boot, frame.request, writer.span(), error_text));
        break;
      }
    }
  }
  impl_->CloseSocketLocked();
  return true;
}

// ---------------------------------------------------------------------------
// Client.
// ---------------------------------------------------------------------------
struct DistributedPlannerClient::Impl {
  Impl(std::string endpoint_value, ResourceLimits resource_limits)
      : endpoint(std::move(endpoint_value)), limits(resource_limits) {}

  std::string endpoint;
  ResourceLimits limits;
  SocketHandle socket = kInvalidSocket;
  std::uint64_t sequence = 0;
  CoordinatorEpoch last_epoch;
  mutable std::mutex mutex;
};

DistributedPlannerClient::DistributedPlannerClient(std::string endpoint, ResourceLimits limits)
    : impl_(std::make_unique<Impl>(std::move(endpoint), limits)) {}

DistributedPlannerClient::~DistributedPlannerClient() { Close(); }

bool DistributedPlannerClient::connected() const { return impl_->socket != kInvalidSocket; }

void DistributedPlannerClient::Close() {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  if (impl_->socket != kInvalidSocket) {
    internal::ShutdownSocket(impl_->socket);
    internal::CloseSocket(impl_->socket);
    impl_->socket = kInvalidSocket;
  }
}

bool DistributedPlannerClient::Connect(std::string& error) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  if (impl_->socket != kInvalidSocket) {
    return true;
  }
  std::string host;
  std::uint16_t port = 0;
  if (!internal::ParseEndpoint(impl_->endpoint, host, port)) {
    error = "invalid coordinator endpoint: " + impl_->endpoint;
    return false;
  }
  if (!internal::SocketRuntimeEnsure(error)) {
    return false;
  }
  impl_->socket = internal::ConnectTo(host, port, impl_->limits.connect_bound_ms, error);
  if (impl_->socket == kInvalidSocket) {
    return false;
  }
  internal::SetNoDelay(impl_->socket);
  internal::SetSendTimeout(impl_->socket, impl_->limits.send_bound_ms);
  return true;
}

bool DistributedPlannerClient::SnapshotInfo(SnapshotId& snapshot, SnapshotGenerations& generations,
                                            std::string& error) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  if (impl_->socket == kInvalidSocket) {
    error = "client is not connected";
    return false;
  }
  impl_->sequence += 1;
  std::string send_error;
  if (!SendFrame(impl_->socket, WireMessage::kSnapshotRequest, 0, impl_->last_epoch, impl_->sequence, WorkerBootId{},
                 PlanningRequestId{}, std::span<const std::byte>(), send_error)) {
    error = send_error;
    return false;
  }
  WireFrame response;
  std::string detail;
  const RecvOutcome outcome =
      ReadFrame(impl_->socket, impl_->limits.max_frame_bytes, impl_->limits.receive_bound_ms, response, detail);
  if (outcome != RecvOutcome::kOk) {
    error = detail.empty() ? "coordinator session ended" : detail;
    return false;
  }
  if (response.type != WireMessage::kSnapshotResponse) {
    error = "unexpected response: " + std::string(ToString(response.type));
    return false;
  }
  SnapshotResponsePayload payload;
  std::string payload_detail;
  if (DecodeSnapshotResponsePayload(std::span<const std::byte>(response.payload.data(), response.payload.size()),
                                    payload, payload_detail) != WireStatus::kOk) {
    error = "malformed snapshot response: " + payload_detail;
    return false;
  }
  snapshot = payload.snapshot;
  generations = payload.generations;
  if (response.coordinator_epoch > impl_->last_epoch) {
    impl_->last_epoch = response.coordinator_epoch;
  }
  return true;
}

bool DistributedPlannerClient::Submit(const PlanningRequest& request, PlanningResult& result, PlanStatus& status,
                                      std::string& error) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  if (impl_->socket == kInvalidSocket) {
    error = "client is not connected";
    return false;
  }
  ByteWriter writer(impl_->limits.max_frame_bytes);
  EncodePlanningRequestPayload(writer, request);
  if (writer.overflowed()) {
    error = "planning request exceeds the configured frame ceiling";
    status = PlanStatus::kResourceLimit;
    return false;
  }
  impl_->sequence += 1;
  std::string send_error;
  if (!SendFrame(impl_->socket, WireMessage::kPlanRequest, 0, impl_->last_epoch, impl_->sequence, WorkerBootId{},
                 request.id, writer.span(), send_error)) {
    error = send_error;
    return false;
  }
  WireFrame response;
  std::string detail;
  const RecvOutcome outcome =
      ReadFrame(impl_->socket, impl_->limits.max_frame_bytes, impl_->limits.receive_bound_ms, response, detail);
  if (outcome != RecvOutcome::kOk) {
    error = detail.empty() ? "coordinator session ended" : detail;
    status = PlanStatus::kRevalidationRequired;
    return false;
  }
  if (response.coordinator_epoch > impl_->last_epoch) {
    impl_->last_epoch = response.coordinator_epoch;
  }
  if (response.type == WireMessage::kPlanResult) {
    std::string result_detail;
    const WireStatus decode = DecodePlanningResultPayload(
        std::span<const std::byte>(response.payload.data(), response.payload.size()), impl_->limits, result,
        result_detail);
    if (decode != WireStatus::kOk) {
      error = "malformed planning result: " + result_detail;
      status = PlanStatus::kRevalidationRequired;
      return false;
    }
    status = result.status;
    return true;
  }
  if (response.type == WireMessage::kPlanError) {
    PlanErrorPayload payload;
    std::string payload_detail;
    if (DecodePlanErrorPayload(std::span<const std::byte>(response.payload.data(), response.payload.size()), payload,
                               payload_detail) != WireStatus::kOk) {
      error = "malformed error response: " + payload_detail;
      status = PlanStatus::kRevalidationRequired;
      return false;
    }
    status = payload.plan_status;
    error = std::string(ToString(payload.status)) + ": " + payload.detail;
    return false;
  }
  if (response.type == WireMessage::kFenceNotice) {
    FenceNoticePayload payload;
    std::string payload_detail;
    static_cast<void>(DecodeFenceNoticePayload(
        std::span<const std::byte>(response.payload.data(), response.payload.size()), payload, payload_detail));
    error = "coordinator fenced this session: " + payload.detail;
    status = PlanStatus::kEpochStale;
    return false;
  }
  error = "unexpected response: " + std::string(ToString(response.type));
  status = PlanStatus::kRevalidationRequired;
  return false;
}

bool DistributedPlannerClient::QueryCurrentness(const PathPlan& plan, Currentness& currentness, std::string& error) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  if (impl_->socket == kInvalidSocket) {
    error = "client is not connected";
    return false;
  }
  CurrentnessQueryPayload query;
  query.plan = plan.id;
  query.request = plan.request;
  query.evidence = plan.evidence;
  ByteWriter writer(impl_->limits.max_frame_bytes);
  EncodeCurrentnessQueryPayload(writer, query);
  impl_->sequence += 1;
  std::string send_error;
  if (!SendFrame(impl_->socket, WireMessage::kValidateCurrentness, 0, impl_->last_epoch, impl_->sequence,
                 WorkerBootId{}, plan.request, writer.span(), send_error)) {
    error = send_error;
    return false;
  }
  WireFrame response;
  std::string detail;
  const RecvOutcome outcome =
      ReadFrame(impl_->socket, impl_->limits.max_frame_bytes, impl_->limits.receive_bound_ms, response, detail);
  if (outcome != RecvOutcome::kOk) {
    error = detail.empty() ? "coordinator session ended" : detail;
    return false;
  }
  if (response.type == WireMessage::kPlanError) {
    PlanErrorPayload payload;
    std::string payload_detail;
    static_cast<void>(DecodePlanErrorPayload(
        std::span<const std::byte>(response.payload.data(), response.payload.size()), payload, payload_detail));
    error = std::string(ToString(payload.status)) + ": " + payload.detail;
    return false;
  }
  if (response.type != WireMessage::kCurrentnessResult) {
    error = "unexpected response: " + std::string(ToString(response.type));
    return false;
  }
  CurrentnessResultPayload payload;
  std::string payload_detail;
  const WireStatus decode = DecodeCurrentnessResultPayload(
      std::span<const std::byte>(response.payload.data(), response.payload.size()), impl_->limits, payload,
      payload_detail);
  if (decode != WireStatus::kOk) {
    error = "malformed currentness result: " + payload_detail;
    return false;
  }
  currentness = payload.currentness;
  return true;
}

}  // namespace summon::pathplanner

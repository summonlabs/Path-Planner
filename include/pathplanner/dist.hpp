#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "pathplanner/graph.hpp"
#include "pathplanner/ids.hpp"
#include "pathplanner/limits.hpp"
#include "pathplanner/planner.hpp"
#include "pathplanner/proto.hpp"
#include "pathplanner/request.hpp"
#include "pathplanner/result.hpp"

namespace summon::pathplanner {

// ---------------------------------------------------------------------------
// Distributed planning runtime.
//
//  * the coordinator owns the Fabric Epoch it issues, the worker registry, and the
//    acceptance decision for worker publications;
//  * workers hold their own evidence (the same snapshot identity the coordinator
//    holds) and compute candidate paths with the local PlannerRuntime;
//  * clients submit planning requests and receive structured results.
//
// A worker publication is accepted only when its WorkerBootId is registered and not
// fenced, its CoordinatorEpoch equals the current epoch, and its snapshot identity
// matches the coordinator evidence. Completion order never confers authority.
// ---------------------------------------------------------------------------
struct WorkerRegistration {
  WorkerBootId boot;
  PublisherId publisher;
  SnapshotId snapshot;
  SnapshotGenerations generations;
  CoordinatorEpoch registered_epoch;
  bool fenced = false;
  std::uint64_t plans_completed = 0;
  std::uint64_t publications_rejected = 0;
};

struct CoordinatorConfig {
  std::string bind_address = "127.0.0.1";
  std::uint16_t port = 0;  // 0 requests an ephemeral port
  ResourceLimits limits;
  std::shared_ptr<const FabricSnapshot> snapshot;
  FabricEpoch initial_epoch{1};
  // Optional durable planning history. When set, accepted worker publications are
  // retained and persisted atomically, and a restart recovers them conservatively
  // (every recovered plan requires revalidation before it may be treated as current).
  std::string store_path;
};

class Coordinator {
 public:
  explicit Coordinator(CoordinatorConfig config);
  ~Coordinator();
  Coordinator(const Coordinator&) = delete;
  Coordinator& operator=(const Coordinator&) = delete;

  bool Start(std::string& error);
  void Stop();
  bool running() const;

  std::uint16_t Port() const;
  std::string Endpoint() const;
  FabricEpoch Epoch() const;
  // Advances the epoch by one and applies conservative recovery: every retained plan
  // requires revalidation and every registered worker is fenced.
  bool AdvanceEpoch(FabricEpoch new_epoch, std::string& error);
  void PublishSnapshot(std::shared_ptr<const FabricSnapshot> snapshot, FabricEpoch epoch);
  bool FenceWorker(const WorkerBootId& boot, std::string& error);
  std::vector<WorkerRegistration> Workers() const;
  std::size_t SessionCount() const;
  PlannerStatistics Stats() const;
  // Number of worker publications accepted since Start().
  std::uint64_t AcceptedPublications() const;
  // Number of retained plans recovered from the configured store at Start().
  std::size_t RecoveredPlanCount() const;
  // Persists the retained planning history (no-op without a configured store path).
  bool SaveStore(std::string& error) const;
  // Acceptance decision for a worker publication (also used by tests and by the
  // session layer before a result is forwarded to a client).
  WireStatus ValidateWorkerPublication(const WorkerBootId& boot, CoordinatorEpoch epoch, const SnapshotId& snapshot,
                                       std::string& detail) const;
  // Direct access to the coordinator runtime for currentness queries and retention.
  const PlannerRuntime& Runtime() const;
  PlannerRuntime& Runtime();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

struct WorkerConfig {
  std::string coordinator_endpoint;
  std::shared_ptr<const FabricSnapshot> snapshot;
  PublisherId publisher;
  WorkerBootId boot;
  ResourceLimits limits;
};

// Generates a fresh worker boot identity from operating-system entropy. A restarted
// worker process therefore never reuses the identity of its predecessor.
WorkerBootId GenerateWorkerBootId();
PublisherId GeneratePublisherId();
// Deterministic identity helpers used when a deployment provisions explicit values.
WorkerBootId MakeWorkerBootIdFromLabel(const std::string& label);
PublisherId MakePublisherIdFromLabel(const std::string& label);

class Worker {
 public:
  explicit Worker(WorkerConfig config);
  ~Worker();
  Worker(const Worker&) = delete;
  Worker& operator=(const Worker&) = delete;

  // Connects, registers, and serves planning requests until stopped, fenced, or the
  // session fails. Returns false with an explanation on failure or fencing.
  bool Run(std::string& error);
  void Stop();
  bool fenced() const;
  bool registered() const;
  WorkerBootId Boot() const;
  std::uint64_t PlansServed() const;
  std::uint64_t ResultsRejected() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

class DistributedPlannerClient {
 public:
  DistributedPlannerClient(std::string endpoint, ResourceLimits limits);
  ~DistributedPlannerClient();
  DistributedPlannerClient(const DistributedPlannerClient&) = delete;
  DistributedPlannerClient& operator=(const DistributedPlannerClient&) = delete;

  bool Connect(std::string& error);
  bool connected() const;
  void Close();

  // Submits a planning request. Returns false on transport or structured failure; the
  // structured failure detail is reported through status/error.
  bool Submit(const PlanningRequest& request, PlanningResult& result, PlanStatus& status, std::string& error);
  bool QueryCurrentness(const PathPlan& plan, Currentness& currentness, std::string& error);
  bool SnapshotInfo(SnapshotId& snapshot, SnapshotGenerations& generations, std::string& error);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace summon::pathplanner

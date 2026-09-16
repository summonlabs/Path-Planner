// Path Planner test suite: race.
//
// Deterministic concurrency proofs and real-process distributed proofs.
//
// In-process cases force the interesting scheduling window with the public
// PlanningHooks callback: the planning thread blocks inside a planning stage on a
// condition variable until the test thread has performed the competing action, and
// the test thread waits for the hook to arrive on the same condition variable. No
// sleep is used as synchronisation.
//
// PlannerRuntime::Plan() evaluates its compare-before-publish watermark check and
// then notifies PlanningStage::kBeforePublish. The last stage notified before that
// decision is therefore kRanked, and that is the staging point a hook must block on
// to make a competing publication observable by the decision itself.
//
// Distributed cases spawn the real CLI coordinator and worker processes, kill them
// with TerminateProcess, and read the coordinator endpoint from the endpoint file
// through a bounded poll whose exhaustion is a hard check failure (never a hang).
// Every spawned child is terminated and verified gone before the case returns.

// std::getenv is used to read the CLI path; the MSVC deprecation warning is silenced
// exactly as the CMake test target does for every suite on Windows.
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS 1
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "test_framework.hpp"

#ifndef PP_CLI_BINARY
#define PP_CLI_BINARY ""
#endif

#include <algorithm>
#include <atomic>
#include <barrier>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "pathplanner/dist.hpp"
#include "pathplanner/explain.hpp"
#include "pathplanner/pathplanner.hpp"
#include "pathplanner/store.hpp"

// Local convenience used by this file only: PP_REQUIRE with a diagnostic message.
// The shared framework offers PP_REQUIRE (early return, no message) and PP_CHECK_MSG
// (message, no early return); the process proofs need both properties at once.
#define PP_REQUIRE_MSG(condition, message)                                                        \
  do {                                                                                            \
    ::pp_test::g_checks += 1;                                                                     \
    if (!(condition)) {                                                                           \
      ::pp_test::Fail(__FILE__, __LINE__,                                                         \
                      std::string("requirement failed: " #condition " :: ") + (message));         \
      return;                                                                                     \
    }                                                                                             \
  } while (false)

namespace {

using namespace summon::pathplanner;

// ---------------------------------------------------------------------------
// Deterministic identities and a small controllable fabric.
// ---------------------------------------------------------------------------
NodeId NodeFromLabel(const std::string& label) { return NodeId::FromDigest(Sha256::Hash(label)); }
LinkId LinkFromLabel(const std::string& label) { return LinkId::FromDigest(Sha256::Hash(label)); }
PortId PortFromLabel(const std::string& label) { return PortId::FromDigest(Sha256::Hash(label)); }
EndpointId EndpointFromLabel(const std::string& label) { return EndpointId::FromDigest(Sha256::Hash(label)); }
SwitchId SwitchFromLabel(const std::string& label) { return SwitchId::FromDigest(Sha256::Hash(label)); }

// A five-node diamond: source -> {node1 | node2} -> destination. The two routes use
// disjoint links and disjoint intermediate nodes, which is what the targeted
// invalidation proof needs.
struct TestFabric {
  std::shared_ptr<const FabricSnapshot> snapshot;
  EndpointId source_endpoint;
  EndpointId destination_endpoint;
  NodeId source_node;
  NodeId destination_node;
  std::vector<LinkId> route_a;  // source -> node1 -> destination
  std::vector<LinkId> route_b;  // source -> node2 -> destination
};

struct FabricSpec {
  std::string label = "race";
  std::uint64_t topology = 1;
  std::uint64_t link_state = 1;
  std::uint64_t epoch = 1;
  bool first_route_a_link_down = false;
};

TestFabric BuildFabric(const FabricSpec& spec) {
  TestFabric fabric;
  ResourceLimits limits;
  FabricSnapshotBuilder builder(limits);
  SnapshotGenerations generations;
  generations.topology = TopologyGeneration(spec.topology);
  generations.link_state = LinkStateGeneration(spec.link_state);
  generations.ports = PortGeneration(1);
  generations.capabilities = CapabilityGeneration(1);
  generations.failure_domains = FailureDomainGeneration(1);
  generations.epoch = FabricEpoch(spec.epoch);
  generations.policy = PolicyGeneration(1);
  generations.constraints = ConstraintGeneration(1);
  builder.SetGenerations(generations);
  builder.SetSource(EvidenceSource::kSynthetic);

  const std::string& label = spec.label;
  const std::uint32_t kNodeCount = 5;
  std::vector<PortStateRecord> port_states;
  for (std::uint32_t index = 0; index < kNodeCount; ++index) {
    NodeRecord node;
    node.id = NodeFromLabel(label + "-node:" + std::to_string(index));
    node.attachment = SwitchFromLabel(label + "-switch:" + std::to_string(index / 2));
    node.entity_generation = EntityGeneration(1);
    node.structural_generation = TopologyGeneration(spec.topology);
    for (std::uint32_t port = 0; port < 4; ++port) {
      const PortId id = PortFromLabel(label + "-port:" + std::to_string(index) + ":" + std::to_string(port));
      node.ports.push_back(id);
      port_states.push_back(PortStateRecord{id, PortState::kUp});
    }
    PP_CHECK(builder.AddNode(std::move(node)));
  }

  struct LinkPlan {
    const char* name;
    std::uint32_t from;
    std::uint32_t to;
    std::uint32_t from_port;
    std::uint32_t to_port;
    bool down;
  };
  const LinkPlan plans[4] = {
      {"a0", 0, 1, 1, 0, spec.first_route_a_link_down},
      {"a1", 1, 4, 1, 0, false},
      {"b0", 0, 2, 2, 0, false},
      {"b1", 2, 4, 1, 2, false},
  };
  std::vector<LinkStateRecord> link_states;
  for (const LinkPlan& plan : plans) {
    EdgeRecord edge;
    edge.id = LinkFromLabel(label + "-link:" + plan.name);
    edge.from = NodeFromLabel(label + "-node:" + std::to_string(plan.from));
    edge.to = NodeFromLabel(label + "-node:" + std::to_string(plan.to));
    edge.from_port = PortFromLabel(label + "-port:" + std::to_string(plan.from) + ":" + std::to_string(plan.from_port));
    edge.to_port = PortFromLabel(label + "-port:" + std::to_string(plan.to) + ":" + std::to_string(plan.to_port));
    edge.layer = PathLayer::kPhysical;
    edge.relationship = RelationshipType::kDirectLink;
    edge.static_cost = StaticCost(1);
    edge.entity_generation = EntityGeneration(1);
    edge.structural_generation = TopologyGeneration(spec.topology);
    PP_CHECK(builder.AddEdge(edge));
    link_states.push_back(LinkStateRecord{edge.id, plan.down ? LinkState::kDown : LinkState::kUp});
    if (std::string(plan.name) == "a0") {
      fabric.route_a.push_back(edge.id);
    } else if (std::string(plan.name) == "a1") {
      fabric.route_a.push_back(edge.id);
    } else if (std::string(plan.name) == "b0") {
      fabric.route_b.push_back(edge.id);
    } else {
      fabric.route_b.push_back(edge.id);
    }
  }
  std::sort(link_states.begin(), link_states.end(),
            [](const LinkStateRecord& lhs, const LinkStateRecord& rhs) { return lhs.link < rhs.link; });
  std::sort(port_states.begin(), port_states.end(),
            [](const PortStateRecord& lhs, const PortStateRecord& rhs) { return lhs.port < rhs.port; });
  builder.SetLinkStates(link_states);
  builder.SetPortStates(port_states);

  fabric.source_node = NodeFromLabel(label + "-node:0");
  fabric.destination_node = NodeFromLabel(label + "-node:4");
  EndpointRecord source;
  source.id = EndpointFromLabel(label + "-endpoint:source");
  source.endpoint_class = EndpointClass::kEndpoint;
  source.node = fabric.source_node;
  source.port = PortFromLabel(label + "-port:0:0");
  source.entity_generation = EntityGeneration(1);
  EndpointRecord destination;
  destination.id = EndpointFromLabel(label + "-endpoint:destination");
  destination.endpoint_class = EndpointClass::kEndpoint;
  destination.node = fabric.destination_node;
  destination.port = PortFromLabel(label + "-port:4:1");
  destination.entity_generation = EntityGeneration(1);
  PP_CHECK(builder.AddEndpoint(source));
  PP_CHECK(builder.AddEndpoint(destination));
  fabric.source_endpoint = source.id;
  fabric.destination_endpoint = destination.id;

  SnapshotBuildResult built = builder.Build();
  PP_CHECK_MSG(built.ok(), "fabric build failed: " +
                               std::string(built.error.has_value() ? ToString(*built.error) : "unknown") + " " +
                               built.detail);
  fabric.snapshot = built.snapshot;
  return fabric;
}

PlanningRequest MakeRequest(const TestFabric& fabric, const std::string& label,
                            const std::vector<LinkId>& forbidden_links) {
  PlanningRequest request;
  request.id = PlanningRequestId::FromDigest(Sha256::Hash("race-request:" + label));
  request.source.id = fabric.source_endpoint;
  request.source.endpoint_class = EndpointClass::kEndpoint;
  request.source.generation = EntityGeneration(1);
  request.destination.id = fabric.destination_endpoint;
  request.destination.endpoint_class = EndpointClass::kEndpoint;
  request.destination.generation = EntityGeneration(1);
  request.max_candidates = 1;
  request.constraints.id = ConstraintSetId::FromDigest(Sha256::Hash("race-constraints:" + label));
  request.constraints.generation = ConstraintGeneration(1);
  request.constraints.layer = PathLayer::kPhysical;
  request.constraints.forbidden_links = forbidden_links;
  std::sort(request.constraints.forbidden_links.begin(), request.constraints.forbidden_links.end());
  request.policy.generation = PolicyGeneration(1);
  return request;
}

std::vector<LinkId> TraversedLinks(const PlanningResult& result) {
  std::vector<LinkId> links;
  for (const Candidate& candidate : result.candidates) {
    for (const PathHop& hop : candidate.path.hops) {
      links.push_back(hop.link);
    }
  }
  std::sort(links.begin(), links.end());
  links.erase(std::unique(links.begin(), links.end()), links.end());
  return links;
}

bool AllCandidatesNotCurrent(const PlanningResult& result) {
  if (result.candidates.empty()) {
    return false;
  }
  for (const Candidate& candidate : result.candidates) {
    if (candidate.currentness == Currentness::kCurrent) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Stage gate: the planning thread blocks inside PlanningStage::kRanked until the
// test thread has performed the competing action.
// ---------------------------------------------------------------------------
class StageGate {
 public:
  void OnStage(PlanningStage stage, const PlanningRequestId& request) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (!armed_ || stage != stage_ || request != request_) {
      return;
    }
    entered_ = true;
    condition_.notify_all();
    condition_.wait(lock, [this]() { return released_; });
  }

  void Arm(PlanningStage stage, const PlanningRequestId& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    stage_ = stage;
    request_ = request;
    entered_ = false;
    released_ = false;
    armed_ = true;
  }

  void WaitForEntry() {
    std::unique_lock<std::mutex> lock(mutex_);
    condition_.wait(lock, [this]() { return entered_; });
  }

  void Release() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      released_ = true;
    }
    condition_.notify_all();
  }

 private:
  std::mutex mutex_;
  std::condition_variable condition_;
  PlanningStage stage_ = PlanningStage::kRanked;
  PlanningRequestId request_{};
  bool armed_ = false;
  bool entered_ = false;
  bool released_ = false;
};

PlannerConfig MakeConfig(const std::shared_ptr<const FabricSnapshot>& snapshot, StageGate& gate) {
  PlannerConfig config;
  config.initial_snapshot = snapshot;
  config.hooks.on_stage = [&gate](PlanningStage stage, const PlanningRequestId& request) {
    gate.OnStage(stage, request);
  };
  return config;
}

// ---------------------------------------------------------------------------
// Real child processes.
// ---------------------------------------------------------------------------
constexpr int kPollIterations = 1500;      // bounded readiness polls
constexpr DWORD kPollSliceMs = 10;
constexpr DWORD kChildBoundMs = 30000;     // bounded wait for a child that ends by itself

std::wstring ToWide(const std::string& text) {
  if (text.empty()) {
    return std::wstring();
  }
  const int size = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
  if (size <= 0) {
    return std::wstring();
  }
  std::wstring wide(static_cast<std::size_t>(size), L'\0');
  static_cast<void>(MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), wide.data(), size));
  return wide;
}

std::string ToNarrow(const std::wstring& text) {
  if (text.empty()) {
    return std::string();
  }
  const int size = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr,
                                       nullptr);
  if (size <= 0) {
    return std::string();
  }
  std::string narrow(static_cast<std::size_t>(size), '\0');
  static_cast<void>(WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), narrow.data(), size,
                                        nullptr, nullptr));
  return narrow;
}

std::wstring TempDirectory() {
  std::vector<wchar_t> buffer(MAX_PATH + 1, L'\0');
  const DWORD length = GetTempPathW(static_cast<DWORD>(buffer.size()), buffer.data());
  if (length == 0 || static_cast<std::size_t>(length) >= buffer.size()) {
    return std::wstring();
  }
  return std::wstring(buffer.data(), length);
}

std::wstring UniquePath(const wchar_t* suffix) {
  static std::atomic<std::uint64_t> counter{0};
  const std::uint64_t index = counter.fetch_add(1);
  std::wstring path = TempDirectory();
  path += L"pp_race_";
  path += std::to_wstring(static_cast<unsigned long long>(GetCurrentProcessId()));
  path += L"_";
  path += std::to_wstring(static_cast<unsigned long long>(index));
  path += suffix;
  return path;
}

std::string ReadFileText(const std::wstring& path) {
  const HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return std::string();
  }
  std::string text;
  char buffer[4096];
  DWORD read = 0;
  while (ReadFile(handle, buffer, static_cast<DWORD>(sizeof(buffer)), &read, nullptr) != FALSE && read > 0) {
    text.append(buffer, static_cast<std::size_t>(read));
  }
  CloseHandle(handle);
  return text;
}

bool ProcessIdAlive(DWORD process_id) {
  if (process_id == 0) {
    return false;
  }
  const HANDLE handle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id);
  if (handle == nullptr) {
    return false;
  }
  const DWORD wait = WaitForSingleObject(handle, 0);
  CloseHandle(handle);
  return wait == WAIT_TIMEOUT;
}

class ChildProcess {
 public:
  ChildProcess() = default;
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;
  ~ChildProcess() { Stop(); }

  bool Launch(const std::wstring& executable, const std::wstring& arguments, const std::wstring& output_path) {
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    const HANDLE output =
        CreateFileW(output_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, nullptr);
    if (output == INVALID_HANDLE_VALUE) {
      return false;
    }
    const HANDLE input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes,
                                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (input == INVALID_HANDLE_VALUE) {
      CloseHandle(output);
      return false;
    }
    std::wstring command_line = L"\"" + executable + L"\" " + arguments;
    std::vector<wchar_t> mutable_line(command_line.begin(), command_line.end());
    mutable_line.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input;
    startup.hStdOutput = output;
    startup.hStdError = output;
    PROCESS_INFORMATION info{};
    const BOOL created = CreateProcessW(executable.c_str(), mutable_line.data(), nullptr, nullptr, TRUE,
                                        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info);
    CloseHandle(output);
    CloseHandle(input);
    if (created == FALSE) {
      return false;
    }
    info_ = info;
    output_path_ = output_path;
    process_id_ = info.dwProcessId;
    launched_ = true;
    return true;
  }

  bool alive() const {
    if (!launched_) {
      return false;
    }
    DWORD code = 0;
    if (GetExitCodeProcess(info_.hProcess, &code) == FALSE) {
      return false;
    }
    return code == STILL_ACTIVE;
  }

  DWORD exit_code() const {
    if (!launched_) {
      return 0;
    }
    DWORD code = 0;
    static_cast<void>(GetExitCodeProcess(info_.hProcess, &code));
    return code;
  }

  bool WaitForExit(DWORD bound_ms) const {
    if (!launched_) {
      return false;
    }
    return WaitForSingleObject(info_.hProcess, bound_ms) == WAIT_OBJECT_0;
  }

  bool Stop() {
    if (!launched_) {
      return true;
    }
    if (alive()) {
      static_cast<void>(TerminateProcess(info_.hProcess, 1));
    }
    const bool exited = WaitForSingleObject(info_.hProcess, kChildBoundMs) == WAIT_OBJECT_0;
    CloseHandle(info_.hThread);
    CloseHandle(info_.hProcess);
    info_ = PROCESS_INFORMATION{};
    launched_ = false;
    return exited;
  }

  DWORD process_id() const { return process_id_; }
  std::string ReadOutput() const { return ReadFileText(output_path_); }

 private:
  PROCESS_INFORMATION info_{};
  std::wstring output_path_;
  DWORD process_id_ = 0;
  bool launched_ = false;
};

class ChildRegistry {
 public:
  ChildRegistry() = default;
  ChildRegistry(const ChildRegistry&) = delete;
  ChildRegistry& operator=(const ChildRegistry&) = delete;
  ~ChildRegistry() {
    for (const std::unique_ptr<ChildProcess>& child : children_) {
      static_cast<void>(child->Stop());
    }
  }

  ChildProcess& Spawn(const std::wstring& executable, const std::wstring& arguments) {
    children_.push_back(std::make_unique<ChildProcess>());
    ChildProcess& child = *children_.back();
    PP_CHECK_MSG(child.Launch(executable, arguments, UniquePath(L".out")), "child process could not be launched");
    return child;
  }

  // Terminates every child and asserts (bounded poll) that none of the process ids we
  // started is still alive.
  void KillAllAndVerify(const char* context) {
    for (const std::unique_ptr<ChildProcess>& child : children_) {
      static_cast<void>(child->Stop());
    }
    bool all_gone = false;
    for (int attempt = 0; attempt < kPollIterations && !all_gone; ++attempt) {
      all_gone = true;
      for (const std::unique_ptr<ChildProcess>& child : children_) {
        if (ProcessIdAlive(child->process_id())) {
          all_gone = false;
          break;
        }
      }
      if (!all_gone) {
        Sleep(kPollSliceMs);
      }
    }
    PP_CHECK_MSG(all_gone, std::string("a child process is still alive after ") + context);
  }

 private:
  std::vector<std::unique_ptr<ChildProcess>> children_;
};

std::wstring CliExecutable() {
  const char* from_environment = std::getenv("PP_CLI_BINARY");
  if (from_environment != nullptr && from_environment[0] != '\0') {
    return ToWide(from_environment);
  }
  return ToWide(std::string(PP_CLI_BINARY));
}

// ---------------------------------------------------------------------------
// Small text helpers over captured child output.
// ---------------------------------------------------------------------------
std::vector<std::string> SplitLines(const std::string& text) {
  std::vector<std::string> lines;
  std::string current;
  for (const char character : text) {
    if (character == '\n') {
      lines.push_back(current);
      current.clear();
    } else if (character != '\r') {
      current.push_back(character);
    }
  }
  if (!current.empty()) {
    lines.push_back(current);
  }
  return lines;
}

bool HasExactLine(const std::string& text, const std::string& wanted) {
  const std::vector<std::string> lines = SplitLines(text);
  return std::find(lines.begin(), lines.end(), wanted) != lines.end();
}

// Value of the first line of the form "<key> <value>".
bool LineValue(const std::string& text, const std::string& key, std::string& value) {
  const std::string prefix = key + " ";
  for (const std::string& line : SplitLines(text)) {
    if (line.rfind(prefix, 0) == 0) {
      value = line.substr(prefix.size());
      return true;
    }
  }
  return false;
}

bool LineNumber(const std::string& text, const std::string& key, std::uint64_t& value) {
  std::string raw;
  if (!LineValue(text, key, raw) || raw.empty() || raw.size() > 20) {
    return false;
  }
  std::uint64_t parsed = 0;
  for (const char character : raw) {
    if (character < '0' || character > '9') {
      return false;
    }
    parsed = parsed * 10 + static_cast<std::uint64_t>(character - '0');
  }
  value = parsed;
  return true;
}

bool IsLoopbackEndpoint(const std::string& text) {
  if (text.rfind("127.0.0.1:", 0) != 0 || text.size() <= 10) {
    return false;
  }
  for (std::size_t index = 10; index < text.size(); ++index) {
    if (text[index] < '0' || text[index] > '9') {
      return false;
    }
  }
  return true;
}

// Bounded readiness poll over the endpoint file written by the coordinator.
bool PollEndpointFile(const std::wstring& path, std::string& endpoint) {
  for (int attempt = 0; attempt < kPollIterations; ++attempt) {
    std::string text = ReadFileText(path);
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) {
      text.pop_back();
    }
    if (IsLoopbackEndpoint(text)) {
      endpoint = text;
      return true;
    }
    Sleep(kPollSliceMs);
  }
  return false;
}

bool FileExists(const std::wstring& path) {
  const DWORD attributes = GetFileAttributesW(path.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

// ---------------------------------------------------------------------------
// Client helpers.
// ---------------------------------------------------------------------------
ResourceLimits ClientLimits() {
  ResourceLimits limits;
  // Keeps a dispatch that lost its worker from stalling a bounded poll for the
  // coordinator's own (larger) pending bound.
  limits.receive_bound_ms = 4000;
  limits.connect_bound_ms = 4000;
  return limits;
}

struct PlanAttempt {
  bool delivered = false;
  PlanStatus status = PlanStatus::kNoPath;
  std::string error;
  PlanningResult result;
};

PlanAttempt SubmitOnce(const std::string& endpoint, const PlanningRequest& request) {
  PlanAttempt attempt;
  DistributedPlannerClient client(endpoint, ClientLimits());
  std::string error;
  if (!client.Connect(error)) {
    attempt.error = "connect failed: " + error;
    return attempt;
  }
  attempt.delivered = client.Submit(request, attempt.result, attempt.status, error);
  attempt.error = error;
  client.Close();
  return attempt;
}

struct PlanPoll {
  bool planned = false;
  int attempts = 0;
  PlanAttempt last;
};

// Submits until a plan is PLANNED. The bound is a hard one: exhaustion returns false
// and the caller fails explicitly.
PlanPoll PollUntilPlanned(const std::string& endpoint, const PlanningRequest& request, int max_attempts) {
  PlanPoll poll;
  for (int attempt = 0; attempt < max_attempts; ++attempt) {
    poll.attempts = attempt + 1;
    poll.last = SubmitOnce(endpoint, request);
    if (poll.last.delivered && poll.last.status == PlanStatus::kPlanned) {
      poll.planned = true;
      return poll;
    }
    if (attempt + 1 < max_attempts) {
      Sleep(kPollSliceMs);
    }
  }
  return poll;
}

// The CLI demonstration fabric identity used by the coordinator and worker commands.
PlanningRequest CliDemoRequest(const std::string& label) {
  PlanningRequest request;
  request.id = PlanningRequestId::FromDigest(Sha256::Hash("race-cli-request:" + label));
  request.source.id = EndpointFromLabel("demo-endpoint:source");
  request.source.endpoint_class = EndpointClass::kEndpoint;
  request.source.generation = EntityGeneration(1);
  request.destination.id = EndpointFromLabel("demo-endpoint:destination");
  request.destination.endpoint_class = EndpointClass::kEndpoint;
  request.destination.generation = EntityGeneration(1);
  request.max_candidates = 2;
  request.constraints.id = ConstraintSetId::FromDigest(Sha256::Hash("race-cli-constraints:" + label));
  request.constraints.generation = ConstraintGeneration(1);
  request.constraints.layer = PathLayer::kPhysical;
  request.policy.generation = PolicyGeneration(1);
  return request;
}

std::wstring CoordinatorArguments(std::uint64_t epoch, const std::wstring& endpoint_file, const std::wstring& store) {
  std::wstring arguments = L"coordinator --nodes 6 --epoch " + std::to_wstring(epoch) + L" --port 0 --endpoint-file \"" +
                           endpoint_file + L"\"";
  if (!store.empty()) {
    arguments += L" --store \"" + store + L"\"";
  }
  return arguments;
}

std::wstring WorkerArguments(std::uint64_t epoch, const std::string& endpoint, const std::string& boot,
                             const std::string& publisher) {
  return L"worker --nodes 6 --epoch " + std::to_wstring(epoch) + L" --coordinator " + ToWide(endpoint) +
         L" --boot-id " + ToWide(boot) + L" --publisher " + ToWide(publisher);
}

bool ContainsTargetedNotice(const PlanCurrentnessReport& report) {
  for (const ExplanationEntry& entry : report.changes) {
    if (entry.detail.find("invalidated by a targeted notice") != std::string::npos) {
      return true;
    }
  }
  return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// 1. Plan completion vs topology invalidation.
// ---------------------------------------------------------------------------
PP_TEST(race, plan_completion_vs_topology_invalidation) {
  const TestFabric base = BuildFabric(FabricSpec{});
  FabricSpec newer_spec;
  newer_spec.label = "race-newer";
  newer_spec.topology = 2;
  const TestFabric newer = BuildFabric(newer_spec);
  PP_REQUIRE(base.snapshot != nullptr);
  PP_REQUIRE(newer.snapshot != nullptr);
  PP_CHECK(base.snapshot->Id() != newer.snapshot->Id());
  PP_CHECK(base.snapshot->Generations().topology != newer.snapshot->Generations().topology);

  StageGate gate;
  PlannerRuntime runtime(MakeConfig(base.snapshot, gate));
  const PlanningRequest request = MakeRequest(base, "topology-invalidation", base.route_b);
  gate.Arm(PlanningStage::kRanked, request.id);

  PlanningResult result;
  std::thread planner([&runtime, &request, &result]() { result = runtime.Plan(request); });
  gate.WaitForEntry();
  runtime.PublishSnapshot(newer.snapshot);
  gate.Release();
  planner.join();

  PP_CHECK_EQ(result.status, PlanStatus::kRevalidationRequired);
  PP_REQUIRE(!result.candidates.empty());
  PP_CHECK(AllCandidatesNotCurrent(result));
  for (const Candidate& candidate : result.candidates) {
    PP_CHECK_EQ(candidate.currentness, Currentness::kRevalidationRequired);
  }
  const PlannerStatistics stats = runtime.Stats();
  PP_CHECK_EQ(stats.plans_publish_rejected_stale, std::uint64_t(1));
  PP_CHECK_EQ(stats.plans_published, std::uint64_t(1));
  PP_CHECK_EQ(stats.plans_computed, std::uint64_t(1));
  PP_CHECK_EQ(stats.snapshots_published, std::uint64_t(1));
  PP_CHECK_EQ(runtime.PublishSequence().Value(), std::uint64_t(1));
}

// ---------------------------------------------------------------------------
// 2. Plan completion vs a traversed link going DOWN.
// ---------------------------------------------------------------------------
PP_TEST(race, plan_completion_vs_link_down) {
  const TestFabric base = BuildFabric(FabricSpec{});
  // Same topology label, so the link identities are the same links; only link state
  // moved (a newer link-state generation) and the traversed link is DOWN.
  FabricSpec down_spec;
  down_spec.link_state = 2;
  down_spec.first_route_a_link_down = true;
  const TestFabric down = BuildFabric(down_spec);
  PP_REQUIRE(base.snapshot != nullptr);
  PP_REQUIRE(down.snapshot != nullptr);
  // The request is pinned to route A, so the link that goes DOWN is a link the plan
  // must traverse.
  PP_CHECK_EQ(down.snapshot->LinkStates().StateOf(base.route_a.front()), LinkState::kDown);
  PP_CHECK_EQ(base.snapshot->LinkStates().StateOf(base.route_a.front()), LinkState::kUp);

  StageGate gate;
  PlannerRuntime runtime(MakeConfig(base.snapshot, gate));
  const PlanningRequest request = MakeRequest(base, "link-down", base.route_b);

  const PlanningResult initial = runtime.Plan(request);
  PP_REQUIRE(initial.status == PlanStatus::kPlanned);
  PP_REQUIRE(initial.candidates.size() == std::size_t(1));
  const std::vector<PathHop>& hops = initial.candidates.front().path.hops;
  PP_REQUIRE(hops.size() == std::size_t(2));
  PP_CHECK_EQ(hops.front().link, base.route_a.front());
  PP_CHECK_EQ(hops.back().link, base.route_a.back());

  gate.Arm(PlanningStage::kRanked, request.id);
  PlanningResult resent;
  std::thread planner([&runtime, &request, &resent]() { resent = runtime.Plan(request); });
  gate.WaitForEntry();
  runtime.PublishSnapshot(down.snapshot);
  gate.Release();
  planner.join();

  PP_CHECK_EQ(resent.status, PlanStatus::kRevalidationRequired);
  PP_REQUIRE(!resent.candidates.empty());
  PP_CHECK(AllCandidatesNotCurrent(resent));
  PP_CHECK_EQ(runtime.Stats().plans_publish_rejected_stale, std::uint64_t(1));

  // The new evidence genuinely makes the traversed link unusable.
  const PlanningResult after = runtime.Plan(request);
  PP_CHECK(after.candidates.empty());
  PP_CHECK(after.status != PlanStatus::kPlanned);
  bool reported_down = false;
  for (const RejectionExplanation& rejection : after.rejections) {
    if (rejection.code == DiagnosticCode::kLinkStateDown) {
      reported_down = true;
    }
  }
  PP_CHECK(reported_down);
  PP_CHECK_EQ(after.evidence.generations.link_state, LinkStateGeneration(2));
  PP_CHECK_EQ(after.evidence.snapshot, down.snapshot->Id());
}

// ---------------------------------------------------------------------------
// 3. Plan completion vs epoch advance.
// ---------------------------------------------------------------------------
PP_TEST(race, plan_completion_vs_epoch_advance) {
  const TestFabric base = BuildFabric(FabricSpec{});
  PP_REQUIRE(base.snapshot != nullptr);
  StageGate gate;
  PlannerRuntime runtime(MakeConfig(base.snapshot, gate));
  const PlanningRequest request = MakeRequest(base, "epoch-advance", base.route_b);
  gate.Arm(PlanningStage::kRanked, request.id);

  PlanningResult result;
  std::thread planner([&runtime, &request, &result]() { result = runtime.Plan(request); });
  gate.WaitForEntry();
  std::string reason;
  PP_REQUIRE(runtime.AdvanceEpoch(FabricEpoch(2), true, reason));
  PP_CHECK(!reason.empty());
  gate.Release();
  planner.join();

  PP_CHECK_EQ(result.status, PlanStatus::kRevalidationRequired);
  PP_REQUIRE(!result.candidates.empty());
  PP_CHECK(AllCandidatesNotCurrent(result));
  PP_CHECK_EQ(runtime.CurrentEpoch().Value(), std::uint64_t(2));
  PP_CHECK_EQ(runtime.Stats().plans_publish_rejected_stale, std::uint64_t(1));
  PP_CHECK_EQ(runtime.Stats().epochs_advanced, std::uint64_t(1));

  // The epoch hand-off is monotonic: the superseded epoch is refused.
  std::string refused_reason;
  PP_CHECK(!runtime.AdvanceEpoch(FabricEpoch(1), true, refused_reason));
  PP_CHECK(!refused_reason.empty());
  PP_CHECK_EQ(runtime.CurrentEpoch().Value(), std::uint64_t(2));

  // A request carrying the superseded coordinator epoch is EPOCH_STALE.
  PlanningRequest stale = MakeRequest(base, "epoch-advance-stale", base.route_b);
  stale.authority.epoch_bound = true;
  stale.authority.coordinator_epoch = CoordinatorEpoch(1);
  const PlanningResult stale_result = runtime.Plan(stale);
  PP_CHECK_EQ(stale_result.status, PlanStatus::kEpochStale);
  PP_REQUIRE(stale_result.primary_failure.has_value());
  PP_CHECK_EQ(*stale_result.primary_failure, DiagnosticCode::kEpochMismatch);
  PP_CHECK(stale_result.candidates.empty());

  // The current epoch still plans.
  PlanningRequest current = MakeRequest(base, "epoch-advance-current", base.route_b);
  current.authority.epoch_bound = true;
  current.authority.coordinator_epoch = CoordinatorEpoch(2);
  const PlanningResult current_result = runtime.Plan(current);
  PP_CHECK_EQ(current_result.status, PlanStatus::kPlanned);
  PP_CHECK_EQ(current_result.candidates.size(), std::size_t(1));
}

// ---------------------------------------------------------------------------
// 4. Concurrent identical requests.
// ---------------------------------------------------------------------------
PP_TEST(race, concurrent_identical_requests_are_stable) {
  const TestFabric base = BuildFabric(FabricSpec{});
  PP_REQUIRE(base.snapshot != nullptr);
  StageGate gate;  // never armed: the competing action here is repetition itself
  PlannerRuntime runtime(MakeConfig(base.snapshot, gate));
  const PlanningRequest request = MakeRequest(base, "concurrent", base.route_b);

  constexpr int kThreads = 8;
  std::barrier start(kThreads);
  std::vector<PlanningResult> results(static_cast<std::size_t>(kThreads));
  std::vector<std::string> rendered(static_cast<std::size_t>(kThreads));
  std::vector<std::thread> threads;
  threads.reserve(static_cast<std::size_t>(kThreads));
  for (int index = 0; index < kThreads; ++index) {
    threads.emplace_back([&runtime, &request, &start, &results, &rendered, index]() {
      const std::size_t slot = static_cast<std::size_t>(index);
      start.arrive_and_wait();
      results[slot] = runtime.Plan(request);
      rendered[slot] = RenderResult(results[slot], true);
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }

  const PlanningResult& first = results.front();
  PP_REQUIRE(first.status == PlanStatus::kPlanned);
  PP_REQUIRE(first.plan_id.IsValid());
  PP_REQUIRE(first.candidates.size() == std::size_t(1));
  for (int index = 0; index < kThreads; ++index) {
    const std::size_t slot = static_cast<std::size_t>(index);
    PP_CHECK_EQ(results[slot].plan_id, first.plan_id);
    PP_CHECK_EQ(results[slot].semantic_digest.bytes, first.semantic_digest.bytes);
    PP_CHECK_EQ(results[slot].planning_generation.Value(), std::uint64_t(1));
    PP_CHECK_EQ(rendered[slot], rendered.front());
  }
  PP_CHECK_EQ(runtime.Stats().plans_computed, static_cast<std::uint64_t>(kThreads));
  PP_CHECK_EQ(runtime.Stats().plans_published, static_cast<std::uint64_t>(kThreads));

  // Repeating the same request afterwards keeps generation 1 and the same identity:
  // semantic identity is stable under repetition, not only under concurrency.
  const PlanningResult repeat = runtime.Plan(request);
  PP_CHECK_EQ(repeat.planning_generation.Value(), std::uint64_t(1));
  PP_CHECK_EQ(repeat.plan_id, first.plan_id);
  PP_CHECK_EQ(repeat.semantic_digest.bytes, first.semantic_digest.bytes);
  PP_CHECK_EQ(RenderResult(repeat, true), rendered.front());
}

// ---------------------------------------------------------------------------
// 5. Persistence snapshot taken across an invalidation.
// ---------------------------------------------------------------------------
PP_TEST(race, persistence_snapshot_is_conservative) {
  const TestFabric base = BuildFabric(FabricSpec{});
  PP_REQUIRE(base.snapshot != nullptr);
  StageGate gate;
  PlannerRuntime runtime(MakeConfig(base.snapshot, gate));
  const PlanningRequest request = MakeRequest(base, "persistence", base.route_b);
  gate.Arm(PlanningStage::kRanked, request.id);

  PlanningResult result;
  std::thread planner([&runtime, &request, &result]() { result = runtime.Plan(request); });
  gate.WaitForEntry();
  InvalidationNotice notice;
  notice.links.push_back(base.route_a.front());
  const InvalidationReport invalidation = runtime.ApplyInvalidation(notice);
  PP_CHECK(invalidation.affected.empty());
  gate.Release();
  planner.join();

  PP_CHECK_EQ(result.status, PlanStatus::kRevalidationRequired);
  PP_REQUIRE(!result.candidates.empty());
  PP_CHECK(AllCandidatesNotCurrent(result));

  const PathPlan stale_plan = MakePathPlan(request, result, runtime.PublishSequence());
  PP_REQUIRE(runtime.Retain(stale_plan));
  PP_CHECK(!runtime.CheckCurrentness(stale_plan).current());

  // A second plan computed from proven-current evidence is persisted alongside it, so
  // the record set itself must be recovered conservatively.
  PlannerConfig clean_config;
  clean_config.initial_snapshot = base.snapshot;
  PlannerRuntime clean_runtime(clean_config);
  const PlanningRequest clean_request = MakeRequest(base, "persistence-current", base.route_b);
  const PlanningResult clean_result = clean_runtime.Plan(clean_request);
  PP_REQUIRE(clean_result.status == PlanStatus::kPlanned);
  const PathPlan current_plan = MakePathPlan(clean_request, clean_result, clean_runtime.PublishSequence());
  PP_CHECK(current_plan.currentness_proven);

  std::vector<StoredPlanRecord> records;
  records.push_back(ToStoredRecord(stale_plan));
  records.push_back(ToStoredRecord(current_plan));
  StoreOptions options;
  options.publish_sequence = runtime.PublishSequence();
  const std::wstring store_path = UniquePath(L".ppstore");
  const StoreResult saved = SavePlanStore(ToNarrow(store_path), records, options);
  PP_CHECK_MSG(saved.ok, saved.detail);

  std::vector<StoredPlanRecord> loaded;
  const StoreResult load = LoadPlanStore(ToNarrow(store_path), ResourceLimits{}, loaded);
  PP_CHECK_MSG(load.ok, load.detail);
  PP_REQUIRE(loaded.size() == std::size_t(2));
  PP_CHECK_EQ(loaded.front().plan, stale_plan.id);
  PP_CHECK_EQ(loaded.front().status, PlanStatus::kRevalidationRequired);
  PP_CHECK_EQ(loaded.back().plan, current_plan.id);
  PP_CHECK_EQ(loaded.back().status, PlanStatus::kPlanned);

  // A recovered record is never a CURRENT plan, whatever its stored status was.
  for (const StoredPlanRecord& record : loaded) {
    const PathPlan recovered = FromStoredRecord(record);
    PP_CHECK(!recovered.currentness_proven);
    PP_CHECK_EQ(recovered.ComputePlanId(), record.plan);
    PP_REQUIRE(!recovered.candidates.empty());
    for (const Candidate& candidate : recovered.candidates) {
      PP_CHECK(candidate.currentness != Currentness::kCurrent);
      PP_CHECK_EQ(candidate.currentness, Currentness::kRevalidationRequired);
    }
  }
  // The record recovered from the invalidated window additionally keeps the status
  // that was computed from non-current evidence.
  const PathPlan recovered_stale = FromStoredRecord(loaded.front());
  PP_CHECK_EQ(recovered_stale.status, PlanStatus::kRevalidationRequired);
}

// ---------------------------------------------------------------------------
// 6. Targeted invalidation vs an unrelated plan.
// ---------------------------------------------------------------------------
PP_TEST(race, targeted_invalidation_spares_unrelated_plan) {
  const TestFabric base = BuildFabric(FabricSpec{});
  PP_REQUIRE(base.snapshot != nullptr);
  StageGate gate;
  PlannerRuntime runtime(MakeConfig(base.snapshot, gate));

  const PlanningRequest request_a = MakeRequest(base, "targeted-a", base.route_b);
  const PlanningRequest request_b = MakeRequest(base, "targeted-b", base.route_a);
  const PlanningResult result_a = runtime.Plan(request_a);
  const PlanningResult result_b = runtime.Plan(request_b);
  PP_REQUIRE(result_a.status == PlanStatus::kPlanned);
  PP_REQUIRE(result_b.status == PlanStatus::kPlanned);

  const std::vector<LinkId> links_a = TraversedLinks(result_a);
  const std::vector<LinkId> links_b = TraversedLinks(result_b);
  PP_CHECK_EQ(links_a.size(), std::size_t(2));
  PP_CHECK_EQ(links_b.size(), std::size_t(2));
  std::vector<LinkId> shared;
  std::set_intersection(links_a.begin(), links_a.end(), links_b.begin(), links_b.end(), std::back_inserter(shared));
  PP_CHECK(shared.empty());

  const PathPlan plan_a = MakePathPlan(request_a, result_a, runtime.PublishSequence());
  const PathPlan plan_b = MakePathPlan(request_b, result_b, runtime.PublishSequence());
  PP_REQUIRE(runtime.Retain(plan_a));
  PP_REQUIRE(runtime.Retain(plan_b));
  PP_CHECK_EQ(runtime.RetainedPlanCount(), std::size_t(2));
  PP_CHECK(runtime.CheckCurrentness(plan_a).current());
  PP_CHECK(runtime.CheckCurrentness(plan_b).current());

  InvalidationNotice notice;
  notice.links.push_back(links_a.front());
  const InvalidationReport report = runtime.ApplyInvalidation(notice);
  PP_CHECK(!report.conservative);
  PP_CHECK_EQ(report.retained_plans, std::size_t(2));
  PP_CHECK_EQ(report.affected.size(), std::size_t(1));
  PP_REQUIRE(!report.affected.empty());
  PP_CHECK_EQ(report.affected.front(), plan_a.id);
  PP_CHECK_EQ(report.marked_revalidation_required.size(), std::size_t(1));
  PP_CHECK(report.retired.empty());

  const PlanCurrentnessReport currentness_a = runtime.CheckCurrentness(plan_a);
  PP_CHECK_EQ(currentness_a.currentness, Currentness::kRevalidationRequired);
  PP_CHECK(ContainsTargetedNotice(currentness_a));
  PP_CHECK(!currentness_a.current());

  // The unrelated plan is not marked by the notice: its only reported difference is
  // the global publication watermark every invalidation advances.
  const PlanCurrentnessReport currentness_b = runtime.CheckCurrentness(plan_b);
  PP_CHECK(!ContainsTargetedNotice(currentness_b));
  PP_CHECK_EQ(currentness_b.changes.size(), std::size_t(1));
  PP_REQUIRE(!currentness_b.changes.empty());
  PP_CHECK_EQ(currentness_b.changes.front().code, DiagnosticCode::kInvalidationWatermarkChanged);

  // Re-attesting both results at the watermark the invalidation published shows what
  // the notice actually did: the evidence of both routes is still current, so the
  // unrelated plan is CURRENT, and the named plan is non-current purely because the
  // targeted notice marked it (it stays marked above).
  PlanningResult reattested = result_b;
  reattested.evidence.publish_sequence = runtime.PublishSequence();
  const PathPlan plan_b_reattested = MakePathPlan(request_b, reattested, runtime.PublishSequence());
  PP_CHECK(runtime.CheckCurrentness(plan_b_reattested).current());
  PlanningResult reattested_a = result_a;
  reattested_a.evidence.publish_sequence = runtime.PublishSequence();
  const PathPlan plan_a_reattested = MakePathPlan(request_a, reattested_a, runtime.PublishSequence());
  PP_CHECK(runtime.CheckCurrentness(plan_a_reattested).current());

  // An invalidation naming a link no retained plan traverses affects nothing.
  InvalidationNotice unrelated;
  unrelated.links.push_back(LinkFromLabel("race-link:none"));
  const InvalidationReport unrelated_report = runtime.ApplyInvalidation(unrelated);
  PP_CHECK(unrelated_report.affected.empty());
  PP_CHECK_EQ(unrelated_report.retained_plans, std::size_t(2));
}

// ---------------------------------------------------------------------------
// Proof 1: real worker death and boot-identity fencing.
// ---------------------------------------------------------------------------
PP_TEST(race, distributed_worker_death_is_fenced) {
  const std::wstring executable = CliExecutable();
  if (executable.empty()) {
    PP_CHECK_MSG(false, "PP_CLI_BINARY (environment variable or compile-time macro) is not configured");
    return;
  }
  ChildRegistry children;
  const std::wstring endpoint_file = UniquePath(L".endpoint");
  ChildProcess& coordinator = children.Spawn(executable, CoordinatorArguments(1, endpoint_file, std::wstring()));
  std::string endpoint;
  PP_REQUIRE_MSG(PollEndpointFile(endpoint_file, endpoint), "the coordinator did not publish an endpoint");
  PP_CHECK(endpoint.size() > 10);

  ChildProcess& worker_a = children.Spawn(executable, WorkerArguments(1, endpoint, "boot-a", "publisher-a"));
  ChildProcess& worker_b = children.Spawn(executable, WorkerArguments(1, endpoint, "boot-b", "publisher-b"));

  PlanPoll first = PollUntilPlanned(endpoint, CliDemoRequest("proof1-first"), 60);
  PP_REQUIRE_MSG(first.planned, "no plan succeeded while two workers were registered: " + first.last.error);
  PP_CHECK_EQ(first.last.status, PlanStatus::kPlanned);
  PP_CHECK(!first.last.result.candidates.empty());
  PP_CHECK(first.last.result.plan_id.IsValid());

  // A genuine operating-system kill of worker A.
  PP_CHECK(worker_a.alive());
  PP_CHECK(worker_a.Stop());
  PP_CHECK(!ProcessIdAlive(worker_a.process_id()));

  // A further plan still succeeds through the surviving worker.
  PlanPoll second = PollUntilPlanned(endpoint, CliDemoRequest("proof1-second"), 60);
  PP_REQUIRE_MSG(second.planned, "planning failed after worker A died: " + second.last.error);
  PP_CHECK_EQ(second.last.status, PlanStatus::kPlanned);
  PP_CHECK(!second.last.result.candidates.empty());

  // A new worker process reusing the dead boot identity is refused by the coordinator.
  ChildProcess& duplicate = children.Spawn(executable, WorkerArguments(1, endpoint, "boot-a", "publisher-a"));
  PP_REQUIRE_MSG(duplicate.WaitForExit(kChildBoundMs), "the duplicate boot identity worker did not exit");
  const std::string duplicate_output = duplicate.ReadOutput();
  PP_CHECK_MSG(duplicate.exit_code() != 0, "duplicate boot worker output: " + duplicate_output);
  PP_CHECK_MSG(HasExactLine(duplicate_output, "worker_fenced true"), "output: " + duplicate_output);
  PP_CHECK_MSG(HasExactLine(duplicate_output, "worker_registered false"), "output: " + duplicate_output);
  PP_CHECK(!HasExactLine(duplicate_output, "worker_registered true"));

  // A fresh boot identity is accepted and planning succeeds again.
  ChildProcess& worker_c = children.Spawn(executable, WorkerArguments(1, endpoint, "boot-c", "publisher-c"));
  PlanPoll third = PollUntilPlanned(endpoint, CliDemoRequest("proof1-third"), 60);
  PP_REQUIRE_MSG(third.planned, "planning failed after a fresh worker registered: " + third.last.error);
  PP_CHECK_EQ(third.last.status, PlanStatus::kPlanned);
  PP_CHECK(!third.last.result.candidates.empty());

  // The coordinator survived the death of worker A and the refused duplicate, and the
  // worker that carried the traffic is still running.
  PP_CHECK(coordinator.alive());
  PP_CHECK(worker_b.alive());
  PP_CHECK(worker_c.alive());
  children.KillAllAndVerify("the worker death proof");
}

// ---------------------------------------------------------------------------
// Proof 2: real coordinator restart with durable history.
// ---------------------------------------------------------------------------
PP_TEST(race, distributed_coordinator_restart_is_conservative) {
  const std::wstring executable = CliExecutable();
  if (executable.empty()) {
    PP_CHECK_MSG(false, "PP_CLI_BINARY (environment variable or compile-time macro) is not configured");
    return;
  }
  ChildRegistry children;
  const std::wstring store_path = UniquePath(L".ppstore");
  const std::wstring endpoint_file_1 = UniquePath(L".endpoint");

  // Incarnation 1 at epoch 1, with a durable planning history.
  ChildProcess& coordinator_1 = children.Spawn(executable, CoordinatorArguments(1, endpoint_file_1, store_path));
  std::string endpoint_1;
  PP_REQUIRE_MSG(PollEndpointFile(endpoint_file_1, endpoint_1), "coordinator 1 published no endpoint");
  {
    const std::string output = coordinator_1.ReadOutput();
    std::uint64_t epoch = 0;
    PP_REQUIRE_MSG(LineNumber(output, "epoch", epoch), "coordinator 1 printed no epoch line: " + output);
    PP_CHECK_EQ(epoch, std::uint64_t(1));
    PP_CHECK(LineNumber(output, "recovered_plans", epoch));
  }

  children.Spawn(executable, WorkerArguments(1, endpoint_1, "boot-r1", "publisher-r1"));
  PlanPoll first = PollUntilPlanned(endpoint_1, CliDemoRequest("proof2-first"), 60);
  PP_REQUIRE_MSG(first.planned, "planning failed against coordinator 1: " + first.last.error);
  PP_CHECK_EQ(first.last.status, PlanStatus::kPlanned);
  PP_CHECK(!first.last.result.candidates.empty());

  // The durable record set exists and is decodable, and every recovered record is
  // conservatively marked: FromStoredRecord never yields a CURRENT plan.
  std::vector<StoredPlanRecord> records;
  bool stored = false;
  for (int attempt = 0; attempt < kPollIterations && !stored; ++attempt) {
    if (FileExists(store_path)) {
      std::vector<StoredPlanRecord> candidate_records;
      const StoreResult loaded = LoadPlanStore(ToNarrow(store_path), ResourceLimits{}, candidate_records);
      if (loaded.ok && !candidate_records.empty()) {
        records = std::move(candidate_records);
        stored = true;
        break;
      }
    }
    Sleep(kPollSliceMs);
  }
  PP_REQUIRE_MSG(stored, "the coordinator store was never written");
  const PathPlan recovered_before = FromStoredRecord(records.front());
  PP_CHECK(!recovered_before.currentness_proven);
  for (const Candidate& candidate : recovered_before.candidates) {
    PP_CHECK(candidate.currentness != Currentness::kCurrent);
  }

  // Hard kill of the first coordinator incarnation.
  PP_CHECK(coordinator_1.alive());
  PP_CHECK(coordinator_1.Stop());
  PP_CHECK(!ProcessIdAlive(coordinator_1.process_id()));

  // Incarnation 2 at epoch 2 recovers the durable history.
  const std::wstring endpoint_file_2 = UniquePath(L".endpoint");
  ChildProcess& coordinator_2 = children.Spawn(executable, CoordinatorArguments(2, endpoint_file_2, store_path));
  std::string endpoint_2;
  PP_REQUIRE_MSG(PollEndpointFile(endpoint_file_2, endpoint_2), "coordinator 2 published no endpoint");
  std::uint64_t epoch_2 = 0;
  PP_REQUIRE_MSG(LineNumber(coordinator_2.ReadOutput(), "epoch", epoch_2),
                 "coordinator 2 printed no epoch line: " + coordinator_2.ReadOutput());
  PP_CHECK_EQ(epoch_2, std::uint64_t(2));
  std::uint64_t recovered_2 = 0;
  PP_REQUIRE_MSG(LineNumber(coordinator_2.ReadOutput(), "recovered_plans", recovered_2),
                 "coordinator 2 printed no recovered_plans line: " + coordinator_2.ReadOutput());
  PP_CHECK(recovered_2 >= std::uint64_t(1));

  // No worker has registered against the new incarnation yet: a structured failure,
  // never a fabricated success. Prior live worker authority did not survive.
  const PlanAttempt no_worker = SubmitOnce(endpoint_2, CliDemoRequest("proof2-no-worker"));
  PP_CHECK(!no_worker.delivered);
  PP_CHECK_MSG(no_worker.error.find("NO_WORKER_AVAILABLE") != std::string::npos,
               "unexpected failure for a workerless coordinator: " + no_worker.error);
  PP_CHECK(no_worker.result.candidates.empty());
  PP_CHECK_EQ(no_worker.status, PlanStatus::kRevalidationRequired);

  // A fresh worker registers against incarnation 2 and planning succeeds.
  ChildProcess& worker_2 = children.Spawn(executable, WorkerArguments(2, endpoint_2, "boot-r2", "publisher-r2"));
  PlanPoll second = PollUntilPlanned(endpoint_2, CliDemoRequest("proof2-second"), 60);
  PP_REQUIRE_MSG(second.planned, "planning failed against coordinator 2: " + second.last.error);
  PP_CHECK_EQ(second.last.status, PlanStatus::kPlanned);
  PP_CHECK(worker_2.alive());

  // Worker evidence from the previous epoch is refused.
  ChildProcess& stale_worker = children.Spawn(executable, WorkerArguments(1, endpoint_2, "boot-stale", "publisher-old"));
  PP_REQUIRE_MSG(stale_worker.WaitForExit(kChildBoundMs), "the stale-epoch worker did not exit");
  const std::string stale_output = stale_worker.ReadOutput();
  PP_CHECK_MSG(stale_worker.exit_code() != 0, "stale epoch worker output: " + stale_output);
  PP_CHECK_MSG(HasExactLine(stale_output, "worker_fenced true"), "output: " + stale_output);
  PP_CHECK_MSG(HasExactLine(stale_output, "worker_registered false"), "output: " + stale_output);

  // Incarnation 3 at epoch 3: the epoch progresses monotonically across three
  // incarnations and the durable history is still recovered.
  PP_CHECK(coordinator_2.Stop());
  const std::wstring endpoint_file_3 = UniquePath(L".endpoint");
  ChildProcess& coordinator_3 = children.Spawn(executable, CoordinatorArguments(3, endpoint_file_3, store_path));
  std::string endpoint_3;
  PP_REQUIRE_MSG(PollEndpointFile(endpoint_file_3, endpoint_3), "coordinator 3 published no endpoint");
  std::uint64_t epoch_3 = 0;
  PP_REQUIRE_MSG(LineNumber(coordinator_3.ReadOutput(), "epoch", epoch_3),
                 "coordinator 3 printed no epoch line: " + coordinator_3.ReadOutput());
  PP_CHECK_EQ(epoch_3, std::uint64_t(3));
  std::uint64_t recovered_3 = 0;
  PP_REQUIRE_MSG(LineNumber(coordinator_3.ReadOutput(), "recovered_plans", recovered_3),
                 "coordinator 3 printed no recovered_plans line: " + coordinator_3.ReadOutput());
  PP_CHECK(recovered_3 >= std::uint64_t(1));
  PP_CHECK(epoch_3 > epoch_2);
  PP_CHECK(epoch_2 > std::uint64_t(1));

  // The third incarnation is alive with the recovered history.
  PP_CHECK(coordinator_3.alive());
  children.KillAllAndVerify("the coordinator restart proof");
}

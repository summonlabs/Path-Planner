# Path Planner 1.0.0

Path Planner is the deterministic candidate-path computation runtime of the Distributed Fabric
Infrastructure / Fabric OS stack. It answers one question:

> Given exact source and destination identities, current authoritative fabric state, and an explicit
> bounded planning request, which end-to-end candidate path or paths satisfy the request, in what
> deterministic order, under which generations and evidence, and why?

A path being *computable* is not the same as the path being authoritative, installed, selected for traffic,
bandwidth-reserved, congestion-optimal, part of an ECMP group, diverse from another path, or still legal
after evidence changes. Path Planner keeps those concepts separate and never collapses them.

---

## 1. What Path Planner owns

* path computation, path search and graph traversal for planning;
* source/destination planning requests and bounded planning constraints;
* hard feasibility filtering, deterministic candidate ordering and tie-breaking;
* path-cost and hop-count calculation, path reconstruction;
* planning generation, plan identity and plan provenance;
* planning evidence vectors, currentness, stale-plan detection and deterministic explanations;
* bounded candidate enumeration, planning snapshots and deterministic plan digests;
* bounded planning persistence, distributed planning requests, conservative restart/revalidation;
* deterministic synthetic planning at scale.

## 2. What Path Planner does not own, and never claims

| Concern | Owner |
| --- | --- |
| Canonical entity identity | Fabric Registry |
| Topology truth, structural generations | Fabric Topology |
| Operational link state | Link State Fabric |
| Port configuration and port state | Port Fabric |
| Capability truth | Fabric Capability Registry |
| Failure-domain semantics and membership | Failure Domain Registry |
| Fabric Epoch issuance | Fabric Epoch |
| Legality of one exact path | Path Authority |
| Authoritative route lifecycle | Route Fabric |
| Concurrent path use, path-set authority | Multipath Fabric |
| ECMP membership, hashing, rebalancing | ECMP Governor |
| Traffic weights for non-equal distribution | Weighted Path Fabric |
| Adaptive reaction to changing state | Adaptive Routing Fabric |
| Ordered migration, loop avoidance, convergence staging | Route Convergence |
| Bandwidth reservation, admission, congestion control, queueing, flow placement, failover promotion | outside Path Planner |

Path Planner reads authoritative records; it never issues identity, topology, link state, port state,
capability, failure-domain or epoch truth, and it never installs, withdraws or supersedes route state.

### 2.1 Path Planner and Path Authority

Path Planner constructs candidate paths. Path Authority validates exact supplied paths under current
authoritative evidence. The intended handoff is:

```
Path Planner computes candidate path P
  -> Path Authority evaluates exact P
  -> Route Fabric may bind an authoritative route to a currently legal P
```

The integration is explicit and optional. With `AuthorityValidationMode::kNone` (the default) every
candidate is reported with `authority=NOT_REQUESTED`, which is a statement that Path Planner is making no
legality claim. With `kBestEffort` or `kRequired` a caller-supplied `IPathAuthority` is consulted per
candidate and the verdict (`VALIDATED`, `REJECTED`, `UNAVAILABLE`) is recorded. `kRequired` without a
configured Path Authority is refused with `UNSUPPORTED` rather than silently downgraded.

### 2.2 Path Planner and Route Fabric, Multipath, ECMP, Weighted, Adaptive, Convergence

Planning results are values, not route state. A ranked candidate list is a deterministic list; it is not a
multipath policy, not an ECMP group, and not a traffic-share assignment. Path Planner reports staleness
("this plan is stale because its link-state dependency changed") and never moves live flows, schedules
convergence or reserves bandwidth.

## 3. Graph inputs

Planning consumes an immutable `FabricSnapshot` built by `FabricSnapshotBuilder` from the records the owning
runtimes publish:

* nodes with entity and structural generations plus their published ports;
* directed edges with link identity, endpoint nodes, endpoint ports, layer, relationship type, administrative
  static cost and structural generation;
* endpoint bindings (identity, class, node, port, entity generation);
* link-state records (Link State Fabric), port-state records (Port Fabric), capability bindings
  (Fabric Capability Registry) and failure domains with risk classes and membership (Failure Domain Registry);
* the generation vector: topology, link state, port, capability, failure domain, Fabric Epoch, policy and
  constraint generations.

The builder rejects duplicate identities, dangling node/port references, self loops, relationship types that
disagree with the layer, structural generations ahead of the topology generation, duplicate view records and
every configured size ceiling. A snapshot is deeply immutable once built, has a content-derived `SnapshotId`
and a `Digest()` over its canonical encoding, and is safe to share across threads by `const` reference.

Planning never traverses a graph that can change underneath it: a request captures the current snapshot
(`shared_ptr` copy) under a short lock, releases it, and plans against stable values. No topology write lock
is ever held during path computation.

## 4. Planning request

`PlanningRequest` binds everything the computation depends on:

* `source` / `destination`: canonical endpoint identity **plus endpoint class plus entity generation**;
* `constraints`: constraint-set identity and generation, layer, forbidden nodes/links/ports/failure domains/
  risk classes, ordered transit stages, capability requirements, optional `max_hops` (absent means unbounded),
  `max_members_per_failure_domain` and the failure-domain fail-closed flag;
* `policy`: policy generation, cost model, degraded/draining/maintenance permissions, operational-proof
  requirement, zero-hop self-path semantics, locality scope, Path Authority validation mode;
* `max_candidates`, `mode` (STANDARD or DIAGNOSTIC_NON_CURRENT);
* caller authority: scope mask, publisher, worker boot, coordinator epoch, mutation attempt;
* optional currentness expectations: expected Fabric Epoch, topology generation and snapshot identity.

`ValidateRequest` rejects nil identities, unknown enumeration values, unsupported layers, duplicate
constraint entries, constraint counts above the configured ceilings, `max_candidates` above the ceiling and
a locality penalty without a locality scope. Malformed input is reported as `MALFORMED_REQUEST`, never as an
exception and never as an empty success.

## 5. Hard constraints before scoring

The pipeline order is fixed:

```
decode request
  -> validate caller authority
  -> validate epoch expectation
  -> resolve source/destination (exact identity, class and generation)
  -> capture coherent evidence snapshot
  -> build the eligible planning view (hard structural validity, currentness, administrative
     eligibility, link state, port state, capability requirements, failure-domain requirements,
     bounded path constraints)
  -> search
  -> reconstruct candidates
  -> score
  -> canonicalize
  -> rank deterministically
  -> validate final currentness against the invalidation watermark
  -> publish the structured result
```

Legality and preference are never blended into one number: a hard-invalid candidate cannot survive because
it has a favourable score.

### 5.1 Link-state filtering

| State | Standard mode | Diagnostic mode |
| --- | --- | --- |
| `UP` | eligible | eligible |
| `DOWN` | ineligible | ineligible |
| `FAULTED` | ineligible | ineligible |
| `RETIRED` | ineligible | ineligible |
| `REVALIDATION_REQUIRED` | ineligible | eligible, result never `CURRENT` |
| `UNKNOWN` (including "no record published") | ineligible while `require_operational_proof` is true | eligible, result never `CURRENT` |
| `DEGRADED` | eligible only with `allow_degraded_links`, charged the degraded penalty | same |

`UNKNOWN` is never treated as `UP`. Setting `require_operational_proof=false` makes UNKNOWN traversable but
marks the whole result provisional (`REVALIDATION_REQUIRED`, candidate `currentness=REVALIDATION_REQUIRED`).

### 5.2 Port-state filtering

`ADMIN_DISABLED`, `RETIRED` and `SUPERSEDED` are always ineligible. `DRAINING` and `MAINTENANCE` require
`allow_draining_ports` / `allow_maintenance_ports` (or diagnostic mode) and are reported as non-current.
`REVALIDATION_REQUIRED` and `UNKNOWN` follow the operational-proof rule above.

### 5.3 Capability filtering

A requirement is satisfied only by an explicitly published binding that satisfies the comparator
(`AT_LEAST`, `AT_MOST`, `EQUAL`) in the requested scope (`EVERY_NODE`, `EVERY_LINK`, `EVERY_PORT`,
`SOURCE_NODE`, `DESTINATION_NODE`). A missing binding is `CAPABILITY_UNKNOWN` and fails the requirement;
capabilities are never inferred from device names or vendors.

### 5.4 Failure-domain filtering

`avoid FailureDomainId`, `avoid risk class`, and `max_members_per_failure_domain` (the number of traversed
links sharing one domain) are supported. Membership is never invented. When the registry does not publish
complete membership, an entity without a membership record has UNKNOWN membership, and any active
failure-domain constraint fails closed (`FAILURE_DOMAIN_UNKNOWN`) unless the request explicitly clears
`fail_closed_on_unknown_domains`.

## 6. Path representation and identity

A candidate path is an ordered typed sequence: source node, then one `PathHop` per traversed adjacency
(link identity, source/destination node, source/destination port, layer, relationship type, structural
generation, static cost, observed link state, degraded flag), then the destination node. Paths are never
free-form text.

Canonical encoding is versioned (`kPathEncodingVersion`) and deterministic; equivalent semantic paths encode
identically and a different hop order produces different bytes. `CandidatePathId` is the leading 16 bytes of
SHA-256 over that canonical form, so it contains no process-local counter, timestamp, address or arrival
order. `PathPlanId` and the plan semantic digest are derived the same way from the plan semantic encoding,
which covers request identity, evidence generations, status and the ordered candidate identities with their
costs. Publication sequence and runtime planning generation are deliberately excluded, so an exact
recomputation under unchanged evidence yields the same semantic plan and digest.

## 7. Cost model and ranking

```
total = hops_cost + static_cost + degraded_penalty + locality_penalty
  hops_cost        = hop_count * cost_model.hop_cost
  static_cost      = sum of the administrative static cost of every traversed link
  degraded_penalty = degraded_hops * cost_model.degraded_penalty
  locality_penalty = hops leaving policy.locality_scope * cost_model.locality_penalty
```

All arithmetic is checked fixed-width unsigned arithmetic. Overflow is rejected (`RESOURCE_LIMIT` with
`COST_OVERFLOW`), never wrapped. There is no floating point anywhere in the planning path, no live congestion
input, no bandwidth-reservation state and no hidden weight.

Ranking is a total order: **total cost**, then **hop count**, then the **lexicographic node-id sequence**
(then link ids for parallel links between the same nodes). No hash-map iteration order, insertion order,
thread scheduling, address or timestamp takes part.

## 8. Algorithms

**Single shortest path (exact).** Two modes of one label-setting algorithm over the eligible view:

* when the caller supplies no hop bound, or when `max_hops` cannot bind (it is at least `V-1`),
  Dijkstra over nodes with lexicographic `(cost, hops)` labels: `O((V + E) log V)`;
* otherwise Dijkstra over `(hops, node)` states with `H + 1` layers, `H = max_hops`:
  `O((V*H + E*H) log(V*H))`, allocated only when `(H+1) * V` fits `max_search_states`.

Reconstruction walks the exact-cost DAG restricted to the chosen hop count and greedily takes the smallest
successor node id, which yields the lexicographically smallest node sequence among all minimum
`(cost, hops)` paths. Paths produced this way are simple by construction: any repeat could be short-circuited
into a strictly better `(cost, hops)` label.

**K candidates.** Yen's algorithm over the eligible view with the same canonical subroutine. Edges are banned
by adjacency entry, so parallel links between the same nodes are enumerated as distinct candidates. The
algorithm is bounded by `max_candidates` (requested), `max_enumeration_candidates` (enumeration ceiling when
a path-level constraint filters the canonical order), `max_spur_searches` and the shared state/push budget.
K = 1 bypasses the K-path machinery entirely. Candidate work, memory and spur searches are all bounded;
exhausting a bound returns `RESOURCE_LIMIT` with `WORK_BUDGET_EXHAUSTED`.

**Required transit.** `required_transit` is an ordered list of stages; each stage is one exact node or a
bounded set of alternatives. Each leg is the canonical-minimum path in the eligible graph with the nodes
already used by earlier legs excluded; every alternative combination is evaluated (bounded by
`max_transit_combinations`) and the canonical minimum is returned, so the outcome does not depend on
enumeration order. Required transit is a hard planning requirement, never a legality claim. K > 1 combined
with required transit is rejected explicitly with `UNSUPPORTED` because staged legs have no proven
K-shortest semantics.

**Loop prevention.** Ordinary forwarding paths must be simple. Cycles are never generated (the search is
acyclic by construction) and never accepted: well-formedness and simplicity are re-checked before a candidate
is emitted.

## 9. Evidence, currentness, staleness and replanning

Every candidate and every plan binds an `EvidenceVector`: snapshot identity, topology, link-state, port,
capability, failure-domain, Fabric Epoch, policy and constraint generations, evidence provenance and the
publication sequence (invalidation watermark). Wall-clock age is never a currentness model.

Currentness values are `CURRENT`, `REVALIDATION_REQUIRED`, `STALE_TOPOLOGY`, `STALE_LINK_STATE`,
`STALE_PORT_STATE`, `STALE_CAPABILITY`, `STALE_FAILURE_DOMAIN`, `STALE_POLICY`, `STALE_EPOCH` and `RETIRED`,
with a documented severity order (epoch and topology outrank link state, port state, capability, failure
domain and policy; `RETIRED` is terminal).

`CheckCurrentness(plan)` compares the plan evidence with current evidence, reports the **exact** dependency
changes (`link-state generation changed: 3 -> 4`, `publication watermark advanced: 0 -> 1`), and reports
`RETIRED` when a dependency no longer exists. `Replan` recomputes and reports `UNCHANGED`, `ORDERING_CHANGED`,
`CANDIDATE_SET_CHANGED`, `NO_PATH` or `REVALIDATION_REQUIRED`. Replanning never alters Route Fabric or any
other runtime.

### 9.1 Invalidation watermarks and precise invalidation

Retained plans are indexed by reverse dependency (node, link, port subjects). `ApplyInvalidation` with a
targeted notice marks exactly the plans that depend on the named subjects; plans that do not depend on them
stay `CURRENT`. A depended-upon subject that no longer exists in the current snapshot marks the plan
`RETIRED`. Capability and failure-domain notices do not carry per-plan dependency records, so they use an
explicit conservative fallback (`conservative=true`) that invalidates every retained plan; this is reported,
not silent.

Every invalidation and every snapshot publication advances a monotonic publication sequence. A plan that
started under sequence *N* and finishes after the sequence moved to *N+1* is reported as
`REVALIDATION_REQUIRED` and its candidates are never `CURRENT`: stale completion cannot become current, and
completion order never determines authority.

## 10. Structured results and explanations

`PlanningResult` always carries a `PlanStatus`: `PLANNED`, `NO_PATH`, `SOURCE_UNKNOWN`, `DESTINATION_UNKNOWN`,
`SOURCE_STALE`, `DESTINATION_STALE`, `TOPOLOGY_STALE`, `EPOCH_STALE`, `CONSTRAINT_UNSATISFIED`,
`RESOURCE_LIMIT`, `REVALIDATION_REQUIRED`, `MALFORMED_REQUEST`, `UNAUTHORIZED`, `UNSUPPORTED` or
`TRUNCATED_BY_LIMIT`. Callers never have to guess why planning did not produce candidates.

When no candidate exists the result carries a deterministic primary failure classification with a documented
precedence (invalid request -> caller authority -> stale epoch -> source/destination identity -> topology
evidence -> hard constraint impossibility -> no traversable structural path -> no operational path -> no
capability-compatible path -> no failure-domain-compliant path), plus secondary diagnostics. Rejections are
aggregated per cause with example subjects (`LINK_STATE_DOWN occurrences=12 subject=LINK:... examples: ...`),
and constraint-driven exclusions are listed individually. Rank explanations expose the real cost components
of each candidate, never a single unexplained score. `explain.hpp` renders all of this as stable,
line-oriented text.

## 11. Distributed planning

```
client ──PLAN_REQUEST──▶ coordinator ──PLAN_REQUEST──▶ worker (PlannerRuntime)
                             │◀─────PLAN_RESULT─────┘
                             │  validate: boot registered? not fenced? epoch? evidence?
        ◀──PLAN_RESULT/PLAN_ERROR──┘
```

* The coordinator owns the Fabric Epoch it issues, the worker registry and the acceptance decision.
* Workers hold the same evidence identity as the coordinator and plan locally; the coordinator verifies the
  worker evidence identity instead of shipping the graph.
* A publication is accepted only when its `WorkerBootId` is registered and not fenced, its
  `CoordinatorEpoch` equals the current epoch and its snapshot identity matches current coordinator evidence.
* Worker session loss fences that boot identity permanently; a restarted worker process generates a fresh
  boot identity from operating-system entropy. A late completion from a fenced boot is refused.
* `AdvanceEpoch` (coordinator restart or explicit advancement) requires a strictly greater epoch, applies
  conservative recovery to the local runtime (every retained plan requires revalidation) and fences every
  registered worker so no prior live authority survives.

### 11.1 Wire protocol

Every frame is a fixed header plus payload, with stable explicit message identifiers (`HELLO`,
`REGISTER_WORKER`, `PLAN_REQUEST`, `PLAN_RESULT`, `PLAN_ERROR`, `VALIDATE_CURRENTNESS`,
`CURRENTNESS_RESULT`, `SNAPSHOT_REQUEST`, `SNAPSHOT_RESPONSE`, `FENCE_NOTICE`, `ERROR`, `SHUTDOWN_WORKER`) and
explicit enumeration values that never depend on ordinal layout. Frames carry a protocol version, the
coordinator epoch, a sequence, the worker boot identity and the request identity. A truncated SHA-256
integrity value covers the semantic header fields and the payload. Decoding is strict: wrong magic, wrong
version, unknown message, unknown flag bits, non-zero reserved fields, length disagreement, integrity
mismatch, unknown enum values, over-limit counts and trailing bytes are all rejected with a specific status.

Integrity is integrity, not authentication: the protocol performs no cryptographic peer authentication and
must only be exposed on a trusted transport.

The receive path is bounded by product behaviour, not by a test watchdog: the header and the payload are each
read under `limits.receive_bound_ms`, and a partial frame or a slow peer produces an explicit session failure
(`RECEIVE_BOUND_EXCEEDED`) instead of pinning a session thread. The same bound applies to a coordinator
waiting for a worker publication.

## 12. Persistence and recovery

`store.hpp` persists bounded planning history: request identity, plan identity, planning generation, publish
sequence, status, evidence vector, constraint/policy generations, canonical candidate paths with costs and
ranks, and the semantic digest. It never persists live worker authority, sockets, thread state or transient
search state.

The format has a fixed magic, an explicit persisted-format version, independent planning-rule and
path-encoding versions, a checked record count and payload length, and a SHA-256 digest over header and
payload. Decoding rejects an empty image, bad magic, unsupported versions, truncation at any length, a
flipped bit in the payload or the digest, duplicate plan or candidate identities, impossible generations,
cost components that do not sum to the total, costs that are not non-decreasing, malformed path encodings,
nil identifiers, over-limit counts, a record whose recomputed semantic digest does not match, and trailing
bytes. Saving is an atomic replacement, so the destination is only ever observed complete.

Recovery is conservative. `FromStoredRecord` always clears `currentness_proven` and marks every candidate
`REVALIDATION_REQUIRED`; a coordinator started with `--store` reports `recovered_plans <n>` and never resumes
authority from disk.

## 13. Determinism

Same graph, same evidence, same request, same policy produce the same ordered candidates, the same candidate
identities, the same plan identity and byte-identical rendered output. Equivalent graphs built in different
insertion orders produce identical results. Determinism is enforced by:

* sorted, content-addressed identity everywhere (nodes, links, ports, endpoints, views);
* a total ranking order independent of container iteration or scheduling;
* canonical, versioned encodings for paths and plans;
* a deterministic work budget counted in states, pushes and spur searches - never in elapsed time;
* compare-before-publish watermarks for in-flight work.

## 14. Resource limits

Every configured limit is enforced and every breach is reported, never silently truncated:

| Limit | Default | Enforced at |
| --- | --- | --- |
| `max_nodes` / `max_edges` / `max_endpoints` | 1,048,576 / 4,194,304 / 1,048,576 | snapshot build |
| `max_ports_per_node` | 4096 | snapshot build |
| `max_link_state_records`, `max_port_state_records`, `max_capability_bindings` | 4,194,304 | snapshot build |
| `max_failure_domains` / `max_members_per_failure_domain` | 262,144 / 65,536 | snapshot build |
| `max_candidates_per_request` | 64 | request validation |
| `max_hops` | 512 | ceiling for a caller-supplied hop bound (request validation); the hop-expanded search dimension |
| `max_constraints_total`, `max_forbidden_ids`, `max_required_ids` | 4096, 2048, 256 | request validation |
| `max_required_any_sets`, `max_members_in_any_set` | 64, 256 | request validation |
| `max_transit_alternatives`, `max_transit_combinations` | 1024, 64 | transit enumeration |
| `max_capability_requirements`, `max_forbidden_domain_classes` | 256, 256 | request validation |
| `max_enumeration_candidates` | 256 | candidate enumeration |
| `max_expanded_states`, `max_queue_entries`, `max_spur_searches` | 50,000,000 / 20,000,000 / 4,000,000 | search work budget |
| `max_search_states` | 4,000,000 | hop-expanded allocation |
| `max_retained_plans`, `max_history_entries`, `max_explanation_entries` | 4096, 64, 256 | retention and explanations |
| `max_reverse_dependency_entries`, `max_persisted_plans` | 1,048,576 / 65,536 | invalidation index and store |
| `max_frame_bytes` | 1 MiB | protocol framing |
| `max_sessions`, `max_concurrent_requests`, `max_workers` | 256, 256, 64 | coordinator sessions |
| `receive_bound_ms`, `send_bound_ms`, `connect_bound_ms` | 15,000 / 15,000 / 10,000 | protocol receive, send and connect bounds |

`ValidateLimits` rejects incoherent configurations at construction.

## 15. Proof classification: REAL, SYNTHETIC, UNSUPPORTED

**REAL** (verified in this repository, on this host):

* real OS processes: coordinator and worker are separate processes; worker death uses genuine process
  termination and coordinator restart uses a hard kill;
* real loopback TCP sessions with the framed protocol above;
* real file persistence with atomic replacement and a real corruption test matrix;
* real local host adapter identities read through the Windows IP Helper API (read-only);
* real MSVC Release, Debug, AddressSanitizer and `/analyze` builds.

**SYNTHETIC** (clearly labelled, deterministic, generated by the seeded generator):

* every fabric-scale topology used in tests, examples and benchmarks (chain, ring, diamond, leaf-spine,
  fat-tree-like, mesh, disconnected, one-way, parallel equal-cost, tie-storm, hub, deep, sparse-large,
  dense-bounded);
* link-state, port-state, capability and failure-domain populations;
* 1k / 10k / 100k node scale measurements.

Synthetic fabric paths are never described as physical proof.

**UNSUPPORTED** (not available in this environment and therefore not claimed):

* physical switch/router/optical/InfiniBand fabric hardware and any vendor route SDK;
* multi-host partitions or external routing protocols;
* authority to install, withdraw or supersede routes;
* ECMP membership, traffic weighting, adaptive routing, convergence sequencing or bandwidth reservation.

### 15.1 Real local discovery

`pathplanner snapshot --source local` reports the host's own adapters (friendly name, description, MAC,
interface index, operational state, loopback flag) as a single-node host-local planning view labelled
`REAL`. That is the honest limit of a single workstation: it exposes host adapter identity, not switch
topology.

## 16. Build

Requirements: CMake 3.20 or newer and a C++20 compiler. On Windows the verified toolchain is MSVC 19.44
(Visual Studio 2022) with the Windows SDK; first-party code is built with `/W4 /WX /permissive- /utf-8` and
zero warnings.

```
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `PATHPLANNER_BUILD_TESTS` | ON | build the test suites |
| `PATHPLANNER_BUILD_EXAMPLES` | ON | build the public API examples |
| `PATHPLANNER_BUILD_BENCHMARKS` | ON | build the guarded benchmarks |
| `PATHPLANNER_BUILD_CLI` | ON | build the `pathplanner` binary |
| `PATHPLANNER_WARNINGS_AS_ERRORS` | ON | `/WX` (MSVC) or `-Werror` |
| `PATHPLANNER_ENABLE_ASAN` | OFF | AddressSanitizer build (MSVC `/fsanitize=address` with debug info; the runtime is staged next to every executable) |
| `PATHPLANNER_ENABLE_ANALYZE` | OFF | MSVC static analysis (`/analyze`) |
| `BUILD_SHARED_LIBS` | OFF | build `PathPlanner` as a shared library |

Executables land in `build/bin/<config>`.

## 17. Test

```
ctest --test-dir build -C Release --output-on-failure
```

Suites: `core` (identity, codec, snapshot contract, request validation, planner statuses, currentness,
persistence, protocol codec, rendering), `oracle` (independent brute-force oracle and property tests over
randomized seeded graphs plus the graph families), `adversarial` (malformed input, forged and stale
publications, protocol corruption, partial frames, persistence corruption, resource exhaustion), `race`
(deterministic in-process races and the real-process worker-death, fencing and coordinator-restart proofs)
and `sources` (synthetic generator determinism and real local discovery).

No test uses a timeout, a fixed TCP port or a sleep as synchronization. Bounded waits always end in an
explicit assertion.

## 18. Install and use the package

```
cmake --install build --config Release --prefix <prefix>
```

Downstream:

```cmake
find_package(PathPlanner CONFIG REQUIRED)
target_link_libraries(my_target PRIVATE SummonSoftwareLabs::PathPlanner)
```

```cpp
#include <pathplanner/pathplanner.hpp>
using namespace summon::pathplanner;
```

`PathPlannerConfig.cmake` fails fast if the exported target or its include directories are missing. The
package also reports `PathPlanner_VERSION` and `PathPlanner_LIBRARY_TARGET`. A complete, buildable downstream
project lives in `consumer/`; it is deliberately not part of this build.

```
cmake -S consumer -B <dir> -DCMAKE_PREFIX_PATH=<prefix>
cmake --build <dir> --config Release
<dir>/Release/consumer_plan_check
```

## 19. Command line

```
pathplanner version
pathplanner snapshot [--source synthetic|local] [--nodes N] [--epoch E]
pathplanner plan [--nodes N] [--max-candidates K] [--max-hops H] [--forbid-link L] [--forbid-node N]
                   [--avoid-domain D] [--require-capability ID=V[:SCOPE[:COMPARATOR]]] [--transit-index I]
                   [--allow-degraded] [--diagnostic] [--verbose] [--stats]
                   [--endpoint HOST:PORT]   # submit through a running coordinator instead
pathplanner replan [--down-link INDEX]
pathplanner explain | compare | currentness
pathplanner inspect-store --path FILE
pathplanner coordinator --port P [--epoch E] [--store FILE] [--endpoint-file FILE] [--exit-after-plans N]
pathplanner worker --coordinator HOST:PORT [--epoch E] [--boot-id LABEL] [--exit-after-plans N]
```

Exit codes are script friendly: `0` when the command produced the expected structured outcome, `1` when the
outcome is a structured failure or a check failed, `2` for usage errors. Output is deterministic line-oriented
text, never timing-dependent.

`pathplanner coordinator` prints `endpoint <host:port>` (and `epoch`, `recovered_plans`) on stdout and can also
write the endpoint to `--endpoint-file` for scripts; `pathplanner worker` prints its boot identity and, at
exit, `worker_registered`, `worker_plans_served` and `worker_fenced`. Coordinators are always started with
`--port 0` in tests, so no fixed port is ever used.

## 20. Examples

| Example | Demonstrates |
| --- | --- |
| `example_quickstart` | shortest path, equal-cost deterministic tie across insertion orders, K candidates, max-hop rejection |
| `example_constraints` | link-down avoidance, capability failure, failure-domain avoidance, forbidden-node `NO_PATH` |
| `example_lifecycle` | currentness `CURRENT` -> `STALE_LINK_STATE`, replan outcomes, epoch advancement, fenced-worker refusal |
| `consumer/` | installed-package consumption through `find_package(PathPlanner CONFIG REQUIRED)` |

Each example prints facts it actually computed and exits non-zero if an expected outcome did not occur.

## 21. Benchmarks

```
build/bin/Release/pp_bench --quick
build/bin/Release/pp_bench --scale 100000
```

Measured: snapshot preparation, single shortest path, K = 4 and K = 8 candidates, constraint-heavy planning,
no-path planning, currentness checks, unchanged replans and targeted invalidation, each with its completed
operation count. Reported numbers are measurements on one machine; they are not a portable performance
guarantee and no benchmark asserts a timing threshold.

## 22. Genuine limitations

* **No authority.** Path Planner computes candidates. It does not decide legality, install routes, own route
  lifecycle, govern ECMP membership, weight traffic, adapt to changing state or sequence convergence.
* **Single host.** Distributed proofs run coordinator and worker processes on one host over loopback TCP.
  Multi-host partitions, real fabric hardware and vendor route SDKs are UNSUPPORTED here.
* **Evidence supply.** The runtime consumes snapshots; how other Fabric OS runtimes publish topology, link
  state, port state, capability and failure-domain records is outside this repository. The bundled synthetic
  generator and local adapter discovery are the only producers shipped here, and the latter covers host
  adapters only.
* **Required transit semantics.** Ordered staged legs are documented and bounded; they are not a claim of
  global cost optimality over all waypoint-constrained simple paths, and K > 1 with required transit is
  explicitly UNSUPPORTED.
* **Path-level failure-domain limit.** `max_members_per_failure_domain` filters the canonical candidate order
  during enumeration; when the enumeration ceiling is reached before the requested number of compliant
  candidates is found, the result status is `TRUNCATED_BY_LIMIT` rather than an unproven claim.
* **Conservative fallbacks.** Capability and failure-domain invalidations invalidate every retained plan
  because those publications carry no per-plan dependency records; this is reported with
  `conservative=true`.
* **Integrity is not authentication.** The framed protocol is unauthenticated and unencrypted; it must run on
  a trusted transport.
* **One request, one worker.** The coordinator dispatches a planning request to one registered worker per
  request; it does not replicate, compare or quorum worker results.
* **No restart of in-flight work.** A lost worker session fails its outstanding request explicitly; there is
  no automatic retry and no partial-result merge.
* **Persistence scope.** The store keeps bounded planning history only. It is not a database, not a
  replication log and not a source of currentness by itself.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.

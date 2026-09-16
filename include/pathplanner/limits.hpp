#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "pathplanner/status.hpp"

namespace summon::pathplanner {

// ---------------------------------------------------------------------------
// ResourceLimits
//
// Every field is enforced by production code. Limits are product resource
// bounds, not test scaffolding: a request that exceeds a bound is rejected with
// an explicit status (RESOURCE_LIMIT / MALFORMED_REQUEST) rather than being
// silently truncated. The only bound that is expressed in wall-clock terms is
// the protocol receive bound, which exists so a partial frame cannot pin a
// session; breaching it produces an explicit protocol failure.
// ---------------------------------------------------------------------------
struct ResourceLimits {
  // --- Snapshot shape -----------------------------------------------------
  std::uint32_t max_nodes = 1u << 20;              // 1,048,576 nodes
  std::uint32_t max_edges = 1u << 22;              // 4,194,304 edges
  std::uint32_t max_endpoints = 1u << 20;
  std::uint32_t max_ports_per_node = 4096;
  std::uint32_t max_link_state_records = 1u << 22;
  std::uint32_t max_port_state_records = 1u << 22;
  std::uint32_t max_capability_bindings = 1u << 22;
  std::uint32_t max_failure_domains = 1u << 18;
  std::uint32_t max_members_per_failure_domain = 1u << 16;

  // --- Request shape ------------------------------------------------------
  std::uint32_t max_candidates_per_request = 64;   // hard ceiling for max_candidates
  std::uint32_t max_hops = 512;                    // hard ceiling for max_hops
  std::uint32_t max_constraints_total = 4096;      // total entries across all constraint vectors
  std::uint32_t max_forbidden_ids = 2048;          // per forbidden vector
  std::uint32_t max_required_ids = 256;            // per required vector
  std::uint32_t max_required_any_sets = 64;
  std::uint32_t max_members_in_any_set = 256;
  std::uint32_t max_transit_alternatives = 1024;   // total alternatives across all transit stages
  std::uint32_t max_transit_combinations = 64;     // staged combinations evaluated for one request
  std::uint32_t max_capability_requirements = 256;
  std::uint32_t max_forbidden_domain_classes = 256;

  // --- Deterministic work budget -----------------------------------------
  std::uint64_t max_expanded_states = 50u * 1000u * 1000u;   // heuristic state relaxations
  std::uint64_t max_spur_searches = 4u * 1000u * 1000u;      // Yen spur searches
  std::uint64_t max_queue_entries = 20u * 1000u * 1000u;     // total heap pushes
  // Hop-expanded search allocates (max_hops + 1) * nodes labels. Exceeding this
  // bound is reported as RESOURCE_LIMIT instead of attempting the allocation.
  std::uint64_t max_search_states = 4u * 1000u * 1000u;

  // --- Retention and explanation -----------------------------------------
  std::uint32_t max_retained_plans = 4096;
  std::uint32_t max_history_entries = 64;
  std::uint32_t max_explanation_entries = 256;
  std::uint32_t max_reverse_dependency_entries = 1u << 20;
  std::uint32_t max_persisted_plans = 65536;
  // Bound on candidates enumerated when a path-level constraint forces filtering of
  // the canonical candidate order.
  std::uint32_t max_enumeration_candidates = 256;

  // --- Protocol and sessions ---------------------------------------------
  std::uint32_t max_frame_bytes = 1u << 20;        // 1 MiB framed payload ceiling
  std::uint32_t max_sessions = 256;
  std::uint32_t max_concurrent_requests = 256;
  std::uint32_t max_workers = 64;
  std::uint32_t receive_bound_ms = 15000;          // partial-frame bound (product behavior)
  std::uint32_t send_bound_ms = 15000;             // bound on a single send to a stalled peer
  std::uint32_t connect_bound_ms = 10000;

  // Rejects incoherent configurations. Returns the first problem found.
  std::optional<DiagnosticCode> Validate() const noexcept;
};

// Returns the first diagnostic explaining how two limits conflict, or nullopt.
std::optional<DiagnosticCode> ValidateLimits(const ResourceLimits& limits) noexcept;

}  // namespace summon::pathplanner

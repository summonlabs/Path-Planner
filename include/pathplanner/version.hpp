#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace summon::pathplanner {

// Product version. Single source of truth for library, package and CLI version reporting.
inline constexpr int kVersionMajor = 1;
inline constexpr int kVersionMinor = 0;
inline constexpr int kVersionPatch = 0;
inline constexpr std::string_view kProductVersion = "1.0.0";

// Representation versions. These are independent of the product version and only change when the
// corresponding representation changes incompatibly.
inline constexpr std::uint32_t kPersistedFormatVersion = 1;
inline constexpr std::uint32_t kWireProtocolVersion = 1;
inline constexpr std::uint32_t kPathEncodingVersion = 1;
inline constexpr std::uint32_t kPlanDigestSchemeVersion = 1;
inline constexpr std::uint32_t kPlanningRuleVersion = 1;

// "1.0.0"
std::string VersionString();

// "Path Planner 1.0.0 (planning-rules 1, path-encoding 1, wire 1, persisted 1)"
std::string VersionBanner();

}  // namespace summon::pathplanner

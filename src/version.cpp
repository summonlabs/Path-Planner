#include "pathplanner/version.hpp"

#include <string>

namespace summon::pathplanner {

std::string VersionString() { return std::string(kProductVersion); }

std::string VersionBanner() {
  std::string banner = "Path Planner " + std::string(kProductVersion);
  banner += " (planning-rules " + std::to_string(kPlanningRuleVersion);
  banner += ", path-encoding " + std::to_string(kPathEncodingVersion);
  banner += ", wire " + std::to_string(kWireProtocolVersion);
  banner += ", persisted " + std::to_string(kPersistedFormatVersion) + ")";
  return banner;
}

}  // namespace summon::pathplanner

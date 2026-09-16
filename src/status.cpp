#include "pathplanner/status.hpp"

#include <cstddef>

namespace summon::pathplanner::detail {

std::optional<std::uint32_t> EnumValueFromName(const EnumEntry* table, std::size_t count, std::string_view name) {
  for (std::size_t i = 0; i < count; ++i) {
    if (table[i].name == name) {
      return table[i].value;
    }
  }
  return std::nullopt;
}

std::string_view EnumNameFromValue(const EnumEntry* table, std::size_t count, std::uint32_t value) {
  for (std::size_t i = 0; i < count; ++i) {
    if (table[i].value == value) {
      return table[i].name;
    }
  }
  return std::string_view{};
}

}  // namespace summon::pathplanner::detail

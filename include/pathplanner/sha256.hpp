#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace summon::pathplanner {

inline constexpr std::size_t kSha256Bytes = 32;

// SHA-256 digest. Used for candidate path identity, plan identity, canonical
// encoding identity and frame/record integrity. Integrity, not authentication:
// Path Planner performs no cryptographic authentication of peers.
struct Sha256Digest {
  std::array<std::byte, kSha256Bytes> bytes{};

  std::string ToHex() const;
  static std::optional<Sha256Digest> FromHex(std::string_view text);
  bool IsZero() const noexcept;

  friend bool operator==(const Sha256Digest& lhs, const Sha256Digest& rhs) noexcept {
    return lhs.bytes == rhs.bytes;
  }
  friend bool operator!=(const Sha256Digest& lhs, const Sha256Digest& rhs) noexcept { return !(lhs == rhs); }
  friend std::strong_ordering operator<=>(const Sha256Digest& lhs, const Sha256Digest& rhs) noexcept;
};

class Sha256 {
 public:
  Sha256() noexcept;

  void Update(std::span<const std::byte> data) noexcept;
  void Update(std::string_view text) noexcept;
  Sha256Digest Finish() noexcept;

  static Sha256Digest Hash(std::span<const std::byte> data) noexcept;
  static Sha256Digest Hash(std::string_view text) noexcept;

 private:
  void Transform(const std::uint8_t* block) noexcept;

  std::array<std::uint32_t, 8> state_;
  std::array<std::uint8_t, 64> buffer_;
  std::uint64_t total_bytes_;
  std::size_t buffered_;
};

}  // namespace summon::pathplanner

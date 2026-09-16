#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace summon::pathplanner {

// Default ceiling for a single canonical encoding (path, plan, payload).
inline constexpr std::size_t kDefaultEncodingCeiling = 1u << 20;  // 1 MiB

// ---------------------------------------------------------------------------
// ByteWriter: deterministic little-endian, length-prefixed encoder with an
// explicit ceiling. Once the ceiling is exceeded the writer stops mutating and
// reports overflow; callers must check overflowed() before using data().
// ---------------------------------------------------------------------------
class ByteWriter {
 public:
  explicit ByteWriter(std::size_t ceiling = kDefaultEncodingCeiling) noexcept;

  void U8(std::uint8_t value);
  void U16(std::uint16_t value);
  void U32(std::uint32_t value);
  void U64(std::uint64_t value);
  // Unsigned LEB128. Canonical: the shortest form is required on decode.
  void VarU64(std::uint64_t value);
  void Bytes(std::span<const std::byte> value);
  void FixedBytes(std::span<const std::byte> value);
  // VarU64 length prefix followed by the raw bytes.
  void Text(std::string_view value);
  void Bool(bool value);

  bool overflowed() const noexcept { return overflowed_; }
  std::size_t size() const noexcept { return data_.size(); }
  const std::vector<std::byte>& data() const noexcept { return data_; }
  std::span<const std::byte> span() const noexcept {
    return std::span<const std::byte>(data_.data(), data_.size());
  }

 private:
  void Put(std::span<const std::byte> value);
  void PutByte(std::uint8_t value);

  std::vector<std::byte> data_;
  std::size_t ceiling_;
  bool overflowed_;
};

// ---------------------------------------------------------------------------
// ByteReader: strict decoder. Every failure (short read, non-canonical varint,
// oversized length prefix, overflow) is reported as nullopt and latches the
// reader into a failed state.
// ---------------------------------------------------------------------------
class ByteReader {
 public:
  explicit ByteReader(std::span<const std::byte> data) noexcept;

  std::optional<std::uint8_t> U8();
  std::optional<std::uint16_t> U16();
  std::optional<std::uint32_t> U32();
  std::optional<std::uint64_t> U64();
  std::optional<std::uint64_t> VarU64();
  std::optional<std::string_view> Text();
  std::optional<bool> Bool();
  bool FixedBytes(std::span<std::byte> out);
  // Returns a view over the next length bytes without copying.
  std::optional<std::span<const std::byte>> View(std::size_t length);

  bool failed() const noexcept { return failed_; }
  bool AtEnd() const noexcept { return position_ == data_.size(); }
  std::size_t Remaining() const noexcept { return data_.size() - position_; }
  std::size_t Position() const noexcept { return position_; }

 private:
  bool Need(std::size_t count);

  std::span<const std::byte> data_;
  std::size_t position_;
  bool failed_;
};

// ---------------------------------------------------------------------------
// Hex helpers. Canonical textual form is exactly two lowercase hex digits per
// byte. Decoding is strict: wrong length, uppercase, whitespace or any
// non-[0-9a-f] character is rejected.
// ---------------------------------------------------------------------------
std::string HexEncode(std::span<const std::byte> bytes);
bool HexDecodeStrict(std::string_view text, std::span<std::byte> out) noexcept;
constexpr bool IsLowerHexDigit(char c) noexcept {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}
constexpr std::uint8_t LowerHexValue(char c) noexcept {
  return static_cast<std::uint8_t>(c <= '9' ? (c - '0') : (c - 'a' + 10));
}

}  // namespace summon::pathplanner

#include "pathplanner/canonical.hpp"

namespace summon::pathplanner {
namespace {

constexpr std::size_t kVarU64MaxBytes = 10;

}  // namespace

ByteWriter::ByteWriter(std::size_t ceiling) noexcept : ceiling_(ceiling), overflowed_(false) {}

void ByteWriter::PutByte(std::uint8_t value) {
  if (overflowed_) {
    return;
  }
  if (data_.size() + 1 > ceiling_) {
    overflowed_ = true;
    return;
  }
  data_.push_back(static_cast<std::byte>(value));
}

void ByteWriter::Put(std::span<const std::byte> value) {
  if (overflowed_) {
    return;
  }
  if (value.size() > ceiling_ - data_.size()) {
    overflowed_ = true;
    return;
  }
  data_.insert(data_.end(), value.begin(), value.end());
}

void ByteWriter::U8(std::uint8_t value) { PutByte(value); }

void ByteWriter::U16(std::uint16_t value) {
  PutByte(static_cast<std::uint8_t>(value & 0xFFu));
  PutByte(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void ByteWriter::U32(std::uint32_t value) {
  for (int shift = 0; shift < 32; shift += 8) {
    PutByte(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
  }
}

void ByteWriter::U64(std::uint64_t value) {
  for (int shift = 0; shift < 64; shift += 8) {
    PutByte(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
  }
}

void ByteWriter::VarU64(std::uint64_t value) {
  while (value >= 0x80u) {
    PutByte(static_cast<std::uint8_t>((value & 0x7Fu) | 0x80u));
    value >>= 7;
  }
  PutByte(static_cast<std::uint8_t>(value));
}

void ByteWriter::Bytes(std::span<const std::byte> value) {
  VarU64(value.size());
  Put(value);
}

void ByteWriter::FixedBytes(std::span<const std::byte> value) { Put(value); }

void ByteWriter::Text(std::string_view value) {
  VarU64(value.size());
  Put(std::span<const std::byte>(reinterpret_cast<const std::byte*>(value.data()), value.size()));
}

void ByteWriter::Bool(bool value) { PutByte(value ? 1u : 0u); }

ByteReader::ByteReader(std::span<const std::byte> data) noexcept
    : data_(data), position_(0), failed_(false) {}

bool ByteReader::Need(std::size_t count) {
  if (failed_) {
    return false;
  }
  if (count > data_.size() - position_) {
    failed_ = true;
    return false;
  }
  return true;
}

std::optional<std::uint8_t> ByteReader::U8() {
  if (!Need(1)) {
    return std::nullopt;
  }
  const std::uint8_t value = static_cast<std::uint8_t>(data_[position_]);
  position_ += 1;
  return value;
}

std::optional<std::uint16_t> ByteReader::U16() {
  if (!Need(2)) {
    return std::nullopt;
  }
  std::uint16_t value = 0;
  for (int i = 0; i < 2; ++i) {
    value |= static_cast<std::uint16_t>(static_cast<std::uint8_t>(data_[position_ + static_cast<std::size_t>(i)]))
             << (8 * i);
  }
  position_ += 2;
  return value;
}

std::optional<std::uint32_t> ByteReader::U32() {
  if (!Need(4)) {
    return std::nullopt;
  }
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(static_cast<std::uint8_t>(data_[position_ + static_cast<std::size_t>(i)]))
             << (8 * i);
  }
  position_ += 4;
  return value;
}

std::optional<std::uint64_t> ByteReader::U64() {
  if (!Need(8)) {
    return std::nullopt;
  }
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(static_cast<std::uint8_t>(data_[position_ + static_cast<std::size_t>(i)]))
             << (8 * i);
  }
  position_ += 8;
  return value;
}

std::optional<std::uint64_t> ByteReader::VarU64() {
  std::uint64_t value = 0;
  int shift = 0;
  for (int i = 0; i < static_cast<int>(kVarU64MaxBytes); ++i) {
    const std::optional<std::uint8_t> byte = U8();
    if (!byte.has_value()) {
      return std::nullopt;
    }
    const std::uint8_t low = static_cast<std::uint8_t>(*byte & 0x7Fu);
    if (shift == 63 && low > 0x01u) {
      failed_ = true;
      return std::nullopt;
    }
    value |= static_cast<std::uint64_t>(low) << shift;
    if ((*byte & 0x80u) == 0) {
      // Reject non-canonical (over-long) encodings.
      if (i > 0 && low == 0) {
        failed_ = true;
        return std::nullopt;
      }
      return value;
    }
    shift += 7;
  }
  failed_ = true;
  return std::nullopt;
}

std::optional<std::span<const std::byte>> ByteReader::View(std::size_t length) {
  if (!Need(length)) {
    return std::nullopt;
  }
  const std::span<const std::byte> view(data_.data() + position_, length);
  position_ += length;
  return view;
}

std::optional<std::string_view> ByteReader::Text() {
  const std::optional<std::uint64_t> length = VarU64();
  if (!length.has_value()) {
    return std::nullopt;
  }
  if (*length > static_cast<std::uint64_t>(data_.size())) {
    failed_ = true;
    return std::nullopt;
  }
  const std::optional<std::span<const std::byte>> view = View(static_cast<std::size_t>(*length));
  if (!view.has_value()) {
    return std::nullopt;
  }
  return std::string_view(reinterpret_cast<const char*>(view->data()), view->size());
}

std::optional<bool> ByteReader::Bool() {
  const std::optional<std::uint8_t> value = U8();
  if (!value.has_value()) {
    return std::nullopt;
  }
  if (*value > 1u) {
    failed_ = true;
    return std::nullopt;
  }
  return *value == 1u;
}

bool ByteReader::FixedBytes(std::span<std::byte> out) {
  const std::optional<std::span<const std::byte>> view = View(out.size());
  if (!view.has_value()) {
    return false;
  }
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = (*view)[i];
  }
  return true;
}

std::string HexEncode(std::span<const std::byte> bytes) {
  constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const std::byte b : bytes) {
    const std::uint8_t value = static_cast<std::uint8_t>(b);
    out.push_back(kDigits[value >> 4]);
    out.push_back(kDigits[value & 0x0Fu]);
  }
  return out;
}

bool HexDecodeStrict(std::string_view text, std::span<std::byte> out) noexcept {
  if (text.size() != out.size() * 2) {
    return false;
  }
  for (std::size_t i = 0; i < out.size(); ++i) {
    const char high = text[i * 2];
    const char low = text[i * 2 + 1];
    if (!IsLowerHexDigit(high) || !IsLowerHexDigit(low)) {
      return false;
    }
    out[i] = static_cast<std::byte>(static_cast<std::uint8_t>((LowerHexValue(high) << 4) | LowerHexValue(low)));
  }
  return true;
}

}  // namespace summon::pathplanner

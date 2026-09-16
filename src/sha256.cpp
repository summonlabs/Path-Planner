#include "pathplanner/sha256.hpp"

#include "pathplanner/canonical.hpp"

namespace summon::pathplanner {
namespace {

constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

constexpr std::array<std::uint32_t, 8> kInitialState = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

constexpr std::uint32_t RotateRight(std::uint32_t value, int bits) noexcept {
  return (value >> bits) | (value << (32 - bits));
}

}  // namespace

std::string Sha256Digest::ToHex() const {
  return HexEncode(std::span<const std::byte>(bytes.data(), bytes.size()));
}

std::optional<Sha256Digest> Sha256Digest::FromHex(std::string_view text) {
  Sha256Digest digest;
  if (!HexDecodeStrict(text, std::span<std::byte>(digest.bytes.data(), digest.bytes.size()))) {
    return std::nullopt;
  }
  return digest;
}

bool Sha256Digest::IsZero() const noexcept {
  for (const std::byte b : bytes) {
    if (b != std::byte{0}) {
      return false;
    }
  }
  return true;
}

std::strong_ordering operator<=>(const Sha256Digest& lhs, const Sha256Digest& rhs) noexcept {
  for (std::size_t i = 0; i < kSha256Bytes; ++i) {
    const auto left = static_cast<unsigned int>(static_cast<std::uint8_t>(lhs.bytes[i]));
    const auto right = static_cast<unsigned int>(static_cast<std::uint8_t>(rhs.bytes[i]));
    if (left < right) {
      return std::strong_ordering::less;
    }
    if (left > right) {
      return std::strong_ordering::greater;
    }
  }
  return std::strong_ordering::equal;
}

Sha256::Sha256() noexcept : state_(kInitialState), buffer_{}, total_bytes_(0), buffered_(0) {}

void Sha256::Transform(const std::uint8_t* block) noexcept {
  std::array<std::uint32_t, 64> schedule{};
  for (std::size_t i = 0; i < 16; ++i) {
    schedule[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
                  (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
                  (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
                  (static_cast<std::uint32_t>(block[i * 4 + 3]));
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t s0 =
        RotateRight(schedule[i - 15], 7) ^ RotateRight(schedule[i - 15], 18) ^ (schedule[i - 15] >> 3);
    const std::uint32_t s1 =
        RotateRight(schedule[i - 2], 17) ^ RotateRight(schedule[i - 2], 19) ^ (schedule[i - 2] >> 10);
    schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t sigma1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
    const std::uint32_t choice = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + sigma1 + choice + kRoundConstants[i] + schedule[i];
    const std::uint32_t sigma0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = sigma0 + majority;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::Update(std::span<const std::byte> data) noexcept {
  total_bytes_ += static_cast<std::uint64_t>(data.size());
  std::size_t offset = 0;
  if (buffered_ > 0) {
    while (buffered_ < buffer_.size() && offset < data.size()) {
      buffer_[buffered_] = static_cast<std::uint8_t>(data[offset]);
      buffered_ += 1;
      offset += 1;
    }
    if (buffered_ == buffer_.size()) {
      Transform(buffer_.data());
      buffered_ = 0;
    }
  }
  while (data.size() - offset >= buffer_.size()) {
    Transform(reinterpret_cast<const std::uint8_t*>(data.data() + offset));
    offset += buffer_.size();
  }
  while (offset < data.size()) {
    buffer_[buffered_] = static_cast<std::uint8_t>(data[offset]);
    buffered_ += 1;
    offset += 1;
  }
}

void Sha256::Update(std::string_view text) noexcept {
  Update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size()));
}

Sha256Digest Sha256::Finish() noexcept {
  const std::uint64_t bit_length = total_bytes_ * 8u;
  const std::uint8_t padding = 0x80u;
  Update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&padding), 1));
  const std::uint8_t zero = 0x00u;
  while (buffered_ != 56) {
    Update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&zero), 1));
  }
  std::array<std::uint8_t, 8> length_bytes{};
  for (std::size_t i = 0; i < 8; ++i) {
    length_bytes[i] = static_cast<std::uint8_t>((bit_length >> (8 * (7 - i))) & 0xFFu);
  }
  Update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(length_bytes.data()), length_bytes.size()));

  Sha256Digest digest;
  for (std::size_t i = 0; i < state_.size(); ++i) {
    digest.bytes[i * 4] = static_cast<std::byte>(static_cast<std::uint8_t>((state_[i] >> 24) & 0xFFu));
    digest.bytes[i * 4 + 1] = static_cast<std::byte>(static_cast<std::uint8_t>((state_[i] >> 16) & 0xFFu));
    digest.bytes[i * 4 + 2] = static_cast<std::byte>(static_cast<std::uint8_t>((state_[i] >> 8) & 0xFFu));
    digest.bytes[i * 4 + 3] = static_cast<std::byte>(static_cast<std::uint8_t>(state_[i] & 0xFFu));
  }
  return digest;
}

Sha256Digest Sha256::Hash(std::span<const std::byte> data) noexcept {
  Sha256 hasher;
  hasher.Update(data);
  return hasher.Finish();
}

Sha256Digest Sha256::Hash(std::string_view text) noexcept {
  Sha256 hasher;
  hasher.Update(text);
  return hasher.Finish();
}

}  // namespace summon::pathplanner

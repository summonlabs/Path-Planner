#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

#include "pathplanner/canonical.hpp"
#include "pathplanner/sha256.hpp"

namespace summon::pathplanner {

// ---------------------------------------------------------------------------
// FixedId<Tag, N>: strongly typed fixed-width identifier.
//
//  * textual form is exactly 2N lowercase hex characters (strict);
//  * the all-zero value is the reserved nil value and is never produced by
//    Parse();
//  * ordering is bytewise, so it is stable, total and content derived;
//  * distinct Tag types are distinct C++ types: no implicit cross-domain
//    conversion exists.
// ---------------------------------------------------------------------------
template <class Tag, std::size_t N>
class FixedId {
 public:
  using tag_type = Tag;
  using byte_array = std::array<std::byte, N>;
  static constexpr std::size_t kByteCount = N;
  static constexpr std::size_t kTextLength = N * 2;

  constexpr FixedId() noexcept = default;

  static constexpr FixedId FromBytes(const byte_array& bytes) noexcept {
    FixedId id;
    id.bytes_ = bytes;
    return id;
  }

  // Derives an identifier from the leading N bytes of a SHA-256 digest.
  static FixedId FromDigest(const Sha256Digest& digest) noexcept {
    FixedId id;
    for (std::size_t i = 0; i < N; ++i) {
      id.bytes_[i] = digest.bytes[i];
    }
    return id;
  }

  static std::optional<FixedId> Parse(std::string_view text) noexcept {
    if (text.size() != kTextLength) {
      return std::nullopt;
    }
    FixedId id;
    if (!HexDecodeStrict(text, std::span<std::byte>(id.bytes_.data(), id.bytes_.size()))) {
      return std::nullopt;
    }
    if (!id.IsValid()) {
      return std::nullopt;
    }
    return id;
  }

  const byte_array& Bytes() const noexcept { return bytes_; }
  std::span<const std::byte> Span() const noexcept { return std::span<const std::byte>(bytes_.data(), bytes_.size()); }

  std::string ToString() const { return HexEncode(Span()); }

  constexpr bool IsValid() const noexcept {
    for (std::size_t i = 0; i < N; ++i) {
      if (bytes_[i] != std::byte{0}) {
        return true;
      }
    }
    return false;
  }

  friend bool operator==(const FixedId& lhs, const FixedId& rhs) noexcept { return lhs.bytes_ == rhs.bytes_; }
  friend bool operator!=(const FixedId& lhs, const FixedId& rhs) noexcept { return !(lhs == rhs); }
  friend std::strong_ordering operator<=>(const FixedId& lhs, const FixedId& rhs) noexcept {
    for (std::size_t i = 0; i < N; ++i) {
      const auto left = static_cast<unsigned int>(static_cast<std::uint8_t>(lhs.bytes_[i]));
      const auto right = static_cast<unsigned int>(static_cast<std::uint8_t>(rhs.bytes_[i]));
      if (left < right) {
        return std::strong_ordering::less;
      }
      if (left > right) {
        return std::strong_ordering::greater;
      }
    }
    return std::strong_ordering::equal;
  }

 private:
  byte_array bytes_{};
};

// ---------------------------------------------------------------------------
// StrongUInt<Tag, T, MaxValue>: strongly typed bounded unsigned integer.
//
// Arithmetic is never implicit. Use CheckedAdd / CheckedMul, which report
// overflow as nullopt instead of wrapping.
// ---------------------------------------------------------------------------
template <class Tag, class T, T MaxValue>
class StrongUInt {
 public:
  using tag_type = Tag;
  using value_type = T;
  static_assert(std::is_unsigned<T>::value, "StrongUInt requires an unsigned representation");

  constexpr StrongUInt() noexcept = default;
  constexpr explicit StrongUInt(T value) noexcept : value_(value) {}

  // Numeric upper bound of the representation.
  static constexpr T Bound() noexcept { return MaxValue; }
  // Typed maximum value (used as an explicit sentinel, never as an implicit conversion).
  static constexpr StrongUInt Max() noexcept { return StrongUInt(MaxValue); }

  static constexpr std::optional<StrongUInt> TryFrom(T value) noexcept {
    if (value > MaxValue) {
      return std::nullopt;
    }
    return StrongUInt(value);
  }

  // Canonical decimal form: no sign, no whitespace, no leading zeros (except "0").
  static std::optional<StrongUInt> Parse(std::string_view text) noexcept {
    if (text.empty() || text.size() > 20) {
      return std::nullopt;
    }
    if (text.size() > 1 && text[0] == '0') {
      return std::nullopt;
    }
    T value = 0;
    for (const char c : text) {
      if (c < '0' || c > '9') {
        return std::nullopt;
      }
      const T digit = static_cast<T>(c - '0');
      if (value > static_cast<T>((MaxValue - digit) / 10)) {
        return std::nullopt;
      }
      value = static_cast<T>(value * 10 + digit);
    }
    return StrongUInt(value);
  }

  constexpr T Value() const noexcept { return value_; }

  std::string ToString() const {
    if (value_ == 0) {
      return std::string("0");
    }
    std::string out;
    T remaining = value_;
    while (remaining > 0) {
      out.push_back(static_cast<char>('0' + static_cast<int>(remaining % 10)));
      remaining = static_cast<T>(remaining / 10);
    }
    for (std::size_t i = 0; i < out.size() / 2; ++i) {
      const char tmp = out[i];
      out[i] = out[out.size() - 1 - i];
      out[out.size() - 1 - i] = tmp;
    }
    return out;
  }

  friend constexpr bool operator==(const StrongUInt& lhs, const StrongUInt& rhs) noexcept {
    return lhs.value_ == rhs.value_;
  }
  friend constexpr bool operator!=(const StrongUInt& lhs, const StrongUInt& rhs) noexcept {
    return lhs.value_ != rhs.value_;
  }
  friend constexpr std::strong_ordering operator<=>(const StrongUInt& lhs, const StrongUInt& rhs) noexcept {
    return lhs.value_ <=> rhs.value_;
  }

 private:
  T value_{};
};

template <class Tag, class T, T M>
std::optional<StrongUInt<Tag, T, M>> CheckedAdd(StrongUInt<Tag, T, M> lhs, StrongUInt<Tag, T, M> rhs) noexcept {
  const T a = lhs.Value();
  const T b = rhs.Value();
  if (a > static_cast<T>(StrongUInt<Tag, T, M>::Bound() - b)) {
    return std::nullopt;
  }
  return StrongUInt<Tag, T, M>::TryFrom(static_cast<T>(a + b));
}

template <class Tag, class T, T M>
std::optional<StrongUInt<Tag, T, M>> CheckedMul(StrongUInt<Tag, T, M> lhs, T factor) noexcept {
  const T a = lhs.Value();
  if (factor != 0 && a > static_cast<T>(StrongUInt<Tag, T, M>::Bound() / factor)) {
    return std::nullopt;
  }
  return StrongUInt<Tag, T, M>::TryFrom(static_cast<T>(a * factor));
}

template <class Tag, class T, T M>
std::optional<std::uint64_t> ToU64(StrongUInt<Tag, T, M> value) noexcept {
  return static_cast<std::uint64_t>(value.Value());
}

template <class Tag, class T, T M>
std::optional<std::uint32_t> ToU32(StrongUInt<Tag, T, M> value) noexcept {
  const std::uint64_t raw = static_cast<std::uint64_t>(value.Value());
  if (raw > 0xFFFFFFFFull) {
    return std::nullopt;
  }
  return static_cast<std::uint32_t>(raw);
}

// ---------------------------------------------------------------------------
// Identity tags. One tag per planning identity domain.
// ---------------------------------------------------------------------------
struct NodeIdTag {};
struct LinkIdTag {};
struct PortIdTag {};
struct EndpointIdTag {};
struct SwitchIdTag {};
struct FailureDomainIdTag {};
struct FailureDomainClassTag {};
struct CapabilityIdTag {};
struct CandidatePathIdTag {};
struct PathPlanIdTag {};
struct PlanningRequestIdTag {};
struct ConstraintSetIdTag {};
struct SnapshotIdTag {};
struct PublisherIdTag {};
struct WorkerBootIdTag {};
struct MutationAttemptIdTag {};

using NodeId = FixedId<NodeIdTag, 16>;
using LinkId = FixedId<LinkIdTag, 16>;
using PortId = FixedId<PortIdTag, 16>;
using EndpointId = FixedId<EndpointIdTag, 16>;
using SwitchId = FixedId<SwitchIdTag, 16>;
using FailureDomainId = FixedId<FailureDomainIdTag, 8>;
using FailureDomainClass = FixedId<FailureDomainClassTag, 8>;
using CapabilityId = FixedId<CapabilityIdTag, 8>;
using CandidatePathId = FixedId<CandidatePathIdTag, 16>;
using PathPlanId = FixedId<PathPlanIdTag, 16>;
using PlanningRequestId = FixedId<PlanningRequestIdTag, 16>;
using ConstraintSetId = FixedId<ConstraintSetIdTag, 16>;
using SnapshotId = FixedId<SnapshotIdTag, 16>;
using PublisherId = FixedId<PublisherIdTag, 8>;
using WorkerBootId = FixedId<WorkerBootIdTag, 8>;
using MutationAttemptId = FixedId<MutationAttemptIdTag, 8>;

// ---------------------------------------------------------------------------
// Scalar planning quantities.
// ---------------------------------------------------------------------------
struct CostValueTag {};
struct StaticCostTag {};
struct HopCountTag {};
struct CandidateRankTag {};
struct EntityGenerationTag {};
struct TopologyGenerationTag {};
struct LinkStateGenerationTag {};
struct PortGenerationTag {};
struct CapabilityGenerationTag {};
struct FailureDomainGenerationTag {};
struct PolicyGenerationTag {};
struct ConstraintGenerationTag {};
struct PlanningGenerationTag {};
struct PlanPublishSequenceTag {};
struct FabricEpochTag {};
struct CoordinatorEpochTag {};
struct CapabilityValueTag {};

inline constexpr std::uint32_t kMaxHopCount = 65535;
inline constexpr std::uint32_t kMaxCandidateRank = 4095;

using CostValue = StrongUInt<CostValueTag, std::uint64_t, std::numeric_limits<std::uint64_t>::max()>;
using StaticCost = StrongUInt<StaticCostTag, std::uint32_t, std::numeric_limits<std::uint32_t>::max()>;
using HopCount = StrongUInt<HopCountTag, std::uint32_t, kMaxHopCount>;
using CandidateRank = StrongUInt<CandidateRankTag, std::uint32_t, kMaxCandidateRank>;
using EntityGeneration = StrongUInt<EntityGenerationTag, std::uint64_t, std::numeric_limits<std::uint64_t>::max()>;
using TopologyGeneration = StrongUInt<TopologyGenerationTag, std::uint64_t, std::numeric_limits<std::uint64_t>::max()>;
using LinkStateGeneration = StrongUInt<LinkStateGenerationTag, std::uint64_t, std::numeric_limits<std::uint64_t>::max()>;
using PortGeneration = StrongUInt<PortGenerationTag, std::uint64_t, std::numeric_limits<std::uint64_t>::max()>;
using CapabilityGeneration = StrongUInt<CapabilityGenerationTag, std::uint64_t, std::numeric_limits<std::uint64_t>::max()>;
using FailureDomainGeneration =
    StrongUInt<FailureDomainGenerationTag, std::uint64_t, std::numeric_limits<std::uint64_t>::max()>;
using PolicyGeneration = StrongUInt<PolicyGenerationTag, std::uint64_t, std::numeric_limits<std::uint64_t>::max()>;
using ConstraintGeneration = StrongUInt<ConstraintGenerationTag, std::uint64_t, std::numeric_limits<std::uint64_t>::max()>;
using PlanningGeneration = StrongUInt<PlanningGenerationTag, std::uint64_t, std::numeric_limits<std::uint64_t>::max()>;
using PlanPublishSequence = StrongUInt<PlanPublishSequenceTag, std::uint64_t, std::numeric_limits<std::uint64_t>::max()>;
using FabricEpoch = StrongUInt<FabricEpochTag, std::uint64_t, std::numeric_limits<std::uint64_t>::max()>;
using CoordinatorEpoch = StrongUInt<CoordinatorEpochTag, std::uint64_t, std::numeric_limits<std::uint64_t>::max()>;
using CapabilityValue = StrongUInt<CapabilityValueTag, std::uint64_t, std::numeric_limits<std::uint64_t>::max()>;

// Convenience aliases used by the request model.
using TopologyGenerationValue = TopologyGeneration;

}  // namespace summon::pathplanner

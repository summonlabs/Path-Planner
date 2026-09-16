#pragma once

// Internal TCP session helpers. Windows Winsock2 on _WIN32, BSD sockets elsewhere.
// Not installed: this is an implementation detail of the distributed runtime.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace summon::pathplanner::internal {

#ifdef _WIN32
using SocketHandle = std::uintptr_t;
inline constexpr SocketHandle kInvalidSocket = static_cast<SocketHandle>(~0ull);
#else
using SocketHandle = int;
inline constexpr SocketHandle kInvalidSocket = -1;
#endif

enum class RecvOutcome {
  kOk = 0,
  kPeerClosed = 1,
  // The configured receive bound elapsed before a complete message arrived. This is
  // product behaviour: a partial frame or a slow peer must not pin a session thread.
  kBoundExceeded = 2,
  kError = 3,
};

// Idempotent process-wide socket runtime initialization.
bool SocketRuntimeEnsure(std::string& error);
void SocketRuntimeShutdown();

SocketHandle CreateListener(const std::string& address, std::uint16_t port, std::string& error);
SocketHandle AcceptConnection(SocketHandle listener, std::string& error);
SocketHandle ConnectTo(const std::string& host, std::uint16_t port, std::uint32_t bound_ms, std::string& error);
void CloseSocket(SocketHandle socket) noexcept;
void ShutdownSocket(SocketHandle socket) noexcept;

bool SendAll(SocketHandle socket, std::span<const std::byte> data, std::string& error);
// Reads exactly data.size() bytes within bound_ms of the call.
RecvOutcome RecvExact(SocketHandle socket, std::span<std::byte> data, std::uint32_t bound_ms, std::string& error);

bool SetNoDelay(SocketHandle socket) noexcept;
// Bounds a single send so a peer that stops reading cannot pin a session thread forever.
bool SetSendTimeout(SocketHandle socket, std::uint32_t bound_ms) noexcept;
// Reads back the bound port of a listening socket (used when port 0 was requested).
bool ListenerBoundPort(SocketHandle listener, std::uint16_t& port) noexcept;
// Parses "host:port"; returns false when the endpoint is malformed or the port is out of range.
bool ParseEndpoint(const std::string& endpoint, std::string& host, std::uint16_t& port);
std::string FormatEndpoint(const std::string& host, std::uint16_t port);

// Validates that a value is a usable peer address literal or host name (no spaces,
// no control characters, bounded length).
bool ValidateHostString(const std::string& host);

}  // namespace summon::pathplanner::internal

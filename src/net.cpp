#include "net.hpp"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace summon::pathplanner::internal {
namespace {

#ifdef _WIN32
std::atomic<int> g_socket_runtime_state{0};  // 0 = uninitialized, 1 = ready, 2 = failed
#endif

std::string SocketErrorText(int code) {
#ifdef _WIN32
  return "socket error " + std::to_string(code);
#else
  return std::string(std::strerror(code));
#endif
}

int LastSocketError() {
#ifdef _WIN32
  return WSAGetLastError();
#else
  return errno;
#endif
}

}  // namespace

bool SocketRuntimeEnsure(std::string& error) {
#ifdef _WIN32
  int expected = 0;
  if (g_socket_runtime_state.load() == 1) {
    return true;
  }
  if (g_socket_runtime_state.compare_exchange_strong(expected, 1)) {
    WSADATA data;
    const int result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
      g_socket_runtime_state.store(2);
      error = "WSAStartup failed: " + SocketErrorText(result);
      return false;
    }
  }
  return g_socket_runtime_state.load() == 1;
#else
  (void)error;
  return true;
#endif
}

void SocketRuntimeShutdown() {
#ifdef _WIN32
  int expected = 1;
  if (g_socket_runtime_state.compare_exchange_strong(expected, 0)) {
    WSACleanup();
  }
#endif
}

bool ValidateHostString(const std::string& host) {
  if (host.empty() || host.size() > 253) {
    return false;
  }
  for (const char c : host) {
    const unsigned char value = static_cast<unsigned char>(c);
    if (value <= 0x20 || value == 0x7F) {
      return false;
    }
    const bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                         c == '.' || c == '-' || c == ':' || c == '_';
    if (!allowed) {
      return false;
    }
  }
  return true;
}

bool ParseEndpoint(const std::string& endpoint, std::string& host, std::uint16_t& port) {
  const std::size_t separator = endpoint.rfind(':');
  if (separator == std::string::npos || separator == 0 || separator + 1 >= endpoint.size()) {
    return false;
  }
  host = endpoint.substr(0, separator);
  if (!ValidateHostString(host)) {
    return false;
  }
  const std::string port_text = endpoint.substr(separator + 1);
  if (port_text.empty() || port_text.size() > 5) {
    return false;
  }
  std::uint32_t value = 0;
  for (const char c : port_text) {
    if (c < '0' || c > '9') {
      return false;
    }
    value = value * 10 + static_cast<std::uint32_t>(c - '0');
  }
  if (value == 0 || value > 65535) {
    return false;
  }
  port = static_cast<std::uint16_t>(value);
  return true;
}

std::string FormatEndpoint(const std::string& host, std::uint16_t port) {
  return host + ":" + std::to_string(port);
}

SocketHandle CreateListener(const std::string& address, std::uint16_t port, std::string& error) {
  if (!ValidateHostString(address)) {
    error = "invalid bind address";
    return kInvalidSocket;
  }
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  if (getaddrinfo(address.c_str(), service.c_str(), &hints, &results) != 0 || results == nullptr) {
    error = "cannot resolve bind address";
    return kInvalidSocket;
  }
  SocketHandle listener = kInvalidSocket;
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
#ifdef _WIN32
    listener = static_cast<SocketHandle>(socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol));
    if (listener == INVALID_SOCKET) {
      listener = kInvalidSocket;
      continue;
    }
#else
    listener = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (listener < 0) {
      continue;
    }
#endif
    const char reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, static_cast<socklen_t>(sizeof(reuse)));
    if (bind(listener, candidate->ai_addr, static_cast<socklen_t>(candidate->ai_addrlen)) == 0 &&
        listen(listener, SOMAXCONN) == 0) {
      break;
    }
    CloseSocket(listener);
    listener = kInvalidSocket;
  }
  freeaddrinfo(results);
  if (listener == kInvalidSocket) {
    error = "cannot bind listener on " + address + ":" + service;
  }
  return listener;
}

SocketHandle AcceptConnection(SocketHandle listener, std::string& error) {
  sockaddr_storage address{};
  socklen_t length = static_cast<socklen_t>(sizeof(address));
#ifdef _WIN32
  const SOCKET accepted = accept(static_cast<SOCKET>(listener), reinterpret_cast<sockaddr*>(&address), &length);
  if (accepted == INVALID_SOCKET) {
    error = "accept failed: " + SocketErrorText(LastSocketError());
    return kInvalidSocket;
  }
  return static_cast<SocketHandle>(accepted);
#else
  const int accepted = accept(listener, reinterpret_cast<sockaddr*>(&address), &length);
  if (accepted < 0) {
    error = "accept failed: " + SocketErrorText(LastSocketError());
    return kInvalidSocket;
  }
  return accepted;
#endif
}

SocketHandle ConnectTo(const std::string& host, std::uint16_t port, std::uint32_t bound_ms, std::string& error) {
  if (!ValidateHostString(host)) {
    error = "invalid host";
    return kInvalidSocket;
  }
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  if (getaddrinfo(host.c_str(), service.c_str(), &hints, &results) != 0 || results == nullptr) {
    error = "cannot resolve " + host;
    return kInvalidSocket;
  }
  SocketHandle socket_handle = kInvalidSocket;
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
#ifdef _WIN32
    socket_handle =
        static_cast<SocketHandle>(socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol));
    if (socket_handle == INVALID_SOCKET) {
      socket_handle = kInvalidSocket;
      continue;
    }
#else
    socket_handle = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (socket_handle < 0) {
      continue;
    }
#endif
    if (connect(socket_handle, candidate->ai_addr, static_cast<socklen_t>(candidate->ai_addrlen)) == 0) {
      break;
    }
    CloseSocket(socket_handle);
    socket_handle = kInvalidSocket;
  }
  freeaddrinfo(results);
  if (socket_handle == kInvalidSocket) {
    error = "cannot connect to " + FormatEndpoint(host, port) + " within " + std::to_string(bound_ms) + " ms";
  }
  return socket_handle;
}

void CloseSocket(SocketHandle socket_handle) noexcept {
  if (socket_handle == kInvalidSocket) {
    return;
  }
#ifdef _WIN32
  closesocket(static_cast<SOCKET>(socket_handle));
#else
  ::close(socket_handle);
#endif
}

void ShutdownSocket(SocketHandle socket_handle) noexcept {
  if (socket_handle == kInvalidSocket) {
    return;
  }
#ifdef _WIN32
  shutdown(static_cast<SOCKET>(socket_handle), SD_BOTH);
#else
  shutdown(socket_handle, SHUT_RDWR);
#endif
}

bool SetNoDelay(SocketHandle socket_handle) noexcept {
  const char enabled = 1;
  return setsockopt(socket_handle, IPPROTO_TCP, TCP_NODELAY, &enabled, static_cast<socklen_t>(sizeof(enabled))) == 0;
}

bool SendAll(SocketHandle socket_handle, std::span<const std::byte> data, std::string& error) {
  std::size_t sent = 0;
  while (sent < data.size()) {
    const std::size_t remaining = data.size() - sent;
    const std::size_t limit = static_cast<std::size_t>(1) << 20;
    const int chunk = static_cast<int>(remaining > limit ? limit : remaining);
#ifdef _WIN32
    const int result = send(static_cast<SOCKET>(socket_handle),
                            reinterpret_cast<const char*>(data.data() + sent), chunk, 0);
    if (result == SOCKET_ERROR) {
      error = "send failed: " + SocketErrorText(LastSocketError());
      return false;
    }
#else
    const ssize_t result = send(socket_handle, data.data() + sent, static_cast<std::size_t>(chunk), 0);
    if (result < 0) {
      error = "send failed: " + SocketErrorText(LastSocketError());
      return false;
    }
#endif
    if (result == 0) {
      error = "send made no progress";
      return false;
    }
    sent += static_cast<std::size_t>(result);
  }
  return true;
}

bool SetSendTimeout(SocketHandle socket_handle, std::uint32_t bound_ms) noexcept {
#ifdef _WIN32
  const DWORD timeout = static_cast<DWORD>(bound_ms);
  return setsockopt(static_cast<SOCKET>(socket_handle), SOL_SOCKET, SO_SNDTIMEO,
                    reinterpret_cast<const char*>(&timeout), static_cast<socklen_t>(sizeof(timeout))) == 0;
#else
  timeval tv{};
  tv.tv_sec = static_cast<long>(bound_ms / 1000);
  tv.tv_usec = static_cast<long>((bound_ms % 1000) * 1000);
  return setsockopt(socket_handle, SOL_SOCKET, SO_SNDTIMEO, &tv, static_cast<socklen_t>(sizeof(tv))) == 0;
#endif
}

bool ListenerBoundPort(SocketHandle listener, std::uint16_t& port) noexcept {
  sockaddr_storage address{};
  socklen_t length = static_cast<socklen_t>(sizeof(address));
  if (getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    return false;
  }
  if (address.ss_family != AF_INET) {
    return false;
  }
  const auto* inet = reinterpret_cast<const sockaddr_in*>(&address);
  port = ntohs(inet->sin_port);
  return port != 0;
}

RecvOutcome RecvExact(SocketHandle socket_handle, std::span<std::byte> data, std::uint32_t bound_ms, std::string& error) {
  if (bound_ms == 0) {
    error = "receive bound must be positive";
    return RecvOutcome::kError;
  }
#ifdef _WIN32
  const DWORD timeout = static_cast<DWORD>(bound_ms);
  setsockopt(static_cast<SOCKET>(socket_handle), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout),
             static_cast<socklen_t>(sizeof(timeout)));
#else
  timeval tv{};
  tv.tv_sec = static_cast<long>(bound_ms / 1000);
  tv.tv_usec = static_cast<long>((bound_ms % 1000) * 1000);
  setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, &tv, static_cast<socklen_t>(sizeof(tv)));
#endif
  std::size_t received = 0;
  while (received < data.size()) {
    const std::size_t remaining = data.size() - received;
    const std::size_t limit = static_cast<std::size_t>(1) << 20;
    const int chunk = static_cast<int>(remaining > limit ? limit : remaining);
#ifdef _WIN32
    const int result = recv(static_cast<SOCKET>(socket_handle), reinterpret_cast<char*>(data.data() + received),
                            chunk, 0);
    if (result == SOCKET_ERROR) {
      const int code = LastSocketError();
      if (code == WSAETIMEDOUT) {
        error = "receive bound of " + std::to_string(bound_ms) + " ms elapsed with an incomplete message";
        return RecvOutcome::kBoundExceeded;
      }
      if (code == WSAECONNRESET || code == WSAECONNABORTED) {
        return RecvOutcome::kPeerClosed;
      }
      error = "recv failed: " + SocketErrorText(code);
      return RecvOutcome::kError;
    }
#else
    const ssize_t result = recv(socket_handle, data.data() + received, static_cast<std::size_t>(chunk), 0);
    if (result < 0) {
      const int code = LastSocketError();
      if (code == EAGAIN || code == EWOULDBLOCK) {
        error = "receive bound of " + std::to_string(bound_ms) + " ms elapsed with an incomplete message";
        return RecvOutcome::kBoundExceeded;
      }
      if (code == ECONNRESET || code == ECONNABORTED) {
        return RecvOutcome::kPeerClosed;
      }
      error = "recv failed: " + SocketErrorText(code);
      return RecvOutcome::kError;
    }
#endif
    if (result == 0) {
      return RecvOutcome::kPeerClosed;
    }
    received += static_cast<std::size_t>(result);
  }
  return RecvOutcome::kOk;
}

}  // namespace summon::pathplanner::internal

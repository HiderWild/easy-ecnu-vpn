#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "platform/win32/native_datagram_socket.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <limits>
#include <sstream>
#include <string>
#include <utility>

namespace exv {
namespace platform {
namespace {

constexpr int kDatagramTimeoutMs = 15000;
constexpr std::size_t kMaxDatagramSize = 64 * 1024;

SOCKET socket_from_handle(std::uintptr_t handle) {
  return handle == 0 ? INVALID_SOCKET : static_cast<SOCKET>(handle);
}

std::uintptr_t handle_from_socket(SOCKET socket) {
  return socket == INVALID_SOCKET ? 0 : static_cast<std::uintptr_t>(socket);
}

vpn_engine::protocol::DatagramResult fail(std::string code,
                                          std::string message,
                                          int native_code = 0) {
  vpn_engine::protocol::DatagramResult result;
  result.ok = false;
  result.code = std::move(code);
  result.message = std::move(message);
  result.native_code = native_code;
  return result;
}

std::string wsa_message(const char *operation, int native_code) {
  std::ostringstream out;
  out << operation << " failed with WSA error " << native_code;
  return out.str();
}

vpn_engine::protocol::DatagramResult set_timeout(SOCKET socket, int opt) {
  const DWORD timeout = kDatagramTimeoutMs;
  if (::setsockopt(socket, SOL_SOCKET, opt,
                   reinterpret_cast<const char *>(&timeout),
                   sizeof(timeout)) == SOCKET_ERROR) {
    const int native_error = WSAGetLastError();
    return fail("udp_socket_config_failed",
                wsa_message("setsockopt", native_error), native_error);
  }
  return {};
}

vpn_engine::protocol::DatagramResult configure_timeouts(SOCKET socket) {
  auto recv_timeout = set_timeout(socket, SO_RCVTIMEO);
  if (!recv_timeout.ok) {
    return recv_timeout;
  }
  return set_timeout(socket, SO_SNDTIMEO);
}

addrinfo hints() {
  addrinfo out{};
  out.ai_family = AF_UNSPEC;
  out.ai_socktype = SOCK_DGRAM;
  out.ai_protocol = IPPROTO_UDP;
  return out;
}

} // namespace

NativeDatagramSocket::NativeDatagramSocket() = default;

NativeDatagramSocket::~NativeDatagramSocket() { close(); }

vpn_engine::protocol::DatagramResult NativeDatagramSocket::connect(
    const vpn_engine::protocol::DatagramEndpoint &endpoint) {
  close();

  WSADATA data{};
  int startup = ::WSAStartup(MAKEWORD(2, 2), &data);
  if (startup != 0) {
    return fail("udp_startup_failed", wsa_message("WSAStartup", startup),
                startup);
  }
  wsa_started_ = true;

  addrinfo *resolved = nullptr;
  const std::string port = std::to_string(endpoint.port);
  addrinfo query = hints();
  const int resolve =
      ::getaddrinfo(endpoint.host.c_str(), port.c_str(), &query, &resolved);
  if (resolve != 0) {
    return fail("udp_resolve_failed", wsa_message("getaddrinfo", resolve),
                resolve);
  }

  vpn_engine::protocol::DatagramResult last =
      fail("udp_connect_failed", "no UDP address candidates were available");
  for (addrinfo *it = resolved; it != nullptr; it = it->ai_next) {
    SOCKET candidate =
        ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (candidate == INVALID_SOCKET) {
      const int native_error = WSAGetLastError();
      last = fail("udp_connect_failed", wsa_message("socket", native_error),
                  native_error);
      continue;
    }
    auto timeout = configure_timeouts(candidate);
    if (!timeout.ok) {
      ::closesocket(candidate);
      last = timeout;
      continue;
    }
    if (::connect(candidate, it->ai_addr,
                  static_cast<int>(it->ai_addrlen)) == 0) {
      socket_ = handle_from_socket(candidate);
      last = {};
      break;
    }
    const int native_error = WSAGetLastError();
    last = fail(native_error == WSAETIMEDOUT ? "udp_timeout"
                                             : "udp_connect_failed",
                wsa_message("connect", native_error), native_error);
    ::closesocket(candidate);
  }

  ::freeaddrinfo(resolved);
  if (!last.ok) {
    close();
  }
  return last;
}

vpn_engine::protocol::DatagramResult
NativeDatagramSocket::send(const std::vector<std::uint8_t> &packet) {
  SOCKET socket = socket_from_handle(socket_);
  if (socket == INVALID_SOCKET) {
    return fail("udp_socket_closed", "UDP socket is not connected");
  }
  const int size = static_cast<int>(std::min<std::size_t>(
      packet.size(), static_cast<std::size_t>(std::numeric_limits<int>::max())));
  const int sent =
      ::send(socket, reinterpret_cast<const char *>(packet.data()), size, 0);
  if (sent == SOCKET_ERROR || sent != size) {
    const int native_error =
        sent == SOCKET_ERROR ? WSAGetLastError() : WSAEMSGSIZE;
    return fail(native_error == WSAETIMEDOUT ? "udp_timeout"
                                             : "udp_send_failed",
                wsa_message("send", native_error), native_error);
  }
  return {};
}

vpn_engine::protocol::DatagramResult
NativeDatagramSocket::receive(std::vector<std::uint8_t> *packet) {
  if (!packet) {
    return fail("udp_receive_failed", "receive output must not be null");
  }
  packet->clear();
  SOCKET socket = socket_from_handle(socket_);
  if (socket == INVALID_SOCKET) {
    return fail("udp_socket_closed", "UDP socket is not connected");
  }

  std::vector<std::uint8_t> buffer(kMaxDatagramSize);
  const int received =
      ::recv(socket, reinterpret_cast<char *>(buffer.data()),
             static_cast<int>(buffer.size()), 0);
  if (received == SOCKET_ERROR) {
    const int native_error = WSAGetLastError();
    return fail(native_error == WSAETIMEDOUT ? "udp_timeout"
                                             : "udp_receive_failed",
                wsa_message("recv", native_error), native_error);
  }
  buffer.resize(static_cast<std::size_t>(received));
  *packet = std::move(buffer);
  return {};
}

void NativeDatagramSocket::close() {
  SOCKET socket = socket_from_handle(socket_);
  socket_ = 0;
  if (socket != INVALID_SOCKET) {
    ::closesocket(socket);
  }
  if (wsa_started_) {
    ::WSACleanup();
    wsa_started_ = false;
  }
}

} // namespace platform
} // namespace exv

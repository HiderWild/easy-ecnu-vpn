#include "platform/darwin/native_datagram_socket.hpp"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <sstream>
#include <string>
#include <utility>

namespace exv {
namespace platform {
namespace {

constexpr int kDatagramTimeoutMs = 15000;
constexpr std::size_t kMaxDatagramSize = 64 * 1024;

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

std::string errno_message(const char *operation, int native_code) {
  std::ostringstream out;
  out << operation << " failed with errno " << native_code << ": "
      << std::strerror(native_code);
  return out.str();
}

bool timeout_errno(int native_code) {
  return native_code == EAGAIN || native_code == EWOULDBLOCK ||
         native_code == ETIMEDOUT;
}

addrinfo hints() {
  addrinfo out{};
  out.ai_family = AF_UNSPEC;
  out.ai_socktype = SOCK_DGRAM;
  out.ai_protocol = IPPROTO_UDP;
  return out;
}

vpn_engine::protocol::DatagramResult configure_timeouts(int fd) {
  timeval timeout{};
  timeout.tv_sec = kDatagramTimeoutMs / 1000;
  timeout.tv_usec = (kDatagramTimeoutMs % 1000) * 1000;
  if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
      ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
    const int native_error = errno;
    return fail("udp_socket_config_failed",
                errno_message("setsockopt", native_error), native_error);
  }
  return {};
}

} // namespace

NativeDatagramSocket::NativeDatagramSocket() = default;

NativeDatagramSocket::~NativeDatagramSocket() { close(); }

vpn_engine::protocol::DatagramResult NativeDatagramSocket::connect(
    const vpn_engine::protocol::DatagramEndpoint &endpoint) {
  close();

  addrinfo *resolved = nullptr;
  const std::string port = std::to_string(endpoint.port);
  addrinfo query = hints();
  const int resolve =
      ::getaddrinfo(endpoint.host.c_str(), port.c_str(), &query, &resolved);
  if (resolve != 0) {
    return fail("udp_resolve_failed", "getaddrinfo failed: " + std::to_string(resolve),
                resolve);
  }

  auto last = fail("udp_connect_failed", "no UDP address candidates were available");
  for (addrinfo *it = resolved; it != nullptr; it = it->ai_next) {
    const int candidate = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (candidate < 0) {
      const int native_error = errno;
      last = fail("udp_connect_failed", errno_message("socket", native_error),
                  native_error);
      continue;
    }
    auto timeout = configure_timeouts(candidate);
    if (!timeout.ok) {
      ::close(candidate);
      last = timeout;
      continue;
    }
    if (::connect(candidate, it->ai_addr, it->ai_addrlen) == 0) {
      fd_ = candidate;
      last = {};
      break;
    }
    const int native_error = errno;
    last = fail(timeout_errno(native_error) ? "udp_timeout" : "udp_connect_failed",
                errno_message("connect", native_error), native_error);
    ::close(candidate);
  }

  ::freeaddrinfo(resolved);
  if (!last.ok) {
    close();
  }
  return last;
}

vpn_engine::protocol::DatagramResult
NativeDatagramSocket::send(const std::vector<std::uint8_t> &packet) {
  if (fd_ < 0) {
    return fail("udp_socket_closed", "UDP socket is not connected");
  }
  const std::size_t size = std::min<std::size_t>(
      packet.size(), static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()));
  const ssize_t sent = ::send(fd_, packet.data(), size, 0);
  if (sent < 0 || static_cast<std::size_t>(sent) != size) {
    const int native_error = sent < 0 ? errno : EMSGSIZE;
    return fail(timeout_errno(native_error) ? "udp_timeout" : "udp_send_failed",
                errno_message("send", native_error), native_error);
  }
  return {};
}

vpn_engine::protocol::DatagramResult
NativeDatagramSocket::receive(std::vector<std::uint8_t> *packet) {
  if (!packet) {
    return fail("udp_receive_failed", "receive output must not be null");
  }
  packet->clear();
  if (fd_ < 0) {
    return fail("udp_socket_closed", "UDP socket is not connected");
  }

  std::vector<std::uint8_t> buffer(kMaxDatagramSize);
  const ssize_t received = ::recv(fd_, buffer.data(), buffer.size(), 0);
  if (received < 0) {
    const int native_error = errno;
    return fail(timeout_errno(native_error) ? "udp_timeout" : "udp_receive_failed",
                errno_message("recv", native_error), native_error);
  }
  buffer.resize(static_cast<std::size_t>(received));
  *packet = std::move(buffer);
  return {};
}

void NativeDatagramSocket::close() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

} // namespace platform
} // namespace exv

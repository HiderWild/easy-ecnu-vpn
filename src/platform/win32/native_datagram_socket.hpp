#pragma once

#include "vpn_engine/protocol/datagram_socket.hpp"

#include <cstdint>
#include <vector>

namespace exv {
namespace platform {

class NativeDatagramSocket final
    : public vpn_engine::protocol::DatagramSocket {
public:
  NativeDatagramSocket();
  ~NativeDatagramSocket() override;

  NativeDatagramSocket(const NativeDatagramSocket &) = delete;
  NativeDatagramSocket &operator=(const NativeDatagramSocket &) = delete;

  vpn_engine::protocol::DatagramResult
  connect(const vpn_engine::protocol::DatagramEndpoint &endpoint) override;
  vpn_engine::protocol::DatagramResult
  send(const std::vector<std::uint8_t> &packet) override;
  vpn_engine::protocol::DatagramResult
  receive(std::vector<std::uint8_t> *packet) override;
  void close() override;

private:
  std::uintptr_t socket_ = 0;
  bool wsa_started_ = false;
};

} // namespace platform
} // namespace exv

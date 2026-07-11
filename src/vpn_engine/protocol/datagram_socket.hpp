#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace exv {
namespace vpn_engine {
namespace protocol {

struct DatagramEndpoint {
  std::string host;
  int port = 0;
};

struct DatagramResult {
  bool ok = true;
  std::string code;
  std::string message;
  int native_code = 0;
};

class DatagramSocket {
public:
  virtual ~DatagramSocket() = default;

  virtual DatagramResult connect(const DatagramEndpoint &endpoint) = 0;
  virtual DatagramResult send(const std::vector<std::uint8_t> &packet) = 0;
  virtual DatagramResult receive(std::vector<std::uint8_t> *packet) = 0;
  virtual void close() = 0;
};

} // namespace protocol
} // namespace vpn_engine
} // namespace exv

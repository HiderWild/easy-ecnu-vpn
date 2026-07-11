#pragma once

#include "vpn_engine/engine.hpp"
#include "vpn_engine/protocol/dtls_policy.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace exv {
namespace vpn_engine {
namespace protocol {

class DataChannel {
public:
  virtual ~DataChannel() = default;

  virtual const char *name() const = 0;
  virtual ValidationResult connect() = 0;
  virtual ValidationResult
  send_packet(const std::vector<std::uint8_t> &packet) = 0;
  virtual ValidationResult receive_packet(std::vector<std::uint8_t> *packet) = 0;
  virtual void close() = 0;
};

struct DataChannelSelection {
  ValidationResult connect_result;
  std::string active_channel = "cstp_tls";
  std::string fallback_reason;
  DataChannel *channel = nullptr;
};

class DataChannelSelector {
public:
  DataChannelSelection select(DataChannel &cstp_tls, DataChannel &dtls,
                              const DtlsDecision &decision) const;
};

} // namespace protocol
} // namespace vpn_engine
} // namespace exv

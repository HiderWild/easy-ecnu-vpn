#pragma once

#include "vpn_engine/engine.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace exv {
namespace vpn_engine {
namespace protocol {

struct TlsEndpoint {
  std::string host;
  int port = 443;
  std::string sni_host;
};

class TlsStream {
public:
  virtual ~TlsStream() = default;

  virtual ValidationResult connect(const TlsEndpoint &endpoint) = 0;
  virtual ValidationResult write_all(const std::vector<std::uint8_t> &bytes) = 0;
  virtual ValidationResult read_some(std::vector<std::uint8_t> *bytes) = 0;
  virtual ValidationResult
  export_keying_material(const std::string &label, std::size_t length,
                         std::vector<std::uint8_t> *out) {
    (void)label;
    (void)length;
    if (out)
      out->clear();

    ValidationResult result;
    result.ok = false;
    result.code = "dtls_exporter_unavailable";
    result.message = "TLS exporter is not available from this TLS stream";
    return result;
  }
  virtual void close() = 0;
};

} // namespace protocol
} // namespace vpn_engine
} // namespace exv

#pragma once

#include "vpn_engine/engine.hpp"
#include "vpn_engine/protocol/datagram_socket.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace exv {
namespace vpn_engine {
namespace protocol {

class TlsStream;

struct DtlsChannelOptions {
  DatagramEndpoint endpoint;
  std::string session_id;
  std::string cipher_suite;
  std::vector<std::uint8_t> psk;
  int mtu = 1200;
};

class DtlsChannel {
public:
  virtual ~DtlsChannel() = default;
  virtual ValidationResult connect(const DtlsChannelOptions &options) = 0;
  virtual ValidationResult
  send_packet(const std::vector<std::uint8_t> &packet) = 0;
  virtual ValidationResult receive_packet(std::vector<std::uint8_t> *packet) = 0;
  virtual void close() = 0;
};

inline constexpr const char kDtls12PskExporterLabel[] =
    "EXPORTER-openconnect-psk";
inline constexpr std::size_t kDtls12PskLength = 32;

bool dtls_backend_compiled();

ValidationResult derive_dtls12_psk_from_tls_exporter(
    TlsStream *stream, std::vector<std::uint8_t> *psk);

std::unique_ptr<DtlsChannel>
make_openssl_dtls_channel(std::unique_ptr<DatagramSocket> socket);

} // namespace protocol
} // namespace vpn_engine
} // namespace exv

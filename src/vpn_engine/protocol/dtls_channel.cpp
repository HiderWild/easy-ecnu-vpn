#include "vpn_engine/protocol/dtls_channel.hpp"

#include "vpn_engine/protocol/tls_stream.hpp"

#include <utility>

namespace exv {
namespace vpn_engine {
namespace protocol {

namespace {

ValidationResult invalid(std::string code, std::string message) {
  ValidationResult result;
  result.ok = false;
  result.code = std::move(code);
  result.message = std::move(message);
  return result;
}

} // namespace

ValidationResult derive_dtls12_psk_from_tls_exporter(
    TlsStream *stream, std::vector<std::uint8_t> *psk) {
  if (!psk) {
    return invalid("dtls_exporter_null_out",
                   "TLS exporter output must not be null");
  }
  if (!stream) {
    psk->clear();
    return invalid("dtls_exporter_unavailable",
                   "TLS exporter is not available from the current TLS stream");
  }
  ValidationResult exported = stream->export_keying_material(
      kDtls12PskExporterLabel, kDtls12PskLength, psk);
  if (!exported.ok)
    psk->clear();
  return exported;
}

} // namespace protocol
} // namespace vpn_engine
} // namespace exv

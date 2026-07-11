#include "vpn_engine/protocol/dtls_offer.hpp"

#include <cstddef>
#include <iomanip>
#include <sstream>

namespace exv {
namespace vpn_engine {
namespace protocol {
namespace {

constexpr std::size_t kLegacyMasterSecretSize = 48;

bool is_safe_header_value(const std::string &value) {
  return value.find('\r') == std::string::npos &&
         value.find('\n') == std::string::npos &&
         value.find('\0') == std::string::npos;
}

std::string uppercase_hex(const std::vector<std::uint8_t> &bytes) {
  std::ostringstream out;
  out << std::uppercase << std::hex << std::setfill('0');
  for (std::uint8_t byte : bytes)
    out << std::setw(2) << static_cast<int>(byte);
  return out.str();
}

void append_safe_header(std::ostringstream *out, const char *name,
                        const std::string &value) {
  if (!out || value.empty() || !is_safe_header_value(value))
    return;
  *out << name << ": " << value << "\r\n";
}

} // namespace

std::string build_dtls_offer_headers(const DtlsOfferInput &input) {
  if (input.mode == DtlsMode::Disabled || !input.backend_available ||
      !input.request_headers_allowed) {
    return {};
  }

  std::ostringstream out;
  if (input.legacy_master_secret.size() == kLegacyMasterSecretSize) {
    out << "X-DTLS-Master-Secret: "
        << uppercase_hex(input.legacy_master_secret) << "\r\n";
  }
  append_safe_header(&out, "X-DTLS-CipherSuite", input.legacy_cipher_suites);
  append_safe_header(&out, "X-DTLS12-CipherSuite",
                     input.dtls12_cipher_suites);
  return out.str();
}

} // namespace protocol
} // namespace vpn_engine
} // namespace exv

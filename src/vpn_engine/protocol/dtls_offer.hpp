#pragma once

#include "vpn_engine/protocol/dtls_policy.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace exv {
namespace vpn_engine {
namespace protocol {

struct DtlsOfferInput {
  DtlsMode mode = DtlsMode::Auto;
  bool backend_available = false;
  bool request_headers_allowed = false;
  std::vector<std::uint8_t> legacy_master_secret;
  std::string legacy_cipher_suites;
  std::string dtls12_cipher_suites;
};

std::string build_dtls_offer_headers(const DtlsOfferInput &input);

} // namespace protocol
} // namespace vpn_engine
} // namespace exv

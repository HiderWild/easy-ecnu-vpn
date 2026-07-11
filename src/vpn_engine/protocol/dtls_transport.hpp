#pragma once

#include <string>

namespace exv {
namespace vpn_engine {
namespace protocol {

enum class DtlsTransportState {
  disabled,
  not_advertised_or_skipped,
  attempted_and_connected,
  attempted_and_fell_back_to_tls,
  attempted_and_failed_without_tls_fallback,
};

struct DtlsNegotiationInput {
  bool disabled_by_config = true;
  bool gateway_advertised = false;
  bool backend_available = false;
  bool attempted = false;
  bool handshake_succeeded = false;
  bool tls_fallback_allowed = true;
  std::string failure_reason;
};

struct DtlsNegotiationStatus {
  DtlsTransportState state = DtlsTransportState::disabled;
  bool cstp_tls_active = true;
  std::string reason;
};

const char *dtls_transport_state_to_string(DtlsTransportState state);
DtlsNegotiationStatus
classify_dtls_negotiation(const DtlsNegotiationInput &input);

} // namespace protocol
} // namespace vpn_engine
} // namespace exv

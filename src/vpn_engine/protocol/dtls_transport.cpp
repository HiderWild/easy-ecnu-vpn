#include "vpn_engine/protocol/dtls_transport.hpp"

namespace exv {
namespace vpn_engine {
namespace protocol {

const char *dtls_transport_state_to_string(DtlsTransportState state) {
  switch (state) {
  case DtlsTransportState::disabled:
    return "disabled";
  case DtlsTransportState::not_advertised_or_skipped:
    return "not_advertised_or_skipped";
  case DtlsTransportState::attempted_and_connected:
    return "attempted_and_connected";
  case DtlsTransportState::attempted_and_fell_back_to_tls:
    return "attempted_and_fell_back_to_tls";
  case DtlsTransportState::attempted_and_failed_without_tls_fallback:
    return "attempted_and_failed_without_tls_fallback";
  }
  return "disabled";
}

DtlsNegotiationStatus
classify_dtls_negotiation(const DtlsNegotiationInput &input) {
  DtlsNegotiationStatus status;

  if (input.disabled_by_config) {
    status.state = DtlsTransportState::disabled;
    status.cstp_tls_active = true;
    status.reason = "DTLS disabled by native engine policy";
    return status;
  }

  if (!input.gateway_advertised) {
    status.state = DtlsTransportState::not_advertised_or_skipped;
    status.cstp_tls_active = true;
    status.reason = "gateway did not advertise DTLS";
    return status;
  }

  if (!input.backend_available) {
    status.state = DtlsTransportState::not_advertised_or_skipped;
    status.cstp_tls_active = true;
    status.reason = input.failure_reason.empty()
                        ? "native DTLS backend unavailable; using CSTP/TLS"
                        : input.failure_reason;
    return status;
  }

  if (!input.attempted) {
    status.state = DtlsTransportState::not_advertised_or_skipped;
    status.cstp_tls_active = true;
    status.reason = input.failure_reason.empty()
                        ? "DTLS was skipped by policy; using CSTP/TLS"
                        : input.failure_reason;
    return status;
  }

  if (input.handshake_succeeded) {
    status.state = DtlsTransportState::attempted_and_connected;
    status.cstp_tls_active = false;
    status.reason = "DTLS transport connected";
    return status;
  }

  if (input.tls_fallback_allowed) {
    status.state = DtlsTransportState::attempted_and_fell_back_to_tls;
    status.cstp_tls_active = true;
    status.reason = input.failure_reason.empty()
                        ? "native DTLS backend unavailable; using CSTP/TLS"
                        : input.failure_reason;
    return status;
  }

  status.state = DtlsTransportState::attempted_and_failed_without_tls_fallback;
  status.cstp_tls_active = false;
  status.reason = input.failure_reason.empty()
                      ? "DTLS negotiation failed and TLS fallback is disabled"
                      : input.failure_reason;
  return status;
}

} // namespace protocol
} // namespace vpn_engine
} // namespace exv

#include "vpn_engine/protocol/data_channel.hpp"

namespace exv {
namespace vpn_engine {
namespace protocol {

DataChannelSelection DataChannelSelector::select(
    DataChannel &cstp_tls, DataChannel &dtls,
    const DtlsDecision &decision) const {
  DataChannelSelection selection;
  selection.connect_result = {};
  selection.active_channel = cstp_tls.name();
  selection.channel = &cstp_tls;

  if (!decision.should_attempt) {
    selection.fallback_reason = decision.reason;
    return selection;
  }

  ValidationResult dtls_connected = dtls.connect();
  if (dtls_connected.ok) {
    selection.connect_result = dtls_connected;
    selection.active_channel = dtls.name();
    selection.fallback_reason.clear();
    selection.channel = &dtls;
    return selection;
  }

  selection.connect_result = {};
  selection.active_channel = cstp_tls.name();
  selection.fallback_reason = dtls_connected.code.empty() ? dtls_connected.message
                                                          : dtls_connected.code;
  if (selection.fallback_reason.empty())
    selection.fallback_reason = "dtls_connect_failed";
  selection.channel = &cstp_tls;
  dtls.close();
  return selection;
}

} // namespace protocol
} // namespace vpn_engine
} // namespace exv

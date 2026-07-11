#pragma once

#include "vpn_engine/protocol/data_channel.hpp"
#include "vpn_engine/protocol/dtls_channel.hpp"
#include "vpn_engine/protocol/session.hpp"
#include "vpn_engine/protocol/tls_stream.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace exv {
namespace vpn_engine {
namespace protocol {

struct HttpResponse;

class ProductionProtocolTransport final : public ProtocolTransport {
public:
  using DtlsChannelFactory =
      std::function<std::unique_ptr<DtlsChannel>(const TunnelMetadata &)>;

  explicit ProductionProtocolTransport(
      TlsStream *stream, std::string client_hostname = "exv");
  explicit ProductionProtocolTransport(TlsStream *stream,
                                       DtlsChannelFactory dtls_channel_factory,
                                       std::string client_hostname = "exv");
  explicit ProductionProtocolTransport(
      std::unique_ptr<TlsStream> stream,
      std::string client_hostname = "exv");
  explicit ProductionProtocolTransport(std::unique_ptr<TlsStream> stream,
                                       DtlsChannelFactory dtls_channel_factory,
                                       std::string client_hostname = "exv");

  AuthResult authenticate(const ProtocolSessionOptions &options) override;
  ValidationResult connect_cstp(const std::string &cookie,
                                TunnelMetadata *metadata) override;
  ValidationResult
  send_packet(const std::vector<std::uint8_t> &packet) override;
  ValidationResult send_control(InboundFrameKind kind) override;
  ValidationResult receive_frame(InboundFrame *out) override;
  bool can_fallback_to_cstp() const override;
  void fallback_to_cstp(const std::string &reason,
                        const std::string &code) override;

  void disconnect() override;
  void reset_for_reconnect() override;

private:
  ValidationResult read_more();
  ValidationResult read_http_response(bool leave_body_in_buffer,
                                      HttpResponse *response);
  ValidationResult write_frame_locked(const std::vector<std::uint8_t> &wire);

  std::unique_ptr<TlsStream> owned_stream_;
  TlsStream *stream_ = nullptr;
  DtlsChannelFactory dtls_channel_factory_;
  std::shared_ptr<DataChannel> dtls_data_channel_;
  std::string client_hostname_;

  ParsedVpnUrl server_;
  std::string useragent_;
  std::string current_password_;
  std::string current_password_form_encoded_;
  std::string auth_cookie_;
  int requested_mtu_ = 1290;
  AuthCookieJar cookies_;
  std::vector<std::uint8_t> read_buffer_;
  bool stream_connected_ = false;
  bool cstp_connected_ = false;
  bool dtls_disabled_ = true;
  DtlsMode dtls_mode_ = DtlsMode::Disabled;
  bool dtls_backend_available_ = false;
  bool dtls_data_channel_active_ = false;
  DtlsFailureHistory dtls_failures_;

  // Serializes outbound writes (send_packet / send_control / disconnect frame)
  // so the inbound read thread and outbound write thread can share one stream.
  std::mutex write_mutex_;
  mutable std::mutex data_channel_mutex_;
};

} // namespace protocol
} // namespace vpn_engine
} // namespace exv

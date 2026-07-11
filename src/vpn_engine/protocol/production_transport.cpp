#include "vpn_engine/protocol/production_transport.hpp"

#include "vpn_engine/protocol/aggregate_auth.hpp"
#include "vpn_engine/protocol/cstp.hpp"
#include "vpn_engine/protocol/dtls_offer.hpp"
#include "vpn_engine/protocol/dtls_policy.hpp"
#include "vpn_engine/protocol/dtls_transport.hpp"
#include "vpn_engine/protocol/http.hpp"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <sstream>
#include <string_view>
#include <utility>
#include <vector>

namespace exv {
namespace vpn_engine {
namespace protocol {

namespace {

constexpr const char *kCstpPath = "/CSCOSSLC/tunnel";
constexpr const char *kDefaultUserAgent = "EXV Native";
constexpr std::size_t kMaxHttpHeaderBytes = 64 * 1024;
constexpr std::size_t kMaxHttpBodyBytes = 16 * 1024 * 1024;
// Begin inlined from vpn_engine/protocol/production_transport_redaction include-unit
ValidationResult invalid(std::string code, std::string message) {
  ValidationResult result;
  result.ok = false;
  result.code = std::move(code);
  result.message = std::move(message);
  return result;
}

AuthResult auth_error(std::string code, std::string message) {
  AuthResult result;
  result.ok = false;
  result.error_code = std::move(code);
  result.error_message = std::move(message);
  return result;
}

bool is_ascii_space(unsigned char ch) {
  return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

std::string_view trim_ascii(std::string_view s) {
  while (!s.empty() && is_ascii_space(static_cast<unsigned char>(s.front())))
    s.remove_prefix(1);
  while (!s.empty() && is_ascii_space(static_cast<unsigned char>(s.back())))
    s.remove_suffix(1);
  return s;
}

void replace_all(std::string *text, const std::string &needle,
                 const std::string &replacement) {
  if (!text || needle.empty())
    return;

  std::size_t pos = 0;
  while ((pos = text->find(needle, pos)) != std::string::npos) {
    text->replace(pos, needle.size(), replacement);
    pos += replacement.size();
  }
}

void redact_cookie_header(std::string *text, std::string_view cookie_header) {
  if (!text)
    return;

  cookie_header = trim_ascii(cookie_header);
  if (cookie_header.empty())
    return;

  const std::string full(cookie_header);
  replace_all(text, full, "[REDACTED_COOKIE]");

  while (!cookie_header.empty()) {
    const std::size_t semi = cookie_header.find(';');
    std::string_view pair =
        semi == std::string_view::npos ? cookie_header
                                       : cookie_header.substr(0, semi);
    cookie_header =
        semi == std::string_view::npos ? std::string_view()
                                       : cookie_header.substr(semi + 1);

    pair = trim_ascii(pair);
    const std::size_t eq = pair.find('=');
    if (eq == std::string_view::npos || eq + 1 >= pair.size())
      continue;

    std::string_view value = trim_ascii(pair.substr(eq + 1));
    if (!value.empty())
      replace_all(text, std::string(value), "[REDACTED_COOKIE_VALUE]");
  }
}

std::string sanitized_message(
    const std::string &message, const std::string &password,
    const std::string &encoded_password, const std::string &cookie_header,
    const std::string &extra_cookie_header = "") {
  std::string out = message;
  replace_all(&out, password, "[REDACTED_PASSWORD]");
  replace_all(&out, encoded_password, "[REDACTED_PASSWORD]");
  redact_cookie_header(&out, cookie_header);
  redact_cookie_header(&out, extra_cookie_header);
  return out;
}

ValidationResult sanitized_result(
    const ValidationResult &result, const std::string &password,
    const std::string &encoded_password, const std::string &cookie_header,
    const std::string &extra_cookie_header = "") {
  if (result.ok)
    return result;

  return invalid(result.code,
                 sanitized_message(result.message, password, encoded_password,
                                   cookie_header, extra_cookie_header));
}

AuthResult sanitized_auth_error(
    const std::string &code, const std::string &message,
    const std::string &password, const std::string &encoded_password,
    const std::string &cookie_header) {
  return auth_error(code,
                    sanitized_message(message, password, encoded_password,
                                      cookie_header));
}
// End inlined from vpn_engine/protocol/production_transport_redaction include-unit
// Begin inlined from vpn_engine/protocol/production_transport_requests include-unit
std::string useragent_or_default(const std::string &useragent) {
  return useragent.empty() ? std::string(kDefaultUserAgent) : useragent;
}

std::string host_header(const ParsedVpnUrl &server) {
  std::string host = server.host;
  if (host.find(':') != std::string::npos &&
      (host.empty() || host.front() != '[')) {
    host = "[" + host + "]";
  }

  if (server.port != 443)
    host += ":" + std::to_string(server.port);
  return host;
}

std::string form_url_encode(const std::string &value) {
  static constexpr char kHex[] = "0123456789ABCDEF";

  std::string out;
  out.reserve(value.size());
  for (unsigned char ch : value) {
    const bool unreserved =
        std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '*';
    if (unreserved) {
      out.push_back(static_cast<char>(ch));
    } else if (ch == ' ') {
      out.push_back('+');
    } else {
      out.push_back('%');
      out.push_back(kHex[(ch >> 4) & 0x0f]);
      out.push_back(kHex[ch & 0x0f]);
    }
  }
  return out;
}

std::string aggregate_auth_server_url(const ParsedVpnUrl &server) {
  std::ostringstream out;
  out << "https://" << host_header(server);
  if (server.base_path.empty()) {
    out << "/";
  } else {
    out << server.base_path;
  }
  return out.str();
}

std::vector<std::uint8_t> to_bytes(const std::string &text) {
  return std::vector<std::uint8_t>(text.begin(), text.end());
}

DtlsMode effective_dtls_mode(const ProtocolSessionOptions &options) {
  if (options.disable_dtls)
    return DtlsMode::Disabled;
  if (options.dtls_mode == DtlsMode::Enabled)
    return DtlsMode::Enabled;
  return DtlsMode::Auto;
}

std::string dtls_network_key(const ParsedVpnUrl &server) {
  return server.host + ":" + std::to_string(server.port);
}

std::string make_aggregate_auth_post_request(const ParsedVpnUrl &server,
                                             const std::string &useragent,
                                             const std::string &body) {
  std::ostringstream out;
  out << "POST / HTTP/1.1\r\n";
  out << "Host: " << host_header(server) << "\r\n";
  out << "User-Agent: " << useragent_or_default(useragent) << "\r\n";
  out << "Content-Type: application/xml; charset=utf-8\r\n";
  out << "Accept-Encoding: identity\r\n";
  out << "X-Transcend-Version: 1\r\n";
  out << "X-Aggregate-Auth: 1\r\n";
  out << "Content-Length: " << body.size() << "\r\n";
  out << "Connection: keep-alive\r\n";
  out << "\r\n";
  out << body;
  return out.str();
}

std::string make_cstp_connect_request(const ParsedVpnUrl &server,
                                      const std::string &useragent,
                                      const std::string &client_hostname,
                                      const std::string &cookie_header,
                                      int requested_mtu,
                                      const DtlsOfferInput &dtls_offer) {
  if (requested_mtu < 576 || requested_mtu > 1500)
    requested_mtu = 1290;

  std::ostringstream out;
  out << "CONNECT " << kCstpPath << " HTTP/1.1\r\n";
  out << "Host: " << host_header(server) << "\r\n";
  out << "User-Agent: " << useragent_or_default(useragent) << "\r\n";
  out << "Cookie: " << cookie_header << "\r\n";
  out << "X-CSTP-Version: 1\r\n";
  out << "X-CSTP-Hostname: " << client_hostname << "\r\n";
  out << "X-CSTP-Address-Type: IPv6,IPv4\r\n";
  out << "X-CSTP-Base-MTU: " << requested_mtu << "\r\n";
  out << "X-CSTP-MTU: " << requested_mtu << "\r\n";
  out << "X-CSTP-Accept-Encoding: identity\r\n";
  out << "X-Transcend-Version: 1\r\n";
  out << "X-Aggregate-Auth: 1\r\n";
  out << build_dtls_offer_headers(dtls_offer);
  out << "\r\n";
  return out.str();
}

bool response_advertises_dtls(const HttpResponse &response) {
  return response.header_ci("X-DTLS-Session-ID") ||
         response.header_ci("X-DTLS12-CipherSuite") ||
         response.header_ci("X-DTLS-CipherSuite");
}

DtlsChannelOptions dtls_options_from_metadata(
    const ParsedVpnUrl &server, const TunnelMetadata &metadata,
    TlsStream *stream,
    const std::vector<std::uint8_t> &dtls12_exporter_psk) {
  DtlsChannelOptions options;
  options.endpoint.host = server.host;
  options.endpoint.port =
      metadata.dtls_port > 0 ? metadata.dtls_port : server.port;
  options.session_id = metadata.dtls_session_id;
  options.cipher_suite = !metadata.dtls12_cipher_suite.empty()
                             ? metadata.dtls12_cipher_suite
                             : metadata.dtls_cipher_suite;
  options.psk = metadata.dtls_master_secret;
  if (options.psk.empty() && !metadata.dtls12_cipher_suite.empty()) {
    if (!dtls12_exporter_psk.empty()) {
      options.psk = dtls12_exporter_psk;
    } else {
      std::vector<std::uint8_t> exported;
      ValidationResult exporter =
          derive_dtls12_psk_from_tls_exporter(stream, &exported);
      if (exporter.ok)
        options.psk = std::move(exported);
    }
  }
  options.mtu = metadata.dtls_mtu > 0 ? metadata.dtls_mtu : metadata.mtu;
  return options;
}

class CstpTlsSelectionDataChannel final : public DataChannel {
public:
  const char *name() const override { return "cstp_tls"; }
  ValidationResult connect() override { return {}; }

  ValidationResult
  send_packet(const std::vector<std::uint8_t> & /*packet*/) override {
    return invalid(
        "cstp_data_channel_external_send",
        "CSTP/TLS packet sending is owned by ProductionProtocolTransport");
  }

  ValidationResult
  receive_packet(std::vector<std::uint8_t> * /*packet*/) override {
    return invalid(
        "cstp_data_channel_external_receive",
        "CSTP/TLS packet receiving is owned by ProductionProtocolTransport");
  }

  void close() override {}
};

class DtlsSelectionDataChannel final : public DataChannel {
public:
  DtlsSelectionDataChannel(std::unique_ptr<DtlsChannel> channel,
                           DtlsChannelOptions options)
      : channel_(std::move(channel)), options_(std::move(options)) {}

  ~DtlsSelectionDataChannel() override { close(); }

  const char *name() const override { return "dtls"; }

  ValidationResult connect() override {
    if (!channel_) {
      return invalid("dtls_backend_unavailable",
                     "native DTLS backend is unavailable");
    }
    return channel_->connect(options_);
  }

  ValidationResult
  send_packet(const std::vector<std::uint8_t> &packet) override {
    if (!channel_) {
      return invalid("dtls_backend_unavailable",
                     "native DTLS backend is unavailable");
    }
    return channel_->send_packet(packet);
  }

  ValidationResult receive_packet(std::vector<std::uint8_t> *packet) override {
    if (!channel_) {
      return invalid("dtls_backend_unavailable",
                     "native DTLS backend is unavailable");
    }
    return channel_->receive_packet(packet);
  }

  void close() override {
    if (channel_ && !closed_) {
      channel_->close();
      closed_ = true;
    }
  }

private:
  std::unique_ptr<DtlsChannel> channel_;
  DtlsChannelOptions options_;
  bool closed_ = false;
};

void assign_inbound_frame(const CstpFrame &inbound, InboundFrame *out) {
  switch (inbound.type) {
  case CstpFrameType::data:
    out->kind = InboundFrameKind::data;
    break;
  case CstpFrameType::keepalive:
    out->kind = InboundFrameKind::keepalive;
    break;
  case CstpFrameType::dpd_request:
    out->kind = InboundFrameKind::dpd_request;
    break;
  case CstpFrameType::dpd_response:
    out->kind = InboundFrameKind::dpd_response;
    break;
  case CstpFrameType::disconnect:
    out->kind = InboundFrameKind::disconnect;
    break;
  case CstpFrameType::compressed:
    out->kind = InboundFrameKind::compressed;
    break;
  case CstpFrameType::terminate:
    out->kind = InboundFrameKind::terminate;
    break;
  }
  out->payload = inbound.payload;
}

bool tls_read_has_no_cstp_frame(const ValidationResult &result) {
  return result.code == "tls_read_timeout" ||
         result.code == "tls_read_would_block" ||
         result.code == "transport_timeout";
}

const AggregateAuthField *field_named(const AggregateAuthResponse &response,
                                      const std::string &name) {
  for (const AggregateAuthField &field : response.fields) {
    if (field.name == name)
      return &field;
  }
  return nullptr;
}

std::string selected_group_from_response(const AggregateAuthResponse &response) {
  if (const AggregateAuthField *field = field_named(response, "group_list"))
    return field->value;
  return {};
}

std::string lower_ascii_copy(std::string_view value) {
  std::string out;
  out.reserve(value.size());
  for (unsigned char ch : value)
    out.push_back(static_cast<char>(std::tolower(ch)));
  return out;
}

bool is_challenge_field(const AggregateAuthField &field) {
  const std::string name = lower_ascii_copy(field.name);
  return name.find("secondary") != std::string::npos ||
         name.find("challenge") != std::string::npos ||
         name.find("token") != std::string::npos ||
         name.find("passcode") != std::string::npos;
}

const AggregateAuthField *
first_challenge_field(const AggregateAuthResponse &response) {
  for (const AggregateAuthField &field : response.fields) {
    if (is_challenge_field(field))
      return &field;
  }
  return nullptr;
}

const AggregateAuthField *
group_field(const AggregateAuthResponse &response) {
  return field_named(response, "group_list");
}

std::string extract_set_cookie_pair(std::string_view header) {
  const std::size_t semi = header.find(';');
  const std::string_view pair = trim_ascii(
      semi == std::string_view::npos ? header : header.substr(0, semi));
  return std::string(pair);
}

std::string aggregate_auth_cookie_from_response(const HttpResponse &response) {
  const std::vector<std::string> *cookie_headers =
      response.header_values_ci("set-cookie");
  if (!cookie_headers || cookie_headers->empty()) {
    return {};
  }

  for (const std::string &header : *cookie_headers) {
    const std::string pair = extract_set_cookie_pair(header);
    const std::size_t eq = pair.find('=');
    if (eq == std::string::npos) {
      continue;
    }

    const std::string name =
        lower_ascii_copy(trim_ascii(std::string_view(pair).substr(0, eq)));
    const std::string value =
        std::string(trim_ascii(std::string_view(pair).substr(eq + 1)));
    if (value.empty()) {
      continue;
    }

    if (name == "webvpn") {
      return "webvpn=" + value;
    }
    if (name == "webvpn_session") {
      return "webvpn=" + value;
    }
  }
  return {};
}

bool group_selection_requires_user_choice(
    const AggregateAuthResponse &response) {
  const AggregateAuthField *field = group_field(response);
  if (!field)
    return false;
  return field->value.empty() || field->options.size() > 1;
}

void append_json_string(std::string *out, std::string_view value) {
  if (!out)
    return;

  static constexpr char kHex[] = "0123456789abcdef";
  out->push_back('"');
  for (unsigned char ch : value) {
    switch (ch) {
    case '"':
      *out += "\\\"";
      break;
    case '\\':
      *out += "\\\\";
      break;
    case '\b':
      *out += "\\b";
      break;
    case '\f':
      *out += "\\f";
      break;
    case '\n':
      *out += "\\n";
      break;
    case '\r':
      *out += "\\r";
      break;
    case '\t':
      *out += "\\t";
      break;
    default:
      if (ch < 0x20) {
        *out += "\\u00";
        out->push_back(kHex[(ch >> 4) & 0x0f]);
        out->push_back(kHex[ch & 0x0f]);
      } else {
        out->push_back(static_cast<char>(ch));
      }
      break;
    }
  }
  out->push_back('"');
}

std::string group_options_json(const AggregateAuthField &field) {
  std::string out = "[";
  bool first = true;
  for (const AggregateAuthChoice &choice : field.options) {
    if (!first)
      out.push_back(',');
    first = false;
    out += "{\"value\":";
    append_json_string(&out, choice.value);
    out += ",\"label\":";
    append_json_string(&out, choice.label);
    out.push_back('}');
  }
  out.push_back(']');
  return out;
}

std::vector<std::string> group_option_values(
    const AggregateAuthResponse &response) {
  std::vector<std::string> values;
  const AggregateAuthField *field = group_field(response);
  if (!field)
    return values;

  values.reserve(field->options.size());
  for (const AggregateAuthChoice &choice : field->options) {
    if (!choice.value.empty())
      values.push_back(choice.value);
  }
  return values;
}

AuthResult aggregate_auth_error(const AggregateAuthResponse &response,
                                const std::string &fallback_code,
                                const std::string &fallback_message,
                                const std::string &password,
                                const std::string &encoded_password,
                                const std::string &cookie_header) {
  std::string code = response.error_code.empty() ? fallback_code
                                                 : response.error_code;
  std::string message = response.error_message.empty()
                            ? (response.message.empty() ? fallback_message
                                                        : response.message)
                            : response.error_message;
  return sanitized_auth_error(std::move(code), std::move(message), password,
                              encoded_password, cookie_header);
}

AuthResult challenge_auth_error(const AggregateAuthResponse &response,
                                const std::string &password,
                                const std::string &encoded_password,
                                const std::string &cookie_header) {
  AuthResult result =
      aggregate_auth_error(response, "auth_challenge_required",
                           "aggregate-auth challenge requires user input",
                           password, encoded_password, cookie_header);
  const AggregateAuthField *field = first_challenge_field(response);
  if (field) {
    result.interaction_prompt_label = field->label.empty()
                                          ? response.message
                                          : field->label;
    result.interaction_prompt_type =
        field->type.empty() ? std::string("password") : field->type;
  } else {
    result.interaction_prompt_label = response.message;
    result.interaction_prompt_type = "password";
  }
  return result;
}

AuthResult group_auth_error(const AggregateAuthResponse &response,
                            const std::string &password,
                            const std::string &encoded_password,
                            const std::string &cookie_header) {
  AuthResult result =
      aggregate_auth_error(response, "auth_group_required",
                           "aggregate-auth group selection requires user input",
                           password, encoded_password, cookie_header);
  const AggregateAuthField *field = group_field(response);
  if (field) {
    result.interaction_prompt_label =
        field->label.empty() ? std::string("VPN group") : field->label;
    result.interaction_prompt_type = "select";
    result.interaction_group_options = group_options_json(*field);
  } else {
    result.interaction_prompt_label = response.message;
    result.interaction_prompt_type = "select";
  }
  return result;
}

bool resolve_auth_interaction(const ProtocolSessionOptions &options,
                              std::string kind,
                              const AuthResult &interaction,
                              std::vector<std::string> request_options,
                              std::string *value) {
  if (!value || !options.auth_interaction_handler)
    return false;

  AuthInteractionRequest request;
  request.kind = kind;
  request.id = "auth-" + std::move(kind) + "-continuation";
  request.label = interaction.interaction_prompt_label;
  request.input_type = interaction.interaction_prompt_type;
  request.options = std::move(request_options);

  try {
    AuthInteractionResponse response = options.auth_interaction_handler(request);
    if (!response.ok || response.value.empty())
      return false;
    *value = std::move(response.value);
    return true;
  } catch (const std::exception &) {
    return false;
  } catch (...) {
    return false;
  }
}
// End inlined from vpn_engine/protocol/production_transport_requests include-unit
// Begin inlined from vpn_engine/protocol/production_transport_response_parse include-unit
bool find_header_terminator(const std::vector<std::uint8_t> &bytes,
                            std::size_t *header_end,
                            std::size_t *delimiter_size) {
  if (!header_end || !delimiter_size)
    return false;

  for (std::size_t i = 0; i + 3 < bytes.size(); ++i) {
    if (bytes[i] == '\r' && bytes[i + 1] == '\n' && bytes[i + 2] == '\r' &&
        bytes[i + 3] == '\n') {
      *header_end = i;
      *delimiter_size = 4;
      return true;
    }
  }

  for (std::size_t i = 0; i + 1 < bytes.size(); ++i) {
    if (bytes[i] == '\n' && bytes[i + 1] == '\n') {
      *header_end = i;
      *delimiter_size = 2;
      return true;
    }
  }

  return false;
}

ValidationResult parse_content_length(const HttpResponse &response,
                                      bool *present, std::size_t *out) {
  if (!present)
    return invalid("http_invalid", "content length presence output is null");
  if (!out)
    return invalid("http_invalid", "content length output is null");

  const std::string *value = response.header_ci("content-length");
  if (!value) {
    *present = false;
    *out = 0;
    return {};
  }

  *present = true;

  std::string_view s = trim_ascii(*value);
  if (s.empty())
    return invalid("http_invalid", "empty Content-Length header");

  std::size_t parsed = 0;
  for (unsigned char ch : s) {
    if (ch < '0' || ch > '9')
      return invalid("http_invalid", "invalid Content-Length header");
    const std::size_t digit = static_cast<std::size_t>(ch - '0');
    if (parsed >
        (std::numeric_limits<std::size_t>::max() - digit) /
            static_cast<std::size_t>(10)) {
      return invalid("http_invalid", "Content-Length header is too large");
    }
    parsed = parsed * 10 + digit;
  }

  *out = parsed;
  return {};
}

bool header_value_contains_token_ci(std::string_view value,
                                    std::string_view token) {
  const std::string lowered_token = lower_ascii_copy(token);
  while (true) {
    const std::size_t comma = value.find(',');
    const std::string_view part = trim_ascii(
        comma == std::string_view::npos ? value : value.substr(0, comma));
    if (lower_ascii_copy(part) == lowered_token) {
      return true;
    }
    if (comma == std::string_view::npos) {
      break;
    }
    value.remove_prefix(comma + 1);
  }
  return false;
}

bool response_header_contains_token_ci(const HttpResponse &response,
                                       const std::string &name,
                                       std::string_view token) {
  if (const std::vector<std::string> *values =
          response.header_values_ci(name);
      values) {
    for (const std::string &value : *values) {
      if (header_value_contains_token_ci(value, token)) {
        return true;
      }
    }
    return false;
  }
  if (const std::string *value = response.header_ci(name); value) {
    return header_value_contains_token_ci(*value, token);
  }
  return false;
}
// End inlined from vpn_engine/protocol/production_transport_response_parse include-unit

// Build a non-sensitive single-line summary of an HTTP response's framing for
// inclusion in an aggregate-auth protocol-mismatch error message. Only
// includes status, content-type, content-length, transfer-encoding and
// body_bytes — never cookies, set-cookie, server identifiers, opaque tokens
// or body content. Used when the gateway returns an empty body and the auth
// path needs to surface a diagnostic without leaking secret material. See
// docs/AGGREGATE_AUTH_EMPTY_RESPONSE_FIX_PLAN.md §3.
std::string body_diagnostics_summary(const HttpResponse &response) {
  std::string out;
  out += "status=";
  out += std::to_string(response.status);
  if (const std::string *ct = response.header_ci("content-type"); ct) {
    out += " content-type=";
    out += *ct;
  }
  if (const std::string *cl = response.header_ci("content-length"); cl) {
    out += " content-length=";
    out += *cl;
  }
  if (const std::string *te = response.header_ci("transfer-encoding"); te) {
    out += " transfer-encoding=";
    out += *te;
  }
  out += " body_bytes=";
  out += std::to_string(response.body.size());
  return out;
}
} // namespace
// Begin inlined from vpn_engine/protocol/production_transport_auth include-unit
ProductionProtocolTransport::ProductionProtocolTransport(
    TlsStream *stream, std::string client_hostname)
    : stream_(stream), client_hostname_(std::move(client_hostname)),
      dtls_backend_available_(false) {}

ProductionProtocolTransport::ProductionProtocolTransport(
    TlsStream *stream, DtlsChannelFactory dtls_channel_factory,
    std::string client_hostname)
    : stream_(stream), dtls_channel_factory_(std::move(dtls_channel_factory)),
      client_hostname_(std::move(client_hostname)),
      dtls_backend_available_(static_cast<bool>(dtls_channel_factory_)) {}

ProductionProtocolTransport::ProductionProtocolTransport(
    std::unique_ptr<TlsStream> stream, std::string client_hostname)
    : owned_stream_(std::move(stream)), stream_(owned_stream_.get()),
      client_hostname_(std::move(client_hostname)),
      dtls_backend_available_(false) {}

ProductionProtocolTransport::ProductionProtocolTransport(
    std::unique_ptr<TlsStream> stream, DtlsChannelFactory dtls_channel_factory,
    std::string client_hostname)
    : owned_stream_(std::move(stream)), stream_(owned_stream_.get()),
      dtls_channel_factory_(std::move(dtls_channel_factory)),
      client_hostname_(std::move(client_hostname)),
      dtls_backend_available_(static_cast<bool>(dtls_channel_factory_)) {}

AuthResult ProductionProtocolTransport::authenticate(
    const ProtocolSessionOptions &options) {
  server_ = options.server;
  useragent_ = options.useragent;
  requested_mtu_ = options.mtu_fallback;
  current_password_ = options.password;
  current_password_form_encoded_ = form_url_encode(options.password);
  dtls_mode_ = effective_dtls_mode(options);
  dtls_disabled_ = dtls_mode_ == DtlsMode::Disabled;
  auth_cookie_.clear();
  cookies_.clear();
  read_buffer_.clear();
  cstp_connected_ = false;
  dtls_data_channel_active_ = false;
  if (dtls_data_channel_) {
    dtls_data_channel_->close();
    dtls_data_channel_.reset();
  }

  if (!stream_) {
    return auth_error("transport_missing", "TLS stream is not configured");
  }

  if (!stream_connected_) {
    TlsEndpoint endpoint;
    endpoint.host = server_.host;
    endpoint.port = server_.port;
    endpoint.sni_host = server_.host;

    ValidationResult connected = stream_->connect(endpoint);
    if (!connected.ok) {
      return sanitized_auth_error(connected.code, connected.message,
                                  current_password_,
                                  current_password_form_encoded_,
                                  auth_cookie_);
    }
    stream_connected_ = true;
  }

  {
    AggregateAuthInitRequest init;
    init.server_url = aggregate_auth_server_url(server_);
    init.device_id = client_hostname_;
    init.version = useragent_or_default(useragent_);
    const std::string body = build_aggregate_auth_init_xml(init);
    ValidationResult written =
        stream_->write_all(
            to_bytes(make_aggregate_auth_post_request(server_, useragent_, body)));
    if (!written.ok) {
      ValidationResult sanitized =
          sanitized_result(written, current_password_,
                           current_password_form_encoded_, auth_cookie_);
      return auth_error(sanitized.code, sanitized.message);
    }
  }

  HttpResponse init_http;
  {
    ValidationResult read = read_http_response(false, &init_http);
    if (!read.ok) {
      ValidationResult sanitized =
          sanitized_result(read, current_password_,
                           current_password_form_encoded_, auth_cookie_);
      return auth_error(sanitized.code, sanitized.message);
    }
  }

  if (init_http.status < 200 || init_http.status >= 300) {
    return sanitized_auth_error("auth_protocol_error",
                                "aggregate-auth init returned HTTP status " +
                                    std::to_string(init_http.status),
                                current_password_,
                                current_password_form_encoded_, auth_cookie_);
  }

  // The XML parser would surface an empty body as "auth_response_invalid:
  // aggregate auth response is empty", which Fix #2 maps to
  // auth_protocol_mismatch. Short-circuit here so operators get a richer
  // (still-redacted) framing summary in the error message and so the
  // error_code is set up-front rather than via the keyword fallback.
  if (init_http.body.empty()) {
    return sanitized_auth_error(
        "auth_protocol_mismatch",
        "aggregate-auth init response had empty body — " +
            body_diagnostics_summary(init_http),
        current_password_,
        current_password_form_encoded_, auth_cookie_);
  }

  AggregateAuthResponse init_response;
  {
    ValidationResult parsed =
        parse_aggregate_auth_response(init_http.body, &init_response);
    if (!parsed.ok) {
      ValidationResult sanitized =
          sanitized_result(parsed, current_password_,
                           current_password_form_encoded_, auth_cookie_);
      return auth_error(sanitized.code, sanitized.message);
    }
  }

  if (init_response.type == AggregateAuthResponseType::error) {
    return aggregate_auth_error(init_response, "auth_rejected",
                                "aggregate-auth init rejected credentials",
                                current_password_,
                                current_password_form_encoded_, auth_cookie_);
  }
  std::string selected_group = options.auth_group;
  std::string challenge_value;
  std::string challenge_field_name;
  if (init_response.type == AggregateAuthResponseType::challenge) {
    AuthResult interaction =
        challenge_auth_error(init_response, current_password_,
                             current_password_form_encoded_, auth_cookie_);
    if (!resolve_auth_interaction(options, "challenge", interaction, {},
                                  &challenge_value)) {
      return interaction;
    }
    if (const AggregateAuthField *field = first_challenge_field(init_response))
      challenge_field_name = field->name;
  }
  if (init_response.type == AggregateAuthResponseType::group_select &&
      selected_group.empty() &&
      group_selection_requires_user_choice(init_response)) {
    AuthResult interaction =
        group_auth_error(init_response, current_password_,
                         current_password_form_encoded_, auth_cookie_);
    if (!resolve_auth_interaction(options, "group", interaction,
                                  group_option_values(init_response),
                                  &selected_group)) {
      return interaction;
    }
  } else if (selected_group.empty()) {
    selected_group = selected_group_from_response(init_response);
  }
  if (init_response.type == AggregateAuthResponseType::host_scan) {
    return sanitized_auth_error("csd_required_unsupported",
                                "AnyConnect host-scan is required",
                                current_password_,
                                current_password_form_encoded_, auth_cookie_);
  }
  if (init_response.type != AggregateAuthResponseType::auth_request &&
      init_response.type != AggregateAuthResponseType::group_select &&
      init_response.type != AggregateAuthResponseType::challenge) {
    return sanitized_auth_error("auth_protocol_error",
                                "aggregate-auth init did not request credentials",
                                current_password_,
                                current_password_form_encoded_, auth_cookie_);
  }

  {
    AggregateAuthReplyRequest reply;
    reply.username = options.username;
    reply.password = current_password_;
    reply.selected_group = selected_group;
    reply.challenge_value = challenge_value;
    reply.challenge_field_name = challenge_field_name;
    reply.device_id = client_hostname_;
    reply.version = useragent_or_default(useragent_);
    reply.opaque_xml = init_response.opaque_xml;
    const std::string body = build_aggregate_auth_reply_xml(reply);
    ValidationResult written =
        stream_->write_all(
            to_bytes(make_aggregate_auth_post_request(server_, useragent_, body)));
    if (!written.ok) {
      ValidationResult sanitized =
          sanitized_result(written, current_password_,
                           current_password_form_encoded_, auth_cookie_);
      return auth_error(sanitized.code, sanitized.message);
    }
  }

  HttpResponse submitted;
  {
    ValidationResult read =
        read_http_response(false, &submitted);
    if (!read.ok) {
      ValidationResult sanitized =
          sanitized_result(read, current_password_,
                           current_password_form_encoded_, auth_cookie_);
      return auth_error(sanitized.code, sanitized.message);
    }
  }

  if (submitted.status < 200 || submitted.status >= 300) {
    return sanitized_auth_error("auth_protocol_error",
                                "aggregate-auth reply returned HTTP status " +
                                    std::to_string(submitted.status),
                                current_password_,
                                current_password_form_encoded_, auth_cookie_);
  }

  if (submitted.body.empty()) {
    return sanitized_auth_error(
        "auth_protocol_mismatch",
        "aggregate-auth reply response had empty body — " +
            body_diagnostics_summary(submitted),
        current_password_,
        current_password_form_encoded_, auth_cookie_);
  }

  AggregateAuthResponse submitted_auth;
  std::string submitted_cookie;
  {
    ValidationResult parsed =
        parse_aggregate_auth_response(submitted.body, &submitted_auth);
    if (!parsed.ok) {
      ValidationResult sanitized =
          sanitized_result(parsed, current_password_,
                           current_password_form_encoded_, auth_cookie_);
      return auth_error(sanitized.code, sanitized.message);
    }
    submitted_cookie = aggregate_auth_cookie_from_response(submitted);
  }

  for (int followup = 0; followup < 3; ++followup) {
    if (submitted_auth.type == AggregateAuthResponseType::error) {
      return aggregate_auth_error(submitted_auth, "auth_rejected",
                                  "aggregate-auth rejected credentials",
                                  current_password_,
                                  current_password_form_encoded_, auth_cookie_);
    }
    if (submitted_auth.type == AggregateAuthResponseType::host_scan) {
      return sanitized_auth_error("csd_required_unsupported",
                                  "AnyConnect host-scan is required",
                                  current_password_,
                                  current_password_form_encoded_, auth_cookie_);
    }
    if (submitted_auth.type != AggregateAuthResponseType::challenge &&
        submitted_auth.type != AggregateAuthResponseType::group_select) {
      break;
    }

    AggregateAuthReplyRequest reply;
    reply.opaque_xml = submitted_auth.opaque_xml;
    reply.device_id = client_hostname_;
    reply.version = useragent_or_default(useragent_);
    if (submitted_auth.type == AggregateAuthResponseType::challenge) {
      AuthResult interaction =
          challenge_auth_error(submitted_auth, current_password_,
                               current_password_form_encoded_, auth_cookie_);
      if (!resolve_auth_interaction(options, "challenge", interaction, {},
                                    &reply.challenge_value)) {
        return interaction;
      }
      if (const AggregateAuthField *field =
              first_challenge_field(submitted_auth)) {
        reply.challenge_field_name = field->name;
      }
    } else {
      AuthResult interaction =
          group_auth_error(submitted_auth, current_password_,
                           current_password_form_encoded_, auth_cookie_);
      if (!resolve_auth_interaction(options, "group", interaction,
                                    group_option_values(submitted_auth),
                                    &reply.selected_group)) {
        return interaction;
      }
    }

    const std::string body = build_aggregate_auth_reply_xml(reply);
    ValidationResult written =
        stream_->write_all(
            to_bytes(make_aggregate_auth_post_request(server_, useragent_, body)));
    if (!written.ok) {
      ValidationResult sanitized =
          sanitized_result(written, current_password_,
                           current_password_form_encoded_, auth_cookie_);
      return auth_error(sanitized.code, sanitized.message);
    }

    HttpResponse followup_http;
    ValidationResult read = read_http_response(false, &followup_http);
    if (!read.ok) {
      ValidationResult sanitized =
          sanitized_result(read, current_password_,
                           current_password_form_encoded_, auth_cookie_);
      return auth_error(sanitized.code, sanitized.message);
    }
    if (followup_http.status < 200 || followup_http.status >= 300) {
      return sanitized_auth_error("auth_protocol_error",
                                  "aggregate-auth follow-up returned HTTP status " +
                                      std::to_string(followup_http.status),
                                  current_password_,
                                  current_password_form_encoded_, auth_cookie_);
    }

    if (followup_http.body.empty()) {
      return sanitized_auth_error(
          "auth_protocol_mismatch",
          "aggregate-auth follow-up response had empty body — " +
              body_diagnostics_summary(followup_http),
          current_password_,
          current_password_form_encoded_, auth_cookie_);
    }

    ValidationResult parsed =
        parse_aggregate_auth_response(followup_http.body, &submitted_auth);
    if (!parsed.ok) {
      ValidationResult sanitized =
          sanitized_result(parsed, current_password_,
                           current_password_form_encoded_, auth_cookie_);
      return auth_error(sanitized.code, sanitized.message);
    }
    submitted_cookie = aggregate_auth_cookie_from_response(followup_http);
  }

  if (submitted_auth.type == AggregateAuthResponseType::challenge) {
    return challenge_auth_error(submitted_auth, current_password_,
                                current_password_form_encoded_, auth_cookie_);
  }
  if (submitted_auth.type == AggregateAuthResponseType::group_select) {
    return group_auth_error(submitted_auth, current_password_,
                            current_password_form_encoded_, auth_cookie_);
  }

  const std::string token = !submitted_auth.session_token.empty()
                                ? submitted_auth.session_token
                                : submitted_auth.session_id;
  if (submitted_auth.type != AggregateAuthResponseType::success ||
      (token.empty() && submitted_cookie.empty())) {
    return sanitized_auth_error("protocol_error",
                                "missing session token in aggregate-auth response",
                                current_password_,
                                current_password_form_encoded_,
                                auth_cookie_);
  }

  auth_cookie_ = token.empty() ? submitted_cookie : "webvpn=" + token;
  AuthResult result;
  result.ok = true;
  result.cookie = auth_cookie_;
  return result;
}
// End inlined from vpn_engine/protocol/production_transport_auth include-unit
// Begin inlined from vpn_engine/protocol/production_transport_cstp include-unit
ValidationResult
ProductionProtocolTransport::connect_cstp(const std::string &cookie,
                                          TunnelMetadata *metadata) {
  if (!metadata)
    return invalid("cstp_null_metadata", "metadata output must not be null");
  if (!stream_)
    return invalid("transport_missing", "TLS stream is not configured");
  if (!stream_connected_)
    return invalid("transport_closed", "TLS stream is not connected");

  const std::string effective_cookie = cookie.empty() ? auth_cookie_ : cookie;
  if (effective_cookie.empty())
    return invalid("auth_cookie_missing", "CSTP connect requires auth cookie");

  DtlsOfferInput dtls_offer;
  std::vector<std::uint8_t> dtls12_exporter_psk;
  bool dtls12_exporter_ready = false;
  if (dtls_mode_ != DtlsMode::Disabled && dtls_backend_available_) {
    ValidationResult exporter =
        derive_dtls12_psk_from_tls_exporter(stream_, &dtls12_exporter_psk);
    dtls12_exporter_ready = exporter.ok && !dtls12_exporter_psk.empty();
  }
  dtls_offer.mode = dtls_mode_;
  dtls_offer.backend_available = dtls_backend_available_;
  dtls_offer.request_headers_allowed = dtls12_exporter_ready;
  if (dtls12_exporter_ready)
    dtls_offer.dtls12_cipher_suites = "TLS_PSK_WITH_AES_256_GCM_SHA384";

  ValidationResult written =
      stream_->write_all(to_bytes(make_cstp_connect_request(
          server_, useragent_, client_hostname_, effective_cookie,
          requested_mtu_, dtls_offer)));
  if (!written.ok) {
    return sanitized_result(written, current_password_,
                            current_password_form_encoded_, auth_cookie_,
                            effective_cookie);
  }

  HttpResponse response;
  ValidationResult read =
      read_http_response(true, &response);
  if (!read.ok) {
    cstp_connected_ = false;
    read_buffer_.clear();
    return sanitized_result(read, current_password_,
                            current_password_form_encoded_, auth_cookie_,
                            effective_cookie);
  }

  ValidationResult parsed = parse_cstp_headers(response, metadata);
  if (!parsed.ok) {
    cstp_connected_ = false;
    read_buffer_.clear();
    return sanitized_result(parsed, current_password_,
                            current_password_form_encoded_, auth_cookie_,
                            effective_cookie);
  }

  {
    const std::lock_guard<std::mutex> lock(data_channel_mutex_);
    dtls_data_channel_active_ = false;
    dtls_data_channel_.reset();
  }

  const DtlsMode policy_mode = dtls_mode_;
  const bool gateway_advertised_dtls = response_advertises_dtls(response);
  const DtlsCooldown cooldown =
      dtls_failures_.cooldown_for(dtls_network_key(server_));
  DtlsPolicyInput policy_input;
  policy_input.mode = policy_mode;
  policy_input.gateway_advertised = gateway_advertised_dtls;
  policy_input.backend_available = dtls_backend_available_;
  policy_input.cooldown_active = cooldown.active;

  const DtlsDecision decision = decide_dtls(policy_input);
  CstpTlsSelectionDataChannel cstp_channel;
  std::unique_ptr<DataChannel> dtls_candidate;
  if (decision.should_attempt) {
    std::unique_ptr<DtlsChannel> dtls_channel;
    if (dtls_channel_factory_)
      dtls_channel = dtls_channel_factory_(*metadata);
    dtls_candidate.reset(new DtlsSelectionDataChannel(
        std::move(dtls_channel),
        dtls_options_from_metadata(server_, *metadata, stream_,
                                   dtls12_exporter_psk)));
  } else {
    dtls_candidate.reset(
        new DtlsSelectionDataChannel(nullptr, DtlsChannelOptions{}));
  }

  DataChannelSelector selector;
  DataChannelSelection selected =
      selector.select(cstp_channel, *dtls_candidate, decision);
  const bool dtls_connected = selected.channel == dtls_candidate.get() &&
                              selected.active_channel == "dtls";
  std::shared_ptr<DataChannel> selected_dtls_channel;
  if (dtls_connected) {
    selected_dtls_channel =
        std::shared_ptr<DataChannel>(std::move(dtls_candidate));
  } else if (decision.should_attempt) {
    dtls_failures_.record_failure(dtls_network_key(server_),
                                  selected.fallback_reason);
  }
  {
    const std::lock_guard<std::mutex> lock(data_channel_mutex_);
    dtls_data_channel_active_ = dtls_connected;
    dtls_data_channel_ = std::move(selected_dtls_channel);
  }

  DtlsNegotiationInput dtls;
  dtls.disabled_by_config = policy_mode == DtlsMode::Disabled;
  dtls.gateway_advertised = gateway_advertised_dtls;
  dtls.backend_available = dtls_backend_available_;
  dtls.attempted = decision.should_attempt;
  dtls.handshake_succeeded = dtls_connected;
  dtls.tls_fallback_allowed = true;
  dtls.failure_reason = selected.fallback_reason;
  DtlsNegotiationStatus dtls_status = classify_dtls_negotiation(dtls);
  metadata->dtls_mode = dtls_mode_to_string(policy_mode);
  metadata->active_data_channel = dtls_connected ? "dtls" : "cstp_tls";
  metadata->dtls_state = dtls_transport_state_to_string(dtls_status.state);
  metadata->dtls_fallback_reason = selected.fallback_reason;
  metadata->dtls_fallback_count = decision.should_attempt && !dtls_connected
                                      ? 1
                                      : 0;

  cstp_connected_ = true;
  return {};
}

ValidationResult ProductionProtocolTransport::write_frame_locked(
    const std::vector<std::uint8_t> &wire) {
  const std::lock_guard<std::mutex> lock(write_mutex_);
  if (!stream_ || !stream_connected_ || !cstp_connected_)
    return invalid("transport_closed", "CSTP transport is not connected");

  ValidationResult written = stream_->write_all(wire);
  if (!written.ok) {
    return sanitized_result(written, current_password_,
                            current_password_form_encoded_, auth_cookie_);
  }
  return {};
}

ValidationResult ProductionProtocolTransport::send_packet(
    const std::vector<std::uint8_t> &packet) {
  std::shared_ptr<DataChannel> dtls_channel;
  {
    const std::lock_guard<std::mutex> lock(data_channel_mutex_);
    if (dtls_data_channel_active_)
      dtls_channel = dtls_data_channel_;
  }
  if (dtls_channel) {
    return dtls_channel->send_packet(packet);
  }

  CstpFrame outbound;
  outbound.type = CstpFrameType::data;
  outbound.payload = packet;

  std::vector<std::uint8_t> wire;
  ValidationResult encoded = encode_cstp_frame(outbound, &wire);
  if (!encoded.ok)
    return encoded;

  return write_frame_locked(wire);
}

ValidationResult
ProductionProtocolTransport::send_control(InboundFrameKind kind) {
  CstpFrame outbound;
  switch (kind) {
  case InboundFrameKind::dpd_request:
    outbound.type = CstpFrameType::dpd_request;
    break;
  case InboundFrameKind::dpd_response:
    outbound.type = CstpFrameType::dpd_response;
    break;
  case InboundFrameKind::keepalive:
    outbound.type = CstpFrameType::keepalive;
    break;
  case InboundFrameKind::disconnect:
    outbound.type = CstpFrameType::disconnect;
    break;
  case InboundFrameKind::data:
  case InboundFrameKind::none:
  case InboundFrameKind::compressed:
  case InboundFrameKind::terminate:
  default:
    return invalid("cstp_control_invalid",
                   "send_control requires a control frame kind");
  }

  std::vector<std::uint8_t> wire;
  ValidationResult encoded = encode_cstp_frame(outbound, &wire);
  if (!encoded.ok)
    return encoded;

  return write_frame_locked(wire);
}

ValidationResult
ProductionProtocolTransport::receive_frame(InboundFrame *out) {
  if (!out)
    return invalid("packet_null_out", "inbound frame output must not be null");
  out->kind = InboundFrameKind::none;
  out->payload.clear();

  if (!stream_ || !stream_connected_ || !cstp_connected_)
    return invalid("transport_closed", "CSTP transport is not connected");

  std::shared_ptr<DataChannel> dtls_channel;
  {
    const std::lock_guard<std::mutex> lock(data_channel_mutex_);
    if (dtls_data_channel_active_)
      dtls_channel = dtls_data_channel_;
  }

  if (dtls_channel) {
    while (true) {
      if (read_buffer_.empty()) {
        ValidationResult read = read_more();
        if (!read.ok) {
          if (tls_read_has_no_cstp_frame(read))
            break;
          return read;
        }
      }

      ByteReader reader(read_buffer_);
      CstpFrame inbound;
      ValidationResult decoded = decode_cstp_frame(&reader, &inbound);
      if (decoded.ok) {
        read_buffer_.erase(read_buffer_.begin(),
                           read_buffer_.begin() +
                               static_cast<std::ptrdiff_t>(reader.position()));
        assign_inbound_frame(inbound, out);
        return {};
      }
      if (decoded.code != "cstp_frame_incomplete") {
        return sanitized_result(decoded, current_password_,
                                current_password_form_encoded_, auth_cookie_);
      }
      ValidationResult read = read_more();
      if (!read.ok) {
        if (tls_read_has_no_cstp_frame(read))
          break;
        return read;
      }
    }

    ValidationResult received = dtls_channel->receive_packet(&out->payload);
    if (!received.ok)
      return received;
    out->kind = InboundFrameKind::data;
    return {};
  }

  while (true) {
    ByteReader reader(read_buffer_);
    CstpFrame inbound;
    ValidationResult decoded = decode_cstp_frame(&reader, &inbound);
    if (decoded.ok) {
      read_buffer_.erase(read_buffer_.begin(),
                         read_buffer_.begin() +
                             static_cast<std::ptrdiff_t>(reader.position()));

      assign_inbound_frame(inbound, out);
      return {};
    }

    if (decoded.code != "cstp_frame_incomplete") {
      return sanitized_result(decoded, current_password_,
                              current_password_form_encoded_, auth_cookie_);
    }

    ValidationResult read = read_more();
    if (!read.ok)
      return read;
  }
}

bool ProductionProtocolTransport::can_fallback_to_cstp() const {
  const std::lock_guard<std::mutex> lock(data_channel_mutex_);
  return dtls_data_channel_active_ && dtls_data_channel_;
}

void ProductionProtocolTransport::fallback_to_cstp(const std::string &reason,
                                                   const std::string &code) {
  dtls_failures_.record_failure(dtls_network_key(server_),
                                code.empty() ? reason : code);
  const std::lock_guard<std::mutex> lock(data_channel_mutex_);
  dtls_data_channel_active_ = false;
  dtls_data_channel_.reset();
}

void ProductionProtocolTransport::disconnect() {
  const std::lock_guard<std::mutex> lock(write_mutex_);
  if (stream_ && stream_connected_) {
    CstpFrame frame;
    frame.type = CstpFrameType::disconnect;

    std::vector<std::uint8_t> encoded;
    if (encode_cstp_frame(frame, &encoded).ok)
      (void)stream_->write_all(encoded);

    stream_->close();
  }

  {
    const std::lock_guard<std::mutex> data_lock(data_channel_mutex_);
    dtls_data_channel_active_ = false;
    dtls_data_channel_.reset();
  }

  stream_connected_ = false;
  cstp_connected_ = false;
  read_buffer_.clear();
  cookies_.clear();
  auth_cookie_.clear();
  current_password_.clear();
  current_password_form_encoded_.clear();
  dtls_failures_ = DtlsFailureHistory{};
}
// End inlined from vpn_engine/protocol/production_transport_cstp include-unit
// Begin inlined from vpn_engine/protocol/production_transport_read_http include-unit
void ProductionProtocolTransport::reset_for_reconnect() {
  const std::lock_guard<std::mutex> lock(write_mutex_);
  if (stream_ && stream_connected_)
    stream_->close();

  {
    const std::lock_guard<std::mutex> data_lock(data_channel_mutex_);
    dtls_data_channel_active_ = false;
    dtls_data_channel_.reset();
  }

  stream_connected_ = false;
  cstp_connected_ = false;
  read_buffer_.clear();
  cookies_.clear();
  auth_cookie_.clear();
  current_password_.clear();
  current_password_form_encoded_.clear();
}

ValidationResult ProductionProtocolTransport::read_more() {
  std::vector<std::uint8_t> chunk;
  ValidationResult read = stream_->read_some(&chunk);
  if (!read.ok) {
    return sanitized_result(read, current_password_,
                            current_password_form_encoded_, auth_cookie_);
  }
  if (chunk.empty())
    return invalid("transport_closed", "TLS stream closed during CSTP read");

  read_buffer_.insert(read_buffer_.end(), chunk.begin(), chunk.end());
  return {};
}

ValidationResult ProductionProtocolTransport::read_http_response(
    bool leave_body_in_buffer, HttpResponse *response) {
  if (!response)
    return invalid("http_invalid", "HTTP response output is null");

  std::size_t header_end = 0;
  std::size_t delimiter_size = 0;
  while (!find_header_terminator(read_buffer_, &header_end, &delimiter_size)) {
    if (read_buffer_.size() > kMaxHttpHeaderBytes) {
      return invalid("http_header_too_large",
                     "HTTP response header exceeds maximum size");
    }

    ValidationResult read = read_more();
    if (!read.ok)
      return read;
  }

  const std::size_t body_start = header_end + delimiter_size;
  if (body_start > kMaxHttpHeaderBytes) {
    return invalid("http_header_too_large",
                   "HTTP response header exceeds maximum size");
  }

  std::string header_only(read_buffer_.begin(),
                          read_buffer_.begin() +
                              static_cast<std::ptrdiff_t>(body_start));

  HttpResponse header_response;
  ValidationResult parsed_header =
      parse_http_response(header_only, &header_response);
  if (!parsed_header.ok)
    return parsed_header;

  if (leave_body_in_buffer) {
    *response = std::move(header_response);
    read_buffer_.erase(read_buffer_.begin(),
                       read_buffer_.begin() +
                           static_cast<std::ptrdiff_t>(body_start));
    return {};
  }

  // Transfer-Encoding wins over Content-Length per RFC 7230 §3.3.3. The
  // existing aggregate-auth gateway has been observed to return chunked
  // responses for some edge paths; treating those bytes as the body wholesale
  // would feed "1c\r\n<config-auth..." to the XML parser and surface as
  // "aggregate auth response is empty" once the chunk-size lines fail to
  // match. See docs/AGGREGATE_AUTH_EMPTY_RESPONSE_FIX_PLAN.md §3.
  const bool is_chunked = response_header_contains_token_ci(
      header_response, "transfer-encoding", "chunked");

  if (is_chunked) {
    // RFC 7230 §4.1 chunked decoding. Each chunk is "<hex-size>[;ext]\r\n",
    // followed by exactly <hex-size> bytes, followed by "\r\n". A zero-size
    // chunk plus a single trailing "\r\n" terminates the body. We accept an
    // empty trailer line and stop; spec-strict trailer header parsing is not
    // needed because the gateway never emits trailer fields.
    std::string decoded;
    std::size_t cursor = body_start;
    while (true) {
      // Read until we have a complete chunk-size line.
      std::size_t crlf_at = std::string::npos;
      while (crlf_at == std::string::npos) {
        for (std::size_t i = cursor; i + 1 < read_buffer_.size(); ++i) {
          if (read_buffer_[i] == '\r' && read_buffer_[i + 1] == '\n') {
            crlf_at = i;
            break;
          }
        }
        if (crlf_at != std::string::npos) break;
        // Cap the chunk-size line so a malformed gateway can not keep us
        // reading forever.
        if (read_buffer_.size() - cursor > 256) {
          return invalid("http_invalid",
                         "chunk size line exceeds 256 bytes");
        }
        ValidationResult r = read_more();
        if (!r.ok) return r;
      }

      // Parse "<hex>[;extension]" up to crlf_at. Strip ASCII whitespace.
      std::string size_line(read_buffer_.begin() +
                                static_cast<std::ptrdiff_t>(cursor),
                            read_buffer_.begin() +
                                static_cast<std::ptrdiff_t>(crlf_at));
      const std::size_t semi = size_line.find(';');
      if (semi != std::string::npos) size_line.resize(semi);
      while (!size_line.empty() &&
             (size_line.back() == ' ' || size_line.back() == '\t')) {
        size_line.pop_back();
      }
      while (!size_line.empty() &&
             (size_line.front() == ' ' || size_line.front() == '\t')) {
        size_line.erase(size_line.begin());
      }
      if (size_line.empty()) {
        return invalid("http_invalid", "empty chunk size line");
      }
      std::size_t chunk_size = 0;
      for (char c : size_line) {
        int digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') digit = 10 + (c - 'A');
        else {
          return invalid("http_invalid",
                         "non-hex digit in chunk size line");
        }
        if (chunk_size >
            (std::numeric_limits<std::size_t>::max() -
             static_cast<std::size_t>(digit)) / 16) {
          return invalid("http_chunk_too_large",
                         "chunk size overflows size_t");
        }
        chunk_size = chunk_size * 16 + static_cast<std::size_t>(digit);
      }
      cursor = crlf_at + 2;

      if (chunk_size == 0) {
        // Drain the complete trailer section. We ignore trailer fields, but
        // must consume them all so the next response starts at the next HTTP
        // status line.
        while (true) {
          if (cursor + 1 < read_buffer_.size() &&
              read_buffer_[cursor] == '\r' &&
              read_buffer_[cursor + 1] == '\n') {
            cursor += 2;
            break;
          }

          std::size_t line_end = std::string::npos;
          for (std::size_t i = cursor; i + 1 < read_buffer_.size(); ++i) {
            if (read_buffer_[i] == '\r' && read_buffer_[i + 1] == '\n') {
              line_end = i;
              break;
            }
          }
          if (line_end != std::string::npos) {
            cursor = line_end + 2;
            continue;
          }

          if (read_buffer_.size() - cursor > kMaxHttpHeaderBytes) {
            return invalid("http_header_too_large",
                           "trailer fields exceed maximum size");
          }
          ValidationResult r = read_more();
          if (!r.ok) {
            // Be permissive: some gateways close the connection after the
            // zero-chunk without sending a final CRLF. Treat that as the end
            // of the body, but only if no trailer bytes were seen.
            if (r.code == "transport_closed" && cursor == read_buffer_.size()) {
              break;
            }
            return r;
          }
        }
        break;
      }

      if (chunk_size > kMaxHttpBodyBytes - decoded.size()) {
        return invalid("http_body_too_large",
                       "decoded chunked body exceeds maximum size");
      }

      // Read exactly chunk_size bytes plus the trailing "\r\n".
      while (read_buffer_.size() < cursor + chunk_size + 2) {
        ValidationResult r = read_more();
        if (!r.ok) return r;
      }
      decoded.append(reinterpret_cast<const char *>(read_buffer_.data() +
                                                    cursor),
                     chunk_size);
      cursor += chunk_size;
      if (read_buffer_[cursor] != '\r' ||
          read_buffer_[cursor + 1] != '\n') {
        return invalid("http_invalid",
                       "missing CRLF terminator after chunk data");
      }
      cursor += 2;
    }

    header_response.body = std::move(decoded);
    *response = std::move(header_response);
    read_buffer_.erase(read_buffer_.begin(),
                       read_buffer_.begin() +
                           static_cast<std::ptrdiff_t>(cursor));
    return {};
  }

  std::size_t content_length = 0;
  bool has_content_length = false;
  ValidationResult length_result =
      parse_content_length(header_response, &has_content_length,
                           &content_length);
  if (!length_result.ok)
    return length_result;

  if (has_content_length) {
    if (content_length >
        std::numeric_limits<std::size_t>::max() - body_start) {
      return invalid("http_content_length_overflow",
                     "HTTP Content-Length overflows response buffer size");
    }
    if (content_length > kMaxHttpBodyBytes) {
      return invalid("http_body_too_large",
                     "HTTP response body exceeds maximum size");
    }

    const std::size_t target = body_start + content_length;
    while (read_buffer_.size() < target) {
      ValidationResult read = read_more();
      if (!read.ok)
        return read;
    }

    std::string raw(read_buffer_.begin(),
                    read_buffer_.begin() +
                        static_cast<std::ptrdiff_t>(target));
    ValidationResult parsed = parse_http_response(raw, response);
    if (!parsed.ok)
      return parsed;

    read_buffer_.erase(read_buffer_.begin(),
                       read_buffer_.begin() +
                           static_cast<std::ptrdiff_t>(target));
    return {};
  }

  const bool close_delimited_allowed =
      response_header_contains_token_ci(header_response, "connection", "close") ||
      header_only.rfind("HTTP/1.0 ", 0) == 0;
  if (!close_delimited_allowed) {
    return invalid("auth_protocol_mismatch",
                   "HTTP response has no body delimiter: missing "
                   "Content-Length, Transfer-Encoding: chunked, and "
                   "Connection: close");
  }

  // No Content-Length and not chunked -> "Connection: close" / HTTP/1.0
  // close-delimited framing per RFC 7230 §3.3.3 (#7). The body terminates
  // when the TLS stream EOFs. Previously we returned whatever bytes had
  // already arrived in the buffer and cleared it, which surfaced as an
  // empty body whenever the gateway hadn't delivered the full payload yet.
  while (true) {
    if (read_buffer_.size() - body_start > kMaxHttpBodyBytes) {
      return invalid("http_body_too_large",
                     "HTTP response body exceeds maximum size");
    }
    ValidationResult read = read_more();
    if (!read.ok) {
      if (read.code == "transport_closed") {
        // EOF — close-delimited body is complete.
        break;
      }
      return read;
    }
  }

  std::string raw(read_buffer_.begin(), read_buffer_.end());
  ValidationResult parsed = parse_http_response(raw, response);
  if (!parsed.ok)
    return parsed;

  read_buffer_.clear();
  return {};
}
// End inlined from vpn_engine/protocol/production_transport_read_http include-unit
} // namespace protocol
} // namespace vpn_engine
} // namespace exv

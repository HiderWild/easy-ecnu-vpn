#include "vpn_engine/protocol/cstp.hpp"

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace exv {
namespace vpn_engine {
namespace protocol {

namespace {

// CSTP data-channel record header ("STF"): the AnyConnect-compatible record
// framing places one 8-byte header before each payload. The payload length is
// a big-endian uint16, so the maximum payload per record is 65535 bytes.
//   [0]=0x53 'S' [1]=0x54 'T' [2]=0x46 'F' [3]=0x01
//   [4..5]=payload length (big-endian uint16)
//   [6]=packet type [7]=0x00
constexpr std::uint8_t kStfMagic0 = 0x53; // 'S'
constexpr std::uint8_t kStfMagic1 = 0x54; // 'T'
constexpr std::uint8_t kStfMagic2 = 0x46; // 'F'
constexpr std::uint8_t kStfVersion = 0x01;
constexpr std::size_t kStfHeaderBytes = 8;
constexpr std::uint32_t kMaxFramePayloadBytes = 0xFFFF; // big-endian uint16
constexpr std::size_t kMaxRouteCount = 256;
constexpr std::size_t kMaxHeaderValueBytes = 512;

// Public CSTP/AnyConnect data-channel packet type tags.
constexpr std::uint8_t kPktData = 0x00;
constexpr std::uint8_t kPktDpdRequest = 0x03;
constexpr std::uint8_t kPktDpdResponse = 0x04;
constexpr std::uint8_t kPktDisconnect = 0x05;
constexpr std::uint8_t kPktKeepalive = 0x07;
constexpr std::uint8_t kPktCompressed = 0x08;
constexpr std::uint8_t kPktTerminate = 0x09;

ValidationResult invalid(std::string code, std::string message) {
  ValidationResult r;
  r.ok = false;
  r.code = std::move(code);
  r.message = std::move(message);
  return r;
}

ValidationResult incomplete_frame() {
  return invalid("cstp_frame_incomplete", "insufficient bytes to decode a complete frame");
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

ValidationResult parse_u32_decimal(std::string_view s, std::uint32_t *out) {
  if (!out)
    return invalid("cstp_null_out", "output pointer is null");

  s = trim_ascii(s);
  if (s.empty())
    return invalid("cstp_invalid_number", "empty numeric value");

  std::uint64_t v = 0;
  for (unsigned char ch : s) {
    if (ch < '0' || ch > '9')
      return invalid("cstp_invalid_number", "numeric value contains non-digit");
    v = v * 10 + (ch - '0');
    if (v > std::numeric_limits<std::uint32_t>::max())
      return invalid("cstp_invalid_number", "numeric value out of range");
  }

  *out = static_cast<std::uint32_t>(v);
  return ValidationResult{};
}

ValidationResult validate_ipv4_dotted(std::string_view s) {
  s = trim_ascii(s);
  if (s.empty())
    return invalid("cstp_invalid_ipv4", "IPv4 value is empty");
  if (s.size() > 64)
    return invalid("cstp_invalid_ipv4", "IPv4 value is too long");

  int octets = 0;
  while (!s.empty()) {
    if (octets >= 4)
      return invalid("cstp_invalid_ipv4", "too many octets");

    std::size_t dot = s.find('.');
    std::string_view part = (dot == std::string_view::npos) ? s : s.substr(0, dot);
    s = (dot == std::string_view::npos) ? std::string_view() : s.substr(dot + 1);

    part = trim_ascii(part);
    if (part.empty() || part.size() > 3)
      return invalid("cstp_invalid_ipv4", "invalid octet");

    std::uint32_t value = 0;
    for (unsigned char ch : part) {
      if (ch < '0' || ch > '9')
        return invalid("cstp_invalid_ipv4", "octet contains non-digit");
      value = value * 10 + (ch - '0');
      if (value > 255)
        return invalid("cstp_invalid_ipv4", "octet out of range");
    }

    ++octets;
  }

  if (octets != 4)
    return invalid("cstp_invalid_ipv4", "IPv4 must have 4 octets");

  return ValidationResult{};
}

ValidationResult append_header_values(const HttpResponse &response,
                                     const char *header_name,
                                     std::vector<std::string> *out) {
  if (!out)
    return invalid("cstp_null_out", "output pointer is null");

  const auto *values = response.header_values_ci(header_name);
  if (!values)
    return ValidationResult{};

  for (const std::string &raw : *values) {
    std::string_view v = trim_ascii(raw);
    if (v.empty())
      continue;
    if (v.size() > kMaxHeaderValueBytes)
      return invalid("cstp_header_too_large", std::string(header_name) + " value too large");
    out->push_back(std::string(v));
    if (out->size() > kMaxRouteCount)
      return invalid("cstp_too_many_routes", "too many route headers");
  }

  return ValidationResult{};
}

std::string header_string(const HttpResponse &response,
                          const char *header_name) {
  const std::string *value = response.header_ci(header_name);
  if (!value)
    return {};
  std::string_view trimmed = trim_ascii(*value);
  if (trimmed.empty())
    return {};
  return std::string(trimmed);
}

ValidationResult parse_optional_int_header(const HttpResponse &response,
                                           const char *header_name,
                                           int *out) {
  if (!out)
    return invalid("cstp_null_out", "output pointer is null");
  const std::string value = header_string(response, header_name);
  if (value.empty())
    return ValidationResult{};

  std::uint32_t parsed = 0;
  ValidationResult result = parse_u32_decimal(value, &parsed);
  if (!result.ok) {
    return invalid("cstp_invalid_number",
                   std::string("invalid ") + header_name + " value");
  }
  if (parsed > static_cast<std::uint32_t>(std::numeric_limits<int>::max())) {
    return invalid("cstp_invalid_number",
                   std::string(header_name) + " value out of range");
  }
  *out = static_cast<int>(parsed);
  return ValidationResult{};
}

ValidationResult parse_optional_timeout_header(const HttpResponse &response,
                                               const char *header_name,
                                               int *out) {
  if (!out)
    return invalid("cstp_null_out", "output pointer is null");
  const std::string value = header_string(response, header_name);
  if (value.empty())
    return ValidationResult{};

  std::uint32_t parsed = 0;
  ValidationResult result = parse_u32_decimal(value, &parsed);
  if (!result.ok ||
      parsed > static_cast<std::uint32_t>(std::numeric_limits<int>::max())) {
    return ValidationResult{};
  }
  *out = static_cast<int>(parsed);
  return ValidationResult{};
}

std::string lower_ascii(std::string_view value) {
  std::string out;
  out.reserve(value.size());
  for (unsigned char ch : value)
    out.push_back(static_cast<char>(std::tolower(ch)));
  return out;
}

bool parse_bool_header(const HttpResponse &response, const char *header_name) {
  const std::string value = lower_ascii(header_string(response, header_name));
  return value == "1" || value == "true" || value == "yes";
}

int hex_value(unsigned char ch) {
  if (ch >= '0' && ch <= '9')
    return ch - '0';
  if (ch >= 'a' && ch <= 'f')
    return 10 + ch - 'a';
  if (ch >= 'A' && ch <= 'F')
    return 10 + ch - 'A';
  return -1;
}

ValidationResult parse_hex_bytes(std::string_view text,
                                 std::vector<std::uint8_t> *out,
                                 std::size_t expected_size) {
  if (!out)
    return invalid("cstp_null_out", "hex output pointer is null");

  text = trim_ascii(text);
  if (text.size() != expected_size * 2) {
    return invalid("cstp_invalid_dtls_master_secret",
                   "X-DTLS-Master-Secret has invalid length");
  }

  std::vector<std::uint8_t> parsed;
  parsed.reserve(expected_size);
  for (std::size_t i = 0; i < text.size(); i += 2) {
    const int hi = hex_value(static_cast<unsigned char>(text[i]));
    const int lo = hex_value(static_cast<unsigned char>(text[i + 1]));
    if (hi < 0 || lo < 0) {
      return invalid("cstp_invalid_dtls_master_secret",
                     "X-DTLS-Master-Secret contains non-hex bytes");
    }
    parsed.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }

  *out = std::move(parsed);
  return ValidationResult{};
}

std::string url_decode(std::string_view value) {
  std::string out;
  out.reserve(value.size());
  for (std::size_t i = 0; i < value.size(); ++i) {
    const unsigned char ch = static_cast<unsigned char>(value[i]);
    if (ch == '%' && i + 2 < value.size()) {
      const int hi = hex_value(static_cast<unsigned char>(value[i + 1]));
      const int lo = hex_value(static_cast<unsigned char>(value[i + 2]));
      if (hi >= 0 && lo >= 0) {
        out.push_back(static_cast<char>((hi << 4) | lo));
        i += 2;
        continue;
      }
    }
    if (ch == '+') {
      out.push_back(' ');
    } else {
      out.push_back(static_cast<char>(ch));
    }
  }
  return out;
}

std::uint32_t read_be_u32_raw(const std::uint8_t *p) {
  return (static_cast<std::uint32_t>(p[0]) << 24) |
         (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) |
         (static_cast<std::uint32_t>(p[3]) << 0);
}

} // namespace

ByteReader::ByteReader(const std::uint8_t *data, std::size_t size)
    : data_(data), size_(size), pos_(0) {}

ByteReader::ByteReader(const std::vector<std::uint8_t> &bytes)
    : ByteReader(bytes.data(), bytes.size()) {}

std::size_t ByteReader::position() const { return pos_; }

std::size_t ByteReader::remaining() const { return (pos_ <= size_) ? (size_ - pos_) : 0; }

const std::uint8_t *ByteReader::current_data() const {
  if (!data_ || pos_ > size_)
    return nullptr;
  return data_ + pos_;
}

void ByteReader::set_position(std::size_t pos) {
  pos_ = (pos <= size_) ? pos : size_;
}

bool ByteReader::can_read(std::size_t n) const { return remaining() >= n; }

ValidationResult ByteReader::read_u8(std::uint8_t *out) {
  if (!out)
    return invalid("cstp_null_out", "output pointer is null");
  if (!can_read(1))
    return incomplete_frame();
  *out = data_[pos_];
  ++pos_;
  return ValidationResult{};
}

ValidationResult ByteReader::read_be_u16(std::uint16_t *out) {
  if (!out)
    return invalid("cstp_null_out", "output pointer is null");
  if (!can_read(2))
    return incomplete_frame();
  *out = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data_[pos_]) << 8) |
                                    static_cast<std::uint16_t>(data_[pos_ + 1]));
  pos_ += 2;
  return ValidationResult{};
}

ValidationResult ByteReader::read_be_u32(std::uint32_t *out) {
  if (!out)
    return invalid("cstp_null_out", "output pointer is null");
  if (!can_read(4))
    return incomplete_frame();
  *out = read_be_u32_raw(&data_[pos_]);
  pos_ += 4;
  return ValidationResult{};
}

ValidationResult ByteReader::read_payload(std::size_t n, std::vector<std::uint8_t> *out) {
  if (!out)
    return invalid("cstp_null_out", "output pointer is null");
  if (!can_read(n))
    return incomplete_frame();
  out->assign(data_ + pos_, data_ + pos_ + n);
  pos_ += n;
  return ValidationResult{};
}

namespace {

void write_be_u16(std::uint16_t v, std::vector<std::uint8_t> *out) {
  out->push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
  out->push_back(static_cast<std::uint8_t>((v >> 0) & 0xff));
}

ValidationResult type_to_wire(CstpFrameType t, std::uint8_t *out) {
  if (!out)
    return invalid("cstp_null_out", "output pointer is null");

  // Public CSTP/AnyConnect data-channel packet type tags.
  switch (t) {
  case CstpFrameType::data:
    *out = kPktData;
    return ValidationResult{};
  case CstpFrameType::keepalive:
    *out = kPktKeepalive;
    return ValidationResult{};
  case CstpFrameType::dpd_request:
    *out = kPktDpdRequest;
    return ValidationResult{};
  case CstpFrameType::dpd_response:
    *out = kPktDpdResponse;
    return ValidationResult{};
  case CstpFrameType::disconnect:
    *out = kPktDisconnect;
    return ValidationResult{};
  case CstpFrameType::compressed:
    *out = kPktCompressed;
    return ValidationResult{};
  case CstpFrameType::terminate:
    *out = kPktTerminate;
    return ValidationResult{};
  }

  return invalid("cstp_unknown_type", "unknown frame type");
}

ValidationResult wire_to_type(std::uint8_t t, CstpFrameType *out) {
  if (!out)
    return invalid("cstp_null_out", "output pointer is null");

  // Public CSTP/AnyConnect data-channel packet type tags.
  switch (t) {
  case kPktData:
    *out = CstpFrameType::data;
    return ValidationResult{};
  case kPktKeepalive:
    *out = CstpFrameType::keepalive;
    return ValidationResult{};
  case kPktDpdRequest:
    *out = CstpFrameType::dpd_request;
    return ValidationResult{};
  case kPktDpdResponse:
    *out = CstpFrameType::dpd_response;
    return ValidationResult{};
  case kPktDisconnect:
    *out = CstpFrameType::disconnect;
    return ValidationResult{};
  case kPktCompressed:
    *out = CstpFrameType::compressed;
    return ValidationResult{};
  case kPktTerminate:
    *out = CstpFrameType::terminate;
    return ValidationResult{};
  default:
    return invalid("cstp_unknown_type", "unknown frame type tag");
  }
}

} // namespace

ValidationResult parse_cstp_headers(const HttpResponse &response,
                                   TunnelMetadata *metadata) {
  if (!metadata)
    return invalid("cstp_null_metadata", "metadata output must not be null");

  if (response.status == 401)
    return invalid("auth_expired", "CSTP CONNECT authentication expired");
  if (response.status < 200 || response.status > 299)
    return invalid("cstp_connect_failed", "CSTP CONNECT response status is not 2xx");

  const std::string *addr = response.header_ci("X-CSTP-Address");
  const std::string *mask = response.header_ci("X-CSTP-Netmask");
  const std::string *mtu = response.header_ci("X-CSTP-MTU");

  if (!addr || trim_ascii(*addr).empty())
    return invalid("cstp_missing_address", "missing X-CSTP-Address header");
  if (!mask || trim_ascii(*mask).empty())
    return invalid("cstp_missing_netmask", "missing X-CSTP-Netmask header");
  if (!mtu || trim_ascii(*mtu).empty())
    return invalid("cstp_missing_mtu", "missing X-CSTP-MTU header");

  {
    ValidationResult v = validate_ipv4_dotted(*addr);
    if (!v.ok)
      return v;
  }
  {
    ValidationResult v = validate_ipv4_dotted(*mask);
    if (!v.ok)
      return v;
  }

  std::uint32_t mtu_value = 0;
  {
    ValidationResult v = parse_u32_decimal(*mtu, &mtu_value);
    if (!v.ok)
      return invalid("cstp_invalid_mtu", "invalid X-CSTP-MTU value");
  }
  if (mtu_value < 576 || mtu_value > 1500)
    return invalid("cstp_invalid_mtu", "X-CSTP-MTU out of allowed range");

  metadata->internal_ip4_address = std::string(trim_ascii(*addr));
  metadata->internal_ip4_netmask = std::string(trim_ascii(*mask));
  metadata->mtu = static_cast<int>(mtu_value);

  metadata->ip6_address = header_string(response, "X-CSTP-Address-IP6");
  {
    ValidationResult v = parse_optional_int_header(
        response, "X-CSTP-Netmask-IP6", &metadata->ip6_prefix);
    if (!v.ok)
      return v;
  }
  metadata->default_domain =
      header_string(response, "X-CSTP-Default-Domain");
  metadata->tunnel_all_dns =
      parse_bool_header(response, "X-CSTP-Tunnel-All-DNS");
  metadata->banner = url_decode(header_string(response, "X-CSTP-Banner"));
  metadata->rekey_method = header_string(response, "X-CSTP-Rekey-Method");
  metadata->content_encoding =
      header_string(response, "X-CSTP-Content-Encoding");
  metadata->dtls_session_id = header_string(response, "X-DTLS-Session-ID");
  metadata->dtls_cipher_suite = header_string(response, "X-DTLS-CipherSuite");
  metadata->dtls12_cipher_suite =
      header_string(response, "X-DTLS12-CipherSuite");
  metadata->dtls_master_secret.clear();
  if (const std::string *master_secret =
          response.header_ci("X-DTLS-Master-Secret")) {
    ValidationResult v =
        parse_hex_bytes(*master_secret, &metadata->dtls_master_secret, 48);
    if (!v.ok)
      return v;
  }

  {
    ValidationResult v =
        parse_optional_int_header(response, "X-CSTP-Keepalive",
                                  &metadata->keepalive_seconds);
    if (!v.ok)
      return v;
  }
  {
    ValidationResult v =
        parse_optional_int_header(response, "X-CSTP-DPD",
                                  &metadata->dpd_seconds);
    if (!v.ok)
      return v;
  }
  {
    ValidationResult v =
        parse_optional_int_header(response, "X-CSTP-Rekey-Time",
                                  &metadata->rekey_seconds);
    if (!v.ok)
      return v;
  }
  {
    ValidationResult v = parse_optional_timeout_header(
        response, "X-CSTP-Lease-Duration",
        &metadata->lease_duration_seconds);
    if (!v.ok)
      return v;
  }
  {
    ValidationResult v = parse_optional_timeout_header(
        response, "X-CSTP-Idle-Timeout", &metadata->idle_timeout_seconds);
    if (!v.ok)
      return v;
  }
  {
    ValidationResult v = parse_optional_timeout_header(
        response, "X-CSTP-Session-Timeout",
        &metadata->session_timeout_seconds);
    if (!v.ok)
      return v;
  }
  {
    ValidationResult v = parse_optional_timeout_header(
        response, "X-CSTP-Disconnected-Timeout",
        &metadata->disconnected_timeout_seconds);
    if (!v.ok)
      return v;
  }
  {
    ValidationResult v =
        parse_optional_int_header(response, "X-DTLS-MTU",
                                  &metadata->dtls_mtu);
    if (!v.ok)
      return v;
  }
  {
    ValidationResult v =
        parse_optional_int_header(response, "X-DTLS-Port",
                                  &metadata->dtls_port);
    if (!v.ok)
      return v;
  }

  metadata->routes.clear();
  metadata->split_include_routes.clear();
  metadata->split_exclude_routes.clear();
  metadata->server_bypass_ips.clear();
  metadata->dns_servers.clear();
  metadata->nbns_servers.clear();
  metadata->search_domains.clear();

  {
    ValidationResult v = append_header_values(response, "X-CSTP-Split-Include",
                                             &metadata->split_include_routes);
    if (!v.ok)
      return v;
    metadata->routes = metadata->split_include_routes;
  }
  {
    ValidationResult v = append_header_values(response, "X-CSTP-Split-Exclude",
                                             &metadata->split_exclude_routes);
    if (!v.ok)
      return v;
  }
  {
    ValidationResult v = append_header_values(response, "X-CSTP-Bypass-Route",
                                             &metadata->server_bypass_ips);
    if (!v.ok)
      return v;
  }
  {
    ValidationResult v = append_header_values(response, "X-CSTP-DNS",
                                             &metadata->dns_servers);
    if (!v.ok)
      return v;
  }
  {
    ValidationResult v = append_header_values(response, "X-CSTP-NBNS",
                                             &metadata->nbns_servers);
    if (!v.ok)
      return v;
  }
  {
    ValidationResult v = append_header_values(response, "X-CSTP-Split-DNS",
                                             &metadata->search_domains);
    if (!v.ok)
      return v;
  }

  return ValidationResult{};
}

ValidationResult encode_cstp_frame(const CstpFrame &frame,
                                  std::vector<std::uint8_t> *out) {
  if (!out)
    return invalid("cstp_null_out", "output pointer is null");

  if (frame.payload.size() > kMaxFramePayloadBytes)
    return invalid("cstp_frame_oversized", "payload exceeds maximum size");

  std::uint8_t type_tag = 0;
  {
    ValidationResult v = type_to_wire(frame.type, &type_tag);
    if (!v.ok)
      return v;
  }

  std::vector<std::uint8_t> encoded;
  encoded.reserve(kStfHeaderBytes + frame.payload.size());
  encoded.push_back(kStfMagic0);
  encoded.push_back(kStfMagic1);
  encoded.push_back(kStfMagic2);
  encoded.push_back(kStfVersion);
  write_be_u16(static_cast<std::uint16_t>(frame.payload.size()), &encoded);
  encoded.push_back(type_tag);
  encoded.push_back(0x00);
  encoded.insert(encoded.end(), frame.payload.begin(), frame.payload.end());

  *out = std::move(encoded);
  return ValidationResult{};
}

ValidationResult decode_cstp_frame(ByteReader *reader, CstpFrame *out) {
  if (!reader)
    return invalid("cstp_null_reader", "reader must not be null");
  if (!out)
    return invalid("cstp_null_out", "output pointer is null");

  // Wire format (AnyConnect-compatible CSTP "STF" record header):
  // [0..2]='S''T''F' [3]=0x01 [4..5]=payload_len_be16 [6]=type [7]=0x00
  const std::size_t start_pos = reader->position();

  std::uint8_t magic0 = 0;
  std::uint8_t magic1 = 0;
  std::uint8_t magic2 = 0;
  std::uint8_t version = 0;
  if (!reader->can_read(kStfHeaderBytes)) {
    reader->set_position(start_pos);
    return incomplete_frame();
  }

  // Peek/validate the fixed header before consuming the payload.
  (void)reader->read_u8(&magic0);
  (void)reader->read_u8(&magic1);
  (void)reader->read_u8(&magic2);
  (void)reader->read_u8(&version);
  if (magic0 != kStfMagic0 || magic1 != kStfMagic1 || magic2 != kStfMagic2 ||
      version != kStfVersion) {
    reader->set_position(start_pos);
    return invalid("cstp_bad_magic", "CSTP record header magic mismatch");
  }

  std::uint16_t payload_len = 0;
  {
    ValidationResult v = reader->read_be_u16(&payload_len);
    if (!v.ok) {
      reader->set_position(start_pos);
      return v;
    }
  }

  std::uint8_t type_tag = 0;
  {
    ValidationResult v = reader->read_u8(&type_tag);
    if (!v.ok) {
      reader->set_position(start_pos);
      return v;
    }
  }

  std::uint8_t reserved = 0;
  (void)reader->read_u8(&reserved); // header byte [7]; ignored on decode

  CstpFrameType type;
  {
    ValidationResult v = wire_to_type(type_tag, &type);
    if (!v.ok) {
      reader->set_position(start_pos);
      return v;
    }
  }

  if (payload_len > kMaxFramePayloadBytes) {
    reader->set_position(start_pos);
    return invalid("cstp_frame_oversized", "frame payload exceeds maximum size");
  }

  CstpFrame decoded;
  decoded.type = type;

  {
    ValidationResult v = reader->read_payload(static_cast<std::size_t>(payload_len),
                                             &decoded.payload);
    if (!v.ok) {
      reader->set_position(start_pos);
      return v;
    }
  }

  *out = std::move(decoded);
  return ValidationResult{};
}

ValidationResult decode_cstp_frame(const std::vector<std::uint8_t> &bytes,
                                  CstpFrame *out) {
  if (!out)
    return invalid("cstp_null_out", "output pointer is null");

  ByteReader reader(bytes);
  ValidationResult v = decode_cstp_frame(&reader, out);
  if (!v.ok)
    return v;

  if (reader.remaining() != 0)
    return invalid("cstp_frame_length_mismatch", "trailing bytes after frame");

  return ValidationResult{};
}

} // namespace protocol
} // namespace vpn_engine
} // namespace exv

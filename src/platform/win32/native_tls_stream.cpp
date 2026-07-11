#include "platform/win32/native_tls_stream.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
#include <schannel.h>
#include <security.h>
#include <wincrypt.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <sstream>
#include <string>
#include <utility>

namespace exv {
namespace platform {

namespace {

constexpr int kConnectTimeoutMs = 15000;
constexpr std::size_t kEncryptedReadSize = 16 * 1024;
constexpr int kMaxHandshakeSteps = 64;
// Begin inlined from platform/win32/native_tls_stream_errors include-unit
vpn_engine::ValidationResult invalid(std::string code, std::string message) {
  vpn_engine::ValidationResult result;
  result.ok = false;
  result.code = std::move(code);
  result.message = std::move(message);
  return result;
}

vpn_engine::ValidationResult connect_failed(std::string message) {
  return invalid("tls_connect_failed", std::move(message));
}

vpn_engine::ValidationResult handshake_failed(std::string message) {
  return invalid("tls_handshake_failed", std::move(message));
}

std::string security_status_hex(SECURITY_STATUS status) {
  std::ostringstream out;
  out << "0x" << std::hex << static_cast<unsigned long>(status);
  return out.str();
}

std::string wsa_error_message(const char *operation, int error) {
  std::ostringstream out;
  out << operation << " failed with WSA error " << error;
  return out.str();
}

bool valid_socket_handle(NativeTlsSocketHandle socket) {
  return socket != kInvalidNativeTlsSocketHandle;
}

bool valid_context_handle(NativeTlsContextHandle context) {
  return context != kInvalidNativeTlsContextHandle;
}

SOCKET socket_from_handle(NativeTlsSocketHandle socket) {
  return static_cast<SOCKET>(socket);
}

NativeTlsSocketHandle handle_from_socket(SOCKET socket) {
  if (socket == INVALID_SOCKET)
    return kInvalidNativeTlsSocketHandle;
  return static_cast<NativeTlsSocketHandle>(socket);
}

std::wstring utf8_to_wide(const std::string &input) {
  if (input.empty())
    return {};

  int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                                  static_cast<int>(input.size()), nullptr, 0);
  if (chars <= 0) {
    chars = MultiByteToWideChar(CP_ACP, 0, input.data(),
                                static_cast<int>(input.size()), nullptr, 0);
  }
  if (chars <= 0)
    return {};

  std::wstring output(static_cast<std::size_t>(chars), L'\0');
  const UINT code_page = MultiByteToWideChar(
                             CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                             static_cast<int>(input.size()), nullptr, 0) > 0
                             ? CP_UTF8
                             : CP_ACP;
  const DWORD flags = code_page == CP_UTF8 ? MB_ERR_INVALID_CHARS : 0;
  MultiByteToWideChar(code_page, flags, input.data(),
                      static_cast<int>(input.size()), &output[0], chars);
  return output;
}
// End inlined from platform/win32/native_tls_stream_errors include-unit
// Begin inlined from platform/win32/native_tls_stream_socket include-unit
void append_bytes(std::vector<std::uint8_t> *target,
                  const std::vector<std::uint8_t> &source) {
  target->insert(target->end(), source.begin(), source.end());
}

vpn_engine::ValidationResult send_all_socket(SOCKET socket,
                                             const std::uint8_t *data,
                                             std::size_t size) {
  std::size_t sent = 0;
  while (sent < size) {
    const std::size_t remaining = size - sent;
    const int chunk = static_cast<int>(
        std::min<std::size_t>(remaining, static_cast<std::size_t>(
                                             std::numeric_limits<int>::max())));
    const int written =
        ::send(socket, reinterpret_cast<const char *>(data + sent), chunk, 0);
    if (written == SOCKET_ERROR) {
      return invalid("tls_write_failed",
                     wsa_error_message("send", WSAGetLastError()));
    }
    if (written == 0) {
      return invalid("transport_closed", "socket closed while sending TLS data");
    }
    sent += static_cast<std::size_t>(written);
  }

  return {};
}

bool wait_for_connect(SOCKET socket, int timeout_ms) {
  fd_set write_set;
  FD_ZERO(&write_set);
  FD_SET(socket, &write_set);

  fd_set error_set;
  FD_ZERO(&error_set);
  FD_SET(socket, &error_set);

  timeval timeout;
  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;

  const int selected =
      select(0, nullptr, &write_set, &error_set, &timeout);
  if (selected <= 0)
    return false;

  int socket_error = 0;
  int socket_error_size = sizeof(socket_error);
  if (getsockopt(socket, SOL_SOCKET, SO_ERROR,
                 reinterpret_cast<char *>(&socket_error),
                 &socket_error_size) == SOCKET_ERROR) {
    return false;
  }

  return socket_error == 0;
}

bool connect_socket_with_timeout(SOCKET socket, const sockaddr *address,
                                 int address_length, int timeout_ms) {
  u_long nonblocking = 1;
  if (ioctlsocket(socket, FIONBIO, &nonblocking) == SOCKET_ERROR)
    return false;

  const int connected = ::connect(socket, address, address_length);
  if (connected == 0) {
    u_long blocking = 0;
    ioctlsocket(socket, FIONBIO, &blocking);
    return true;
  }

  const int error = WSAGetLastError();
  if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS &&
      error != WSAEINVAL) {
    return false;
  }

  if (!wait_for_connect(socket, timeout_ms))
    return false;

  u_long blocking = 0;
  if (ioctlsocket(socket, FIONBIO, &blocking) == SOCKET_ERROR)
    return false;

  return true;
}

void configure_socket_timeouts(SOCKET socket) {
  DWORD timeout = static_cast<DWORD>(kConnectTimeoutMs);
  setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
             reinterpret_cast<const char *>(&timeout), sizeof(timeout));
  setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO,
             reinterpret_cast<const char *>(&timeout), sizeof(timeout));
}
// End inlined from platform/win32/native_tls_stream_socket include-unit
// Begin inlined from platform/win32/native_tls_stream_context include-unit
struct AddrInfoDeleter {
  void operator()(addrinfo *info) const {
    if (info)
      freeaddrinfo(info);
  }
};

struct SchannelTlsContext {
  CredHandle credentials{};
  CtxtHandle context{};
  SecPkgContext_StreamSizes sizes{};
  bool has_credentials = false;
  bool has_context = false;
};

void destroy_schannel_context(SchannelTlsContext *context) {
  if (!context)
    return;

  if (context->has_context)
    DeleteSecurityContext(&context->context);
  if (context->has_credentials)
    FreeCredentialsHandle(&context->credentials);

  delete context;
}

using SchannelContextPtr =
    std::unique_ptr<SchannelTlsContext, decltype(&destroy_schannel_context)>;

SchannelTlsContext *context_from_handle(NativeTlsContextHandle handle) {
  return reinterpret_cast<SchannelTlsContext *>(handle);
}

NativeTlsContextHandle handle_from_context(SchannelTlsContext *context) {
  if (!context)
    return kInvalidNativeTlsContextHandle;
  return reinterpret_cast<NativeTlsContextHandle>(context);
}

void keep_handshake_extra(std::vector<std::uint8_t> *incoming,
                          const SecBuffer &extra_buffer) {
  if (extra_buffer.BufferType != SECBUFFER_EXTRA ||
      extra_buffer.cbBuffer == 0 ||
      extra_buffer.cbBuffer > incoming->size()) {
    incoming->clear();
    return;
  }

  const std::size_t extra_size =
      static_cast<std::size_t>(extra_buffer.cbBuffer);
  std::vector<std::uint8_t> extra(incoming->end() - extra_size,
                                  incoming->end());
  *incoming = std::move(extra);
}

bool receive_handshake_bytes(SOCKET socket,
                             std::vector<std::uint8_t> *incoming,
                             vpn_engine::ValidationResult *failure) {
  std::vector<std::uint8_t> buffer(kEncryptedReadSize);
  const int received =
      recv(socket, reinterpret_cast<char *>(buffer.data()),
           static_cast<int>(buffer.size()), 0);
  if (received == 0) {
    *failure = handshake_failed("TLS peer closed during handshake");
    return false;
  }
  if (received == SOCKET_ERROR) {
    *failure =
        handshake_failed(wsa_error_message("recv", WSAGetLastError()));
    return false;
  }

  incoming->insert(incoming->end(), buffer.begin(),
                   buffer.begin() + received);
  return true;
}

vpn_engine::ValidationResult
verify_server_certificate(SchannelTlsContext *context,
                          const std::string &sni_host) {
  PCCERT_CONTEXT certificate = nullptr;
  SECURITY_STATUS status = QueryContextAttributesA(
      &context->context, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &certificate);
  if (status != SEC_E_OK || !certificate) {
    return invalid("tls_verify_failed",
                   "failed to read server certificate from Schannel context");
  }

  PCCERT_CHAIN_CONTEXT chain = nullptr;
  CERT_CHAIN_PARA chain_parameters{};
  chain_parameters.cbSize = sizeof(chain_parameters);

  const BOOL chain_ok =
      CertGetCertificateChain(nullptr, certificate, nullptr,
                              certificate->hCertStore, &chain_parameters, 0,
                              nullptr, &chain);
  if (!chain_ok || !chain) {
    CertFreeCertificateContext(certificate);
    return invalid("tls_verify_failed",
                   "failed to build server certificate chain");
  }

  std::wstring wide_sni = utf8_to_wide(sni_host);
  SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl_policy{};
  ssl_policy.cbSize = sizeof(ssl_policy);
  ssl_policy.dwAuthType = AUTHTYPE_SERVER;
  ssl_policy.fdwChecks = 0;
  ssl_policy.pwszServerName =
      wide_sni.empty() ? nullptr : const_cast<wchar_t *>(wide_sni.c_str());

  CERT_CHAIN_POLICY_PARA policy_parameters{};
  policy_parameters.cbSize = sizeof(policy_parameters);
  policy_parameters.pvExtraPolicyPara = &ssl_policy;

  CERT_CHAIN_POLICY_STATUS policy_status{};
  policy_status.cbSize = sizeof(policy_status);

  const BOOL policy_ok = CertVerifyCertificateChainPolicy(
      CERT_CHAIN_POLICY_SSL, chain, &policy_parameters, &policy_status);
  const DWORD policy_error = policy_status.dwError;

  CertFreeCertificateChain(chain);
  CertFreeCertificateContext(certificate);

  if (!policy_ok || policy_error != ERROR_SUCCESS) {
    std::ostringstream message;
    message << "server certificate verification failed with Windows error "
            << policy_error;
    return invalid("tls_verify_failed", message.str());
  }

  return {};
}
// End inlined from platform/win32/native_tls_stream_context include-unit
// Begin inlined from platform/win32/native_tls_stream_api include-unit
class WindowsNativeTlsApi final : public NativeTlsApi {
public:
  vpn_engine::ValidationResult startup() override {
    WSADATA data;
    const int started = WSAStartup(MAKEWORD(2, 2), &data);
    if (started != 0)
      return connect_failed(wsa_error_message("WSAStartup", started));
    return {};
  }

  NativeTlsTcpConnectResult connect_tcp(
      const vpn_engine::protocol::TlsEndpoint &endpoint) override {
    NativeTlsTcpConnectResult result;

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo *raw_addresses = nullptr;
    const std::string port = std::to_string(endpoint.port);
    const int resolved =
        getaddrinfo(endpoint.host.c_str(), port.c_str(), &hints,
                    &raw_addresses);
    std::unique_ptr<addrinfo, AddrInfoDeleter> addresses(raw_addresses);
    if (resolved != 0) {
      result.result =
          connect_failed("DNS resolution failed for " + endpoint.host);
      return result;
    }

    for (addrinfo *address = addresses.get(); address;
         address = address->ai_next) {
      SOCKET socket =
          ::socket(address->ai_family, address->ai_socktype,
                   address->ai_protocol);
      if (socket == INVALID_SOCKET)
        continue;

      if (connect_socket_with_timeout(
              socket, address->ai_addr,
              static_cast<int>(address->ai_addrlen), kConnectTimeoutMs)) {
        configure_socket_timeouts(socket);
        result.socket = handle_from_socket(socket);
        return result;
      }

      closesocket(socket);
    }

    result.result =
        connect_failed("TCP connect failed or timed out for " + endpoint.host);
    return result;
  }

  NativeTlsHandshakeResult handshake(NativeTlsSocketHandle socket_handle,
                                     const std::string &sni_host) override {
    NativeTlsHandshakeResult result;
    SOCKET socket = socket_from_handle(socket_handle);

    SchannelContextPtr context(new SchannelTlsContext(),
                               destroy_schannel_context);

    SCHANNEL_CRED credentials{};
    credentials.dwVersion = SCHANNEL_CRED_VERSION;
    credentials.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION |
                          SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;

    TimeStamp expiry{};
    SECURITY_STATUS status = AcquireCredentialsHandleA(
        nullptr, const_cast<SEC_CHAR *>(UNISP_NAME_A), SECPKG_CRED_OUTBOUND,
        nullptr, &credentials, nullptr, nullptr, &context->credentials,
        &expiry);
    if (status != SEC_E_OK) {
      result.result = handshake_failed(
          "AcquireCredentialsHandle failed with " + security_status_hex(status));
      return result;
    }
    context->has_credentials = true;

    std::vector<std::uint8_t> incoming;
    const unsigned long request_flags =
        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY |
        ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM |
        ISC_REQ_EXTENDED_ERROR | ISC_REQ_MANUAL_CRED_VALIDATION;

    for (int step = 0; step < kMaxHandshakeSteps; ++step) {
      SecBuffer output_buffer{};
      output_buffer.BufferType = SECBUFFER_TOKEN;

      SecBufferDesc output_desc{};
      output_desc.ulVersion = SECBUFFER_VERSION;
      output_desc.cBuffers = 1;
      output_desc.pBuffers = &output_buffer;

      SecBuffer input_buffers[2]{};
      SecBufferDesc input_desc{};
      SecBufferDesc *input_desc_ptr = nullptr;

      if (!incoming.empty()) {
        input_buffers[0].BufferType = SECBUFFER_TOKEN;
        input_buffers[0].pvBuffer = incoming.data();
        input_buffers[0].cbBuffer =
            static_cast<unsigned long>(incoming.size());
        input_buffers[1].BufferType = SECBUFFER_EMPTY;

        input_desc.ulVersion = SECBUFFER_VERSION;
        input_desc.cBuffers = 2;
        input_desc.pBuffers = input_buffers;
        input_desc_ptr = &input_desc;
      }

      unsigned long attributes = 0;
      status = InitializeSecurityContextA(
          &context->credentials,
          context->has_context ? &context->context : nullptr,
          const_cast<SEC_CHAR *>(sni_host.c_str()), request_flags, 0,
          SECURITY_NATIVE_DREP, input_desc_ptr, 0, &context->context,
          &output_desc, &attributes, &expiry);

      if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED)
        context->has_context = true;

      const bool have_output = output_buffer.pvBuffer &&
                               output_buffer.cbBuffer > 0;
      if (have_output) {
        vpn_engine::ValidationResult sent = send_all_socket(
            socket, static_cast<const std::uint8_t *>(output_buffer.pvBuffer),
            static_cast<std::size_t>(output_buffer.cbBuffer));
        FreeContextBuffer(output_buffer.pvBuffer);
        if (!sent.ok) {
          result.result = sent;
          return result;
        }
      } else if (output_buffer.pvBuffer) {
        FreeContextBuffer(output_buffer.pvBuffer);
      }

      if (status == SEC_E_OK) {
        if (input_desc_ptr &&
            input_buffers[1].BufferType == SECBUFFER_EXTRA &&
            input_buffers[1].cbBuffer <= incoming.size()) {
          const std::size_t extra_size =
              static_cast<std::size_t>(input_buffers[1].cbBuffer);
          result.encrypted_extra.assign(incoming.end() - extra_size,
                                        incoming.end());
        }

        status = QueryContextAttributesA(
            &context->context, SECPKG_ATTR_STREAM_SIZES, &context->sizes);
        if (status != SEC_E_OK) {
          result.result = handshake_failed(
              "QueryContextAttributes(stream sizes) failed with " +
              security_status_hex(status));
          return result;
        }

        vpn_engine::ValidationResult verified =
            verify_server_certificate(context.get(), sni_host);
        result.tls_context = handle_from_context(context.get());
        if (!verified.ok) {
          result.result = verified;
          context.release();
          return result;
        }

        context.release();
        return result;
      }

      if (status == SEC_E_INCOMPLETE_MESSAGE) {
        vpn_engine::ValidationResult failure;
        if (!receive_handshake_bytes(socket, &incoming, &failure)) {
          result.result = failure;
          return result;
        }
        continue;
      }

      if (status == SEC_I_CONTINUE_NEEDED) {
        if (input_desc_ptr)
          keep_handshake_extra(&incoming, input_buffers[1]);

        if (incoming.empty()) {
          vpn_engine::ValidationResult failure;
          if (!receive_handshake_bytes(socket, &incoming, &failure)) {
            result.result = failure;
            return result;
          }
        }
        continue;
      }

      result.result = handshake_failed(
          "InitializeSecurityContext failed with " +
          security_status_hex(status));
      return result;
    }

    result.result = handshake_failed("TLS handshake exceeded step limit");
    return result;
  }

  vpn_engine::ValidationResult send_plaintext(
      NativeTlsContextHandle tls_context, NativeTlsSocketHandle socket_handle,
      const std::vector<std::uint8_t> &bytes) override {
    if (bytes.empty())
      return {};

    SchannelTlsContext *context = context_from_handle(tls_context);
    if (!context || !context->has_context)
      return invalid("tls_stream_not_connected", "TLS context is not connected");

    SOCKET socket = socket_from_handle(socket_handle);
    const std::size_t max_message = std::max<std::size_t>(
        1, static_cast<std::size_t>(context->sizes.cbMaximumMessage));
    std::size_t offset = 0;

    while (offset < bytes.size()) {
      const std::size_t chunk_size =
          std::min(max_message, bytes.size() - offset);
      std::vector<std::uint8_t> packet(
          static_cast<std::size_t>(context->sizes.cbHeader) + chunk_size +
          static_cast<std::size_t>(context->sizes.cbTrailer));

      std::memcpy(packet.data() + context->sizes.cbHeader,
                  bytes.data() + offset, chunk_size);

      SecBuffer buffers[4]{};
      buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
      buffers[0].pvBuffer = packet.data();
      buffers[0].cbBuffer = context->sizes.cbHeader;
      buffers[1].BufferType = SECBUFFER_DATA;
      buffers[1].pvBuffer = packet.data() + context->sizes.cbHeader;
      buffers[1].cbBuffer = static_cast<unsigned long>(chunk_size);
      buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
      buffers[2].pvBuffer =
          packet.data() + context->sizes.cbHeader + chunk_size;
      buffers[2].cbBuffer = context->sizes.cbTrailer;
      buffers[3].BufferType = SECBUFFER_EMPTY;

      SecBufferDesc desc{};
      desc.ulVersion = SECBUFFER_VERSION;
      desc.cBuffers = 4;
      desc.pBuffers = buffers;

      SECURITY_STATUS status = EncryptMessage(&context->context, 0, &desc, 0);
      if (status != SEC_E_OK) {
        return invalid("tls_write_failed",
                       "EncryptMessage failed with " +
                           security_status_hex(status));
      }

      const std::size_t encrypted_size =
          static_cast<std::size_t>(buffers[0].cbBuffer) +
          static_cast<std::size_t>(buffers[1].cbBuffer) +
          static_cast<std::size_t>(buffers[2].cbBuffer);
      vpn_engine::ValidationResult sent =
          send_all_socket(socket, packet.data(), encrypted_size);
      if (!sent.ok)
        return sent;

      offset += chunk_size;
    }

    return {};
  }

  NativeTlsRecvResult
  recv_encrypted(NativeTlsSocketHandle socket_handle) override {
    NativeTlsRecvResult result;
    std::vector<std::uint8_t> buffer(kEncryptedReadSize);
    const int received =
        recv(socket_from_handle(socket_handle),
             reinterpret_cast<char *>(buffer.data()),
             static_cast<int>(buffer.size()), 0);
    if (received == 0) {
      result.peer_closed = true;
      return result;
    }
    if (received == SOCKET_ERROR) {
      const int native_error = WSAGetLastError();
      const char *code =
          native_error == WSAETIMEDOUT ? "tls_read_timeout" : "tls_read_failed";
      result.result = invalid(code, wsa_error_message("recv", native_error));
      return result;
    }

    result.bytes.assign(buffer.begin(), buffer.begin() + received);
    return result;
  }

  NativeTlsDecryptResult decrypt(
      NativeTlsContextHandle tls_context,
      const std::vector<std::uint8_t> &encrypted) override {
    NativeTlsDecryptResult result;
    SchannelTlsContext *context = context_from_handle(tls_context);
    if (!context || !context->has_context) {
      result.result =
          invalid("tls_stream_not_connected", "TLS context is not connected");
      return result;
    }

    if (encrypted.empty()) {
      result.status = NativeTlsReadStatus::need_more_data;
      return result;
    }

    std::vector<std::uint8_t> buffer = encrypted;
    SecBuffer buffers[4]{};
    buffers[0].BufferType = SECBUFFER_DATA;
    buffers[0].pvBuffer = buffer.data();
    buffers[0].cbBuffer = static_cast<unsigned long>(buffer.size());
    buffers[1].BufferType = SECBUFFER_EMPTY;
    buffers[2].BufferType = SECBUFFER_EMPTY;
    buffers[3].BufferType = SECBUFFER_EMPTY;

    SecBufferDesc desc{};
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = 4;
    desc.pBuffers = buffers;

    unsigned long qop = 0;
    SECURITY_STATUS status =
        DecryptMessage(&context->context, &desc, 0, &qop);
    if (status == SEC_E_INCOMPLETE_MESSAGE) {
      result.status = NativeTlsReadStatus::need_more_data;
      return result;
    }
    if (status == SEC_I_CONTEXT_EXPIRED) {
      result.status = NativeTlsReadStatus::peer_closed;
      return result;
    }
    if (status != SEC_E_OK) {
      result.status = NativeTlsReadStatus::tls_alert;
      result.result =
          invalid("tls_alert",
                  "DecryptMessage failed with " + security_status_hex(status));
      return result;
    }

    std::size_t extra_size = 0;
    for (SecBuffer &sec_buffer : buffers) {
      if (sec_buffer.BufferType == SECBUFFER_DATA && sec_buffer.pvBuffer &&
          sec_buffer.cbBuffer > 0) {
        const auto *data =
            static_cast<const std::uint8_t *>(sec_buffer.pvBuffer);
        result.plaintext.assign(data, data + sec_buffer.cbBuffer);
      } else if (sec_buffer.BufferType == SECBUFFER_EXTRA) {
        extra_size = static_cast<std::size_t>(sec_buffer.cbBuffer);
      }
    }

    if (extra_size > encrypted.size()) {
      result.result = invalid("tls_decrypt_failed",
                              "Schannel returned invalid extra byte count");
      return result;
    }

    result.encrypted_bytes_consumed = encrypted.size() - extra_size;
    result.status = NativeTlsReadStatus::data;
    return result;
  }

  void close_tls_context(NativeTlsContextHandle tls_context) override {
    destroy_schannel_context(context_from_handle(tls_context));
  }

  void close_socket(NativeTlsSocketHandle socket) override {
    if (valid_socket_handle(socket))
      closesocket(socket_from_handle(socket));
  }

  void shutdown() override { WSACleanup(); }
};
// End inlined from platform/win32/native_tls_stream_api include-unit
} // namespace
// Begin inlined from platform/win32/native_tls_stream_public include-unit
std::unique_ptr<NativeTlsApi> make_windows_native_tls_api() {
  return std::unique_ptr<NativeTlsApi>(new WindowsNativeTlsApi());
}

NativeTlsStream::NativeTlsStream()
    : NativeTlsStream(make_windows_native_tls_api()) {}

NativeTlsStream::NativeTlsStream(std::unique_ptr<NativeTlsApi> api)
    : api_(std::move(api)) {}

NativeTlsStream::~NativeTlsStream() { close(); }

vpn_engine::ValidationResult NativeTlsStream::connect(
    const vpn_engine::protocol::TlsEndpoint &endpoint) {
  close();
  closed_ = false;

  if (!api_)
    return invalid("tls_api_missing", "native TLS API is not configured");

  const std::string verification_host =
      endpoint.sni_host.empty() ? endpoint.host : endpoint.sni_host;
  if (verification_host.empty()) {
    return invalid("tls_endpoint_invalid",
                   "TLS endpoint host or SNI host must be configured");
  }

  vpn_engine::ValidationResult started = api_->startup();
  if (!started.ok)
    return started;
  api_started_ = true;

  NativeTlsTcpConnectResult tcp = api_->connect_tcp(endpoint);
  if (valid_socket_handle(tcp.socket))
    socket_ = tcp.socket;
  if (!tcp.result.ok)
    return fail_connect_and_reset(tcp.result);
  if (!valid_socket_handle(socket_)) {
    return fail_connect_and_reset(
        connect_failed("TCP connect did not return a socket"));
  }

  NativeTlsHandshakeResult tls = api_->handshake(socket_, verification_host);
  if (valid_context_handle(tls.tls_context))
    tls_context_ = tls.tls_context;
  if (!tls.result.ok)
    return fail_connect_and_reset(tls.result);
  if (!valid_context_handle(tls_context_)) {
    return fail_connect_and_reset(
        handshake_failed("TLS handshake did not return a security context"));
  }

  encrypted_buffer_ = std::move(tls.encrypted_extra);
  connected_ = true;
  closed_ = false;
  return {};
}

vpn_engine::ValidationResult
NativeTlsStream::write_all(const std::vector<std::uint8_t> &bytes) {
  vpn_engine::ValidationResult open = ensure_open();
  if (!open.ok)
    return open;
  if (bytes.empty())
    return {};

  vpn_engine::ValidationResult written =
      api_->send_plaintext(tls_context_, socket_, bytes);
  if (!written.ok)
    return fail_and_close(written);

  return {};
}

vpn_engine::ValidationResult
NativeTlsStream::read_some(std::vector<std::uint8_t> *bytes) {
  if (!bytes)
    return invalid("tls_stream_null_output", "read output must not be null");

  {
    std::lock_guard<std::mutex> lock(io_mutex_);
    vpn_engine::ValidationResult open = ensure_open();
    if (!open.ok)
      return open;
  }

  bytes->clear();

  // Full-duplex hardening: the decrypt path and the buffer mutate under
  // io_mutex_ so close() (driven from the outbound thread) can never destroy
  // the Schannel context while this reader thread is mid-DecryptMessage. The
  // blocking recv() runs OUTSIDE the lock; close() interrupts it by closing the
  // socket, after which the reader re-checks closed_ under the lock and bails
  // before touching the torn-down context.
  enum class Step { return_ok, loop, do_recv, peer_closed, fail };

  while (true) {
    Step step = Step::do_recv;
    vpn_engine::ValidationResult fail_result;
    NativeTlsSocketHandle recv_socket = kInvalidNativeTlsSocketHandle;

    {
      std::lock_guard<std::mutex> lock(io_mutex_);
      if (closed_.load())
        return invalid("tls_stream_closed", "TLS stream is closed");

      if (encrypted_buffer_.empty()) {
        step = Step::do_recv;
        recv_socket = socket_;
      } else {
        NativeTlsDecryptResult decrypted =
            api_->decrypt(tls_context_, encrypted_buffer_);
        if (!decrypted.result.ok) {
          step = Step::fail;
          fail_result = decrypted.result;
        } else if (decrypted.encrypted_bytes_consumed >
                   encrypted_buffer_.size()) {
          step = Step::fail;
          fail_result = invalid(
              "tls_decrypt_failed",
              "TLS decrypt consumed more encrypted bytes than available");
        } else {
          const std::size_t consumed = decrypted.encrypted_bytes_consumed;
          if (consumed > 0) {
            encrypted_buffer_.erase(encrypted_buffer_.begin(),
                                    encrypted_buffer_.begin() + consumed);
          }

          switch (decrypted.status) {
          case NativeTlsReadStatus::data:
            if (!decrypted.plaintext.empty()) {
              if (consumed == 0) {
                step = Step::fail;
                fail_result = invalid(
                    "tls_decrypt_failed",
                    "TLS decrypt returned plaintext without consuming input");
              } else {
                *bytes = std::move(decrypted.plaintext);
                step = Step::return_ok;
              }
            } else if (consumed == 0) {
              step = Step::fail;
              fail_result =
                  invalid("tls_decrypt_failed", "TLS decrypt made no progress");
            } else {
              step = Step::loop;
            }
            break;

          case NativeTlsReadStatus::need_more_data:
            step = Step::do_recv;
            recv_socket = socket_;
            break;

          case NativeTlsReadStatus::peer_closed:
            step = Step::peer_closed;
            break;

          case NativeTlsReadStatus::tls_alert:
            step = Step::fail;
            fail_result = invalid("tls_alert", "TLS alert received");
            break;
          }
        }
      }
    }

    switch (step) {
    case Step::return_ok:
      return {};
    case Step::loop:
      continue;
    case Step::peer_closed:
      close();
      return {};
    case Step::fail:
      return fail_and_close(fail_result);
    case Step::do_recv:
      break;
    }

    // Blocking recv must stay outside io_mutex_ so close() can interrupt it.
    NativeTlsRecvResult received = api_->recv_encrypted(recv_socket);
    if (!received.result.ok)
      return fail_and_close(received.result);
    if (received.peer_closed) {
      close();
      return {};
    }
    if (received.bytes.empty())
      return fail_and_close(
          invalid("tls_read_failed", "socket read returned no data"));

    {
      std::lock_guard<std::mutex> lock(io_mutex_);
      if (closed_.load())
        return invalid("tls_stream_closed", "TLS stream is closed");
      append_bytes(&encrypted_buffer_, received.bytes);
    }
  }
}

void NativeTlsStream::close() {
  NativeTlsContextHandle tls_context;
  NativeTlsSocketHandle socket;
  bool api_started;

  {
    std::lock_guard<std::mutex> lock(io_mutex_);
    tls_context = tls_context_;
    socket = socket_;
    api_started = api_started_;

    tls_context_ = kInvalidNativeTlsContextHandle;
    socket_ = kInvalidNativeTlsSocketHandle;
    encrypted_buffer_.clear();
    connected_ = false;
    closed_.store(true);
    api_started_ = false;
  }

  if (!api_)
    return;

  // Destroyed after releasing io_mutex_: any concurrent reader either holds the
  // lock during DecryptMessage (so this teardown waited for it) or re-checks
  // closed_ under the lock before reusing the context. Closing the socket
  // unblocks an in-flight recv() on the reader thread.
  if (valid_context_handle(tls_context))
    api_->close_tls_context(tls_context);
  if (valid_socket_handle(socket))
    api_->close_socket(socket);
  if (api_started)
    api_->shutdown();
}

vpn_engine::ValidationResult NativeTlsStream::ensure_open() const {
  if (closed_)
    return invalid("tls_stream_closed", "TLS stream is closed");
  if (!connected_)
    return invalid("tls_stream_not_connected", "TLS stream is not connected");
  return {};
}

vpn_engine::ValidationResult
NativeTlsStream::fail_and_close(vpn_engine::ValidationResult result) {
  close();
  return result;
}

vpn_engine::ValidationResult
NativeTlsStream::fail_connect_and_reset(vpn_engine::ValidationResult result) {
  close();
  closed_ = false;
  return result;
}
// End inlined from platform/win32/native_tls_stream_public include-unit
} // namespace platform
} // namespace exv

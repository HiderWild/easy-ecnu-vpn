#include "vpn_engine/protocol/dtls_channel.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <mutex>
#include <utility>

#include <openssl/err.h>
#include <openssl/ssl.h>

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

ValidationResult datagram_failure(const DatagramResult &result,
                                  const std::string &fallback_code) {
  return invalid(result.code.empty() ? fallback_code : result.code,
                 result.message.empty() ? fallback_code : result.message);
}

std::string openssl_error_message(const char *operation) {
  std::string message = operation;
  message += " failed";
  const unsigned long err = ERR_get_error();
  if (err != 0) {
    std::array<char, 256> buffer{};
    ERR_error_string_n(err, buffer.data(), buffer.size());
    message += ": ";
    message += buffer.data();
  }
  return message;
}

int psk_ex_data_index() {
  static const int index =
      SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  return index;
}

unsigned int psk_client_callback(SSL *ssl, const char * /*hint*/,
                                 char *identity,
                                 unsigned int max_identity_len,
                                 unsigned char *psk,
                                 unsigned int max_psk_len) {
  const int index = psk_ex_data_index();
  if (index < 0)
    return 0;
  auto *options =
      static_cast<DtlsChannelOptions *>(SSL_get_ex_data(ssl, index));
  if (!options || options->psk.empty())
    return 0;

  const std::string identity_text =
      options->session_id.empty() ? "exv" : options->session_id;
  if (identity_text.size() + 1 > max_identity_len ||
      options->psk.size() > max_psk_len) {
    return 0;
  }

  std::memcpy(identity, identity_text.c_str(), identity_text.size() + 1);
  std::copy(options->psk.begin(), options->psk.end(), psk);
  return static_cast<unsigned int>(options->psk.size());
}

class OpenSslDtlsChannel final : public DtlsChannel {
public:
  explicit OpenSslDtlsChannel(std::unique_ptr<DatagramSocket> socket)
      : socket_(std::move(socket)) {}

  ~OpenSslDtlsChannel() override { close(); }

  ValidationResult connect(const DtlsChannelOptions &options) override {
    const std::lock_guard<std::mutex> lock(io_mutex_);
    if (!socket_) {
      return invalid("dtls_socket_missing",
                     "DTLS channel requires a datagram socket");
    }
    if (options.endpoint.host.empty() || options.endpoint.port <= 0) {
      return invalid("dtls_endpoint_invalid",
                     "DTLS endpoint host and port are required");
    }
    if (options.psk.empty()) {
      return invalid("dtls_psk_missing",
                     "DTLS PSK is required before opening the DTLS channel");
    }

    close_openssl();
    options_ = options;

    DatagramResult udp_connected = socket_->connect(options.endpoint);
    if (!udp_connected.ok)
      return datagram_failure(udp_connected, "dtls_socket_connect_failed");

    ctx_ = SSL_CTX_new(DTLS_method());
    if (!ctx_)
      return invalid("dtls_openssl_init_failed",
                     openssl_error_message("SSL_CTX_new"));
    SSL_CTX_set_psk_client_callback(ctx_, psk_client_callback);
    (void)SSL_CTX_set_min_proto_version(ctx_, DTLS1_2_VERSION);

    ssl_ = SSL_new(ctx_);
    if (!ssl_)
      return invalid("dtls_openssl_init_failed", openssl_error_message("SSL_new"));

    const int index = psk_ex_data_index();
    if (index < 0 || SSL_set_ex_data(ssl_, index, &options_) != 1) {
      return invalid("dtls_openssl_init_failed",
                     "failed to bind DTLS PSK options");
    }

    BIO *ssl_bio = nullptr;
    BIO *network_bio = nullptr;
    if (BIO_new_bio_pair(&ssl_bio, 0, &network_bio, 0) != 1) {
      return invalid("dtls_openssl_init_failed",
                     openssl_error_message("BIO_new_bio_pair"));
    }
    network_bio_ = network_bio;
    SSL_set_bio(ssl_, ssl_bio, ssl_bio);
    SSL_set_connect_state(ssl_);
    if (options_.mtu > 0)
      SSL_set_mtu(ssl_, static_cast<unsigned int>(options_.mtu));

    for (int attempt = 0; attempt < 8; ++attempt) {
      const int ret = SSL_connect(ssl_);
      ValidationResult flushed = flush_network_bio();
      if (!flushed.ok)
        return flushed;

      if (ret == 1) {
        connected_ = true;
        return {};
      }

      const int error = SSL_get_error(ssl_, ret);
      if (error == SSL_ERROR_WANT_WRITE)
        continue;
      if (error == SSL_ERROR_WANT_READ) {
        ValidationResult read = receive_network_datagram_locked();
        if (!read.ok)
          return read;
        continue;
      }
      return invalid("dtls_handshake_failed",
                     openssl_error_message("SSL_connect"));
    }

    return invalid("dtls_handshake_failed",
                   "DTLS handshake did not complete before retry budget");
  }

  ValidationResult
  send_packet(const std::vector<std::uint8_t> &packet) override {
    const std::lock_guard<std::mutex> lock(io_mutex_);
    if (!connected_ || !ssl_)
      return invalid("dtls_not_connected", "DTLS channel is not connected");
    if (packet.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
      return invalid("dtls_packet_too_large", "DTLS packet is too large");

    const int written = SSL_write(ssl_, packet.data(), static_cast<int>(packet.size()));
    if (written <= 0) {
      return invalid("dtls_write_failed",
                     openssl_error_message("SSL_write"));
    }
    return flush_network_bio();
  }

  ValidationResult receive_packet(std::vector<std::uint8_t> *packet) override {
    if (!packet)
      return invalid("packet_null_out", "DTLS packet output must not be null");
    packet->clear();

    std::unique_lock<std::mutex> lock(io_mutex_);
    if (!connected_ || !ssl_)
      return invalid("dtls_not_connected", "DTLS channel is not connected");

    std::array<unsigned char, 65536> buffer{};
    for (int attempt = 0; attempt < 4; ++attempt) {
      const int read =
          SSL_read(ssl_, buffer.data(), static_cast<int>(buffer.size()));
      if (read > 0) {
        packet->assign(buffer.begin(), buffer.begin() + read);
        return {};
      }

      const int error = SSL_get_error(ssl_, read);
      if (error == SSL_ERROR_WANT_WRITE) {
        ValidationResult flushed = flush_network_bio();
        if (!flushed.ok)
          return flushed;
        continue;
      }
      if (error == SSL_ERROR_WANT_READ) {
        DatagramSocket *socket = socket_.get();
        lock.unlock();
        std::vector<std::uint8_t> datagram;
        ValidationResult received =
            receive_socket_datagram(socket, &datagram);
        lock.lock();
        if (!received.ok)
          return received;
        if (!connected_ || !ssl_ || !network_bio_)
          return invalid("dtls_not_connected", "DTLS channel is not connected");
        ValidationResult fed = feed_network_datagram(datagram);
        if (!fed.ok)
          return fed;
        continue;
      }
      return invalid("dtls_read_failed", openssl_error_message("SSL_read"));
    }
    return invalid("dtls_read_timeout", "DTLS packet was not available");
  }

  void close() override {
    const std::lock_guard<std::mutex> lock(io_mutex_);
    close_openssl();
    if (socket_)
      socket_->close();
  }

private:
  ValidationResult flush_network_bio() {
    if (!network_bio_)
      return {};

    std::array<char, 2048> buffer{};
    while (BIO_pending(network_bio_) > 0) {
      const int read =
          BIO_read(network_bio_, buffer.data(), static_cast<int>(buffer.size()));
      if (read <= 0)
        return invalid("dtls_bio_read_failed", "failed to read DTLS BIO output");

      std::vector<std::uint8_t> datagram(buffer.begin(), buffer.begin() + read);
      DatagramResult sent = socket_->send(datagram);
      if (!sent.ok)
        return datagram_failure(sent, "dtls_socket_send_failed");
    }
    return {};
  }

  ValidationResult receive_network_datagram_locked() {
    std::vector<std::uint8_t> datagram;
    ValidationResult received =
        receive_socket_datagram(socket_.get(), &datagram);
    if (!received.ok)
      return received;
    return feed_network_datagram(datagram);
  }

  ValidationResult receive_socket_datagram(
      DatagramSocket *socket, std::vector<std::uint8_t> *datagram) {
    if (!socket)
      return invalid("dtls_socket_missing", "DTLS socket is not available");
    DatagramResult received = socket->receive(datagram);
    if (!received.ok) {
      return invalid(received.code.empty() ? "dtls_socket_receive_failed"
                                           : received.code,
                     received.message.empty() ? "DTLS socket receive failed"
                                              : received.message);
    }
    if (datagram->empty())
      return invalid("dtls_socket_receive_empty", "DTLS socket received no data");
    return {};
  }

  ValidationResult feed_network_datagram(
      const std::vector<std::uint8_t> &datagram) {
    const int written =
        BIO_write(network_bio_, datagram.data(), static_cast<int>(datagram.size()));
    if (written <= 0 ||
        written != static_cast<int>(datagram.size())) {
      return invalid("dtls_bio_write_failed", "failed to feed DTLS BIO input");
    }
    return {};
  }

  void close_openssl() {
    connected_ = false;
    if (ssl_) {
      SSL_free(ssl_);
      ssl_ = nullptr;
    }
    if (network_bio_) {
      BIO_free(network_bio_);
      network_bio_ = nullptr;
    }
    if (ctx_) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }

  std::unique_ptr<DatagramSocket> socket_;
  SSL_CTX *ctx_ = nullptr;
  SSL *ssl_ = nullptr;
  BIO *network_bio_ = nullptr;
  DtlsChannelOptions options_;
  bool connected_ = false;
  std::mutex io_mutex_;
};

} // namespace

bool dtls_backend_compiled() { return true; }

std::unique_ptr<DtlsChannel>
make_openssl_dtls_channel(std::unique_ptr<DatagramSocket> socket) {
  if (!socket)
    return nullptr;
  return std::unique_ptr<DtlsChannel>(new OpenSslDtlsChannel(std::move(socket)));
}

} // namespace protocol
} // namespace vpn_engine
} // namespace exv

#include "vpn_engine/protocol/dtls_channel.hpp"

namespace exv {
namespace vpn_engine {
namespace protocol {

bool dtls_backend_compiled() { return false; }

std::unique_ptr<DtlsChannel>
make_openssl_dtls_channel(std::unique_ptr<DatagramSocket> socket) {
  (void)socket;
  return nullptr;
}

} // namespace protocol
} // namespace vpn_engine
} // namespace exv

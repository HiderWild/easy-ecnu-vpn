#include "vpn_engine/native_engine.hpp"
#include "vpn_engine/protocol/production_transport.hpp"
#include "platform/win32/native_datagram_socket.hpp"
#include "platform/win32/native_packet_device.hpp"
#include "platform/win32/native_tls_stream.hpp"

#include <memory>

namespace exv {
namespace vpn_engine {

NativeVpnEngineDependencies default_native_engine_dependencies() {
  NativeVpnEngineDependencies deps;

  deps.transport_factory = [] {
    std::unique_ptr<protocol::TlsStream> stream(new platform::NativeTlsStream());
    protocol::ProductionProtocolTransport::DtlsChannelFactory dtls_factory;
    if (protocol::dtls_backend_compiled()) {
      dtls_factory = [](const TunnelMetadata &) {
        return protocol::make_openssl_dtls_channel(
            std::unique_ptr<protocol::DatagramSocket>(
                new platform::NativeDatagramSocket()));
      };
    }
    return std::unique_ptr<protocol::ProtocolTransport>(
        new protocol::ProductionProtocolTransport(std::move(stream),
                                                  std::move(dtls_factory)));
  };
  deps.packet_device_factory = [] {
    return platform::create_native_packet_device();
  };

  return deps;
}

} // namespace vpn_engine
} // namespace exv

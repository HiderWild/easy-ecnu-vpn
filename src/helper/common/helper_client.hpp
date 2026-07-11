#pragma once
#include <memory>
#include <functional>
#include "helper_messages.hpp"
#include "helper_error.hpp"

namespace exv::helper {

class HelperClient {
public:
    virtual ~HelperClient() = default;

    // Connection management
    virtual bool connect() = 0;
    virtual void disconnect() = 0;
    virtual bool is_connected() const = 0;

    // Helper protocol
    virtual HelloResponse hello(const HelloRequest& req) = 0;
    virtual StartSessionResponse start_session(const StartSessionRequest& req) = 0;
    virtual PrepareTunnelDeviceResponse prepare_tunnel_device(const PrepareTunnelDeviceRequest& req) = 0;
    virtual ApplyTunnelConfigResponse apply_tunnel_config(const ApplyTunnelConfigRequest& req) = 0;
    virtual HeartbeatResponse heartbeat(const HeartbeatRequest& req) = 0;
    virtual CleanupResponse cleanup(const CleanupRequest& req) = 0;
    virtual GetSnapshotResponse get_snapshot(const GetSnapshotRequest& req) = 0;
    virtual ShutdownResponse shutdown(const ShutdownRequest& req) = 0;
    virtual InspectResponse inspect(const InspectRequest& req) {
        (void)req;
        return {};
    }
    virtual AcquireCoreLeaseResponse acquire_core_lease(const AcquireCoreLeaseRequest& req) {
        (void)req;
        return {};
    }
    virtual KeepAliveResponse keep_alive(const KeepAliveRequest& req) {
        (void)req;
        KeepAliveResponse resp;
        resp.ok = false;
        return resp;
    }
    virtual ReleaseCoreLeaseResponse release_core_lease(const ReleaseCoreLeaseRequest& req) {
        (void)req;
        return {};
    }

    // Callback for helper disconnection
    using DisconnectCallback = std::function<void()>;
    virtual void set_disconnect_callback(DisconnectCallback cb) = 0;
};

} // namespace exv::helper

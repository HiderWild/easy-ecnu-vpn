#pragma once
#include "app_rpc_dispatcher.hpp"
#include "core/tunnel_controller/vpn_connect_job.hpp"
#include <nlohmann/json.hpp>
#include <memory>
#include <functional>
#include <stop_token>

namespace exv::core {

// Forward declarations
class TunnelController;
struct UserIntent;

} // namespace exv::core

namespace exv::core_api {

class VpnActions {
public:
    using ConnectJobRunner =
        std::function<void(std::stop_token, std::uint64_t)>;

    explicit VpnActions(std::shared_ptr<exv::core::TunnelController> controller);
    VpnActions(std::shared_ptr<exv::core::TunnelController> controller,
               ConnectJobRunner connect_job_runner);

    // Register all vpn.* handlers with dispatcher
    void register_handlers(AppRpcDispatcher& dispatcher);

    // Individual actions
    RpcResponse connect(const RpcRequest& req);
    RpcResponse disconnect(const RpcRequest& req);
    RpcResponse status(const RpcRequest& req);
    RpcResponse set_auto_reconnect(const RpcRequest& req);
    RpcResponse get_legacy_status(const RpcRequest& req);

private:
    nlohmann::json connect_state_json(const exv::core::VpnConnectJobState& state) const;
    exv::core::VpnConnectJobOwner& connect_jobs();
    exv::core::VpnConnectJobState current_connect_job() const;
    std::shared_ptr<exv::core::TunnelController> controller_for_status() const;
    std::shared_ptr<exv::core::TunnelController> controller_for_mutation() const;

    std::shared_ptr<exv::core::TunnelController> controller_;
    ConnectJobRunner connect_job_runner_;
    exv::core::VpnConnectJobOwner connect_jobs_;
};

} // namespace exv::core_api

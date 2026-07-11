#include "core/tunnel_controller/tunnel_controller_test_access.hpp"

#include "core/tunnel_controller/tunnel_controller_impl.hpp"

#include <utility>

namespace exv::core {

std::unique_ptr<TunnelController> TunnelControllerTestAccess::create(
    std::shared_ptr<exv::helper::HelperClient> helper,
    std::shared_ptr<exv::platform::PlatformNetworkOps> net_ops,
    ReconnectConfig reconnect_config,
    CoreSessionRunner::NativeDependenciesFactory deps_factory) {
  auto controller =
      std::make_unique<TunnelController>(helper, net_ops, reconnect_config);

  controller->impl_ =
      std::make_unique<TunnelController::Impl>(std::move(deps_factory));
  controller->impl_->helper_ = std::move(helper);
  controller->impl_->net_ops_ = std::move(net_ops);
  controller->impl_->reconnect_policy_ = ReconnectPolicy(reconnect_config);

  controller->impl_->runner_.set_event_callback(
      [controller = controller.get()](TunnelEvent event) {
        controller->on_event(std::move(event));
      });
  controller->impl_->runner_.set_network_config_callback(
      [controller = controller.get()](
          const exv::vpn_engine::TunnelMetadata &metadata,
          exv::vpn_engine::DeviceConfig *device_config) {
        return controller->impl_->configure_network_for_engine(metadata,
                                                               device_config);
      });

  return controller;
}

exv::vpn_engine::ValidationResult
TunnelControllerTestAccess::configure_network_for_engine(
    TunnelController &controller,
    const exv::vpn_engine::TunnelMetadata &metadata,
    exv::vpn_engine::DeviceConfig *device_config) {
  return controller.impl_->configure_network_for_engine(metadata,
                                                        device_config);
}

void TunnelControllerTestAccess::run_core_lease_keepalive(
    TunnelController &controller) {
  controller.impl_->do_core_lease_keepalive();
}

} // namespace exv::core

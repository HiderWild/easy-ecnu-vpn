#include "helper/helper_daemon_context.hpp"

#include <utility>

namespace exv::helper {

std::unique_ptr<exv::helper::HelperHandler> create_helper_handler_for_daemon(
    const DaemonOptions &options, HelperNetworkOpsFactory network_ops_factory) {
  std::shared_ptr<exv::helper::HelperNetworkOps> network_ops =
      network_ops_factory ? network_ops_factory()
                          : exv::helper::create_helper_network_ops();

  auto handler = std::make_unique<exv::helper::HelperHandler>(
      exv::helper::HelperLifecyclePolicy{}, std::move(network_ops));

  exv::helper::HelperStartupContext startup_context;
  startup_context.launch_mode = options.mode;
  startup_context.endpoint = options.endpoint;
  startup_context.owner = options.owner;
  startup_context.parent_pid = options.parent_pid;
  handler->set_startup_context(std::move(startup_context));
  return handler;
}

} // namespace exv::helper

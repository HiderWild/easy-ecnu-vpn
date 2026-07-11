#pragma once

#include "app/ui_shell/core_gateway.hpp"
#include "app/ui_shell/core_rpc_client.hpp"
#include "app/ui_shell/host_bridge.hpp"
#include "app/ui_shell/ui_window.hpp"

namespace exv::ui_shell {

int run_ui_shell_window(UiWindow &window,
                        const UiWindowConfig &config,
                        CoreGateway &gateway);

int run_ui_shell_window(UiWindow &window,
                        const UiWindowConfig &config,
                        CoreRpcClient &client);

} // namespace exv::ui_shell

#pragma once

#include "helper/helper.hpp"
#include "helper/helper_handler.hpp"
#include "helper/helper_network_ops.hpp"

#include <functional>
#include <memory>

namespace exv::helper {

using HelperNetworkOpsFactory =
    std::function<std::shared_ptr<exv::helper::HelperNetworkOps>()>;

std::unique_ptr<exv::helper::HelperHandler> create_helper_handler_for_daemon(
    const DaemonOptions &options,
    HelperNetworkOpsFactory network_ops_factory = HelperNetworkOpsFactory{});

} // namespace exv::helper

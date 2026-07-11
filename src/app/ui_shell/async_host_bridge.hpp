#pragma once

#include "app/ui_shell/core_rpc_client.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <string>

namespace exv::ui_shell {

using HostResponsePoster = std::function<void(std::string)>;
using CoreRpcAsyncInvoker =
    std::function<std::future<CoreRpcResponse>(CoreRpcRequest)>;
using CoreRestartInvoker = std::function<CoreRpcResponse()>;

class AsyncHostBridge {
public:
  AsyncHostBridge(CoreRpcClient &client, HostResponsePoster post_response,
                  std::chrono::milliseconds request_timeout =
                      std::chrono::seconds(15));
  AsyncHostBridge(CoreRpcAsyncInvoker invoke_core,
                  HostResponsePoster post_response,
                  CoreRestartInvoker restart_core,
                  std::chrono::milliseconds request_timeout =
                      std::chrono::seconds(15));
  ~AsyncHostBridge();

  bool accept_message(std::string message_json);
  void shutdown();

private:
  CoreRpcAsyncInvoker invoke_core_;
  CoreRestartInvoker restart_core_;
  HostResponsePoster post_response_;
  std::shared_ptr<std::atomic<bool>> stopped_;
  std::chrono::milliseconds request_timeout_;
};

std::string accepted_host_response();

} // namespace exv::ui_shell

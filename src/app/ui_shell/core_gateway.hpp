#pragma once

#include "app/ui_shell/core_process_manager.hpp"
#include "app/ui_shell/core_rpc_client.hpp"

#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>

namespace exv::ui_shell {

class CoreGateway {
public:
  using TransportFactory =
      std::function<std::unique_ptr<CoreRpcTransport>(const CoreProcessLaunch &)>;

  explicit CoreGateway(CoreProcessLaunch launch,
                       TransportFactory transport_factory =
                           create_core_process_transport);
  ~CoreGateway();

  CoreGateway(const CoreGateway &) = delete;
  CoreGateway &operator=(const CoreGateway &) = delete;

  CoreRpcResponse invoke(const CoreRpcRequest &request);
  std::future<CoreRpcResponse> invoke_async(CoreRpcRequest request);
  void pump_events();
  void set_event_handler(CoreRpcEventHandler handler);
  CoreRpcResponse restart();
  void shutdown();

private:
  CoreRpcResponse invoke_with_recovery(const CoreRpcRequest &request);
  CoreRpcResponse invoke_once(const CoreRpcRequest &request);
  CoreRpcResponse restart_locked();
  void ensure_started_locked();
  void emit_core_crashed(const CoreRpcResponse &response);

  struct Session;

  CoreProcessLaunch launch_;
  TransportFactory transport_factory_;
  std::shared_ptr<Session> session_;
  CoreRpcEventHandler event_handler_;
  std::mutex mutex_;
  bool shutting_down_ = false;
};

} // namespace exv::ui_shell

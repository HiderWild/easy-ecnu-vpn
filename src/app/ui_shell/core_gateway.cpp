#include "app/ui_shell/core_gateway.hpp"

#include <nlohmann/json.hpp>

#include <charconv>
#include <chrono>
#include <future>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>

namespace exv::ui_shell {
namespace {

int request_id_to_int(std::string_view request_id) {
  if (request_id.empty()) {
    return 0;
  }
  int value = 0;
  const char *begin = request_id.data();
  const char *end = begin + request_id.size();
  const auto result = std::from_chars(begin, end, value);
  if (result.ec != std::errc{} || result.ptr != end) {
    return 0;
  }
  return value;
}

CoreRpcResponse gateway_error(const CoreRpcRequest &request,
                              std::string code,
                              std::string message) {
  CoreRpcResponse response;
  response.id = request_id_to_int(request.request_id);
  response.request_id = request.request_id;
  response.ok = false;
  response.code = std::move(code);
  response.message = std::move(message);
  return response;
}

CoreRpcResponse gateway_status(std::string code,
                               std::string message,
                               bool ok) {
  CoreRpcResponse response;
  response.ok = ok;
  response.code = std::move(code);
  response.message = std::move(message);
  if (ok) {
    response.data_json = R"({"restarted":true})";
  }
  return response;
}

bool is_transport_failure(const CoreRpcResponse &response) {
  if (response.ok) {
    return false;
  }
  return response.code == "transport_closed" ||
         response.code == "core_comm_broken" ||
         response.code == "core_unresponsive";
}

bool is_retryable_action(std::string_view action) {
  return action == "core.hello" ||
         action == "status.get" ||
         action == "runtime.status" ||
         action == "drivers.status" ||
         action == "service.status" ||
         action == "helper.status" ||
         action == "cli.status" ||
         action == "logs.list" ||
         action == "routes.list" ||
         action == "config.getAuth" ||
         action == "config.saveAuth" ||
         action == "config.getSettings" ||
         action == "config.saveSettings" ||
         action == "config.getKey" ||
         action == "vpn.authInteraction.get" ||
         action == "maintenance.inspectCore";
}

} // namespace

CoreGateway::CoreGateway(CoreProcessLaunch launch,
                         TransportFactory transport_factory)
    : launch_(std::move(launch)),
      transport_factory_(std::move(transport_factory)) {}

CoreGateway::~CoreGateway() {
  shutdown();
}

struct CoreGateway::Session {
  std::unique_ptr<CoreRpcTransport> transport;
  std::unique_ptr<CoreRpcClient> client;

  ~Session() {
    if (client) {
      client->shutdown();
    } else if (transport) {
      transport->close();
    }
  }
};

CoreRpcResponse CoreGateway::invoke(const CoreRpcRequest &request) {
  return invoke_with_recovery(request);
}

std::future<CoreRpcResponse> CoreGateway::invoke_async(CoreRpcRequest request) {
  std::promise<CoreRpcResponse> promise;
  auto future = promise.get_future();
  std::thread([this, request = std::move(request),
               promise = std::move(promise)]() mutable {
    promise.set_value(invoke_with_recovery(request));
  }).detach();
  return future;
}

void CoreGateway::pump_events() {
  std::shared_ptr<Session> session;
  {
    std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
    if (!lock.owns_lock() || shutting_down_) {
      return;
    }
    ensure_started_locked();
    session = session_;
  }
  if (session && session->client) {
    session->client->pump_events();
  }
}

void CoreGateway::set_event_handler(CoreRpcEventHandler handler) {
  std::lock_guard<std::mutex> lock(mutex_);
  event_handler_ = std::move(handler);
  if (session_ && session_->client) {
    session_->client->set_event_handler(event_handler_);
  }
}

CoreRpcResponse CoreGateway::restart() {
  std::lock_guard<std::mutex> lock(mutex_);
  return restart_locked();
}

void CoreGateway::shutdown() {
  std::shared_ptr<Session> session;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (shutting_down_) {
      return;
    }
    shutting_down_ = true;
    session = std::move(session_);
  }
  if (session && session->client) {
    session->client->shutdown();
  } else if (session && session->transport) {
    session->transport->close();
  }
  session.reset();
}

CoreRpcResponse CoreGateway::invoke_with_recovery(
    const CoreRpcRequest &request) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (shutting_down_) {
      return gateway_error(request, "transport_closed",
                           "Core RPC transport is closed");
    }
  }
  CoreRpcResponse response = invoke_once(request);
  if (!is_transport_failure(response)) {
    return response;
  }

  if (!is_retryable_action(request.action)) {
    emit_core_crashed(response);
    return response;
  }

  CoreRpcResponse restart_response;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    restart_response = restart_locked();
  }
  if (!restart_response.ok) {
    emit_core_crashed(restart_response);
    return gateway_error(request, restart_response.code.empty()
                                      ? "core_restart_required"
                                      : restart_response.code,
                         restart_response.message.empty()
                                      ? "Core restart is required"
                                      : restart_response.message);
  }

  response = invoke_once(request);
  if (is_transport_failure(response)) {
    emit_core_crashed(response);
  }
  return response;
}

CoreRpcResponse CoreGateway::invoke_once(
    const CoreRpcRequest &request) {
  std::shared_ptr<Session> session;
  try {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      ensure_started_locked();
      session = session_;
      if (!session || !session->client) {
        return gateway_error(request, "core_comm_broken",
                             "Core RPC transport is not available");
      }
    }
    return session->client->invoke(request);
  } catch (const std::exception &error) {
    return gateway_error(request, "core_comm_broken", error.what());
  } catch (...) {
    return gateway_error(request, "core_comm_broken",
                         "Unknown core gateway failure");
  }
}

CoreRpcResponse CoreGateway::restart_locked() {
  std::shared_ptr<Session> old_session = std::move(session_);
  if (old_session && old_session->client) {
    old_session->client->shutdown();
  } else if (old_session && old_session->transport) {
    old_session->transport->close();
  }
  old_session.reset();

  try {
    ensure_started_locked();
    if (!session_ || !session_->client) {
      return gateway_status("core_restart_failed",
                            "Core restart did not create a transport", false);
    }
  } catch (const std::exception &error) {
    return gateway_status("core_restart_failed", error.what(), false);
  } catch (...) {
    return gateway_status("core_restart_failed",
                          "Unknown core restart failure", false);
  }

  return gateway_status({}, {}, true);
}

void CoreGateway::ensure_started_locked() {
  if (session_ || shutting_down_) {
    return;
  }
  auto transport = transport_factory_(launch_);
  if (!transport) {
    return;
  }
  auto session = std::make_shared<Session>();
  session->transport = std::move(transport);
  session->client = std::make_unique<CoreRpcClient>(*session->transport);
  session->client->set_event_handler(event_handler_);
  session_ = std::move(session);
}

void CoreGateway::emit_core_crashed(const CoreRpcResponse &response) {
  CoreRpcEventHandler handler;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    handler = event_handler_;
  }
  if (!handler) return;
  nlohmann::json data{
      {"code", response.code.empty() ? "core_comm_broken" : response.code},
      {"message", response.message.empty()
                      ? "Core RPC transport is unavailable"
                      : response.message},
  };
  CoreRpcEvent event;
  event.event = "core-crashed";
  event.data_json = data.dump();
  handler(event);
}

} // namespace exv::ui_shell

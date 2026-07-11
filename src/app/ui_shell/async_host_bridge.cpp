#include "app/ui_shell/async_host_bridge.hpp"

#include "app/ui_shell/host_bridge.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <future>
#include <string_view>
#include <thread>
#include <utility>

namespace exv::ui_shell {
namespace {

std::string error_response(int id, std::string_view code,
                           std::string_view message) {
  nlohmann::ordered_json out;
  out["id"] = id;
  out["ok"] = false;
  out["code"] = code;
  out["message"] = message;
  return out.dump();
}

std::string ok_response(int id) {
  nlohmann::ordered_json out;
  out["id"] = id;
  out["ok"] = true;
  out["data"] = nlohmann::json::object();
  return out.dump();
}

int request_id_from_json(const nlohmann::json &parsed) {
  if (parsed.is_object() && parsed.contains("id") &&
      parsed.at("id").is_number_integer()) {
    return parsed.at("id").get<int>();
  }
  return 0;
}

std::string host_wire_response(int id, const CoreRpcResponse &response) {
  nlohmann::ordered_json out;
  out["id"] = id;
  out["ok"] = response.ok;
  if (response.ok) {
    out["data"] = response.data_json.empty()
                      ? nlohmann::json::object()
                      : nlohmann::json::parse(response.data_json);
  } else {
    out["code"] = response.code;
    out["message"] = response.message;
  }
  return out.dump();
}

std::string timeout_response(int id) {
  return error_response(id, "core_unresponsive",
                        "核心进程无响应，可重启内核后重试。");
}

std::chrono::milliseconds request_timeout_for_action(
    std::string_view action, std::chrono::milliseconds default_timeout) {
  if (action == "service.install" || action == "service.uninstall" ||
      action == "service.repair" || action == "drivers.install" ||
      action == "maintenance.killStaleCore") {
    return std::chrono::minutes(5);
  }
  return default_timeout;
}

} // namespace

AsyncHostBridge::AsyncHostBridge(CoreRpcClient &client,
                                 HostResponsePoster post_response,
                                 std::chrono::milliseconds request_timeout)
    : invoke_core_([&client](CoreRpcRequest request) {
        return client.invoke_async(std::move(request));
      }),
      restart_core_([] {
        CoreRpcResponse response;
        response.ok = false;
        response.code = "unsupported_action";
        response.message = "Core restart is not available";
        return response;
      }),
      post_response_(std::move(post_response)),
      stopped_(std::make_shared<std::atomic<bool>>(false)),
      request_timeout_(request_timeout) {}

AsyncHostBridge::AsyncHostBridge(CoreRpcAsyncInvoker invoke_core,
                                 HostResponsePoster post_response,
                                 CoreRestartInvoker restart_core,
                                 std::chrono::milliseconds request_timeout)
    : invoke_core_(std::move(invoke_core)),
      restart_core_(std::move(restart_core)),
      post_response_(std::move(post_response)),
      stopped_(std::make_shared<std::atomic<bool>>(false)),
      request_timeout_(request_timeout) {}

AsyncHostBridge::~AsyncHostBridge() {
  shutdown();
}

bool AsyncHostBridge::accept_message(std::string message_json) {
  nlohmann::json parsed;
  try {
    parsed = nlohmann::json::parse(message_json);
  } catch (const nlohmann::json::exception &) {
    post_response_(error_response(0, "invalid_request",
                                  "Invalid desktop request"));
    return true;
  }

  if (parsed.is_object() && parsed.contains("id") &&
      !parsed.at("id").is_number_integer()) {
    post_response_(error_response(0, "host_bridge_error",
                                  "Invalid desktop request id"));
    return true;
  }

  const int id = request_id_from_json(parsed);
  const std::string action = parsed.value("action", "");
  if (!is_allowed_host_action(action)) {
    post_response_(error_response(id, "unknown_action",
                                  "Unknown desktop action"));
    return true;
  }

  if (action == "window.setMode" || action == "window.resolveClosePrompt" ||
      action == "window.hideToTray" || action == "shell.notify") {
    post_response_(ok_response(id));
    return true;
  }

  std::future<CoreRpcResponse> future;
  if (action == "core.restart") {
    auto restart_core = restart_core_;
    future = std::async(std::launch::async, [restart_core, id] {
      CoreRpcResponse response = restart_core ? restart_core() : CoreRpcResponse{};
      response.id = id;
      response.request_id = std::to_string(id);
      return response;
    });
  } else {
    CoreRpcRequest request;
    request.action = action;
    request.payload_json = parsed.contains("payload")
                               ? parsed.at("payload").dump()
                               : nlohmann::json::object().dump();
    request.request_id = std::to_string(id);
    future = invoke_core_(std::move(request));
  }
  auto poster = post_response_;
  auto stopped = stopped_;
  const auto timeout = request_timeout_for_action(action, request_timeout_);
  std::thread([future = std::move(future), poster = std::move(poster),
               stopped, id, timeout]() mutable {
    if (future.wait_for(timeout) != std::future_status::ready) {
      if (!stopped->load()) {
        poster(timeout_response(id));
      }
      return;
    }
    CoreRpcResponse response = future.get();
    if (stopped->load()) {
      return;
    }
    poster(host_wire_response(id, response));
  }).detach();
  return true;
}

void AsyncHostBridge::shutdown() {
  stopped_->store(true);
}

std::string accepted_host_response() {
  return {};
}

} // namespace exv::ui_shell

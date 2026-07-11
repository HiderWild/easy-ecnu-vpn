#include "app/ui_shell/ui_shell_runtime.hpp"

#include "app/ui_shell/async_host_bridge.hpp"
#include "app/ui_shell/tray_status_snapshot.hpp"

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <exception>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>

namespace exv::ui_shell {
namespace {

struct RuntimeCoreAccess {
  std::function<void(CoreRpcEventHandler)> set_event_handler;
  std::function<void()> pump_events;
  std::function<std::future<CoreRpcResponse>(CoreRpcRequest)> invoke_async;
  std::function<CoreRpcResponse()> restart;
  std::function<void()> shutdown;
};

class WindowMessageHandlerGuard {
public:
  explicit WindowMessageHandlerGuard(UiWindow &window) : window_(window) {}
  ~WindowMessageHandlerGuard() {
    window_.set_message_handler({});
  }

  WindowMessageHandlerGuard(const WindowMessageHandlerGuard &) = delete;
  WindowMessageHandlerGuard &operator=(const WindowMessageHandlerGuard &) = delete;

private:
  UiWindow &window_;
};

class CoreEventHandlerGuard {
public:
  explicit CoreEventHandlerGuard(
      std::function<void(CoreRpcEventHandler)> set_event_handler)
      : set_event_handler_(std::move(set_event_handler)) {}
  ~CoreEventHandlerGuard() {
    set_event_handler_({});
  }

  CoreEventHandlerGuard(const CoreEventHandlerGuard &) = delete;
  CoreEventHandlerGuard &operator=(const CoreEventHandlerGuard &) = delete;

private:
  std::function<void(CoreRpcEventHandler)> set_event_handler_;
};

class TrayStatusSnapshotCache {
public:
  TrayStatusSnapshot snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    TrayStatusSnapshot copy = snapshot_;
    if (copy.connected && connected_since_.has_value()) {
      const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::steady_clock::now() - connected_since_.value());
      if (elapsed > copy.connected_duration) {
        copy.connected_duration = elapsed;
      }
    }
    return copy;
  }

  void update_from_response(const std::string &response_json) {
    try {
      const auto response = nlohmann::json::parse(response_json);
      if (!response.is_object() || !response.value("ok", false) ||
          !response.contains("data")) {
        return;
      }
      update_from_status_json(response.at("data"));
    } catch (const nlohmann::json::exception &) {
    }
  }

  void update_from_core_response(const CoreRpcResponse &response) {
    if (!response.ok || response.data_json.empty()) {
      return;
    }
    try {
      update_from_status_json(nlohmann::json::parse(response.data_json));
    } catch (const nlohmann::json::exception &) {
    }
  }

  void update_from_event(const CoreRpcEvent &event) {
    try {
      const auto data = event.data_json.empty()
                            ? nlohmann::json::object()
                            : nlohmann::json::parse(event.data_json);
      if (event.event == "vpn.disconnected" ||
          event.event == "tunnel.disconnected") {
        std::lock_guard<std::mutex> lock(mutex_);
        mark_disconnected_locked();
        return;
      }
      if (event.event == "vpn.connected" || event.event == "tunnel.connected") {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto now = std::chrono::steady_clock::now();
        std::optional<std::string> username;
        if (data.is_object() && data.contains("username") &&
            data["username"].is_string()) {
          username = data["username"].get<std::string>();
        }
        mark_connected_locked(now, username, duration_from_status(data));
        return;
      }
      update_from_status_json(data);
    } catch (const nlohmann::json::exception &) {
    }
  }

private:
  void update_from_status_json(const nlohmann::json &data) {
    if (!data.is_object() || !data.contains("connected") ||
        !data["connected"].is_boolean()) {
      return;
    }

    const auto now = std::chrono::steady_clock::now();
    std::optional<std::string> username;
    if (data.contains("username") && data["username"].is_string()) {
      username = data["username"].get<std::string>();
    }
    const auto connected = data["connected"].get<bool>();
    const auto duration = duration_from_status(data);

    std::lock_guard<std::mutex> lock(mutex_);
    if (connected) {
      mark_connected_locked(now, username, duration);
    } else {
      if (username.has_value()) {
        snapshot_.username = *username;
      }
      mark_disconnected_locked();
    }
  }

  static std::optional<std::chrono::seconds>
  duration_from_status(const nlohmann::json &data) {
    if (!data.is_object()) {
      return std::nullopt;
    }
    for (const char *key : {"uptime_seconds", "connected_seconds",
                            "connected_duration_seconds", "duration_seconds",
                            "connected_duration"}) {
      if (data.contains(key) && data[key].is_number_integer()) {
        const auto value = data[key].get<std::int64_t>();
        return std::chrono::seconds(value > 0 ? value : 0);
      }
    }
    return std::nullopt;
  }

  void mark_connected_locked(
      std::chrono::steady_clock::time_point now,
      const std::optional<std::string> &username,
      std::optional<std::chrono::seconds> reported_duration) {
    if (username.has_value()) {
      snapshot_.username = *username;
    }
    if (!snapshot_.connected || !connected_since_.has_value()) {
      connected_since_ = now - reported_duration.value_or(std::chrono::seconds{0});
    } else if (reported_duration.has_value()) {
      connected_since_ = now - reported_duration.value();
    }
    snapshot_.connected = true;
    if (connected_since_.has_value()) {
      snapshot_.connected_duration = std::chrono::duration_cast<std::chrono::seconds>(
          now - connected_since_.value());
    }
  }

  void mark_disconnected_locked() {
    snapshot_.connected = false;
    snapshot_.connected_duration = std::chrono::seconds{0};
    connected_since_.reset();
  }

  mutable std::mutex mutex_;
  TrayStatusSnapshot snapshot_;
  std::optional<std::chrono::steady_clock::time_point> connected_since_;
};

int request_id_from_message(const std::string &message_json) {
  try {
    const auto parsed = nlohmann::json::parse(message_json);
    if (parsed.is_object() && parsed.contains("id") && parsed.at("id").is_number_integer()) {
      return parsed.at("id").get<int>();
    }
  } catch (const nlohmann::json::exception &) {
  }
  return 0;
}

std::string callback_error_response(const std::string &message_json,
                                    std::string_view message) {
  nlohmann::ordered_json out;
  out["id"] = request_id_from_message(message_json);
  out["ok"] = false;
  out["code"] = "host_bridge_error";
  out["message"] = message;
  return out.dump();
}

std::string renderer_event_envelope(const CoreRpcEvent &event) {
  nlohmann::ordered_json out;
  out["type"] = event.event;
  out["data"] = event.data_json.empty()
                    ? nlohmann::json::object()
                    : nlohmann::json::parse(event.data_json);
  return out.dump();
}

void request_core_shutdown(const RuntimeCoreAccess &core) {
  static std::atomic_int shutdown_request_id{1100000000};
  CoreRpcRequest request;
  request.action = "core.shutdown";
  request.payload_json = nlohmann::json::object().dump();
  request.request_id = std::to_string(++shutdown_request_id);
  auto future = core.invoke_async(std::move(request));
  (void)future.wait_for(std::chrono::seconds(2));
}

bool status_phase_active_for_close(std::string_view phase) {
  return phase == "preparing_helper" || phase == "authenticating" ||
         phase == "connecting" || phase == "connecting_cstp" ||
         phase == "applying_network_config" ||
         phase == "opening_packet_device" || phase == "connected" ||
         phase == "reconnecting" || phase == "disconnecting" ||
         phase == "cleaning_up";
}

std::optional<bool>
status_response_active_for_close(const CoreRpcResponse &response) {
  if (!response.ok || response.data_json.empty()) {
    return std::nullopt;
  }
  try {
    const auto data = nlohmann::json::parse(response.data_json);
    if (!data.is_object()) {
      return std::nullopt;
    }
    if (data.contains("connected") && data["connected"].is_boolean() &&
        data["connected"].get<bool>()) {
      return true;
    }
    if (data.contains("process_running") && data["process_running"].is_boolean() &&
        data["process_running"].get<bool>()) {
      return true;
    }
    if (data.contains("session_active") && data["session_active"].is_boolean() &&
        data["session_active"].get<bool>()) {
      return true;
    }
    if (data.contains("network_ready") && data["network_ready"].is_boolean() &&
        data["network_ready"].get<bool>()) {
      return true;
    }
    if (data.contains("phase") && data["phase"].is_string() &&
        status_phase_active_for_close(data["phase"].get<std::string>())) {
      return true;
    }
    if (data.contains("phase") && data["phase"].is_string()) {
      return false;
    }
    if (data.contains("desired_connected") &&
        data["desired_connected"].is_boolean() &&
        data["desired_connected"].get<bool>()) {
      return true;
    }
    if (data.contains("connected") && data["connected"].is_boolean()) {
      return false;
    }
    if (data.contains("process_running") &&
        data["process_running"].is_boolean()) {
      return false;
    }
    if (data.contains("desired_connected") &&
        data["desired_connected"].is_boolean()) {
      return false;
    }
    if (data.contains("session_active") && data["session_active"].is_boolean()) {
      return false;
    }
    if (data.contains("network_ready") && data["network_ready"].is_boolean()) {
      return false;
    }
    return std::nullopt;
  } catch (const nlohmann::json::exception &) {
    return std::nullopt;
  }
}

bool query_vpn_connected_for_close(const RuntimeCoreAccess &core) {
  static std::atomic_int close_status_request_id{1000000000};
  CoreRpcRequest request;
  request.action = "status.get";
  request.payload_json = nlohmann::json::object().dump();
  request.request_id = std::to_string(++close_status_request_id);

  auto future = core.invoke_async(std::move(request));
  if (future.wait_for(std::chrono::milliseconds(750)) !=
      std::future_status::ready) {
    return true;
  }
  return status_response_active_for_close(future.get()).value_or(true);
}

void refresh_tray_status_from_core(const RuntimeCoreAccess &core,
                                   TrayStatusSnapshotCache &cache) {
  if (!core.invoke_async) {
    return;
  }
  try {
    static std::atomic_int tray_status_request_id{1300000000};
    CoreRpcRequest request;
    request.action = "status.get";
    request.payload_json = nlohmann::json::object().dump();
    request.request_id = std::to_string(++tray_status_request_id);

    auto future = core.invoke_async(std::move(request));
    if (future.wait_for(std::chrono::milliseconds(500)) !=
        std::future_status::ready) {
      return;
    }
    cache.update_from_core_response(future.get());
  } catch (...) {
  }
}

int run_ui_shell_window(UiWindow &window,
                        const UiWindowConfig &config,
                        RuntimeCoreAccess core) {
  auto tray_snapshot_cache = std::make_shared<TrayStatusSnapshotCache>();
  core.set_event_handler([&window, tray_snapshot_cache](const CoreRpcEvent &event) {
    tray_snapshot_cache->update_from_event(event);
    window.emit_event(renderer_event_envelope(event));
  });
  CoreEventHandlerGuard event_guard(core.set_event_handler);

  std::atomic<bool> stop_event_pump{false};
  std::thread event_pump_thread([&core, &stop_event_pump]() {
    while (!stop_event_pump.load()) {
      core.pump_events();
      std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }
  });

  UiWindowConfig runtime_config = config;
  runtime_config.pump_core_events = [&core]() { core.pump_events(); };
  runtime_config.is_vpn_connected = [&core]() {
    return query_vpn_connected_for_close(core);
  };
  runtime_config.tray_status_snapshot_provider = [tray_snapshot_cache, &core]() {
    refresh_tray_status_from_core(core, *tray_snapshot_cache);
    return tray_snapshot_cache->snapshot();
  };
  runtime_config.disconnect_vpn_in_background = [&core]() {
    static std::atomic_int disconnect_request_id{1200000000};
    CoreRpcRequest request;
    request.action = "vpn.disconnect";
    request.payload_json = nlohmann::json::object().dump();
    request.request_id = std::to_string(++disconnect_request_id);
    (void)core.invoke_async(std::move(request));
  };

  AsyncHostBridge bridge(
      core.invoke_async,
      [&window, tray_snapshot_cache](std::string response_json) {
        tray_snapshot_cache->update_from_response(response_json);
        window.post_host_response(response_json);
      },
      core.restart);

  window.set_message_handler([&bridge](const std::string &message_json) {
    try {
      bridge.accept_message(message_json);
      return accepted_host_response();
    } catch (const std::exception &error) {
      return callback_error_response(message_json, error.what());
    } catch (...) {
      return callback_error_response(message_json, "Unknown host bridge error");
    }
  });
  WindowMessageHandlerGuard handler_guard(window);

  auto shutdown_runtime = [&]() {
    stop_event_pump.store(true);
    if (event_pump_thread.joinable()) {
      event_pump_thread.join();
    }
    bridge.shutdown();
    request_core_shutdown(core);
    core.shutdown();
  };

  int exit_code = 70;
  try {
    exit_code = window.run(runtime_config);
  } catch (...) {
    shutdown_runtime();
    throw;
  }
  shutdown_runtime();
  return exit_code;
}

} // namespace

int run_ui_shell_window(UiWindow &window,
                        const UiWindowConfig &config,
                        CoreGateway &gateway) {
  RuntimeCoreAccess core{
      [&gateway](CoreRpcEventHandler handler) {
        gateway.set_event_handler(std::move(handler));
      },
      [&gateway]() { gateway.pump_events(); },
      [&gateway](CoreRpcRequest request) {
        return gateway.invoke_async(std::move(request));
      },
      [&gateway]() { return gateway.restart(); },
      [&gateway]() { gateway.shutdown(); },
  };
  return run_ui_shell_window(window, config, std::move(core));
}

int run_ui_shell_window(UiWindow &window,
                        const UiWindowConfig &config,
                        CoreRpcClient &client) {
  RuntimeCoreAccess core{
      [&client](CoreRpcEventHandler handler) {
        client.set_event_handler(std::move(handler));
      },
      [&client]() { client.pump_events(); },
      [&client](CoreRpcRequest request) {
        return client.invoke_async(std::move(request));
      },
      [] {
        CoreRpcResponse response;
        response.ok = false;
        response.code = "unsupported_action";
        response.message = "Core restart is not available";
        return response;
      },
      [&client]() { client.shutdown(); },
  };
  return run_ui_shell_window(window, config, std::move(core));
}

} // namespace exv::ui_shell

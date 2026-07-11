#include "platform/common/file_system.hpp"
#include "platform/common/interface_stats.hpp"
#include "platform/common/process_utils.hpp"
#include "platform/common/runtime_discovery.hpp"
#include "platform/common/runtime_paths.hpp"
#include "helper/helper.hpp"
#include "helper/helper_daemon_context.hpp"
#include "helper/helper_ipc.hpp"
#include "helper/helper_lane_scheduler.hpp"
#include "helper/helper_single_instance.hpp"

#include "helper/common/helper_messages.hpp"
#include "helper/helper_handler.hpp"
#include "observability/log_facade.hpp"
#include "runtime/runtime_context.hpp"
#include "feedback/feedback.hpp"
#include "platform/common/helper_client.hpp"
#include "platform/common/helper_lifecycle.hpp"
#include "platform/common/helper_platform.hpp"
#include "platform/common/helper_service_manager.hpp"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <chrono>
#include <future>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace exv {
namespace helper {

namespace {

volatile sig_atomic_t daemon_stop_requested = 0;
DaemonOptions active_daemon_options;

#if defined(EXV_PLATFORM_WINDOWS)
inline constexpr std::string_view kHelperPlatformName = "windows";
inline constexpr std::string_view kHelperTransportName = "named-pipe";
#elif defined(EXV_PLATFORM_DARWIN)
inline constexpr std::string_view kHelperPlatformName = "darwin";
inline constexpr std::string_view kHelperTransportName = "unix-socket";
#elif defined(EXV_PLATFORM_LINUX)
inline constexpr std::string_view kHelperPlatformName = "linux";
inline constexpr std::string_view kHelperTransportName = "unix-socket";
#else
#error "Unsupported EXV platform"
#endif

void daemon_signal_handler(int) {
  daemon_stop_requested = 1;
}

nlohmann::json make_error(const std::string &message,
                          const std::string &code = std::string()) {
  return feedback::make_error(message, code);
}

nlohmann::json make_helper_capabilities() {
  return nlohmann::json{{"vpn_connect", true},
                        {"vpn_disconnect", true},
                        {"logs", false},
                        {"events", false},
                        {"temporary_connect", active_daemon_options.oneshot},
                        {"oneshot_mode", active_daemon_options.oneshot},
                        {"service_mode", true}};
}

nlohmann::json make_helper_descriptor() {
  const auto &platform_config = platform::helper_platform_config();
  return nlohmann::json{{"name", "exv-helper"},
                        {"version", EXV_VERSION},
                        {"platform_service_mode", platform_config.service_mode},
                        {"mode", active_daemon_options.mode},
                        {"endpoint", active_daemon_options.endpoint},
                        {"owner", active_daemon_options.owner},
                        {"parent_pid", active_daemon_options.parent_pid},
                        {"platform", std::string(kHelperPlatformName)},
                        {"transport", std::string(kHelperTransportName)},
                        {"capabilities", make_helper_capabilities()}};
}

nlohmann::json make_hello_response() {
  nlohmann::json descriptor = make_helper_descriptor();
  descriptor["ok"] = true;
  return descriptor;
}

exv::helper::CleanupPolicy full_cleanup_policy() {
  exv::helper::CleanupPolicy policy;
  policy.remove_routes = true;
  policy.remove_dns = true;
  policy.remove_adapter = true;
  policy.remove_firewall_rules = true;
  return policy;
}

bool peer_matches_expected_owner(const IpcServer &ipc,
                                 const DaemonOptions &options) {
  if (!options.oneshot)
    return true;
  if (options.owner.empty())
    return false;

  const std::string peer_owner = ipc.peer_owner();
  if (!peer_owner.empty() && peer_owner == options.owner)
    return true;

  const std::string peer_uid = std::to_string(ipc.peer_uid());
  if (!peer_uid.empty() && peer_uid == options.owner)
    return true;

  return false;
}

exv::helper::HelperRequestContext make_helper_request_context(
    const IpcServer &ipc) {
  exv::helper::HelperRequestContext context;
  context.peer.verified = true;
  context.peer.owner = ipc.peer_owner();
  context.peer.uid = ipc.peer_uid();
  context.peer.gid = ipc.peer_gid();
  context.peer.pid = ipc.peer_pid();
  if (context.peer.owner.empty() && context.peer.uid == 0 &&
      context.peer.gid == 0) {
    context.peer.uid = std::numeric_limits<unsigned int>::max();
    context.peer.gid = std::numeric_limits<unsigned int>::max();
  }
  return context;
}

bool cleanup_all_sessions_or_keep_running(
    exv::helper::HelperHandler &handler,
    const std::string &reason) {
  exv::helper::CleanupResponse cleanup =
      handler.cleanup_all_sessions(full_cleanup_policy());
  if (cleanup.success) {
    return true;
  }

  std::ostringstream message;
  message << "Helper cleanup failed during " << reason
          << "; keeping daemon alive for retry";
  for (const auto &error : cleanup.errors) {
    message << "; " << error;
  }
  exv::observability::LogFacade::warn(message.str());
  return false;
}

void add_helper_descriptor_fields(nlohmann::json &response) {
  nlohmann::json descriptor = make_helper_descriptor();
  response["helper"] = descriptor;
  response["backend_mode"] = descriptor.value("mode", "service");
  response["transport"] = descriptor.value("transport", "unknown");
  response["capabilities"] =
      descriptor.value("capabilities", nlohmann::json::object());
}

bool send_request(const nlohmann::json &request, nlohmann::json *response,
                  std::string *error_message = nullptr,
                  int /*timeout_seconds*/ = 15) {
  nlohmann::json result = platform::send_helper_request(request);
  if (!result.is_object()) {
    if (error_message) *error_message = "Failed to parse EXV helper response.";
    return false;
  }
  if (result.contains("ok") && result["ok"].is_boolean() && !result["ok"].get<bool>()) {
    if (result.contains("code") && result["code"].is_string() &&
        result["code"].get<std::string>() == std::string(platform::kHelperUnavailableCode)) {
      if (error_message) *error_message = "EXV helper is not available.";
    } else {
      if (error_message)
        *error_message = result.value("message", std::string("EXV helper request failed."));
    }
    return false;
  }
  if (response) *response = result;
  return true;
}

bool wait_until_available(int attempts = 1, unsigned int delay_us = 0) {
  for (int i = 0; i < attempts; ++i) {
    nlohmann::json response;
    std::string error_message;
    exv::helper::HelperRequest hello_req;
    hello_req.op = exv::helper::HelperOp::Hello;
    hello_req.payload_json = nlohmann::json(exv::helper::HelloRequest{}).dump();
    nlohmann::json request_json = hello_req;
    if (send_request(request_json, &response, &error_message)) {
      return true;
    }
    if (i + 1 < attempts && delay_us > 0) {
      platform::sleep_ms(static_cast<int>(delay_us / 1000));
    }
  }
  return false;
}

void reap_finished_request_handlers() {
  platform::reap_children();
}

bool wait_until_available_for_platform(int attempts, unsigned int delay_us) {
  return wait_until_available(attempts, delay_us);
}

bool send_request_for_platform(const nlohmann::json &request,
                               nlohmann::json *response,
                               std::string *error_message,
                               int timeout_seconds) {
  return send_request(request, response, error_message, timeout_seconds);
}

platform::HelperServiceManagerContext make_helper_service_manager_context() {
  return platform::HelperServiceManagerContext{
      wait_until_available_for_platform,
      send_request_for_platform,
      nullptr,
      nullptr,
  };
}

} // namespace

void request_daemon_stop() {
  daemon_stop_requested = 1;
  platform::wake_helper_daemon_for_shutdown();
}

bool is_available() {
  return wait_until_available();
}

int show_service_status() {
  return platform::show_helper_service_status(
      make_helper_service_manager_context());
}

int daemon_main(const DaemonOptions &options) {
  daemon_stop_requested = 0;
  active_daemon_options = options;

  signal(SIGTERM, daemon_signal_handler);
  signal(SIGINT, daemon_signal_handler);

  exv::observability::LogFacade::info("Helper daemon starting (mode=" + options.mode + ")");

  // Single-instance assertion: refuse to start if another helper of the same
  // kind is already running. The handle is held for the lifetime of daemon_main
  // and released on return.
  exv::helper::HelperInstanceKind instance_kind =
      options.oneshot ? exv::helper::HelperInstanceKind::Oneshot
                      : exv::helper::HelperInstanceKind::Service;
  auto single_instance = exv::helper::acquire_single_instance(instance_kind);
  if (!single_instance) {
    exv::observability::LogFacade::error(
        "Another helper instance is already running; exiting to avoid "
        "multi-instance drift.");
    return 1;
  }

  auto ipc = helper::create_ipc_server();
  if (!ipc || !ipc->start(options.endpoint)) {
    exv::observability::LogFacade::error("Failed to open helper IPC endpoint: " + options.endpoint);
    return 1;
  }

  auto handler = create_helper_handler_for_daemon(options);

  // Lane scheduler: dispatch each helper request onto the lane appropriate for
  // its op so a slow Tunnel-lane operation (ApplyTunnelConfig etc.) does not
  // block Hello / Heartbeat / lease lifecycle on other lanes. Same-lane ops
  // remain serialized so the managed network state never races.
  exv::helper::HelperLaneScheduler lane_scheduler;
  if (!lane_scheduler.start()) {
    exv::observability::LogFacade::error("Failed to start helper lane scheduler");
    return 1;
  }

  std::thread maintenance_thread([&] {
    while (!daemon_stop_requested) {
      for (int i = 0; i < 150 && !daemon_stop_requested; ++i) {
        platform::sleep_ms(100);
      }
      if (daemon_stop_requested)
        break;

      handler->tick();
      if (options.oneshot && options.parent_pid > 0 &&
          !platform::is_process_alive(options.parent_pid)) {
        exv::observability::LogFacade::info("Helper oneshot parent disappeared; cleaning up and exiting");
        handler->mark_shutdown(exv::helper::HelperExitReason::Timeout);
        if (cleanup_all_sessions_or_keep_running(*handler, "parent exit")) {
          daemon_stop_requested = 1;
        }
      }
      auto core_pid = handler->active_core_pid();
      if (core_pid.has_value() && *core_pid > 0 &&
          !platform::is_process_alive(*core_pid)) {
        exv::observability::LogFacade::info("Helper core process disappeared; cleaning active sessions");
        handler->handle_core_lifecycle_lost();
      }
      if (handler->should_stop()) {
        daemon_stop_requested = 1;
      }
      if (daemon_stop_requested) {
        platform::wake_helper_daemon_for_shutdown();
      }
    }
  });

  exv::observability::LogFacade::info("Helper daemon ready, accepting connections");

  while (!daemon_stop_requested) {
    if (!ipc->accept_client()) {
      if (daemon_stop_requested)
        break;
      reap_finished_request_handlers();
      handler->tick();
      if (handler->should_stop()) {
        daemon_stop_requested = 1;
      }
      continue;
    }

    if (!ipc->verify_client()) {
      ipc->close_client();
      continue;
    }
    if (!peer_matches_expected_owner(*ipc, options)) {
      exv::observability::LogFacade::warn("Helper client owner mismatch; rejecting connection");
      ipc->send_response(
          make_error("Helper client owner mismatch", "permission_denied").dump());
      ipc->close_client();
      if (options.oneshot) {
        if (cleanup_all_sessions_or_keep_running(*handler, "owner mismatch")) {
          daemon_stop_requested = 1;
        }
      }
      continue;
    }

    exv::helper::HelperRequestContext request_context =
        make_helper_request_context(*ipc);
    bool first_request = true;
    while (!daemon_stop_requested) {
      std::string raw =
          ipc->read_request(first_request ? options.first_request_timeout_ms : -1);
      if (raw.empty()) {
        if (first_request) {
          exv::observability::LogFacade::warn("Helper client did not send initial Hello before timeout");
        }
        break;
      }

      // Parse and dispatch
      try {
        nlohmann::json req = nlohmann::json::parse(raw);

        if (req.contains("op")) {
          exv::helper::HelperRequest helper_req = exv::helper::helper_request_from_json(req);
          if (first_request && helper_req.op != exv::helper::HelperOp::Hello) {
            exv::helper::HelperResponse helper_resp;
            helper_resp.op = helper_req.op;
            helper_resp.success = false;
            helper_resp.error_code = "hello_required";
            helper_resp.error_message = "First helper request must be Hello";
            nlohmann::json resp_json = helper_resp;
            ipc->send_response(resp_json.dump());
            if (options.oneshot) {
              if (cleanup_all_sessions_or_keep_running(*handler, "invalid first request")) {
                daemon_stop_requested = 1;
              }
            }
            break;
          }

          exv::helper::HelperResponse helper_resp;
          {
            std::promise<exv::helper::HelperResponse> promise;
            std::future<exv::helper::HelperResponse> future = promise.get_future();
            exv::helper::HelperLaneItem item;
            item.request = helper_req;
            item.context = request_context;
            item.handler =
                [handler_ptr = handler.get()](
                    const exv::helper::HelperRequest &req,
                    const exv::helper::HelperRequestContext &ctx) {
                  return handler_ptr->handle(req, ctx);
                };
            item.respond =
                [&promise](exv::helper::HelperResponse resp) {
                  promise.set_value(std::move(resp));
                };
            if (!lane_scheduler.schedule(std::move(item))) {
              helper_resp.op = helper_req.op;
              helper_resp.success = false;
              helper_resp.error_code = "scheduler_stopped";
              helper_resp.error_message =
                  "Helper lane scheduler is not accepting work";
            } else {
              helper_resp = future.get();
            }
          }
          nlohmann::json resp_json = helper_resp;
          ipc->send_response(resp_json.dump());
          first_request = false;
          if (handler->should_stop()) {
            daemon_stop_requested = 1;
          }
        } else {
          nlohmann::json err =
              make_error(first_request ? "First helper request must be Hello"
                                       : "Helper request envelope must include op",
                         first_request ? "hello_required" : "invalid_envelope");
          ipc->send_response(err.dump());
          if (first_request && options.oneshot) {
            if (cleanup_all_sessions_or_keep_running(*handler, "invalid envelope")) {
              daemon_stop_requested = 1;
            }
          }
          break;
        }
      } catch (const std::exception &e) {
        nlohmann::json err = make_error(std::string("Parse error: ") + e.what());
        ipc->send_response(err.dump());
        if (first_request && options.oneshot) {
          if (cleanup_all_sessions_or_keep_running(*handler, "parse error")) {
            daemon_stop_requested = 1;
          }
        }
        break;
      }

      reap_finished_request_handlers();
      handler->tick();
      if (handler->should_stop()) {
        daemon_stop_requested = 1;
      }
    }

    ipc->close_client();
    if (options.oneshot) {
      if (!handler->has_active_core_lease()) {
        if (cleanup_all_sessions_or_keep_running(*handler, "client disconnect")) {
          daemon_stop_requested = 1;
        }
      }
    }
    reap_finished_request_handlers();
    handler->tick();
    if (handler->should_stop()) {
      daemon_stop_requested = 1;
    }
  }

  exv::observability::LogFacade::info("Helper daemon shutting down");
  daemon_stop_requested = 1;
  if (maintenance_thread.joinable()) {
    maintenance_thread.join();
  }
  lane_scheduler.stop();
  ipc->close();
  platform::cleanup_daemon_endpoint(active_daemon_options.endpoint);
  return 0;
}

} // namespace helper
} // namespace exv

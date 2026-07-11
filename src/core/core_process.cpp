#include "core_process.hpp"
#include "core/lifecycle/core_lock.hpp"
#include "core/lifecycle/core_paths.hpp"
#include "core/lifecycle/core_registry.hpp"
#include "helper/common/helper_client.hpp"
#include "observability/log_facade.hpp"
#include "platform/common/logging/log_runtime.hpp"
#include "platform/common/logging/stdout_log_sink.hpp"
#include "common/diagnostics/log_renderer.hpp"
#include "core/pipe_ipc.hpp"
#include "runtime/runtime_context.hpp"
#include "core/app_api/app_api.hpp"
#include "core/app_api/desktop_status_presenter.hpp"
#include "core/app_api/desktop_vpn_actions.hpp"
#include "core/config/config_manager.hpp"
#include "core/config/config_initialization.hpp"
#include "core/rpc/lane_scheduler.hpp"
#include "core/rpc/core_api_setup.hpp"
#include "core/tunnel_controller/reconnect_policy.hpp"
#include "core/tunnel_controller/tunnel_controller.hpp"
#include "core/use_cases/tunnel_use_cases.hpp"

#include <nlohmann/json.hpp>

#include <atomic>
#include <csignal>
#include <deque>
#include <iostream>
#include <chrono>
#include <functional>
#include <future>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

using json = nlohmann::json;

namespace exv::core {

namespace testing {

using CoreRegistryPersistCandidateHook =
    std::function<void(
        exv::core::lifecycle::CoreRegistrySnapshot& snapshot,
        int persist_attempt)>;

CoreRegistryPersistCandidateHook& core_registry_persist_candidate_hook() {
    static CoreRegistryPersistCandidateHook hook;
    return hook;
}

void set_core_registry_persist_candidate_hook(
    CoreRegistryPersistCandidateHook hook) {
    core_registry_persist_candidate_hook() = std::move(hook);
}

} // namespace testing

bool should_inspect_helper_for_registry(
    const std::optional<TunnelStatusSnapshot>& status) {
    return status.has_value() && status->core_lease_active;
}

// ------------------------------------------------------------------
// Global signal flag — set by SIGTERM/SIGINT handler
// ------------------------------------------------------------------

static std::atomic<bool> g_stop_requested{false};

static void core_signal_handler(int) {
    g_stop_requested.store(true);
}

static void log_startup_fatal(const std::string& code,
                              const std::string& message) {
    exv::observability::LogFacade::error(
        "Core process startup failed [" + code + "]: " + message);
}

// ------------------------------------------------------------------
// Helper: write a JSON line to stdout (thread-safe)
// ------------------------------------------------------------------

static void write_json_line(const json& obj) {
    std::string line = obj.dump();
    std::lock_guard<std::mutex> lock(
        exv::platform::logging::stdout_stream_mutex());
    std::cout << line << '\n' << std::flush;
}

// ------------------------------------------------------------------
// Helper: dispatch an Electron-facing desktop action through the real
// app_api handlers and convert the legacy result to core JSON-RPC wire.
// ------------------------------------------------------------------

static json desktop_action_response(int id,
                                    const std::string& action,
                                    const json& payload) {
    json result = exv::app_api::handle_action(action, payload);

    if (result.is_object() && result.value("ok", true) == false) {
        std::string message = result.value("error", std::string());
        if (message.empty()) {
            message = result.value("message", std::string());
        }
        if (message.empty()) {
            message = "Desktop action failed";
        }

        json response = {
            {"id", id},
            {"ok", false},
            {"code", result.value("code", std::string())},
            {"message", message}
        };
        return response;
    }

    json data = result;
    if (data.is_object() && data.value("ok", false) == true) {
        data.erase("ok");
    }

    return {
        {"id", id},
        {"ok", true},
        {"data", data}
    };
}

static json handle_desktop_request_json(const json& request) {
    int id = request.value("id", 0);
    std::string action = request.value("action", std::string());
    if (action.empty()) {
        return {
            {"id", id},
            {"ok", false},
            {"code", "missing_action"},
            {"message", "Request must contain an 'action' field"}
        };
    }

    const json payload = request.contains("payload")
        ? request.at("payload")
        : json::object();
    return desktop_action_response(id, action, payload);
}

static exv::core_api::RpcResponse dispatch_desktop_as_rpc(
    const exv::core_api::RpcRequest& request) {
    exv::core_api::RpcResponse response;
    response.request_id = request.request_id;

    json payload = json::object();
    try {
        if (!request.payload_json.empty()) {
            payload = json::parse(request.payload_json);
        }
    } catch (const json::exception& error) {
        response.success = false;
        response.error_code = "invalid_payload";
        response.error_message = error.what();
        return response;
    }

    json result = exv::app_api::handle_action(request.action, payload);
    if (result.is_object() && result.value("ok", true) == false) {
        response.success = false;
        response.error_message = result.value("error", std::string());
        if (response.error_message.empty()) {
            response.error_message = result.value("message", std::string());
        }
        if (response.error_message.empty()) {
            response.error_message = "Desktop action failed";
        }
        response.error_code = result.value("code", std::string());
        response.payload_json = result.dump();
        return response;
    }

    response.success = true;
    response.payload_json = result.dump();
    return response;
}

static bool is_native_core_request(const json& request) {
    return request.contains("request_id") || request.contains("payload_json") ||
           request.value("envelope", std::string()) == "core";
}

static bool is_desktop_backed_native_action(const std::string& action) {
    return action == "status.get" ||
           action == "vpn.connect" ||
           action == "vpn.disconnect" ||
           action == "vpn.authInteraction.get" ||
           action == "vpn.authInteraction.respond";
}

static bool is_core_owned_control_action(const std::string& action) {
    return action == "core.shutdown";
}

static json native_core_response(exv::core_api::AppRpcDispatcher& dispatcher,
                                 const json& request) {
    std::string action = request.value("action", std::string());
    std::string request_id = request.value("request_id", std::string());
    if (action.empty()) {
        return {
            {"request_id", request_id},
            {"success", false},
            {"error_code", "missing_action"},
            {"error_message", "Request must contain an 'action' field"}
        };
    }

    exv::core_api::RpcRequest rpc_request;
    rpc_request.action = action;
    rpc_request.request_id = request_id;
    if (request.contains("payload_json")) {
        const json& payload_json = request.at("payload_json");
        rpc_request.payload_json =
            payload_json.is_string() ? payload_json.get<std::string>()
                                     : payload_json.dump();
    } else if (request.contains("payload")) {
        rpc_request.payload_json = request.at("payload").dump();
    } else {
        rpc_request.payload_json = "{}";
    }

    exv::core_api::RpcResponse rpc_response =
        is_desktop_backed_native_action(action)
            ? dispatch_desktop_as_rpc(rpc_request)
            : dispatcher.dispatch(rpc_request);

    json response = {
        {"request_id", rpc_response.request_id},
        {"success", rpc_response.success}
    };
    if (rpc_response.success) {
        response["payload_json"] =
            rpc_response.payload_json.empty() ? "{}" : rpc_response.payload_json;
    } else {
        response["error_code"] = rpc_response.error_code;
        response["error_message"] = rpc_response.error_message;
    }
    return response;
}

struct ScheduledRequest {
    bool is_desktop = true;
    int desktop_id = 0;
    exv::core_api::RpcRequest rpc;
};

static ScheduledRequest make_scheduled_request(const json& request) {
    ScheduledRequest out;
    out.is_desktop = !is_native_core_request(request);
    out.rpc.action = request.value("action", std::string());

    if (out.is_desktop) {
        out.desktop_id = request.value("id", 0);
        out.rpc.request_id = std::to_string(out.desktop_id);
        const json payload = request.contains("payload")
            ? request.at("payload")
            : json::object();
        out.rpc.payload_json = payload.dump();
    } else {
        out.rpc.request_id = request.value("request_id", std::string());
        if (request.contains("payload_json")) {
            const json& payload_json = request.at("payload_json");
            out.rpc.payload_json =
                payload_json.is_string() ? payload_json.get<std::string>()
                                         : payload_json.dump();
        } else if (request.contains("payload")) {
            out.rpc.payload_json = request.at("payload").dump();
        } else {
            out.rpc.payload_json = "{}";
        }
    }

    return out;
}

static json desktop_wire_response(int id,
                                  const exv::core_api::RpcResponse& response) {
    if (!response.success) {
        return {
            {"id", id},
            {"ok", false},
            {"code", response.error_code},
            {"message", response.error_message.empty()
                            ? std::string("Desktop action failed")
                            : response.error_message}
        };
    }

    json data = json::object();
    if (!response.payload_json.empty()) {
        try {
            data = json::parse(response.payload_json);
        } catch (...) {
            data = response.payload_json;
        }
    }
    if (data.is_object() && data.value("ok", false) == true) {
        data.erase("ok");
    }
    return {
        {"id", id},
        {"ok", true},
        {"data", data}
    };
}

static json native_wire_response(const exv::core_api::RpcResponse& response) {
    json out = {
        {"request_id", response.request_id},
        {"success", response.success}
    };
    if (response.success) {
        out["payload_json"] =
            response.payload_json.empty() ? "{}" : response.payload_json;
    } else {
        out["error_code"] = response.error_code;
        out["error_message"] = response.error_message;
    }
    return out;
}

static json missing_action_response(const ScheduledRequest& request) {
    if (request.is_desktop) {
        return {
            {"id", request.desktop_id},
            {"ok", false},
            {"code", "missing_action"},
            {"message", "Request must contain an 'action' field"}
        };
    }
    return {
        {"request_id", request.rpc.request_id},
        {"success", false},
        {"error_code", "missing_action"},
        {"error_message", "Request must contain an 'action' field"}
    };
}

static bool schedule_request_json(
    exv::core_api::AppRpcDispatcher& dispatcher,
    exv::core_api::LaneScheduler& scheduler,
    const json& request,
    std::function<void(json)> respond) {
    ScheduledRequest scheduled = make_scheduled_request(request);
    if (scheduled.rpc.action.empty()) {
        respond(missing_action_response(scheduled));
        return true;
    }

    exv::core_api::LaneWorkItem item;
    item.request = scheduled.rpc;
    const bool use_core_handler =
        is_core_owned_control_action(item.request.action);
    const bool use_desktop_handler =
        !use_core_handler &&
        (scheduled.is_desktop ||
         is_desktop_backed_native_action(item.request.action));
    item.metadata = use_core_handler
        ? dispatcher.metadata_for(item.request.action)
              .value_or(exv::core_api::default_metadata_for_action(
                  item.request.action))
        : use_desktop_handler
        ? exv::core_api::default_metadata_for_action(item.request.action)
        : dispatcher.metadata_for(item.request.action)
              .value_or(exv::core_api::default_metadata_for_action(
                  item.request.action));

    const bool is_desktop = scheduled.is_desktop;
    const int desktop_id = scheduled.desktop_id;
    item.handler = [&dispatcher, use_desktop_handler](
                       const exv::core_api::RpcRequest& rpc_request) {
        if (use_desktop_handler) {
            return dispatch_desktop_as_rpc(rpc_request);
        }
        return dispatcher.dispatch(rpc_request);
    };
    item.respond = [respond = std::move(respond), is_desktop, desktop_id](
                       exv::core_api::RpcResponse response) mutable {
        respond(is_desktop ? desktop_wire_response(desktop_id, response)
                           : native_wire_response(response));
    };

    if (scheduler.schedule(std::move(item))) {
        return true;
    }

    json error = scheduled.is_desktop
        ? json{{"id", scheduled.desktop_id},
               {"ok", false},
               {"code", "scheduler_stopped"},
               {"message", "Core RPC scheduler is stopped"}}
        : json{{"request_id", scheduled.rpc.request_id},
               {"success", false},
               {"error_code", "scheduler_stopped"},
               {"error_message", "Core RPC scheduler is stopped"}};
    respond(error);
    return false;
}

// Supported request envelopes:
// - Desktop envelope: id/action/payload -> id/ok/data or id/ok/code/message.
//   This keeps Electron and CLI pipe clients on the legacy app_api surface.
// - Core native envelope: action/payload_json/request_id ->
//   success/payload_json or error_code/error_message.  This routes through
//   AppRpcDispatcher while sharing the same use-case services as desktop.
static json handle_request_json(exv::core_api::AppRpcDispatcher& dispatcher,
                                const json& request) {
    if (is_native_core_request(request)) {
        return native_core_response(dispatcher, request);
    }
    return handle_desktop_request_json(request);
}

static std::string handle_request_line(exv::core_api::AppRpcDispatcher& dispatcher,
                                       const std::string& request_line) {
    try {
        return handle_request_json(dispatcher, json::parse(request_line)).dump();
    } catch (const json::parse_error& e) {
        json err = {
            {"id", 0},
            {"ok", false},
            {"code", "parse_error"},
            {"message", std::string("Invalid JSON: ") + e.what()}
        };
        return err.dump();
    } catch (const std::exception& e) {
        json err = {
            {"id", 0},
            {"ok", false},
            {"code", "internal_error"},
            {"message", e.what()}
        };
        return err.dump();
    }
}

static std::string handle_request_line_sync(
    exv::core_api::AppRpcDispatcher& dispatcher,
    const std::string& request_line) {
    return handle_request_line(dispatcher, request_line);
}

static std::string schedule_request_line_sync(
    exv::core_api::AppRpcDispatcher& dispatcher,
    exv::core_api::LaneScheduler& scheduler,
    const std::string& request_line) {
    try {
        std::promise<std::string> response_promise;
        auto response_future = response_promise.get_future();
        schedule_request_json(
            dispatcher, scheduler, json::parse(request_line),
            [&response_promise](json response) mutable {
                response_promise.set_value(response.dump());
            });
        return response_future.get();
    } catch (const json::parse_error& e) {
        json err = {
            {"id", 0},
            {"ok", false},
            {"code", "parse_error"},
            {"message", std::string("Invalid JSON: ") + e.what()}
        };
        return err.dump();
    } catch (const std::exception& e) {
        json err = {
            {"id", 0},
            {"ok", false},
            {"code", "internal_error"},
            {"message", e.what()}
        };
        return err.dump();
    }
}

static std::optional<exv::core::lifecycle::CoreRegistrySnapshot>
bootstrap_registry_snapshot(exv::core_api::AppRpcDispatcher& dispatcher,
                            const std::string& pipe_path) {
    exv::core_api::RpcRequest request;
    request.action = "core.hello";
    request.request_id = "core-process-bootstrap";
    request.payload_json = "{}";

    auto response = dispatcher.dispatch(request);
    if (!response.success) {
        return std::nullopt;
    }

    try {
        return exv::core::lifecycle::core_registry_snapshot_from_hello(
            json::parse(response.payload_json), pipe_path);
    } catch (...) {
        return std::nullopt;
    }
}

// ------------------------------------------------------------------
// core_process_main
// ------------------------------------------------------------------

int core_process_main(const std::string& config_dir,
                      const std::string& home_dir,
                      bool use_stdin)
{
    g_stop_requested.store(false);

    // 0. Ensure stdout/stdin are in text mode and unbuffered for pipe communication
#ifdef _WIN32
    // Use text mode (not binary) for proper line handling with Node.js pipes
    _setmode(_fileno(stdout), _O_TEXT);
    _setmode(_fileno(stdin), _O_TEXT);
    // Also set stderr to text mode for debug output
    _setmode(_fileno(stderr), _O_TEXT);
#endif
    // Keep the current C++ stream buffers intact; lifecycle tests replace
    // std::cin/std::cout rdbufs to exercise core_process_main() in-process.
    // Enable unbuffered output - critical for real-time pipe communication
    std::cout.setf(std::ios::unitbuf);
    // Also unbuffer stderr for immediate debug output
    std::cerr.setf(std::ios::unitbuf);

    // 1. Bootstrap runtime paths
    exv::runtime::bootstrap(config_dir, home_dir, true);

    // 2. Initialize logger
    exv::platform::logging::configure_default_logging(false);

    // 2b. Instantiate LogRenderer so typed events reach the disk file.
    // Must live for the lifetime of the core process.
    exv::LogRenderer log_renderer;

    exv::observability::LogFacade::info("Core process starting (mode=core, use_stdin=" + std::string(use_stdin ? "true" : "false") + ")");

    const auto startup_config =
        exv::config::ensure_initialized_config(config_dir);

    // 3. Install signal handlers for graceful shutdown
    std::signal(SIGINT,  core_signal_handler);
    std::signal(SIGTERM, core_signal_handler);
#ifndef _WIN32
    // SIGPIPE is irrelevant — we write to stdout, not a pipe
    std::signal(SIGPIPE, SIG_IGN);
#endif

    auto core_lock = exv::core::lifecycle::CoreInstanceLock::try_acquire();
    if (!core_lock.has_value()) {
        log_startup_fatal(
            "core_lock_busy",
            "another core process already owns the versioned core lock at " +
                exv::core::lifecycle::core_lock_path());
        std::cerr << "fatal: another core process already owns the versioned core lock"
                  << std::endl;
        return 1;
    }

    // The native dispatcher receives a shell controller for non-desktop-backed
    // actions (e.g. vpn.set_auto_reconnect).  Desktop-backed VPN actions are
    // intercepted and routed to app_api, which resolves the live controller via
    // tunnel_use_cases().  The registry worker also observes the live controller
    // through tunnel_use_cases() so it sees real tunnel state instead of the
    // idle shell.
    auto shell_controller = std::make_shared<TunnelController>(
        std::shared_ptr<exv::helper::HelperClient>{},
        std::shared_ptr<exv::platform::PlatformNetworkOps>{},
        ReconnectConfig{});
    auto native_dispatcher = exv::core_api::create_dispatcher(shell_controller);
    native_dispatcher->register_handler(
        "core.shutdown",
        [](const exv::core_api::RpcRequest& req) {
            (void)req;
            g_stop_requested.store(true);
            exv::core_api::RpcResponse resp;
            resp.success = true;
            resp.payload_json = R"({"ok":true})";
            return resp;
        });
    exv::core_api::LaneScheduler lane_scheduler;
    lane_scheduler.start();
    auto dispatch_line = [&](const std::string& request_line) {
        return schedule_request_line_sync(*native_dispatcher, lane_scheduler,
                                          request_line);
    };

    const auto pipe_path = core_pipe_path();

    // 5. Create pipe listener for CLI connections after owning the versioned lock.
    auto pipe_listener = std::make_unique<PipeIpcListener>(pipe_path);
    if (!pipe_listener->start()) {
        log_startup_fatal(
            "pipe_bind_failed",
            "could not bind versioned core IPC endpoint '" + pipe_path + "'");
        std::cerr << "fatal: another core process is already running (pipe '"
                  << pipe_path << "' is in use)" << std::endl;
        return 1;
    }

    auto registry_snapshot =
        bootstrap_registry_snapshot(*native_dispatcher, pipe_path);
    if (!registry_snapshot.has_value()) {
        log_startup_fatal("registry_bootstrap_failed",
                          "could not initialize versioned core registry");
        std::cerr << "fatal: could not initialize versioned core registry"
                  << std::endl;
        pipe_listener->stop();
        return 1;
    }

    const auto registry_path = exv::core::lifecycle::core_registry_path();
    std::mutex registry_mutex;
    std::optional<exv::core::lifecycle::CoreRegistrySnapshot>
        last_persisted_registry_snapshot;
    int registry_persist_attempt = 0;
    auto persist_registry = [&](const std::optional<TunnelStatusSnapshot>& status) {
        std::lock_guard<std::mutex> lock(registry_mutex);
        auto candidate = *registry_snapshot;
        if (status.has_value()) {
            exv::core::lifecycle::apply_tunnel_status(candidate,
                                                      *status);
        }

        // Observe the live controller (if one exists) for helper lease state.
        // Do not send Inspect until the controller has completed the initial
        // Hello/CoreLease sequence; a one-shot helper requires Hello as the
        // first request on its only client connection.
        auto live_controller = exv::core::tunnel_use_cases().controller_if_exists();
        std::optional<TunnelStatusSnapshot> helper_status_for_registry = status;
        if (live_controller) {
            auto live_status = live_controller->status();
            if (!helper_status_for_registry.has_value() ||
                live_status.core_lease_active) {
                helper_status_for_registry = live_status;
            }
        }
        candidate.helper_core_lease_id.clear();
        if (should_inspect_helper_for_registry(helper_status_for_registry)) {
            auto helper = live_controller
                ? live_controller->helper_client_for_maintenance()
                : nullptr;
            if (helper && helper->is_connected()) {
                try {
                    const auto inspect =
                        helper->inspect(exv::helper::InspectRequest{});
                    if (inspect.core_lease.active) {
                        candidate.helper_core_lease_id =
                            inspect.core_lease.lease_id;
                    }
                } catch (...) {
                    candidate.helper_core_lease_id.clear();
                }
            }
        }

        exv::core::lifecycle::refresh_core_registry_heartbeat(candidate);
        ++registry_persist_attempt;
        auto& hook = testing::core_registry_persist_candidate_hook();
        if (hook) {
            hook(candidate, registry_persist_attempt);
        }
        if (!exv::core::lifecycle::write_core_registry(candidate,
                                                       registry_path)) {
            return false;
        }
        registry_snapshot = candidate;
        last_persisted_registry_snapshot = candidate;
        return true;
    };

    struct PendingStatusEvent {
        std::optional<TunnelStatusSnapshot> snapshot;
    };

    const bool status_events_enabled = use_stdin;
    std::mutex status_event_mutex;
    std::deque<PendingStatusEvent> pending_status_events;
    auto enqueue_status_event = [&](PendingStatusEvent event) {
        if (!status_events_enabled) {
            return;
        }
        std::lock_guard<std::mutex> lock(status_event_mutex);
        pending_status_events.push_back(std::move(event));
    };

    auto load_status_config = [&]() {
        exv::config::ConfigManager mgr(exv::platform::get_config_dir());
        return mgr.load();
    };

    auto make_status_event_from_snapshot =
        [&](const TunnelStatusSnapshot& snapshot) {
            auto cfg = load_status_config();
            auto status =
                exv::app_api::frontend_status_from_controller_snapshot(
                    snapshot, cfg);
            exv::app_api::apply_desktop_connect_job_status(&status, true);
            exv::app_api::apply_desktop_connect_error(&status);
            return status;
        };

    auto make_status_event_from_latest_runtime = [&]() {
        if (auto controller =
                exv::core::tunnel_use_cases().controller_if_exists();
            controller) {
            return make_status_event_from_snapshot(controller->status());
        }
        if (auto latest = exv::core::tunnel_use_cases().latest_status();
            latest.has_value()) {
            return make_status_event_from_snapshot(*latest);
        }
        auto cfg = load_status_config();
        auto status = exv::app_api::disconnected_status(cfg);
        exv::app_api::apply_desktop_connect_job_status(&status, false);
        exv::app_api::apply_desktop_connect_error(&status);
        return status;
    };

    auto status_observer_id =
        exv::core::tunnel_use_cases().add_status_observer(
            [&](const TunnelStatusSnapshot& status) {
                if (!persist_registry(status)) {
                    exv::observability::LogFacade::warn(
                        "Core process could not refresh the versioned core registry after status update");
                }
                enqueue_status_event(PendingStatusEvent{status});
            });

    auto connect_job_observer_id =
        exv::core::tunnel_use_cases().add_connect_job_observer(
            [&](const exv::core::VpnConnectJobState&) {
                enqueue_status_event(PendingStatusEvent{std::nullopt});
            });

    struct TunnelUseCaseObserverGuard {
        exv::core::TunnelUseCases::StatusObserverId status_id = 0;
        exv::core::TunnelUseCases::ConnectJobObserverId connect_job_id = 0;

        ~TunnelUseCaseObserverGuard() {
            reset();
        }

        void reset() {
            if (status_id != 0) {
                exv::core::tunnel_use_cases().remove_status_observer(status_id);
                status_id = 0;
            }
            if (connect_job_id != 0) {
                exv::core::tunnel_use_cases().remove_connect_job_observer(
                    connect_job_id);
                connect_job_id = 0;
            }
        }
    } use_case_observers{status_observer_id, connect_job_observer_id};

    if (!persist_registry(shell_controller->status())) {
        log_startup_fatal(
            "registry_persist_failed",
            "Core process could not persist the versioned core registry; aborting startup");
        pipe_listener->stop();
        return 1;
    }

    std::atomic<bool> registry_worker_stop{false};
    std::thread registry_worker([&] {
        while (!registry_worker_stop.load() && !g_stop_requested.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (registry_worker_stop.load() || g_stop_requested.load()) {
                break;
            }
            if (!persist_registry(std::nullopt)) {
                exv::observability::LogFacade::warn(
                    "Core process could not refresh the versioned core registry heartbeat");
            }
        }
    });

    exv::observability::LogFacade::info(
        "Core process ready — reading JSON-RPC from stdin and pipe");

    // 8. Main event loop: read JSON-RPC requests from stdin and pipe, one per line
    std::string line;

    // Daemon mode (pipe-only) when use_stdin=false
    bool stdin_available = use_stdin;

    std::atomic<bool> pipe_worker_stop{false};
    std::thread pipe_worker;

    if (!stdin_available) {
        exv::observability::LogFacade::info("Core process: running in daemon mode (pipe-only)");
    } else {
        pipe_worker = std::thread([&] {
            while (!pipe_worker_stop.load() && !g_stop_requested.load()) {
                pipe_listener->accept_one(dispatch_line);
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
    }

    std::atomic<bool> status_event_worker_stop{false};
    std::thread status_event_worker;
    if (stdin_available) {
        status_event_worker = std::thread([&] {
            while (!status_event_worker_stop.load() &&
                   !g_stop_requested.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                if (status_event_worker_stop.load() ||
                    g_stop_requested.load()) {
                    break;
                }

                std::deque<PendingStatusEvent> pending_events;
                {
                    std::lock_guard<std::mutex> lock(status_event_mutex);
                    pending_events.swap(pending_status_events);
                }

                for (const auto& pending : pending_events) {
                    try {
                        const auto status =
                            pending.snapshot.has_value()
                                ? make_status_event_from_snapshot(
                                      *pending.snapshot)
                                : make_status_event_from_latest_runtime();
                        write_json_line(json{{"event", "status"},
                                             {"data", status}});
                    } catch (const std::exception& e) {
                        exv::observability::LogFacade::warn(
                            std::string("Core process could not build live status event: ") +
                            e.what());
                    }
                }

                auto virtual_network_events =
                    exv::app_api::drain_virtual_network_status_events();
                if (pending_events.empty() && virtual_network_events.empty()) {
                    continue;
                }
                for (const auto& event : virtual_network_events) {
                    write_json_line(json{{"event", "status"},
                                         {"data", event}});
                }
            }
        });
    }

    if (stdin_available && startup_config.should_request_quick_start()) {
        write_json_line(json{{"event", "quick-start-request"},
                             {"data", exv::config::quick_start_request_data(
                                          startup_config)}});
    }

    while (!g_stop_requested.load()) {
        // In daemon mode, just process pipe connections in a loop
        if (!stdin_available) {
            pipe_listener->accept_one(dispatch_line);
            // Sleep briefly to avoid busy-waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        if (!std::getline(std::cin, line)) {
            exv::observability::LogFacade::info("Core process: stdin EOF, shutting down");
            break;
        }


        // Skip empty lines
        if (line.empty() || line.find_first_not_of(" \t\r\n") == std::string::npos) {
            // Process pipe connections even on empty lines
            pipe_listener->accept_one(dispatch_line);
            continue;
        }

        json response;

        try {
            json request = json::parse(line);
            schedule_request_json(
                *native_dispatcher, lane_scheduler, request,
                [](json scheduled_response) {
                    write_json_line(scheduled_response);
                });
        } catch (const json::parse_error& e) {
            response = {
                {"id",      0},
                {"ok",      false},
                {"code",    "parse_error"},
                {"message", std::string("Invalid JSON: ") + e.what()}
            };
            write_json_line(response);
        } catch (const std::exception& e) {
            response = {
                {"id",      0},
                {"ok",      false},
                {"code",    "internal_error"},
                {"message", e.what()}
            };
            write_json_line(response);
        }

        // Note: In stdin mode, we don't process pipe connections here.
        // Pipe processing is only needed in daemon mode (handled above in the !stdin_available block).
        // Calling accept_one() here would block the stdin read loop.
    }

    registry_worker_stop.store(true);
    use_case_observers.reset();
    if (registry_worker.joinable()) {
        registry_worker.join();
    }

    pipe_worker_stop.store(true);
    if (pipe_worker.joinable()) {
        pipe_worker.join();
    }
    status_event_worker_stop.store(true);
    if (status_event_worker.joinable()) {
        status_event_worker.join();
    }
    lane_scheduler.stop();
    exv::app_api::shutdown_desktop_vpn_runtime();
    pipe_listener->stop();

    std::optional<exv::core::lifecycle::CoreRegistryDeleteMatch> delete_match;
    {
        std::lock_guard<std::mutex> lock(registry_mutex);
        if (last_persisted_registry_snapshot.has_value()) {
            delete_match = exv::core::lifecycle::core_registry_delete_match(
                *last_persisted_registry_snapshot);
        }
    }
    if (delete_match.has_value()) {
        (void)exv::core::lifecycle::compare_and_delete_core_registry(
            registry_path, *delete_match);
    }

    exv::observability::LogFacade::info("Core process shutting down");
    return 0;
}

} // namespace exv::core

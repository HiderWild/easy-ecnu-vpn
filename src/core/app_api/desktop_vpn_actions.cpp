#include "core/app_api/desktop_vpn_actions.hpp"

#include "core/app_api/auth_interaction_coordinator.hpp"
#include "core/app_api/desktop_json.hpp"
#include "core/app_api/desktop_runtime_context.hpp"
#include "core/app_api/desktop_status_presenter.hpp"
#include "core/app_api/desktop_tunnel_host.hpp"
#include "core/app_api/desktop_vpn_test_hooks.hpp"
#include "core/config/config_manager.hpp"
#include "core/config/config_platform_view.hpp"
#include "core/connection/connection_attempt.hpp"
#include "core/crypto/crypto.hpp"
#include "core/rpc/desktop_rpc_adapter.hpp"
#include "core/tunnel_controller/connect_pipeline.hpp"
#include "core/tunnel_controller/engine_event_bridge.hpp"
#include "core/tunnel_controller/native_engine_config_mapper.hpp"
#include "core/tunnel_controller/timing.hpp"
#include "core/tunnel_controller/tunnel_controller.hpp"
#include "core/tunnel_controller/vpn_connect_job.hpp"
#include "core/use_cases/tunnel_use_cases.hpp"
#include "helper/common/helper_client.hpp"
#include "helper/common/helper_connector.hpp"
#include "observability/log_facade.hpp"
#include "platform/common/logging/log_runtime.hpp"
#include "platform/common/app_api_runtime_policy.hpp"
#include "platform/common/backend_resolver.hpp"
#include "platform/common/file_system.hpp"
#include "platform/common/helper_client.hpp"
#include "platform/common/process_control.hpp"
#include "platform/common/process_utils.hpp"
#include "platform/common/runtime_paths.hpp"
#include "vpn_engine/native_handshake_job.hpp"

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace exv {
namespace app_api {

namespace testing {
namespace {
std::mutex g_hook_mutex;
DesktopVpnConnectEnteredHook g_connect_entered_hook;
} // namespace

void set_desktop_vpn_connect_entered_hook(DesktopVpnConnectEnteredHook hook) {
  std::lock_guard<std::mutex> lock(g_hook_mutex);
  g_connect_entered_hook = std::move(hook);
}

void fire_desktop_vpn_connect_entered_hook() {
  DesktopVpnConnectEnteredHook hook;
  {
    std::lock_guard<std::mutex> lock(g_hook_mutex);
    hook = g_connect_entered_hook;
  }
  if (hook) {
    hook();
  }
}

} // namespace testing

namespace {

using StageTimer = exv::core::ConnectStageTimer;

// The connect-job owner and connect-error state were relocated to
// exv::core::TunnelUseCases so that the use-case layer owns all tunnel runtime
// state.  The file-local helper functions below delegate to the shared
// tunnel_use_cases() singleton.

config::ConfigManager make_config_manager() {
  platform::ensure_dir(platform::get_config_dir());
  exv::platform::logging::configure_default_logging(false);
  return config::ConfigManager(platform::get_config_dir());
}

nlohmann::json preflight_connect(const Config &cfg,
                                 const std::string &password) {
  StageTimer timing("desktop.preflight_connect");
  if (cfg.vpn_engine != "native") {
    timing.finish(false, "stage=config_validation code=legacy_engine_removed");
    return error("VPN engine is native-only.", "legacy_engine_removed");
  }
  if (cfg.server.empty()) {
    timing.finish(false, "stage=config_validation code=server_missing");
    return error("VPN server is not configured.");
  }
  if (cfg.username.empty()) {
    timing.finish(false, "stage=config_validation code=username_missing");
    return error("VPN username is not configured.");
  }
  if (password.empty()) {
    timing.finish(false, "stage=config_validation code=password_missing");
    return error("VPN password is not configured.");
  }

  auto native_validation = exv::core::validate_native_app_config(cfg);
  if (!native_validation.ok) {
    timing.finish(false, "stage=config_validation code=" +
                             native_validation.code);
    return error(native_validation.message, native_validation.code);
  }
  timing.mark("config_validated", "engine=" + cfg.vpn_engine);

  platform::BackendResolveOptions options;
  options.preferred_mode = "auto";
  options.allow_oneshot = true;
  options.start_oneshot = true;
  options.allow_service_start = false;
  options.helper_path = helper_binary_next_to_exv();
  timing.mark("backend_resolve_started", "mode=auto");
  nlohmann::json backend = platform::resolve_backend(options);
  const bool backend_ok = backend.value("ok", false);
  const std::string backend_mode = backend.value("mode", "unknown");
  timing.mark("backend_resolved",
              "ok=" + std::string(backend_ok ? "true" : "false") +
                  " mode=" + backend_mode);
  exv::observability::LogFacade::info(
      "app_api: preflight backend resolved - ok=" +
      std::string(backend_ok ? "true" : "false") +
      " mode=" + backend_mode);
  if (!backend.value("ok", false)) {
    timing.finish(false,
                  "stage=backend_resolved code=" +
                      backend.value("code", platform::kHelperUnavailableCode));
    return platform::backend_unavailable_error(
        backend, platform::helper_unavailable_connect_message());
  }

  nlohmann::json runtime = runtime_status_json(cfg);
  const bool runtime_available = runtime.value("available", false);
  timing.mark("runtime_status_checked",
              "available=" +
                  std::string(runtime_available ? "true" : "false"));
  exv::observability::LogFacade::info(
      "app_api: preflight runtime status - available=" +
      std::string(runtime_available ? "true" : "false"));
  if (!runtime_available) {
    timing.finish(false, "stage=runtime_status_checked");
    return error("VPN runtime is not available. The desktop bundle is missing "
                 "the selected VPN engine dependencies.");
  }

  nlohmann::json platform_err =
      platform::preflight_connect_platform_checks(
          config::to_platform_config_view(cfg));
  const bool platform_ok =
      !platform_err.is_object() || platform_err.value("ok", true);
  timing.mark("platform_checks_checked",
              "ok=" + std::string(platform_ok ? "true" : "false"));
  exv::observability::LogFacade::info(
      "app_api: preflight platform checks - ok=" +
      std::string(platform_ok ? "true" : "false"));
  if (!platform_ok) {
    timing.finish(false,
                  "stage=platform_checks_checked code=" +
                      platform_err.value("code", std::string("unknown")));
    return platform_err;
  }

  nlohmann::json result;
  result["ok"] = true;
  result["backend"] = backend;
  timing.finish(true, "stage=preflight_complete");
  return result;
}

nlohmann::json quick_validate_connect(const Config &cfg,
                                      const std::string &password) {
  if (cfg.vpn_engine != "native") {
    return error("VPN engine is native-only.", "legacy_engine_removed");
  }
  if (cfg.server.empty()) {
    return error("VPN server is not configured.");
  }
  if (cfg.username.empty()) {
    return error("VPN username is not configured.");
  }
  if (password.empty()) {
    return error("VPN password is not configured.");
  }
  auto native_validation = exv::core::validate_native_app_config(cfg);
  if (!native_validation.ok) {
    return error(native_validation.message, native_validation.code);
  }
  return nlohmann::json{{"ok", true}};
}

nlohmann::json connect_state_json(const exv::core::VpnConnectJobState &state) {
  nlohmann::json out;
  out["accepted"] = state.accepted;
  out["phase"] = state.phase.empty() ? "connecting" : state.phase;
  out["job_id"] = state.job_id;
  out["active_job_id"] = state.job_id;
  out["active"] = state.active;
  out["coalesced"] = state.coalesced;
  out["cancelling"] = state.cancelling;
  out["user_cancelled"] = state.user_cancelled;
  out["desired_connected"] = state.desired_connected;
  out["intent_epoch"] = state.intent_epoch;
  if (!state.last_error_code.empty()) {
    out["last_error"] = {{"code", state.last_error_code},
                         {"message", state.last_error_message}};
  }
  return out;
}

void clear_desktop_connect_error() {
  exv::core::tunnel_use_cases().clear_connect_error();
}

void set_desktop_connect_error(nlohmann::json failure) {
  exv::core::tunnel_use_cases().set_connect_error(std::move(failure));
}

std::optional<nlohmann::json> desktop_connect_error() {
  return exv::core::tunnel_use_cases().connect_error();
}

struct PreparedHandshakeHolder {
  ~PreparedHandshakeHolder() {
    std::lock_guard<std::mutex> lock(mutex);
    if (!ready) return;
    if (handshake.session) {
      handshake.session->disconnect();
    } else if (handshake.transport) {
      handshake.transport->disconnect();
    }
  }

  exv::vpn_engine::NativeHandshakeResult take_handshake() {
    ready = false;
    return std::move(handshake);
  }

  std::mutex mutex;
  exv::vpn_engine::VpnEngineConfig engine_config;
  exv::vpn_engine::NativeHandshakeResult handshake;
  bool ready = false;
};

void apply_desktop_connect_error(nlohmann::json *status) {
  if (!status) return;
  auto failure = desktop_connect_error();
  if (!failure || !failure->is_object()) return;
  (*status)["error"] = json_string(*failure, "error",
                                   json_string(*failure, "message"));
  (*status)["error_code"] =
      json_string(*failure, "code", json_string(*failure, "error_code"));
  (*status)["error_recoverable"] = json_bool(*failure, "recoverable", true);
  (*status)["recommended_action"] =
      json_string(*failure, "recommended_action");
}

void apply_desktop_connect_job_status(nlohmann::json *status) {
  if (!status) return;
  auto state = exv::core::tunnel_use_cases().connect_jobs().snapshot();
  if (!state.active || !state.desired_connected) {
    return;
  }

  (*status)["connected"] = false;
  (*status)["process_running"] = true;
  (*status)["network_ready"] = false;
  (*status)["phase"] = state.phase.empty() ? "connecting" : state.phase;
  (*status)["connect_job_id"] = state.job_id;
  (*status)["connect_intent_epoch"] = state.intent_epoch;
  (*status)["connect_cancelling"] = state.cancelling;
}

void cleanup_unused_oneshot_backend(const nlohmann::json &backend) {
  if (!backend.is_object() || backend.value("mode", std::string()) != "oneshot") {
    return;
  }
  const std::string endpoint = backend.value("endpoint", std::string());
  if (endpoint.empty()) {
    return;
  }

  try {
    auto connector = exv::helper::HelperConnector::create();
    exv::helper::HelperConnectorConfig config;
    config.mode = exv::helper::ConnectorMode::Transient;
    config.pipe_endpoint = endpoint;
    config.connect_timeout_ms = 1000;
    auto client = connector->connect(config);
    if (!client) {
      exv::observability::LogFacade::warn(
          "app_api: unused oneshot helper cleanup could not connect");
      return;
    }
    (void)client->hello(exv::helper::HelloRequest{});
    client->disconnect();
    exv::observability::LogFacade::info(
        "app_api: unused oneshot helper cleanup requested");
  } catch (const std::exception &e) {
    exv::observability::LogFacade::warn(
        std::string("app_api: unused oneshot helper cleanup failed - ") +
        e.what());
  }
}

void run_desktop_connect_job(Config cfg,
                             std::string password,
                             std::string attempt_id,
                             std::stop_token stop) {
  StageTimer timing("desktop.connect.background");
  timing.mark("background_job_started",
              attempt_id.empty() ? "attempt_id=none" : "attempt_id=present");
  testing::fire_desktop_vpn_connect_entered_hook();
  if (stop.stop_requested()) {
    return;
  }

  namespace conn_attempt = exv::connection_attempt;
  conn_attempt::TerminalAttemptScope attempt_cleanup(
      platform::get_config_dir(), attempt_id, "scope_exit");

  auto prepared_handshake = std::make_shared<PreparedHandshakeHolder>();
  exv::core::ConnectPipeline pipeline(
      "desktop-connect",
      [](const exv::core::ConnectBranchResult &late,
         std::string_view first_code) {
        exv::observability::LogFacade::info(
            "app_api: late connect branch failure - branch=" +
            std::string(exv::core::connect_branch_name(late.branch)) +
            " code=" + late.code + " first_code=" + std::string(first_code));
      });

  auto backend_branch = [attempt_id](
                             [[maybe_unused]] std::stop_token branch_stop) {
    StageTimer branch_timing("desktop.connect.backend_helper_ready");
    platform::BackendResolveOptions options;
    options.preferred_mode = "auto";
    options.allow_oneshot = true;
    options.start_oneshot = true;
    options.allow_service_start = false;
    options.helper_path = helper_binary_next_to_exv();

    branch_timing.mark("backend_resolve_started",
                       "preferred_mode=auto allow_oneshot=true");
    nlohmann::json backend = platform::resolve_backend(options);
    const bool backend_ok = backend.value("ok", false);
    exv::observability::LogFacade::info(
        "app_api: preflight backend resolved - ok=" +
        std::string(backend_ok ? "true" : "false") +
        " mode=" + backend.value("mode", std::string("unknown")));
    if (!backend_ok) {
      branch_timing.finish(false,
                           "code=" + backend.value(
                                         "code",
                                         platform::kHelperUnavailableCode));
      return exv::core::ConnectBranchResult{
          exv::core::ConnectBranch::BackendHelperReady,
          false,
          backend.value("code", platform::kHelperUnavailableCode),
          backend.value("message",
                        platform::helper_unavailable_connect_message()),
          backend};
    }
    conn_attempt::update_pids_if_current(
        platform::get_config_dir(), attempt_id, backend.value("pid", -1));
    if (branch_stop.stop_requested()) {
      cleanup_unused_oneshot_backend(backend);
      branch_timing.finish(false, "code=cancelled");
      return exv::core::ConnectBranchResult{
          exv::core::ConnectBranch::BackendHelperReady,
          false,
          "cancelled",
          "Backend helper readiness cancelled",
          nlohmann::json::object()};
    }
    branch_timing.finish(true,
                         "mode=" + backend.value("mode", std::string("unknown")));
    return exv::core::ConnectBranchResult{
        exv::core::ConnectBranch::BackendHelperReady, true, {}, {}, backend};
  };

  auto platform_branch = [cfg](std::stop_token branch_stop) {
    StageTimer branch_timing("desktop.connect.platform_ready");
    if (branch_stop.stop_requested()) {
      branch_timing.finish(false, "code=cancelled");
      return exv::core::ConnectBranchResult{
          exv::core::ConnectBranch::PlatformReady,
          false,
          "cancelled",
          "Platform checks cancelled",
          nlohmann::json::object()};
    }

    branch_timing.mark("runtime_status_check_started");
    nlohmann::json runtime = runtime_status_json(cfg);
    if (!runtime.value("available", false)) {
      branch_timing.finish(false, "code=runtime_unavailable");
      return exv::core::ConnectBranchResult{
          exv::core::ConnectBranch::PlatformReady,
          false,
          "runtime_unavailable",
          "VPN runtime is not available. The desktop bundle is missing the "
          "selected VPN engine dependencies.",
          nlohmann::json{{"runtime", runtime}}};
    }

    branch_timing.mark("platform_checks_started");
    nlohmann::json platform_err =
        platform::preflight_connect_platform_checks(
            config::to_platform_config_view(cfg));
    const bool platform_ok =
        !platform_err.is_object() || platform_err.value("ok", true);
    exv::observability::LogFacade::info(
        "app_api: preflight platform checks - ok=" +
        std::string(platform_ok ? "true" : "false"));
    if (!platform_ok) {
      branch_timing.finish(
          false,
          "code=" +
              platform_err.value("code", std::string("platform_checks_failed")));
      return exv::core::ConnectBranchResult{
          exv::core::ConnectBranch::PlatformReady,
          false,
          platform_err.value("code", std::string("platform_checks_failed")),
          platform_err.value("message",
                             platform_err.value("error",
                                                std::string("Platform checks failed"))),
          platform_err};
    }

    branch_timing.finish(true, "stage=platform_checks_checked");
    return exv::core::ConnectBranchResult{
        exv::core::ConnectBranch::PlatformReady,
        true,
        {},
        {},
        nlohmann::json{{"runtime", runtime}, {"platform", platform_err}}};
  };

  auto protocol_branch = [cfg, password, prepared_handshake](
                              std::stop_token branch_stop) mutable {
    StageTimer branch_timing("desktop.connect.protocol_handshake");
    exv::vpn_engine::VpnEngineConfig engine_config;
    branch_timing.mark("native_config_mapping_started");
    auto mapped =
        exv::core::make_native_engine_config(cfg, password, &engine_config);
    if (!mapped.ok) {
      branch_timing.finish(false, "code=" + mapped.code);
      return exv::core::ConnectBranchResult{
          exv::core::ConnectBranch::ProtocolHandshake,
          false,
          mapped.code,
          mapped.message,
          nlohmann::json::object()};
    }

    auto deps = exv::vpn_engine::default_native_engine_dependencies();
    // Reuse EngineEventBridge as a log-only sink: the prepared-handshake job
    // still emits auth.started / auth.failed / cstp.failed events even though
    // we are not adopting a runner yet. Without a sink they vanish, leaving
    // operators with no log trail for the most common failure layer of a real
    // connect attempt. The bridge already filters noisy events, classifies
    // severity, and redacts secret-bearing message and field text — passing
    // nullptr as the TunnelEvent callback turns it into a pure log emitter
    // without any controller coupling. See
    // docs/AGGREGATE_AUTH_EMPTY_RESPONSE_FIX_PLAN.md §5.
    exv::core::EngineEventBridge protocol_event_logger(nullptr);
    deps.event_sink = &protocol_event_logger;

    // Auth-interaction coordinator for the prepared-handshake window. The
    // gateway can demand group_select or challenge before any TunnelController
    // is initialized; without a handler the production_transport layer fails
    // immediately with auth_group_required / auth_challenge_required and the
    // user has no way to continue. Publish a coordinator into the connect-job
    // global slot so vpn.authInteraction.get / vpn.authInteraction.respond
    // can drive the prompt to completion before the runner adopts. See
    // docs/AGGREGATE_AUTH_EMPTY_RESPONSE_FIX_PLAN.md §6.
    auto auth_coordinator =
        std::make_shared<exv::app_api::AuthInteractionCoordinator>();
    exv::app_api::set_active_connect_auth_coordinator(auth_coordinator);
    struct AuthCoordinatorClearGuard {
      explicit AuthCoordinatorClearGuard(
          std::shared_ptr<exv::app_api::AuthInteractionCoordinator>
              coordinator_value)
          : coordinator(std::move(coordinator_value)) {}

      ~AuthCoordinatorClearGuard() {
        if (coordinator) {
          coordinator->cancel();
          exv::app_api::clear_active_connect_auth_coordinator_if_current(
              coordinator);
        }
      }

      std::shared_ptr<exv::app_api::AuthInteractionCoordinator>
          coordinator;
    } auth_coordinator_clear_guard(auth_coordinator);
    deps.auth_interaction_handler =
        [auth_coordinator, branch_stop](
            const exv::vpn_engine::protocol::AuthInteractionRequest &req) {
          return auth_coordinator->handle(req, branch_stop);
        };

    exv::vpn_engine::NativeHandshakeResult handshake;
    exv::vpn_engine::NativeHandshakeJob job(engine_config, deps);
    branch_timing.mark("native_handshake_started");
    auto result = job.run(branch_stop, &handshake);
    if (!result.ok) {
      branch_timing.finish(false, "code=" + result.code);
      return exv::core::ConnectBranchResult{
          exv::core::ConnectBranch::ProtocolHandshake,
          false,
          result.code,
          result.message,
          nlohmann::json::object()};
    }
    if (branch_stop.stop_requested()) {
      if (handshake.session) {
        handshake.session->disconnect();
      } else if (handshake.transport) {
        handshake.transport->disconnect();
      }
      branch_timing.finish(false, "code=cancelled");
      return exv::core::ConnectBranchResult{
          exv::core::ConnectBranch::ProtocolHandshake,
          false,
          "cancelled",
          "Protocol handshake cancelled",
          nlohmann::json::object()};
    }

    nlohmann::json payload{
        {"interface", handshake.metadata.interface_name},
        {"internal_ip", handshake.metadata.internal_ip4_address},
        {"mtu", handshake.metadata.mtu}};
    {
      std::lock_guard<std::mutex> lock(prepared_handshake->mutex);
      prepared_handshake->engine_config = std::move(engine_config);
      prepared_handshake->handshake = std::move(handshake);
      prepared_handshake->ready = true;
    }
    branch_timing.finish(true, "stage=cstp_connected");
    return exv::core::ConnectBranchResult{
        exv::core::ConnectBranch::ProtocolHandshake, true, {}, {}, payload};
  };

  auto pipeline_result =
      pipeline.run(std::move(backend_branch), std::move(platform_branch),
                   std::move(protocol_branch), stop);
  if (!pipeline_result.ok) {
    timing.mark("first_failure",
                "branch=" + pipeline_result.first_failure_branch +
                    " code=" + pipeline_result.code);
    timing.finish(false, "stage=connect_pipeline branch=" +
                             pipeline_result.first_failure_branch +
                             " code=" + pipeline_result.code);
    cleanup_unused_oneshot_backend(pipeline_result.backend);
    if (pipeline_result.code != "cancelled") {
      set_desktop_connect_error(
          error(pipeline_result.message.empty()
                    ? "VPN connect preflight failed."
                    : pipeline_result.message,
                pipeline_result.code.empty() ? "connect_pipeline_failed"
                                             : pipeline_result.code));
    }
    return;
  }
  timing.mark("connect_pipeline", "result=ok");
  timing.mark("serial_tail", "entered=true");

  if (stop.stop_requested()) {
    cleanup_unused_oneshot_backend(pipeline_result.backend);
    return;
  }

  std::string helper_endpoint;
  if (pipeline_result.backend.is_object()) {
    auto backend = pipeline_result.backend;
    if (!backend.value("ok", false)) {
      timing.finish(false, "stage=backend_resolution error=backend_not_ok");
      auto failure = error("Failed to resolve helper backend: " +
                               backend.value(
                                   "message",
                                   std::string("Unknown backend error")),
                           backend.value("code",
                                         platform::kHelperUnavailableCode));
      set_desktop_connect_error(failure);
      return;
    }
    helper_endpoint = backend.value("endpoint", std::string());
    timing.mark("backend_endpoint",
                helper_endpoint.empty() ? "endpoint=none"
                                        : "endpoint=extracted");
  }

  reset_tunnel_controller();
  timing.mark("reset_controller", "stale_state_cleared");

  timing.mark("tunnel_controller_init_start",
              helper_endpoint.empty() ? "endpoint=default" : "endpoint=custom");
  exv::observability::LogFacade::info(
      "app_api: Initializing TunnelController - endpoint=" +
      (helper_endpoint.empty() ? "default" : helper_endpoint));
  auto controller = ensure_tunnel_controller(helper_endpoint);
  if (controller) {
    exv::observability::LogFacade::info(
        "app_api: TunnelController initialized successfully");
  }
  timing.mark("tunnel_controller",
              controller ? "initialized=true" : "initialized=false");

  if (!controller) {
    timing.finish(false, "stage=tunnel_controller_init");
    set_desktop_connect_error(
        error("Failed to initialize VPN controller: " +
                  tunnel_controller_init_error(),
              platform::kHelperUnavailableCode));
    return;
  }

  if (stop.stop_requested()) {
    reset_tunnel_controller();
    return;
  }

  timing.mark("tunnel_controller_config_start");
  controller->set_vpn_config(cfg, password);
  {
    std::lock_guard<std::mutex> lock(prepared_handshake->mutex);
    if (!prepared_handshake->ready) {
      timing.finish(false, "stage=prepared_handshake_missing");
      set_desktop_connect_error(
          error("Native handshake did not produce a prepared session.",
                "prepared_handshake_missing"));
      return;
    }
    controller->set_prepared_native_handshake(
        std::move(prepared_handshake->engine_config),
        prepared_handshake->take_handshake());
  }
  timing.mark("cleanup_legacy_state");

  exv::core::UserIntent intent;
  intent.desired_connected = true;
  intent.auto_reconnect = cfg.auto_reconnect;
  intent.profile_id.value = cfg.server;
  timing.mark("tunnel_controller_connect_start");
  exv::observability::LogFacade::info(
      "app_api: Calling TunnelController::connect - server=" + cfg.server);
  exv::observability::LogFacade::info(
      "app_api: Calling TunnelController::connect");
  controller->connect(intent);

  auto snap = controller->status();
  const bool connect_failed = snap.phase == exv::core::TunnelPhase::Failed;
  timing.finish(!connect_failed,
                "phase=" + std::to_string(static_cast<int>(snap.phase)));
  if (connect_failed) {
    nlohmann::json status = frontend_status_from_controller_snapshot(snap, cfg);
    set_desktop_connect_error(status);
    reset_tunnel_controller();
    return;
  }
  attempt_cleanup.dismiss();
}

nlohmann::json auth_interaction_json(
    const exv::core::TunnelController::PendingAuthInteraction &pending) {
  return nlohmann::json{{"id", pending.id},
                        {"kind", pending.kind},
                        {"label", pending.label},
                        {"input_type", pending.input_type},
                        {"options", pending.options}};
}

} // namespace

void shutdown_desktop_vpn_runtime() {
  exv::observability::LogFacade::info(
      "app_api: Shutting down desktop VPN runtime");
  exv::core::tunnel_use_cases().shutdown_connect_jobs("core_shutdown");

  if (auto coordinator = get_active_connect_auth_coordinator(); coordinator) {
    coordinator->cancel();
    clear_active_connect_auth_coordinator_if_current(coordinator);
  }

  if (auto controller = get_tunnel_controller_if_exists(); controller) {
    exv::observability::LogFacade::info(
        "app_api: Disconnecting desktop VPN controller during shutdown");
    try {
      controller->disconnect(exv::core::DisconnectReason::UserRequested);
    } catch (const std::exception &e) {
      exv::observability::LogFacade::warn(
          std::string("app_api: desktop VPN disconnect during shutdown failed - ") +
          e.what());
    }
  } else {
    exv::observability::LogFacade::info(
        "app_api: No desktop VPN controller during shutdown");
  }
  exv::observability::LogFacade::info(
      "app_api: Resetting desktop VPN controller during shutdown");
  reset_tunnel_controller();
  clear_desktop_connect_error();
}

void register_desktop_vpn_actions(exv::core_api::DesktopRpcAdapter &adapter) {
  adapter.register_legacy_handler(
      "status.get", [](const nlohmann::json &payload) -> nlohmann::json {
        apply_desktop_runtime_context(payload);
        config::ConfigManager mgr = make_config_manager();
        Config cfg = mgr.load();
        auto controller = get_tunnel_controller_if_exists();
        if (controller) {
          auto snap = controller->status();
          return frontend_status_from_controller_snapshot(snap, cfg);
        }
        auto status = disconnected_status(cfg);
        apply_desktop_connect_job_status(&status);
        apply_desktop_connect_error(&status);
        return status;
      });

  adapter.register_legacy_handler(
      "vpn.connect", [](const nlohmann::json &payload) -> nlohmann::json {
        apply_desktop_runtime_context(payload);
        config::ConfigManager mgr = make_config_manager();
        Config cfg = mgr.load();
        StageTimer timing("desktop.connect");
        std::string password = payload.value("password", std::string());
        exv::observability::LogFacade::info("app_api: vpn.connect entry - password_provided=" +
                     std::string(password.empty() ? "false" : "true") +
                     " server=" + cfg.server + " username=" + cfg.username);
        if (password.empty() && !cfg.password.empty()) {
          std::string key = crypto::load_key();
          if (!key.empty()) {
            password = crypto::decrypt(cfg.password, key);
          }
        }
        timing.mark("password_resolved",
                    password.empty() ? "source=missing" : "source=available");

        nlohmann::json validation = quick_validate_connect(cfg, password);
        if (validation.is_object() && validation.value("ok", true) == false) {
          timing.finish(false, "stage=quick_validation error=" +
                                   json_string(validation, "error"));
          return validation;
        }

        clear_desktop_connect_error();

        exv::core::PendingConnectRequest pending;
        pending.profile_id = cfg.server;
        pending.server = cfg.server;
        pending.has_password = !password.empty();

        {
          auto &tuc = exv::core::tunnel_use_cases();
          std::lock_guard<std::mutex> lock(tuc.connect_jobs_mutex());
          auto &jobs = tuc.connect_jobs();
          auto active = jobs.snapshot();
          if (active.active) {
            auto state = jobs.submit_connect(
                pending,
                [cfg, password](std::stop_token stop, std::uint64_t) mutable {
                  if (stop.stop_requested()) return;
                  run_desktop_connect_job(cfg, password, std::string(), stop);
                });
            timing.finish(true, "stage=accepted coalesced=true");
            return connect_state_json(state);
          }
        }

        namespace conn_attempt = exv::connection_attempt;
        conn_attempt::AcquireOptions attempt_opts;
        attempt_opts.config_dir = platform::get_config_dir();
        attempt_opts.mode = "native";
        attempt_opts.owner_pid = conn_attempt::current_process_id();
        conn_attempt::AcquireResult attempt_result =
            conn_attempt::try_acquire(attempt_opts);
        timing.mark("connection_attempt",
                    attempt_result.acquired
                        ? "acquired=true"
                        : ("acquired=false code=" + attempt_result.code));

        if (!attempt_result.acquired) {
          nlohmann::json details;
          details["lock_path"] =
              platform::get_config_dir() + "/connect-attempt.lock";
          details["owner_pid"] = attempt_result.record.owner_pid;
          details["attempt_id"] = attempt_result.record.attempt_id;
          details["created_at_unix_ms"] =
              attempt_result.record.created_at_unix_ms;
          details["state"] = attempt_result.record.state;
          details["mode"] = attempt_result.record.mode;

          bool owner_alive = false;
          if (attempt_result.record.owner_pid > 0) {
            owner_alive =
                platform::is_process_alive(attempt_result.record.owner_pid);
          }
          details["owner_alive"] = owner_alive;

          const bool stale_detected =
              !owner_alive && attempt_result.record.owner_pid > 0;
          details["stale_attempt_detected"] = stale_detected;

          if (attempt_result.record.created_at_unix_ms > 0) {
            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::system_clock::now()
                                  .time_since_epoch())
                              .count();
            details["owner_age_ms"] =
                now_ms - attempt_result.record.created_at_unix_ms;
          }

          std::string user_message = attempt_result.message;
          if (stale_detected) {
            user_message =
                "检测到上次连接尝试异常残留（进程已退出）。正在自动清理...";
            conn_attempt::mark_terminal(platform::get_config_dir(),
                                        "stale_auto_cleanup");
            conn_attempt::AcquireResult retry =
                conn_attempt::try_acquire(attempt_opts);
            if (retry.acquired) {
              timing.mark("connection_attempt_retry",
                          "acquired=true stale_cleanup=true");
              attempt_result = std::move(retry);
            } else {
              timing.finish(false, "stage=connection_attempt retry_failed");
              nlohmann::json resp = error(user_message, attempt_result.code);
              resp["current_attempt"] = details;
              return resp;
            }
          } else {
            timing.finish(false, "stage=connection_attempt");
            nlohmann::json resp = error(user_message, attempt_result.code);
            resp["current_attempt"] = details;
            return resp;
          }
        }

        auto attempt_id = attempt_result.record.attempt_id;
        exv::core::VpnConnectJobState state;
        {
          auto &tuc = exv::core::tunnel_use_cases();
          std::lock_guard<std::mutex> lock(tuc.connect_jobs_mutex());
          state = tuc.connect_jobs().submit_connect(
              pending,
              [cfg, password, attempt_id](std::stop_token stop,
                                          std::uint64_t) mutable {
                if (stop.stop_requested()) return;
                run_desktop_connect_job(cfg, password, attempt_id, stop);
              });
        }
        timing.finish(true, "stage=accepted");
        return connect_state_json(state);
      });

  adapter.register_legacy_handler(
      "vpn.authInteraction.get",
      [](const nlohmann::json &payload) -> nlohmann::json {
        apply_desktop_runtime_context(payload);
        // Connect-job-scoped coordinator wins over the runner: a
        // prepared-handshake prompt is published before any TunnelController
        // exists, so the controller path would always say "no pending"
        // during that window. See
        // docs/AGGREGATE_AUTH_EMPTY_RESPONSE_FIX_PLAN.md §6.
        if (auto coordinator =
                exv::app_api::get_active_connect_auth_coordinator();
            coordinator) {
          if (auto pending = coordinator->pending(); pending) {
            return nlohmann::json{
                {"ok", true},
                {"pending", true},
                {"interaction",
                 nlohmann::json{{"id", pending->id},
                                {"kind", pending->kind},
                                {"label", pending->label},
                                {"input_type", pending->input_type},
                                {"options", pending->options}}}};
          }
        }
        auto controller = get_tunnel_controller_if_exists();
        if (!controller) {
          return nlohmann::json{{"ok", true}, {"pending", false}};
        }
        auto pending = controller->pending_auth_interaction();
        if (!pending) {
          return nlohmann::json{{"ok", true}, {"pending", false}};
        }
        return nlohmann::json{{"ok", true},
                              {"pending", true},
                              {"interaction", auth_interaction_json(*pending)}};
      });

  adapter.register_legacy_handler(
      "vpn.authInteraction.respond",
      [](const nlohmann::json &payload) -> nlohmann::json {
        apply_desktop_runtime_context(payload);
        const std::string id = payload.value("id", std::string());
        const std::string value = payload.value("value", std::string());
        // Try the connect-job-scoped coordinator first: prepared-handshake
        // prompts are not visible to the controller. See
        // docs/AGGREGATE_AUTH_EMPTY_RESPONSE_FIX_PLAN.md §6.
        if (auto coordinator =
                exv::app_api::get_active_connect_auth_coordinator();
            coordinator) {
          if (coordinator->respond(id, value)) {
            return nlohmann::json{{"ok", true}};
          }
        }
        auto controller = get_tunnel_controller_if_exists();
        if (!controller) {
          return error("No active VPN controller.", "invalid_request");
        }
        if (id.empty()) {
          return error("Missing auth interaction id.", "invalid_request");
        }
        if (!controller->provide_auth_interaction_response(id, value)) {
          return error("Auth interaction is no longer pending.",
                       "invalid_request");
        }
        return nlohmann::json{{"ok", true}};
      });

  adapter.register_legacy_handler(
      "vpn.disconnect", [](const nlohmann::json &payload) -> nlohmann::json {
        apply_desktop_runtime_context(payload);
        config::ConfigManager mgr = make_config_manager();
        Config cfg = mgr.load();
        auto controller = get_tunnel_controller_if_exists();
        {
          auto &tuc = exv::core::tunnel_use_cases();
          std::lock_guard<std::mutex> lock(tuc.connect_jobs_mutex());
          auto active = tuc.connect_jobs().snapshot();
          if (active.active) {
            auto state =
                tuc.connect_jobs().submit_disconnect("user_cancelled_connect");
            clear_desktop_connect_error();
            return connect_state_json(state);
          }
        }
        if (controller) {
          controller->disconnect(exv::core::DisconnectReason::UserRequested);
        }
        namespace conn_attempt = exv::connection_attempt;
        conn_attempt::mark_terminal(platform::get_config_dir(),
                                    "user_disconnect");
        return disconnected_status(cfg);
      });
}

} // namespace app_api
} // namespace exv

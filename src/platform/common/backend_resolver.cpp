#include "platform/common/backend_resolver.hpp"

#include "platform/common/helper_client.hpp"
#include "platform/common/oneshot_bootstrap.hpp"
#include "platform/common/service_status.hpp"
#include "observability/log_facade.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>

namespace exv {
namespace platform {
namespace {

constexpr int kServiceStartPollAttempts = 30;
constexpr auto kServiceStartPollDelay = std::chrono::milliseconds(50);

nlohmann::json descriptor_from_service(const ServiceStatusSnapshot &service) {
  return nlohmann::json{{"ok", true},
                        {"backend", "service"},
                        {"mode", "service"},
                        {"transport",
                         service.endpoint.rfind("\\\\.\\pipe\\", 0) == 0
                             ? "named-pipe"
                             : "unix-socket"},
                        {"endpoint", service.endpoint},
                        {"pid", -1},
                        {"service", service_status_to_json(service)},
                        {"capabilities", service.capabilities}};
}

ServiceStatusSnapshot wait_for_started_service(
    const BackendResolverDeps &deps) {
  ServiceStatusSnapshot latest;
  for (int attempt = 1; attempt <= kServiceStartPollAttempts; ++attempt) {
    latest = deps.current_service_status();
    if (latest.available) {
      if (attempt > 1) {
        exv::observability::LogFacade::info(
            "Backend resolver: Service became available after poll attempt=" +
            std::to_string(attempt) + " endpoint=" + latest.endpoint);
      }
      return latest;
    }
    if (attempt < kServiceStartPollAttempts) {
      std::this_thread::sleep_for(kServiceStartPollDelay);
    }
  }
  return latest;
}

nlohmann::json unavailable(const char *code, const std::string &message,
                           const ServiceStatusSnapshot &service,
                           nlohmann::json service_start = nlohmann::json()) {
  nlohmann::json out{{"ok", false},
                     {"code", code},
                     {"message", message},
                     {"service", service_status_to_json(service)},
                     {"capabilities", service.capabilities}};
  if (service_start.is_object() && !service_start.empty()) {
    out["service_start"] = std::move(service_start);
  }
  return out;
}

nlohmann::json service_start_result_to_json(
    const ServiceStartResult &result, bool attempted) {
  nlohmann::json out{{"attempted", attempted}, {"accepted", result.accepted}};
  if (!result.code.empty()) {
    out["code"] = result.code;
  }
  if (!result.message.empty()) {
    out["message"] = result.message;
  }
  if (result.native_code != 0) {
    out["native_code"] = result.native_code;
  }
  if (!result.native_message.empty()) {
    out["native_message"] = result.native_message;
  }
  return out;
}

std::string service_start_failure_message(const ServiceStartResult &result) {
  const std::string detail =
      !result.message.empty() ? result.message : result.native_message;
  if (!detail.empty()) {
    return "Helper service is installed but could not be started: " + detail;
  }
  return "Helper service is installed but could not be started.";
}

nlohmann::json start_oneshot_with_service_fallback(
    const BackendResolveOptions &options, const BackendResolverDeps &deps,
    const ServiceStatusSnapshot &service,
    const nlohmann::json &service_start) {
  exv::observability::LogFacade::event(
      "WARN", "helper", "helper.service.fallback_to_oneshot",
      "Falling back to one-shot helper because installed service is unavailable",
      {{"service_installed", service.installed ? "true" : "false"},
       {"service_running", service.running ? "true" : "false"},
       {"service_available", service.available ? "true" : "false"},
       {"service_start_code", service_start.value("code", std::string())},
       {"service_start_message",
        service_start.value("message", std::string())},
       {"service_start_native_code",
        service_start.contains("native_code")
            ? std::to_string(service_start.value("native_code", 0))
            : std::string()},
       {"service_start_native_message",
        service_start.value("native_message", std::string())}});

  OneshotBackend backend =
      deps.start_oneshot_helper(OneshotBootstrapRequest{options.helper_path});
  if (backend.ok) {
    exv::observability::LogFacade::info(
        "Backend resolver: Oneshot helper started after service failure - endpoint=" +
        backend.endpoint + " pid=" + std::to_string(backend.pid));
  } else {
    exv::observability::LogFacade::error(
        "Backend resolver: Oneshot helper fallback failed - code=" +
        backend.code + " message=" + backend.message);
  }
  nlohmann::json out = oneshot_backend_to_json(backend);
  out["service_fallback"] = service_start;
  out["service"] = service_status_to_json(service);
  return out;
}

} // namespace

nlohmann::json resolve_backend(const BackendResolveOptions &options) {
  return resolve_backend(options,
                         BackendResolverDeps{current_service_status,
                                             start_oneshot_helper,
                                             try_start_helper_service});
}

nlohmann::json resolve_backend(const BackendResolveOptions &options,
                               const BackendResolverDeps &deps) {
  exv::observability::LogFacade::info("Backend resolver: Starting resolution - preferred_mode=" +
               options.preferred_mode + " allow_oneshot=" +
               (options.allow_oneshot ? "true" : "false"));

  ServiceStatusSnapshot service = deps.current_service_status();

  exv::observability::LogFacade::info("Backend resolver: Service status - installed=" +
               std::string(service.installed ? "true" : "false") +
               " available=" + std::string(service.available ? "true" : "false") +
               " endpoint=" + service.endpoint);

  // Prefer an installed service, but in auto/oneshot resolution a failed
  // service start should not block a one-shot helper fallback.
  if (service.installed) {
    if (service.available) {
      exv::observability::LogFacade::info(
          "Backend resolver: Using service backend - endpoint=" + service.endpoint);
      return descriptor_from_service(service);
    }
    if (service.running) {
      const std::string diagnostic_code =
          !service.diagnostic_code.empty() ? service.diagnostic_code
                                           : "service_pipe_unavailable";
      const std::string message =
          !service.warning.empty()
              ? service.warning
              : "Helper service is running but its control pipe is not reachable.";
      exv::observability::LogFacade::event(
          "WARN", "helper", "helper.service.running_unreachable", message,
          {{"endpoint", service.endpoint},
           {"diagnostic_code", diagnostic_code},
           {"service_running", service.running ? "true" : "false"},
           {"service_available", service.available ? "true" : "false"}});
      return unavailable(kServiceInstalledNotRunningCode, message, service);
    }
    bool service_start_attempted = false;
    ServiceStartResult service_start_result;
    if (deps.try_start_service) {
      exv::observability::LogFacade::info(
          "Backend resolver: Service installed but not running; attempting start");
      service_start_attempted = true;
      service_start_result = deps.try_start_service();
      if (service_start_result.accepted) {
        ServiceStatusSnapshot refreshed = wait_for_started_service(deps);
        if (refreshed.available) {
          exv::observability::LogFacade::info(
              "Backend resolver: Service started - endpoint=" + refreshed.endpoint);
          return descriptor_from_service(refreshed);
        }
        service = refreshed;
      }
    }
    nlohmann::json service_start =
        service_start_result_to_json(service_start_result,
                                     service_start_attempted);
    if (options.preferred_mode != "service" &&
        (options.allow_oneshot || options.preferred_mode == "oneshot") &&
        options.start_oneshot && deps.start_oneshot_helper) {
      return start_oneshot_with_service_fallback(options, deps, service,
                                                service_start);
    }
    std::string failure_log =
        "Backend resolver: Installed service could not be made available";
    if (!service_start_result.code.empty()) {
      failure_log += " code=" + service_start_result.code;
    }
    if (service_start_result.native_code != 0) {
      failure_log +=
          " native_code=" + std::to_string(service_start_result.native_code);
    }
    if (!service_start_result.message.empty()) {
      failure_log += " message=" + service_start_result.message;
    }
    exv::observability::LogFacade::warn(failure_log);
    return unavailable(kServiceInstalledNotRunningCode,
                       service_start_failure_message(service_start_result),
                       service, service_start);
  }

  // No service install record. If the caller explicitly asked for a service
  // backend, report the missing service rather than silently falling back.
  if (options.preferred_mode == "service") {
    exv::observability::LogFacade::warn("Backend resolver: Service not installed (service mode requested)");
    return unavailable(kServiceNotInstalledCode,
                       "Helper service is not installed.", service);
  }

  // Otherwise a one-shot helper is the only option, and only when the caller
  // explicitly opted into starting one.
  if ((options.allow_oneshot || options.preferred_mode == "oneshot") &&
      options.start_oneshot) {
    exv::observability::LogFacade::info("Backend resolver: Starting oneshot helper - path=" + options.helper_path);
    OneshotBackend backend =
        deps.start_oneshot_helper(OneshotBootstrapRequest{options.helper_path});
    if (backend.ok) {
      exv::observability::LogFacade::info("Backend resolver: Oneshot helper started - endpoint=" +
                   backend.endpoint + " pid=" + std::to_string(backend.pid));
    } else {
      exv::observability::LogFacade::error("Backend resolver: Oneshot helper failed - code=" +
                    backend.code + " message=" + backend.message);
    }
    return oneshot_backend_to_json(backend);
  }

  if (options.allow_oneshot || options.preferred_mode == "oneshot") {
    exv::observability::LogFacade::warn("Backend resolver: Oneshot not supported without start_oneshot=true");
    return unavailable(kOneshotNotSupportedCode,
                       "One-shot helper is available only when explicitly requested.",
                       service);
  }

  exv::observability::LogFacade::warn("Backend resolver: No backend available - service not installed");
  return unavailable(kServiceNotInstalledCode,
                     "Helper service is not installed.", service);
}

nlohmann::json backend_unavailable_error(const nlohmann::json &resolved,
                                         const std::string &fallback_message) {
  return nlohmann::json{
      {"ok", false},
      {"error", resolved.value("message", fallback_message)},
      {"message", resolved.value("message", fallback_message)},
      {"code", resolved.value("code", kHelperUnavailableCode)},
      {"backend_resolution", resolved},
  };
}

} // namespace platform
} // namespace exv

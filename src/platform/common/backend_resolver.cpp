#include "platform/common/backend_resolver.hpp"

#include "platform/common/helper_client.hpp"
#include "platform/common/oneshot_bootstrap.hpp"
#include "platform/common/service_status.hpp"
#include "observability/log_facade.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <string>

namespace exv {
namespace platform {
namespace {

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

nlohmann::json unavailable(const char *code, const std::string &message,
                           const ServiceStatusSnapshot &service) {
  return nlohmann::json{{"ok", false},
                        {"code", code},
                        {"message", message},
                        {"service", service_status_to_json(service)},
                        {"capabilities", service.capabilities}};
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

  // Install-record is the single determinant. When a service is installed it
  // MUST be used; a one-shot helper is never started alongside an installed
  // service (avoids multi-instance drift and silent fallback). If the installed
  // service is not running, attempt to wake it before giving up.
  if (service.installed) {
    if (service.available) {
      exv::observability::LogFacade::info(
          "Backend resolver: Using service backend - endpoint=" + service.endpoint);
      return descriptor_from_service(service);
    }
    if (deps.try_start_service) {
      exv::observability::LogFacade::info(
          "Backend resolver: Service installed but not running; attempting start");
      if (deps.try_start_service()) {
        ServiceStatusSnapshot refreshed = deps.current_service_status();
        if (refreshed.available) {
          exv::observability::LogFacade::info(
              "Backend resolver: Service started - endpoint=" + refreshed.endpoint);
          return descriptor_from_service(refreshed);
        }
      }
    }
    exv::observability::LogFacade::warn(
        "Backend resolver: Installed service could not be made available");
    return unavailable(kServiceInstalledNotRunningCode,
                       "Helper service is installed but could not be started.",
                       service);
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

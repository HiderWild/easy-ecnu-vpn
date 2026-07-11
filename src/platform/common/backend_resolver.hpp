#pragma once

#include "platform/common/oneshot_bootstrap.hpp"
#include "platform/common/service_status.hpp"

#include <nlohmann/json.hpp>

#include <functional>
#include <string>

namespace exv {
namespace platform {

inline constexpr const char *kServiceNotInstalledCode = "service_not_installed";
inline constexpr const char *kServiceInstalledNotRunningCode =
    "service_installed_not_running";
inline constexpr const char *kServiceStartFailedCode = "service_start_failed";
inline constexpr const char *kOneshotNotSupportedCode = "oneshot_not_supported";
inline constexpr const char *kOneshotElevationDeniedCode =
    "oneshot_elevation_denied";
inline constexpr const char *kHelperRpcFailedCode = "helper_rpc_failed";
inline constexpr const char *kAuthFailedCode = "auth_failed";
inline constexpr const char *kVpnStartFailedCode = "vpn_start_failed";

struct BackendResolveOptions {
  std::string preferred_mode = "auto";
  std::string helper_path;
  bool allow_oneshot = true;
  bool allow_service_start = true;
  bool start_oneshot = false;
};

struct BackendResolverDeps {
  std::function<ServiceStatusSnapshot()> current_service_status;
  std::function<OneshotBackend(const OneshotBootstrapRequest &)>
      start_oneshot_helper;
  // Attempt to start an installed-but-not-running helper service. Returns
  // accepted=true if the start command was accepted (the caller re-probes
  // status afterward).
  // May be empty when service-start is not supported in the current context.
  std::function<ServiceStartResult()> try_start_service;
};

nlohmann::json resolve_backend(const BackendResolveOptions &options);
nlohmann::json resolve_backend(const BackendResolveOptions &options,
                               const BackendResolverDeps &deps);
nlohmann::json backend_unavailable_error(const nlohmann::json &resolved,
                                         const std::string &fallback_message);

} // namespace platform
} // namespace exv

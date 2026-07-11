#include "platform/common/service_status.hpp"
#include "platform/common/helper_platform.hpp"
#include "observability/log_facade.hpp"
#include "platform/win32/windows_strings.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <string>
#include <vector>

namespace exv {
namespace platform {
namespace {

std::string normalize_windows_path_for_compare(std::string path) {
  std::replace(path.begin(), path.end(), '/', '\\');
  std::transform(path.begin(), path.end(), path.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return std::filesystem::path(path).lexically_normal().string();
}

bool same_windows_path(const std::string &left, const std::string &right) {
  return normalize_windows_path_for_compare(left) ==
         normalize_windows_path_for_compare(right);
}

std::string win32_message(DWORD error) {
  return windows_error_message(error);
}

void set_status_native_error(ServiceStatusSnapshot &status,
                             const std::string &api, DWORD error) {
  status.last_start_api = api;
  status.last_start_native_error = static_cast<int>(error);
  status.last_start_native_message = win32_message(error);
}

bool service_endpoint_reachable(const std::string &endpoint) {
  if (endpoint.empty()) {
    return false;
  }
  return WaitNamedPipeA(endpoint.c_str(), 100) != 0;
}

void mark_service_config_failed(ServiceStatusSnapshot &status,
                                const std::string &diagnostic_code,
                                DWORD error) {
  set_status_native_error(status, "QueryServiceConfigW", error);
  status.health = "degraded";
  status.diagnostic_code = diagnostic_code;
  status.recommended_action = "repair_helper";
  status.available = false;
}

ServiceStartResult win32_start_failed(DWORD error, std::string fallback) {
  ServiceStartResult result;
  result.accepted = false;
  result.code = "service_start_failed";
  result.native_code = static_cast<int>(error);
  result.native_message = win32_message(error);
  result.message = result.native_message.empty() ? std::move(fallback)
                                                 : result.native_message;
  return result;
}

} // namespace

ServiceStatusSnapshot current_service_status() {
  const auto &config = helper_platform_config();
  ServiceStatusSnapshot status;
  status.mode = config.service_mode;
  status.path = config.default_service_binary_path;
  status.endpoint = config.endpoint;
  status.label = config.service_label;
  status.capabilities = nlohmann::json{{"service_mode", true},
                                       {"oneshot_mode", true},
                                       {"temporary_connect", true},
                                       {"direct_fallback", false},
                                       {"helper_binary", true}};

  SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
  if (!scm) {
    const DWORD err = GetLastError();
    set_status_native_error(status, "OpenSCManagerA", err);
    status.health = "unknown";
    status.diagnostic_code = "service_scm_unavailable";
    status.recommended_action = "repair_helper";
    exv::observability::LogFacade::event(
        "WARN", "helper", "helper.service.scm_open_failed",
        "Failed to open Windows Service Control Manager for helper status",
        {{"win32_error", std::to_string(err)},
         {"win32_message", win32_message(err)}});
    status.installed = false;
    status.running = false;
    return status;
  }

  SC_HANDLE svc = OpenServiceA(
      scm, config.service_name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
  status.installed = (svc != NULL);
  if (!svc) {
    const DWORD err = GetLastError();
    set_status_native_error(status, "OpenServiceA", err);
    status.running = false;
    status.available = false;
    if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
      status.health = "missing";
      status.diagnostic_code = "service_not_installed";
      status.recommended_action = "install_helper";
    } else {
      status.health = "unknown";
      status.diagnostic_code = "service_open_failed";
      status.recommended_action = "repair_helper";
      exv::observability::LogFacade::event(
          "WARN", "helper", "helper.service.open_failed",
          "Failed to open Windows helper service for status",
          {{"service", config.service_name},
           {"win32_error", std::to_string(err)},
           {"win32_message", status.last_start_native_message}});
    }
    CloseServiceHandle(scm);
    return status;
  }

  SERVICE_STATUS_PROCESS service_status{};
  DWORD status_bytes_needed = 0;
  if (QueryServiceStatusEx(
          svc, SC_STATUS_PROCESS_INFO,
          reinterpret_cast<LPBYTE>(&service_status), sizeof(service_status),
          &status_bytes_needed)) {
    status.running = service_status.dwCurrentState == SERVICE_RUNNING;
    status.has_service_state = true;
    status.service_state = static_cast<int>(service_status.dwCurrentState);
    status.process_id = service_status.dwProcessId;
  } else {
    const DWORD err = GetLastError();
    set_status_native_error(status, "QueryServiceStatusEx", err);
    status.health = "unknown";
    status.diagnostic_code = "service_status_query_failed";
    status.recommended_action = "repair_helper";
    exv::observability::LogFacade::event(
        "WARN", "helper", "helper.service.query_status_failed",
        "Failed to query Windows helper service status",
        {{"win32_error", std::to_string(err)},
         {"win32_message", status.last_start_native_message}});
    status.running = false;
  }

  bool service_config_verified = false;
  DWORD bytes_needed = 0;
  if (!QueryServiceConfigW(svc, NULL, 0, &bytes_needed)) {
    const DWORD initial_err = GetLastError();
    if (initial_err == ERROR_INSUFFICIENT_BUFFER && bytes_needed > 0) {
      std::vector<unsigned char> buffer(bytes_needed);
      auto *service_config =
          reinterpret_cast<QUERY_SERVICE_CONFIGW *>(buffer.data());
      if (QueryServiceConfigW(svc, service_config, bytes_needed,
                              &bytes_needed)) {
        if (service_config->lpBinaryPathName &&
            service_config->lpBinaryPathName[0] != L'\0') {
          status.binary_path =
              utf8_from_wide(service_config->lpBinaryPathName);
          std::string binary = status.binary_path;
          if (!binary.empty() && binary.front() == '"') {
            const auto end_quote = binary.find('"', 1);
            if (end_quote != std::string::npos)
              status.path = binary.substr(1, end_quote - 1);
          } else {
            const auto arg_pos = binary.find(" --");
            status.path = binary.substr(0, arg_pos);
          }
          service_config_verified = !status.path.empty();
        }
        if (!service_config_verified) {
          mark_service_config_failed(status, "service_config_unavailable",
                                     ERROR_INVALID_DATA);
          exv::observability::LogFacade::event(
              "WARN", "helper", "helper.service.config_unavailable",
              "Windows helper service configuration did not include a "
              "verifiable binary path",
              {{"service", config.service_name}});
        }
      } else {
        const DWORD err = GetLastError();
        mark_service_config_failed(status, "service_config_query_failed", err);
        exv::observability::LogFacade::event(
            "WARN", "helper", "helper.service.config_query_failed",
            "Failed to query Windows helper service configuration",
            {{"service", config.service_name},
             {"win32_error", std::to_string(err)},
             {"win32_message", status.last_start_native_message}});
      }
    } else {
      mark_service_config_failed(status, "service_config_query_failed",
                                 initial_err);
      exv::observability::LogFacade::event(
          "WARN", "helper", "helper.service.config_query_failed",
          "Failed to query Windows helper service configuration size",
          {{"service", config.service_name},
           {"win32_error", std::to_string(initial_err)},
           {"win32_message", status.last_start_native_message}});
    }
  } else {
    mark_service_config_failed(status, "service_config_unavailable",
                               ERROR_INVALID_DATA);
    exv::observability::LogFacade::event(
        "WARN", "helper", "helper.service.config_query_unexpected",
        "Windows helper service configuration size query unexpectedly "
        "succeeded without a buffer",
        {{"service", config.service_name}});
  }

  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  status.endpoint_reachable =
      status.running && service_endpoint_reachable(status.endpoint);
  status.available =
      status.running && service_config_verified && status.endpoint_reachable;
  if (status.running && !status.endpoint_reachable &&
      status.diagnostic_code.empty()) {
    status.health = "degraded";
    status.diagnostic_code = "service_pipe_unavailable";
    status.recommended_action = "repair_helper";
    status.warning =
        "Helper service is running, but its control pipe is not reachable.";
    exv::observability::LogFacade::event(
        "WARN", "helper", "helper.service.pipe_unavailable",
        "Windows helper service is running, but its control pipe is not "
        "reachable",
        {{"service", config.service_name},
         {"endpoint", status.endpoint},
         {"pid", std::to_string(status.process_id)}});
  }
  if (status.installed && !status.path.empty()) {
    std::filesystem::path service_path(status.path);
    if (!same_windows_path(status.path, config.default_service_binary_path)) {
      status.available = false;
      status.warning =
          "Helper service is registered, but it points to an old helper "
          "binary path. Reinstall the helper service from the desktop app.";
      status.capabilities["service_mode"] = false;
      exv::observability::LogFacade::event(
          "WARN", "helper", "helper.service.binary_path_mismatch",
          "Helper service points to a different helper binary",
          {{"registered_path", status.path},
           {"expected_path", config.default_service_binary_path}});
    } else if (!std::filesystem::exists(service_path)) {
      status.available = false;
      status.warning =
          "Helper service is registered, but the installed helper binary is "
          "missing. Reinstall the helper service from the desktop package.";
      status.capabilities["service_mode"] = false;
      exv::observability::LogFacade::event(
          "WARN", "helper", "helper.service.binary_missing",
          "Registered helper service binary is missing",
          {{"registered_path", status.path}});
    }
  }
  return status;
}

ServiceStartResult try_start_helper_service() {
  const auto &config = helper_platform_config();
  SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
  if (!scm) {
    DWORD err = GetLastError();
    auto result = win32_start_failed(
        err, "Failed to open Windows Service Control Manager.");
    exv::observability::LogFacade::event(
        "WARN", "helper", "helper.service.scm_open_failed",
        "Failed to open Windows Service Control Manager for helper start",
        {{"win32_error", std::to_string(err)},
         {"win32_message", result.native_message}});
    return result;
  }
  SC_HANDLE svc = OpenServiceA(scm, config.service_name,
                               SERVICE_QUERY_STATUS | SERVICE_START);
  if (!svc) {
    DWORD err = GetLastError();
    auto result =
        win32_start_failed(err, "Failed to open Windows helper service.");
    exv::observability::LogFacade::event(
        "WARN", "helper", "helper.service.open_failed",
        "Failed to open Windows helper service for start",
        {{"service", config.service_name},
         {"win32_error", std::to_string(err)},
         {"win32_message", result.native_message}});
    CloseServiceHandle(scm);
    return result;
  }
  ServiceStartResult result;
  if (StartService(svc, 0, NULL)) {
    result.accepted = true;
  } else {
    DWORD err = GetLastError();
    // Already running counts as success for the caller's availability probe.
    result.accepted = (err == ERROR_SERVICE_ALREADY_RUNNING);
    if (!result.accepted) {
      result = win32_start_failed(err, "Failed to start Windows helper service.");
      exv::observability::LogFacade::event(
          "WARN", "helper", "helper.service.start_failed",
          "Failed to start Windows helper service",
          {{"service", config.service_name},
           {"win32_error", std::to_string(err)},
           {"win32_message", result.native_message}});
    }
  }
  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  return result;
}

} // namespace platform
} // namespace exv

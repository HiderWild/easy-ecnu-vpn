#include "platform/common/service_status.hpp"
#include "platform/common/helper_platform.hpp"

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
    status.installed = false;
    status.running = false;
    return status;
  }

  SC_HANDLE svc = OpenServiceA(
      scm, config.service_name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
  status.installed = (svc != NULL);
  if (!svc) {
    status.running = false;
    CloseServiceHandle(scm);
    return status;
  }

  SERVICE_STATUS service_status;
  if (QueryServiceStatus(svc, &service_status)) {
    status.running = service_status.dwCurrentState == SERVICE_RUNNING;
    status.has_service_state = true;
    status.service_state = static_cast<int>(service_status.dwCurrentState);
  } else {
    status.running = false;
  }

  DWORD bytes_needed = 0;
  QueryServiceConfigA(svc, NULL, 0, &bytes_needed);
  if (bytes_needed > 0) {
    std::vector<unsigned char> buffer(bytes_needed);
    auto *config = reinterpret_cast<QUERY_SERVICE_CONFIGA *>(buffer.data());
    if (QueryServiceConfigA(svc, config, bytes_needed, &bytes_needed) &&
        config->lpBinaryPathName) {
      status.binary_path = std::string(config->lpBinaryPathName);
      std::string binary = status.binary_path;
      if (!binary.empty() && binary.front() == '"') {
        const auto end_quote = binary.find('"', 1);
        if (end_quote != std::string::npos)
          status.path = binary.substr(1, end_quote - 1);
      } else {
        const auto arg_pos = binary.find(" --");
        status.path = binary.substr(0, arg_pos);
      }
    }
  }

  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  status.available = status.running;
  if (status.installed && !status.path.empty()) {
    std::filesystem::path service_path(status.path);
    if (!same_windows_path(status.path, config.default_service_binary_path)) {
      status.available = false;
      status.warning =
          "Helper service is registered, but it points to an old helper "
          "binary path. Reinstall the helper service from the desktop app.";
      status.capabilities["service_mode"] = false;
    } else if (!std::filesystem::exists(service_path)) {
      status.available = false;
      status.warning =
          "Helper service is registered, but the installed helper binary is "
          "missing. Reinstall the helper service from the desktop package.";
      status.capabilities["service_mode"] = false;
    }
  }
  return status;
}

bool try_start_helper_service() {
  const auto &config = helper_platform_config();
  SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
  if (!scm) {
    return false;
  }
  SC_HANDLE svc = OpenServiceA(scm, config.service_name,
                               SERVICE_QUERY_STATUS | SERVICE_START);
  if (!svc) {
    CloseServiceHandle(scm);
    return false;
  }
  bool accepted = false;
  if (StartService(svc, 0, NULL)) {
    accepted = true;
  } else {
    DWORD err = GetLastError();
    // Already running counts as success for the caller's availability probe.
    accepted = (err == ERROR_SERVICE_ALREADY_RUNNING);
  }
  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  return accepted;
}

} // namespace platform
} // namespace exv

#include "windows_setup_rust/service_control.hpp"

#include "windows_setup_rust/util/hidden_process.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <filesystem>
#include <string>

namespace exv::setup {
namespace fs = std::filesystem;

ServicePresence QueryServicePresence(const std::wstring &service_name) {
  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (scm == nullptr) {
    return ServicePresence::Error;
  }
  SC_HANDLE svc = OpenServiceW(scm, service_name.c_str(), SERVICE_QUERY_STATUS);
  if (svc != nullptr) {
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ServicePresence::Installed;
  }
  const DWORD error = GetLastError();
  CloseServiceHandle(scm);
  return error == ERROR_SERVICE_DOES_NOT_EXIST ? ServicePresence::NotInstalled
                                                : ServicePresence::Error;
}

bool IsServiceInstalled(const std::wstring &service_name) {
  // The legacy bool API is conservative: an SCM query error must not be
  // mistaken for absence and must not silently skip privileged cleanup.
  return QueryServicePresence(service_name) != ServicePresence::NotInstalled;
}

bool StopService(const std::wstring &service_name) {
  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
  if (scm == nullptr) {
    return false;
  }

  SC_HANDLE svc = OpenServiceW(scm, service_name.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
  if (svc == nullptr) {
    const DWORD error = GetLastError();
    CloseServiceHandle(scm);
    return error == ERROR_SERVICE_DOES_NOT_EXIST;
  }

  SERVICE_STATUS status{};
  bool stopped = true;
  if (!QueryServiceStatus(svc, &status)) {
    stopped = false;
  } else if (status.dwCurrentState != SERVICE_STOPPED) {
    if (!ControlService(svc, SERVICE_CONTROL_STOP, &status)) {
      stopped = GetLastError() == ERROR_SERVICE_NOT_ACTIVE;
    }
    for (int i = 0; stopped && i < 50 && status.dwCurrentState != SERVICE_STOPPED; ++i) {
      if (!QueryServiceStatus(svc, &status)) {
        stopped = false;
        break;
      }
      if (status.dwCurrentState != SERVICE_STOPPED) {
        Sleep(100);
      }
    }
    stopped = stopped && status.dwCurrentState == SERVICE_STOPPED;
  }

  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  return stopped;
}

bool StopAndDeleteService(const std::wstring &service_name) {
  if (!StopService(service_name)) {
    return QueryServicePresence(service_name) == ServicePresence::NotInstalled;
  }

  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
  if (scm == nullptr) {
    return false;
  }
  SC_HANDLE svc = OpenServiceW(scm, service_name.c_str(), DELETE);
  if (svc == nullptr) {
    const DWORD error = GetLastError();
    CloseServiceHandle(scm);
    return error == ERROR_SERVICE_DOES_NOT_EXIST;
  }

  const BOOL deleted = DeleteService(svc);
  const DWORD delete_error = GetLastError();
  CloseServiceHandle(svc);
  CloseServiceHandle(scm);

  if (!deleted && delete_error != ERROR_SERVICE_MARKED_FOR_DELETE) {
    return false;
  }
  return WaitForServiceRemoved(service_name);
}

bool WaitForServiceRemoved(const std::wstring &service_name, int max_attempts, int poll_ms) {
  for (int i = 0; i < max_attempts; ++i) {
    switch (QueryServicePresence(service_name)) {
      case ServicePresence::NotInstalled:
        return true;
      case ServicePresence::Error:
        return false;
      case ServicePresence::Installed:
        break;
    }
    Sleep(static_cast<DWORD>(poll_ms));
  }
  return QueryServicePresence(service_name) == ServicePresence::NotInstalled;
}

bool RunEngineServiceUninstall(const std::wstring &engine_exe_path) {
  if (engine_exe_path.empty() || !fs::exists(engine_exe_path)) {
    return false;
  }
  // Rust engine --service-uninstall removes the SCM exv-engine service + PSK.
  const std::wstring cmd = L"\"" + engine_exe_path + L"\" --service-uninstall";
  const auto r = RunHidden(L"", cmd, 60000);
  return r.started && r.exit_code == 0;
}

}  // namespace exv::setup

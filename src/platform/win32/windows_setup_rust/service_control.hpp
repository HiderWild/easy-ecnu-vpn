#pragma once

#include <string>

namespace exv::setup {

inline constexpr wchar_t kEngineServiceName[] = L"exv-engine";

enum class ServicePresence {
  Installed,
  NotInstalled,
  Error,
};

ServicePresence QueryServicePresence(const std::wstring &service_name = kEngineServiceName);

bool IsServiceInstalled(const std::wstring &service_name = kEngineServiceName);

// Stop the service without deleting its SCM registration. Idempotent when the
// service is absent or already stopped.
bool StopService(const std::wstring &service_name = kEngineServiceName);

// Stop then delete service via SCM. Requires sufficient privileges.
// Returns true if service is gone (or was never installed).
bool StopAndDeleteService(const std::wstring &service_name = kEngineServiceName);

// Poll until service is not installed or attempts exhausted.
bool WaitForServiceRemoved(const std::wstring &service_name = kEngineServiceName,
                           int max_attempts = 10,
                           int poll_ms = 200);

// Rust line: run "exv-engine.exe" --service-uninstall (self-contained removal of
// the Rust SCM service exv-engine + PSK).
bool RunEngineServiceUninstall(const std::wstring &engine_exe_path);


}  // namespace exv::setup

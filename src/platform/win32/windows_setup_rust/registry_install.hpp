#pragma once

#include <string>

namespace exv::setup {

inline constexpr wchar_t kUninstallKey[] =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\EXV";
inline constexpr wchar_t kAppKey[] = L"Software\\EXV";

bool WriteInstallRegistry(const std::wstring &install_dir,
                          const std::wstring &version,
                          const std::wstring &uninstall_exe);

bool RemoveInstallRegistry();

// Read InstallDir from HKCU Software\EXV if present.
std::wstring ReadRegisteredInstallDir();

}  // namespace exv::setup

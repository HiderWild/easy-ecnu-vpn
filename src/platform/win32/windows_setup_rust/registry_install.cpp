#include "windows_setup_rust/registry_install.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace exv::setup {
namespace {

bool WriteString(HKEY key, const wchar_t *name, const std::wstring &value) {
  return RegSetValueExW(key, name, 0, REG_SZ,
                        reinterpret_cast<const BYTE *>(value.c_str()),
                        static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
}

bool WriteDword(HKEY key, const wchar_t *name, DWORD value) {
  return RegSetValueExW(key, name, 0, REG_DWORD, reinterpret_cast<const BYTE *>(&value),
                        sizeof(value)) == ERROR_SUCCESS;
}

}  // namespace

bool WriteInstallRegistry(const std::wstring &install_dir,
                          const std::wstring &version,
                          const std::wstring &uninstall_exe) {
  HKEY app = nullptr;
  if (RegCreateKeyExW(HKEY_CURRENT_USER, kAppKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &app,
                      nullptr) != ERROR_SUCCESS) {
    return false;
  }
  WriteString(app, L"InstallDir", install_dir);
  RegCloseKey(app);

  HKEY un = nullptr;
  if (RegCreateKeyExW(HKEY_CURRENT_USER, kUninstallKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &un,
                      nullptr) != ERROR_SUCCESS) {
    return false;
  }
  const std::wstring icon = install_dir + L"\\exv-ui.exe";
  const std::wstring uninstall_string = L"\"" + uninstall_exe + L"\" /uninstall";
  const std::wstring quiet = L"\"" + uninstall_exe + L"\" /uninstall /S";

  WriteString(un, L"DisplayName", L"EXV");
  WriteString(un, L"DisplayVersion", version);
  WriteString(un, L"Publisher", L"EXV");
  WriteString(un, L"InstallLocation", install_dir);
  WriteString(un, L"DisplayIcon", icon);
  WriteString(un, L"UninstallString", uninstall_string);
  WriteString(un, L"QuietUninstallString", quiet);
  WriteDword(un, L"NoModify", 1);
  WriteDword(un, L"NoRepair", 1);
  RegCloseKey(un);
  return true;
}

bool RemoveInstallRegistry() {
  RegDeleteTreeW(HKEY_CURRENT_USER, kUninstallKey);
  HKEY app = nullptr;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, kAppKey, 0, KEY_SET_VALUE, &app) == ERROR_SUCCESS) {
    RegDeleteValueW(app, L"InstallDir");
    RegCloseKey(app);
  }
  // Remove key if empty — ignore errors.
  RegDeleteKeyW(HKEY_CURRENT_USER, kAppKey);
  return true;
}

std::wstring ReadRegisteredInstallDir() {
  HKEY app = nullptr;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, kAppKey, 0, KEY_QUERY_VALUE, &app) != ERROR_SUCCESS) {
    return {};
  }
  wchar_t buffer[MAX_PATH] = {};
  DWORD type = 0;
  DWORD size = sizeof(buffer);
  const LONG rc =
      RegQueryValueExW(app, L"InstallDir", nullptr, &type, reinterpret_cast<LPBYTE>(buffer), &size);
  RegCloseKey(app);
  if (rc != ERROR_SUCCESS || type != REG_SZ) {
    return {};
  }
  return buffer;
}

}  // namespace exv::setup

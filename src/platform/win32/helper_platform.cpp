#include "platform/common/helper_platform.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shlobj.h>

#include <string>

namespace exv {
namespace platform {
namespace {

std::string join_windows_path(const std::string &base,
                              const std::string &component) {
  if (base.empty())
    return component;
  if (base.back() == '\\' || base.back() == '/')
    return base + component;
  return base + "\\" + component;
}

bool is_ascii_drive_letter(wchar_t ch) {
  return (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z');
}

bool is_absolute_local_windows_path(const std::wstring &path) {
  return path.size() >= 3 && is_ascii_drive_letter(path[0]) &&
         path[1] == L':' && (path[2] == L'\\' || path[2] == L'/');
}

std::string narrow_windows_path(const std::wstring &path) {
  if (path.empty()) {
    return {};
  }

  const int required =
      WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path.c_str(), -1,
                          nullptr, 0, nullptr, nullptr);
  if (required <= 1) {
    return {};
  }

  std::string result(static_cast<size_t>(required), '\0');
  const int written =
      WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path.c_str(), -1,
                          result.data(), required, nullptr, nullptr);
  if (written <= 1) {
    return {};
  }
  result.resize(static_cast<size_t>(written - 1));
  return result;
}

std::string program_data_root() {
  PWSTR known_path = nullptr;
  const HRESULT hr =
      SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr,
                           &known_path);
  if (SUCCEEDED(hr) && known_path) {
    const std::wstring root(known_path);
    CoTaskMemFree(known_path);
    if (is_absolute_local_windows_path(root)) {
      const std::string narrowed = narrow_windows_path(root);
      if (!narrowed.empty()) {
        return narrowed;
      }
    }
  } else if (known_path) {
    CoTaskMemFree(known_path);
  }

  return "C:\\ProgramData";
}

std::string stable_helper_path() {
  return join_windows_path(
      join_windows_path(join_windows_path(program_data_root(), "EXV"),
                        "Helper"),
      "exv-helper.exe");
}

} // namespace

const HelperPlatformConfig &helper_platform_config() {
  static const std::string service_helper_path = stable_helper_path();
  static const HelperPlatformConfig config{
      "exv-helper",
      "exv-helper",
      "",
      "\\\\.\\pipe\\exv-helper",
      "C:\\ProgramData\\exv-helper-session.json",
      "C:\\Program Files\\EXV\\exv.exe",
      service_helper_path.c_str(),
      "windows-service",
  };
  return config;
}

void wake_helper_daemon_for_shutdown() {
  const auto &config = helper_platform_config();
  if (WaitNamedPipeA(config.endpoint, 200)) {
    HANDLE hPipe = CreateFileA(config.endpoint, GENERIC_READ | GENERIC_WRITE, 0,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE)
      CloseHandle(hPipe);
  }
}

} // namespace platform
} // namespace exv

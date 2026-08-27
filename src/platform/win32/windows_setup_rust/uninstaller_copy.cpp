#include "windows_setup_rust/uninstaller_copy.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <system_error>

namespace exv::setup {
namespace fs = std::filesystem;

namespace {

constexpr ULONGLONG kRetryWindowMs = 5000;
constexpr DWORD kRetryIntervalMs = 100;

bool IsRetryableLockError(DWORD error) {
  // MoveFileExW reports an exclusively opened destination as ERROR_ACCESS_DENIED on some
  // Windows versions, despite the underlying cause being a transient file lock.
  return error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION ||
         error == ERROR_ACCESS_DENIED;
}

std::wstring ErrorSuffix(DWORD error) {
  return L"（Windows 错误 " + std::to_wstring(error) + L"）";
}

UninstallerWriteResult Failure(DWORD error, const std::wstring &message) {
  return {false, error, message + ErrorSuffix(error)};
}

bool ClearReadOnlyAttribute(const fs::path &target, DWORD *error) {
  const DWORD attributes = GetFileAttributesW(target.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    const DWORD last_error = GetLastError();
    if (last_error == ERROR_FILE_NOT_FOUND || last_error == ERROR_PATH_NOT_FOUND) {
      return true;
    }
    *error = last_error;
    return false;
  }
  if ((attributes & FILE_ATTRIBUTE_READONLY) == 0) {
    return true;
  }
  if (SetFileAttributesW(target.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY)) {
    return true;
  }
  *error = GetLastError();
  return false;
}

void RemoveStagedFile(const fs::path &path) {
  if (path.empty()) {
    return;
  }
  const DWORD attributes = GetFileAttributesW(path.c_str());
  if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_READONLY) != 0) {
    SetFileAttributesW(path.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY);
  }
  DeleteFileW(path.c_str());
}

}  // namespace

UninstallerWriteResult WriteUninstallerCopy(const std::wstring &source_path,
                                            const std::wstring &install_dir) {
  std::error_code ec;
  fs::create_directories(install_dir, ec);
  if (ec) {
    return Failure(static_cast<DWORD>(ec.value()), L"无法创建安装目录");
  }

  const fs::path target = fs::path(install_dir) / L"Uninstall.exe";
  wchar_t staged_path[MAX_PATH] = {};
  if (GetTempFileNameW(install_dir.c_str(), L"EXU", 0, staged_path) == 0) {
    return Failure(GetLastError(), L"无法准备 Uninstall.exe 的临时替换文件");
  }
  const fs::path staged = staged_path;

  if (!CopyFileW(source_path.c_str(), staged.c_str(), FALSE)) {
    const DWORD error = GetLastError();
    RemoveStagedFile(staged);
    return Failure(error, L"无法写入 Uninstall.exe 的临时替换文件");
  }

  const ULONGLONG deadline = GetTickCount64() + kRetryWindowMs;
  for (;;) {
    DWORD error = ERROR_SUCCESS;
    if (!ClearReadOnlyAttribute(target, &error)) {
      if (!IsRetryableLockError(error) || GetTickCount64() >= deadline) {
        RemoveStagedFile(staged);
        return Failure(error, L"无法移除 Uninstall.exe 的只读属性");
      }
    } else if (MoveFileExW(staged.c_str(), target.c_str(),
                           MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
      return {true, ERROR_SUCCESS, {}};
    } else {
      error = GetLastError();
      if (!IsRetryableLockError(error) || GetTickCount64() >= deadline) {
        RemoveStagedFile(staged);
        const std::wstring message = IsRetryableLockError(error)
                                         ? L"Uninstall.exe 被占用超过 5 秒，请关闭旧卸载程序或稍后重试"
                                         : L"无法替换 Uninstall.exe，请检查文件属性和安全软件拦截";
        return Failure(error, message);
      }
    }

    const ULONGLONG now = GetTickCount64();
    const DWORD wait = static_cast<DWORD>(std::min<ULONGLONG>(kRetryIntervalMs, deadline - now));
    Sleep(wait);
  }
}

}  // namespace exv::setup

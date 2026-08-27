#include "windows_setup_rust/app_paths.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

namespace exv::setup {
namespace {

std::wstring KnownFolderPath(REFKNOWNFOLDERID id) {
  PWSTR path = nullptr;
  if (FAILED(SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &path)) || path == nullptr) {
    return {};
  }
  std::wstring result(path);
  CoTaskMemFree(path);
  return result;
}

std::wstring JoinPath(std::wstring base, const wchar_t *leaf) {
  if (base.empty()) {
    return leaf ? std::wstring(leaf) : std::wstring{};
  }
  if (!base.empty() && (base.back() == L'\\' || base.back() == L'/')) {
    base.pop_back();
  }
  base.push_back(L'\\');
  if (leaf != nullptr) {
    base.append(leaf);
  }
  return base;
}

}  // namespace

std::wstring DefaultPerUserInstallDir() {
  const auto local = KnownFolderPath(FOLDERID_LocalAppData);
  if (local.empty()) {
    return L"%LOCALAPPDATA%\\Programs\\EXV";
  }
  return JoinPath(JoinPath(local, L"Programs"), L"EXV");
}

}  // namespace exv::setup

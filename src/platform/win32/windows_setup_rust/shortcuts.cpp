#include "windows_setup_rust/shortcuts.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <objbase.h>
#include <shobjidl.h>

#include <filesystem>

namespace exv::setup {
namespace fs = std::filesystem;

namespace {

std::wstring KnownPath(REFKNOWNFOLDERID id) {
  PWSTR p = nullptr;
  if (FAILED(SHGetKnownFolderPath(id, 0, nullptr, &p)) || p == nullptr) {
    return {};
  }
  std::wstring s(p);
  CoTaskMemFree(p);
  return s;
}

bool EnsureParent(const fs::path &file) {
  std::error_code ec;
  fs::create_directories(file.parent_path(), ec);
  return !ec || fs::exists(file.parent_path());
}

bool EnsureComApartment() {
  const HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  if (hr == S_OK || hr == S_FALSE || hr == RPC_E_CHANGED_MODE) {
    return true;
  }
  return SUCCEEDED(hr);
}

}  // namespace

bool CreateShortcut(const std::wstring &link_path,
                    const std::wstring &target_path,
                    const std::wstring &icon_path,
                    const std::wstring &working_dir) {
  if (link_path.empty() || target_path.empty()) {
    return false;
  }
  EnsureComApartment();
  EnsureParent(link_path);

  IShellLinkW *link = nullptr;
  HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                reinterpret_cast<void **>(&link));
  if (FAILED(hr) || link == nullptr) {
    return false;
  }

  link->SetPath(target_path.c_str());
  std::wstring wd = working_dir;
  if (wd.empty()) {
    wd = fs::path(target_path).parent_path().wstring();
  }
  if (!wd.empty()) {
    link->SetWorkingDirectory(wd.c_str());
  }
  const std::wstring icon = icon_path.empty() ? target_path : icon_path;
  link->SetIconLocation(icon.c_str(), 0);
  link->SetDescription(L"EXV");

  IPersistFile *file = nullptr;
  hr = link->QueryInterface(IID_IPersistFile, reinterpret_cast<void **>(&file));
  bool ok = false;
  if (SUCCEEDED(hr) && file != nullptr) {
    // TRUE = remember the path for relative links.
    ok = SUCCEEDED(file->Save(link_path.c_str(), TRUE));
    file->Release();
  }
  link->Release();
  return ok;
}

bool CreateStartMenuShortcuts(const std::wstring &install_dir) {
  const auto programs = KnownPath(FOLDERID_Programs);
  if (programs.empty()) {
    return false;
  }
  const fs::path folder = fs::path(programs) / L"EXV";
  std::error_code ec;
  fs::create_directories(folder, ec);
  const auto ui = (fs::path(install_dir) / L"exv-ui.exe").wstring();
  const auto un = (fs::path(install_dir) / L"Uninstall.exe").wstring();
  bool ok = CreateShortcut((folder / L"EXV.lnk").wstring(), ui, ui, install_dir);
  ok = CreateShortcut((folder / L"Uninstall EXV.lnk").wstring(), un, un, install_dir) && ok;
  return ok;
}

bool CreateDesktopShortcut(const std::wstring &install_dir) {
  const auto desktop = KnownPath(FOLDERID_Desktop);
  if (desktop.empty()) {
    return false;
  }
  const auto ui = (fs::path(install_dir) / L"exv-ui.exe").wstring();
  return CreateShortcut((fs::path(desktop) / L"EXV.lnk").wstring(), ui, ui, install_dir);
}

bool CreateQuickLaunchShortcut(const std::wstring &install_dir) {
  const auto appdata = KnownPath(FOLDERID_RoamingAppData);
  if (appdata.empty()) {
    return false;
  }
  const fs::path ql =
      fs::path(appdata) / L"Microsoft" / L"Internet Explorer" / L"Quick Launch" / L"EXV.lnk";
  const auto ui = (fs::path(install_dir) / L"exv-ui.exe").wstring();
  return CreateShortcut(ql.wstring(), ui, ui, install_dir);
}

bool RemoveDesktopShortcut() {
  const auto desktop = KnownPath(FOLDERID_Desktop);
  if (desktop.empty()) {
    return true;
  }
  std::error_code ec;
  fs::remove(fs::path(desktop) / L"EXV.lnk", ec);
  return true;
}

bool RemoveStartMenuShortcuts() {
  const auto programs = KnownPath(FOLDERID_Programs);
  if (programs.empty()) {
    return true;
  }
  const fs::path folder = fs::path(programs) / L"EXV";
  std::error_code ec;
  fs::remove(folder / L"EXV.lnk", ec);
  fs::remove(folder / L"Uninstall EXV.lnk", ec);
  fs::remove(folder, ec);
  return true;
}

bool RemoveQuickLaunchShortcut() {
  const auto appdata = KnownPath(FOLDERID_RoamingAppData);
  if (appdata.empty()) {
    return true;
  }
  const fs::path ql =
      fs::path(appdata) / L"Microsoft" / L"Internet Explorer" / L"Quick Launch" / L"EXV.lnk";
  std::error_code ec;
  fs::remove(ql, ec);
  return true;
}

}  // namespace exv::setup

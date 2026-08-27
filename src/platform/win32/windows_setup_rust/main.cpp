#include "windows_setup_rust/cli.hpp"
#include "windows_setup_rust/elevate.hpp"
#include "windows_setup_rust/install_engine.hpp"
#include "windows_setup_rust/ui/setup_window.hpp"
#include "windows_setup_rust/uninstall_engine.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <objbase.h>

namespace {

class ComInit {
 public:
  ComInit() {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  }
  ~ComInit() {
    CoUninitialize();
  }
};

int RunSilentInstall(const exv::setup::CliOptions &opts) {
  ComInit com;
  exv::setup::InstallRequest req;
  req.install_dir = opts.install_dir.empty() ? exv::setup::DefaultInstallDir() : opts.install_dir;
  // Match NSIS: Start Menu always; desktop/launch from flags (defaults true).
  req.create_desktop_shortcut = opts.desktop_shortcut;
  req.create_start_menu = true;
  req.create_quick_launch = opts.quick_launch;
  req.launch_app = opts.launch_app;
#ifndef EXV_PRODUCT_VERSION
#define EXV_PRODUCT_VERSION L"4.0.0"
#endif
  req.app_version = EXV_PRODUCT_VERSION;
  wchar_t env[4096] = {};
  if (GetEnvironmentVariableW(L"EXV_SETUP_PAYLOAD_DIR", env, 4096) > 0) {
    req.payload_path = env;
    req.payload_is_directory = true;
  }
  const auto result = exv::setup::RunInstall(req, nullptr);
  return result.ok ? 0 : 1;
}

int RunSilentUninstall(const exv::setup::CliOptions &opts) {
  ComInit com;
  exv::setup::UninstallRequest req;
  req.install_dir = opts.install_dir;
  req.clear_user_data = opts.clear_user_data;
  const auto result = exv::setup::RunUninstall(req, nullptr);
  return result.ok ? 0 : 1;
}

}  // namespace

int APIENTRY wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
  int argc = 0;
  LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (argv == nullptr) {
    return 2;
  }

  const auto parsed = exv::setup::ParseCli(argc, argv);
  LocalFree(argv);

  if (!parsed.has_value()) {
    return 2;
  }

  // 卸载涉及杀进程（StopRunningAppProcesses）、删服务（RunEngineServiceUninstall /
  // StopAndDeleteService）与删文件（DeleteTreeBestEffort，含 MoveFileEx 重启删除登记——
  // 写 HKLM\SYSTEM\...\PendingFileRenameOperations 需要管理员）。清单为 asInvoker，
  // 未提权时所有卸载权限均不足（实测 remove=5/schedule=5 报「无法删除或登记重启删除」）。
  // 对策：卸载角色在派发前自提权——runas 重启自身（携带原卸载参数），原进程退出，
  // 提权实例完成实际卸载。安装角色继续走既有的 ElevatedWorker 提权模式。
  const bool is_uninstall_role = parsed->role == exv::setup::Role::UninstallGui ||
                                 parsed->role == exv::setup::Role::UninstallSilent;
  if (is_uninstall_role && !exv::setup::IsProcessElevated()) {
    wchar_t self[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, self, MAX_PATH) == 0 || self[0] == 0) {
      return 2;
    }
    std::wstring params;
    if (parsed->role == exv::setup::Role::UninstallSilent) {
      params += L"/S ";
    }
    params += L"/uninstall";
    if (parsed->clear_user_data) {
      params += L" /clear-user-data";
    }
    if (!parsed->install_dir.empty()) {
      params += L" /D=" + parsed->install_dir;
    }
    SHELLEXECUTEINFOW sei = {sizeof(sei)};
    sei.lpVerb = L"runas";
    sei.lpFile = self;
    sei.lpParameters = params.c_str();
    sei.nShow = parsed->role == exv::setup::Role::UninstallSilent ? SW_HIDE : SW_SHOWNORMAL;
    if (!ShellExecuteExW(&sei)) {
      return 2;  // UAC 拒绝/失败 → 不继续非提权卸载（避免再次报权限错）。
    }
    return 0;  // 原进程退出；提权实例完成实际卸载。
  }

  ComInit com;

  switch (parsed->role) {
    case exv::setup::Role::InstallGui:
      return exv::setup::ui::RunInstallerGui(*parsed);
    case exv::setup::Role::UninstallGui:
      return exv::setup::ui::RunUninstallerGui(*parsed);
    case exv::setup::Role::InstallSilent:
      return RunSilentInstall(*parsed);
    case exv::setup::Role::UninstallSilent:
      return RunSilentUninstall(*parsed);
    case exv::setup::Role::ElevatedWorker:
      return exv::setup::RunElevatedWorkerServer(parsed->elevated_pipe, parsed->elevated_token);
  }
  return 2;
}

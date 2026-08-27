#include "windows_setup_rust/uninstall_engine.hpp"

#include "windows_setup_rust/app_paths.hpp"
#include "windows_setup_rust/elevate.hpp"
#include "windows_setup_rust/process_control.hpp"
#include "windows_setup_rust/registry_install.hpp"
#include "windows_setup_rust/service_control.hpp"
#include "windows_setup_rust/shortcuts.hpp"
#include "windows_setup_rust/util/hidden_process.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

namespace exv::setup {
namespace fs = std::filesystem;

namespace {

struct DeleteTreeResult {
  bool ok{true};
  std::wstring error;
};

void AppendError(std::wstring &errors, const std::wstring &error) {
  if (!errors.empty()) {
    errors += L"；";
  }
  errors += error;
}

bool DeleteOrSchedule(const fs::path &path, std::wstring &error) {
  std::error_code ec;
  const bool present = fs::exists(path, ec);
  if (ec) {
    error = L"无法检查路径：" + path.wstring();
    return false;
  }
  if (!present) {
    return true;
  }
  if (fs::remove(path, ec)) {
    return true;
  }
  if (!ec) {
    const bool still_present = fs::exists(path, ec);
    if (!ec && !still_present) {
      return true;
    }
  }
  const auto remove_error = ec.value();
  if (MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) {
    return true;
  }
  const DWORD schedule_error = GetLastError();
  error = L"无法删除或登记重启删除：" + path.wstring() + L"（remove=" +
          std::to_wstring(remove_error) + L"，schedule=" +
          std::to_wstring(schedule_error) + L"）";
  return false;
}

DeleteTreeResult DeleteTreeBestEffort(const fs::path &root) {
  DeleteTreeResult result;
  std::error_code ec;
  if (!fs::exists(root, ec)) {
    if (ec) {
      result.ok = false;
      result.error = L"无法检查安装目录：" + root.wstring();
    }
    return result;
  }

  // Delete files first deepest-first.
  std::vector<fs::path> files;
  std::vector<fs::path> dirs;
  for (auto it = fs::recursive_directory_iterator(root, ec); !ec && it != fs::recursive_directory_iterator();
       it.increment(ec)) {
    if (it->is_directory(ec)) {
      dirs.push_back(it->path());
    } else {
      files.push_back(it->path());
    }
  }
  if (ec) {
    result.ok = false;
    result.error = L"无法枚举安装目录：" + root.wstring();
    return result;
  }

  std::wstring errors;
  for (const auto &f : files) {
    std::wstring error;
    if (!DeleteOrSchedule(f, error)) {
      AppendError(errors, error);
    }
  }
  std::sort(dirs.begin(), dirs.end(),
            [](const fs::path &a, const fs::path &b) {
              return a.wstring().size() > b.wstring().size();
            });
  for (const auto &d : dirs) {
    std::wstring error;
    if (!DeleteOrSchedule(d, error)) {
      AppendError(errors, error);
    }
  }
  std::wstring error;
  if (!DeleteOrSchedule(root, error)) {
    AppendError(errors, error);
  }
  if (!errors.empty()) {
    result.ok = false;
    result.error = errors;
  }
  return result;
}

}  // namespace

UninstallResult RunUninstall(const UninstallRequest &request, ProgressModel *progress) {
  UninstallResult result;
  std::wstring errors;
  // Monotonic milestones 0→1. UI maps target to falling water (1 - t).
  // Skipped work still advances the waterline so each step is visually accounted for.
  double mark = 0.0;
  auto status = [&](const wchar_t *s, double t) {
    mark = std::max(mark, std::clamp(t, 0.0, 1.0));
    if (progress) {
      progress->SetStatus(s);
      progress->SetTarget(mark);
    }
  };

  std::wstring install_dir = request.install_dir;
  if (install_dir.empty()) {
    install_dir = ReadRegisteredInstallDir();
  }
  if (install_dir.empty()) {
    result.error = L"无法确定安装目录";
    return result;
  }

  status(L"正在结束已运行的 EXV…", 0.06);
  if (progress) {
    progress->SetStageSpan(0.06, 0.10);
  }
  StopRunningAppProcesses();
  status(L"已结束运行中的进程", 0.10);

  status(L"正在移除服务…", 0.16);
  if (progress) {
    progress->SetStageSpan(0.16, 0.30);
  }
  // Rust line: the engine service is self-installed by exv-engine --service-install.
  // Uninstall via exv-engine --service-uninstall (engine sits at install_dir root,
  // at the install root, with a direct SCM delete as fallback.
  const auto presence = QueryServicePresence(kEngineServiceName);
  if (presence == ServicePresence::Error) {
    AppendError(errors, L"无法查询 exv-engine 服务状态");
  } else if (presence == ServicePresence::Installed) {
    const auto engine = fs::path(install_dir) / L"exv-engine.exe";
    bool ok = false;
    if (fs::exists(engine)) {
      ok = RunEngineServiceUninstall(engine.wstring());
      if (ok) {
        WaitForServiceRemoved(kEngineServiceName);
      }
    }
    if (!ok || IsServiceInstalled(kEngineServiceName)) {
      ok = StopAndDeleteService(kEngineServiceName);
    }
    if (!ok) {
      AppendError(errors, L"无法停止并删除 exv-engine 服务");
    }
    status(ok ? L"服务已移除" : L"服务移除失败，继续清理文件", 0.30);
  } else {
    status(L"未安装服务，已跳过", 0.30);
  }

  status(L"正在移除快捷方式…", 0.38);
  if (progress) {
    progress->SetStageSpan(0.38, 0.48);
  }
  RemoveDesktopShortcut();
  RemoveStartMenuShortcuts();
  RemoveQuickLaunchShortcut();
  status(L"快捷方式已移除", 0.48);

  status(L"正在清理注册表…", 0.52);
  if (progress) {
    progress->SetStageSpan(0.52, 0.60);
  }
  RemoveInstallRegistry();
  status(L"注册表已清理", 0.60);

  if (request.clear_user_data) {
    status(L"正在清除用户数据…", 0.66);
    if (progress) {
      progress->SetStageSpan(0.66, 0.78);
    }
    const auto script = fs::path(install_dir) / L"support" / L"clear-local-user-config.ps1";
    if (fs::exists(script)) {
      // Hidden PowerShell only — never elevated Verb RunAs window path.
      const std::wstring cmd =
          L"powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"" +
          script.wstring() + L"\" -Force -IncludeCredentialManager";
      RunHidden(L"", cmd, 120000);
      status(L"用户数据已清除", 0.78);
    } else {
      status(L"未找到清理脚本，已跳过", 0.78);
    }
  } else {
    status(L"保留用户数据", 0.78);
  }

  status(L"正在删除文件…", 0.82);
  if (progress) {
    progress->SetStageSpan(0.82, 0.96);
  }
  const auto delete_result = DeleteTreeBestEffort(install_dir);
  if (!delete_result.ok) {
    AppendError(errors, delete_result.error);
    status(L"文件删除失败", 0.96);
  } else {
    status(L"文件已删除或已登记延迟删除", 0.96);
  }

  if (!errors.empty()) {
    result.error = errors;
    status(L"卸载未完成", 1.0);
    return result;
  }
  status(L"卸载完成", 1.0);
  result.ok = true;
  return result;
}

}  // namespace exv::setup

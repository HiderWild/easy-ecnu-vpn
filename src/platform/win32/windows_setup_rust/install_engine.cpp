#include "windows_setup_rust/install_engine.hpp"

#include "windows_setup_rust/elevate.hpp"
#include "windows_setup_rust/payload/archive_reader.hpp"
#include "windows_setup_rust/payload/embedded_payload.hpp"
#include "windows_setup_rust/process_control.hpp"
#include "windows_setup_rust/registry_install.hpp"
#include "windows_setup_rust/service_control.hpp"
#include "windows_setup_rust/shortcuts.hpp"
#include "windows_setup_rust/uninstaller_copy.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string_view>
#include <vector>

namespace exv::setup {
namespace fs = std::filesystem;

namespace {

std::wstring SelfPath() {
  wchar_t path[MAX_PATH] = {};
  GetModuleFileNameW(nullptr, path, MAX_PATH);
  return path;
}

bool LooksLikePe(const fs::path &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return false;
  }
  char mz[2] = {};
  in.read(mz, 2);
  return in && mz[0] == 'M' && mz[1] == 'Z';
}

bool CopyDirectoryRecursive(const fs::path &from, const fs::path &to) {
  std::error_code ec;
  fs::create_directories(to, ec);
  for (auto it = fs::recursive_directory_iterator(from, ec); it != fs::recursive_directory_iterator();
       it.increment(ec)) {
    if (ec) {
      return false;
    }
    const auto rel = fs::relative(it->path(), from, ec);
    if (ec) {
      return false;
    }
    const auto dest = to / rel;
    if (it->is_directory(ec)) {
      fs::create_directories(dest, ec);
    } else if (it->is_regular_file(ec)) {
      fs::create_directories(dest.parent_path(), ec);
      // Existing install: force overwrite (NSIS File /r behavior on reinstall).
      fs::remove(dest, ec);
      ec.clear();
      fs::copy_file(it->path(), dest, fs::copy_options::overwrite_existing, ec);
      if (ec) {
        return false;
      }
    }
  }
  return true;
}

// Rust line: the host resolves wintun.dll from env EXV_RUST_VPN_WINTUN_DLL OR the
// frozen default path %USERPROFILE%\.exv\wintun\wintun\bin\amd64\wintun.dll — there
// is NO sibling fallback. The installer must preplace wintun.dll there so the
// packaged app works without an env var.
bool PreplaceWintunToFrozenPath(const fs::path &install_dir) {
  const fs::path src = install_dir / L"wintun.dll";
  std::error_code ec;
  if (!fs::exists(src, ec)) {
    return false;
  }
  wchar_t profile[MAX_PATH] = {};
  const DWORD n = GetEnvironmentVariableW(L"USERPROFILE", profile, MAX_PATH);
  if (n == 0 || n >= MAX_PATH) {
    return false;
  }
  const fs::path dest =
      fs::path(profile) / L".exv" / L"wintun" / L"wintun" / L"bin" / L"amd64" / L"wintun.dll";
  fs::create_directories(dest.parent_path(), ec);
  if (ec) {
    return false;
  }
  fs::copy_file(src, dest, fs::copy_options::overwrite_existing, ec);
  return !ec;
}

std::wstring Utf8ToWide(std::string_view text) {
  if (text.empty()) {
    return {};
  }
  const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                       nullptr, 0);
  if (size <= 0) {
    return L"未知解压错误";
  }
  std::wstring out(static_cast<std::size_t>(size), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size);
  return out;
}

void SetExtractionError(std::wstring *error, const std::wstring &value) {
  if (error != nullptr) {
    *error = value;
  }
}

bool ExtractExvpFile(const fs::path &exvp, const fs::path &dest, ProgressModel *progress,
                     double base, double weight, std::wstring *error) {
  std::ifstream in(exvp, std::ios::binary);
  if (!in) {
    SetExtractionError(error, L"无法打开安装包文件");
    return false;
  }
  in.seekg(0, std::ios::end);
  const auto sz = in.tellg();
  if (sz <= 0) {
    SetExtractionError(error, L"安装包为空");
    return false;
  }
  in.seekg(0, std::ios::beg);
  std::vector<std::uint8_t> blob(static_cast<std::size_t>(sz));
  in.read(reinterpret_cast<char *>(blob.data()), sz);
  if (!in) {
    SetExtractionError(error, L"读取安装包失败");
    return false;
  }
  payload::ArchiveView view;
  if (!payload::ParseArchive(blob, view)) {
    SetExtractionError(error, L"安装包格式无效");
    return false;
  }
  std::string err;
  const bool ok = payload::ExtractArchive(
      view, dest, &err, [&](std::uint64_t w, std::uint64_t total) {
        if (progress != nullptr && total > 0) {
          progress->SetStage(base, weight, static_cast<double>(w) / static_cast<double>(total));
        }
      });
  if (!ok) {
    SetExtractionError(error, Utf8ToWide(err));
  }
  return ok;
}

bool ExtractEmbeddedPayload(const fs::path &dest, ProgressModel *progress, double base,
                            double weight, std::wstring *error) {
  std::string err;
  const bool ok = payload::ExtractEmbeddedPayloadTo(
      dest, &err, [&](std::uint64_t w, std::uint64_t total) {
        if (progress != nullptr && total > 0) {
          progress->SetStage(base, weight, static_cast<double>(w) / static_cast<double>(total));
        }
      });
  if (!ok) {
    SetExtractionError(error, Utf8ToWide(err));
  }
  return ok;
}

// Cover installation must release the running LocalSystem engine before the
// archive writes exv-engine.exe. Keep the SCM registration: the existing
// service configuration remains valid because the install path is unchanged.
bool PreInstallServiceMaintenance(const std::wstring &install_dir) {
  (void)install_dir;
  return EnsureServiceStopped();
}

bool LaunchInstalledApp(const std::wstring &install_dir, std::wstring *error) {
  const auto ui = fs::path(install_dir) / L"exv-ui.exe";
  if (!fs::exists(ui)) {
    if (error) {
      *error = L"未找到 exv-ui.exe，无法启动。请确认安装包内容完整。";
    }
    return false;
  }
  if (!LooksLikePe(ui)) {
    if (error) {
      *error = L"exv-ui.exe 不是有效程序（演示包可能只含占位文件）。正式包应包含真实二进制。";
    }
    return false;
  }

  // Prefer CreateProcess with working directory = install dir.
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  std::wstring cmd = L"\"" + ui.wstring() + L"\"";
  std::wstring cwd = install_dir;
  if (CreateProcessW(ui.c_str(), cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, cwd.c_str(), &si,
                     &pi)) {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
  }

  // Fallback ShellExecute.
  const HINSTANCE r =
      ShellExecuteW(nullptr, L"open", ui.c_str(), nullptr, install_dir.c_str(), SW_SHOWNORMAL);
  if (reinterpret_cast<INT_PTR>(r) > 32) {
    return true;
  }
  if (error) {
    *error = L"启动 EXV 失败（CreateProcess/ShellExecute）。";
  }
  return false;
}

}  // namespace

InstallResult RunInstall(const InstallRequest &request, ProgressModel *progress) {
  InstallResult result;
  result.install_dir = request.install_dir;

  // Discrete monotonic milestones: every step (including skipped work) still advances
  // the waterline so the icon fill tracks real install progress, not wall-clock waiting.
  // preflight 0→0.50（检查旧版本 0.04：无进程→0.33 视为完成；有进程→0.15 结束→0.40；
  // 准备服务 0.42→0.46）、解压 0.50→0.85、finalize 0.85→1.0
  double mark = 0.0;
  auto status = [&](const wchar_t *s, double t) {
    mark = std::max(mark, std::clamp(t, 0.0, 1.0));
    if (progress) {
      progress->SetStatus(s);
      progress->SetTarget(mark);
    }
  };
  auto status_done = [&](const wchar_t *s, double t) {
    // Always publish completion of a step, even when work was skipped.
    status(s, t);
  };

  if (request.install_dir.empty()) {
    result.error = L"empty install dir";
    return result;
  }

  if (!CanWriteDirectory(request.install_dir)) {
    result.error = L"install directory is not writable";
    return result;
  }

  // --- NSIS Section Install preflight ---
  // 检查是否有运行中的旧版本（新增步骤）：没有则直接跳到 33% 视为完成；有则 15%，
  // 结束进程后跳到 40%（关旧实例占进度拉满到 40%）。UI 停滞注入以该满值为蠕动上限。
  status(L"正在检查是否运行旧版本…", 0.04);
  if (progress) {
    progress->SetStageSpan(0.04, 0.40);
  }
  if (!IsAnyExvProcessRunning()) {
    status_done(L"未发现运行中的旧版本", 0.33);
  } else {
    status(L"发现运行中的旧版本，正在结束…", 0.15);
    StopRunningAppProcesses();
    status_done(L"已结束运行中的进程", 0.40);
  }

  status(L"正在准备服务组件…", 0.42);
  // Service installation is an explicit post-install engine/UI action.
  const bool had_service = IsServiceInstalled();
  if (!PreInstallServiceMaintenance(request.install_dir)) {
    result.error = L"无法停止已安装的 exv-engine 服务，请稍后重试。";
    return result;
  }
  status_done(had_service ? L"服务已停止，保留安装配置" : L"无需预清理服务", 0.46);

  // --- Extract / copy (overwrite) ---
  // Extract range: 0.50 → 0.85
  constexpr double kExtractBase = 0.50;
  constexpr double kExtractWeight = 0.35;
  status(L"正在安装文件…", kExtractBase);
  if (progress) {
    progress->SetStageSpan(kExtractBase, kExtractBase + kExtractWeight);
  }
  bool extracted = false;
  std::wstring extraction_error;
  if (request.payload_is_directory && !request.payload_path.empty()) {
    extracted = CopyDirectoryRecursive(request.payload_path, request.install_dir);
    if (progress) {
      progress->SetStage(kExtractBase, kExtractWeight, 1.0);
      mark = std::max(mark, kExtractBase + kExtractWeight);
    }
  } else if (!request.payload_path.empty()) {
    extracted = ExtractExvpFile(request.payload_path, request.install_dir, progress, kExtractBase,
                                kExtractWeight, &extraction_error);
    mark = std::max(mark, kExtractBase + kExtractWeight);
  } else {
    extracted = ExtractEmbeddedPayload(request.install_dir, progress, kExtractBase, kExtractWeight,
                                       &extraction_error);
    mark = std::max(mark, kExtractBase + kExtractWeight);
  }
  if (!extracted) {
    result.error = L"解压安装包失败";
    if (!extraction_error.empty()) {
      result.error += L"：" + extraction_error;
    }
    return result;
  }
  status_done(L"文件安装完成", kExtractBase + kExtractWeight);

  // Sanity: require at least something under install dir.
  std::error_code ec;
  if (!fs::exists(fs::path(request.install_dir), ec)) {
    result.error = L"安装目录在解压后不存在";
    return result;
  }

  status(L"正在写入卸载程序…", 0.87);
  if (progress) {
    progress->SetStageSpan(0.87, 0.90);
  }
  const auto uninstaller = WriteUninstallerCopy(SelfPath(), request.install_dir);
  if (!uninstaller.ok) {
    result.error = uninstaller.error;
    return result;
  }
  status_done(L"卸载程序已就绪", 0.90);

  status(L"正在更新注册表…", 0.91);
  if (progress) {
    progress->SetStageSpan(0.91, 0.93);
  }
  const auto uninstall = (fs::path(request.install_dir) / L"Uninstall.exe").wstring();
  const std::wstring version =
      request.app_version.empty() ? std::wstring(L"0.0.0") : request.app_version;
  if (!WriteInstallRegistry(request.install_dir, version, uninstall)) {
    result.error = L"写入卸载注册表失败";
    return result;
  }
  status_done(L"注册表已更新", 0.93);

  // Rust line: preplace wintun.dll to the frozen default path so the app finds it
  // without EXV_RUST_VPN_WINTUN_DLL. Non-fatal if the payload lacks wintun.dll.
  status(L"正在配置 wintun 驱动…", 0.94);
  const bool wintun_placed = PreplaceWintunToFrozenPath(request.install_dir);
  status_done(wintun_placed ? L"wintun 驱动已就位" : L"wintun 未随包携带，跳过", 0.94);

  // NSIS always creates Start Menu during Install section.
  status(L"正在创建开始菜单快捷方式…", 0.95);
  if (progress) {
    progress->SetStageSpan(0.95, 0.96);
  }
  CreateStartMenuShortcuts(request.install_dir);
  status_done(L"开始菜单快捷方式已创建", 0.96);

  // Optional finish-page defaults when silent path requests them immediately.
  if (request.create_desktop_shortcut) {
    status(L"正在创建桌面快捷方式…", 0.97);
    CreateDesktopShortcut(request.install_dir);
  } else {
    status_done(L"跳过桌面快捷方式", 0.97);
  }
  if (request.create_quick_launch) {
    status(L"正在创建快速启动…", 0.98);
    CreateQuickLaunchShortcut(request.install_dir);
  } else {
    status_done(L"跳过快速启动", 0.98);
  }

  // Service installation is an explicit post-install engine/UI action.
  status_done(L"无需修复服务", 0.99);

  if (request.launch_app) {
    status(L"正在启动 EXV…", 0.995);
    if (progress) {
      progress->SetStageSpan(0.995, 1.0);
    }
    std::wstring launch_err;
    if (!LaunchInstalledApp(request.install_dir, &launch_err)) {
      // Do not fail the whole install just because launch failed (file may be a demo stub).
      if (progress) {
        progress->SetStatus(launch_err.empty() ? L"安装完成（启动已跳过）"
                                               : launch_err.c_str());
      }
    }
  }

  status(L"安装完成", 1.0);
  result.ok = true;
  return result;
}

bool LaunchExvUi(const std::wstring &install_dir, std::wstring *error) {
  return LaunchInstalledApp(install_dir, error);
}

}  // namespace exv::setup

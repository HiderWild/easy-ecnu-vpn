#include "core/use_cases/system_status_use_cases.hpp"

#include "core/config/config_platform_view.hpp"
#include "core/vpn/vpn.hpp"
#include "observability/log_facade.hpp"
#include "platform/common/backend_resolver.hpp"
#include "platform/common/driver_status.hpp"
#include "platform/common/elevated_service_launcher.hpp"
#include "platform/common/helper_service_manager.hpp"
#include "platform/common/logging/log_runtime.hpp"
#include "platform/common/process_utils.hpp"
#include "platform/common/process_control.hpp"
#include "platform/common/runtime_paths.hpp"
#include "platform/common/runtime_status.hpp"
#include "platform/common/service_status.hpp"
#include "platform/common/status_models.hpp"

#include <algorithm>
#include <cwctype>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace exv::core {
namespace {

UseCaseResult fail_with_payload(const char *error_code, std::string message,
                                nlohmann::json payload) {
  UseCaseResult result = UseCaseResult::fail(error_code, std::move(message));
  result.payload = std::move(payload);
  return result;
}

// Build the service-status payload returned by the elevated service ops. Mirrors
// the {"service_status": {...}} shape the prior helper-daemon path produced, so
// callers/UI do not need to change how they read the result.
nlohmann::json service_status_payload(
    const exv::platform::ServiceStatusSnapshot &snapshot) {
  return nlohmann::json{
      {"service_status", exv::platform::service_status_to_json(snapshot)}};
}

// Launch an elevated helper process (`exv-helper.exe --<subcommand>`) to perform
// a privileged service install/uninstall/repair, then poll the live service
// status until it reflects the desired end state or the timeout elapses.
// `launch_elevated_service_op` is async: it returns {launched=true} once the
// elevated process is started; the elevated process then does the SCM work.
UseCaseResult run_elevated_service_op(const std::string &subcommand,
                                      const char *error_code,
                                      const std::string &error_message,
                                      bool desired_installed) {
  exv::platform::ElevatedServiceLaunchResult launch =
      exv::platform::launch_elevated_service_op(subcommand);
  if (!launch.launched) {
    return UseCaseResult::fail(
        launch.code.empty() ? error_code : launch.code,
        launch.message.empty() ? error_message : launch.message);
  }
  // The elevated process runs async. Poll service status until it reflects the
  // desired end state or we time out.
  constexpr int kMaxAttempts = 60; // ~15s at 250ms
  for (int i = 0; i < kMaxAttempts; ++i) {
    exv::platform::ServiceStatusSnapshot snap =
        exv::platform::current_service_status();
    if (desired_installed && snap.installed && snap.available) {
      return UseCaseResult::ok(service_status_payload(snap));
    }
    if (!desired_installed && !snap.installed) {
      return UseCaseResult::ok(service_status_payload(snap));
    }
    exv::platform::sleep_ms(250);
  }
  // Timed out waiting for the desired state. Report current status as a
  // non-failure "still in progress" result so the caller can re-check.
  exv::platform::ServiceStatusSnapshot snap =
      exv::platform::current_service_status();
  return UseCaseResult::ok(service_status_payload(snap));
}

std::string env_value(const char *name) {
  const char *value = std::getenv(name);
  return value ? std::string(value) : std::string();
}

std::filesystem::path cli_install_dir() {
#ifdef _WIN32
  std::string local_app_data = env_value("LOCALAPPDATA");
  if (!local_app_data.empty()) {
    return std::filesystem::path(local_app_data) / "EXV" / "bin";
  }
  std::string user_profile = env_value("USERPROFILE");
  if (!user_profile.empty()) {
    return std::filesystem::path(user_profile) / "AppData" / "Local" /
           "EXV" / "bin";
  }
  return std::filesystem::temp_directory_path() / "EXV" / "bin";
#else
  std::string home = env_value("HOME");
  if (!home.empty()) {
    return std::filesystem::path(home) / ".local" / "bin";
  }
  return std::filesystem::temp_directory_path() / "exv-bin";
#endif
}

std::filesystem::path cli_target_path() {
#ifdef _WIN32
  return cli_install_dir() / "exv.exe";
#else
  return cli_install_dir() / "exv";
#endif
}

std::filesystem::path cli_source_path() {
  std::filesystem::path current(exv::platform::get_executable_path());
  std::vector<std::filesystem::path> candidates;
#ifdef _WIN32
  candidates.push_back(current.parent_path() / "bin" / "exv.exe");
  candidates.push_back(current.parent_path() / "exv.exe");
#else
  candidates.push_back(current.parent_path() / "bin" / "exv");
  candidates.push_back(current.parent_path() / "exv");
#endif
  candidates.push_back(current);

  for (const auto &candidate : candidates) {
    std::error_code ec;
    if (!std::filesystem::exists(candidate, ec) || ec) {
      continue;
    }
#ifdef _WIN32
    if (candidate.filename().wstring() == L"exv.exe") {
      return candidate;
    }
#else
    if (candidate.filename() == "exv") {
      return candidate;
    }
#endif
  }
  return current;
}

std::vector<std::string> split_path_env(const std::string &value) {
#ifdef _WIN32
  constexpr char delimiter = ';';
#else
  constexpr char delimiter = ':';
#endif
  std::vector<std::string> parts;
  std::string current;
  for (char ch : value) {
    if (ch == delimiter) {
      parts.push_back(current);
      current.clear();
    } else {
      current.push_back(ch);
    }
  }
  parts.push_back(current);
  return parts;
}

#ifdef _WIN32
std::wstring normalize_path_for_compare(std::filesystem::path path) {
  std::error_code ec;
  path = std::filesystem::weakly_canonical(path, ec);
  if (ec) {
    path = path.lexically_normal();
  }
  std::wstring text = path.wstring();
  while (!text.empty() && (text.back() == L'\\' || text.back() == L'/')) {
    text.pop_back();
  }
  std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
    return static_cast<wchar_t>(std::towlower(ch));
  });
  return text;
}
#else
std::string normalize_path_for_compare(std::filesystem::path path) {
  std::error_code ec;
  path = std::filesystem::weakly_canonical(path, ec);
  if (ec) {
    path = path.lexically_normal();
  }
  std::string text = path.string();
  while (!text.empty() && text.back() == '/') {
    text.pop_back();
  }
  return text;
}
#endif

bool path_env_contains_dir(const std::filesystem::path &dir) {
  const auto expected = normalize_path_for_compare(dir);
  for (const auto &part : split_path_env(env_value("PATH"))) {
    if (part.empty()) {
      continue;
    }
    if (normalize_path_for_compare(std::filesystem::path(part)) == expected) {
      return true;
    }
  }
  return false;
}

#ifdef _WIN32
std::vector<std::wstring> split_windows_path(const std::wstring &value) {
  std::vector<std::wstring> parts;
  std::wstring current;
  for (wchar_t ch : value) {
    if (ch == L';') {
      if (!current.empty()) {
        parts.push_back(current);
      }
      current.clear();
    } else {
      current.push_back(ch);
    }
  }
  if (!current.empty()) {
    parts.push_back(current);
  }
  return parts;
}

std::wstring join_windows_path(const std::vector<std::wstring> &parts) {
  std::wstring result;
  for (const auto &part : parts) {
    if (part.empty()) {
      continue;
    }
    if (!result.empty()) {
      result += L';';
    }
    result += part;
  }
  return result;
}

bool update_user_path_with_cli_dir(bool add, std::string *warning) {
  HKEY key = nullptr;
  LONG open_result = RegCreateKeyExW(
      HKEY_CURRENT_USER, L"Environment", 0, nullptr, 0,
      KEY_QUERY_VALUE | KEY_SET_VALUE, nullptr, &key, nullptr);
  if (open_result != ERROR_SUCCESS) {
    if (warning) {
      *warning = "CLI copied, but user PATH could not be updated.";
    }
    return false;
  }

  DWORD type = 0;
  DWORD size = 0;
  LONG query_size = RegQueryValueExW(key, L"Path", nullptr, &type, nullptr, &size);
  std::wstring path_value;
  if (query_size == ERROR_SUCCESS &&
      (type == REG_SZ || type == REG_EXPAND_SZ) && size > 0) {
    path_value.resize(size / sizeof(wchar_t));
    LONG query = RegQueryValueExW(
        key, L"Path", nullptr, &type,
        reinterpret_cast<LPBYTE>(path_value.data()), &size);
    if (query == ERROR_SUCCESS) {
      while (!path_value.empty() && path_value.back() == L'\0') {
        path_value.pop_back();
      }
    } else {
      path_value.clear();
    }
  }

  const auto cli_dir = cli_install_dir();
  const std::wstring cli_dir_text = cli_dir.wstring();
  const std::wstring cli_dir_cmp = normalize_path_for_compare(cli_dir);
  std::vector<std::wstring> parts = split_windows_path(path_value);
  const auto matches_cli_dir = [&](const std::wstring &part) {
    return normalize_path_for_compare(std::filesystem::path(part)) == cli_dir_cmp;
  };

  const bool already_present =
      std::any_of(parts.begin(), parts.end(), matches_cli_dir);
  bool changed = false;
  if (add && !already_present) {
    parts.push_back(cli_dir_text);
    changed = true;
  } else if (!add && already_present) {
    parts.erase(std::remove_if(parts.begin(), parts.end(), matches_cli_dir),
                parts.end());
    changed = true;
  }

  if (changed) {
    std::wstring next = join_windows_path(parts);
    LONG set_result = RegSetValueExW(
        key, L"Path", 0, REG_EXPAND_SZ,
        reinterpret_cast<const BYTE *>(next.c_str()),
        static_cast<DWORD>((next.size() + 1) * sizeof(wchar_t)));
    if (set_result != ERROR_SUCCESS && warning) {
      *warning = "CLI copied, but user PATH could not be updated.";
    }
  }
  RegCloseKey(key);

  SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                      reinterpret_cast<LPARAM>(L"Environment"),
                      SMTO_ABORTIFHUNG, 2000, nullptr);
  return true;
}
#endif

nlohmann::json cli_status_json(std::string warning = {}) {
  const auto target = cli_target_path();
  const auto source = cli_source_path();
  std::error_code ec;
  const bool installed = std::filesystem::exists(target, ec) && !ec;
  const bool available_in_path = path_env_contains_dir(cli_install_dir());
  if (warning.empty() && installed && !available_in_path) {
    warning = "CLI 已安装；请打开新终端让 PATH 生效。";
  }
  return nlohmann::json{{"installed", installed},
                        {"installPath", target.string()},
                        {"targetPath", source.string()},
                        {"availableInPath", available_in_path},
                        {"warning", warning}};
}

} // namespace
SystemStatusUseCases::SystemStatusUseCases()
    : SystemStatusUseCases(exv::platform::get_config_dir()) {}

SystemStatusUseCases::SystemStatusUseCases(std::string config_dir)
    : manager_(std::move(config_dir)) {
  exv::platform::logging::configure_default_logging(false);
}

UseCaseResult SystemStatusUseCases::service_status() {
  return UseCaseResult::ok(exv::platform::service_status_to_json(
      exv::platform::current_service_status()));
}

UseCaseResult SystemStatusUseCases::helper_status() {
  exv::platform::BackendResolveOptions options;
  options.preferred_mode = "auto";
  options.allow_oneshot = true;
  options.allow_service_start = false;
  nlohmann::json resolved = exv::platform::resolve_backend(options);
  if (!resolved.value("ok", false)) {
    resolved["resolved"] = false;
    resolved["resolution_code"] = resolved.value("code", std::string());
    resolved["resolution_message"] = resolved.value("message", std::string());
    resolved["ok"] = true;
  } else {
    resolved["resolved"] = true;
  }
  return UseCaseResult::ok(resolved);
}

UseCaseResult SystemStatusUseCases::runtime_status() {
  exv::Config cfg = manager_.load();
  return UseCaseResult::ok(exv::platform::runtime_status_json(
      exv::config::to_platform_config_view(cfg)));
}

UseCaseResult SystemStatusUseCases::driver_status() {
  exv::Config cfg = manager_.load();
  return UseCaseResult::ok(exv::platform::driver_status_json(
      exv::config::to_platform_config_view(cfg)));
}

UseCaseResult
SystemStatusUseCases::install_driver(const nlohmann::json &payload) {
  exv::Config cfg = manager_.load();
  nlohmann::json result = exv::platform::install_driver(
      exv::config::to_platform_config_view(cfg), payload);
  if (result.is_object() && result.value("ok", true) == false) {
    return UseCaseResult::fail(result.value("code", "driver_install_failed"),
                               result.value("error", "Driver install failed"));
  }
  return UseCaseResult::ok(result);
}

UseCaseResult SystemStatusUseCases::cli_status() {
  return UseCaseResult::ok(cli_status_json());
}

UseCaseResult SystemStatusUseCases::install_cli() {
  const auto source = cli_source_path();
  const auto target = cli_target_path();
  std::error_code ec;
  if (!std::filesystem::exists(source, ec) || ec) {
    return UseCaseResult::fail("cli_source_missing",
                               "CLI source executable was not found.");
  }

  std::string warning;
  std::filesystem::create_directories(target.parent_path(), ec);
  if (ec) {
    return UseCaseResult::fail("cli_install_failed",
                               "Failed to create CLI install directory.");
  }

  const bool already_target = std::filesystem::equivalent(source, target, ec);
  if (ec) {
    ec.clear();
  }
  if (!already_target) {
    std::filesystem::copy_file(
        source, target, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
      return UseCaseResult::fail("cli_install_failed",
                                 "Failed to copy CLI executable: " +
                                     ec.message());
    }
  }

#ifdef _WIN32
  (void)update_user_path_with_cli_dir(true, &warning);
#else
  chmod(target.c_str(), 0755);
  if (!path_env_contains_dir(target.parent_path())) {
    warning = "CLI copied to ~/.local/bin; add it to PATH if exv is not found.";
  }
#endif

  return UseCaseResult::ok(cli_status_json(std::move(warning)));
}

UseCaseResult SystemStatusUseCases::uninstall_cli() {
  const auto target = cli_target_path();
  std::error_code ec;
  if (std::filesystem::exists(target, ec) && !ec) {
    std::filesystem::remove(target, ec);
    if (ec) {
      return UseCaseResult::fail("cli_uninstall_failed",
                                 "Failed to remove CLI executable: " +
                                     ec.message());
    }
  }

#ifdef _WIN32
  std::string warning;
  (void)update_user_path_with_cli_dir(false, &warning);
  return UseCaseResult::ok(cli_status_json(std::move(warning)));
#else
  return UseCaseResult::ok(cli_status_json());
#endif
}

UseCaseResult SystemStatusUseCases::install_helper() {
  return run_elevated_service_op("install-service", "service_install_failed",
                                 "Helper service installation failed.",
                                 /*desired_installed=*/true);
}

UseCaseResult SystemStatusUseCases::uninstall_helper() {
  exv::Config cfg = manager_.load();
  auto runtime = exv::vpn::read_runtime_status_snapshot(cfg);
  if (runtime.running || runtime.network_ready) {
    return UseCaseResult::fail(
        "vpn_session_active",
        "Disconnect the VPN session before uninstalling the helper service.");
  }
  return run_elevated_service_op("uninstall-service", "service_uninstall_failed",
                                 "Helper service uninstallation failed.",
                                 /*desired_installed=*/false);
}

UseCaseResult SystemStatusUseCases::repair_helper() {
  return run_elevated_service_op("repair-service", "service_repair_failed",
                                 "Helper service repair failed.",
                                 /*desired_installed=*/true);
}

} // namespace exv::core

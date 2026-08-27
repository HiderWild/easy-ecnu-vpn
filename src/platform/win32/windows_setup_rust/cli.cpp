#include "windows_setup_rust/cli.hpp"

#include "windows_setup_rust/app_paths.hpp"

#include <algorithm>
#include <cctype>
#include <cwchar>

namespace exv::setup {
namespace {

std::wstring ToLowerAscii(std::wstring value) {
  for (auto &ch : value) {
    if (ch >= L'A' && ch <= L'Z') {
      ch = static_cast<wchar_t>(ch - L'A' + L'a');
    }
  }
  return value;
}

std::wstring FileNameOf(const std::wstring &path) {
  const auto pos = path.find_last_of(L"\\/");
  if (pos == std::wstring::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

bool StartsWithIgnoreCase(const std::wstring &value, const wchar_t *prefix) {
  const auto p = ToLowerAscii(value);
  const auto pref = ToLowerAscii(prefix);
  return p.compare(0, pref.size(), pref) == 0;
}

bool EqualsIgnoreCase(const std::wstring &a, const wchar_t *b) {
  return ToLowerAscii(a) == ToLowerAscii(b);
}

bool ParseBoolFlag(const std::wstring &arg, const wchar_t *name, bool &out) {
  // name is like L"/desktop-shortcut="
  if (!StartsWithIgnoreCase(arg, name)) {
    return false;
  }
  const auto prefix_len = std::wcslen(name);
  if (arg.size() <= prefix_len) {
    return false;
  }
  const auto v = arg.substr(prefix_len);
  if (v == L"1" || EqualsIgnoreCase(v, L"true") || EqualsIgnoreCase(v, L"yes")) {
    out = true;
    return true;
  }
  if (v == L"0" || EqualsIgnoreCase(v, L"false") || EqualsIgnoreCase(v, L"no")) {
    out = false;
    return true;
  }
  return false;
}

}  // namespace

bool IsUninstallExecutableName(const std::wstring &path_or_name) {
  return EqualsIgnoreCase(FileNameOf(path_or_name), L"Uninstall.exe");
}

std::wstring DefaultInstallDir() {
  return DefaultPerUserInstallDir();
}

std::wstring ResolveGuiInstallDir(bool uninstall, const CliOptions &options) {
  if (uninstall) {
    return options.install_dir;
  }
  return options.install_dir.empty() ? DefaultInstallDir() : options.install_dir;
}

std::optional<CliOptions> ParseCli(int argc, wchar_t **argv) {
  if (argc < 0 || argv == nullptr) {
    return std::nullopt;
  }

  CliOptions opts;
  bool silent = false;
  bool uninstall = false;
  bool elevated = false;

  if (argc >= 1 && argv[0] != nullptr && IsUninstallExecutableName(argv[0])) {
    uninstall = true;
  }

  for (int i = 1; i < argc; ++i) {
    if (argv[i] == nullptr) {
      continue;
    }
    const std::wstring arg = argv[i];
    if (arg.empty()) {
      continue;
    }

    if (EqualsIgnoreCase(arg, L"/S") || EqualsIgnoreCase(arg, L"/silent") ||
        EqualsIgnoreCase(arg, L"--silent")) {
      silent = true;
      continue;
    }
    if (EqualsIgnoreCase(arg, L"/uninstall") || EqualsIgnoreCase(arg, L"--uninstall")) {
      uninstall = true;
      continue;
    }
    if (EqualsIgnoreCase(arg, L"/clear-user-data") ||
        EqualsIgnoreCase(arg, L"--clear-user-data")) {
      opts.clear_user_data = true;
      continue;
    }
    if (EqualsIgnoreCase(arg, L"/elevated-worker") ||
        EqualsIgnoreCase(arg, L"--elevated-worker")) {
      elevated = true;
      continue;
    }
    if (EqualsIgnoreCase(arg, L"--pipe") || EqualsIgnoreCase(arg, L"/pipe")) {
      if (i + 1 >= argc || argv[i + 1] == nullptr) {
        return std::nullopt;
      }
      opts.elevated_pipe = argv[++i];
      continue;
    }
    if (StartsWithIgnoreCase(arg, L"--pipe=")) {
      opts.elevated_pipe = arg.substr(7);
      continue;
    }
    if (EqualsIgnoreCase(arg, L"--token") || EqualsIgnoreCase(arg, L"/token")) {
      if (i + 1 >= argc || argv[i + 1] == nullptr) {
        return std::nullopt;
      }
      opts.elevated_token = argv[++i];
      continue;
    }
    if (StartsWithIgnoreCase(arg, L"--token=")) {
      opts.elevated_token = arg.substr(8);
      continue;
    }

    // NSIS-compatible /D=path or /D path
    if (StartsWithIgnoreCase(arg, L"/D=")) {
      opts.install_dir = arg.substr(3);
      continue;
    }
    if (EqualsIgnoreCase(arg, L"/D")) {
      if (i + 1 >= argc || argv[i + 1] == nullptr) {
        return std::nullopt;
      }
      opts.install_dir = argv[++i];
      continue;
    }

    if (ParseBoolFlag(arg, L"/desktop-shortcut=", opts.desktop_shortcut) ||
        ParseBoolFlag(arg, L"--desktop-shortcut=", opts.desktop_shortcut) ||
        ParseBoolFlag(arg, L"/start-menu=", opts.start_menu) ||
        ParseBoolFlag(arg, L"--start-menu=", opts.start_menu) ||
        ParseBoolFlag(arg, L"/quick-launch=", opts.quick_launch) ||
        ParseBoolFlag(arg, L"--quick-launch=", opts.quick_launch) ||
        ParseBoolFlag(arg, L"/launch=", opts.launch_app) ||
        ParseBoolFlag(arg, L"--launch=", opts.launch_app)) {
      continue;
    }

    // Unknown flags starting with / or - are hard errors for safety in silent automation.
    if (arg[0] == L'/' || arg[0] == L'-') {
      return std::nullopt;
    }
  }

  if (elevated) {
    if (opts.elevated_pipe.empty() || opts.elevated_token.empty()) {
      return std::nullopt;
    }
    opts.role = Role::ElevatedWorker;
    return opts;
  }

  if (uninstall) {
    opts.role = silent ? Role::UninstallSilent : Role::UninstallGui;
  } else {
    opts.role = silent ? Role::InstallSilent : Role::InstallGui;
  }

  if (opts.install_dir.empty() &&
      (opts.role == Role::InstallGui || opts.role == Role::InstallSilent)) {
    opts.install_dir = DefaultInstallDir();
  }

  return opts;
}

}  // namespace exv::setup

#pragma once

#include <optional>
#include <string>

namespace exv::setup {

enum class Role {
  InstallGui,
  InstallSilent,
  UninstallGui,
  UninstallSilent,
  ElevatedWorker,
};

struct CliOptions {
  Role role{Role::InstallGui};
  std::wstring install_dir;
  bool clear_user_data{false};
  bool desktop_shortcut{true};
  bool start_menu{true};
  bool quick_launch{false};
  bool launch_app{true};
  std::wstring elevated_pipe;
  std::wstring elevated_token;
};

// Parses wide argv (like wmain). Returns nullopt only on unrecoverable parse errors.
std::optional<CliOptions> ParseCli(int argc, wchar_t **argv);

// Default per-user install directory: %LOCALAPPDATA%\Programs\EXV
std::wstring DefaultInstallDir();

// GUI directory resolution keeps uninstall empty when /D was not supplied so
// the uninstall engine can read the registered custom install directory.
std::wstring ResolveGuiInstallDir(bool uninstall, const CliOptions &options);

// True when executable base name is Uninstall.exe (case-insensitive).
bool IsUninstallExecutableName(const std::wstring &path_or_name);

}  // namespace exv::setup

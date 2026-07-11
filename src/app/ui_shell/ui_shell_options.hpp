#pragma once

#include <filesystem>
#include <string>

namespace exv::ui_shell {

struct UiShellOptions {
  std::string renderer_dev_server_url;
  std::string packaged_renderer_index;
  std::string exv_path;
  std::string state_dir;
  bool enable_dev_tools = false;
  bool start_hidden = false;
  bool start_visibility_explicit = false;
};

UiShellOptions parse_ui_shell_options(int argc, char **argv);
UiShellOptions parse_ui_shell_args_file(const std::filesystem::path &args_file);
UiShellOptions load_packaged_ui_shell_options(
    const std::filesystem::path &executable_path);
UiShellOptions resolve_ui_shell_options(
    int argc, char **argv, const std::filesystem::path &executable_path);
std::string validate_ui_shell_options(const UiShellOptions &options);
std::string validate_packaged_ui_shell_options(
    const UiShellOptions &options, const std::filesystem::path &package_root);

} // namespace exv::ui_shell

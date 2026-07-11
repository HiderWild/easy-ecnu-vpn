#include "app/ui_shell/core_process_manager.hpp"
#include "app/ui_shell/core_gateway.hpp"
#include "app/ui_shell/core_rpc_client.hpp"
#include "app/ui_shell/renderer_assets.hpp"
#include "app/ui_shell/ui_shell_options.hpp"
#include "app/ui_shell/ui_shell_runtime.hpp"
#include "app/ui_shell/ui_shell_single_instance.hpp"
#include "app/ui_shell/ui_window.hpp"
#include "core/config/config.hpp"
#include "runtime/runtime_context.hpp"

#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#elif defined(__linux__)
#include <array>
#include <unistd.h>
#endif

namespace {

std::filesystem::path current_executable_path() {
#if defined(_WIN32)
  std::vector<wchar_t> buffer(32768);
  const DWORD length = GetModuleFileNameW(
      nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (length == 0 || length >= buffer.size()) {
    return {};
  }
  return std::filesystem::path(std::wstring(buffer.data(), length));
#elif defined(__APPLE__)
  uint32_t size = 0;
  _NSGetExecutablePath(nullptr, &size);
  std::vector<char> buffer(size);
  if (_NSGetExecutablePath(buffer.data(), &size) != 0) {
    return {};
  }
  return std::filesystem::path(buffer.data());
#elif defined(__linux__)
  std::array<char, 4096> buffer{};
  const ssize_t length =
      readlink("/proc/self/exe", buffer.data(), buffer.size() - 1);
  if (length <= 0) {
    return {};
  }
  return std::filesystem::path(std::string(buffer.data(), static_cast<size_t>(length)));
#else
  return {};
#endif
}

} // namespace

#if defined(_WIN32)
namespace exv::platform::win32::ui_shell {
std::unique_ptr<exv::ui_shell::UiWindow> create_webview2_window();
}
#elif defined(__APPLE__)
namespace exv::platform::darwin::ui_shell {
std::unique_ptr<exv::ui_shell::UiWindow> create_wk_webview_window();
}
#elif defined(__linux__)
namespace exv::platform::linux_ui_shell {
std::unique_ptr<exv::ui_shell::UiWindow> create_webkitgtk_window();
}
#endif

int main(int argc, char **argv) {
  auto options = exv::ui_shell::resolve_ui_shell_options(
      argc, argv, current_executable_path());
  const std::string validation_error =
      exv::ui_shell::validate_ui_shell_options(options);
  if (!validation_error.empty()) {
    std::cerr << "exv-ui: " << validation_error << '\n';
    return 64;
  }

  exv::ui_shell::UiWindowConfig config{
      exv::ui_shell::resolve_renderer_assets(
          options.renderer_dev_server_url, options.packaged_renderer_index),
      options.exv_path,
      options.enable_dev_tools,
  };
  exv::runtime::bootstrap(options.state_dir);
  config.state_dir = exv::runtime::paths().state_dir;
  config.start_hidden = options.start_visibility_explicit
                            ? options.start_hidden
                            : exv::config::load().silent_startup;

  auto single_instance =
      exv::ui_shell::acquire_ui_shell_single_instance(config.state_dir);
  if (single_instance && !single_instance->is_primary()) {
    return 0;
  }
  if (single_instance) {
    config.poll_wake_requests =
        [instance = single_instance.get()](const std::function<void()> &on_wake) {
          instance->poll_wake_requests(on_wake);
        };
  }

  exv::ui_shell::configure_core_process_transport_signal_policy();
  exv::ui_shell::CoreProcessLaunch core_launch{
      options.exv_path,
      config.state_dir,
      exv::runtime::paths().home,
      true};
  exv::ui_shell::CoreGateway gateway(core_launch);

#if defined(_WIN32)
  auto window = exv::platform::win32::ui_shell::create_webview2_window();
#elif defined(__APPLE__)
  auto window = exv::platform::darwin::ui_shell::create_wk_webview_window();
#elif defined(__linux__)
  auto window = exv::platform::linux_ui_shell::create_webkitgtk_window();
#else
  return 70;
#endif
  if (!window) {
    std::cerr << "exv-ui: failed to create platform WebView window\n";
    return 70;
  }
  return exv::ui_shell::run_ui_shell_window(*window, config, gateway);
}

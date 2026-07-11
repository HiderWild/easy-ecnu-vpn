#pragma once

#include "app/ui_shell/core_rpc_client.hpp"
#include "app/ui_shell/host_bridge.hpp"
#include "app/ui_shell/tray_status_snapshot.hpp"
#include "app/ui_shell/ui_window.hpp"
#include "app/ui_shell/window_layout.hpp"

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace exv::platform::win32::ui_shell {

std::string dispatch_webview2_host_message(
    const std::string &message_json,
    const exv::ui_shell::CoreRpcInvoker &invoke_core);

void post_webview2_host_response(
    const std::string &message_json,
    const exv::ui_shell::CoreRpcInvoker &invoke_core,
    const std::function<void(const std::string &)> &post_response);

std::wstring webview2_renderer_uri(
    const exv::ui_shell::RendererAssets &renderer);

std::wstring webview2_packaged_renderer_folder(
    const exv::ui_shell::RendererAssets &renderer);

[[nodiscard]] exv::ui_shell::WindowBounds
webview2_default_window_bounds() noexcept;

[[nodiscard]] exv::ui_shell::WindowBounds
webview2_window_mode_bounds_for_dpi(std::string_view mode,
                                    unsigned int dpi) noexcept;

struct WebView2TrayMenuItem {
  std::wstring label;
  int command_id;
  bool separator;
  bool enabled;
};

enum class WebView2CloseDecision {
  QuitImmediately,
  ApplyRememberedPreference,
  Prompt,
};

WebView2CloseDecision webview2_close_decision_for_connection(
    bool vpn_connected, bool has_remembered_preference) noexcept;

std::vector<WebView2TrayMenuItem> webview2_tray_menu_model(
    const exv::ui_shell::TrayStatusSnapshot &snapshot = {});
bool webview2_should_create_tray_on_start();
std::wstring webview2_taskbar_created_message_name();
int webview2_app_icon_resource_id() noexcept;

std::unique_ptr<exv::ui_shell::UiWindow> create_webview2_window();

} // namespace exv::platform::win32::ui_shell

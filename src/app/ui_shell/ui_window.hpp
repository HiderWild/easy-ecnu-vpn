#pragma once

#include "app/ui_shell/renderer_assets.hpp"
#include "app/ui_shell/tray_status_snapshot.hpp"

#include <functional>
#include <string>

namespace exv::ui_shell {

using HostMessageHandler = std::function<std::string(const std::string &)>;

struct UiWindowConfig {
  RendererAssets renderer;
  std::string exv_path;
  bool enable_dev_tools = false;
  std::function<void()> pump_core_events;
  std::function<bool()> is_vpn_connected;
  bool start_hidden = true;
  std::function<TrayStatusSnapshot()> tray_status_snapshot_provider;
  std::function<void()> disconnect_vpn_in_background;
  std::function<void(const std::function<void()> &)> poll_wake_requests;
  std::string state_dir;
};

class UiWindow {
public:
  virtual ~UiWindow() = default;
  virtual void set_message_handler(HostMessageHandler handler) = 0;
  virtual int run(const UiWindowConfig &config) = 0;
  virtual void emit_event(const std::string &event_json) = 0;
  virtual void post_host_response(const std::string &response_json) {
    (void)response_json;
  }
};

} // namespace exv::ui_shell

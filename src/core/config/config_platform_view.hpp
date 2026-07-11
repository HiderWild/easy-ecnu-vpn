#pragma once

#include "core/config/config.hpp"
#include "platform/common/config_view.hpp"

namespace exv {
namespace config {

inline platform::ConfigView to_platform_config_view(const Config &cfg) {
  platform::ConfigView view;
  view.server = cfg.server;
  view.username = cfg.username;
  view.mtu = cfg.mtu;
  view.useragent = cfg.useragent;
  view.disable_dtls = cfg.disable_dtls;
  view.dtls_mode = cfg.dtls_mode;
  view.extra_args = cfg.extra_args;
  view.log_file = cfg.log_file;
  view.vpn_engine = cfg.vpn_engine;
  view.windows_tunnel_driver = cfg.windows_tunnel_driver;
  view.windows_tap_interface = cfg.windows_tap_interface;
  return view;
}

} // namespace config
} // namespace exv

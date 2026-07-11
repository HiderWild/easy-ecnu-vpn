#include "core/config/config.hpp"
#include "core/crypto/crypto.hpp"
#include "observability/log_facade.hpp"
#include "platform/common/logging/log_runtime.hpp"
#include "cli/console.hpp"

#include <iomanip>
#include <iostream>

namespace exv {
namespace config {

// ── Show ─────────────────────────────────────────────────────────

void show(const Config &cfg) {
  cli::print_header("EXV Configuration");
  std::cout << "  " << cli::BOLD << "Server" << cli::RESET << "       : "
            << cfg.server << std::endl;
  std::cout << "  " << cli::BOLD << "Username" << cli::RESET << "     : "
            << cfg.username << std::endl;
  std::cout << "  " << cli::BOLD << "Password" << cli::RESET << "     : "
            << (cfg.password.empty() ? std::string(cli::DIM) + "(not stored)"
                                     : std::string(cli::GREEN) + "(encrypted)")
            << cli::RESET << std::endl;
  std::cout << "  " << cli::BOLD << "MTU" << cli::RESET << "          : "
            << cfg.mtu << std::endl;
  std::cout << "  " << cli::BOLD << "User-Agent" << cli::RESET << "   : "
            << cfg.useragent << std::endl;
  std::cout << "  " << cli::BOLD << "DTLS" << cli::RESET << "         : "
            << cfg.dtls_mode << std::endl;
  std::cout << "  " << cli::BOLD << "Remember PW" << cli::RESET << "  : "
            << (cfg.remember_password ? "yes" : "no") << std::endl;
  std::cout << "  " << cli::BOLD << "Auto Reconnect" << cli::RESET << ": "
            << (cfg.auto_reconnect ? "yes" : "no") << std::endl;
  std::cout << "  " << cli::BOLD << "Retry Limit" << cli::RESET << "   : "
            << (cfg.retry_limit == 0 ? "unlimited" : std::to_string(cfg.retry_limit))
            << std::endl;
  std::cout << "  " << cli::BOLD << "VPN Engine" << cli::RESET << "   : "
            << cfg.vpn_engine << std::endl;
  std::cout << "  " << cli::BOLD << "Tunnel Driver" << cli::RESET << ": "
            << cfg.windows_tunnel_driver << std::endl;
  std::cout << "  " << cli::BOLD << "Log File" << cli::RESET << "     : "
            << cfg.log_file << std::endl;
  std::cout << "  " << cli::BOLD << "Minimal Mode" << cli::RESET << " : "
            << (cfg.minimal_mode ? "yes" : "no") << std::endl;
  std::cout << std::endl;

  list_routes(cfg);
  key_show();
}

} // namespace config
} // namespace exv

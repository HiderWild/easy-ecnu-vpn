#include "platform/common/file_system.hpp"
#include "platform/common/interface_stats.hpp"
#include "platform/common/process_utils.hpp"
#include "platform/common/runtime_discovery.hpp"
#include "platform/common/runtime_paths.hpp"
#include "platform/common/helper_service_manager.hpp"

#include "platform/common/helper_lifecycle.hpp"
#include "platform/common/helper_platform.hpp"
#include "platform/common/service_status.hpp"
#include "cli/console.hpp"

#include <fstream>
#include <filesystem>
#include <iostream>
#include <string>

namespace exv {
namespace platform {
namespace {

bool wait_until_ready(const HelperServiceManagerContext &context, int attempts,
                     unsigned int delay_us) {
  return context.wait_until_available &&
         context.wait_until_available(attempts, delay_us);
}

bool send_helper_request(const HelperServiceManagerContext &context,
                         const nlohmann::json &request,
                         nlohmann::json *response,
                         std::string *error_message,
                         int timeout_seconds = 15) {
  return context.send_request &&
         context.send_request(request, response, error_message,
                              timeout_seconds);
}

void print_runtime_status_if_available(const HelperServiceManagerContext &context,
                                       bool available) {
  (void)context;
  if (!available)
    return;
}

} // namespace

int install_helper_service(const std::string &executable_path,
                           const HelperServiceManagerContext &context) {
  const auto &platform_config = helper_platform_config();

  if (!platform::check_root()) {
    cli::print_error("Root privileges required. Please run with sudo.");
    return 1;
  }

  std::string exec_path = executable_path.empty() ? platform::get_executable_path()
                                                  : executable_path;
  if (exec_path.empty()) {
    cli::print_error("Failed to resolve the exv executable path.");
    return 1;
  }
  std::filesystem::path exec_fs_path(exec_path);
  std::filesystem::path helper_path =
      exec_fs_path.parent_path() / "exv-helper";
  std::string service_binary;
  if (exec_fs_path.filename() == "exv-helper") {
    service_binary = exec_path;
  } else if (std::filesystem::exists(helper_path)) {
    service_binary = helper_path.string();
  } else {
    cli::print_error("Dedicated exv-helper binary was not found next to exv.");
    return 1;
  }

  std::ofstream ofs(platform_config.service_definition_path);
  if (!ofs.is_open()) {
    cli::print_error("Failed to write systemd unit file: " +
                       std::string(platform_config.service_definition_path));
    return 1;
  }
  ofs << "[Unit]\n";
  ofs << "Description=EXV Helper Daemon\n";
  ofs << "After=network.target\n\n";
  ofs << "[Service]\n";
  ofs << "Type=simple\n";
  ofs << "ExecStart=" << service_binary << " --service\n";
  ofs << "Restart=on-failure\n";
  ofs << "RestartSec=5\n\n";
  ofs << "[Install]\n";
  ofs << "WantedBy=multi-user.target\n";
  ofs.close();

  if (platform::run_command("systemctl daemon-reload") != 0) {
    cli::print_error("Failed to reload systemd daemon.");
    return 1;
  }

  std::string enable_cmd =
      "systemctl enable " + std::string(platform_config.service_name);
  if (platform::run_command(enable_cmd) != 0) {
    cli::print_error("Failed to enable EXV helper service.");
    return 1;
  }

  std::string start_cmd =
      "systemctl start " + std::string(platform_config.service_name);
  if (platform::run_command(start_cmd) != 0) {
    cli::print_error("Failed to start EXV helper service.");
    return 1;
  }

  bool helper_ready = wait_until_ready(context, 50, 100000);

  cli::print_success("EXV helper service installed.");
  if (!helper_ready) {
    cli::print_warning(
        "Helper service was installed, but it has not responded on the socket yet.");
    cli::print_info("Run 'exv service status' again in a moment if needed.");
  }
  cli::print_info("You can now run 'exv' and 'exv stop' without sudo.");
  return 0;
}

int uninstall_helper_service(const HelperServiceManagerContext &context) {
  const auto &platform_config = helper_platform_config();

  if (!platform::check_root()) {
    cli::print_error("Root privileges required. Please run with sudo.");
    return 1;
  }

  if (context.cleanup_routes)
    context.cleanup_routes();

  std::string stop_cmd =
      "systemctl stop " + std::string(platform_config.service_name);
  platform::run_command(stop_cmd + " >/dev/null 2>&1");
  std::string disable_cmd =
      "systemctl disable " + std::string(platform_config.service_name);
  platform::run_command(disable_cmd + " >/dev/null 2>&1");
  if (*platform_config.service_definition_path)
    std::remove(platform_config.service_definition_path);
  if (*platform_config.endpoint)
    std::remove(platform_config.endpoint);
  platform::run_command("systemctl daemon-reload >/dev/null 2>&1");
  if (context.clear_session_state)
    context.clear_session_state();

  // Full artifact cleanup: remove the stable helper binary, the one-shot
  // socket endpoint, and kill any orphaned one-shot helpers (best-effort) so
  // the "not installed" state is trustworthy for the next backend resolution.
  if (*platform_config.default_service_binary_path)
    std::remove(platform_config.default_service_binary_path);
  platform::run_command(
      "rm -f /tmp/exv-*-oneshot.sock >/dev/null 2>&1");
  platform::run_command(
      "pkill -f 'exv-helper.*--oneshot' >/dev/null 2>&1");

  const ServiceStatusSnapshot after = current_service_status();
  if (after.installed) {
    cli::print_error("Uninstall completed but the service is still installed.");
    return 1;
  }

  cli::print_success("EXV helper service uninstalled.");
  return 0;
}

int repair_helper_service(const HelperServiceManagerContext &context) {
  const auto &platform_config = helper_platform_config();

  if (!platform::check_root()) {
    cli::print_error("Root privileges required. Please run with sudo.");
    return 1;
  }

  if (!platform::file_exists(platform_config.service_definition_path)) {
    cli::print_error("EXV helper service is not installed.");
    return 1;
  }

  std::string start_cmd =
      "systemctl start " + std::string(platform_config.service_name);
  if (platform::run_command(start_cmd) != 0) {
    cli::print_error("Failed to start EXV helper service.");
    return 1;
  }

  if (!wait_until_ready(context, 50, 100000)) {
    cli::print_error("Helper service is running but did not respond.");
    return 1;
  }

  cli::print_success("EXV helper service repaired.");
  return 0;
}

int show_helper_service_status(const HelperServiceManagerContext &context) {
  const auto &platform_config = helper_platform_config();

  cli::print_header("EXV Service Status");

  bool installed = platform::file_exists(platform_config.service_definition_path);
  bool available = installed ? wait_until_ready(context, 10, 100000) : false;
  std::cout << "  Installed       : " << (installed ? "yes" : "no")
            << std::endl;
  std::cout << "  Socket Ready    : " << (available ? "yes" : "no")
            << std::endl;
  print_runtime_status_if_available(context, available);
  std::cout << std::endl;
  return 0;
}

} // namespace platform
} // namespace exv

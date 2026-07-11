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

#include <sys/stat.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
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

bool files_have_same_contents(const std::filesystem::path &left,
                              const std::filesystem::path &right) {
  std::error_code ec;
  if (!std::filesystem::is_regular_file(left, ec) ||
      !std::filesystem::is_regular_file(right, ec)) {
    return false;
  }

  const auto left_size = std::filesystem::file_size(left, ec);
  if (ec)
    return false;
  const auto right_size = std::filesystem::file_size(right, ec);
  if (ec || left_size != right_size)
    return false;

  std::ifstream left_stream(left, std::ios::binary);
  std::ifstream right_stream(right, std::ios::binary);
  if (!left_stream || !right_stream)
    return false;

  std::array<char, 65536> left_buffer{};
  std::array<char, 65536> right_buffer{};
  while (left_stream && right_stream) {
    left_stream.read(left_buffer.data(), left_buffer.size());
    right_stream.read(right_buffer.data(), right_buffer.size());
    if (left_stream.gcount() != right_stream.gcount())
      return false;
    if (!std::equal(left_buffer.begin(),
                    left_buffer.begin() + left_stream.gcount(),
                    right_buffer.begin())) {
      return false;
    }
  }
  return left_stream.eof() && right_stream.eof();
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

  std::filesystem::path helper_source =
      std::filesystem::path(exec_path).parent_path() / "exv-helper";
  if (helper_source.string() != platform_config.default_service_binary_path &&
      std::filesystem::exists(helper_source)) {
    std::error_code copy_error;
    std::filesystem::create_directories(
        std::filesystem::path(platform_config.default_service_binary_path)
            .parent_path(),
        copy_error);
    if (copy_error) {
      cli::print_error("Failed to create stable helper directory: " +
                       copy_error.message());
      return 1;
    }
    if (!files_have_same_contents(
            helper_source, platform_config.default_service_binary_path)) {
      std::filesystem::copy_file(
          helper_source, platform_config.default_service_binary_path,
          std::filesystem::copy_options::overwrite_existing, copy_error);
      if (copy_error) {
        cli::print_error(
            "Failed to copy exv-helper to " +
            std::string(platform_config.default_service_binary_path) + ": " +
            copy_error.message());
        return 1;
      }
    }
    chmod(platform_config.default_service_binary_path, 0755);
  }

  if (!platform::file_exists(platform_config.default_service_binary_path)) {
    cli::print_error("Stable exv-helper binary is missing: " +
                       std::string(platform_config.default_service_binary_path));
    cli::print_info(
        "Install the CLI separately from Settings if you want a global exv command.");
    return 1;
  }

  std::string shell_command =
      "if [ ! -x " +
      platform::shell_quote(platform_config.default_service_binary_path) +
      " ]; then exit 0; fi; exec " +
      platform::shell_quote(platform_config.default_service_binary_path) +
      " --service";

  std::ostringstream plist;
  plist << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  plist << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
           "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n";
  plist << "<plist version=\"1.0\">\n";
  plist << "<dict>\n";
  plist << "  <key>Label</key>\n";
  plist << "  <string>" << platform_config.service_label << "</string>\n";
  plist << "  <key>ProgramArguments</key>\n";
  plist << "  <array>\n";
  plist << "    <string>/bin/sh</string>\n";
  plist << "    <string>-c</string>\n";
  plist << "    <string>" << shell_command << "</string>\n";
  plist << "  </array>\n";
  plist << "  <key>RunAtLoad</key>\n";
  plist << "  <true/>\n";
  plist << "  <key>KeepAlive</key>\n";
  plist << "  <dict>\n";
  plist << "    <key>SuccessfulExit</key>\n";
  plist << "    <false/>\n";
  plist << "  </dict>\n";
  plist << "  <key>StandardOutPath</key>\n";
  plist << "  <string>/var/log/exv-helper.log</string>\n";
  plist << "  <key>StandardErrorPath</key>\n";
  plist << "  <string>/var/log/exv-helper.log</string>\n";
  plist << "  <key>ThrottleInterval</key>\n";
  plist << "  <integer>10</integer>\n";
  plist << "</dict>\n";
  plist << "</plist>\n";

  std::ofstream ofs(platform_config.service_definition_path);
  if (!ofs.is_open()) {
    cli::print_error("Failed to write LaunchDaemon plist: " +
                       std::string(platform_config.service_definition_path));
    return 1;
  }
  ofs << plist.str();
  ofs.close();
  chmod(platform_config.service_definition_path, 0644);

  platform::run_command(std::string("launchctl bootout system ") +
                     platform_config.service_definition_path +
                     " >/dev/null 2>&1");
  if (platform::run_command(std::string("launchctl bootstrap system ") +
                         platform_config.service_definition_path) != 0) {
    cli::print_error("Failed to bootstrap EXV helper LaunchDaemon.");
    return 1;
  }

  bool helper_ready = wait_until_ready(context, 50, 100000);

  platform::fix_config_dir_ownership();

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

  platform::run_command(std::string("launchctl bootout system ") +
                     platform_config.service_definition_path +
                     " >/dev/null 2>&1");
  if (*platform_config.service_definition_path)
    std::remove(platform_config.service_definition_path);
  if (*platform_config.endpoint)
    std::remove(platform_config.endpoint);
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

  std::string kickstart =
      "launchctl kickstart -k system/" +
      std::string(platform_config.service_label);
  if (platform::run_command(kickstart) != 0) {
    std::string bootstrap = std::string("launchctl bootstrap system ") +
                            platform_config.service_definition_path;
    if (platform::run_command(bootstrap) != 0) {
      cli::print_error("Failed to start EXV helper LaunchDaemon.");
      return 1;
    }
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

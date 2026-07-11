#include "platform/common/file_system.hpp"
#include "platform/common/interface_stats.hpp"
#include "platform/common/logging/log_runtime.hpp"
#include "platform/common/process_utils.hpp"
#include "platform/common/runtime_discovery.hpp"
#include "platform/common/runtime_paths.hpp"
#include "helper/helper.hpp"
#include "helper/helper_install_cli.hpp"
#include "platform/common/helper_platform.hpp"
#include "cli/console.hpp"

#include <iostream>
#include <optional>
#include <string>

#if defined(EXV_PLATFORM_WINDOWS)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace {

constexpr const char *kServiceName = "exv-helper";

SERVICE_STATUS_HANDLE service_status_handle = nullptr;
SERVICE_STATUS service_status = {};

void report_service_status(DWORD state, DWORD win32_exit_code = NO_ERROR,
                           DWORD wait_hint = 0) {
  if (!service_status_handle)
    return;

  service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  service_status.dwCurrentState = state;
  service_status.dwWin32ExitCode = win32_exit_code;
  service_status.dwWaitHint = wait_hint;
  service_status.dwControlsAccepted =
      state == SERVICE_RUNNING ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN)
                               : 0;

  static DWORD checkpoint = 1;
  if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
    service_status.dwCheckPoint = checkpoint++;
  } else {
    service_status.dwCheckPoint = 0;
  }

  SetServiceStatus(service_status_handle, &service_status);
}

DWORD WINAPI service_control_handler(DWORD control, DWORD, LPVOID, LPVOID) {
  if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
    report_service_status(SERVICE_STOP_PENDING, NO_ERROR, 3000);
    exv::helper::request_daemon_stop();
    return NO_ERROR;
  }
  return ERROR_CALL_NOT_IMPLEMENTED;
}

void WINAPI service_main(DWORD, LPSTR *) {
  service_status_handle =
      RegisterServiceCtrlHandlerExA(kServiceName, service_control_handler, NULL);
  if (!service_status_handle)
    return;

  report_service_status(SERVICE_START_PENDING, NO_ERROR, 3000);
  report_service_status(SERVICE_RUNNING);
  exv::helper::DaemonOptions options;
  options.mode = "service";
  options.endpoint = exv::platform::helper_platform_config().endpoint;
  int rc = exv::helper::daemon_main(options);
  report_service_status(SERVICE_STOPPED,
                        rc == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
}

int run_windows_service() {
  SERVICE_TABLE_ENTRYA table[] = {
      {const_cast<char *>(kServiceName), service_main},
      {NULL, NULL},
  };

  if (StartServiceCtrlDispatcherA(table))
    return 0;

  return 1;
}

} // namespace
#endif

namespace {

int print_usage() {
  std::cerr << "Usage:\n"
            << "  exv-helper --service\n"
            << "  exv-helper --oneshot --endpoint <endpoint> --owner <uid-or-sid> --parent-pid <pid>\n"
            << "  exv-helper --install-service\n"
            << "  exv-helper --uninstall-service\n"
            << "  exv-helper --repair-service\n";
  return 2;
}

bool read_option_value(int argc, char *argv[], int *index, std::string *value) {
  if (*index + 1 >= argc)
    return false;
  *value = argv[++(*index)];
  return true;
}

std::optional<int> parse_positive_int(const std::string &value) {
  try {
    size_t parsed = 0;
    int result = std::stoi(value, &parsed);
    if (parsed != value.size() || result <= 0)
      return std::nullopt;
    return result;
  } catch (...) {
    return std::nullopt;
  }
}

} // namespace

int main(int argc, char *argv[]) {
  exv::cli::enable_windows_ansi();

  // Emit logs to stdout so launchd captures them via StandardOutPath into
  // /var/log/exv-helper.log. Without this the helper is silent on failure
  // (bind errors, crashes) and the only symptom is the service appearing
  // installed-but-unavailable. configure_default_logging is idempotent.
  exv::platform::logging::configure_default_logging(true);

  if (argc > 1) {
    std::string arg = argv[1];

    if (arg == "--service") {
      exv::helper::DaemonOptions options;
      options.mode = "service";
      options.endpoint = exv::platform::helper_platform_config().endpoint;
#if defined(EXV_PLATFORM_WINDOWS)
      return run_windows_service();
#else
      return exv::helper::daemon_main(options);
#endif
    }

    if (arg == "--install-service") {
      return exv::helper::run_install_cli("install-service", {});
    }
    if (arg == "--uninstall-service") {
      return exv::helper::run_install_cli("uninstall-service", {});
    }
    if (arg == "--repair-service") {
      return exv::helper::run_install_cli("repair-service", {});
    }

    if (arg == "--oneshot") {
      exv::helper::DaemonOptions options;
      options.mode = "oneshot";
      options.oneshot = true;

      for (int i = 2; i < argc; ++i) {
        std::string option = argv[i];
        if (option == "--endpoint") {
          if (!read_option_value(argc, argv, &i, &options.endpoint))
            return print_usage();
          continue;
        }
        if (option == "--owner") {
          if (!read_option_value(argc, argv, &i, &options.owner))
            return print_usage();
          continue;
        }
        if (option == "--parent-pid") {
          std::string value;
          if (!read_option_value(argc, argv, &i, &value))
            return print_usage();
          auto parsed = parse_positive_int(value);
          if (!parsed.has_value())
            return print_usage();
          options.parent_pid = *parsed;
          continue;
        }
        return print_usage();
      }

      if (options.endpoint.empty() || options.owner.empty() ||
          options.parent_pid <= 0) {
        return print_usage();
      }

      return exv::helper::daemon_main(options);
    }

    return print_usage();
  }

  return print_usage();
}

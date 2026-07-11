#include "cli/cli_entrypoint.hpp"
#include "core/app_api/app_api.hpp"
#include "core/core_process.hpp"
#include "observability/log_facade.hpp"
#include "platform/common/file_system.hpp"
#include "runtime/runtime_context.hpp"

#include <nlohmann/json.hpp>

#include <exception>
#include <iostream>
#include <string>
#include <vector>

using namespace exv;

int main(int argc, char *argv[]) {
  std::vector<std::string> raw_args;
  for (int i = 0; i < argc; ++i) {
    raw_args.emplace_back(argv[i]);
  }

  if (raw_args.size() > 1 && raw_args[1] == "--version") {
    std::cout << "exv " << EXV_VERSION << std::endl;
    return 0;
  }

  if (raw_args.size() > 1 && raw_args[1] == "--mode=core") {
    std::string config_dir;
    std::string home_dir;
    bool use_stdin = true;
    for (size_t i = 2; i < raw_args.size(); ++i) {
      if (raw_args[i] == "--config-dir" && i + 1 < raw_args.size()) {
        config_dir = raw_args[++i];
      } else if (raw_args[i] == "--home" && i + 1 < raw_args.size()) {
        home_dir = raw_args[++i];
      } else if (raw_args[i] == "--daemon") {
        use_stdin = false;
      }
    }
    try {
      return exv::core::core_process_main(config_dir, home_dir, use_stdin);
    } catch (const std::exception &ex) {
      exv::observability::LogFacade::error(
          std::string("Core process terminated by uncaught exception: ") +
          ex.what());
      std::cerr << "fatal: core process terminated by uncaught exception: "
                << ex.what() << std::endl;
      return 1;
    } catch (...) {
      exv::observability::LogFacade::error(
          "Core process terminated by unknown uncaught exception");
      std::cerr << "fatal: core process terminated by unknown uncaught exception"
                << std::endl;
      return 1;
    }
  }

  runtime::bootstrap();

  if (raw_args.size() > 2 &&
      (raw_args[1] == "desktop-rpc" || raw_args[1] == "desktop-rpc-file" ||
       raw_args[1] == "desktop-rpc-file-output")) {
    const bool payload_is_file = raw_args[1] == "desktop-rpc-file" ||
                                 raw_args[1] == "desktop-rpc-file-output";
    const bool output_is_file = raw_args[1] == "desktop-rpc-file-output";
    const std::string output_path =
        output_is_file && raw_args.size() > 4 ? raw_args[4] : "";
    auto write_rpc_result = [&](const nlohmann::json &result) {
      std::string body = result.dump();
      if (output_is_file && !output_path.empty()) {
        return platform::write_file(output_path, body + "\n") ? 0 : 1;
      }
      std::cout << body << std::endl;
      return 0;
    };

    nlohmann::json payload = nlohmann::json::object();
    if (raw_args.size() > 3) {
      try {
        if (payload_is_file) {
          payload = nlohmann::json::parse(platform::read_file(raw_args[3]));
        } else {
          payload = nlohmann::json::parse(raw_args[3]);
        }
      } catch (const std::exception &ex) {
        write_rpc_result(nlohmann::json{
            {"ok", false},
            {"error", std::string("invalid JSON payload: ") + ex.what()}});
        return 1;
      }
    }

    nlohmann::json result = app_api::handle_action(raw_args[2], payload);
    int wr = write_rpc_result(result);
    if (wr != 0) {
      return wr;
    }
    if (result.is_object() && result.value("ok", true) == false) {
      return 1;
    }
    return 0;
  }

  exv::cli::CliEntrypointOptions cli_options;
  cli_options.allow_self_core_candidate = true;
  return exv::cli::run_cli_entrypoint(raw_args, cli_options);
}

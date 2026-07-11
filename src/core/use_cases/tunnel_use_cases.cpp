#include "core/use_cases/tunnel_use_cases.hpp"

#include "core/tunnel_controller/tunnel_controller.hpp"
#include "core/tunnel_controller/tunnel_controller_active.hpp"
#include "helper/common/helper_client.hpp"
#include "helper/common/helper_connector.hpp"
#include "platform/common/helper_delegating_network_ops.hpp"
#include "platform/common/process_utils.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <utility>

namespace exv::core {

// Holder of the shared tunnel runtime.  Relocated verbatim from the former
// core/app_api/desktop_tunnel_host.cpp file-local TunnelControllerHolder so
// that ownership now lives in the use-case layer.
struct TunnelUseCases::State {
  std::unique_ptr<exv::helper::HelperConnector> connector;
  std::shared_ptr<exv::helper::HelperClient> client;
  std::shared_ptr<exv::platform::HelperDelegatingPlatformNetworkOps> net_ops;
  std::shared_ptr<exv::core::TunnelController> controller;
  bool init_attempted = false;
  std::string init_error;
  std::chrono::steady_clock::time_point last_failure_time;
  static constexpr auto kRetryCooldown = std::chrono::seconds(30);

  // Desktop connect-error state (guarded by connect_error_mutex).
  std::mutex connect_error_mutex;
  std::optional<nlohmann::json> connect_error;

  // Desktop connect-job owner (guarded by connect_jobs_mutex).
  // Declared after connect_error so that ~State joins the connect-job thread
  // before the error state is destroyed.
  std::mutex connect_jobs_mutex;
  VpnConnectJobOwner connect_jobs;
};

TunnelUseCases::TunnelUseCases() : state_(std::make_unique<State>()) {}

TunnelUseCases::~TunnelUseCases() = default;

std::string TunnelUseCases::helper_binary_next_to_exv() {
  std::filesystem::path exv_path(platform::get_executable_path());
#ifdef _WIN32
  return (exv_path.parent_path() / "exv-helper.exe").string();
#else
  return (exv_path.parent_path() / "exv-helper").string();
#endif
}

std::shared_ptr<exv::core::TunnelController>
TunnelUseCases::ensure_controller(const std::string &endpoint_override) {
  auto &h = *state_;
  if (h.controller) {
    exv::core::set_tunnel_controller_active(true);
    return h.controller;
  }

  const auto now = std::chrono::steady_clock::now();
  if (h.last_failure_time != std::chrono::steady_clock::time_point{}) {
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - h.last_failure_time);
    if (elapsed < State::kRetryCooldown) {
      return nullptr;
    }
  }

  h.init_attempted = true;
  try {
    h.connector = exv::helper::HelperConnector::create();
    exv::helper::HelperConnectorConfig cc;
    cc.mode = exv::helper::ConnectorMode::Transient;
    if (!endpoint_override.empty()) {
      cc.pipe_endpoint = endpoint_override;
    } else {
      cc.helper_executable_path = helper_binary_next_to_exv();
    }
    h.client = h.connector->connect(cc);
    if (!h.client) {
      h.init_error = "Failed to connect to helper daemon";
      h.last_failure_time = now;
      return nullptr;
    }
    h.net_ops =
        std::make_shared<exv::platform::HelperDelegatingPlatformNetworkOps>(
            h.client.get());
    h.controller =
        std::make_shared<exv::core::TunnelController>(h.client, h.net_ops);
    exv::core::set_tunnel_controller_active(true);
    return h.controller;
  } catch (const std::exception &e) {
    h.init_error = e.what();
    h.last_failure_time = now;
    return nullptr;
  }
}

std::shared_ptr<exv::core::TunnelController>
TunnelUseCases::controller_if_exists() const {
  return state_->controller;
}

std::shared_ptr<exv::helper::HelperClient>
TunnelUseCases::current_helper_client() const {
  return state_->client;
}

std::mutex &TunnelUseCases::connect_jobs_mutex() {
  return state_->connect_jobs_mutex;
}

VpnConnectJobOwner &TunnelUseCases::connect_jobs() {
  return state_->connect_jobs;
}

std::optional<nlohmann::json> TunnelUseCases::connect_error() const {
  std::lock_guard<std::mutex> lock(state_->connect_error_mutex);
  return state_->connect_error;
}

void TunnelUseCases::set_connect_error(nlohmann::json failure) {
  std::lock_guard<std::mutex> lock(state_->connect_error_mutex);
  state_->connect_error = std::move(failure);
}

void TunnelUseCases::clear_connect_error() {
  std::lock_guard<std::mutex> lock(state_->connect_error_mutex);
  state_->connect_error.reset();
}

void TunnelUseCases::shutdown_connect_jobs(const std::string &reason) {
  std::lock_guard<std::mutex> lock(state_->connect_jobs_mutex);
  state_->connect_jobs.shutdown(reason);
}

void TunnelUseCases::reset_controller() {
  auto &h = *state_;
  h.controller.reset();
  h.client.reset();
  h.net_ops.reset();
  h.connector.reset();
  h.init_attempted = false;
  h.init_error.clear();
  h.last_failure_time = std::chrono::steady_clock::time_point{};
  exv::core::set_tunnel_controller_active(false);
}

std::string TunnelUseCases::controller_init_error() const {
  return state_->init_error;
}

TunnelUseCases &tunnel_use_cases() {
  static TunnelUseCases instance;
  return instance;
}

} // namespace exv::core

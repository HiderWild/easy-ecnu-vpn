#pragma once

#include "core/config/config.hpp"
#include "core/tunnel_controller/core_error_mapper.hpp"
#include "core/tunnel_controller/core_session_runner.hpp"
#include "core/tunnel_controller/timer_scheduler.hpp"
#include "core/tunnel_controller/timing.hpp"
#include "core/tunnel_controller/tunnel_controller.hpp"
#include "helper/common/helper_client.hpp"
#include "platform/common/helper_delegating_network_ops.hpp"
#include "platform/common/platform_network_ops.hpp"
#include "vpn_engine/native_handshake_job.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace exv::core {

void log_tunnel_event(
    const std::string &level,
    const std::string &code,
    const std::string &message,
    const std::vector<std::pair<std::string, std::string>> &fields = {});

std::shared_ptr<exv::platform::HelperDelegatingPlatformNetworkOps>
as_helper_delegating_ops(
    const std::shared_ptr<exv::platform::PlatformNetworkOps> &ops);

struct TunnelController::Impl {
  struct PreparedNativeHandshake {
    exv::vpn_engine::VpnEngineConfig engine_config;
    exv::vpn_engine::NativeHandshakeResult handshake;
  };

  Impl() = default;
  explicit Impl(CoreSessionRunner::NativeDependenciesFactory deps_factory)
      : runner_(std::move(deps_factory)) {}

  bool can_start_connect() const;
  bool can_disconnect() const;

  void transition_to(TunnelPhase new_phase);
  void update_snapshot();
  void notify_status();
  void set_error(const ErrorInfo &error);
  void clear_error();

  void start_heartbeat();
  void stop_heartbeat();
  void schedule_next_heartbeat();
  void do_heartbeat();
  void start_core_lease_keepalive();
  void stop_core_lease_keepalive();
  void schedule_next_core_lease_keepalive();
  void do_core_lease_keepalive();
  bool acquire_core_lease();
  void release_core_lease();

  bool prepare_tunnel_device_for_session(
      exv::platform::TunnelDeviceDescriptor *device);
  bool apply_tunnel_config_for_session(
      const exv::platform::TunnelDeviceDescriptor &device,
      const std::string &interface_address,
      const exv::vpn_engine::TunnelMetadata *metadata = nullptr);
  ErrorInfo current_native_failure(const std::string &fallback_code,
                                   const std::string &fallback_message) const;
  exv::vpn_engine::ValidationResult current_network_failure(
      const std::string &fallback_code,
      const std::string &fallback_message) const;
  std::string interface_address_from_metadata(
      const exv::vpn_engine::TunnelMetadata &metadata) const;
  exv::vpn_engine::ValidationResult configure_network_for_engine(
      const exv::vpn_engine::TunnelMetadata &metadata,
      exv::vpn_engine::DeviceConfig *device_config);
  void do_connect();

  void do_disconnect(DisconnectReason reason);
  void shutdown_helper_session_for_cleanup();
  void cleanup_after_failed_startup();
  void do_cleanup();

  void attempt_reconnect(const ErrorInfo &error);

  void on_helper_ready();
  void on_auth_succeeded();
  void on_auth_failed();
  void on_cstp_connected();
  void apply_tunnel_config_and_advance();
  void on_network_config_applied();
  void complete_packet_loop_started();
  void on_packet_loop_started();
  void on_transport_closed();
  void on_packet_device_failed();
  void on_lease_expired();
  void on_reconnect_timer_fired();
  void on_helper_lost();
  void on_cleanup_succeeded();
  void on_cleanup_failed();

  std::shared_ptr<exv::helper::HelperClient> helper_;
  std::shared_ptr<exv::platform::PlatformNetworkOps> net_ops_;

  ReconnectPolicy reconnect_policy_;
  TunnelPhase phase_ = TunnelPhase::Idle;
  UserIntent intent_;
  TunnelStatusSnapshot snapshot_;
  StatusCallback status_callback_;

  ConnectTiming timing_;

  exv::helper::SessionId session_id_;
  std::string adapter_name_{"EXV"};
  std::string assigned_internal_ip_;
  bool network_config_applied_ = false;
  bool packet_loop_started_ = false;
  std::optional<exv::platform::TunnelDeviceDescriptor> prepared_tunnel_device_;

  int reconnect_attempts_ = 0;

  TimerScheduler scheduler_;

  bool heartbeat_active_ = false;
  bool core_lease_keepalive_active_ = false;
  static constexpr auto kHeartbeatInterval = std::chrono::seconds(10);
  static constexpr auto kCoreLeaseKeepAliveInterval = std::chrono::seconds(10);

  bool helper_connected_seen_ = false;
  std::string helper_mode_ = "unknown";
  std::string helper_status_override_;
  std::string helper_endpoint_;
  std::string core_lease_id_;

  CoreSessionRunner runner_;

  exv::Config vpn_cfg_;
  std::string vpn_password_;
  std::optional<PreparedNativeHandshake> prepared_native_handshake_;
};

} // namespace exv::core

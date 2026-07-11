#include "core/tunnel_controller/tunnel_controller_impl.hpp"

#include "platform/common/network_diagnostics.hpp"

#include <algorithm>
#include <exception>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace exv::core {

namespace {

int current_process_id() {
#ifdef _WIN32
        return static_cast<int>(GetCurrentProcessId());
#else
        return static_cast<int>(getpid());
#endif
    }

std::string helper_mode_wire_name(exv::helper::HelperMode mode) {
        switch (mode) {
        case exv::helper::HelperMode::Resident:
            return "resident";
        case exv::helper::HelperMode::Transient:
        default:
            return "oneshot";
        }
    }

bool parse_ipv4_octets(const std::string& value, int octets[4]) {
        std::istringstream input(value);
        std::string part;
        int index = 0;
        while (std::getline(input, part, '.')) {
            if (index >= 4 || part.empty()) return false;
            int octet = 0;
            for (char ch : part) {
                if (ch < '0' || ch > '9') return false;
                octet = octet * 10 + (ch - '0');
                if (octet > 255) return false;
            }
            octets[index++] = octet;
        }
        return index == 4;
    }

int prefix_from_ipv4_netmask(const std::string& netmask) {
        int octets[4] = {};
        if (!parse_ipv4_octets(netmask, octets)) return 24;

        int prefix = 0;
        bool saw_zero = false;
        for (int octet : octets) {
            for (int bit = 7; bit >= 0; --bit) {
                const bool one = ((octet >> bit) & 1) != 0;
                if (one) {
                    if (saw_zero) return 24;
                    ++prefix;
                } else {
                    saw_zero = true;
                }
            }
        }
        return prefix;
    }

void add_route_once(std::vector<exv::platform::RouteEntry>* routes,
                    const std::string& destination) {
        if (!routes || destination.empty()) return;
        const auto found = std::find_if(
            routes->begin(), routes->end(),
            [&destination](const exv::platform::RouteEntry& route) {
                return route.destination == destination;
            });
        if (found != routes->end()) return;

        exv::platform::RouteEntry route;
        route.destination = destination;
        routes->push_back(route);
    }

bool configured_broad_private_route_disabled(const exv::Config& cfg,
                                             const std::string& destination) {
        if (destination == "10.0.0.0/8")
            return !cfg.include_class_a_private_routes;
        if (destination == "172.16.0.0/12")
            return !cfg.include_class_b_private_routes;
        return false;
    }

std::string join_route_destinations(
        const std::vector<exv::platform::RouteEntry>& routes) {
        std::ostringstream out;
        for (std::size_t i = 0; i < routes.size(); ++i) {
            if (i > 0) out << ',';
            out << routes[i].destination;
        }
        return out.str();
    }

} // namespace

// ================================================================
// Guards
// ================================================================

bool TunnelController::Impl::can_start_connect() const {
        return phase_ == TunnelPhase::Idle
            || phase_ == TunnelPhase::Failed;
    }

bool TunnelController::Impl::can_disconnect() const {
        return phase_ != TunnelPhase::Idle
            && phase_ != TunnelPhase::Disconnecting
            && phase_ != TunnelPhase::CleaningUp
            && phase_ != TunnelPhase::Failed;
    }

// ================================================================
// Connect flow (event-driven via CoreSessionRunner)
//
// 1.  PreparingHelper       — start_session()
// 2.  Authenticating        — runner_.start() -> session begins
// 3.  [async] AuthSucceeded — phase moves to ConnectingCstp
// 4.  [async] CstpConnected — phase moves to ApplyingNetworkConfig
// 5.  OpeningPacketDevice — prepare_tunnel_device()
// 6.  ApplyingNetworkConfig — apply_tunnel_config()
// 7.  [async] PacketLoopStarted — phase moves to Connected
//
// When no VPN config is provided (fallback path), the old synchronous
// flow is preserved for backward compatibility with tests that don't
// set a VPN config.
// ================================================================
bool TunnelController::Impl::prepare_tunnel_device_for_session(
        exv::platform::TunnelDeviceDescriptor* device) {
        if (!device) return false;

        timing_.timer.start(ConnectTiming::PACKET_DEVICE);
        log_tunnel_event("INFO", "tunnel.device.preparing", "Preparing tunnel device",
                         {{"adapter", adapter_name_}});
        transition_to(TunnelPhase::OpeningPacketDevice);

        try {
            *device = net_ops_->prepare_tunnel_device(adapter_name_);
            if (device->path.empty() || !device->is_open) {
                timing_.timer.end(ConnectTiming::PACKET_DEVICE);
                auto err = device->error_code.empty()
                    ? CoreErrorMapper::from_platform_error(
                          "packet", -1, "prepare_tunnel_device")
                    : CoreErrorMapper::from_native_error(
                          device->error_code, device->error_message);
                if (device->error_code.empty())
                    err.message = "Tunnel device returned empty path";
                log_tunnel_event("ERROR", "tunnel.device.prepare_failed",
                                 "Tunnel device preparation failed",
                                 {{"code", err.code},
                                  {"message", err.message}});
                set_error(err);
                transition_to(TunnelPhase::Failed);
                return false;
            }
        } catch (const std::exception& e) {
            timing_.timer.end(ConnectTiming::PACKET_DEVICE);
            auto err = CoreErrorMapper::from_platform_error(
                "packet", -1, "prepare_tunnel_device");
            err.message = std::string("prepare_tunnel_device: ") + e.what();
            set_error(err);
            transition_to(TunnelPhase::Failed);
            return false;
        }

        timing_.timer.end(ConnectTiming::PACKET_DEVICE);
        return true;
    }

bool TunnelController::Impl::apply_tunnel_config_for_session(
        const exv::platform::TunnelDeviceDescriptor& device,
        const std::string& interface_address,
        const exv::vpn_engine::TunnelMetadata* metadata) {
        timing_.timer.start(ConnectTiming::NETWORK_CONFIG);
        transition_to(TunnelPhase::ApplyingNetworkConfig);
        log_tunnel_event("INFO", "network.config.applying", "Applying network config",
                         {{"session_id", session_id_.value}});

        try {
            exv::platform::TunnelConfig config;
            config.interface_address = interface_address;
            config.interface_name = device.adapter_name;
            config.mtu = device.mtu;
            config.enable_kill_switch = false;
            if (metadata) {
                const auto& gateway_routes =
                    metadata->split_include_routes.empty()
                        ? metadata->routes
                        : metadata->split_include_routes;
                for (const auto& destination : gateway_routes)
                    add_route_once(&config.routes, destination);
                for (const auto& destination : vpn_cfg_.routes) {
                    if (configured_broad_private_route_disabled(vpn_cfg_, destination))
                        continue;
                    add_route_once(&config.routes, destination);
                }
                if (vpn_cfg_.include_class_a_private_routes)
                    add_route_once(&config.routes, "10.0.0.0/8");
                if (vpn_cfg_.include_class_b_private_routes)
                    add_route_once(&config.routes, "172.16.0.0/12");
                config.server_bypass_ips = metadata->server_bypass_ips;
                config.dns.servers = metadata->dns_servers;
                config.dns.search_domain = metadata->default_domain;
                config.dns.suffixes = metadata->search_domains;
                config.exclude_routes = metadata->split_exclude_routes;
                if (!config.exclude_routes.empty())
                    config.exclude_route = config.exclude_routes.front();
            }

            log_tunnel_event("INFO", "network.config.details",
                             "Prepared network config",
                             {{"interface", device.adapter_name},
                              {"interface_address", config.interface_address},
                              {"route_count",
                               std::to_string(config.routes.size())},
                              {"routes", join_route_destinations(config.routes)},
                              {"server_bypass_count",
                               std::to_string(config.server_bypass_ips.size())},
                              {"dns_count",
                               std::to_string(config.dns.servers.size())}});

            log_tunnel_event(
                "INFO", "network.diagnostics.route_snapshot",
                "Captured network adapter diagnostics",
                exv::platform::network_diagnostics_route_snapshot_fields(
                    vpn_cfg_.server));

            if (!net_ops_->apply_tunnel_config(device, config)) {
                timing_.timer.end(ConnectTiming::NETWORK_CONFIG);
                auto platform_error = net_ops_->last_error();
                if (!platform_error.code.empty()) {
                    std::string message = platform_error.message.empty()
                        ? "Failed to apply tunnel config"
                        : platform_error.message;
                    if (!platform_error.target.empty()) {
                        message += " target=" + platform_error.target;
                    }
                    if (platform_error.system_error != 0) {
                        message += " system_error=" +
                                   std::to_string(platform_error.system_error);
                    }
                    auto err = CoreErrorMapper::from_native_error(
                        platform_error.code, message);
                    if (platform_error.system_error != 0) {
                        err.native_code =
                            static_cast<int>(platform_error.system_error);
                    }
                    set_error(err);
                } else {
                    set_error(CoreErrorMapper::from_helper_error(
                        "apply_config_failed", "Failed to apply tunnel config"));
                }
                transition_to(TunnelPhase::Failed);
                return false;
            }
        } catch (const std::exception& e) {
            timing_.timer.end(ConnectTiming::NETWORK_CONFIG);
            set_error(CoreErrorMapper::from_helper_error(
                "apply_config_failed", e.what()));
            transition_to(TunnelPhase::Failed);
            return false;
        }

        timing_.timer.end(ConnectTiming::NETWORK_CONFIG);
        network_config_applied_ = true;
        return true;
    }

ErrorInfo TunnelController::Impl::current_native_failure(
        const std::string& fallback_code,
        const std::string& fallback_message) const {
        auto status = runner_.status();
        const std::string code =
            status.error_code.empty() ? fallback_code : status.error_code;
        const std::string message = status.error_message.empty()
            ? fallback_message
            : status.error_message;
        return CoreErrorMapper::from_native_error(code, message);
    }

exv::vpn_engine::ValidationResult
TunnelController::Impl::current_network_failure(
        const std::string& fallback_code,
        const std::string& fallback_message) const {
        exv::vpn_engine::ValidationResult result;
        result.ok = false;
        result.code = fallback_code;
        result.message = fallback_message;
        if (snapshot_.last_error) {
            if (!snapshot_.last_error->code.empty()) {
                result.code = snapshot_.last_error->code;
            }
            if (!snapshot_.last_error->message.empty()) {
                result.message = snapshot_.last_error->message;
            }
        }
        return result;
    }

std::string TunnelController::Impl::interface_address_from_metadata(
        const exv::vpn_engine::TunnelMetadata& metadata) const {
        std::string ip = metadata.internal_ip4_address;
        if (ip.empty()) {
            return "10.0.0.2/24";
        }
        if (ip.find('/') == std::string::npos) {
            ip += "/" + std::to_string(
                prefix_from_ipv4_netmask(metadata.internal_ip4_netmask));
        }
        return ip;
    }

exv::vpn_engine::ValidationResult
TunnelController::Impl::configure_network_for_engine(
        const exv::vpn_engine::TunnelMetadata& metadata,
        exv::vpn_engine::DeviceConfig* device_config) {
        const bool was_connected = phase_ == TunnelPhase::Connected;
        exv::platform::TunnelDeviceDescriptor device;
        if (prepared_tunnel_device_.has_value() &&
            prepared_tunnel_device_->is_open) {
            device = *prepared_tunnel_device_;
        } else {
            if (!prepare_tunnel_device_for_session(&device)) {
                return current_network_failure(
                    "prepare_tunnel_device_failed",
                    "Failed to prepare tunnel device");
            }
            prepared_tunnel_device_ = device;
        }

        if (!apply_tunnel_config_for_session(
                device, interface_address_from_metadata(metadata), &metadata)) {
            return current_network_failure(
                "apply_config_failed",
                "Failed to apply tunnel config");
        }

        assigned_internal_ip_ = metadata.internal_ip4_address;

        if (device_config) {
            device_config->interface_name =
                device.adapter_name.empty() ? metadata.interface_name
                                            : device.adapter_name;
            device_config->mtu = device.mtu > 0 ? device.mtu : metadata.mtu;
        }

        if (was_connected) {
            transition_to(TunnelPhase::Connected);
        } else if (packet_loop_started_) {
            complete_packet_loop_started();
        } else {
            transition_to(TunnelPhase::OpeningPacketDevice);
        }
        return {};
    }

void TunnelController::Impl::do_connect() {
        log_tunnel_event("INFO", "connect.start", "Connect requested",
                         {{"server", intent_.profile_id.value},
                          {"auto_reconnect", intent_.auto_reconnect ? "true" : "false"}});

        // Step 1 — bookkeeping
        intent_.desired_connected = true;
        clear_error();
        helper_status_override_.clear();
        network_config_applied_ = false;
        packet_loop_started_ = false;
        prepared_tunnel_device_.reset();
        assigned_internal_ip_.clear();
        timing_.timer.reset();
        reconnect_attempts_ = 0;

        if (!helper_) {
            log_tunnel_event("ERROR", "helper.missing", "Helper client unavailable");
            set_error(CoreErrorMapper::from_helper_error(
                "helper_missing", "Helper client unavailable"));
            transition_to(TunnelPhase::Failed);
            return;
        }
        if (!net_ops_) {
            log_tunnel_event("ERROR", "network.ops.missing", "Network operations unavailable");
            auto err = CoreErrorMapper::from_platform_error(
                "network", -1, "network_ops");
            err.message = "Network operations unavailable";
            set_error(err);
            transition_to(TunnelPhase::Failed);
            return;
        }
        const bool has_prepared_native_session =
            prepared_native_handshake_.has_value();
        const bool should_run_native_session =
            vpn_configured_ || has_prepared_native_session;
        const bool allow_placeholder_fallback =
            intent_.profile_id.value.empty() ||
            intent_.profile_id.value == "default";
        const bool missing_native_credentials =
            (vpn_configured_ && vpn_password_.empty() &&
             !has_prepared_native_session) ||
            (!should_run_native_session && !allow_placeholder_fallback);
        if (missing_native_credentials) {
            log_tunnel_event("ERROR", "vpn.config.missing",
                             "Native engine credentials unavailable");
            ErrorInfo err;
            err.domain = "config";
            err.code = "native_credentials_missing";
            err.message =
                "Native VPN credentials are missing; cannot start VPN session.";
            err.recoverable = true;
            err.recommended_action =
                "Enter your VPN password and retry the connection.";
            set_error(err);
            transition_to(TunnelPhase::Failed);
            return;
        }

        // Step 2 — PreparingHelper: start helper session
        timing_.timer.start(ConnectTiming::HELPER_PREPARE);
        transition_to(TunnelPhase::PreparingHelper);

        try {
            if (!helper_->is_connected() && !helper_->connect()) {
                helper_connected_seen_ = false;
                helper_status_override_ = "unavailable";
                log_tunnel_event("ERROR", "helper.connect.failed",
                                 "Helper connection could not be established",
                                 {{"stage", "hello"}});
                auto err = CoreErrorMapper::from_helper_error(
                    "helper_connect_failed",
                    "Helper connection could not be established");
                err.recoverable = true;
                err.recommended_action = "repair_service";
                set_error(err);
                update_snapshot();
                timing_.timer.end(ConnectTiming::HELPER_PREPARE);
                transition_to(TunnelPhase::Failed);
                return;
            }

            auto request_hello = [this](int attempt) {
                log_tunnel_event("INFO", "helper.hello.starting",
                                 "Requesting helper status",
                                 {{"attempt", std::to_string(attempt)}});
                return helper_->hello(exv::helper::HelloRequest{});
            };

            auto hello = request_hello(1);
            if (!helper_->is_connected()) {
                log_tunnel_event(
                    "WARN", "helper.hello.disconnected",
                    "Helper disconnected during initialization Hello",
                    {{"attempt", "1"}});
                log_tunnel_event(
                    "INFO", "helper.hello.retrying",
                    "Retrying helper initialization Hello after reconnect",
                    {{"attempt", "2"}});
                if (helper_->connect()) {
                    hello = request_hello(2);
                    if (!helper_->is_connected()) {
                        log_tunnel_event(
                            "WARN", "helper.hello.disconnected",
                            "Helper disconnected during retried initialization Hello",
                            {{"attempt", "2"}});
                    }
                } else {
                    log_tunnel_event(
                        "WARN", "helper.hello.retry_connect_failed",
                        "Helper reconnect failed before retried initialization Hello",
                        {{"attempt", "2"}});
                }
            }
            if (!helper_->is_connected()) {
                helper_connected_seen_ = false;
                helper_status_override_ = "unavailable";
                auto err = CoreErrorMapper::from_helper_error(
                    "helper_hello_disconnected",
                    "Helper disconnected while responding to Hello");
                err.recoverable = true;
                err.recommended_action = "repair_service";
                set_error(err);
                update_snapshot();
                timing_.timer.end(ConnectTiming::HELPER_PREPARE);
                transition_to(TunnelPhase::Failed);
                return;
            }
            if (hello.capabilities.empty()) {
                helper_connected_seen_ = false;
                helper_status_override_ = "unavailable";
                log_tunnel_event("WARN", "helper.hello.failed",
                                 "Helper Hello returned an empty response");
                auto err = CoreErrorMapper::from_helper_error(
                    "helper_hello_failed",
                    "Helper Hello returned an empty response");
                err.recoverable = true;
                err.recommended_action = "repair_service";
                set_error(err);
                update_snapshot();
                timing_.timer.end(ConnectTiming::HELPER_PREPARE);
                transition_to(TunnelPhase::Failed);
                return;
            }
            helper_connected_seen_ = true;
            helper_mode_ = helper_mode_wire_name(hello.mode);
            helper_endpoint_ = hello.startup_context.endpoint;
            update_snapshot();

            if (!acquire_core_lease()) {
                timing_.timer.end(ConnectTiming::HELPER_PREPARE);
                transition_to(TunnelPhase::Failed);
                return;
            }

            exv::helper::StartSessionRequest req;
            req.profile_id.value = intent_.profile_id.value;
            req.mode = exv::helper::HelperMode::Transient;

            log_tunnel_event("INFO", "helper.session.starting",
                             "Starting helper session",
                             {{"profile_id", req.profile_id.value}});
            auto resp = helper_->start_session(req);
            if (resp.session_id.value.empty()) {
                timing_.timer.end(ConnectTiming::HELPER_PREPARE);
                set_error(CoreErrorMapper::from_helper_error(
                    "start_session_failed",
                    "Helper StartSession returned empty session_id"));
                cleanup_after_failed_startup();
                transition_to(TunnelPhase::Failed);
                return;
            }
            session_id_ = resp.session_id;
            if (auto delegated_ops = as_helper_delegating_ops(net_ops_)) {
                delegated_ops->set_session(session_id_);
            }
            start_heartbeat();
            log_tunnel_event("INFO", "helper.session.started", "Helper session started",
                             {{"session_id", session_id_.value}});
        } catch (const std::exception& e) {
            timing_.timer.end(ConnectTiming::HELPER_PREPARE);
            set_error(CoreErrorMapper::from_helper_error(
                "start_session_failed", e.what()));
            cleanup_after_failed_startup();
            transition_to(TunnelPhase::Failed);
            return;
        }
        timing_.timer.end(ConnectTiming::HELPER_PREPARE);

        // Step 3 — Authenticating: start the native engine session.
        //
        // If a VPN config was provided, the CoreSessionRunner creates a
        // NativeVpnEngineSession which drives the rest of the flow via
        // asynchronous events (AuthSucceeded, CstpConnected, etc.).
        //
        // If no VPN config was provided, fall back to the synchronous
        // placeholder flow for backward compatibility.
        timing_.timer.start(ConnectTiming::AUTH);
        transition_to(TunnelPhase::Authenticating);

        if (should_run_native_session) {
            // Real engine path — start CoreSessionRunner.
            // The event callback is already wired up (set in init_runner).
            bool ok = false;
            log_tunnel_event("INFO", "native.runner.starting",
                             "Starting native engine session",
                             {{"source", prepared_native_handshake_
                                             ? "prepared_handshake"
                                             : "direct"}});
            if (prepared_native_handshake_) {
                auto prepared = std::move(*prepared_native_handshake_);
                prepared_native_handshake_.reset();
                ok = runner_.start_from_handshake(
                    std::move(prepared.engine_config),
                    std::move(prepared.handshake));
            } else {
                ok = runner_.start(vpn_cfg_, vpn_password_);
            }
            if (!ok) {
                timing_.timer.end(ConnectTiming::AUTH);
                auto failure = current_native_failure(
                    "native_start_failed",
                    "Native engine session failed to start");
                log_tunnel_event("ERROR", "native.runner.failed",
                                 "Native engine session failed to start",
                                 {{"code", failure.code},
                                  {"message", failure.message}});

                const bool should_replace_error =
                    !snapshot_.last_error ||
                    snapshot_.last_error->code == "auth_failed" ||
                    snapshot_.last_error->code == "packet_device_failed";
                if (should_replace_error) {
                    set_error(failure);
                }

                if (!session_id_.value.empty() || network_config_applied_) {
                    cleanup_after_failed_startup();
                }

                transition_to(TunnelPhase::Failed);
                return;
            }
            log_tunnel_event("INFO", "native.runner.started",
                             "Native engine session started");
            // Events from the runner will drive subsequent transitions.
            return;
        }

        // Synchronous fallback path (no VPN config set).
        timing_.timer.end(ConnectTiming::AUTH);

        // Step 4 — ConnectingCstp (simulated)
        timing_.timer.start(ConnectTiming::CSTP_CONNECT);
        transition_to(TunnelPhase::ConnectingCstp);
        timing_.timer.end(ConnectTiming::CSTP_CONNECT);

        // Step 5/6 — create the tunnel adapter before pushing routes/DNS.
        exv::platform::TunnelDeviceDescriptor device;
        if (!prepare_tunnel_device_for_session(&device)) {
            return;
        }
        if (!apply_tunnel_config_for_session(device, "10.0.0.2/24")) {
            return;
        }

        transition_to(TunnelPhase::OpeningPacketDevice);

        // Step 7 — Connected
        log_tunnel_event("INFO", "packet.loop.started", "Packet loop started",
                         {{"session_id", session_id_.value}});
        transition_to(TunnelPhase::Connected);
        log_tunnel_event("INFO", "connect.connected", "Tunnel connected",
                         {{"session_id", session_id_.value}});
        reconnect_policy_.reset();
        start_heartbeat();
    }

bool TunnelController::Impl::acquire_core_lease() {
        if (!core_lease_id_.empty()) {
            if (helper_ && helper_->is_connected()) {
                try {
                    exv::helper::KeepAliveRequest keep_alive_req;
                    keep_alive_req.lease_id = core_lease_id_;
                    keep_alive_req.state = tunnel_phase_wire_name(phase_);
                    auto keep_alive_resp = helper_->keep_alive(keep_alive_req);
                    if (keep_alive_resp.ok) {
                        return true;
                    }
                    log_tunnel_event(
                        "WARN", "core_lease.reuse.rejected",
                        "Existing helper CoreLease was not accepted; reacquiring",
                        {{"warning", keep_alive_resp.warning.value_or("")},
                         {"phase", tunnel_phase_wire_name(phase_)}});
                } catch (const std::exception& e) {
                    log_tunnel_event(
                        "WARN", "core_lease.reuse.failed",
                        "Existing helper CoreLease validation failed; reacquiring",
                        {{"error", e.what()},
                         {"phase", tunnel_phase_wire_name(phase_)}});
                }
            } else {
                log_tunnel_event(
                    "WARN", "core_lease.reuse.disconnected",
                    "Existing helper CoreLease cannot be reused because helper is disconnected",
                    {{"phase", tunnel_phase_wire_name(phase_)}});
            }
            core_lease_id_.clear();
            stop_core_lease_keepalive();
            update_snapshot();
        }

        exv::helper::AcquireCoreLeaseRequest req;
        req.core_pid = current_process_id();
        req.purpose = "vpn.connect";

        try {
            log_tunnel_event("INFO", "core_lease.acquire.starting",
                             "Acquiring helper core lease",
                             {{"purpose", req.purpose}});
            auto resp = helper_->acquire_core_lease(req);
            if (!resp.accepted || resp.lease_id.empty()) {
                helper_status_override_ = "core_lease_failed";
                const std::string code =
                    resp.error_code.empty() ? "core_lease_failed" : resp.error_code;
                const std::string message =
                    resp.error_message.empty()
                        ? "Helper rejected CoreLease acquisition"
                        : resp.error_message;
                log_tunnel_event("WARN", "core_lease.acquire.rejected",
                                 "Helper rejected CoreLease acquisition",
                                 {{"code", code}, {"message", message}});
                auto err = CoreErrorMapper::from_helper_error(
                    code, message);
                const bool repairable_core_lease_error =
                    code == "core_lease_failed" ||
                    code == "core_lease_conflict" ||
                    code == "core_lease_unauthorized";
                err.recommended_action =
                    repairable_core_lease_error ? "repair_service" : "view_logs";
                err.recoverable = repairable_core_lease_error;
                set_error(err);
                update_snapshot();
                return false;
            }

            core_lease_id_ = resp.lease_id;
            if (!resp.mode.empty()) {
                helper_mode_ = resp.mode;
            }
            helper_status_override_.clear();
            start_core_lease_keepalive();
            update_snapshot();
            return true;
        } catch (const std::exception& e) {
            helper_status_override_ = "core_lease_failed";
            auto err = CoreErrorMapper::from_helper_error("core_lease_failed", e.what());
            err.recoverable = false;
            set_error(err);
            update_snapshot();
            return false;
        }
    }

} // namespace exv::core

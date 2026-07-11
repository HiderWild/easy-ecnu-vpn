#include "core/tunnel_controller/core_session_runner.hpp"
#include "core/tunnel_controller/native_engine_config_mapper.hpp"
#include "vpn_engine/native_handshake_job.hpp"

#include <string>

namespace exv::core {

namespace {

bool is_auth_failure_code(const std::string& code) {
    return code == "auth_failed" ||
           code == "unsupported_auth_flow" ||
           code == "auth_protocol_mismatch" ||
           code == "auth_rejected" ||
           code == "auth_challenge_required" ||
           code == "auth_group_required" ||
           code == "auth_expired" ||
           code == "csd_required_unsupported";
}

} // namespace

// =========================================================================
// CoreSessionRunner
// =========================================================================

CoreSessionRunner::CoreSessionRunner()
    : CoreSessionRunner([] {
          return exv::vpn_engine::default_native_engine_dependencies();
      }) {}

CoreSessionRunner::CoreSessionRunner(NativeDependenciesFactory deps_factory)
    : deps_factory_(std::move(deps_factory)) {}

CoreSessionRunner::~CoreSessionRunner() {
    stop();
}

bool CoreSessionRunner::start(const exv::Config& cfg,
                              const std::string& password) {
    std::unique_lock<std::mutex> lock(mu_);

    if (running_) return false;
    if (monitor_thread_.joinable()) {
        lock.unlock();
        monitor_thread_.join();
        lock.lock();
        if (running_) return false;
    }

    // Build VpnEngineConfig from the application Config at the core boundary.
    exv::vpn_engine::VpnEngineConfig engine_config;
    auto config_result =
        make_native_engine_config(cfg, password, &engine_config);
    if (!config_result.ok) return false;
    // TunnelController owns helper/network reconnect, so the native engine must
    // report transport closure instead of reconnecting internally.
    engine_config.auto_reconnect = false;

    // Create the event bridge — it translates VpnEngineEvents to TunnelEvents
    // and invokes the callback.
    bridge_ = std::make_unique<EngineEventBridge>(
        [this](TunnelEvent te) {
            // The bridge callback is invoked from the engine's background
            // thread.  Copy the callback under lock, then invoke outside
            // to avoid holding mu_ during user code.
            EventCallback cb;
            {
                std::lock_guard<std::mutex> lk(mu_);
                if (session_) {
                    cached_status_ = session_->status();
                }
                cb = event_callback_;
            }
            if (cb) cb(te);
        });

    // Create NativeVpnEngineSession with default dependencies and the bridge
    // as the event sink.
    auto deps = deps_factory_ ? deps_factory_()
                              : exv::vpn_engine::default_native_engine_dependencies();
    deps.event_sink = bridge_.get();
    deps.network_configurator = network_config_callback_;
    deps.auth_interaction_handler =
        [this](const exv::vpn_engine::protocol::AuthInteractionRequest& req) {
            return handle_auth_interaction(req);
        };

    session_ = std::make_unique<exv::vpn_engine::NativeVpnEngineSession>(
        engine_config, deps);

    // Unlock before calling session_->start() because it runs auth + CSTP
    // synchronously and emits events through the bridge callback, which
    // needs to acquire mu_ to read session_ / event_callback_.  Holding mu_
    // across the synchronous start() would deadlock on the same thread.
    lock.unlock();

    // Validate config and start the session (auth + CSTP negotiation happen
    // synchronously during start(); the packet loop runs on a background
    // thread inside the session).
    auto validation = session_->start();

    lock.lock();
    if (!validation.ok) {
        cached_status_ = session_ ? session_->status()
                                  : exv::vpn_engine::VpnEngineStatus{};
        if (cached_status_.error_code.empty())
            cached_status_.error_code = validation.code;
        if (cached_status_.error_message.empty())
            cached_status_.error_message = validation.message;

        TunnelEvent te;
        if (validation.code.rfind("packet", 0) == 0 ||
            validation.code.rfind("native_packet", 0) == 0) {
            te.type = TunnelEventType::PacketDeviceFailed;
        } else if (is_auth_failure_code(validation.code)) {
            te.type = TunnelEventType::AuthFailed;
        } else {
            te.type = TunnelEventType::TransportClosed;
        }

        // Fire the failure event outside the lock.
        EventCallback cb = event_callback_;
        lock.unlock();

        if (cb) {
            cb(te);
        }

        lock.lock();
        session_.reset();
        bridge_.reset();
        return false;
    }

    cached_status_ = session_->status();
    running_ = true;

    start_monitor_thread();

    return true;
}

bool CoreSessionRunner::start_from_handshake(
    exv::vpn_engine::VpnEngineConfig engine_config,
    exv::vpn_engine::NativeHandshakeResult handshake) {
    std::unique_lock<std::mutex> lock(mu_);

    if (running_) return false;
    if (monitor_thread_.joinable()) {
        lock.unlock();
        monitor_thread_.join();
        lock.lock();
        if (running_) return false;
    }
    engine_config.auto_reconnect = false;

    bridge_ = std::make_unique<EngineEventBridge>(
        [this](TunnelEvent te) {
            EventCallback cb;
            {
                std::lock_guard<std::mutex> lk(mu_);
                if (session_) {
                    cached_status_ = session_->status();
                }
                cb = event_callback_;
            }
            if (cb) cb(te);
        });

    auto deps = deps_factory_ ? deps_factory_()
                              : exv::vpn_engine::default_native_engine_dependencies();
    deps.event_sink = bridge_.get();
    deps.auth_interaction_handler =
        [this](const exv::vpn_engine::protocol::AuthInteractionRequest& req) {
            return handle_auth_interaction(req);
        };

    auto network_config_callback = network_config_callback_;

    session_ = std::make_unique<exv::vpn_engine::NativeVpnEngineSession>(
        std::move(engine_config), deps);

    lock.unlock();

    exv::vpn_engine::TunnelMetadata metadata;
    auto validation = session_->adopt_handshake(std::move(handshake), &metadata);
    if (validation.ok) {
        exv::vpn_engine::DeviceConfig device_config;
        device_config.interface_name = metadata.interface_name;
        device_config.mtu = metadata.mtu;
        if (network_config_callback) {
            validation = network_config_callback(metadata, &device_config);
        }
        if (validation.ok) {
            if (device_config.interface_name.empty())
                device_config.interface_name = metadata.interface_name;
            if (device_config.mtu <= 0)
                device_config.mtu = metadata.mtu;
            validation = session_->start_packet_loop(device_config);
            if (validation.ok && network_config_callback) {
                validation = network_config_callback(metadata, &device_config);
            }
        }
    }

    lock.lock();
    if (!validation.ok) {
        cached_status_ = session_ ? session_->status()
                                  : exv::vpn_engine::VpnEngineStatus{};
        if (cached_status_.error_code.empty())
            cached_status_.error_code = validation.code;
        if (cached_status_.error_message.empty())
            cached_status_.error_message = validation.message;

        TunnelEvent te;
        if (validation.code.rfind("packet", 0) == 0 ||
            validation.code.rfind("native_packet", 0) == 0) {
            te.type = TunnelEventType::PacketDeviceFailed;
        } else if (is_auth_failure_code(validation.code)) {
            te.type = TunnelEventType::AuthFailed;
        } else {
            te.type = TunnelEventType::TransportClosed;
        }

        EventCallback cb = event_callback_;
        lock.unlock();

        if (cb) {
            cb(te);
        }

        lock.lock();
        session_.reset();
        bridge_.reset();
        return false;
    }

    cached_status_ = session_->status();
    running_ = true;
    start_monitor_thread();
    return true;
}

void CoreSessionRunner::start_monitor_thread() {
    // Spawn a monitoring thread that waits for the session to finish and
    // then fires a TunnelEvent to notify the controller.
    monitor_thread_ = std::thread([this]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            EventCallback cb;
            bool session_finished = false;
            bool has_error = false;
            TunnelEvent error_event;

            {
                std::lock_guard<std::mutex> lk(mu_);
                if (!session_) break;

                auto st = session_->status();
                cached_status_ = st;

                if (!st.running) {
                    running_ = false;
                    session_finished = true;

                    if (!st.error_code.empty()) {
                        has_error = true;
                        error_event.type = TunnelEventType::TransportClosed;
                    }
                    cb = event_callback_;
                }
            }

            if (session_finished) {
                if (has_error && cb) {
                    cb(error_event);
                }
                break;
            }
        }
    });
}

void CoreSessionRunner::stop() {
    std::unique_ptr<exv::vpn_engine::NativeVpnEngineSession> session;

    {
        std::lock_guard<std::mutex> lock(mu_);
        session = std::move(session_);
        running_ = false;
        pending_auth_interaction_.reset();
        auth_interaction_response_.reset();
    }
    auth_interaction_cv_.notify_all();

    if (session) {
        session->stop();
    }

    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }

    std::lock_guard<std::mutex> lock(mu_);
    bridge_.reset();
    cached_status_ = {};
}

bool CoreSessionRunner::is_running() const {
    std::lock_guard<std::mutex> lock(mu_);
    return running_;
}

exv::vpn_engine::VpnEngineStatus CoreSessionRunner::status() const {
    std::lock_guard<std::mutex> lock(mu_);
    if (session_) {
        return session_->status();
    }
    return cached_status_;
}

std::optional<CoreSessionRunner::PendingAuthInteraction>
CoreSessionRunner::pending_auth_interaction() const {
    std::lock_guard<std::mutex> lock(mu_);
    return pending_auth_interaction_;
}

bool CoreSessionRunner::provide_auth_interaction_response(
    const std::string& id, const std::string& value) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (!pending_auth_interaction_ || pending_auth_interaction_->id != id) {
            return false;
        }
        auth_interaction_response_ = AuthInteractionResponseState{id, value};
    }
    auth_interaction_cv_.notify_all();
    return true;
}

void CoreSessionRunner::set_event_callback(EventCallback cb) {
    std::lock_guard<std::mutex> lock(mu_);
    event_callback_ = std::move(cb);
}

void CoreSessionRunner::set_network_config_callback(NetworkConfigCallback cb) {
    std::lock_guard<std::mutex> lock(mu_);
    network_config_callback_ = std::move(cb);
}

exv::vpn_engine::protocol::AuthInteractionResponse
CoreSessionRunner::handle_auth_interaction(
    const exv::vpn_engine::protocol::AuthInteractionRequest& request) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        pending_auth_interaction_ = PendingAuthInteraction{
            request.id, request.kind, request.label, request.input_type,
            request.options};
        auth_interaction_response_.reset();
    }
    auth_interaction_cv_.notify_all();

    std::unique_lock<std::mutex> lock(mu_);
    const bool answered = auth_interaction_cv_.wait_for(
        lock, std::chrono::seconds(120), [&] {
            return !pending_auth_interaction_ ||
                   (auth_interaction_response_ &&
                    auth_interaction_response_->id == request.id);
        });

    exv::vpn_engine::protocol::AuthInteractionResponse response;
    if (!answered || !pending_auth_interaction_ || !auth_interaction_response_) {
        pending_auth_interaction_.reset();
        auth_interaction_response_.reset();
        response.ok = false;
        return response;
    }

    response.ok = true;
    response.value = auth_interaction_response_->value;
    pending_auth_interaction_.reset();
    auth_interaction_response_.reset();
    return response;
}

} // namespace exv::core

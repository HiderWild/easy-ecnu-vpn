#include "core/tunnel_controller/engine_event_bridge.hpp"
#include "observability/log_facade.hpp"
#include "platform/common/logging/log_runtime.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <utility>
#include <vector>

namespace exv::core {
namespace {

bool is_noisy_event(const std::string& type) {
    return type == "packet.inbound" ||
           type == "packet.outbound" ||
           type.rfind("dpd.", 0) == 0;
}

bool is_log_worthy_event(const std::string& type) {
    if (is_noisy_event(type)) {
        return false;
    }
    return type == "native.starting" ||
           type == "auth.started" ||
           type == "auth.succeeded" ||
           type == "auth.failed" ||
           type == "auth.challenge_required" ||
           type == "auth.group_required" ||
           type == "csd.required_unsupported" ||
           type == "dtls.policy.decision" ||
           type == "dtls.connected" ||
           type == "dtls.unavailable" ||
           type == "dtls.fallback" ||
           type == "cstp.connected" ||
           type == "cstp.failed" ||
           type == "packet.loop.started" ||
           type == "packet_device.failed" ||
           type == "transport.closed" ||
           type == "packet.loop.stopped" ||
           type.rfind("reconnect.", 0) == 0;
}

std::string to_lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool key_is_sensitive(const std::string& key) {
    const std::string lower = to_lower_ascii(key);
    return lower.find("password") != std::string::npos ||
           lower.find("cookie") != std::string::npos ||
           lower.find("token") != std::string::npos ||
           lower.find("secret") != std::string::npos ||
           lower.find("samlrequest") != std::string::npos;
}

void redact_prefixed_value(std::string& text, const std::string& marker) {
    std::string lower = to_lower_ascii(text);
    const std::string lower_marker = to_lower_ascii(marker);
    std::size_t pos = lower.find(lower_marker);
    while (pos != std::string::npos) {
        std::size_t end = pos + lower_marker.size();
        while (end < text.size() && text[end] != ' ' && text[end] != '&' &&
               text[end] != ';' && text[end] != '\r' && text[end] != '\n') {
            ++end;
        }
        text.replace(pos, end - pos, marker + "[REDACTED]");
        lower = to_lower_ascii(text);
        pos = lower.find(lower_marker, pos + marker.size() + 10);
    }
}

std::string redact_sensitive_text(std::string text) {
    redact_prefixed_value(text, "password=");
    redact_prefixed_value(text, "token=");
    redact_prefixed_value(text, "cookie=");
    redact_prefixed_value(text, "webvpn=");
    redact_prefixed_value(text, "SAMLRequest=");

    std::istringstream in(text);
    std::ostringstream out;
    std::string word;
    bool first = true;
    while (in >> word) {
        if (!first) {
            out << ' ';
        }
        first = false;
        if (to_lower_ascii(word).find("secret") != std::string::npos) {
            out << "[REDACTED]";
        } else {
            out << word;
        }
    }
    const std::string redacted = out.str();
    return redacted.empty() && !text.empty() ? "[REDACTED]" : redacted;
}

std::string log_level_for_event(const exv::vpn_engine::VpnEngineEvent& event) {
    if (event.level == "error" || event.type.find(".failed") != std::string::npos) {
        return "ERROR";
    }
    if (event.level == "warn" || event.level == "warning") {
        return "WARN";
    }
    return "INFO";
}

void log_engine_event(const exv::vpn_engine::VpnEngineEvent& event) {
    if (!is_log_worthy_event(event.type)) {
        return;
    }

    std::vector<std::pair<std::string, std::string>> fields;
    fields.reserve(event.fields.size());
    for (const auto& field : event.fields) {
        fields.emplace_back(field.first,
                            key_is_sensitive(field.first)
                                ? "[REDACTED]"
                                : redact_sensitive_text(field.second));
    }

    exv::observability::LogFacade::event(log_level_for_event(event), "engine", event.type,
                           event.message.empty() ? event.type : redact_sensitive_text(event.message),
                           fields);
}

} // namespace

EngineEventBridge::EngineEventBridge(EventCallback callback)
    : callback_(std::move(callback)) {}

EngineEventBridge::~EngineEventBridge() = default;

void EngineEventBridge::emit(const exv::vpn_engine::VpnEngineEvent& event) {
    log_engine_event(event);

    TunnelEventType type{};
    if (!map_event(event.type, &type)) {
        return;  // Unrecognised engine event -- silently skip.
    }
    if (callback_) {
        TunnelEvent tunnel_event{type};
        tunnel_event.message = event.message;
        if (const auto code = event.fields.find("code"); code != event.fields.end()) {
            tunnel_event.code = code->second;
        }
        if (const auto recoverable = event.fields.find("recoverable");
            recoverable != event.fields.end()) {
            const std::string value = to_lower_ascii(recoverable->second);
            tunnel_event.recoverable = value == "true" || value == "1" || value == "yes";
        }
        callback_(tunnel_event);
    }
}

bool EngineEventBridge::map_event(const std::string& engine_type,
                                  TunnelEventType* out) {
    if (engine_type == "auth.succeeded") {
        *out = TunnelEventType::AuthSucceeded;
        return true;
    }
    if (engine_type == "auth.failed") {
        *out = TunnelEventType::AuthFailed;
        return true;
    }
    if (engine_type == "auth.challenge_required") {
        *out = TunnelEventType::AuthChallengeRequired;
        return true;
    }
    if (engine_type == "auth.group_required") {
        *out = TunnelEventType::AuthGroupRequired;
        return true;
    }
    if (engine_type == "cstp.connected") {
        *out = TunnelEventType::CstpConnected;
        return true;
    }
    if (engine_type == "packet.loop.started") {
        *out = TunnelEventType::PacketLoopStarted;
        return true;
    }
    if (engine_type == "transport.closed") {
        *out = TunnelEventType::TransportClosed;
        return true;
    }
    if (engine_type == "packet_device.failed") {
        *out = TunnelEventType::PacketDeviceFailed;
        return true;
    }
    return false;
}

} // namespace exv::core

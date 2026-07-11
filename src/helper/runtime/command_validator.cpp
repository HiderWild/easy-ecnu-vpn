#include "command_validator.hpp"

namespace exv::helper {

const std::set<HelperOp> CommandValidator::allowed_ops_ = {
    HelperOp::Hello,
    HelperOp::StartSession,
    HelperOp::PrepareTunnelDevice,
    HelperOp::ApplyTunnelConfig,
    HelperOp::Heartbeat,
    HelperOp::Cleanup,
    HelperOp::GetSnapshot,
    HelperOp::Shutdown,
    HelperOp::Inspect,
    HelperOp::AcquireCoreLease,
    HelperOp::KeepAlive,
    HelperOp::ReleaseCoreLease,
};

std::optional<HelperError> CommandValidator::validate(const HelperRequest& request) const {
    if (!is_op_allowed(request.op)) {
        return HelperError{HelperErrorCode::UnsupportedOp, "Operation not allowed"};
    }

    // Check payload for shell injection
    if (contains_shell_injection(request.payload_json)) {
        return HelperError{HelperErrorCode::PermissionDenied, "Shell injection detected"};
    }

    // Check payload for path traversal
    if (contains_path_traversal(request.payload_json)) {
        return HelperError{HelperErrorCode::PermissionDenied, "Path traversal detected"};
    }

    return std::nullopt;
}

bool CommandValidator::is_op_allowed(HelperOp op) const {
    return allowed_ops_.count(op) > 0;
}

bool CommandValidator::contains_shell_injection(const std::string& input) {
    // Check for characters commonly used in shell command injection.
    // Note: '{' and '}' are excluded because they appear in JSON payloads
    // and are only benign brace expansion in shells, not injection vectors.
    for (char c : input) {
        switch (c) {
            case ';':
            case '|':
            case '&':
            case '`':
            case '$':
            case '(':
            case ')':
                return true;
            default:
                break;
        }
    }
    return false;
}

bool CommandValidator::contains_path_traversal(const std::string& input) {
    // Check for ../ and ..\ patterns
    for (size_t i = 0; i + 2 < input.size(); ++i) {
        if (input[i] == '.' && input[i + 1] == '.') {
            if (input[i + 2] == '/' || input[i + 2] == '\\') {
                return true;
            }
        }
    }
    return false;
}

} // namespace exv::helper

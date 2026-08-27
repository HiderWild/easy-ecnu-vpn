#!/bin/bash
# architecture-guardrails.sh - Verify architecture boundaries
# Idempotent and safe to run multiple times.
set -e

echo "=== Architecture Guardrails ==="
FAILURES=0
WARNINGS=0

# Resolve repo root (parent of scripts/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Allowlist loading
# ---------------------------------------------------------------------------
ALLOWLIST_FILE="docs/architecture/guardrail_allowlist.yml"
ALLOWLIST_KEYS=()

load_allowlist() {
    if [ ! -f "$ALLOWLIST_FILE" ]; then
        echo "WARNING: Allowlist file not found at $ALLOWLIST_FILE"
        return
    fi

    local current_file=""
    local current_rule=""
    while IFS= read -r line; do
        line="${line%$'\r'}"
        if echo "$line" | grep -qE '^\s+- file:'; then
            current_file=$(echo "$line" | sed 's/.*file:\s*//' | xargs)
        elif echo "$line" | grep -qE '^\s+rule:'; then
            current_rule=$(echo "$line" | sed 's/.*rule:\s*//' | xargs)
            if [ -n "$current_file" ] && [ -n "$current_rule" ]; then
                ALLOWLIST_KEYS[${#ALLOWLIST_KEYS[@]}]="${current_file}|${current_rule}"
            fi
        fi
    done < "$ALLOWLIST_FILE"
}

load_allowlist
echo "Loaded ${#ALLOWLIST_KEYS[@]} allowlist entries from guardrail_allowlist.yml"

# Helper: check if a file+rule pair is allowlisted
is_allowlisted() {
    local file_path="$1"
    local rule="$2"
    local relative="${file_path#$REPO_ROOT/}"
    relative="${relative#\\}"
    local key="${relative}|${rule}"
    local allowed_key
    for allowed_key in "${ALLOWLIST_KEYS[@]}"; do
        [ "$allowed_key" = "$key" ] && return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# Rule 1: Helper protocol must not contain password/cookie/token
# ---------------------------------------------------------------------------
echo -n "Checking helper for forbidden fields... "
found=0
while IFS= read -r match; do
    line_content=$(echo "$match" | cut -d: -f2-)
    skip=0
    echo "$line_content" | grep -qE '^\s*//' && skip=1
    echo "$line_content" | grep -qi 'test' && skip=1
    echo "$line_content" | grep -q '\.md' && skip=1
    if [ $skip -eq 0 ]; then
        echo ""
        echo "  $match"
        found=1
    fi
done < <(grep -rin "password\|cookie\|webvpn_session\|auth_token" src/helper_common/ src/helper_runtime/ 2>/dev/null || true)
if [ $found -eq 1 ]; then
    echo "FAIL"
    FAILURES=$((FAILURES + 1))
else
    echo "PASS"
fi

# ---------------------------------------------------------------------------
# Rule 2: Helper protocol must not include vpn_engine/protocol
# ---------------------------------------------------------------------------
echo -n "Checking helper for protocol includes... "
if grep -r "vpn_engine/protocol" src/helper_common/ src/helper_runtime/ 2>/dev/null; then
    echo "FAIL"
    FAILURES=$((FAILURES + 1))
else
    echo "PASS"
fi

# ---------------------------------------------------------------------------
# Rule 3: Core must not have platform #ifdef
# ---------------------------------------------------------------------------
echo -n "Checking core for platform ifdef... "
core_ifdef_found=0
core_ifdef_allowlisted=0
while IFS= read -r match; do
    [ -z "$match" ] && continue
    file_path=$(echo "$match" | cut -d: -f1)
    if is_allowlisted "$file_path" "platform_ifdef_in_core"; then
        core_ifdef_allowlisted=$((core_ifdef_allowlisted + 1))
    else
        echo ""
        echo "  $match"
        core_ifdef_found=1
    fi
done < <(grep -rn "#ifdef _WIN32\|#ifdef __APPLE__\|#if defined(_WIN32)\|#if defined(__APPLE__)" src/core/ 2>/dev/null || true)
if [ $core_ifdef_found -eq 1 ]; then
    echo "FAIL"
    FAILURES=$((FAILURES + 1))
elif [ $core_ifdef_allowlisted -gt 0 ]; then
    echo "PASS (allowlisted: $core_ifdef_allowlisted hits)"
else
    echo "PASS"
fi

# ---------------------------------------------------------------------------
# Rule 4: New UI path must not have retry_limit
# ---------------------------------------------------------------------------
echo -n "Checking new UI path for retry_limit... "
if grep -r "retry_limit" src/core_api/ 2>/dev/null; then
    echo "FAIL"
    FAILURES=$((FAILURES + 1))
else
    echo "PASS"
fi

# ---------------------------------------------------------------------------
# Rule 5: No secrets in test fixtures (FAIL, not WARNING)
#
# Allowed tokens: MOCK_PASSWORD, test-mock, placeholder, example.invalid
# ---------------------------------------------------------------------------
echo -n "Checking test fixtures for secrets... "
secret_found=0

# Known security test files that legitimately test for secret-leak prevention
security_test_pattern="no_secret_in_argv_test|no_secret_in_logs_test|helper_contract_test"

while IFS= read -r match; do
    [ -z "$match" ] && continue
    file_path=$(echo "$match" | cut -d: -f1)
    line_content=$(echo "$match" | cut -d: -f2-)
    skip=0
    # Skip known security test files
    echo "$file_path" | grep -qE "$security_test_pattern" && skip=1
    echo "$line_content" | grep -q "no_secret" && skip=1
    echo "$line_content" | grep -q "forbidden" && skip=1
    echo "$line_content" | grep -q "should_not" && skip=1
    echo "$line_content" | grep -q "must_not" && skip=1
    echo "$line_content" | grep -q "verify_no" && skip=1
    echo "$line_content" | grep -q "// " && skip=1
    echo "$line_content" | grep -q "MOCK_PASSWORD" && skip=1
    echo "$line_content" | grep -q "test-mock" && skip=1
    echo "$line_content" | grep -q "placeholder" && skip=1
    echo "$line_content" | grep -q "example\.invalid" && skip=1
    echo "$line_content" | grep -q '\.find(' && skip=1
    echo "$line_content" | grep -q "contains_secret" && skip=1
    echo "$line_content" | grep -q "EXPECT FAILED" && skip=1
    echo "$line_content" | grep -q "secret_name" && skip=1
    echo "$line_content" | grep -q "secret_value" && skip=1
    echo "$line_content" | grep -q "secret_like" && skip=1
    echo "$line_content" | grep -q "diagnostic" && skip=1
    echo "$line_content" | grep -q "no-secret" && skip=1
    echo "$line_content" | grep -q '\.at("secret")' && skip=1
    echo "$line_content" | grep -qE '"secret"[[:space:]]*:' && skip=1
    echo "$line_content" | grep -q "interaction_kind" && skip=1
    if [ $skip -eq 0 ]; then
        echo ""
        echo "  $match"
        secret_found=1
    fi
done < <(grep -rinE "password\s*=\s*['\"]|password\s*,\s*['\"]|password\s*==\s*['\"]|\"secret\"" tests/ 2>/dev/null || true)
if [ $secret_found -eq 1 ]; then
    echo "FAIL"
    FAILURES=$((FAILURES + 1))
else
    echo "PASS"
fi

# ---------------------------------------------------------------------------
# Rule 6: Helper must not include core/ headers
# ---------------------------------------------------------------------------
echo -n "Checking helper for core includes... "
if grep -r '#include.*"core/' src/helper_common/ src/helper_runtime/ 2>/dev/null; then
    echo "FAIL"
    FAILURES=$((FAILURES + 1))
else
    echo "PASS"
fi

# ---------------------------------------------------------------------------
# Rule 7: Platform ops must not include protocol/auth headers
#           Allowlisted entries are documented in guardrail_allowlist.yml
# ---------------------------------------------------------------------------
echo -n "Checking platform ops for protocol includes... "
platform_found=0
platform_allowlisted=0
while IFS= read -r match; do
    [ -z "$match" ] && continue
    file_path=$(echo "$match" | cut -d: -f1)
    if is_allowlisted "$file_path" "protocol_include_in_platform"; then
        platform_allowlisted=$((platform_allowlisted + 1))
    else
        echo ""
        echo "  $match"
        platform_found=1
    fi
done < <(grep -rn "vpn_engine/protocol\|native_auth" src/platform/ 2>/dev/null || true)
if [ $platform_found -eq 1 ]; then
    echo "FAIL"
    FAILURES=$((FAILURES + 1))
elif [ $platform_allowlisted -gt 0 ]; then
    echo "PASS (allowlisted: $platform_allowlisted hits)"
else
    echo "PASS"
fi

# ---------------------------------------------------------------------------
# Rule 8: Non-protocol app_api files must not include protocol headers
#           Allowlisted entries are documented in guardrail_allowlist.yml
# ---------------------------------------------------------------------------
echo -n "Checking app_api for protocol includes... "
appapi_found=0
appapi_allowlisted=0
if [ -f "src/app_api_native_orchestration.hpp" ]; then
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        if is_allowlisted "src/app_api_native_orchestration.hpp" "protocol_include_in_non_protocol"; then
            appapi_allowlisted=$((appapi_allowlisted + 1))
        else
            echo ""
            echo "  $match"
            appapi_found=1
        fi
    done < <(grep -n "vpn_engine/protocol" src/app_api_native_orchestration.hpp 2>/dev/null || true)
fi
if [ $appapi_found -eq 1 ]; then
    echo "FAIL"
    FAILURES=$((FAILURES + 1))
elif [ $appapi_allowlisted -gt 0 ]; then
    echo "PASS (allowlisted: $appapi_allowlisted hits)"
else
    echo "PASS"
fi

# ---------------------------------------------------------------------------
# Rule 9: Native-only cutover paths must not retain removed OpenConnect tokens
#           Allowlisted entries are policy tests that own denied-token fixtures.
# ---------------------------------------------------------------------------
echo -n "Checking native-only paths for legacy OpenConnect tokens... "
native_legacy_found=0
native_legacy_allowlisted=0
native_legacy_pattern="__vpn-supervisor|legacy_openconnect|openconnect_process|spawn_openconnect_process|openconnect_tunnel_script|openconnect_log|configure_from_openconnect_log|openconnect_runtime|openconnectBinary|openconnectPath|openconnectArgs|legacyTunnelScript|legacyAdapter|stage-openconnect-runtime"
while IFS= read -r match; do
    [ -z "$match" ] && continue
    file_path=$(echo "$match" | cut -d: -f1)
    if is_allowlisted "$file_path" "legacy_openconnect_token"; then
        native_legacy_allowlisted=$((native_legacy_allowlisted + 1))
    else
        echo ""
        echo "  $match"
        native_legacy_found=1
    fi
done < <(grep -RInE "$native_legacy_pattern" src tests scripts webui/src CMakeLists.txt 2>/dev/null || true)
if [ $native_legacy_found -eq 1 ]; then
    echo "FAIL"
    FAILURES=$((FAILURES + 1))
elif [ $native_legacy_allowlisted -gt 0 ]; then
    echo "PASS (allowlisted: $native_legacy_allowlisted hits)"
else
    echo "PASS"
fi

# ---------------------------------------------------------------------------
# Allowlist summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Allowlist Summary ==="
if [ ${#ALLOWLIST_KEYS[@]} -eq 0 ]; then
    echo "  (no allowlist entries loaded)"
else
    for key in "${ALLOWLIST_KEYS[@]}"; do
        file="${key%%|*}"
        rule="${key#*|}"
        if [ -f "$file" ]; then
            status="active"
        else
            status="STALE (file missing)"
        fi
        echo "  [$status] $file ($rule)"
    done
fi

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------
echo ""
if [ $FAILURES -gt 0 ]; then
    echo "=== $FAILURES guardrail violation(s) found, $WARNINGS warning(s) ==="
    exit 1
elif [ $WARNINGS -gt 0 ]; then
    echo "=== All guardrails passed ($WARNINGS warning(s)) ==="
    exit 0
else
    echo "=== All guardrails passed ==="
    exit 0
fi

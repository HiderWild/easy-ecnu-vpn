# architecture-guardrails.ps1 - Verify architecture boundaries (PowerShell)
# Idempotent and safe to run multiple times.

$ErrorActionPreference = "Continue"
$failures = 0
$warnings = 0

Write-Host "=== Architecture Guardrails ==="

# Resolve repo root (parent of scripts/)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot

# ---------------------------------------------------------------------------
# Allowlist loading
# ---------------------------------------------------------------------------
$allowlistFile = Join-Path $repoRoot "docs\architecture\guardrail_allowlist.yml"
$allowlist = @{}

function Load-Allowlist {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Host "WARNING: Allowlist file not found at $Path"
        return
    }

    $currentFile = ""
    $currentRule = ""
    $lines = Get-Content $Path -ErrorAction SilentlyContinue
    foreach ($line in $lines) {
        if ($line -match '^\s+- file:\s+(.+)$') {
            $currentFile = $Matches[1].Trim()
        }
        elseif ($line -match '^\s+rule:\s+(.+)$') {
            $currentRule = $Matches[1].Trim()
            if ($currentFile -and $currentRule) {
                $key = "${currentFile}|${currentRule}"
                $script:allowlist[$key] = $true
            }
        }
    }
}

Load-Allowlist -Path $allowlistFile
Write-Host "Loaded $($allowlist.Count) allowlist entries from guardrail_allowlist.yml"

# Helper: check if a file+rule pair is allowlisted
function Test-Allowlisted {
    param(
        [string]$FilePath,
        [string]$Rule
    )
    $relativePath = $FilePath.Replace($repoRoot, "").TrimStart('\', '/')
    $relativePath = $relativePath.Replace('\', '/')
    $key = "${relativePath}|${Rule}"
    return $allowlist.ContainsKey($key)
}

# Helper function to check pattern in directory
function Check-Pattern {
    param(
        [string]$Description,
        [string[]]$Paths,
        [string]$Pattern,
        [string[]]$ExcludePatterns = @(),
        [switch]$IsWarning,
        [string]$RuleName = ""
    )

    Write-Host -NoNewline "$Description... "

    $found = $false
    $allowlistedHits = 0
    foreach ($path in $Paths) {
        if (-not (Test-Path $path)) { continue }
        $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            $content = Get-Content $file.FullName -ErrorAction SilentlyContinue
            foreach ($line in $content) {
                if ($line -match $Pattern) {
                    $excluded = $false
                    foreach ($ex in $ExcludePatterns) {
                        if ($line -match $ex) { $excluded = $true; break }
                    }
                    if (-not $excluded) {
                        if ($RuleName -and (Test-Allowlisted -FilePath $file.FullName -Rule $RuleName)) {
                            $allowlistedHits++
                        } else {
                            $found = $true
                            Write-Host ""
                            Write-Host "  $($file.FullName): $line"
                        }
                    }
                }
            }
        }
    }

    if ($found) {
        if ($IsWarning) {
            Write-Host "WARNING"
            $script:warnings++
        } else {
            Write-Host "FAIL"
            $script:failures++
        }
    } elseif ($allowlistedHits -gt 0) {
        Write-Host "PASS (allowlisted: $allowlistedHits hits)"
    } else {
        Write-Host "PASS"
    }
}

# ---------------------------------------------------------------------------
# Rule 1: Helper protocol must not contain password/cookie/token
# ---------------------------------------------------------------------------
Check-Pattern -Description "Checking helper for forbidden fields" `
    -Paths "src/helper_common", "src/helper_runtime" `
    -Pattern "(?i)password|cookie|webvpn_session|auth_token" `
    -ExcludePatterns "^\\s*//", "test", "\.md"

# ---------------------------------------------------------------------------
# Rule 2: Helper protocol must not include vpn_engine/protocol
# ---------------------------------------------------------------------------
Check-Pattern -Description "Checking helper for protocol includes" `
    -Paths "src/helper_common", "src/helper_runtime" `
    -Pattern "vpn_engine/protocol"

# ---------------------------------------------------------------------------
# Rule 3: Core must not have platform #ifdef
# ---------------------------------------------------------------------------
Check-Pattern -Description "Checking core for platform ifdef" `
    -Paths "src/core" `
    -Pattern "#ifdef _WIN32|#ifdef __APPLE__|#if defined\(_WIN32\)|#if defined\(__APPLE__\)" `
    -RuleName "platform_ifdef_in_core"

# ---------------------------------------------------------------------------
# Rule 4: New UI path must not have retry_limit
# ---------------------------------------------------------------------------
Check-Pattern -Description "Checking new UI path for retry_limit" `
    -Paths "src/core_api" `
    -Pattern "retry_limit"

# ---------------------------------------------------------------------------
# Rule 5: No secrets in test fixtures (FAIL, not WARNING)
#
# Allowed tokens: MOCK_PASSWORD, test-mock, placeholder, example.invalid
# These are known safe test-only values.
# ---------------------------------------------------------------------------
Write-Host -NoNewline "Checking test fixtures for secrets... "

$secretFound = $false
$secretPatterns = @(
    '(?i)password\s*=\s*[''"]',            # password = "secret"
    'password\s*,\s*[''"]',                 # {"password", "secret"}
    'password\s*==\s*[''"]',                # password == "secret"
    '"secret"'                               # bare "secret" literal
)

$secretExclude = @(
    "no_secret",
    "forbidden",
    "should_not",
    "must_not",
    "verify_no",
    "// ",
    "MOCK_PASSWORD",
    "test-mock",
    "placeholder",
    "example\.invalid",
    "\.find\(",
    "contains_secret",
    "EXPECT FAILED",
    "secret_name",
    "secret_value",
    "secret_like",
    "diagnostic",
    "no-secret",
    '\.at\("secret"\)',
    '"secret"\s*:',
    "interaction_kind"
)

# Known security test files that legitimately test for secret-leak prevention
$securityTestPatterns = @(
    "no_secret_in_argv_test",
    "no_secret_in_logs_test",
    "helper_contract_test"
)

if (Test-Path "tests") {
    $testFiles = Get-ChildItem -Path "tests" -Recurse -File -ErrorAction SilentlyContinue
    foreach ($file in $testFiles) {
        $isSecurityTest = $false
        foreach ($stp in $securityTestPatterns) {
            if ($file.Name -match $stp) { $isSecurityTest = $true; break }
        }

        $content = Get-Content $file.FullName -ErrorAction SilentlyContinue
        foreach ($line in $content) {
            $matched = $false
            foreach ($pat in $secretPatterns) {
                if ($line -match $pat) { $matched = $true; break }
            }
            if ($matched) {
                $excluded = $false
                # Skip known security test files for all patterns
                if ($isSecurityTest) { $excluded = $true }
                if (-not $excluded) {
                    foreach ($ex in $secretExclude) {
                        if ($line -match $ex) { $excluded = $true; break }
                    }
                }
                if (-not $excluded) {
                    $secretFound = $true
                    Write-Host ""
                    Write-Host "  $($file.FullName): $line"
                }
            }
        }
    }
}

if ($secretFound) {
    Write-Host "FAIL"
    $failures++
} else {
    Write-Host "PASS"
}

# ---------------------------------------------------------------------------
# Rule 6: Helper must not include core/ headers
# ---------------------------------------------------------------------------
Check-Pattern -Description "Checking helper for core includes" `
    -Paths "src/helper_common", "src/helper_runtime" `
    -Pattern '#include.*"core/'

# ---------------------------------------------------------------------------
# Rule 7: Platform ops must not include protocol/auth headers
#           Allowlisted entries are documented in guardrail_allowlist.yml
# ---------------------------------------------------------------------------
Check-Pattern -Description "Checking platform ops for protocol includes" `
    -Paths "src/platform" `
    -Pattern "vpn_engine/protocol|native_auth" `
    -RuleName "protocol_include_in_platform"

# ---------------------------------------------------------------------------
# Rule 8: Non-protocol app_api files must not include protocol headers
#           Allowlisted entries are documented in guardrail_allowlist.yml
# ---------------------------------------------------------------------------
Check-Pattern -Description "Checking app_api for protocol includes" `
    -Paths "src/app_api_native_orchestration.hpp" `
    -Pattern "vpn_engine/protocol" `
    -RuleName "protocol_include_in_non_protocol"

# ---------------------------------------------------------------------------
# Rule 9: Native-only cutover paths must not retain removed OpenConnect tokens
#           Allowlisted entries are policy tests that own denied-token fixtures.
# ---------------------------------------------------------------------------
Check-Pattern -Description "Checking native-only paths for legacy OpenConnect tokens" `
    -Paths "src", "tests", "scripts", "webui/src", "CMakeLists.txt" `
    -Pattern "__vpn-supervisor|legacy_openconnect|openconnect_process|spawn_openconnect_process|openconnect_tunnel_script|openconnect_log|configure_from_openconnect_log|openconnect_runtime|openconnectBinary|openconnectPath|openconnectArgs|legacyTunnelScript|legacyAdapter|stage-openconnect-runtime" `
    -RuleName "legacy_openconnect_token"

# ---------------------------------------------------------------------------
# Allowlist summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== Allowlist Summary ==="
if ($allowlist.Count -eq 0) {
    Write-Host "  (no allowlist entries loaded)"
} else {
    foreach ($entry in $allowlist.GetEnumerator()) {
        $parts = $entry.Key -split '\|'
        $file = $parts[0]
        $rule = $parts[1]
        $exists = Test-Path (Join-Path $repoRoot ($file -replace '/', '\'))
        $status = if ($exists) { "active" } else { "STALE (file missing)" }
        Write-Host "  [$status] $file ($rule)"
    }
}

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------
Write-Host ""
if ($failures -gt 0) {
    Write-Host "=== $failures guardrail violation(s) found, $warnings warning(s) ==="
    exit 1
} elseif ($warnings -gt 0) {
    Write-Host "=== All guardrails passed ($warnings warning(s)) ==="
    exit 0
} else {
    Write-Host "=== All guardrails passed ==="
    exit 0
}

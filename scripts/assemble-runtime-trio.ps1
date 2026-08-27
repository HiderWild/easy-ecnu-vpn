# assemble-runtime-trio.ps1 - EXV Rust runtime trio deterministic assembly (host + engine + tauri app + wintun.dll)
#
# Purpose: freeze the "latest runnable UI runtime" assembly flow into a script, removing
# execution-time discretion. ASCII-only on purpose: PowerShell 5.1 reads .ps1 without a BOM
# as the ANSI codepage, and non-ASCII (UTF-8 Chinese) comment bytes can misparse into a
# backtick line-continuation that swallows the NEXT line (seen 2026-08-19).
#
# Hard-won lessons (2026-08-19, do not regress):
#   - The tauri app MUST be built with the tauri CLI: `tauri build --no-bundle`. A plain
#     `cargo build -p exv-ui` produces a devUrl(localhost:1420) binary that shows
#     ERR_CONNECTION_REFUSED when double-clicked.
#   - The trio + wintun.dll must sit in the SAME directory (sibling layout); host resolves
#     engine by current_exe sibling.
#   - host/engine release bins use /SUBSYSTEM:WINDOWS (workspace [profile.release]
#     rustc-link-arg-bins), so product processes do not pop a console window.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\assemble-runtime-trio.ps1 \
#       [-OutDir C:\path\to\out] [-PreplaceWintun]
#   -PreplaceWintun: also place wintun.dll at host's frozen default path
#   (%USERPROFILE%\.exv\wintun\wintun\bin\amd64\wintun.dll) so double-click needs no env var.

param(
    [string]$OutDir = "$env:TEMP\exv-verify-run",
    [switch]$PreplaceWintun
)

$ErrorActionPreference = "Stop"

# ---- Repo/path resolution (script lives under repo\scripts\; may be a worktree) ----
$RepoRoot = Split-Path -Parent $PSScriptRoot
$RustDir   = Join-Path $RepoRoot "src\platform\win32\rust"
$TauriDir  = Join-Path $RustDir  "tauri"
# PowerShell may resolve an extensionless npm shim inconsistently and silently
# leave the previous release binary in place.  Use the Windows command shim
# explicitly so this assembly can never copy a stale exv-ui.exe.
$TauriCli  = Join-Path $TauriDir "frontend\node_modules\.bin\tauri.cmd"

# wintun.dll source lives in the MAIN repo runtime\win32-x64 (worktrees have no runtime\ dir).
$GitCommon = git -C $RepoRoot rev-parse --path-format=absolute --git-common-dir 2>$null
$MainRepoRoot = if ($GitCommon) { Split-Path -Parent $GitCommon } else { $RepoRoot }
$WintunSrc = Join-Path $MainRepoRoot "runtime\win32-x64\wintun.dll"
if (-not (Test-Path $WintunSrc)) {
    # Fallback: trio copy inside a prior build output.
    $TrioWintun = Join-Path $RustDir "target\release\trio\wintun.dll"
    if (Test-Path $TrioWintun) { $WintunSrc = $TrioWintun }
}
if (-not (Test-Path $WintunSrc)) { throw "wintun.dll not found (main repo runtime\win32-x64 or target trio): $WintunSrc" }
if (-not (Test-Path $TauriCli)) { throw "Tauri CLI command shim not found: $TauriCli" }

# Rust toolchain (fixed 1.96.0-msvc on this machine). $env:USERPROFILE is reliable here
# (the earlier emptiness was the encoding misparse swallowing this line).
$UserProfilePath = $env:USERPROFILE
if (-not $UserProfilePath) { throw "cannot resolve user profile folder" }
$Toolchain = Join-Path $UserProfilePath ".rustup\toolchains\1.96.0-x86_64-pc-windows-msvc\bin"
if (-not (Test-Path (Join-Path $Toolchain "cargo.exe"))) { throw "Rust toolchain not found: $Toolchain" }
$env:PATH = "$Toolchain;$env:PATH"

Write-Host "== 1/4 build host+engine (release, windows-subsystem) =="
Push-Location $RustDir
try {
    $env:CARGO_TARGET_DIR = Join-Path $RustDir "target"
    & cargo build --release -p exv-core -p exv-engine
    if ($LASTEXITCODE -ne 0) { throw "cargo build host+engine failed: $LASTEXITCODE" }
} finally { Pop-Location; Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue }

Write-Host "== 2/4 build tauri app (tauri CLI --no-bundle; the ONLY correct path) =="
Push-Location $TauriDir
try {
    $env:CARGO_TARGET_DIR = Join-Path $TauriDir "target"
    & $TauriCli build --no-bundle
    if ($LASTEXITCODE -ne 0) { throw "tauri build --no-bundle failed: $LASTEXITCODE" }
} finally { Pop-Location; Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue }

Write-Host "== 3/4 assemble sibling directory =="
$EngineExe = Join-Path $RustDir  "target\release\exv-engine.exe"
$HostExe   = Join-Path $RustDir  "target\release\exv-core.exe"
$TauriExe  = Join-Path $TauriDir "target\release\exv-ui.exe"
foreach ($f in @($EngineExe, $HostExe, $TauriExe)) {
    if (-not (Test-Path $f)) { throw "missing build artifact: $f" }
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
# NOTE: -Destination is REQUIRED (comma-list form `Copy-Item $A, $B` treats BOTH as
# sources on PS 5.1 -> PathNotFound on the target path; seen 2026-08-20).
Copy-Item -Path $HostExe   -Destination (Join-Path $OutDir "exv-core.exe")   -Force
Copy-Item -Path $EngineExe -Destination (Join-Path $OutDir "exv-engine.exe") -Force
Copy-Item -Path $TauriExe  -Destination (Join-Path $OutDir "exv-ui.exe")        -Force
Copy-Item -Path $WintunSrc -Destination (Join-Path $OutDir "wintun.dll")               -Force

# Hardening: the copied exe must be byte-identical to the freshly built artifact
# (prevents shipping a stale half-finished binary - seen 2026-08-19).
$Copied = Get-FileHash (Join-Path $OutDir "exv-ui.exe") -Algorithm MD5
$Src    = Get-FileHash $TauriExe                              -Algorithm MD5
if ($Copied.Hash -ne $Src.Hash) { throw "tauri exe copy mismatch (stale artifact?): verify-run != target" }

Write-Host "== 4/4 verify + (optional) wintun preplace =="
if ($PreplaceWintun) {
    $WintunDefault = Join-Path $UserProfilePath ".exv\wintun\wintun\bin\amd64\wintun.dll"
    New-Item -ItemType Directory -Force -Path (Split-Path $WintunDefault) | Out-Null
    Copy-Item $WintunSrc $WintunDefault -Force
    Write-Host "wintun.dll preplaced to frozen default path: $WintunDefault"
} else {
    Write-Host "hint: if not preplaced, set EXV_RUST_VPN_WINTUN_DLL=$OutDir\wintun.dll before launch"
}

Write-Host ""
Write-Host "== Assembly complete: $OutDir =="
Get-ChildItem $OutDir -File | Select-Object Name, Length, LastWriteTime
Write-Host ""
Write-Host "Launch: double-click $OutDir\exv-ui.exe (host auto-spawns engine elevated)"

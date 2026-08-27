# EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
# cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md。
# 本文件是 Win32 真实宿主业务流验收驱动器；门禁执行适配见 docs/superpowers/governance/rust-product-line-governance-execution.md。
<#
.SYNOPSIS
Win32 native acceptance scenario driver (W28-Tb skeleton).

.DESCRIPTION
Runs one of the plan section-9 real-machine acceptance scenarios
(controlled / crash-matrix / school) for the VPN Rust native network stack MVP.

Contract (pinned by plan 2026-08-12-vpn-rust-native-runtime-mvp-win32-plan.md §9,
W26..W30 convention):
  - Environment invalidity is NEVER faked as RED/GREEN. Each failed precondition
    emits exactly one machine-readable marker on stdout and in the evidence JSON:
        WIN_ACCEPTANCE_ENV_INVALID:<predicate>
        not_run/blocked_by_environment:<predicate>
  - The release build is ensured before dispatch (cargo build --locked --release,
    run if the scenario binary is missing).
  - Evidence is written into -EvidenceDir (created if missing). Raw
    secret/cookie/private key is NEVER written to argv, env, log or evidence.
  - Elevated steps reuse the WSP3 pattern: Start-Process -Verb RunAs self-
    relaunch; an IS_ADMIN marker is appended to <EvidenceDir>/elevated-marker.txt
    before dispatch so the coordinator can verify the elevated context.

Exit codes:
  0  scenario dispatched and completed (exit of the scenario binary propagated)
  1  usage error (unknown -Scenario)
  2  precondition failure (WIN_ACCEPTANCE_ENV_INVALID / not_run markers emitted)

This is the W28-Tb skeleton: the per-scenario Rust binaries do not exist yet
(plan scenario files src/scenarios/controlled.rs, crash_matrix.rs, school.rs).
Dispatch and evidence collection are wired with explicit TODO hooks named after
those plan files; W28-I / W29-I / W30-I fill them in.

.PARAMETER Scenario
One of: controlled | crash-matrix | school. Unknown values are a usage error.

.PARAMETER EvidenceDir
Directory for evidence artifacts (created if missing):
  elevated-marker.txt        IS_ADMIN lines (WSP3 pattern)
  acceptance-run.log         script transcript (UTF-8)
  acceptance-evidence.json   orchestration facts + precondition markers + plan §9 schema
  <scenario>-scenario.log    scenario binary self-log (--log-file, WSP3 pattern)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Scenario,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$EvidenceDir
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
$script:ValidScenarios   = @('controlled', 'crash-matrix', 'school')
$script:ExitOk           = 0
$script:ExitUsage        = 1
$script:ExitPrecondition = 2

# Per-scenario release binary name (target/release/<bin>.exe). TODO(W28-I/W29-I/
# W30-I): confirm these bin names when the scenario [[bin]] targets are declared
# next to src/scenarios/controlled.rs / crash_matrix.rs / school.rs; this map is
# the single edit point if a name differs.
$script:ScenarioBin = @{
    'controlled'   = 'exv-win32-controlled-vertical'
    'crash-matrix' = 'exv-win32-crash-matrix'
    'school'       = 'exv-win32-school-scenario'
}

# controlled / crash-matrix create a real Wintun adapter / mutate native
# networking in the scenario process, so they require elevation (admin PowerShell
# or UAC consent).
#
# school (阶段 4-ii-b) is the two-process core+engine topology: the school
# scenario bin is the NON-elevated core coordinator (core 普通 = 预期) and spawns
# the privileged engine itself via ShellExecuteExW(runas) — so the bin must run
# as a normal user, NOT elevated.
$script:ScenarioRequiresElevation = @{
    'controlled'   = $true
    'crash-matrix' = $true
    'school'       = $false
}

# Plan §9 mandatory evidence fields per scenario (null until the scenario binary
# records them; the binary writes the authoritative values via --evidence-dir).
$script:ScenarioEvidenceSchema = @{
    'controlled' = [ordered]@{
        'os_build_hardware'                    = $null  # OS/build/hardware
        'host_pid_token_elevation'             = $null  # host PID + token elevation
        'helper_pid_token_elevation'           = $null  # helper PID + token elevation
        'pipe_peer_predicates'                 = $null  # mutually-authenticated pipe peer checks
        'tls_chain_hostname_outcome'           = $null  # TLS chain + hostname verification result
        'cstp_offer_digest'                    = $null  # CSTP offer digest (never raw secret)
        'wintun_dll_adapter_luid_index'        = $null  # Wintun DLL / adapter / LUID / ifIndex
        'address_mtu_route_dns_before_after'   = $null  # before-applied-after snapshots
        'authenticated_packet_attach'          = $null  # packet attach over authenticated channel
        'real_ipv4_http_flow'                  = $null  # real IPv4 HTTP flow result
        'stop_journal_inventory_proof_retire'  = $null  # Stop journal / inventory / proof / retirement
        'no_dtls_source_dependency_guard'      = $null  # no DTLS / source / dependency guard
    }
    'crash-matrix' = [ordered]@{
        # Per crash point, each of these must be recorded (plan §9 W29):
        'checkpoints' = $null  # [{last_durable_record, native_observation, certainty, remaining_obligation, final_proof_or_blocker}]
        'restart_reconcile_outcome' = $null
        'third_party_route_dns_change' = $null
    }
    'school' = [ordered]@{
        'real_tls_identity'          = $null  # real TLS identity, NOT a controlled fake
        'group_password_challenge'   = $null  # challenge actually encountered (never raw secret)
        'cstp_only_tunnel'           = $null
        'school_target_ipv4_traffic' = $null
        'normal_stop_scoped_cleanup' = $null
    }
}

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
$script:Transcript = [System.Collections.Generic.List[string]]::new()
$script:PreconditionResults = [ordered]@{}
$script:FailedPreconditions = [System.Collections.Generic.List[object]]::new()
$script:EvidenceStatus = 'unknown'
$script:ElevationRequired = $false
$script:IsAdminRun = $false
$script:EvidenceDirResolved = $null
$script:WorkspaceDir = $null
$script:RepoRoot = $null
$script:ReleaseDir = $null
$script:ScenarioBinPath = $null

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Tx {
    param([Parameter(Mandatory = $true)][string]$Text)
    Write-Host $Text
    $script:Transcript.Add($Text)
}

function New-PredicateResult {
    param(
        [Parameter(Mandatory = $true)][string]$Predicate,
        [Parameter(Mandatory = $true)][bool]$Ok,
        [string]$Marker = '',
        [string]$Message = ''
    )
    $entry = [ordered]@{ ok = $Ok; marker = $Marker; message = $Message }
    $script:PreconditionResults[$Predicate] = $entry
    if (-not $Ok) {
        $script:FailedPreconditions.Add([pscustomobject]@{ predicate = $Predicate; marker = $Marker; message = $Message })
        Write-Tx ($Marker + " - " + $Message)
    }
    else {
        Write-Tx ("ok - " + $Predicate + " - " + $Message)
    }
}

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ScenarioBinaryPath {
    param([Parameter(Mandatory = $true)][string]$ScenarioName)
    $binName = $script:ScenarioBin[$ScenarioName]
    return Join-Path $script:ReleaseDir ($binName + '.exe')
}

function Write-ElevatedMarker {
    param([Parameter(Mandatory = $true)][string]$MarkerPath)
    # WSP3 pattern: append IS_ADMIN=<bool> at <iso timestamp> before any dispatch.
    $isAdmin = Test-IsAdmin
    $line = "IS_ADMIN=$isAdmin at $(Get-Date -Format o)"
    Add-Content -Path $MarkerPath -Value $line -Encoding ascii
    return $isAdmin
}

function Write-EvidenceJson {
    param(
        [Parameter(Mandatory = $true)][string]$JsonPath,
        [Parameter(Mandatory = $true)][int]$ExitCode
    )
    $evidence = [ordered]@{
        'scenario'                    = $Scenario
        'script'                      = 'run-native-acceptance.ps1'
        'script_role'                 = 'W28-Tb scenario driver skeleton'
        'generated_at'                = (Get-Date -Format o)
        'status'                      = $script:EvidenceStatus
        'exit_code'                   = $ExitCode
        'host_os'                     = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        'hostname'                    = $env:COMPUTERNAME
        'pwsh_version'                = $PSVersionTable.PSVersion.ToString()
        'repo_root'                   = $script:RepoRoot
        'workspace_dir'               = $script:WorkspaceDir
        'release_binary_checked'      = $script:ScenarioBinPath
        'env_elevated'                = $script:IsAdminRun
        'elevation_required'          = $script:ElevationRequired
        'preconditions'               = $script:PreconditionResults
        'scenario_evidence'           = $script:ScenarioEvidenceSchema[$Scenario]
        'scenario_evidence_authority' = ('scenario binary writes authoritative values via --evidence-dir; ' +
                                         'null fields = not yet observed (W28-I/W29-I/W30-I fill in)')
        'no_raw_secrets_written'      = $true  # contract: never raw secret/cookie/private key in evidence
    }
    $json = $evidence | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($JsonPath, $json, [System.Text.UTF8Encoding]::new($false))
}

function Write-TranscriptLog {
    param([Parameter(Mandatory = $true)][string]$LogPath)
    # WSP3 v2 lesson: no Tee-Object / cmd redirection; write UTF-8 directly.
    [System.IO.File]::WriteAllLines($LogPath, $script:Transcript, [System.Text.UTF8Encoding]::new($false))
}

function Exit-Runner {
    param([Parameter(Mandatory = $true)][int]$ExitCode)
    $jsonPath = Join-Path $script:EvidenceDirResolved 'acceptance-evidence.json'
    $logPath  = Join-Path $script:EvidenceDirResolved 'acceptance-run.log'
    if ($script:EvidenceDirResolved -and (Test-Path -LiteralPath $script:EvidenceDirResolved)) {
        Write-EvidenceJson -JsonPath $jsonPath -ExitCode $ExitCode
        Write-TranscriptLog -LogPath $logPath
    }
    Write-Tx ("== run-native-acceptance.ps1 exit code: $ExitCode (status: $($script:EvidenceStatus)) ==")
    exit $ExitCode
}

function Invoke-CargoReleaseBuild {
    param(
        [Parameter(Mandatory = $true)][string]$BuildOutLog,
        [Parameter(Mandatory = $true)][string]$BuildErrLog
    )
    # cargo build --manifest-path src/platform/win32/rust/Cargo.toml --locked --release
    # (plan §9 W28 frozen command; run from the workspace root).
    $cargoExe = (Get-Command cargo -ErrorAction SilentlyContinue)
    if (-not $cargoExe) {
        return [pscustomobject]@{ ok = $false; error = 'cargo not found on PATH' }
    }
    $manifest = Join-Path $script:WorkspaceDir 'Cargo.toml'
    $args = @('build', '--manifest-path', $manifest, '--locked', '--release')
    # Start-Process redirect avoids the PS 5.1 elevated-context stderr-kill issue
    # (WSP3 v2 lesson); output is read back from files, never via the pipeline.
    $proc = Start-Process -FilePath $cargoExe.Source `
        -ArgumentList $args `
        -WorkingDirectory $script:WorkspaceDir `
        -RedirectStandardOutput $BuildOutLog `
        -RedirectStandardError $BuildErrLog `
        -Wait -PassThru -NoNewWindow
    return [pscustomobject]@{ ok = ($proc.ExitCode -eq 0); exit_code = $proc.ExitCode }
}

function Invoke-SelfElevated {
    # WSP3 pattern: relaunch this script elevated; UAC is the single prompt and
    # passes silently when the operator's session is already consented.
    $pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue)
    $hostExe = if ($pwsh) { $pwsh.Source } else { 'powershell.exe' }
    $argLine = '-NoProfile -File "' + $PSCommandPath + '" -Scenario ' + $Scenario +
               ' -EvidenceDir "' + $script:EvidenceDirResolved + '"'
    try {
        $proc = Start-Process -FilePath $hostExe -ArgumentList $argLine -Verb RunAs -Wait -PassThru
        return [pscustomobject]@{ ok = $true; exit_code = $proc.ExitCode }
    }
    catch {
        return [pscustomobject]@{ ok = $false; exit_code = $null; error = $_.Exception.Message }
    }
}

# ---------------------------------------------------------------------------
# 1. Validate -Scenario (usage error for anything outside the frozen set)
# ---------------------------------------------------------------------------
if ($script:ValidScenarios -notcontains $Scenario) {
    Write-Host "ERROR: unknown -Scenario '$Scenario'. Valid values: $($script:ValidScenarios -join ', ')" -ForegroundColor Red
    exit $script:ExitUsage
}

# ---------------------------------------------------------------------------
# 2. Resolve paths and create -EvidenceDir
# ---------------------------------------------------------------------------
# Script lives at <root>/src/platform/win32/rust/scripts/run-native-acceptance.ps1
$script:RepoRoot      = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..\..\..')).Path
$script:WorkspaceDir  = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$script:ReleaseDir    = Join-Path $script:WorkspaceDir 'target\release'

$script:EvidenceDirResolved = $EvidenceDir
if (-not [System.IO.Path]::IsPathRooted($script:EvidenceDirResolved)) {
    $script:EvidenceDirResolved = Join-Path (Get-Location) $script:EvidenceDirResolved
}
$script:EvidenceDirResolved = [System.IO.Path]::GetFullPath($script:EvidenceDirResolved)
New-Item -ItemType Directory -Force -Path $script:EvidenceDirResolved | Out-Null

$script:ScenarioBinPath = Get-ScenarioBinaryPath -ScenarioName $Scenario
$markerPath = Join-Path $script:EvidenceDirResolved 'elevated-marker.txt'

Write-Tx ("run-native-acceptance.ps1 scenario=$Scenario evidenceDir=$($script:EvidenceDirResolved)")
Write-Tx ("repo_root=$($script:RepoRoot) workspace=$($script:WorkspaceDir)")
Write-Tx ("release_binary=$($script:ScenarioBinPath)")

# ---------------------------------------------------------------------------
# 3. Preconditions (W26..W30 convention: invalid environment is never a fake
#    RED/GREEN; each failed predicate emits its marker and blocks dispatch)
# ---------------------------------------------------------------------------

# 3.1 release build present: scenario binary in target/release; if missing, run
#     the plan's frozen cargo build once, then re-check. A successful build that
#     still lacks the scenario binary means the scenario implementation does not
#     exist yet (W28-I hook) -> not_run, not a fake result.
$binExists = Test-Path -LiteralPath $script:ScenarioBinPath
if (-not $binExists) {
    $buildOut = Join-Path $env:TEMP ('exv-native-acceptance-' + [guid]::NewGuid().ToString('N') + '.build.out.log')
    $buildErr = Join-Path $env:TEMP ('exv-native-acceptance-' + [guid]::NewGuid().ToString('N') + '.build.err.log')
    Write-Tx 'release scenario binary missing; running cargo build --locked --release ...'
    $build = Invoke-CargoReleaseBuild -BuildOutLog $buildOut -BuildErrLog $buildErr
    $binExists = Test-Path -LiteralPath $script:ScenarioBinPath
    if ($binExists) {
        # fallthrough: binary present after build
    }
    elseif (-not $build.ok) {
        $tail = ''
        if (Test-Path -LiteralPath $buildErr) {
            $errLines = @(Get-Content -LiteralPath $buildErr -Encoding UTF8 -ErrorAction SilentlyContinue)
            if ($errLines.Count -gt 8) { $tail = ($errLines | Select-Object -Last 8) -join ' | ' } else { $tail = $errLines -join ' | ' }
        }
        New-PredicateResult -Predicate 'release-build' -Ok $false `
            -Marker 'WIN_ACCEPTANCE_ENV_INVALID:release-build' `
            -Message ("cargo build --locked --release failed (exit $($build.exit_code)); workspace cannot produce the acceptance scenario binary. cargo stderr tail: $tail")
    }
    else {
        # TODO(W28-I): build succeeded but target/release/<bin>.exe was not
        # produced; plan scenario file src/scenarios/controlled.rs (crash_matrix.rs /
        # school.rs for the other scenarios) is not implemented yet. The dispatch
        # hook below is where W28-I wires the real binary.
        New-PredicateResult -Predicate 'scenario-binary-missing' -Ok $false `
            -Marker 'not_run/blocked_by_environment:scenario-binary-missing' `
            -Message ("release build succeeded but scenario binary '$($script:ScenarioBinPath)' does not exist; scenario implementation (plan src/scenarios/$Scenario.rs) not present yet - W28-I/W29-I/W30-I hook")
    }
}
else {
    New-PredicateResult -Predicate 'release-build' -Ok $true -Message ("scenario binary present: $($script:ScenarioBinPath)")
}

# 3.2 Wintun DLL availability via the frozen env name (plan §2 / WSP3).
$wintunDll = $env:EXV_RUST_VPN_WINTUN_DLL
if ($wintunDll -and (Test-Path -LiteralPath $wintunDll)) {
    New-PredicateResult -Predicate 'wintun-dll' -Ok $true -Message ("Wintun DLL: $wintunDll")
}
else {
    $msg = if ($wintunDll) { "EXV_RUST_VPN_WINTUN_DLL points to a missing file: $wintunDll" }
           else { 'EXV_RUST_VPN_WINTUN_DLL is not set; the scenario cannot load the frozen Wintun DLL (plan sec.2 / WSP3)' }
    New-PredicateResult -Predicate 'wintun-dll' -Ok $false `
        -Marker 'WIN_ACCEPTANCE_ENV_INVALID:wintun-dll' -Message $msg
}

# 3.3 School scenario target endpoints. 阶段 4-ii-b 之后，school scenario bin 是
# core 协调层：网关/凭据/UA/MTU/校园路由全部来自 config（`%USERPROFILE%\.exv`），
# 不再经 EXV_RUST_VPN_SCHOOL_TARGET 等环境变量注入，也不做 ingress HTTP/SSH flow。
# 网关可达性由 core 可信解析 + engine Connect 结果诚实记录——本 predicate 变为
# 信息性（不再阻塞）：env 存在时仍记录其形状，未设置也放行（config 驱动）。
if ($Scenario -eq 'school') {
    $targets = @($env:EXV_RUST_VPN_SCHOOL_TARGET -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    $flowTarget = $env:EXV_RUST_VPN_SCHOOL_FLOW_TARGET
    $msg = if ($targets.Count -ge 1) {
        "school env endpoints: $($targets -join ', '); flow target override: $flowTarget (informational; core reads config)"
    }
    else {
        'school gateway/credentials come from config (阶段 4-ii-b core coordinator); env target not required'
    }
    New-PredicateResult -Predicate 'school-target-endpoints' -Ok $true -Message $msg
}

# ---------------------------------------------------------------------------
# 4. Elevation context (WSP3 pattern). Only when every static precondition
#    already passed: no pointless UAC prompt for an invalid environment.
# ---------------------------------------------------------------------------
$script:ElevationRequired = $script:ScenarioRequiresElevation[$Scenario]
$elevationResult = [ordered]@{ ok = $true; marker = ''; message = '' }

if ($script:FailedPreconditions.Count -eq 0) {
    if ($script:ElevationRequired) {
        $script:IsAdminRun = Write-ElevatedMarker -MarkerPath $markerPath
        if ($script:IsAdminRun) {
            $elevationResult = [ordered]@{ ok = $true; marker = ''; message = 'running elevated (IS_ADMIN marker appended)' }
        }
        else {
            Write-Tx "scenario '$Scenario' requires elevation; relaunching self via Start-Process -Verb RunAs ..."
            $relaunch = Invoke-SelfElevated
            if ($relaunch.ok) {
                # The elevated instance writes the authoritative evidence + log.
                exit $relaunch.exit_code
            }
            $elevationResult = [ordered]@{ ok = $false; marker = 'WIN_ACCEPTANCE_ENV_INVALID:elevation-context';
                                           message = "elevated relaunch failed (UAC denied?): $($relaunch.error)" }
            New-PredicateResult -Predicate 'elevation-context' -Ok $false -Marker $elevationResult.marker -Message $elevationResult.message
        }
    }
    else {
        $script:IsAdminRun = Write-ElevatedMarker -MarkerPath $markerPath
        $elevationResult = [ordered]@{ ok = $true; marker = ''; message = 'elevation not required for this scenario' }
    }
}
else {
    # Static preconditions failed: record the elevation predicate honestly as
    # not checked (blocked earlier), never as a fake pass.
    $script:PreconditionResults['elevation-context'] = [ordered]@{ ok = $false; marker = 'not_run/blocked_by_environment:elevation-context';
        message = 'not reached: static preconditions failed' }
    Write-Tx 'not_run/blocked_by_environment:elevation-context - not reached: static preconditions failed'
}

# ---------------------------------------------------------------------------
# 5. Blocked? Write evidence and exit (honest not_run / env_invalid, no dispatch)
# ---------------------------------------------------------------------------
if ($script:FailedPreconditions.Count -gt 0) {
    $anyEnvInvalid = $false
    foreach ($f in $script:FailedPreconditions) {
        if ($f.marker -like 'WIN_ACCEPTANCE_ENV_INVALID:*') { $anyEnvInvalid = $true }
    }
    $script:EvidenceStatus = if ($anyEnvInvalid) { 'env_invalid' } else { 'not_run/blocked_by_environment' }
    Exit-Runner -ExitCode $script:ExitPrecondition
}

# ---------------------------------------------------------------------------
# 6. Dispatch the scenario binary (elevated instance only at this point).
#    WSP3 pattern: the binary self-logs via --log-file; no pipeline capture.
# ---------------------------------------------------------------------------
$scenarioLog = Join-Path $script:EvidenceDirResolved ($Scenario + '-scenario.log')
$dispatch = @{
    'controlled'   = {
        # TODO(W28-I): run the controlled_vertical scenario.
        # Plan scenario file: src/scenarios/controlled.rs
        # Terra gate:      exv-vpn-win32-acceptance/tests/controlled_vertical.rs
        # Evidence (§9 W28): TLS chain/hostname outcome, CSTP offer digest, Wintun
        # DLL/adapter/LUID/index, address/MTU/route/DNS before-applied-after,
        # authenticated packet attach, real IPv4 HTTP flow, Stop
        # journal/inventory/proof/retirement, no-DTLS guard.
        & $script:ScenarioBinPath --evidence-dir $script:EvidenceDirResolved --log-file $scenarioLog
    }
    'crash-matrix' = {
        # TODO(W29-I): run the crash-matrix scenario.
        # Plan scenario file: src/scenarios/crash_matrix.rs (stop_pressure.rs)
        # Terra gate:      exv-vpn-win32-acceptance/tests/crash_matrix.rs
        # Evidence (§9 W29): per crash point last durable record, native
        # observation, certainty, remaining obligation, final proof or blocker.
        & $script:ScenarioBinPath --evidence-dir $script:EvidenceDirResolved --log-file $scenarioLog
    }
    'school'       = {
        # TODO(W30-I): run the school scenario.
        # Plan scenario file: src/scenarios/school.rs
        # Terra gate:      exv-vpn-win32-acceptance/tests/school_scenario.rs
        # Evidence (§9 W30): real TLS identity, challenge actually encountered,
        # CSTP-only tunnel, school target IPv4 traffic, normal Stop + scoped
        # owned-resource cleanup. Credentials enter ONLY via the authenticated
        # controller one-shot - this script never forwards any secret.
        & $script:ScenarioBinPath --evidence-dir $script:EvidenceDirResolved --log-file $scenarioLog
    }
}

& $dispatch[$Scenario]
$scenarioExit = $LASTEXITCODE
# WSP3 pattern: append the exit code to the scenario log (ASCII).
Add-Content -Path $scenarioLog -Value "== scenario exit code: $scenarioExit ==" -Encoding ascii
Write-Tx ("scenario '$Scenario' finished with exit code $scenarioExit")

$script:EvidenceStatus = if ($scenarioExit -eq 0) { 'completed' } else { 'failed' }
Write-Tx ("scenario exit code: $scenarioExit -> status $($script:EvidenceStatus)")

Exit-Runner -ExitCode $scenarioExit

# EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
# cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md。
# 本文件是 Win32 真实宿主业务流验收驱动器；门禁执行适配见 docs/superpowers/governance/rust-product-line-governance-execution.md。

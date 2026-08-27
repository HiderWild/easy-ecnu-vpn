param(
  [string]$ExvPath = "",
  [string]$OutputRoot = "",
  [string]$ValidationPath = "",
  [ValidateSet("disabled", "auto", "enabled")]
  [string[]]$Modes = @("disabled", "auto", "enabled"),
  [ValidateSet("off", "tun")]
  [string[]]$ClashStates = @("off", "tun"),
  [int]$ConnectTimeoutSeconds = 90,
  [int]$CommandTimeoutSeconds = 20,
  [string]$CampusHttpUrl = "",
  [string]$SseWebSocketCommand = "",
  [string]$TunToggleScript = "",
  [int]$TunToggleTimeoutSeconds = 20,
  [int]$TunToggleRequestTimeoutSeconds = 5,
  [switch]$AutoClashTun,
  [switch]$NonInteractive,
  [switch]$SelfTest
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$diagnosticsScript = Join-Path $scriptDir "collect-dtls-network-diagnostics.ps1"
$defaultTunToggleScript = Join-Path $scriptDir "test-clash-tun-toggle.ps1"
$script:DtlsEvidencePattern = 'dtls.policy.decision|dtls.connected|dtls.unavailable|dtls.fallback|network.diagnostics.route_snapshot'
$script:BackendCompiled = "unknown"

function Test-IsAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-ExvPath {
  param([string]$Candidate)

  $candidates = @()
  if ($Candidate) { $candidates += $Candidate }
  $candidates += (Join-Path $repoRoot "build-windows\cpp\exv.exe")
  $candidates += (Join-Path $repoRoot "build\windows\webview\package\EXV\bin\exv.exe")
  $candidates += (Join-Path $repoRoot "build\windows\webview\package\EXV\exv.exe")

  foreach ($path in $candidates) {
    if ($path -and (Test-Path -LiteralPath $path)) {
      return (Resolve-Path -LiteralPath $path).Path
    }
  }

  throw "exv executable not found. Pass -ExvPath to a built exv.exe."
}

function Read-BackendCompiledFromBuildCache {
  param([string]$ExePath)

  $dir = Split-Path -Parent $ExePath
  if (-not $dir) { return "unknown" }

  $repoRootResolved = (Resolve-Path -LiteralPath $repoRoot).Path.TrimEnd("\")
  while ($dir) {
    try {
      $resolvedDir = (Resolve-Path -LiteralPath $dir).Path.TrimEnd("\")
    } catch {
      return "unknown"
    }
    if (-not $resolvedDir.StartsWith($repoRootResolved, [System.StringComparison]::OrdinalIgnoreCase)) {
      break
    }

    $cachePath = Join-Path $resolvedDir "CMakeCache.txt"
    if (Test-Path -LiteralPath $cachePath) {
      foreach ($line in (Get-Content -LiteralPath $cachePath)) {
        $match = [regex]::Match($line, '^EXV_ENABLE_DTLS_BACKEND:BOOL=(ON|OFF)$')
        if ($match.Success) {
          if ($match.Groups[1].Value -eq "ON") { return "yes" }
          if ($match.Groups[1].Value -eq "OFF") { return "no" }
        }
      }
      return "unknown"
    }

    if ($resolvedDir -eq $repoRootResolved) { break }
    $parent = Split-Path -Parent $resolvedDir
    if (-not $parent -or $parent -eq $resolvedDir) { break }
    $dir = $parent
  }

  return "unknown"
}

function Resolve-ExvRuntimeDir {
  param([string]$ExePath)

  $exeDir = Split-Path -Parent $ExePath
  $candidates = @()
  if ($env:EXV_RUNTIME_DIR) { $candidates += $env:EXV_RUNTIME_DIR }
  if ($exeDir) {
    $candidates += $exeDir
    $candidates += (Join-Path $exeDir "runtime")
  }
  $candidates += (Join-Path $repoRoot "runtime\win32-x64")

  foreach ($dir in $candidates) {
    if (-not $dir) { continue }
    $wintunPath = Join-Path $dir "wintun.dll"
    if (Test-Path -LiteralPath $wintunPath) {
      return (Resolve-Path -LiteralPath $dir).Path
    }
  }

  return ""
}

function Assert-ExvRuntimeDependencies {
  if ($script:ExvRuntimeDirResolved) { return }

  throw @"
Selected exv executable cannot find wintun.dll.
Current path: $script:ExvPathResolved

Use a packaged EXV runtime, place wintun.dll next to exv.exe, or restore:
  $repoRoot\runtime\win32-x64\wintun.dll
"@
}

function Ensure-ExvRuntimeDependencies {
  $exeDir = Split-Path -Parent $script:ExvPathResolved
  if (-not $exeDir) {
    throw "Cannot resolve selected exv.exe directory: $script:ExvPathResolved"
  }

  $sourceWintun = Join-Path $script:ExvRuntimeDirResolved "wintun.dll"
  $adjacentWintun = Join-Path $exeDir "wintun.dll"
  if (-not (Test-Path -LiteralPath $sourceWintun)) {
    throw "Resolved EXV runtime dir does not contain wintun.dll: $script:ExvRuntimeDirResolved"
  }

  if (-not (Test-Path -LiteralPath $adjacentWintun)) {
    Copy-Item -LiteralPath $sourceWintun -Destination $adjacentWintun -Force
  }

  if (-not (Test-Path -LiteralPath $adjacentWintun)) {
    throw "Failed to prepare wintun.dll next to selected exv.exe: $adjacentWintun"
  }

  $script:ExvAdjacentWintunPath = (Resolve-Path -LiteralPath $adjacentWintun).Path
}

function New-OutputRoot {
  param([string]$Candidate)

  if ($Candidate) {
    $root = $Candidate
  } else {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $root = Join-Path $repoRoot "build\dtls-live-validation\$stamp"
  }
  New-Item -ItemType Directory -Force -Path $root | Out-Null
  return (Resolve-Path -LiteralPath $root).Path
}

function Resolve-TunToggleScript {
  param([string]$Candidate)

  $candidates = @()
  if ($Candidate) { $candidates += $Candidate }
  $candidates += $defaultTunToggleScript

  foreach ($path in $candidates) {
    if ($path -and (Test-Path -LiteralPath $path)) {
      return (Resolve-Path -LiteralPath $path).Path
    }
  }

  throw "TUN toggle script not found. Pass -TunToggleScript or restore $defaultTunToggleScript."
}

function Quote-Argument {
  param([string]$Value)

  if ($Value -match '^[A-Za-z0-9._:/\\=-]+$') {
    return $Value
  }
  return '"' + ($Value -replace '"', '\"') + '"'
}

function Invoke-ExternalCommand {
  param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [string[]]$Arguments = @(),
    [int]$TimeoutSeconds = 20
  )

  $startInfo = New-Object System.Diagnostics.ProcessStartInfo
  $startInfo.FileName = $FilePath
  $startInfo.UseShellExecute = $false
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $startInfo.CreateNoWindow = $true
  $startInfo.Arguments = ($Arguments | ForEach-Object { Quote-Argument ([string]$_) }) -join " "

  $process = New-Object System.Diagnostics.Process
  $process.StartInfo = $startInfo
  try {
    [void]$process.Start()
    $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) {
      try { $process.Kill() } catch { }
      return [pscustomobject]@{
        ExitCode = -1
        TimedOut = $true
        Stdout = ""
        Stderr = ""
        Output = "command timed out"
      }
    }

    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $combined = (($stdout, $stderr) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join "`n"
    return [pscustomobject]@{
      ExitCode = $process.ExitCode
      TimedOut = $false
      Stdout = $stdout
      Stderr = $stderr
      Output = $combined.Trim()
    }
  }
  finally {
    if ($process) { $process.Dispose() }
  }
}

function Invoke-Exv {
  param(
    [string[]]$Arguments,
    [int]$TimeoutSeconds = $CommandTimeoutSeconds
  )
  return Invoke-ExternalCommand -FilePath $script:ExvPathResolved -Arguments $Arguments -TimeoutSeconds $TimeoutSeconds
}

function Test-ExvSupportsDtlsMode {
  $probe = Invoke-ExternalCommand `
    -FilePath $script:ExvPathResolved `
    -Arguments @("config", "set", "dtls_mode", "__exv_probe_invalid__") `
    -TimeoutSeconds $CommandTimeoutSeconds

  return $probe.Output -match "requires auto, enabled, or disabled"
}

function Assert-ExvSupportsDtlsMode {
  if (Test-ExvSupportsDtlsMode) { return }

  throw @"
Selected exv executable does not support 'config set dtls_mode'.
Current path: $script:ExvPathResolved

Rebuild the CLI first:
  cmake --build --preset windows-release --target exv

Or pass a rebuilt executable explicitly:
  -ExvPath <path-to-rebuilt-exv.exe>
"@
}

function Redact-LogLine {
  param([string]$Line)

  $redacted = $Line
  $patterns = @(
    '(?i)(password|passwd|token|secret|credential|auth_token|session_cookie|webvpn_cookie|csrf_token|bearer_token|api_key|apikey)=\S+',
    '(?i)("?(password|passwd|token|secret|credential|auth_token|session_cookie|webvpn_cookie|csrf_token|bearer_token|api_key|apikey)"?\s*[:=]\s*)("[^"]*"|\S+)',
    '(?i)(Cookie:\s*)\S+',
    '(?i)(Authorization:\s*)\S+'
  )
  foreach ($pattern in $patterns) {
    $redacted = [regex]::Replace($redacted, $pattern, '$1<redacted>')
  }
  return $redacted
}

function Write-CommandResult {
  param(
    [Parameter(Mandatory = $true)]$Result,
    [Parameter(Mandatory = $true)][string]$Path
  )

  @(
    "exit_code=$($Result.ExitCode)",
    "timed_out=$($Result.TimedOut)",
    "",
    $Result.Output
  ) | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Read-LatestTunToggleSummary {
  param([string]$OutputRoot)

  if (-not (Test-Path -LiteralPath $OutputRoot)) {
    throw "TUN toggle output root was not created: $OutputRoot"
  }

  $summaryPath = Get-ChildItem -LiteralPath $OutputRoot -Directory |
    Sort-Object LastWriteTime -Descending |
    ForEach-Object { Join-Path $_.FullName "summary.json" } |
    Where-Object { Test-Path -LiteralPath $_ } |
    Select-Object -First 1

  if (-not $summaryPath) {
    throw "TUN toggle summary.json not found under $OutputRoot"
  }

  return [pscustomobject]@{
    Path = $summaryPath
    Summary = (Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json)
  }
}

function Invoke-ClashTunToggle {
  param(
    [ValidateSet("Probe", "Enable", "Disable")]
    [string]$Mode,
    [string]$OutputRoot,
    [switch]$NoRestore
  )

  New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

  $arguments = @(
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    $script:TunToggleScriptResolved,
    "-Mode",
    $Mode,
    "-OutputRoot",
    $OutputRoot,
    "-TimeoutSeconds",
    ([string]$TunToggleRequestTimeoutSeconds)
  )
  if ($NoRestore) {
    $arguments += "-NoRestore"
  }

  $result = Invoke-ExternalCommand -FilePath "powershell" -Arguments $arguments -TimeoutSeconds $TunToggleTimeoutSeconds
  Write-CommandResult -Result $result -Path (Join-Path $OutputRoot "command.txt")
  $summary = $null
  $summaryError = ""
  try {
    $summary = Read-LatestTunToggleSummary -OutputRoot $OutputRoot
  } catch {
    $summaryError = $_.Exception.Message
  }
  if ($result.ExitCode -ne 0) {
    $summaryHint = if ($summary) { " and $($summary.Path)" } elseif ($summaryError) { "; summary unavailable: $summaryError" } else { "" }
    throw "Failed to set Clash/Mihomo TUN mode via $script:TunToggleScriptResolved. See $OutputRoot\command.txt$summaryHint"
  }
  if (-not $summary) {
    throw "TUN toggle command succeeded but summary was not found. See $OutputRoot\command.txt; $summaryError"
  }

  return $summary
}

function Set-ClashStateForCase {
  param(
    [ValidateSet("off", "tun")]
    [string]$State,
    [string]$CaseDir
  )

  if (-not $AutoClashTun) {
    if (-not $NonInteractive) {
      $caseName = Split-Path -Leaf $CaseDir
      Read-Host "Set Clash/Mihomo state to '$State', then press Enter for case '$caseName'"
    }
    return $null
  }

  $mode = if ($State -eq "tun") { "Enable" } else { "Disable" }
  $toggleRoot = Join-Path $CaseDir "clash-tun-toggle"
  return Invoke-ClashTunToggle -Mode $mode -OutputRoot $toggleRoot -NoRestore
}

function Get-StatusObject {
  $result = Invoke-Exv -Arguments @("status") -TimeoutSeconds $CommandTimeoutSeconds
  if ($result.ExitCode -ne 0) {
    return [pscustomobject]@{
      ok = $false
      error = $result.Output
      raw = $result.Output
    }
  }
  try {
    $parsed = $result.Output | ConvertFrom-Json
    $parsed | Add-Member -NotePropertyName ok -NotePropertyValue $true -Force
    $parsed | Add-Member -NotePropertyName raw -NotePropertyValue $result.Output -Force
    return $parsed
  }
  catch {
    return [pscustomobject]@{
      ok = $false
      error = "status JSON parse failed: $($_.Exception.Message)"
      raw = $result.Output
    }
  }
}

function Wait-ConnectionOutcome {
  param([int]$TimeoutSeconds)

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  $last = $null
  while ((Get-Date) -lt $deadline) {
    $last = Get-StatusObject
    if ($last.ok -and ($last.connected -eq $true -or $last.network_ready -eq $true)) {
      return $last
    }
    if ($last.ok -and ($last.error_code -or $last.last_error -or $last.phase -eq "failed")) {
      return $last
    }
    Start-Sleep -Seconds 2
  }

  if ($last) { return $last }
  return [pscustomobject]@{
    ok = $false
    error = "status polling timed out"
    raw = ""
  }
}

function Extract-Field {
  param($Object, [string]$Name)

  if (-not $Object) { return "" }
  $property = $Object.PSObject.Properties[$Name]
  if (-not $property) { return "" }
  if ($null -eq $property.Value) { return "" }
  return [string]$property.Value
}

function First-NonEmpty {
  param([string[]]$Values)

  foreach ($value in $Values) {
    if (-not [string]::IsNullOrWhiteSpace($value)) {
      return $value
    }
  }
  return ""
}

function Write-RedactedLogs {
  param([string]$Path)

  $result = Invoke-Exv -Arguments @("logs") -TimeoutSeconds $CommandTimeoutSeconds
  $dtlsEvidenceRegex = (($script:DtlsEvidencePattern -split '\|') |
    ForEach-Object { [regex]::Escape($_) }) -join "|"
  $lines = @()
  foreach ($line in ($result.Output -split "`r?`n")) {
    if ($line -match $dtlsEvidenceRegex -or
        $line -match 'dtls|DTLS|cstp|CSTP|transport|active_data_channel|fallback|tls_read_timeout|native.start|packet.loop') {
      $lines += (Redact-LogLine -Line $line)
    }
  }
  if ($lines.Count -eq 0) {
    $lines = @("No DTLS/CSTP summary lines found in exv logs output.")
  }
  $lines | Set-Content -LiteralPath $Path -Encoding UTF8
  return $result
}

function Invoke-Diagnostics {
  param([string]$Path)

  if (-not (Test-Path -LiteralPath $diagnosticsScript)) {
    throw "diagnostics script not found: $diagnosticsScript"
  }
  & $diagnosticsScript *> $Path
}

function Invoke-OptionalHttpProbe {
  param([string]$Uri, [string]$Path)

  if (-not $Uri) {
    "not run; pass -CampusHttpUrl to enable" | Set-Content -LiteralPath $Path -Encoding UTF8
    return "not_run"
  }
  try {
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec 30
    $watch.Stop()
    @(
      "status_code=$($response.StatusCode)",
      "bytes=$($response.RawContentLength)",
      "elapsed_ms=$($watch.ElapsedMilliseconds)"
    ) | Set-Content -LiteralPath $Path -Encoding UTF8
    return "ok"
  }
  catch {
    ("failed: " + $_.Exception.Message) | Set-Content -LiteralPath $Path -Encoding UTF8
    return "failed"
  }
}

function Invoke-OptionalCommandProbe {
  param([string]$Command, [string]$Path)

  if (-not $Command) {
    "not run; pass -SseWebSocketCommand to enable" | Set-Content -LiteralPath $Path -Encoding UTF8
    return "not_run"
  }

  $result = Invoke-ExternalCommand -FilePath "powershell.exe" -Arguments @("-NoProfile", "-Command", $Command) -TimeoutSeconds 45
  Write-CommandResult -Result $result -Path $Path
  if ($result.ExitCode -eq 0 -and -not $result.TimedOut) { return "ok" }
  return "failed"
}

function Write-ValidationMarkdown {
  param(
    [array]$Rows,
    [string]$Path,
    [string]$ArtifactRoot
  )

  $lines = @()
  $lines += "# DTLS Live Validation"
  $lines += ""
  $lines += "- Generated: $(Get-Date -Format o)"
  $lines += "- EXV path: $script:ExvPathResolved"
  $lines += "- Backend compiled (`EXV_ENABLE_DTLS_BACKEND`): $script:BackendCompiled"
  if ($script:ExvRuntimeDirResolved) {
    $lines += "- EXV runtime dir: $script:ExvRuntimeDirResolved"
  }
  if ($script:ExvAdjacentWintunPath) {
    $lines += "- EXV adjacent Wintun: $script:ExvAdjacentWintunPath"
  }
  if ($AutoClashTun -and $script:TunToggleScriptResolved) {
    $lines += "- Clash/Mihomo TUN control: automated via $script:TunToggleScriptResolved"
    $lines += "- Initial Clash/Mihomo TUN: $script:InitialClashTunEnabled"
  } else {
    $lines += "- Clash/Mihomo TUN control: manual"
  }
  $lines += "- Artifact root: $ArtifactRoot"
  $lines += "- Raw route/DNS diagnostics stay in the artifact root and should not be committed unless manually redacted."
  $lines += ""
  $lines += "| Mode | Clash/Mihomo | Backend compiled | Connected | Error code | DTLS mode | Active data channel | DTLS state | Fallback reason | Fallback count | HTTP probe | SSE/WebSocket probe | Artifacts |"
  $lines += "|---|---|---|---:|---|---|---|---|---|---:|---|---|---|"
  foreach ($row in $Rows) {
    $lines += "| $($row.mode) | $($row.clash_state) | $($row.backend_compiled) | $($row.connected) | $($row.error_code) | $($row.dtls_mode) | $($row.active_data_channel) | $($row.dtls_state) | $($row.dtls_fallback_reason) | $($row.dtls_fallback_count) | $($row.http_probe) | $($row.sse_probe) | $($row.artifact_dir) |"
  }
  $lines += ""
  $lines += "## Required Manual Checks"
  $lines += ""
  $lines += '- Confirm `disabled` never reports `active_data_channel=dtls`.'
  $lines += '- Confirm `enabled` attempts DTLS when the gateway advertises DTLS metadata.'
  $lines += '- Confirm `auto` falls back without failing VPN connectivity when UDP/DTLS is unavailable.'
  $lines += "- Compare Clash/Mihomo off vs TUN cases for route/DNS conflicts before changing release defaults."
  $lines += "- Review only redacted logs before copying evidence into committed docs."

  $parent = Split-Path -Parent $Path
  if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
  $lines | Set-Content -LiteralPath $Path -Encoding UTF8
}

if ($SelfTest) {
  if (-not (Test-Path -LiteralPath $diagnosticsScript)) {
    throw "SelfTest failed: collect-dtls-network-diagnostics.ps1 missing"
  }
  $null = New-OutputRoot -Candidate $OutputRoot
  Write-Output "run-dtls-live-validation self-test passed."
  exit 0
}

if (-not $AutoClashTun -and $NonInteractive -and $ClashStates.Count -gt 1) {
  throw "Manual Clash/Mihomo mode with -NonInteractive cannot safely label multiple ClashStates. Remove -NonInteractive, pass a single -ClashStates value, or use -AutoClashTun."
}

if (-not (Test-IsAdministrator)) {
  throw "This live validation changes VPN/network state. Run it from an elevated PowerShell session."
}

$script:ExvPathResolved = Resolve-ExvPath -Candidate $ExvPath
$script:BackendCompiled = Read-BackendCompiledFromBuildCache -ExePath $script:ExvPathResolved
$script:ExvRuntimeDirResolved = Resolve-ExvRuntimeDir -ExePath $script:ExvPathResolved
Assert-ExvRuntimeDependencies
Ensure-ExvRuntimeDependencies
$env:EXV_RUNTIME_DIR = $script:ExvRuntimeDirResolved
$artifactRoot = New-OutputRoot -Candidate $OutputRoot
$script:TunToggleScriptResolved = ""
$script:InitialClashTunEnabled = $null
if ($AutoClashTun) {
  $script:TunToggleScriptResolved = Resolve-TunToggleScript -Candidate $TunToggleScript
}
if (-not $ValidationPath) {
  $date = Get-Date -Format "yyyy-MM-dd"
  $ValidationPath = Join-Path $repoRoot "docs\validation\$date-dtls-live-validation.md"
}

$transcriptPath = Join-Path $artifactRoot "runner-transcript.txt"
try { Start-Transcript -LiteralPath $transcriptPath -Force | Out-Null } catch { }

Assert-ExvSupportsDtlsMode

$rows = @()
try {
  if ($AutoClashTun) {
    $initialToggle = Invoke-ClashTunToggle -Mode "Probe" -OutputRoot (Join-Path $artifactRoot "clash-tun-initial")
    $script:InitialClashTunEnabled = [bool]$initialToggle.Summary.initial_tun_enable
  }

  foreach ($mode in $Modes) {
    foreach ($clashState in $ClashStates) {
      $caseName = "$mode-$clashState"
      $caseDir = Join-Path $artifactRoot $caseName
      New-Item -ItemType Directory -Force -Path $caseDir | Out-Null

      [void](Set-ClashStateForCase -State $clashState -CaseDir $caseDir)

      $setResult = Invoke-Exv -Arguments @("config", "set", "dtls_mode", $mode)
      Write-CommandResult -Result $setResult -Path (Join-Path $caseDir "config-set.txt")
      if ($setResult.ExitCode -ne 0) {
        throw "Failed to set dtls_mode=$mode. See $caseDir\config-set.txt"
      }

      Invoke-Diagnostics -Path (Join-Path $caseDir "network-diagnostics.txt")

      $startResult = Invoke-Exv -Arguments @("start") -TimeoutSeconds $CommandTimeoutSeconds
      Write-CommandResult -Result $startResult -Path (Join-Path $caseDir "start.txt")

      $status = Wait-ConnectionOutcome -TimeoutSeconds $ConnectTimeoutSeconds
      ($status.raw | Out-String) | Set-Content -LiteralPath (Join-Path $caseDir "status.json") -Encoding UTF8

      $httpProbe = Invoke-OptionalHttpProbe -Uri $CampusHttpUrl -Path (Join-Path $caseDir "http-probe.txt")
      $sseProbe = Invoke-OptionalCommandProbe -Command $SseWebSocketCommand -Path (Join-Path $caseDir "sse-websocket-probe.txt")

      [void](Write-RedactedLogs -Path (Join-Path $caseDir "logs-redacted.txt"))

      $stopResult = Invoke-Exv -Arguments @("stop") -TimeoutSeconds $CommandTimeoutSeconds
      Write-CommandResult -Result $stopResult -Path (Join-Path $caseDir "stop.txt")
      Start-Sleep -Seconds 2

      $rows += [pscustomobject]@{
        mode = $mode
        clash_state = $clashState
        backend_compiled = $script:BackendCompiled
        connected = First-NonEmpty @(
          (Extract-Field -Object $status -Name "connected"),
          (Extract-Field -Object $status -Name "network_ready")
        )
        error_code = Extract-Field -Object $status -Name "error_code"
        dtls_mode = Extract-Field -Object $status -Name "dtls_mode"
        active_data_channel = Extract-Field -Object $status -Name "active_data_channel"
        dtls_state = Extract-Field -Object $status -Name "dtls_state"
        dtls_fallback_reason = Extract-Field -Object $status -Name "dtls_fallback_reason"
        dtls_fallback_count = Extract-Field -Object $status -Name "dtls_fallback_count"
        http_probe = $httpProbe
        sse_probe = $sseProbe
        artifact_dir = $caseDir
      }
    }
  }

  Write-ValidationMarkdown -Rows $rows -Path $ValidationPath -ArtifactRoot $artifactRoot
  Write-Output "DTLS live validation summary written to $ValidationPath"
  Write-Output "Raw artifacts written to $artifactRoot"
}
finally {
  if ($AutoClashTun -and $null -ne $script:InitialClashTunEnabled) {
    $restoreMode = if ($script:InitialClashTunEnabled) { "Enable" } else { "Disable" }
    try {
      [void](Invoke-ClashTunToggle -Mode $restoreMode -OutputRoot (Join-Path $artifactRoot "clash-tun-restore") -NoRestore)
    } catch {
      Write-Warning "Failed to restore initial Clash/Mihomo TUN state '$script:InitialClashTunEnabled': $($_.Exception.Message)"
    }
  }
  try { Stop-Transcript | Out-Null } catch { }
}

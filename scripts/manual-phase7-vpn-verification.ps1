param(
  [string]$PackageRoot = "",
  [string]$OutputRoot = "",
  [string]$StateDir = "",
  [int]$MonitorSeconds = 90,
  [int]$SampleIntervalMs = 500,
  [string]$ExvPath = "",
  [int]$ProbeIntervalMs = 2000,
  [int]$RpcTimeoutMs = 5000,
  [switch]$NoLaunch,
  [switch]$IncludeRawLogDelta,
  [switch]$CaptureScreenshot,
  [switch]$ProbeRpc
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

if (-not $PackageRoot) {
  $PackageRoot = Join-Path $repoRoot 'build\windows\webview\package\EXV'
}
if (-not $OutputRoot) {
  $OutputRoot = Join-Path $repoRoot 'build\manual-verification'
}
if ($StateDir) {
  $env:EXV_STATE_DIR = $StateDir
}

function Resolve-StateDir {
  if ($env:EXV_STATE_DIR) {
    return $env:EXV_STATE_DIR
  }
  if ($env:LOCALAPPDATA) {
    return Join-Path $env:LOCALAPPDATA 'EXV\profile\default'
  }
  if ($env:USERPROFILE) {
    return Join-Path $env:USERPROFILE 'AppData\Local\EXV\profile\default'
  }
  return Join-Path $env:ProgramData 'EXV\profile\default'
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

function Read-TextFromOffset {
  param(
    [string]$Path,
    [long]$Offset
  )

  if (-not (Test-Path -LiteralPath $Path)) {
    return "Log file was not present: $Path"
  }

  $stream = [System.IO.File]::Open(
    $Path,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::ReadWrite)
  try {
    if ($Offset -lt 0 -or $Offset -gt $stream.Length) {
      $Offset = 0
    }
    [void]$stream.Seek($Offset, [System.IO.SeekOrigin]::Begin)
    $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8, $true)
    try {
      $content = $reader.ReadToEnd()
    }
    finally {
      $reader.Dispose()
    }
  }
  finally {
    $stream.Dispose()
  }

  if (-not $content) {
    return "No new log content after offset $Offset."
  }
  return $content
}

function Write-LogEvidence {
  param(
    [string]$Path,
    [long]$Offset,
    [string]$SummaryPath,
    [string]$RawPath,
    [bool]$IncludeRaw
  )

  $content = Read-TextFromOffset -Path $Path -Offset $Offset
  $lines = $content -split "`r?`n"
  $summaryLines = @()
  foreach ($line in $lines) {
    if ($line -match '\[connect-timing\]' -or
        $line -match 'app_api:' -or
        $line -match 'Helper connector:' -or
        $line -match 'Native engine session' -or
        $line -match 'Connect requested' -or
        $line -match 'Helper session started') {
      $summaryLines += (Redact-LogLine -Line $line)
    }
  }

  if ($summaryLines.Count -eq 0) {
    $summaryLines = @('No connect-stage summary lines were found in the current-session log delta.')
  }
  $summaryLines | Set-Content -LiteralPath $SummaryPath -Encoding UTF8

  if ($IncludeRaw) {
    $rawLines = @()
    foreach ($line in $lines) {
      $rawLines += (Redact-LogLine -Line $line)
    }
    $rawLines | Set-Content -LiteralPath $RawPath -Encoding UTF8
  }
}

function Write-ProcessSnapshot {
  param([string]$OutPath)

  $rows = @()
  $processes = Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.ProcessName -in @('exv-ui', 'exv', 'exv-helper') }
  foreach ($process in $processes) {
    $startTime = ''
    try {
      $startTime = $process.StartTime.ToString('o')
    }
    catch {
      $startTime = ''
    }
    $rows += [pscustomobject]@{
      timestamp = (Get-Date).ToString('o')
      name = $process.ProcessName
      id = $process.Id
      responding = $process.Responding
      main_window_handle = $process.MainWindowHandle
      main_window_title = $process.MainWindowTitle
      start_time = $startTime
    }
  }

  if ($rows.Count -eq 0) {
    [pscustomobject]@{
      timestamp = (Get-Date).ToString('o')
      name = 'none'
      id = ''
      responding = ''
      main_window_handle = ''
      main_window_title = ''
      start_time = ''
    } | Export-Csv -LiteralPath $OutPath -NoTypeInformation -Encoding UTF8
    return
  }

  $rows | Export-Csv -LiteralPath $OutPath -NoTypeInformation -Encoding UTF8
}

function Capture-PrimaryScreen {
  param([string]$OutPath)

  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing

  $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
  $bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
  try {
    $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    $bitmap.Save($OutPath, [System.Drawing.Imaging.ImageFormat]::Png)
  }
  finally {
    $graphics.Dispose()
    $bitmap.Dispose()
  }
}

function Invoke-DesktopRpcProbe {
  param(
    [string]$ExePath,
    [string]$Action,
    [int]$TimeoutMs
  )

  $started = Get-Date
  $watch = [System.Diagnostics.Stopwatch]::StartNew()
  $stdout = ''
  $stderr = ''
  $timedOut = $false
  $exitCode = ''
  $ok = ''
  $code = ''
  $message = ''
  $statusErrorCode = ''
  $statusError = ''
  $itemCount = ''

  try {
    if (-not (Test-Path -LiteralPath $ExePath)) {
      throw "exv executable not found: $ExePath"
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ExePath
    $psi.Arguments = "desktop-rpc $Action {}"
    $psi.WorkingDirectory = Split-Path -Parent $ExePath
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    [void]$process.Start()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutMs)) {
      $timedOut = $true
      try {
        $process.Kill()
      }
      catch {
      }
      $process.WaitForExit()
    }
    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    $exitCode = $process.ExitCode

    if ($stdout) {
      try {
        $parsed = $stdout | ConvertFrom-Json
        if ($parsed -is [array]) {
          $itemCount = [string]$parsed.Count
        }
        else {
          if ($null -ne $parsed.ok) {
            $ok = [string]$parsed.ok
          }
          if ($parsed.code) {
            $code = [string]$parsed.code
          }
          if ($parsed.message) {
            $message = [string]$parsed.message
          }
          if ($parsed.error_code) {
            $statusErrorCode = [string]$parsed.error_code
          }
          if ($parsed.error) {
            $statusError = [string]$parsed.error
          }
          if ($parsed.data -is [array]) {
            $itemCount = [string]$parsed.data.Count
          }
        }
      }
      catch {
        $message = 'Probe returned non-JSON output.'
      }
    }
  }
  catch {
    $code = 'probe_error'
    $message = $_.Exception.Message
  }
  finally {
    $watch.Stop()
  }

  return [pscustomobject]@{
    timestamp = $started.ToString('o')
    action = $Action
    duration_ms = $watch.ElapsedMilliseconds
    rpc_timeout_ms = $TimeoutMs
    timed_out = $timedOut
    exit_code = $exitCode
    ok = $ok
    code = $code
    message = Redact-LogLine -Line $message
    error_code = $statusErrorCode
    error = Redact-LogLine -Line $statusError
    item_count = $itemCount
    stderr = Redact-LogLine -Line ($stderr.Trim())
  }
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$sessionDir = Join-Path $OutputRoot "phase7-vpn-$timestamp"
New-Item -ItemType Directory -Force -Path $sessionDir | Out-Null

$resolvedStateDir = Resolve-StateDir
$logPath = Join-Path $resolvedStateDir 'exv.log'
$logOffset = 0
if (Test-Path -LiteralPath $logPath) {
  $logOffset = (Get-Item -LiteralPath $logPath).Length
}

$uiShellExe = Join-Path $PackageRoot 'exv-ui.exe'
if (-not $ExvPath) {
  $ExvPath = Join-Path $PackageRoot 'exv.exe'
  if (-not (Test-Path -LiteralPath $ExvPath)) {
    $ExvPath = Join-Path $repoRoot 'build-windows\cpp\exv.exe'
  }
}
$startedProcessId = ''
if (-not $NoLaunch) {
  if (-not (Test-Path -LiteralPath $uiShellExe)) {
    throw "exv-ui.exe not found: $uiShellExe"
  }
  $process = Start-Process -FilePath $uiShellExe -WorkingDirectory $PackageRoot -PassThru
  $startedProcessId = $process.Id
}

$metadata = [ordered]@{
  timestamp = (Get-Date).ToString('o')
  repo_root = $repoRoot
  package_root = $PackageRoot
  state_dir = $resolvedStateDir
  log_path = $logPath
  output_dir = $sessionDir
  launched = (-not $NoLaunch)
  started_process_id = $startedProcessId
  monitor_seconds = $MonitorSeconds
  sample_interval_ms = $SampleIntervalMs
  exv_path = $ExvPath
  probe_rpc = [bool]$ProbeRpc
  probe_interval_ms = $ProbeIntervalMs
  rpc_timeout_ms = $RpcTimeoutMs
  include_raw_log_delta = [bool]$IncludeRawLogDelta
  screenshot_requested = [bool]$CaptureScreenshot
}
$metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $sessionDir 'metadata.json') -Encoding UTF8

Write-Host ''
Write-Host '=== EXV Phase 7 Manual Verification Capture ===' -ForegroundColor Cyan
Write-Host "Output: $sessionDir"
Write-Host "State dir: $resolvedStateDir"
Write-Host "Log: $logPath"
Write-Host ''
Write-Host 'During the monitor window, perform the manual checks:'
Write-Host '  1. Click Connect and open Logs while connect is in progress.'
Write-Host '  2. Click the yellow in-progress cancel button.'
Write-Host '  3. Rapidly click connect/cancel several times.'
Write-Host '  4. Toggle advanced -> minimal 10 times at moderate speed, advanced -> minimal 10 times rapidly, and minimal -> advanced 10 times rapidly.'
Write-Host '  5. If a real connect failure occurs, verify the visible UI error.'
Write-Host ''
if ($IncludeRawLogDelta) {
  Write-Host 'Raw log-delta capture is enabled; secret-like fields are redacted before writing.' -ForegroundColor Yellow
}
else {
  Write-Host 'Raw log-delta capture is disabled. Only a redacted connect-stage summary will be written.'
}
Write-Host "Monitoring process responsiveness for $MonitorSeconds seconds..."
if ($ProbeRpc) {
  Write-Host "Read-only RPC probes enabled: status.get and logs.list every $ProbeIntervalMs ms with $RpcTimeoutMs ms timeout."
}

$samplesPath = Join-Path $sessionDir 'process-samples.csv'
$rpcProbesPath = Join-Path $sessionDir 'rpc-probes.csv'
$samples = @()
$rpcProbes = @()
$deadline = (Get-Date).AddSeconds($MonitorSeconds)
$nextProbeAt = Get-Date
while ((Get-Date) -lt $deadline) {
  $now = Get-Date
  $processes = Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.ProcessName -in @('exv-ui', 'exv', 'exv-helper') }

  if ($processes.Count -eq 0) {
    $samples += [pscustomobject]@{
      timestamp = $now.ToString('o')
      name = 'none'
      id = ''
      responding = ''
      main_window_handle = ''
      main_window_title = ''
    }
  }
  else {
    foreach ($process in $processes) {
      $samples += [pscustomobject]@{
        timestamp = $now.ToString('o')
        name = $process.ProcessName
        id = $process.Id
        responding = $process.Responding
        main_window_handle = $process.MainWindowHandle
        main_window_title = $process.MainWindowTitle
      }
    }
  }

  if ($ProbeRpc -and $now -ge $nextProbeAt) {
    foreach ($action in @('status.get', 'logs.list')) {
      $rpcProbes += Invoke-DesktopRpcProbe `
        -ExePath $ExvPath `
        -Action $action `
        -TimeoutMs $RpcTimeoutMs
    }
    $nextProbeAt = (Get-Date).AddMilliseconds($ProbeIntervalMs)
  }

  Start-Sleep -Milliseconds $SampleIntervalMs
}

$samples | Export-Csv -LiteralPath $samplesPath -NoTypeInformation -Encoding UTF8
if ($ProbeRpc) {
  $rpcProbes | Export-Csv -LiteralPath $rpcProbesPath -NoTypeInformation -Encoding UTF8
}
else {
  [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    action = 'disabled'
    duration_ms = ''
    rpc_timeout_ms = $RpcTimeoutMs
    timed_out = ''
    exit_code = ''
    ok = ''
    code = ''
    message = 'Run with -ProbeRpc to record read-only status.get/logs.list responsiveness.'
    error_code = ''
    error = ''
    item_count = ''
    stderr = ''
  } | Export-Csv -LiteralPath $rpcProbesPath -NoTypeInformation -Encoding UTF8
}
Write-ProcessSnapshot -OutPath (Join-Path $sessionDir 'process-final.csv')
Write-LogEvidence `
  -Path $logPath `
  -Offset $logOffset `
  -SummaryPath (Join-Path $sessionDir 'log-summary.txt') `
  -RawPath (Join-Path $sessionDir 'log-delta-redacted.txt') `
  -IncludeRaw ([bool]$IncludeRawLogDelta)

if ($CaptureScreenshot) {
  Capture-PrimaryScreen -OutPath (Join-Path $sessionDir 'primary-screen.png')
}

$observationTemplate = @'
# Phase 7 Manual Observation

- [ ] Connect attempt was started.
- [ ] Logs panel opened while connect was in progress.
- [ ] Logs/status/config UI stayed responsive during connect.
- [ ] Yellow in-progress button cancelled connect without showing a failure modal.
- [ ] Rapid connect/cancel settled to the latest user intent.
- [ ] Rapid minimal/advanced toggles did not bounce after input stopped.
- [ ] Final mode matched the last accepted user click.
- [ ] Real connect failure, if produced, was visible in the UI.
- [ ] Any unresponsive interval is visible in process-samples.csv.
- [ ] If -ProbeRpc was used, rpc-probes.csv shows status.get/logs.list latency and any status error_code observed during the run.

## Transparent Shell Mode Transition Checks

- [ ] Windows: advanced -> minimal shows app icon mask immediately.
- [ ] Windows: advanced -> minimal visually shrinks inside the old physical window, then performs one final physical resize.
- [ ] Windows: minimal -> advanced performs one physical resize first, then visually expands content.
- [ ] Windows: transparent shell area is not painted as an opaque full-window panel.
- [ ] Windows: during the transition mask, the area outside the mask but inside the physical window is fully transparent.
- [ ] Windows: toggle advanced -> minimal 10 times at moderate speed; final mode matches the last click.
- [ ] Windows: toggle advanced -> minimal 10 times rapidly; final mode matches the last click.
- [ ] Windows: toggle minimal -> advanced 10 times rapidly; final mode matches the last click.
- [ ] Windows: click minimize during idle; the window minimizes.
- [ ] Windows: click close during idle; the existing close-confirmation flow opens.
- [ ] Windows: close and minimize still work after transitions.
- [ ] macOS: advanced -> minimal shows app icon mask immediately.
- [ ] macOS: traffic-light controls remain native and embedded in the app frame.
- [ ] macOS: the same direction-specific resize timing is visible.
- [ ] macOS: transparent shell area is not painted as an opaque full-window panel.
- [ ] macOS: during the transition mask, the area outside the mask but inside the physical window is fully transparent.
- [ ] macOS: app icon mask remains visible through transition settle.

Notes:

'@
$observationTemplate | Set-Content -LiteralPath (Join-Path $sessionDir 'manual-observation.md') -Encoding UTF8

Write-Host ''
Write-Host 'Capture complete.' -ForegroundColor Green
Write-Host "Artifacts: $sessionDir"
Write-Host 'Fill manual-observation.md with the observed result before using this as Phase 7 evidence.'

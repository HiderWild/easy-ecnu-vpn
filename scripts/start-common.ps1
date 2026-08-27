param(
  [Parameter(Mandatory = $true)][string]$RepoRoot,
  [int]$Port = 8288,
  [string]$WebView2SdkDir = $env:WEBVIEW2_SDK_DIR
)

$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath($RepoRoot)

$scriptDir = Join-Path $repoRoot 'scripts'
$webviewRoot = Join-Path $repoRoot 'build\windows\webview'
$packageRoot = Join-Path $repoRoot 'build\windows\webview\package\EXV'
$cppBuildRoot = Join-Path $repoRoot 'build-windows'
$cppBuildDir = Join-Path $cppBuildRoot 'cpp'
$uiShellExe = Join-Path $packageRoot 'exv-ui.exe'
$exvExe = Join-Path $packageRoot 'bin\exv.exe'
$exvHelperExe = Join-Path $packageRoot 'bin\exv-helper.exe'
$helperServiceName = 'exv-helper'
$programData = [Environment]::GetFolderPath('CommonApplicationData')
$stableHelperExe = if ([string]::IsNullOrWhiteSpace($programData)) {
  'C:\ProgramData\EXV\Helper\exv-helper.exe'
}
else {
  Join-Path $programData 'EXV\Helper\exv-helper.exe'
}
$launchArgsFile = Join-Path $packageRoot 'exv-ui.args'
$desktopOutLog = Join-Path $repoRoot 'build\windows\webview\start-desktop.out.log'
$desktopErrLog = Join-Path $repoRoot 'build\windows\webview\start-desktop.err.log'
if (-not $global:ExvStartProtectedProcessIds) {
  $global:ExvStartProtectedProcessIds = @{}
}

function Write-Info([string]$Message) {
  Write-Output "[start] $Message"
}

function Convert-ServicePathNameToExecutablePath {
  param([string]$PathName)

  if ([string]::IsNullOrWhiteSpace($PathName)) {
    return $null
  }

  $trimmed = $PathName.Trim()
  if ($trimmed -match '^"([^"]+)"') {
    return $Matches[1]
  }
  if ($trimmed -match '^(.+?\.exe)(?:\s|$)') {
    return $Matches[1]
  }

  return $trimmed
}

function Test-SamePath {
  param(
    [string]$Left,
    [string]$Right
  )

  if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) {
    return $false
  }

  try {
    return ([System.IO.Path]::GetFullPath($Left).TrimEnd('\') -ieq
      [System.IO.Path]::GetFullPath($Right).TrimEnd('\'))
  }
  catch {
    return ($Left.TrimEnd('\') -ieq $Right.TrimEnd('\'))
  }
}

function Test-HelperServiceUsesStablePath {
  param($Snapshot)

  if (-not $Snapshot) {
    return $false
  }

  return (Test-SamePath $Snapshot.BinaryPath $stableHelperExe)
}

function Get-HelperServiceSnapshot {
  $service = Get-CimInstance Win32_Service -Filter "Name='$helperServiceName'" -ErrorAction SilentlyContinue
  if (-not $service) {
    return $null
  }

  $binaryPath = Convert-ServicePathNameToExecutablePath $service.PathName
  $binaryExists = $false
  if (-not [string]::IsNullOrWhiteSpace($binaryPath)) {
    $binaryExists = Test-Path -LiteralPath $binaryPath
  }

  return [pscustomobject]@{
    Name = $service.Name
    State = $service.State
    Status = $service.Status
    StartMode = $service.StartMode
    ProcessId = [int]$service.ProcessId
    PathName = $service.PathName
    BinaryPath = $binaryPath
    BinaryExists = $binaryExists
    UsesStablePath = (Test-SamePath $binaryPath $stableHelperExe)
  }
}

function Write-HelperServiceSnapshot {
  param($Snapshot)

  if (-not $Snapshot) {
    Write-Info "Service $helperServiceName is not installed"
    return
  }

  $binarySummary = 'unknown'
  if (-not [string]::IsNullOrWhiteSpace($Snapshot.BinaryPath)) {
    $binarySummary = "$($Snapshot.BinaryPath) (exists=$($Snapshot.BinaryExists))"
  }

  Write-Info "Service ${helperServiceName}: state=$($Snapshot.State), start=$($Snapshot.StartMode), pid=$($Snapshot.ProcessId), stable=$($Snapshot.UsesStablePath), binary=$binarySummary"
}

function Wait-HelperServiceStopped {
  param([int]$TimeoutSeconds = 10)

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    $snapshot = Get-HelperServiceSnapshot
    if (-not $snapshot -or $snapshot.State -eq 'Stopped') {
      return $true
    }
    Start-Sleep -Milliseconds 300
  }

  return $false
}

function Wait-HelperServiceAbsent {
  param([int]$TimeoutSeconds = 10)

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    if (-not (Get-HelperServiceSnapshot)) {
      return $true
    }
    Start-Sleep -Milliseconds 300
  }

  return $false
}

function Resolve-WebView2Sdk {
  param([string]$RequestedPath)

  if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
    if (Test-Path -LiteralPath (Join-Path $RequestedPath 'build\native\include\WebView2.h')) {
      return (Resolve-Path -LiteralPath $RequestedPath).Path
    }
    throw "WEBVIEW2_SDK_DIR does not contain build\native\include\WebView2.h: $RequestedPath"
  }

  $candidate = Join-Path $repoRoot 'build\deps\webview2\1.0.4022.49'
  if (Test-Path -LiteralPath (Join-Path $candidate 'build\native\include\WebView2.h')) {
    return (Resolve-Path -LiteralPath $candidate).Path
  }

  throw 'WEBVIEW2_SDK_DIR is required, or build\deps\webview2\1.0.4022.49 must exist.'
}

function Invoke-Step {
  param(
    [Parameter(Mandatory = $true)][string]$Command,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments,
    [string]$WorkingDirectory = $repoRoot
  )

  Push-Location $WorkingDirectory
  try {
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
      throw "Command failed: $Command $($Arguments -join ' ')"
    }
  }
  finally {
    Pop-Location
  }
}

function Invoke-WindowsPackageDependencyBootstrap {
  $bootstrapScript = Join-Path $scriptDir 'bootstrap-windows-package-deps.ps1'
  if (-not (Test-Path -LiteralPath $bootstrapScript -PathType Leaf)) {
    throw "Windows package dependency bootstrap script is missing: $bootstrapScript"
  }

  $arguments = @(
    '-NoProfile',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    $bootstrapScript
  )
  if (-not [string]::IsNullOrWhiteSpace($WebView2SdkDir)) {
    $arguments += @('-WebView2SdkDir', $WebView2SdkDir)
  }
  if (-not [string]::IsNullOrWhiteSpace($env:EXV_WEBVIEW2_LOADER_DLL)) {
    $arguments += @('-WebView2LoaderDll', $env:EXV_WEBVIEW2_LOADER_DLL)
  }
  if (-not [string]::IsNullOrWhiteSpace($env:EXV_RUNTIME_DIR)) {
    $arguments += @('-RuntimeDir', $env:EXV_RUNTIME_DIR)
  }
  if (-not [string]::IsNullOrWhiteSpace($env:EXV_WINTUN_DLL)) {
    $arguments += @('-WintunDllPath', $env:EXV_WINTUN_DLL)
  }

  Invoke-Step -Command 'powershell.exe' -Arguments $arguments
}

function Get-CurrentProcessAncestorIds {
  $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
  $parents = @{}
  foreach ($process in $processes) {
    $parents[[int]$process.ProcessId] = [int]$process.ParentProcessId
  }

  $ids = @()
  $seen = New-Object 'System.Collections.Generic.HashSet[int]'
  $current = [int]$PID
  while ($true) {
    if (-not $seen.Add($current)) { break }
    $ids += $current
    if (-not $parents.ContainsKey($current)) { break }
    $parent = $parents[$current]
    if ($parent -le 0) { break }
    $current = $parent
  }

  return $ids
}

function Set-ProtectedProcessIds {
  param([object[]]$ProcessIds = @())

  $protected = @{}
  function Add-ProtectedPidItem {
    param([object]$Value)

    if ($null -eq $Value) {
      return
    }
    if ($Value -is [System.Array]) {
      foreach ($nested in $Value) {
        Add-ProtectedPidItem $nested
      }
      return
    }
    if ($Value -is [string]) {
      foreach ($token in ($Value -split '[,\s]+')) {
        if (-not [string]::IsNullOrWhiteSpace($token)) {
          $pidValue = [int]$token
          if ($pidValue -gt 0) {
            $protected[$pidValue] = $true
          }
        }
      }
      return
    }

    $pidValue = [int]$Value
    if ($pidValue -gt 0) {
      $protected[$pidValue] = $true
    }
  }

  foreach ($item in $ProcessIds) {
    if ($null -eq $item) {
      continue
    }
    Add-ProtectedPidItem $item
  }

  $global:ExvStartProtectedProcessIds = $protected
}

function Get-ProtectedProcessIds {
  return @($global:ExvStartProtectedProcessIds.Keys | ForEach-Object { [int]$_ } | Sort-Object -Unique)
}

function Test-IsProtectedProcessId {
  param([int]$ProcessId)
  return $global:ExvStartProtectedProcessIds.ContainsKey($ProcessId)
}

function Get-ProcessesOnPort {
  param([int]$LocalPort)

  $owners = Get-NetTCPConnection -LocalPort $LocalPort -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique
  if (-not $owners) {
    return @()
  }

  return Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.ProcessId -in $owners }
}

function Get-ProjectProcesses {
  $results = @()
  $alwaysMatchNames = @('exv.exe', 'exv-ui.exe')
  $conditionalNames = @('exv-helper.exe', 'node.exe', 'pnpm.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe')
  $commandPatterns = @(
    "*$repoRoot*",
    "*$packageRoot*",
    '*exv-ui.exe*',
    '*exv-helper.exe*',
    '*exv.exe*',
    "*localhost:$Port*",
    "*--port $Port*"
  )

  $results += Get-ProcessesOnPort -LocalPort $Port

  foreach ($process in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) {
    $processIdValue = [int]$process.ProcessId
    if (Test-IsProtectedProcessId $processIdValue) {
      continue
    }

    if ($alwaysMatchNames -contains $process.Name) {
      $results += $process
      continue
    }

    if ($conditionalNames -notcontains $process.Name) {
      continue
    }

    $commandLine = [string]$process.CommandLine
    if ([string]::IsNullOrWhiteSpace($commandLine)) {
      continue
    }

    foreach ($pattern in $commandPatterns) {
      if ($commandLine -like $pattern) {
        $results += $process
        break
      }
    }
  }

  return $results |
    Where-Object { -not (Test-IsProtectedProcessId ([int]$_.ProcessId)) } |
    Sort-Object ProcessId -Unique
}

function Stop-ProcessTreeSafe {
  param(
    [Parameter(Mandatory = $true)][int]$ProcessId,
    [string]$Name = ''
  )

  if (Test-IsProtectedProcessId $ProcessId) {
    return
  }

  if (-not (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) {
    return
  }

  try {
    Stop-Process -Id $ProcessId -Force -ErrorAction Stop
  }
  catch {
    try {
      taskkill /PID $ProcessId /F /T | Out-Null
    }
    catch {
      $displayName = if ($Name) { $Name } else { "PID $ProcessId" }
      Write-Info "Failed to terminate ${displayName}: $($_.Exception.Message)"
    }
  }
}

function Stop-HelperService {
  $snapshot = Get-HelperServiceSnapshot
  if (-not $snapshot) {
    return
  }

  Write-HelperServiceSnapshot $snapshot
  if ($snapshot.State -eq 'Stopped') {
    return
  }

  Write-Info "Stopping service $helperServiceName"
  try {
    Stop-Service -Name $helperServiceName -Force -ErrorAction Stop
  }
  catch {
    try {
      sc.exe stop $helperServiceName | Out-Null
    }
    catch {
      Write-Info "Failed to stop service ${helperServiceName}: $($_.Exception.Message)"
    }
  }

  if (-not (Wait-HelperServiceStopped -TimeoutSeconds 10)) {
    $remaining = Get-HelperServiceSnapshot
    Write-HelperServiceSnapshot $remaining
    throw "Service $helperServiceName did not stop before rebuild."
  }
}

function Stop-StaleHelperService {
  $snapshot = Get-HelperServiceSnapshot
  if (-not $snapshot) {
    return
  }

  if ((Test-HelperServiceUsesStablePath $snapshot) -and $snapshot.BinaryExists) {
    Write-Info "Service $helperServiceName uses the stable helper path; leaving it registered and running"
    return
  }

  Stop-HelperService
}

function Uninstall-HelperService {
  $snapshot = Get-HelperServiceSnapshot
  if (-not $snapshot) {
    Write-Info "Service $helperServiceName is not installed; uninstall skipped"
    return
  }

  Stop-HelperService

  Write-Info "Deleting service $helperServiceName"
  $deleteOutput = & sc.exe delete $helperServiceName 2>&1
  $deleteExitCode = $LASTEXITCODE
  if ($deleteExitCode -ne 0 -and (Get-HelperServiceSnapshot)) {
    $deleteText = ($deleteOutput | Out-String).Trim()
    throw "Failed to delete service $helperServiceName with exit code $deleteExitCode. $deleteText"
  }

  if (-not (Wait-HelperServiceAbsent -TimeoutSeconds 10)) {
    $remaining = Get-HelperServiceSnapshot
    Write-HelperServiceSnapshot $remaining
    throw "Service $helperServiceName is still registered after delete request. Close service management tools and rerun start.ps1."
  }

  Write-Info "Service $helperServiceName registration removed"
}

function Invoke-HelperServicePrepackageCleanup {
  Write-Info 'Checking helper service before package cleanup'
  $snapshot = Get-HelperServiceSnapshot
  Write-HelperServiceSnapshot $snapshot
  if (-not $snapshot) {
    return
  }

  if ((Test-HelperServiceUsesStablePath $snapshot) -and $snapshot.BinaryExists) {
    Write-Info "Service $helperServiceName already points to stable helper; uninstall skipped"
    return
  }

  Uninstall-HelperService
}

function Stop-ProjectProcesses {
  Write-Info 'Stopping residual project processes'
  Stop-StaleHelperService

  foreach ($candidate in Get-ProjectProcesses) {
    Write-Info "Stopping $($candidate.Name)[$($candidate.ProcessId)]"
    Stop-ProcessTreeSafe -ProcessId ([int]$candidate.ProcessId) -Name $candidate.Name
  }

  $deadline = (Get-Date).AddSeconds(5)
  while ((Get-Date) -lt $deadline) {
    $remaining = Get-ProjectProcesses
    if (-not $remaining) {
      return
    }
    Start-Sleep -Milliseconds 300
  }

  $remaining = Get-ProjectProcesses
  if ($remaining) {
    $summary = ($remaining | ForEach-Object { "$($_.Name)[$($_.ProcessId)]" }) -join ', '
    throw "Residual project processes still running: $summary. Re-run from an elevated PowerShell terminal before rebuilding."
  }
}

function Remove-DirectorySafe {
  param([Parameter(Mandatory = $true)][string]$Path)

  if (Test-Path -LiteralPath $Path) {
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Clean-BuildArtifacts {
  Write-Info 'Removing build and compilation artifacts only (package caches preserved)'
  Remove-DirectorySafe $cppBuildRoot
  Remove-DirectorySafe $webviewRoot
  Write-Info 'Preserved: webui/node_modules, build/codex-corepack, build/deps'
}

function Show-FileHashIfPresent {
  param([Parameter(Mandatory = $true)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) {
    Write-Info "Missing: $Path"
    return
  }

  Get-FileHash -Algorithm SHA256 -LiteralPath $Path |
    Select-Object Path, Hash |
    Format-Table -AutoSize
}

function Invoke-DesktopRpcProbe {
  param([Parameter(Mandatory = $true)][string]$ExecutablePath)

  if (-not (Test-Path -LiteralPath $ExecutablePath)) {
    Write-Info "Probe skipped because executable is missing: $ExecutablePath"
    return
  }

  Write-Info "Probe: $ExecutablePath desktop-rpc service.status '{}'"
  & $ExecutablePath 'desktop-rpc' 'service.status' '{}'
  Write-Info "Probe exit code: $LASTEXITCODE"
}

function Show-Status {
  Write-Info 'Helper service registration'
  Write-HelperServiceSnapshot (Get-HelperServiceSnapshot)
  Write-Info "Expected stable helper: $stableHelperExe"

  Write-Info 'Native CMake outputs'
  Show-FileHashIfPresent (Join-Path $cppBuildDir 'exv-ui.exe')
  Show-FileHashIfPresent (Join-Path $cppBuildDir 'exv.exe')
  Show-FileHashIfPresent (Join-Path $cppBuildDir 'exv-helper.exe')

  Write-Info 'WebView package outputs'
  Show-FileHashIfPresent $uiShellExe
  Show-FileHashIfPresent $exvExe
  Show-FileHashIfPresent $exvHelperExe

  Invoke-DesktopRpcProbe $exvExe
}

function Test-IsAdministrator {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-PrivilegedMaintenanceScript {
  param([switch]$PauseOnError)

  $maintenanceScript = Join-Path $scriptDir 'start-privileged-maintenance.ps1'
  if (-not (Test-Path -LiteralPath $maintenanceScript)) {
    throw "Privileged maintenance script is missing: $maintenanceScript"
  }

  $logRoot = Join-Path $repoRoot 'build\windows'
  New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
  $logPath = Join-Path $logRoot 'start-privileged-maintenance.log'
  if (Test-Path -LiteralPath $logPath) {
    Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue
  }

  $protectedCsv = (@(Get-ProtectedProcessIds) | ForEach-Object { [string]$_ }) -join ','
  $arguments = @(
    '-NoProfile', '-NoLogo', '-ExecutionPolicy', 'Bypass',
    '-File', $maintenanceScript,
    '-RepoRoot', $repoRoot,
    '-Port', [string]$Port,
    '-LogPath', $logPath,
    '-ProtectedProcessIds', $protectedCsv
  )
  if ($PauseOnError) {
    $arguments += '-PauseOnError'
  }

  if (Test-IsAdministrator) {
    Write-Info 'Running privileged maintenance child in the current elevated PowerShell context'
    & powershell.exe @arguments
    $exitCode = $LASTEXITCODE
  }
  else {
    Write-Info 'Requesting UAC only for privileged maintenance'
    Write-Info "Privileged maintenance log: $logPath"
    $argumentString = Join-LaunchArgsForStartProcess $arguments
    $startProcessParams = @{
      FilePath = 'powershell.exe'
      ArgumentList = $argumentString
      Verb = 'RunAs'
      Wait = $true
      PassThru = $true
    }
    if (-not $PauseOnError) {
      $startProcessParams.WindowStyle = 'Hidden'
    }
    $process = Start-Process @startProcessParams
    $exitCode = $process.ExitCode
  }

  if ($exitCode -ne 0) {
    if (Test-Path -LiteralPath $logPath) {
      Write-Info 'Privileged maintenance log tail:'
      Get-Content -LiteralPath $logPath -Tail 120
    }
    throw "Privileged maintenance failed with exit code $exitCode. See $logPath"
  }

  Write-Info "Privileged maintenance complete; log: $logPath"
}

function Build-WebViewPackage {
  Invoke-WindowsPackageDependencyBootstrap
  $resolvedWebView2Sdk = Resolve-WebView2Sdk $WebView2SdkDir

  if ($NoFrontendBuild) {
    Write-Info 'Building native UI shell and packaging existing WebView renderer assets'
    Invoke-Step -Command 'cmake' -Arguments @('--preset', 'windows-release', '-DEXV_BUILD_UI_SHELL=ON', "-DWEBVIEW2_SDK_DIR=$resolvedWebView2Sdk")
    Invoke-Step -Command 'cmake' -Arguments @(
      '--build', '--preset', 'windows-release',
      '--target', 'exv', 'exv-helper', 'exv-ui'
    )
    Invoke-Step -Command 'python' -Arguments @(
      (Join-Path $scriptDir 'package_ui_shell.py'),
      '--platform', 'windows'
    )
    return
  }

  Write-Info 'Running: scripts\build-windows.ps1 desktop'
  Invoke-Step -Command 'powershell' -Arguments @(
    '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $scriptDir 'build-windows.ps1'),
    'desktop',
    '-WebView2SdkDir', $resolvedWebView2Sdk
  )
}

function Test-WebViewPackage {
  $missing = @()
  foreach ($path in @($uiShellExe, $exvExe, $exvHelperExe, $launchArgsFile)) {
    if (-not (Test-Path -LiteralPath $path)) {
      $missing += $path
    }
  }
  if ($missing.Count -gt 0) {
    throw "WebView package is incomplete. Missing: $($missing -join ', ')"
  }

  Invoke-Step -Command 'python' -Arguments @(
    (Join-Path $scriptDir 'package_ui_shell.py'),
    '--verify-launch-targets-only',
    '--package-dir', $packageRoot
  )
}

function Set-LaunchEnvironment {
  param([Parameter(Mandatory = $true)][string]$CoreDirectory)

  $snapshot = [pscustomobject]@{
    ExvCorePath = $env:EXV_CORE_PATH
    Path = $env:PATH
  }

  $env:EXV_CORE_PATH = $CoreDirectory
  if ([string]::IsNullOrWhiteSpace($env:PATH)) {
    $env:PATH = $CoreDirectory
  }
  elseif ($env:PATH -notlike "*$CoreDirectory*") {
    $env:PATH = "$CoreDirectory;$env:PATH"
  }

  Write-Info "Launch environment: EXV_CORE_PATH=$env:EXV_CORE_PATH"
  return $snapshot
}

function Restore-LaunchEnvironment {
  param($Snapshot)

  if (-not $Snapshot) {
    return
  }

  $env:EXV_CORE_PATH = $Snapshot.ExvCorePath
  $env:PATH = $Snapshot.Path
}

function Resolve-LaunchArgPath {
  param([Parameter(Mandatory = $true)][string]$value)

  if ([System.IO.Path]::IsPathRooted($value)) {
    return $value
  }

  return (Join-Path $packageRoot $value)
}

function Resolve-LaunchArgs {
  param([Parameter(Mandatory = $true)][string[]]$Tokens)

  $resolved = @()
  for ($i = 0; $i -lt $Tokens.Count; $i++) {
    $token = $Tokens[$i]
    $resolved += $token
    if (($token -eq '--exv' -or $token -eq '--renderer-index') -and $i + 1 -lt $Tokens.Count) {
      $i++
      $resolved += (Resolve-LaunchArgPath $Tokens[$i])
    }
  }

  return @($resolved)
}

function ConvertTo-WindowsProcessArgument {
  param([AllowEmptyString()][string]$Value)

  if ($null -eq $Value) {
    return '""'
  }

  if ($Value -notmatch '[\s"]') {
    return $Value
  }

  $escaped = $Value -replace '\\(?=($|"))', '\\' -replace '"', '\"'
  return '"' + $escaped + '"'
}

function Join-LaunchArgsForStartProcess {
  param([Parameter(Mandatory = $true)][string[]]$Tokens)

  return (($Tokens | ForEach-Object { ConvertTo-WindowsProcessArgument $_ }) -join ' ')
}

function Read-LaunchArgs {
  if (-not (Test-Path -LiteralPath $launchArgsFile)) {
    throw "Launch argument file is missing: $launchArgsFile"
  }

  $tokens = @(Get-Content -LiteralPath $launchArgsFile |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  return @(Resolve-LaunchArgs $tokens)
}

function Start-WebViewShellDirect {
  Test-WebViewPackage

  if (Test-Path -LiteralPath $desktopOutLog) { Remove-Item -LiteralPath $desktopOutLog -Force -ErrorAction SilentlyContinue }
  if (Test-Path -LiteralPath $desktopErrLog) { Remove-Item -LiteralPath $desktopErrLog -Force -ErrorAction SilentlyContinue }

  $launchArgs = @(Read-LaunchArgs)
  $launchArgumentList = Join-LaunchArgsForStartProcess $launchArgs
  $launchEnvironment = Set-LaunchEnvironment -CoreDirectory (Split-Path -Parent $exvExe)
  Write-Info "Launching native WebView shell: $uiShellExe"
  try {
    $process = Start-Process -FilePath $uiShellExe `
      -ArgumentList $launchArgumentList `
      -WorkingDirectory $packageRoot `
      -RedirectStandardOutput $desktopOutLog `
      -RedirectStandardError $desktopErrLog `
      -PassThru
  }
  finally {
    Restore-LaunchEnvironment $launchEnvironment
  }

  Start-Sleep -Seconds 2
  if ($process.HasExited) {
    if (Test-Path -LiteralPath $desktopOutLog) {
      Get-Content -LiteralPath $desktopOutLog -Tail 120
    }
    if (Test-Path -LiteralPath $desktopErrLog) {
      Get-Content -LiteralPath $desktopErrLog -Tail 120
    }
    throw "Native WebView shell exited early with code $($process.ExitCode)"
  }

  Write-Info "Native WebView shell PID: $($process.Id)"
  Write-Info "Logs: $desktopOutLog and $desktopErrLog"
}

function Invoke-PrivilegedWebViewShellScript {
  param([switch]$PauseOnError)

  $launcherScript = Join-Path $scriptDir 'start-privileged-webview-shell.ps1'
  if (-not (Test-Path -LiteralPath $launcherScript)) {
    throw "Privileged WebView shell launcher is missing: $launcherScript"
  }

  $logRoot = Join-Path $repoRoot 'build\windows'
  New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
  $logPath = Join-Path $logRoot 'start-privileged-webview-shell.log'
  if (Test-Path -LiteralPath $logPath) {
    Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue
  }

  $arguments = @(
    '-NoProfile', '-NoLogo', '-ExecutionPolicy', 'Bypass',
    '-File', $launcherScript,
    '-RepoRoot', $repoRoot,
    '-Port', [string]$Port,
    '-WebView2SdkDir', $WebView2SdkDir,
    '-LogPath', $logPath
  )
  if ($PauseOnError) {
    $arguments += '-PauseOnError'
  }

  if (Test-IsAdministrator) {
    Write-Info 'Launching WebView shell in the current elevated PowerShell context'
    & powershell.exe @arguments
    $exitCode = $LASTEXITCODE
  }
  else {
    Write-Info 'Requesting UAC for native WebView shell launch'
    Write-Info "WebView shell launch log: $logPath"
    $argumentString = Join-LaunchArgsForStartProcess $arguments
    $startProcessParams = @{
      FilePath = 'powershell.exe'
      ArgumentList = $argumentString
      Verb = 'RunAs'
      Wait = $true
      PassThru = $true
    }
    if (-not $PauseOnError) {
      $startProcessParams.WindowStyle = 'Hidden'
    }
    $process = Start-Process @startProcessParams
    $exitCode = $process.ExitCode
  }

  if ($exitCode -ne 0) {
    if (Test-Path -LiteralPath $logPath) {
      Write-Info 'WebView shell launch log tail:'
      Get-Content -LiteralPath $logPath -Tail 120
    }
    throw "Privileged WebView shell launch failed with exit code $exitCode. See $logPath"
  }

  Write-Info "WebView shell launch complete; log: $logPath"
}

function Start-WebViewShell {
  param([switch]$PauseOnError)
  Invoke-PrivilegedWebViewShellScript -PauseOnError:$PauseOnError
}

param(
  [string]$WebView2SdkDir = $env:WEBVIEW2_SDK_DIR
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$logDir = Join-Path $repoRoot 'build\webview-acceptance\windows'
New-Item -ItemType Directory -Force $logDir | Out-Null

function Resolve-WebView2Sdk {
  param([string]$ConfiguredPath)

  if ($ConfiguredPath -and (Test-Path -LiteralPath $ConfiguredPath)) {
    return (Resolve-Path -LiteralPath $ConfiguredPath).Path
  }

  $candidate = Join-Path $repoRoot 'build\deps\webview2\1.0.4022.49'
  if (Test-Path -LiteralPath $candidate) {
    return (Resolve-Path -LiteralPath $candidate).Path
  }

  throw 'WEBVIEW2_SDK_DIR is required, or build\deps\webview2\1.0.4022.49 must exist.'
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

  & powershell.exe @arguments
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed: powershell.exe $($arguments -join ' ')"
  }
}

function Invoke-Logged {
  param(
    [Parameter(Mandatory = $true)]
    [string]$LogName,
    [Parameter(Mandatory = $true)]
    [scriptblock]$Command
  )

  $logPath = Join-Path $logDir $LogName
  $previousErrorActionPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    & $Command 2>&1 | Tee-Object $logPath
    $exitCode = $LASTEXITCODE
  }
  finally {
    $ErrorActionPreference = $previousErrorActionPreference
  }

  if ($exitCode -ne 0) {
    throw "Command failed with exit $exitCode. See $logPath"
  }
}

Push-Location $repoRoot
try {
  Invoke-Logged 'dependencies.log' { Invoke-WindowsPackageDependencyBootstrap }
  $resolvedWebView2Sdk = Resolve-WebView2Sdk $WebView2SdkDir

  Invoke-Logged 'contracts.log' { python scripts\generate_contracts.py --check }
  Invoke-Logged 'configure.log' {
    cmake --preset windows-release -DEXV_BUILD_UI_SHELL=ON -DWEBVIEW2_SDK_DIR="$resolvedWebView2Sdk"
  }
  Invoke-Logged 'build.log' { cmake --build build-windows\cpp --config Release }
  Invoke-Logged 'ctest.log' {
    ctest --test-dir build-windows\cpp -C Release --output-on-failure
  }
  Invoke-Logged 'package.log' {
    powershell -ExecutionPolicy Bypass -File scripts\build-windows.ps1 desktop
  }
  Invoke-Logged 'smoke.log' {
    powershell -ExecutionPolicy Bypass -File scripts\windows-packaging-smoke.ps1
  }
  Invoke-Logged 'diff-check.log' { git diff --check }
}
finally {
  Pop-Location
}

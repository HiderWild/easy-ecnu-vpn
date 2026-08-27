param(
  [ValidateSet('cpp', 'test', 'webview', 'desktop', 'all', 'clean')]
  [string]$Action = 'all',
  [string]$WebView2SdkDir = $env:WEBVIEW2_SDK_DIR
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$buildRoot = Join-Path $repoRoot 'build\windows'
$cppBuildRoot = Join-Path $repoRoot 'build-windows'
$env:EXV_BUILD_PLATFORM = 'windows'
$env:EXV_WEBUI_DIST_DIR = Join-Path $buildRoot 'webview\dist'

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

function Invoke-WindowsPackageDependencyBootstrap {
  $bootstrapScript = Join-Path $repoRoot 'scripts\bootstrap-windows-package-deps.ps1'
  if (-not (Test-Path -LiteralPath $bootstrapScript -PathType Leaf)) {
    throw "Windows package dependency bootstrap script not found: $bootstrapScript"
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

  Invoke-Step powershell.exe @arguments
}

function Invoke-Step {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
  )

  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed: $FilePath $($Arguments -join ' ')"
  }
}

function Invoke-CppBuild {
  param(
    [switch]$UiShell
  )

  Push-Location $repoRoot
  try {
    if ($UiShell) {
      Invoke-WindowsPackageDependencyBootstrap
      $resolvedWebView2Sdk = Resolve-WebView2Sdk $WebView2SdkDir
      Invoke-Step cmake --preset windows-release -DEXV_BUILD_UI_SHELL=ON "-DWEBVIEW2_SDK_DIR=$resolvedWebView2Sdk"
    }
    else {
      Invoke-Step cmake --preset windows-release
    }
    Invoke-Step cmake --build --preset windows-release --target exv exv-helper exv-ui platform_status_models_test backend_resolver_test native_packaging_policy_test ui_shell_contract_test ui_shell_core_rpc_client_test ui_shell_cmake_policy_test win32_webview2_runtime_test
  }
  finally {
    Pop-Location
  }
}

function Invoke-CppTests {
  Push-Location $repoRoot
  try {
    Invoke-Step ctest --preset windows-release -R 'platform_status_models_test|backend_resolver_test|native_packaging_policy_test|ui_shell_contract_test|ui_shell_core_rpc_client_test|ui_shell_cmake_policy_test|win32_webview2_runtime_test'
  }
  finally {
    Pop-Location
  }
}

function Invoke-WebuiRendererBuild {
  Push-Location (Join-Path $repoRoot 'webui')
  try {
    Invoke-Step pnpm run webview:compile
  }
  finally {
    Pop-Location
  }
}

function Invoke-WebViewPackage {
  Push-Location (Join-Path $repoRoot 'webui')
  try {
    Invoke-Step pnpm run webview:package
  }
  finally {
    Pop-Location
  }
}

switch ($Action) {
  'cpp' {
    Invoke-CppBuild
  }
  'test' {
    Invoke-CppTests
  }
  'webview' {
    Invoke-WebuiRendererBuild
    Invoke-CppBuild -UiShell
    Invoke-CppTests
    Invoke-WebViewPackage
  }
  'desktop' {
    Invoke-WebuiRendererBuild
    Invoke-CppBuild -UiShell
    Invoke-CppTests
    Invoke-WebViewPackage
  }
  'all' {
    Invoke-WebuiRendererBuild
    Invoke-CppBuild -UiShell
    Invoke-CppTests
    Invoke-WebViewPackage
  }
  'clean' {
    Write-Output '[build-windows] Removing build and compilation artifacts only (package caches preserved)'
    if (Test-Path $buildRoot) {
      Remove-Item -Recurse -Force $buildRoot
    }
    if (Test-Path $cppBuildRoot) {
      Remove-Item -Recurse -Force $cppBuildRoot
    }
    Write-Output '[build-windows] Preserved: webui/node_modules, build/codex-corepack, build/deps'
  }
}

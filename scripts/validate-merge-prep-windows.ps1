param(
  [switch]$SkipDesktop,
  [switch]$DesktopSmoke
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

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

Push-Location $repoRoot
try {
  Write-Host '[merge-prep] Build frontend assets for native embedding...'
  Push-Location (Join-Path $repoRoot 'webui')
  try {
    Invoke-Step pnpm run build
  }
  finally {
    Pop-Location
  }

  Write-Host '[merge-prep] Configure and build native targets...'
  Invoke-Step cmake --preset windows-release
  Invoke-Step cmake --build --preset windows-release --target exv exv-helper exv_release_blocking_tests

  Write-Host '[merge-prep] Run release-blocking native regression tests...'
  Invoke-Step ctest --preset windows-release -L release-blocking --output-on-failure
}
finally {
  Pop-Location
}

if (-not $SkipDesktop) {
  Write-Host '[merge-prep] Build native WebView desktop package...'
  Invoke-Step powershell -ExecutionPolicy Bypass -File (Join-Path $scriptDir 'build-windows.ps1') 'desktop'
}

if ($DesktopSmoke) {
  Write-Host '[merge-prep] Run native WebView package smoke checks...'
  Invoke-Step powershell -ExecutionPolicy Bypass -File (Join-Path $scriptDir 'windows-packaging-smoke.ps1')
}

Write-Host '[merge-prep] Windows validation complete.'

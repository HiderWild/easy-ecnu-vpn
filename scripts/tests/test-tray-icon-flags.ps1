$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$traySource = Join-Path $repoRoot 'src\platform\win32\rust\tauri\app\src\tray.rs'
$source = Get-Content -LiteralPath $traySource -Raw

if ($source -notmatch 'NIF_ICON') {
  throw 'Tray implementation does not import NIF_ICON.'
}

if ($source -notmatch "uFlags:\s*NIF_MESSAGE\s*\|\s*NIF_ICON") {
  throw 'NIM_ADD does not declare both NIF_MESSAGE and NIF_ICON.'
}

Write-Host 'PASS tray NIM_ADD declares NIF_ICON'

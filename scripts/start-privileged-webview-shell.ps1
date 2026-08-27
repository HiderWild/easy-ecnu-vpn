param(
  [Parameter(Mandatory = $true)][string]$RepoRoot,
  [int]$Port = 8288,
  [string]$WebView2SdkDir = $env:WEBVIEW2_SDK_DIR,
  [string]$LogPath = '',
  [switch]$PauseOnError
)

$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath($RepoRoot)
$scriptDir = Join-Path $repoRoot 'scripts'
. (Join-Path $scriptDir 'start-common.ps1') -RepoRoot $repoRoot -Port $Port -WebView2SdkDir $WebView2SdkDir

$transcriptStarted = $false
try {
  if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
    $logDir = Split-Path -Parent $LogPath
    if (-not [string]::IsNullOrWhiteSpace($logDir)) {
      New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    }
    Start-Transcript -Path $LogPath -Force | Out-Null
    $transcriptStarted = $true
  }

  Start-WebViewShellDirect
  Write-Info 'WebView shell launcher finished'
  exit 0
}
catch {
  Write-Error $_
  if ($PauseOnError) {
    Read-Host 'Press Enter to close this WebView shell launcher window'
  }
  exit 1
}
finally {
  if ($transcriptStarted) {
    Stop-Transcript | Out-Null
  }
}

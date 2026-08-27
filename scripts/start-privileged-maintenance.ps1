param(
  [Parameter(Mandatory = $true)][string]$RepoRoot,
  [int]$Port = 8288,
  [string]$LogPath = '',
  [string]$ProtectedProcessIds = '',
  [switch]$PauseOnError
)

$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath($RepoRoot)
$scriptDir = Join-Path $repoRoot 'scripts'
. (Join-Path $scriptDir 'start-common.ps1') -RepoRoot $repoRoot -Port $Port

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

  $ids = @()
  if (-not [string]::IsNullOrWhiteSpace($ProtectedProcessIds)) {
    $ids += $ProtectedProcessIds.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries) |
      ForEach-Object { [int]$_.Trim() }
  }
  $ids += Get-CurrentProcessAncestorIds
  Set-ProtectedProcessIds $ids

  Write-Info "Privileged maintenance protecting PIDs: $(@(Get-ProtectedProcessIds) -join ', ')"
  Write-Info "Privileged maintenance self protected: $(Test-IsProtectedProcessId -ProcessId $PID)"
  Stop-ProjectProcesses
  Invoke-HelperServicePrepackageCleanup
  Write-Info 'Privileged maintenance finished'
  exit 0
}
catch {
  Write-Error $_
  if ($PauseOnError) {
    Read-Host 'Press Enter to close this privileged maintenance window'
  }
  exit 1
}
finally {
  if ($transcriptStarted) {
    Stop-Transcript | Out-Null
  }
}

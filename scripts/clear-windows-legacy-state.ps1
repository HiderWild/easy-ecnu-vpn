[CmdletBinding()]
param(
  [string]$CurrentInstallDir = "",
  [string]$LocalAppDataRoot = "",
  [string]$ProgramDataRoot = "",
  [string]$ProgramFilesRoot = "",
  [string]$ProgramFilesX86Root = "",
  [switch]$AllowWebView2UserDataRemoval
)

$ErrorActionPreference = 'Stop'
$WebView2MigrationMarkerFile = 'exv-profile-webview2-migrated.marker'

function Normalize-FullPath {
  param([Parameter(Mandatory = $true)][string]$Path)

  return [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
}

function Test-SamePath {
  param(
    [string]$Left,
    [string]$Right
  )

  if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) {
    return $false
  }

  return (Normalize-FullPath $Left).Equals(
    (Normalize-FullPath $Right),
    [System.StringComparison]::OrdinalIgnoreCase
  )
}

function Test-PathWithinRoot {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Root
  )

  $normalizedPath = Normalize-FullPath $Path
  $normalizedRoot = Normalize-FullPath $Root
  if ($normalizedPath.Equals($normalizedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    return $true
  }

  return $normalizedPath.StartsWith(
    $normalizedRoot + '\',
    [System.StringComparison]::OrdinalIgnoreCase
  )
}

function Assert-PathWithinAnyRoot {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string[]]$AllowedRoots = @()
  )

  foreach ($root in $AllowedRoots) {
    if ([string]::IsNullOrWhiteSpace($root)) {
      continue
    }
    if (Test-PathWithinRoot -Path $Path -Root $root) {
      return
    }
  }

  throw "Refusing to remove path outside allowed roots: $Path"
}

function Remove-FileIfExists {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string[]]$AllowedRoots = @()
  )

  Assert-PathWithinAnyRoot -Path $Path -AllowedRoots $AllowedRoots
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    return
  }

  Remove-Item -LiteralPath $Path -Force
  Write-Host "Removed file: $Path"
}

function Remove-DirectoryTreeIfExists {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string[]]$AllowedRoots = @()
  )

  Assert-PathWithinAnyRoot -Path $Path -AllowedRoots $AllowedRoots
  if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    return
  }

  Remove-Item -LiteralPath $Path -Recurse -Force
  Write-Host "Removed directory tree: $Path"
}

function Test-LegacyWebView2UserDataSafeToRemove {
  param([Parameter(Mandatory = $true)][string]$Path)

  if ($AllowWebView2UserDataRemoval) {
    return $true
  }

  $marker = Join-Path $Path $WebView2MigrationMarkerFile
  return (Test-Path -LiteralPath $marker -PathType Leaf)
}

function Remove-LegacyWebView2UserDataIfSafe {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string[]]$AllowedRoots = @()
  )

  Assert-PathWithinAnyRoot -Path $Path -AllowedRoots $AllowedRoots
  if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    return
  }
  if (-not (Test-LegacyWebView2UserDataSafeToRemove -Path $Path)) {
    Write-Host "Skip removing legacy WebView2 user data without migration marker: $Path"
    return
  }

  Remove-DirectoryTreeIfExists -Path $Path -AllowedRoots $AllowedRoots
}

function Remove-DirectoryIfEmpty {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string[]]$AllowedRoots = @()
  )

  Assert-PathWithinAnyRoot -Path $Path -AllowedRoots $AllowedRoots
  if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    return
  }

  $child = Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if ($null -ne $child) {
    return
  }

  Remove-Item -LiteralPath $Path -Force
  Write-Host "Removed empty directory: $Path"
}

function Add-UniquePath {
  param(
    [Parameter(Mandatory = $true)][ref]$Paths,
    [string]$Path
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    return
  }

  $normalized = Normalize-FullPath $Path
  foreach ($existing in $Paths.Value) {
    if (Test-SamePath -Left $existing -Right $normalized) {
      return
    }
  }
  $Paths.Value += $normalized
}

$localAppData = if ($LocalAppDataRoot) {
  $LocalAppDataRoot
} elseif ($env:LOCALAPPDATA) {
  $env:LOCALAPPDATA
} elseif ($env:USERPROFILE) {
  Join-Path $env:USERPROFILE 'AppData\Local'
} else {
  ''
}

$programData = if ($ProgramDataRoot) {
  $ProgramDataRoot
} elseif ($env:ProgramData) {
  $env:ProgramData
} else {
  'C:\ProgramData'
}

$programFiles = if ($ProgramFilesRoot) {
  $ProgramFilesRoot
} elseif ($env:ProgramFiles) {
  $env:ProgramFiles
} else {
  ''
}

$programFilesX86 = if ($ProgramFilesX86Root) {
  $ProgramFilesX86Root
} elseif (${env:ProgramFiles(x86)}) {
  ${env:ProgramFiles(x86)}
} else {
  ''
}

$currentInstall = if ($CurrentInstallDir) {
  Normalize-FullPath $CurrentInstallDir
} else {
  ''
}

$legacyRootParents = @()
if ($localAppData) {
  Add-UniquePath -Paths ([ref]$legacyRootParents) -Path (Join-Path $localAppData 'Programs')
}
if ($programFiles) {
  Add-UniquePath -Paths ([ref]$legacyRootParents) -Path $programFiles
}
if ($programFilesX86) {
  Add-UniquePath -Paths ([ref]$legacyRootParents) -Path $programFilesX86
}

$legacyInstallRoots = @()
if ($localAppData) {
  Add-UniquePath -Paths ([ref]$legacyInstallRoots) -Path (Join-Path $localAppData 'Programs\ECNU VPN')
  Add-UniquePath -Paths ([ref]$legacyInstallRoots) -Path (Join-Path $localAppData 'Programs\ECNU-VPN')
}
foreach ($base in @($programFiles, $programFilesX86)) {
  if ([string]::IsNullOrWhiteSpace($base)) {
    continue
  }
  foreach ($name in @('EXV', 'ECNU VPN', 'ECNU-VPN')) {
    Add-UniquePath -Paths ([ref]$legacyInstallRoots) -Path (Join-Path $base $name)
  }
}

if ($currentInstall) {
  Remove-LegacyWebView2UserDataIfSafe `
    -Path (Join-Path $currentInstall 'exv-ui.exe.WebView2') `
    -AllowedRoots @($currentInstall)
}

foreach ($legacyInstallRoot in $legacyInstallRoots) {
  $legacyWebView2Dir = Join-Path $legacyInstallRoot 'exv-ui.exe.WebView2'
  Remove-LegacyWebView2UserDataIfSafe `
    -Path $legacyWebView2Dir `
    -AllowedRoots @($legacyInstallRoot)

  if ($currentInstall -and (Test-SamePath -Left $legacyInstallRoot -Right $currentInstall)) {
    Write-Host "Skip removing current install root: $legacyInstallRoot"
    continue
  }
  if (Test-Path -LiteralPath $legacyWebView2Dir -PathType Container) {
    Write-Host "Skip removing legacy install root because WebView2 user data is preserved: $legacyInstallRoot"
    continue
  }

  Remove-DirectoryTreeIfExists `
    -Path $legacyInstallRoot `
    -AllowedRoots $legacyRootParents
}

$helperRoots = @()
if ($localAppData) {
  Add-UniquePath -Paths ([ref]$helperRoots) -Path (Join-Path $localAppData 'EXV\Helper')
}
Add-UniquePath -Paths ([ref]$helperRoots) -Path (Join-Path $programData 'EXV\Helper')

foreach ($helperRoot in $helperRoots) {
  $helperParent = Split-Path -Parent $helperRoot
  Remove-DirectoryTreeIfExists -Path $helperRoot -AllowedRoots @($helperParent)
  Remove-DirectoryIfEmpty -Path $helperParent -AllowedRoots @($localAppData, $programData)
}

Remove-FileIfExists `
  -Path (Join-Path $programData 'exv-helper-session.json') `
  -AllowedRoots @($programData)

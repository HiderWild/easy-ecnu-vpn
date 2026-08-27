[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [switch]$Force,
  [switch]$IncludeCredentialManager,
  [string]$LocalAppDataRoot = ""
)

$ErrorActionPreference = 'Stop'

function Zh {
  param([Parameter(Mandatory = $true)][string]$Base64)
  return [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String($Base64))
}

function Get-UserProfileRoot {
  if ($env:USERPROFILE) {
    return $env:USERPROFILE
  }
  if ($env:HOMEDRIVE -and $env:HOMEPATH) {
    return "$($env:HOMEDRIVE)$($env:HOMEPATH)"
  }
  return ""
}

function Get-LocalAppDataRoot {
  if ($LocalAppDataRoot) {
    return $LocalAppDataRoot
  }
  if ($env:LOCALAPPDATA) {
    return $env:LOCALAPPDATA
  }
  $userProfile = Get-UserProfileRoot
  if ($userProfile) {
    return Join-Path $userProfile 'AppData\Local'
  }
  throw (Zh '5pyq6K6+572uIExPQ0FMQVBQREFUQSDlkowgVVNFUlBST0ZJTEXvvIzml6Dms5XlrprkvY0gRVhWIOeUqOaIt+mFjee9ruebruW9leOAgg==')
}

function Get-FullPath {
  param([Parameter(Mandatory = $true)][string]$Path)
  return [System.IO.Path]::GetFullPath($Path)
}

function Normalize-FullPath {
  param([Parameter(Mandatory = $true)][string]$Path)
  return (Get-FullPath $Path).TrimEnd('\', '/')
}

function Test-PathWithinRoot {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Root
  )

  $rootFull = Normalize-FullPath $Root
  $pathFull = Normalize-FullPath $Path
  if ($pathFull.Equals($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
    return $true
  }
  return $pathFull.StartsWith($rootFull + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-PathUnderRoot {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Root
  )

  if (-not (Test-PathWithinRoot -Path $Path -Root $Root)) {
    throw ((Zh '5ouS57ud5Yig6ZmkIEVYViDmnKzlnLDnlKjmiLfmlbDmja7moLnnm67lvZXkuYvlpJbnmoTot6/lvoTvvJo=') + (Get-FullPath $Path))
  }
}

function Assert-ConfigDirSafeForCleanup {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string[]]$AllowedRoots = @()
  )

  $pathFull = Normalize-FullPath $Path
  $driveRoot = [System.IO.Path]::GetPathRoot($pathFull)
  if ([string]::IsNullOrWhiteSpace($driveRoot)) {
    throw "Redirected config dir has no drive root: $Path"
  }

  $normalizedDriveRoot = $driveRoot.TrimEnd('\', '/')
  if ($pathFull.Equals($normalizedDriveRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Redirected config dir cannot be a drive root: $Path"
  }

  foreach ($allowedRoot in $AllowedRoots) {
    if ([string]::IsNullOrWhiteSpace($allowedRoot)) {
      continue
    }

    if (Test-PathWithinRoot -Path $pathFull -Root $allowedRoot) {
      $allowedFull = Normalize-FullPath $allowedRoot
      if ($pathFull.Equals($allowedFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Redirected config dir cannot equal a broad user root: $Path"
      }
      return
    }
  }

  throw "Redirected config dir is outside supported user-scoped roots: $Path"
}

function New-CleanupEntry {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Root
  )

  return [PSCustomObject]@{
    Path = $Path
    Root = $Root
  }
}

function Remove-ConfigTarget {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Root
  )

  Assert-PathUnderRoot -Path $Path -Root $Root
  if (-not (Test-Path -LiteralPath $Path)) {
    Write-Host ((Zh '5pyq5om+5Yiw77ya') + $Path)
    return
  }

  if ($PSCmdlet.ShouldProcess($Path, (Zh '5Yig6ZmkIEVYViDmnKzlnLDnlKjmiLfphY3nva7mlofku7Y='))) {
    Remove-Item -LiteralPath $Path -Force
    Write-Host ((Zh '5bey5Yig6Zmk77ya') + $Path)
  }
}

function Remove-ConfigTree {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Root
  )

  Assert-PathUnderRoot -Path $Path -Root $Root
  if (-not (Test-Path -LiteralPath $Path)) {
    Write-Host ((Zh '5pyq5om+5Yiw77ya') + $Path)
    return
  }

  if ($PSCmdlet.ShouldProcess($Path, (Zh '5Yig6ZmkIEVYViDmnKzlnLDnlKjmiLfphY3nva7nm67lvZU='))) {
    Remove-Item -LiteralPath $Path -Recurse -Force
    Write-Host ((Zh '5bey5Yig6Zmk77ya') + $Path)
  }
}

function Remove-ConfigPath {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Root
  )

  Assert-PathUnderRoot -Path $Path -Root $Root
  if (-not (Test-Path -LiteralPath $Path)) {
    Write-Host ((Zh '5pyq5om+5Yiw77ya') + $Path)
    return
  }

  $item = Get-Item -LiteralPath $Path -Force
  if ($item.PSIsContainer) {
    Remove-ConfigTree -Path $Path -Root $Root
    return
  }

  Remove-ConfigTarget -Path $Path -Root $Root
}

function Remove-EmptyDirectoryIfExists {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Root
  )

  Assert-PathUnderRoot -Path $Path -Root $Root
  if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    return
  }

  $child = Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if ($null -ne $child) {
    return
  }

  if ($PSCmdlet.ShouldProcess($Path, 'Remove empty EXV config directory')) {
    Remove-Item -LiteralPath $Path -Force
    Write-Host ((Zh '5bey5Yig6Zmk77ya') + $Path)
  }
}

function Get-RedirectedConfigDir {
  param(
    [Parameter(Mandatory = $true)][string]$RedirectPath,
    [Parameter(Mandatory = $true)][string]$UserProfile
  )

  if (-not (Test-Path -LiteralPath $RedirectPath)) {
    return ""
  }

  $content = (Get-Content -LiteralPath $RedirectPath -ErrorAction Stop | Select-Object -First 1)
  $dir = ''
  if ($null -ne $content) {
    $dir = $content.Trim()
  }
  if (-not $dir) {
    return ""
  }
  if ($dir.StartsWith('~') -and $UserProfile) {
    return Join-Path $UserProfile $dir.Substring(1)
  }
  return $dir
}

function Add-ConfigCleanupTargets {
  param(
    [Parameter(Mandatory = $true)][ref]$PathTargets,
    [Parameter(Mandatory = $true)][ref]$TreeTargets,
    [Parameter(Mandatory = $true)][ref]$EmptyDirTargets,
    [Parameter(Mandatory = $true)][string]$ConfigDir,
    [Parameter(Mandatory = $true)][string]$Root
  )

  $profileWebView2Dir = Join-Path $ConfigDir 'WebView2'
  $PathTargets.Value += @(
    (New-CleanupEntry -Path (Join-Path $ConfigDir 'config.json') -Root $Root),
    (New-CleanupEntry -Path (Join-Path $ConfigDir '.key') -Root $Root),
    (New-CleanupEntry -Path (Join-Path $ConfigDir 'close-preference.json') -Root $Root),
    (New-CleanupEntry -Path (Join-Path $ConfigDir 'exv.log') -Root $Root),
    (New-CleanupEntry -Path (Join-Path $ConfigDir 'exv-core-ipc-v1.registry.json') -Root $Root),
    (New-CleanupEntry -Path (Join-Path $ConfigDir 'exv-core-ipc-v1.lock') -Root $Root),
    (New-CleanupEntry -Path (Join-Path $ConfigDir 'exv-core-ipc-v1.sock') -Root $Root),
    (New-CleanupEntry -Path (Join-Path $ConfigDir 'connect-attempt.json') -Root $Root),
    (New-CleanupEntry -Path (Join-Path $ConfigDir 'connect-attempt.mutex') -Root $Root)
  )
  $TreeTargets.Value += @(
    (New-CleanupEntry -Path (Join-Path $ConfigDir 'connect-attempt.lock') -Root $Root),
    (New-CleanupEntry -Path (Join-Path $profileWebView2Dir 'Default\Local Storage') -Root $Root),
    (New-CleanupEntry -Path (Join-Path $profileWebView2Dir 'EBWebView\Default\Local Storage') -Root $Root),
    (New-CleanupEntry -Path $profileWebView2Dir -Root $Root)
  )
  $EmptyDirTargets.Value += (New-CleanupEntry -Path $ConfigDir -Root $Root)
}

function Remove-CleanupEntries {
  param(
    [Parameter(Mandatory = $true)]$Entries,
    [switch]$Tree,
    [switch]$EmptyDirectory
  )

  $seen = @{}
  foreach ($entry in $Entries) {
    if ($null -eq $entry) {
      continue
    }

    $pathKey = Normalize-FullPath $entry.Path
    $rootKey = Normalize-FullPath $entry.Root
    $dedupeKey = "$rootKey|$pathKey"
    if ($seen.ContainsKey($dedupeKey)) {
      continue
    }
    $seen[$dedupeKey] = $true

    if ($EmptyDirectory) {
      Remove-EmptyDirectoryIfExists -Path $entry.Path -Root $entry.Root
      continue
    }
    if ($Tree) {
      Remove-ConfigTree -Path $entry.Path -Root $entry.Root
      continue
    }
    Remove-ConfigPath -Path $entry.Path -Root $entry.Root
  }
}

function Remove-ExvCredentialManagerEntries {
  if (-not $IncludeCredentialManager) {
    return
  }

  $cmdkey = Get-Command cmdkey.exe -ErrorAction SilentlyContinue
  if (-not $cmdkey) {
    Write-Warning (Zh '5pyq5om+5YiwIGNtZGtleS5leGXvvJvlt7Lot7Pov4cgV2luZG93cyDlh63mja7nrqHnkIblmajmuIXnkIbjgII=')
    return
  }

  $listed = & $cmdkey.Path /list 2>$null
  $targets = @()
  foreach ($line in $listed) {
    if ($line -match '^\s*Target:\s*(.+)\s*$') {
      $target = $Matches[1].Trim()
      if ($target -match 'target=(.+)$') {
        $target = $Matches[1].Trim()
      }
      if ($target -like 'EXV/*') {
        $targets += $target
      }
    }
  }

  foreach ($target in ($targets | Sort-Object -Unique)) {
    if ($PSCmdlet.ShouldProcess($target, (Zh '5Yig6ZmkIEVYViBXaW5kb3dzIOWHreaNrueuoeeQhuWZqOadoeebrg=='))) {
      & $cmdkey.Path "/delete:$target" | Out-Null
      Write-Host ((Zh '5bey5Yig6Zmk5Yet5o2u77ya') + $target)
    }
  }
}

function Stop-ExvUserProcesses {
  if ($PSCmdlet.ShouldProcess('exv-ui', (Zh '5YGc5q2iIEVYViBVSSDov5vnqIs='))) {
    Stop-Process -Name exv-ui -Force -ErrorAction SilentlyContinue
  }
  if ($PSCmdlet.ShouldProcess('exv', (Zh '5YGc5q2iIEVYViBjb3JlIOi/m+eoiw=='))) {
    Stop-Process -Name exv -Force -ErrorAction SilentlyContinue
  }
}

function Quote-CommandArgument {
  param([Parameter(Mandatory = $true)][string]$Value)
  return '"' + $Value.Replace('"', '`"') + '"'
}

function Get-ForceCommandText {
  $parts = @(
    'powershell.exe',
    '-NoProfile',
    '-ExecutionPolicy Bypass',
    '-File',
    (Quote-CommandArgument $PSCommandPath),
    '-Force'
  )
  if ($LocalAppDataRoot) {
    $parts += '-LocalAppDataRoot'
    $parts += Quote-CommandArgument $LocalAppDataRoot
  }
  if ($IncludeCredentialManager) {
    $parts += '-IncludeCredentialManager'
  }
  return ($parts -join ' ')
}

if (-not $Force -and -not $WhatIfPreference) {
  $WhatIfPreference = $true
  Write-Host (Zh '5b2T5YmN5LuF6aKE5ryU77yM5LiN5Lya5Yig6Zmk5paH5Lu244CC56Gu6K6k5YiX6KGo5peg6K+v5ZCO77yM5L2/55SoIC1Gb3JjZSDmiafooYzmuIXnkIbjgII=')
  Write-Host ((Zh '5Y+v5aSN5Yi25ZG95Luk77ya') + (Get-ForceCommandText))
}

Stop-ExvUserProcesses

$localAppData = Get-LocalAppDataRoot
$userProfile = Get-UserProfileRoot
$appRoot = Join-Path $localAppData 'EXV'
$profileRoot = Join-Path $appRoot 'profile'
$profileDir = Join-Path $profileRoot 'default'
$redirectPath = Join-Path $appRoot 'profile.redirect'
$programsRoot = Join-Path $localAppData 'Programs\EXV'
$appWebView2Dir = Join-Path $programsRoot 'exv-ui.exe.WebView2'

$pathTargets = @()
$treeTargets = @()
$emptyDirTargets = @()

Add-ConfigCleanupTargets -PathTargets ([ref]$pathTargets) `
  -TreeTargets ([ref]$treeTargets) `
  -EmptyDirTargets ([ref]$emptyDirTargets) `
  -ConfigDir $profileDir `
  -Root $appRoot

$pathTargets += (New-CleanupEntry -Path $redirectPath -Root $appRoot)
$treeTargets += @(
  (New-CleanupEntry -Path (Join-Path $appWebView2Dir 'EBWebView\Default\Local Storage') -Root $programsRoot),
  (New-CleanupEntry -Path $appWebView2Dir -Root $programsRoot)
)
$emptyDirTargets += (New-CleanupEntry -Path $profileRoot -Root $appRoot)

$redirectedConfigDir = Get-RedirectedConfigDir -RedirectPath $redirectPath -UserProfile $userProfile
if ($redirectedConfigDir) {
  try {
    Assert-ConfigDirSafeForCleanup -Path $redirectedConfigDir -AllowedRoots @(
      $appRoot,
      $localAppData,
      $env:APPDATA,
      $userProfile
    )
    $redirectedConfigDir = Get-FullPath $redirectedConfigDir
    Add-ConfigCleanupTargets -PathTargets ([ref]$pathTargets) `
      -TreeTargets ([ref]$treeTargets) `
      -EmptyDirTargets ([ref]$emptyDirTargets) `
      -ConfigDir $redirectedConfigDir `
      -Root $redirectedConfigDir
  } catch {
    Write-Warning ("Skipping redirected config cleanup for $redirectedConfigDir. " + $_.Exception.Message)
  }
}

Remove-CleanupEntries -Entries $pathTargets
Remove-CleanupEntries -Entries $treeTargets -Tree
Remove-CleanupEntries -Entries $emptyDirTargets -EmptyDirectory

Remove-ExvCredentialManagerEntries

param(
  [string]$Version = '',
  [string]$SetupToolsDir = 'build-setup-rust',
  [string]$OutDir = 'build\release',
  [ValidateSet('lzms', 'store')]
  [string]$Compression = 'lzms',
  [ValidateRange(1, 10)]
  [int]$KeepInstallers = 2,
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-FullPath([string]$Candidate, [string]$Label) {
  if ([string]::IsNullOrWhiteSpace($Candidate)) {
    throw "$Label must not be empty"
  }
  try {
    return [IO.Path]::GetFullPath($Candidate)
  } catch {
    throw "$Label is not a valid path: $Candidate"
  }
}

function Resolve-ProductVersion([string]$RequestedVersion, [string]$RepositoryRoot) {
  $version = $RequestedVersion
  if ([string]::IsNullOrWhiteSpace($version)) {
    $configPath = Join-Path $RepositoryRoot 'src\platform\win32\rust\tauri\app\tauri.conf.json'
    try {
      $config = Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
      $version = [string]$config.version
    } catch {
      throw "unable to read product version from ${configPath}: $($_.Exception.Message)"
    }
  }
  if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
    throw "product version must use major.minor.patch: $version"
  }
  return $version
}

function Test-SamePath([string]$Left, [string]$Right) {
  return [string]::Equals(
    $Left.TrimEnd('\'),
    $Right.TrimEnd('\'),
    [StringComparison]::OrdinalIgnoreCase
  )
}

function Resolve-NativeApplication([string]$Name) {
  try {
    $command = @(Get-Command -Name $Name -CommandType Application -ErrorAction Stop)[0]
  } catch {
    throw "unable to resolve native application: $Name"
  }
  if ([string]::IsNullOrWhiteSpace($command.Path)) {
    throw "resolved native application has no path: $Name"
  }
  return Get-FullPath $command.Path "$Name application"
}

function Get-ExistingItem([string]$Path, [string]$Label) {
  try {
    return Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  } catch [System.Management.Automation.ItemNotFoundException] {
    return $null
  } catch [System.IO.FileNotFoundException] {
    return $null
  } catch [System.IO.DirectoryNotFoundException] {
    return $null
  } catch {
    throw "$Label is inaccessible: $Path ($($_.Exception.Message))"
  }
}

function Assert-ItemIsSafe([IO.FileSystemInfo]$Item, [string]$Label) {
  if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Label contains a reparse point: $($Item.FullName)"
  }
}

function Assert-NoReparsePoint([string]$Path, [string]$Label) {
  $rootItem = Get-ExistingItem $Path $Label
  if ($null -ne $rootItem) {
    Assert-ItemIsSafe $rootItem $Label
    if (($rootItem.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
      $pending = New-Object 'System.Collections.Generic.Stack[System.IO.DirectoryInfo]'
      $pending.Push([IO.DirectoryInfo]$rootItem)
      while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        try {
          $children = @($directory.GetFileSystemInfos())
        } catch {
          throw "$Label contains an inaccessible directory: $($directory.FullName) ($($_.Exception.Message))"
        }
        foreach ($child in $children) {
          Assert-ItemIsSafe $child $Label
          if (($child.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
            $pending.Push([IO.DirectoryInfo]$child)
          }
        }
      }
    }
  }

  $probe = $Path
  while ($null -ne $probe -and $probe.Length -gt 0) {
    $item = Get-ExistingItem $probe $Label
    if ($null -ne $item) {
      Assert-ItemIsSafe $item $Label
    }
    $parent = Split-Path -Parent $probe
    if ([string]::IsNullOrEmpty($parent) -or (Test-SamePath $parent $probe)) {
      break
    }
    $probe = $parent
  }
}

function Assert-NotTemporaryPath([string]$FullPath, [string]$Label) {
  foreach ($tempCandidate in @($env:TEMP, $env:TMP)) {
    if ([string]::IsNullOrWhiteSpace($tempCandidate)) {
      continue
    }
    $tempRoot = Get-FullPath $tempCandidate 'temporary directory'
    $tempPrefix = $tempRoot.TrimEnd('\') + '\'
    if (
      (Test-SamePath $FullPath $tempRoot) -or
      $FullPath.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)
    ) {
      throw "$Label resolves under a temporary directory, which is not allowed: $FullPath"
    }
  }
}

function Resolve-InRepo([string]$Candidate, [string]$Label) {
  if ([string]::IsNullOrWhiteSpace($Candidate)) {
    throw "$Label must not be empty"
  }
  $full = if ([IO.Path]::IsPathRooted($Candidate)) {
    Get-FullPath $Candidate $Label
  } else {
    Get-FullPath (Join-Path $repoRoot $Candidate) $Label
  }
  $rootPrefix = $repoRoot.TrimEnd('\') + '\'
  if (-not ((Test-SamePath $full $repoRoot) -or
      $full.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase))) {
    throw "$Label must remain inside the EXV worktree: $full"
  }
  $null = Assert-NotTemporaryPath $full $Label
  $null = Assert-NoReparsePoint $full $Label
  return [string]$full
}

function Assert-SafeDirectoryTarget([string]$Path, [string]$Label) {
  if (Test-SamePath $Path $repoRoot -or Test-SamePath $Path $mainWorktree) {
    throw "$Label may not be the EXV worktree or root/main worktree: $Path"
  }
  Resolve-InRepo $Path $Label | Out-Null
}

function Require-File([string]$Path, [string]$Label) {
  $item = Get-ExistingItem $Path $Label
  if ($null -eq $item -or ($item.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
    throw "missing ${Label}: $Path"
  }
  Assert-ItemIsSafe $item $Label
  return $item
}

function Get-RequiredInput([string]$Path, [string]$Label) {
  $item = Require-File $Path $Label
  $resolved = Get-FullPath $item.FullName $Label
  if (-not $resolved.StartsWith($repoRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Label resolved outside the EXV worktree: $resolved"
  }
  return $item
}

function Write-ProtectedPathList([string]$Phase, [string]$PayloadPath, [string]$InstallerPath) {
  Write-Host "protected-paths phase=$Phase"
  $setupToolsPath = if ($null -ne $setupToolsItem) { $setupToolsItem.FullName } else { $SetupToolsDir }
  $protected = [ordered]@{
      'worktree' = $repoRoot
      'setup-tools' = $setupToolsPath
      'output' = $outDir
      'payload' = $PayloadPath
      'installer' = $InstallerPath
      'installer-stage' = $installerStage
      'archive-stage' = $archiveStage
    }
  foreach ($entry in $protected.GetEnumerator()) {
    Write-Host ("protected-path {0}={1}" -f $entry.Key, $entry.Value)
  }
}

function Assert-PeMZ([string]$Path, [string]$Label) {
  $bytes = [IO.File]::ReadAllBytes($Path)
  if ($bytes.Length -le 0 -or $bytes.Length -lt 2 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
    throw "$Label is not a non-empty PE file: $Path"
  }
  if ($bytes.Length -lt 0x40) {
    throw "$Label is missing a complete DOS header: $Path"
  }
  $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
  if ($peOffset -lt 0 -or $peOffset -gt ($bytes.Length - 4)) {
    throw "$Label has an invalid e_lfanew: $Path"
  }
  if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or
      $bytes[$peOffset + 2] -ne 0x00 -or $bytes[$peOffset + 3] -ne 0x00) {
    throw "$Label is missing the PE\\0\\0 signature: $Path"
  }
  Write-Host ("PE signature verified: path={0} e_lfanew=0x{1:X8}" -f $Path, $peOffset)
  return $bytes
}

function Assert-ContainsMagic([byte[]]$Bytes, [string]$Magic, [string]$Label) {
  $ascii = [Text.Encoding]::ASCII.GetString($Bytes)
  if ($ascii.IndexOf($Magic, [StringComparison]::Ordinal) -lt 0) {
    throw "$Label is missing $Magic"
  }
}

function Remove-ProtectedDirectory([string]$Path, [string]$Label) {
  Assert-SafeDirectoryTarget $Path $Label
  if (Test-Path -LiteralPath $Path) {
    Write-Host "cleaning protected directory: $Path"
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
  }
  if (Test-Path -LiteralPath $Path) {
    throw "$Label still exists after cleanup: $Path"
  }
}

function Remove-GeneratedFile([string]$Path, [string]$Label) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    return
  }
  $full = Resolve-InRepo $Path $Label
  Assert-NotTemporaryPath $full $Label
  $item = Get-ExistingItem $full $Label
  if ($null -ne $item) {
    if (($item.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
      throw "$Label is unexpectedly a directory: $full"
    }
    Assert-ItemIsSafe $item $Label
    Write-Host "cleaning generated file: $full"
    Remove-Item -LiteralPath $full -Force -ErrorAction Stop
  }
  if (Test-Path -LiteralPath $full) {
    throw "$Label still exists after cleanup: $full"
  }
}

$scriptRoot = Get-FullPath $PSScriptRoot 'script directory'
$repoRoot = Get-FullPath (Split-Path -Parent $scriptRoot) 'EXV worktree root'
$gitMetadata = Get-ExistingItem (Join-Path $repoRoot '.git') 'Git metadata'
if ($null -eq $gitMetadata) {
  throw "EXV worktree root is not a Git worktree: $repoRoot"
}

$gitApp = Resolve-NativeApplication 'git'
$gitTopOutput = @(& $gitApp -C $repoRoot rev-parse --show-toplevel)
if ($LASTEXITCODE -ne 0 -or $gitTopOutput.Count -eq 0 -or [string]::IsNullOrWhiteSpace($gitTopOutput[0])) {
  throw "unable to resolve Git worktree root: $repoRoot"
}
$gitTop = Get-FullPath $gitTopOutput[0].Trim() 'Git worktree root'
if (-not (Test-SamePath $gitTop $repoRoot)) {
  throw "script directory is not inside the resolved target worktree: $repoRoot (Git reports $gitTop)"
}

$worktreeRecords = @(& $gitApp -C $repoRoot worktree list --porcelain)
if ($LASTEXITCODE -ne 0) {
  throw "unable to enumerate Git worktrees"
}
$worktreePaths = @(
  $worktreeRecords |
    Where-Object { $_ -match '^worktree (.+)$' } |
    ForEach-Object { Get-FullPath $Matches[1].Trim() 'Git worktree path' }
)
if ($worktreePaths.Count -eq 0) {
  throw "Git returned no worktrees for $repoRoot"
}
$mainWorktree = $worktreePaths[0]
if (Test-SamePath $repoRoot $mainWorktree) {
  throw "refusing to package from the root/main worktree: $repoRoot"
}

$Version = Resolve-ProductVersion $Version $repoRoot

$setupToolsItem = $null
$payloadDir = $null
$installer = $null
$installerStage = $null
$archiveStage = $null
$installerBackup = $null
$packageSucceeded = $false
$finalInstallerPromoted = $false
$finalInstallerBackupCreated = $false
$nativeFailureCode = $null
$failureRecord = $null

try {
  $outDir = Resolve-InRepo $OutDir 'output directory'
  Assert-SafeDirectoryTarget $outDir 'output directory'
  $payloadDir = Get-FullPath (Join-Path $outDir 'rust-payload') 'payload directory'
  $installer = Get-FullPath (Join-Path $outDir "EXV-$Version-windows-x64-setup.exe") 'installer output'
  $installerStage = Get-FullPath (Join-Path $outDir ".EXV-$Version-windows-x64-setup.staging.exe") 'installer staging output'
  $archiveStage = "$installerStage.exvp"
  $installerBackup = Get-FullPath (Join-Path $outDir ".EXV-$Version-windows-x64-setup.previous.exe") 'installer backup'
  Assert-SafeDirectoryTarget $payloadDir 'payload directory'
  Assert-NotTemporaryPath $installer 'installer output'
  Assert-NotTemporaryPath $installerStage 'installer staging output'
  Assert-NotTemporaryPath $archiveStage 'archive staging output'
  Assert-NotTemporaryPath $installerBackup 'installer backup'

  $setupToolsPath = Resolve-InRepo $SetupToolsDir 'setup tools directory'
  $setupToolsItem = Get-Item -LiteralPath $setupToolsPath -Force -ErrorAction SilentlyContinue
  if ($null -eq $setupToolsItem -or ($setupToolsItem.Attributes -band [IO.FileAttributes]::Directory) -eq 0) {
    throw "missing setup tools directory: $SetupToolsDir"
  }
  Assert-NoReparsePoint $setupToolsItem.FullName 'setup tools directory'

  $stub = Require-File (Join-Path $setupToolsItem.FullName 'exv-setup.exe') 'setup stub'
  $packer = Require-File (Join-Path $setupToolsItem.FullName 'pack_setup_payload.exe') 'payload packer'

  $sourceCandidates = [ordered]@{
    'exv-core.exe' = 'src\platform\win32\rust\target\release\exv-core.exe'
    'exv-engine.exe' = 'src\platform\win32\rust\target\release\exv-engine.exe'
    'exv-ui.exe' = 'src\platform\win32\rust\tauri\target\release\exv-ui.exe'
  }
  $sourceMap = [ordered]@{}
  foreach ($entry in $sourceCandidates.GetEnumerator()) {
    $sourceMap[$entry.Key] = (Get-RequiredInput (Resolve-InRepo $entry.Value "source $($entry.Key)") "source $($entry.Key)")
  }

  $wintunCandidates = @(
    'runtime\win32-x64\wintun.dll',
    'wintun.dll',
    'src\platform\win32\rust\target\release\trio\wintun.dll'
  )
  $wintun = $null
  foreach ($candidate in $wintunCandidates) {
    $candidatePath = Resolve-InRepo $candidate 'wintun candidate'
    if (Test-Path -LiteralPath $candidatePath -PathType Leaf) {
      $wintun = Get-RequiredInput $candidatePath 'wintun.dll'
      Write-Host "wintun-selected=$($wintun.FullName)"
      break
    }
  }
  if ($null -eq $wintun) {
    throw ('missing wintun.dll; checked: ' + ($wintunCandidates -join ', '))
  }
  $sourceMap['wintun.dll'] = $wintun

  $sourceHashes = [ordered]@{}
  foreach ($entry in $sourceMap.GetEnumerator()) {
    $hash = (Get-FileHash -LiteralPath $entry.Value.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
    $sourceHashes[$entry.Key] = $hash
  }

  Write-Host "EXV Rust setup package worktree: $repoRoot"
  Write-Host "EXV Rust setup version: $Version"
  Write-Host "EXV Rust setup compression: $Compression"
  Write-Host "EXV Rust setup keep requested: $KeepInstallers effective: $([Math]::Min($KeepInstallers, 2))"
  Write-Host "setup-stub=$($stub.FullName)"
  Write-Host "payload-packer=$($packer.FullName)"
  Write-Host "payload-layout=exv-core.exe,exv-engine.exe,exv-ui.exe,wintun.dll"
  foreach ($entry in $sourceMap.GetEnumerator()) {
    $source = $entry.Value
    Write-Host ("manifest relative={0} source={1} target={2} size={3} sha256={4}" -f
      $entry.Key, $source.FullName, (Join-Path $payloadDir $entry.Key), $source.Length, $sourceHashes[$entry.Key])
  }

  if ($DryRun) {
    Write-Host 'DRY-RUN: no payload, installer, or output directory will be written.'
    Write-Host "dry-run output=$outDir"
    Write-Host "dry-run payload=$payloadDir"
    Write-Host "dry-run installer=$installer"
    foreach ($entry in $sourceMap.GetEnumerator()) {
      Write-Host "dry-run expected hash-match relative=$($entry.Key) sha256=$($sourceHashes[$entry.Key])"
    }
    return
  }

  Write-ProtectedPathList 'before-payload-cleanup' $payloadDir $installer
  if (Test-Path -LiteralPath $payloadDir) {
    Remove-ProtectedDirectory $payloadDir 'payload staging directory'
  }
  Remove-GeneratedFile $installerStage 'installer staging output'
  Remove-GeneratedFile $archiveStage 'archive staging output'
  Remove-GeneratedFile $installerBackup 'installer backup'
  New-Item -ItemType Directory -Path $outDir -Force -ErrorAction Stop | Out-Null
  Assert-NoReparsePoint $outDir 'output directory before staging'
  New-Item -ItemType Directory -Path $payloadDir -Force -ErrorAction Stop | Out-Null
  Assert-NoReparsePoint $payloadDir 'payload staging directory'

  foreach ($entry in $sourceMap.GetEnumerator()) {
    $targetPath = Join-Path $payloadDir $entry.Key
    Copy-Item -LiteralPath $entry.Value.FullName -Destination $targetPath -Force -ErrorAction Stop
    $payloadItem = Require-File $targetPath "payload $($entry.Key)"
    if ($payloadItem.Length -ne $entry.Value.Length) {
      throw "payload size mismatch: $($entry.Key)"
    }
    $payloadHash = (Get-FileHash -LiteralPath $payloadItem.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($sourceHashes[$entry.Key] -ne $payloadHash) {
      throw "payload hash mismatch: $($entry.Key)"
    }
    Write-Host ("payload relative={0} size={1} source-sha256={2} payload-sha256={3} hash-match" -f
      $entry.Key, $payloadItem.Length, $sourceHashes[$entry.Key], $payloadHash)
  }

  & $packer.FullName '--package-dir' $payloadDir '--stub' $stub.FullName '--out' $installerStage '--algo' $Compression
  $packerExitCode = [int]$LASTEXITCODE
  if ($packerExitCode -ne 0) {
    $nativeFailureCode = $packerExitCode
    throw "pack_setup_payload failed: $packerExitCode"
  }

  $installerStageItem = Require-File $installerStage 'installer staging output'
  $installerStageBytes = Assert-PeMZ $installerStageItem.FullName 'installer staging output'
  Assert-ContainsMagic $installerStageBytes 'EXVP01' 'installer staging output'
  $stageHash = (Get-FileHash -LiteralPath $installerStageItem.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
  Write-Host ("installer staging path={0} size={1} sha256={2} mz=verified magic=EXVP01" -f
    $installerStageItem.FullName, $installerStageItem.Length, $stageHash)

  if (Test-Path -LiteralPath $installer -PathType Leaf) {
    $existingInstaller = Require-File $installer 'existing installer output'
    Copy-Item -LiteralPath $existingInstaller.FullName -Destination $installerBackup -Force -ErrorAction Stop
    $finalInstallerBackupCreated = $true
  }
  Move-Item -LiteralPath $installerStage -Destination $installer -Force -ErrorAction Stop
  $finalInstallerPromoted = $true
  $installerItem = Require-File $installer 'installer output'
  $installerBytes = Assert-PeMZ $installerItem.FullName 'installer output'
  Assert-ContainsMagic $installerBytes 'EXVP01' 'installer output'
  $installerHash = (Get-FileHash -LiteralPath $installerItem.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
  Write-Host ("installer path={0} size={1} sha256={2} mz=verified pe=verified magic=EXVP01" -f
    $installerItem.FullName, $installerItem.Length, $installerHash)

  $effectiveKeep = [Math]::Min($KeepInstallers, 2)
  Assert-NoReparsePoint $outDir 'output directory before retention'
  $allCandidates = @(
    Get-ChildItem -LiteralPath $outDir -Filter 'EXV-*-windows-x64-setup.exe' -File -Force |
      Sort-Object @{ Expression = 'LastWriteTimeUtc'; Descending = $true }, @{ Expression = 'Name'; Descending = $false }
  )
  $candidates = @(
    $allCandidates | Where-Object { -not (Test-SamePath $_.FullName $installer) }
  )
  $oldKeep = [Math]::Max($effectiveKeep - 1, 0)
  Write-ProtectedPathList 'before-installer-retention' $payloadDir $installer
  Write-Host "retention candidates=$($allCandidates.Count) old-candidates=$($candidates.Count) effective=$effectiveKeep current=protected"
  for ($index = $oldKeep; $index -lt $candidates.Count; $index++) {
    $candidatePath = Get-FullPath $candidates[$index].FullName 'installer cleanup target'
    Assert-SafeDirectoryTarget $outDir 'installer cleanup directory'
    Assert-NotTemporaryPath $candidatePath 'installer cleanup target'
    if (-not ($candidatePath.StartsWith($outDir.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase))) {
      throw "installer cleanup target escaped output directory: $candidatePath"
    }
    Write-Host "removing old installer: $candidatePath"
    Remove-Item -LiteralPath $candidatePath -Force -ErrorAction Stop
  }
  $retained = @(
    Get-ChildItem -LiteralPath $outDir -Filter 'EXV-*-windows-x64-setup.exe' -File -Force |
      Sort-Object @{ Expression = 'LastWriteTimeUtc'; Descending = $true }, @{ Expression = 'Name'; Descending = $false }
  )
  if ($retained.Count -gt 2) {
    throw "installer retention kept more than two files: $($retained.Count)"
  }
  Require-File $installer 'current installer after retention' | Out-Null
  Write-Host "retained installers=$($retained.Count)"
  foreach ($item in $retained) {
    Write-Host ("retained path={0} size={1} sha256={2}" -f
      $item.FullName, $item.Length, (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToUpperInvariant())
  }
  $packageSucceeded = $true
} catch {
  $failureRecord = $_
} finally {
  if (-not $DryRun) {
    Write-ProtectedPathList 'after-package-cleanup' $payloadDir $installer
    if ($null -ne $payloadDir) {
      Remove-ProtectedDirectory $payloadDir 'payload staging directory'
    }
    Remove-GeneratedFile $installerStage 'installer staging output'
    Remove-GeneratedFile $archiveStage 'archive staging output'
    if (-not $packageSucceeded -and $finalInstallerPromoted) {
      if ($finalInstallerBackupCreated) {
        Remove-GeneratedFile $installer 'failed installer output'
        Move-Item -LiteralPath $installerBackup -Destination $installer -Force -ErrorAction Stop
        $finalInstallerBackupCreated = $false
      } else {
        Remove-GeneratedFile $installer 'failed installer output'
      }
    }
    Remove-GeneratedFile $installerBackup 'installer backup'
  }
}

if ($null -ne $nativeFailureCode) {
  [Console]::Error.WriteLine("pack_setup_payload failed: $nativeFailureCode")
  exit $nativeFailureCode
}
if ($null -ne $failureRecord) {
  throw $failureRecord
}
Write-Host 'Rust setup package completed successfully.'

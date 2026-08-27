param(
  [string]$Version = '',
  [ValidateRange(1, 64)]
  [int]$Jobs = 4,
  [switch]$ConfigureOnly
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

  $path = $command.Path
  if ([string]::IsNullOrWhiteSpace($path)) {
    throw "resolved native application has no path: $Name"
  }
  return Get-FullPath $path "$Name application"
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

function Assert-InWorktree([string]$Candidate, [string]$Label) {
  $full = Get-FullPath $Candidate $Label
  $rootPrefix = $repoRoot.TrimEnd('\') + '\'
  $inWorktree = (
    (Test-SamePath $full $repoRoot) -or
    $full.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)
  )
  if (-not $inWorktree) {
    throw "$Label is outside the EXV worktree: $full"
  }

  foreach ($tempCandidate in @($env:TEMP, $env:TMP)) {
    if ([string]::IsNullOrWhiteSpace($tempCandidate)) {
      continue
    }
    $tempRoot = Get-FullPath $tempCandidate 'temporary directory'
    $tempPrefix = $tempRoot.TrimEnd('\') + '\'
    if (
      (Test-SamePath $full $tempRoot) -or
      $full.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)
    ) {
      throw "$Label resolves under a temporary directory, which is not allowed: $full"
    }
  }

  Assert-NoReparsePoint $full $Label
  return $full
}

$scriptRoot = Get-FullPath $PSScriptRoot 'script directory'
$repoRoot = Get-FullPath (Split-Path -Parent $scriptRoot) 'EXV worktree root'

$gitMetadata = Get-ExistingItem (Join-Path $repoRoot '.git') 'Git metadata'
if ($null -eq $gitMetadata) {
  throw "EXV worktree root is not a Git worktree: $repoRoot"
}

$gitApp = Resolve-NativeApplication 'git'
$gitTopOutput = @(& $gitApp -C $repoRoot rev-parse --show-toplevel)
if ($LASTEXITCODE -ne 0 -or $gitTopOutput.Count -eq 0 -or
    [string]::IsNullOrWhiteSpace($gitTopOutput[0])) {
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
    ForEach-Object { Get-FullPath $Matches[1] 'Git worktree path' }
)
if ($worktreePaths.Count -eq 0) {
  throw "Git returned no worktrees for $repoRoot"
}
$mainWorktree = $worktreePaths[0]
if (Test-SamePath $repoRoot $mainWorktree) {
  throw "refusing to build from the root/main worktree: $repoRoot"
}

$Version = Resolve-ProductVersion $Version $repoRoot

$sourceDir = Assert-InWorktree (Join-Path $repoRoot 'src\platform\win32\windows_setup_rust') 'setup source'
$buildDir = Assert-InWorktree (Join-Path $repoRoot 'build-setup-rust') 'setup build'
$setupArtifact = Assert-InWorktree (Join-Path $buildDir 'exv-setup.exe') 'exv-setup output'
$packerArtifact = Assert-InWorktree (Join-Path $buildDir 'pack_setup_payload.exe') 'pack_setup_payload output'

$sourceCMakeLists = Get-ExistingItem (Join-Path $sourceDir 'CMakeLists.txt') 'setup source CMakeLists.txt'
if ($null -eq $sourceCMakeLists -or
    ($sourceCMakeLists.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
  throw "setup source is missing CMakeLists.txt: $sourceDir"
}

$existingBuild = Get-ExistingItem $buildDir 'setup build'
if ($null -ne $existingBuild) {
  if (($existingBuild.Attributes -band [IO.FileAttributes]::Directory) -eq 0) {
    throw "setup build path is not a directory: $buildDir"
  }
  Write-Host "Removing existing protected setup build: $buildDir"
  Remove-Item -LiteralPath $buildDir -Recurse -Force -ErrorAction Stop
  if ($null -ne (Get-ExistingItem $buildDir 'setup build after cleanup')) {
    throw "setup build still exists after protected cleanup: $buildDir"
  }
}
New-Item -ItemType Directory -Path $buildDir -Force -ErrorAction Stop | Out-Null
Assert-NoReparsePoint $sourceDir 'setup source before configure'
Assert-NoReparsePoint $buildDir 'setup build before configure'
$cmakeApp = Resolve-NativeApplication 'cmake'

Write-Host "EXV setup build worktree: $repoRoot"
Write-Host "EXV setup source: $sourceDir"
Write-Host "EXV setup build: $buildDir"
Write-Host "EXV setup version: $Version"
Write-Host "EXV setup jobs: $Jobs"

$configureArgs = @(
  '-S', $sourceDir,
  '-B', $buildDir,
  '-G', 'Ninja',
  '-DCMAKE_BUILD_TYPE=Release',
  "-DEXV_PRODUCT_VERSION=$Version"
)
Write-Host ('Running: cmake ' + ($configureArgs -join ' '))
& $cmakeApp @configureArgs
$configureExitCode = [int]$LASTEXITCODE
if ($configureExitCode -ne 0) {
  [Console]::Error.WriteLine("cmake configure failed with exit code $configureExitCode")
  exit $configureExitCode
}

Assert-NoReparsePoint $sourceDir 'setup source after configure'
Assert-NoReparsePoint $buildDir 'setup build after configure'

if ($ConfigureOnly) {
  Write-Host 'ConfigureOnly requested; build targets were not built.'
  return
}

$buildArgs = @(
  '--build', $buildDir,
  '--parallel', $Jobs,
  '--target', 'exv-setup', 'pack_setup_payload'
)
Write-Host ('Running: cmake ' + ($buildArgs -join ' '))
& $cmakeApp @buildArgs
$buildExitCode = [int]$LASTEXITCODE
if ($buildExitCode -ne 0) {
  [Console]::Error.WriteLine("cmake build failed with exit code $buildExitCode")
  exit $buildExitCode
}

Assert-NoReparsePoint $sourceDir 'setup source after build'
Assert-NoReparsePoint $buildDir 'setup build after build'

foreach ($artifactPath in @($setupArtifact, $packerArtifact)) {
  $artifact = Get-ExistingItem $artifactPath 'setup artifact'
  if ($null -eq $artifact -or
      ($artifact.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
    throw "missing setup artifact: $artifactPath"
  }

  Assert-NoReparsePoint $artifactPath 'setup artifact'
  $resolvedArtifact = $artifact.FullName
  if ($artifact.Length -le 0) {
    throw "empty setup artifact: $resolvedArtifact"
  }

  $bytes = [IO.File]::ReadAllBytes($resolvedArtifact)
  if ($bytes.Length -lt 2 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
    throw "missing MZ header: $resolvedArtifact"
  }

  $hash = (Get-FileHash -LiteralPath $resolvedArtifact -Algorithm SHA256).Hash
  Write-Host ("artifact: {0} size={1} sha256={2}" -f $resolvedArtifact, $artifact.Length, $hash)
}

Write-Host 'Rust setup build completed successfully.'

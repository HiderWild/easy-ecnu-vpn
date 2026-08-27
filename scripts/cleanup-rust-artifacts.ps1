param(
  [ValidateRange(1, 10)]
  [int]$KeepInstallers = 2,
  [switch]$WhatIf,
  [string]$OutputRoot = 'build\release',
  [string]$FixtureRoot = '',
  [ValidateRange(0, 1000)]
  [int]$TestFailAfter = 0,
  [ValidateRange(0, 1000)]
  [int]$TestFailDuringRemoveAfter = 0
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ExitCodes = @{
  E_ALLOWLIST  = 20
  E_REPARSE    = 21
  E_IO         = 22
  E_PROTECTED  = 23
  E_ARGUMENT   = 24
  E_UNEXPECTED = 25
  E_PARTIAL    = 26
}

$plan = New-Object 'System.Collections.Generic.List[object]'
$deletedItems = New-Object 'System.Collections.Generic.List[object]'
$script:deleteAttemptCount = 0
$script:removeCallCount = 0
$repoRoot = $null
$operationRoot = $null
$productVersion = $null

function Fail([string]$Code, [string]$Message) {
  throw ("W35-T6 {0}: {1}" -f $Code, $Message)
}

function Log([string]$Message) {
  Write-Output ("W35-T6 {0}" -f $Message)
}

function Full-Path([string]$Candidate, [string]$Label) {
  if ([string]::IsNullOrWhiteSpace($Candidate)) {
    Fail 'E_ARGUMENT' "$Label must not be empty"
  }
  try {
    return [IO.Path]::GetFullPath($Candidate)
  } catch {
    Fail 'E_ARGUMENT' "$Label is not a valid path: $Candidate"
  }
}

function Get-ProductVersion([string]$RepositoryRoot) {
  $configPath = Join-Path $RepositoryRoot 'src\platform\win32\rust\tauri\app\tauri.conf.json'
  try {
    $config = Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $version = [string]$config.version
  } catch {
    Fail 'E_IO' "unable to read product version from ${configPath}: $($_.Exception.Message)"
  }
  if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
    Fail 'E_ARGUMENT' "product version must use major.minor.patch: $version"
  }
  return $version
}

function Same-Path([string]$Left, [string]$Right) {
  return [string]::Equals(
    $Left.TrimEnd('\'),
    $Right.TrimEnd('\'),
    [StringComparison]::OrdinalIgnoreCase
  )
}

function Existing-Item([string]$Path, [string]$Label) {
  try {
    return Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  } catch [System.Management.Automation.ItemNotFoundException] {
    return $null
  } catch [System.IO.FileNotFoundException] {
    return $null
  } catch [System.IO.DirectoryNotFoundException] {
    return $null
  } catch {
    Fail 'E_IO' "$Label is inaccessible: $Path ($($_.Exception.Message))"
  }
}

function Assert-NoReparseItem([IO.FileSystemInfo]$Item, [string]$Label) {
  if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail 'E_REPARSE' "$Label contains a reparse point: $($Item.FullName)"
  }
}

function Assert-PathChain([string]$Path, [string]$Label) {
  $probe = Full-Path $Path $Label
  while ($true) {
    $item = Existing-Item $probe $Label
    if ($null -ne $item) {
      Assert-NoReparseItem $item $Label
    }
    $parent = Split-Path -Parent $probe
    if ([string]::IsNullOrWhiteSpace($parent) -or (Same-Path $parent $probe)) {
      break
    }
    $probe = $parent
  }
}

function Assert-SafeTree([string]$Path, [string]$Label) {
  $root = Existing-Item $Path $Label
  if ($null -eq $root) {
    return
  }
  Assert-NoReparseItem $root $Label
  if (($root.Attributes -band [IO.FileAttributes]::Directory) -eq 0) {
    return
  }
  $pending = New-Object 'System.Collections.Generic.Stack[System.IO.DirectoryInfo]'
  $pending.Push([IO.DirectoryInfo]$root)
  while ($pending.Count -gt 0) {
    $directory = $pending.Pop()
    try {
      $children = @($directory.GetFileSystemInfos())
    } catch {
      Fail 'E_IO' "$Label contains an inaccessible directory: $($directory.FullName) ($($_.Exception.Message))"
    }
    foreach ($child in $children) {
      Assert-NoReparseItem $child $Label
      if (($child.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
        $pending.Push([IO.DirectoryInfo]$child)
      }
    }
  }
}

function Resolve-InWorktree([string]$RelativePath, [string]$Label) {
  $full = Full-Path (Join-Path $operationRoot $RelativePath) $Label
  $prefix = $operationRoot.TrimEnd('\') + '\'
  if (-not ((Same-Path $full $operationRoot) -or
      $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase))) {
    Fail 'E_ALLOWLIST' "$Label escaped the controlled operation root: $full"
  }
  Assert-PathChain $full $Label
  return $full
}

function Get-Identity([string]$Path, [string]$Label, [string]$ExpectedKind, [string]$FailureCode = 'E_ALLOWLIST') {
  Assert-PathChain $Path $Label
  $item = Existing-Item $Path $Label
  if ($null -eq $item) {
    Fail $FailureCode "$Label is missing: $Path"
  }
  Assert-NoReparseItem $item $Label
  $kind = if (($item.Attributes -band [IO.FileAttributes]::Directory) -ne 0) { 'directory' } else { 'file' }
  if ($kind -ne $ExpectedKind) {
    Fail $FailureCode "$Label has unexpected kind ${kind}: $Path"
  }
  if ($kind -eq 'directory') {
    Assert-SafeTree $Path $Label
  }
  $hash = $null
  if ($kind -eq 'file') {
    try {
      $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()
    } catch {
      Fail 'E_IO' "$Label hash failed: $Path ($($_.Exception.Message))"
    }
  }
  [pscustomobject]@{
    FullName = [IO.Path]::GetFullPath($item.FullName)
    Kind = $kind
    Length = if ($kind -eq 'file') { [int64]$item.Length } else { [int64]-1 }
    Attributes = [int]$item.Attributes
    CreationTicks = $item.CreationTimeUtc.Ticks
    LastWriteTicks = $item.LastWriteTimeUtc.Ticks
    SHA256 = $hash
  }
}

function Assert-Identity($Expected, [string]$Path, [string]$Label, [string]$FailureCode) {
  $actual = Get-Identity $Path $Label $Expected.Kind $FailureCode
  $same = ($Expected.FullName -eq $actual.FullName) -and
    ($Expected.Kind -eq $actual.Kind) -and
    ($Expected.Length -eq $actual.Length) -and
    ($Expected.Attributes -eq $actual.Attributes) -and
    ($Expected.CreationTicks -eq $actual.CreationTicks) -and
    ($Expected.LastWriteTicks -eq $actual.LastWriteTicks) -and
    ($Expected.SHA256 -eq $actual.SHA256)
  if (-not $same) {
    Fail $FailureCode "$Label identity or attributes changed: $Path"
  }
}

function Add-Plan([string]$Path, [string]$Kind, [string]$Label) {
  $identity = Get-Identity $Path $Label $Kind 'E_ALLOWLIST'
  $null = $plan.Add([pscustomobject]@{
      Kind = $Kind
      Label = $Label
      Path = $identity.FullName
      Identity = $identity
      Attempted = $false
      Unknown = $false
    })
  Log "action=plan kind=$Kind label=$Label path=$($identity.FullName)"
}

function Add-DirectoryPlan([string]$RelativePath, [string]$Label) {
  $full = Resolve-InWorktree $RelativePath $Label
  $item = Existing-Item $full $Label
  if ($null -eq $item) {
    Log "action=skip-missing kind=directory label=$Label path=$full"
    return
  }
  Add-Plan $full 'directory' $Label
}

function Add-DirectFilePlan([IO.FileSystemInfo]$Item, [string]$Root, [string]$Label) {
  $full = Full-Path $Item.FullName $Label
  if (-not (Same-Path (Split-Path -Parent $full) $Root)) {
    Fail 'E_ALLOWLIST' "$Label is not a direct child of its allowlisted root: $full"
  }
  Add-Plan $full 'file' $Label
}

function Read-DirectFiles([string]$RelativeRoot, [string]$Label) {
  $root = Resolve-InWorktree $RelativeRoot $Label
  $item = Existing-Item $root $Label
  if ($null -eq $item) {
    return @()
  }
  if (($item.Attributes -band [IO.FileAttributes]::Directory) -eq 0) {
    Fail 'E_ALLOWLIST' "$Label is not a directory: $root"
  }
  Assert-PathChain $root $Label
  Assert-NoReparseItem $item $Label
  try {
    return @(Get-ChildItem -LiteralPath $root -File -Force -ErrorAction Stop)
  } catch {
    Fail 'E_IO' "unable to enumerate ${Label}: $root ($($_.Exception.Message))"
  }
}

function Is-RustReleaseStale([string]$Name) {
  $artifactExtension = '(?:exe|pdb|rlib|d)'
  $productOutput = '(?:exv-vpn-win32-.+|exv-win32-.+)'
  $fixtureOutput = 'w35-task6-\d{17}-\d+-test'
  return ($Name -match "^$productOutput\.$artifactExtension$") -or
    ($Name -match "^$fixtureOutput\.$artifactExtension$")
}

function Is-TauriReleaseStale([string]$Name) {
  $artifactExtension = '(?:exe|pdb|rlib|d)'
  $productOutput = 'exv-tauri-app(?:[-_].+)?'
  $fixtureOutput = 'w35-task6-\d{17}-\d+-tauri-test'
  return ($Name -match "^$productOutput\.$artifactExtension$") -or
    ($Name -match "^$fixtureOutput\.$artifactExtension$")
}

function Is-SetupIntermediate([string]$Name) {
  $exact = @('.ninja_deps', '.ninja_log', 'build.ninja', 'cmake_install.cmake', 'CMakeCache.txt')
  return ($exact -contains $Name) -or
    ($Name -match '^.+\.(?:cmake|ninja|pdb)$')
}

function Add-RustReleasePlans {
  $root = Resolve-InWorktree 'src\platform\win32\rust\target\release' 'Rust release root'
  foreach ($item in (Read-DirectFiles 'src\platform\win32\rust\target\release' 'Rust release root')) {
    if (Is-RustReleaseStale $item.Name) {
      Add-DirectFilePlan $item $root 'Rust release stale output'
    }
  }
}

function Add-TauriReleasePlans {
  $root = Resolve-InWorktree 'src\platform\win32\rust\tauri\target\release' 'Tauri release root'
  foreach ($item in (Read-DirectFiles 'src\platform\win32\rust\tauri\target\release' 'Tauri release root')) {
    if (Is-TauriReleaseStale $item.Name) {
      Add-DirectFilePlan $item $root 'Tauri release stale output'
    }
  }
}

function Add-SetupIntermediatePlans {
  $root = Resolve-InWorktree 'build-setup-rust' 'setup build root'
  foreach ($item in (Read-DirectFiles 'build-setup-rust' 'setup build root')) {
    if (Is-SetupIntermediate $item.Name) {
      Add-DirectFilePlan $item $root 'CMake or Ninja intermediate'
    }
  }
}

function Add-OutputPlans {
  $root = Resolve-InWorktree 'build\release' 'release output root'
  foreach ($item in (Read-DirectFiles 'build\release' 'release output root')) {
    if ($item.Name -match '^\.EXV-[A-Za-z0-9._-]+\.staging\.exe$') {
      Add-DirectFilePlan $item $root 'installer staging file'
    } elseif ($item.Name -match '^\.EXV-[A-Za-z0-9._-]+\.staging\.exe\.exvp$') {
      Add-DirectFilePlan $item $root 'archive staging file'
    } elseif ($item.Name -match '^\.EXV-[A-Za-z0-9._-]+\.previous\.exe$') {
      Add-DirectFilePlan $item $root 'installer backup file'
    }
  }
  Add-InstallerRetentionPlans $root
}

function Add-InstallerRetentionPlans([string]$Root) {
  $items = @(Read-DirectFiles 'build\release' 'release output root')
  $candidates = @($items | Where-Object {
      $_.Name -match '^EXV-[A-Za-z0-9._-]+-windows-x64-setup\.exe$'
    } | Sort-Object @{ Expression = 'LastWriteTimeUtc'; Descending = $true }, @{ Expression = 'Name'; Descending = $false })
  $deliveredName = "EXV-$productVersion-windows-x64-setup.exe"
  $delivered = @($candidates | Where-Object { $_.Name -eq $deliveredName })
  $kept = New-Object 'System.Collections.Generic.List[string]'
  if ($delivered.Count -gt 0) {
    $deliveredPath = Full-Path $delivered[0].FullName 'delivered installer'
    $null = Get-Identity $deliveredPath 'delivered installer' 'file' 'E_PROTECTED'
    $null = $kept.Add($deliveredName)
    Log "action=retain label=delivered-installer path=$deliveredPath"
  }
  foreach ($item in $candidates) {
    if ($kept.Contains($item.Name)) {
      continue
    }
    if ($kept.Count -lt $KeepInstallers) {
      $path = Full-Path $item.FullName 'retained installer'
      $null = Get-Identity $path 'retained installer' 'file' 'E_PROTECTED'
      $null = $kept.Add($item.Name)
      Log "action=retain label=installer-retention path=$path"
    } else {
      Add-DirectFilePlan $item $Root 'old installer'
    }
  }
}

function Assert-FullPlan {
  foreach ($item in $plan) {
    Assert-Identity $item.Identity $item.Path $item.Label 'E_IO'
    Log "action=preflight kind=$($item.Kind) label=$($item.Label) path=$($item.Path)"
  }
}

function Invoke-RemovePlanItem($Item) {
  $script:removeCallCount += 1
  if ($TestFailDuringRemoveAfter -gt 0 -and $script:removeCallCount -eq $TestFailDuringRemoveAfter) {
    Log "action=test-inject-during-remove-failure kind=$($Item.Kind) label=$($Item.Label) path=$($Item.Path)"
    throw "test-only injected failure during Remove-Item call ${TestFailDuringRemoveAfter}: $($Item.Path)"
  }
  if ($Item.Kind -eq 'directory') {
    Remove-Item -LiteralPath $Item.Path -Recurse -Force -ErrorAction Stop
  } else {
    Remove-Item -LiteralPath $Item.Path -Force -ErrorAction Stop
  }
}

function Remove-PlanItem($Item) {
  try {
    Assert-Identity $Item.Identity $Item.Path $Item.Label 'E_PARTIAL'
    if ($WhatIf) {
      Log "action=whatif-remove kind=$($Item.Kind) label=$($Item.Label) path=$($Item.Path)"
      return
    }
    $script:deleteAttemptCount += 1
    if ($TestFailAfter -gt 0 -and $script:deleteAttemptCount -eq $TestFailAfter) {
      Log "action=test-inject-failure kind=$($Item.Kind) label=$($Item.Label) path=$($Item.Path)"
      Fail 'E_PARTIAL' "test-only injected failure at delete attempt ${TestFailAfter}: $($Item.Path)"
    }
    $Item.Attempted = $true
    Log "action=attempt kind=$($Item.Kind) label=$($Item.Label) path=$($Item.Path)"
    try {
      Invoke-RemovePlanItem $Item
    } catch {
      $Item.Unknown = $true
      Fail 'E_PARTIAL' "failed to remove $($Item.Label): $($Item.Path) ($($_.Exception.Message))"
    }
    if (Test-Path -LiteralPath $Item.Path) {
      $Item.Unknown = $true
      Fail 'E_PARTIAL' "$($Item.Label) still exists after removal: $($Item.Path)"
    }
    $null = $deletedItems.Add($Item)
    Log "action=remove kind=$($Item.Kind) label=$($Item.Label) path=$($Item.Path)"
  } catch {
    if ($Item.Attempted) {
      $Item.Unknown = $true
    }
    if ($_.Exception.Message -match '^W35-T6 E_PARTIAL:') {
      throw
    }
    Fail 'E_PARTIAL' $_.Exception.Message
  }
}

function Emit-Partial([string]$Message) {
  [Console]::Error.WriteLine("W35-T6 code=E_PARTIAL status=partial message=$Message")
  [Console]::Error.WriteLine("W35-T6 partial-deleted-count=$($deletedItems.Count)")
  foreach ($item in $deletedItems) {
    [Console]::Error.WriteLine("W35-T6 partial-deleted path=$($item.Path)")
  }
  $attemptedItems = @($plan | Where-Object { $_.Attempted })
  [Console]::Error.WriteLine("W35-T6 partial-attempted-count=$($attemptedItems.Count)")
  foreach ($item in $attemptedItems) {
    [Console]::Error.WriteLine("W35-T6 partial-attempted path=$($item.Path)")
  }
  $unknownItems = @($plan | Where-Object { $_.Unknown })
  [Console]::Error.WriteLine("W35-T6 partial-unknown-count=$($unknownItems.Count)")
  foreach ($item in $unknownItems) {
    [Console]::Error.WriteLine("W35-T6 partial-unknown path=$($item.Path)")
  }
  $notExecuted = @($plan | Where-Object { -not $_.Attempted })
  [Console]::Error.WriteLine("W35-T6 partial-not-executed-count=$($notExecuted.Count)")
  foreach ($item in $notExecuted) {
    [Console]::Error.WriteLine("W35-T6 partial-not-executed path=$($item.Path)")
  }
}

try {
  $scriptRoot = Full-Path $PSScriptRoot 'script directory'
  $repoRoot = Full-Path (Split-Path -Parent $scriptRoot) 'EXV worktree root'
  $gitCommand = (@(Get-Command git.exe -CommandType Application -ErrorAction Stop)[0]).Path
  $gitTopOutput = @(& $gitCommand -C $repoRoot rev-parse --show-toplevel 2>&1)
  if ($LASTEXITCODE -ne 0 -or $gitTopOutput.Count -eq 0) {
    Fail 'E_IO' "unable to resolve Git worktree root: $repoRoot"
  }
  $gitTop = Full-Path ([string]$gitTopOutput[0]).Trim() 'Git worktree root'
  if (-not (Same-Path $gitTop $repoRoot)) {
    Fail 'E_ALLOWLIST' "script is not running from the target worktree: $repoRoot (Git reports $gitTop)"
  }
  $worktreeRecords = @(& $gitCommand -C $repoRoot worktree list --porcelain 2>&1)
  if ($LASTEXITCODE -ne 0) {
    Fail 'E_IO' 'unable to enumerate Git worktrees'
  }
  $worktreePaths = @($worktreeRecords | Where-Object { $_ -match '^worktree (.+)$' } |
    ForEach-Object { Full-Path $Matches[1].Trim() 'Git worktree path' })
  if ($worktreePaths.Count -eq 0) {
    Fail 'E_IO' 'Git returned no worktrees'
  }
  if (Same-Path $repoRoot $worktreePaths[0]) {
    Fail 'E_ALLOWLIST' "refusing to clean the root/main worktree: $repoRoot"
  }

  $productVersion = Get-ProductVersion $repoRoot

  $operationRoot = $repoRoot
  if (-not [string]::IsNullOrWhiteSpace($FixtureRoot)) {
    $fixtureCandidate = if ([IO.Path]::IsPathRooted($FixtureRoot)) {
      Full-Path $FixtureRoot 'fixture root'
    } else {
      Full-Path (Join-Path $repoRoot $FixtureRoot) 'fixture root'
    }
    $repoPrefix = $repoRoot.TrimEnd('\') + '\'
    if ((Same-Path $fixtureCandidate $repoRoot) -or
        (-not $fixtureCandidate.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase))) {
      Fail 'E_ALLOWLIST' "fixture root is outside the linked worktree or is the worktree root: $fixtureCandidate"
    }
    Assert-PathChain $fixtureCandidate 'fixture root'
    $fixtureItem = Existing-Item $fixtureCandidate 'fixture root'
    if ($null -eq $fixtureItem) {
      Fail 'E_ALLOWLIST' "fixture root is missing: $fixtureCandidate"
    }
    Assert-NoReparseItem $fixtureItem 'fixture root'
    if (($fixtureItem.Attributes -band [IO.FileAttributes]::Directory) -eq 0) {
      Fail 'E_ALLOWLIST' "fixture root is not a directory: $fixtureCandidate"
    }
    Assert-SafeTree $fixtureCandidate 'fixture root'
    $operationRoot = $fixtureCandidate
  }
  if ($TestFailAfter -gt 0 -and [string]::IsNullOrWhiteSpace($FixtureRoot)) {
    Fail 'E_ARGUMENT' 'TestFailAfter is available only with FixtureRoot'
  }
  if ($TestFailDuringRemoveAfter -gt 0 -and [string]::IsNullOrWhiteSpace($FixtureRoot)) {
    Fail 'E_ARGUMENT' 'TestFailDuringRemoveAfter is available only with FixtureRoot'
  }

  $canonicalOutputRoot = Full-Path (Join-Path $operationRoot 'build\release') 'canonical output directory'
  $outputRoot = if ([IO.Path]::IsPathRooted($OutputRoot)) {
    Full-Path $OutputRoot 'output directory'
  } else {
    Full-Path (Join-Path $operationRoot $OutputRoot) 'output directory'
  }
  if (-not (Same-Path $outputRoot $canonicalOutputRoot)) {
    Fail 'E_ALLOWLIST' "output directory is not the explicit Task6 allowlist root: $outputRoot"
  }
  Assert-PathChain $outputRoot 'output directory'

  Log "code=START mode=$(if ($WhatIf) { 'WHATIF' } else { 'APPLY' }) worktree=$repoRoot operation-root=$operationRoot"
  Log 'allowlist=target-debug;release-deps-build-incremental;tauri-debug;tauri-release-deps-build-incremental;release-root-stale;setup-cmake-ninja;release-staging;installer-retention;rust-payload'
  if ($TestFailAfter -gt 0) {
    Log "test-only-failure-injection=enabled after=$TestFailAfter fixture-only=true"
  }
  if ($TestFailDuringRemoveAfter -gt 0) {
    Log "test-only-during-remove-failure-injection=enabled after=$TestFailDuringRemoveAfter fixture-only=true"
  }

  Add-DirectoryPlan 'src\platform\win32\rust\target\debug' 'Rust target debug'
  Add-DirectoryPlan 'src\platform\win32\rust\target\release\deps' 'Rust target release deps'
  Add-DirectoryPlan 'src\platform\win32\rust\target\release\build' 'Rust target release build'
  Add-DirectoryPlan 'src\platform\win32\rust\target\release\incremental' 'Rust target release incremental'
  Add-DirectoryPlan 'src\platform\win32\rust\tauri\target\debug' 'Tauri target debug'
  Add-DirectoryPlan 'src\platform\win32\rust\tauri\target\release\deps' 'Tauri target release deps'
  Add-DirectoryPlan 'src\platform\win32\rust\tauri\target\release\build' 'Tauri target release build'
  Add-DirectoryPlan 'src\platform\win32\rust\tauri\target\release\incremental' 'Tauri target release incremental'
  Add-DirectoryPlan 'build\release\rust-payload' 'Rust setup payload staging'
  Add-DirectoryPlan 'build-setup-rust\CMakeFiles' 'CMake files intermediate'
  Add-RustReleasePlans
  Add-TauriReleasePlans
  Add-SetupIntermediatePlans
  Add-OutputPlans

  Assert-FullPlan
  foreach ($item in $plan) {
    Remove-PlanItem $item
  }
  Log "code=SUCCESS planned=$($plan.Count) deleted=$($deletedItems.Count) mode=$(if ($WhatIf) { 'WHATIF' } else { 'APPLY' })"
  exit 0
} catch {
  $message = $_.Exception.Message
  if ($message -match '^W35-T6 (?<code>E_[A-Z]+): (?<detail>.*)$') {
    $code = $Matches['code']
    $detail = $Matches['detail']
    if ($code -eq 'E_PARTIAL') {
      Emit-Partial $detail
    } else {
      [Console]::Error.WriteLine("W35-T6 code=$code message=$detail")
    }
    exit $ExitCodes[$code]
  }
  [Console]::Error.WriteLine("W35-T6 code=E_UNEXPECTED message=$message")
  exit $ExitCodes.E_UNEXPECTED
}

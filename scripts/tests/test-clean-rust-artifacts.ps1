$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$fixtureRoot = Join-Path $repoRoot '.w35-task6-fixture'
$scriptPath = Join-Path $repoRoot 'scripts\cleanup-rust-artifacts.ps1'
$releaseDir = Join-Path $fixtureRoot 'build\release'
$rustTargetRoot = Join-Path $fixtureRoot 'src\platform\win32\rust\target'
$rustReleaseDir = Join-Path $rustTargetRoot 'release'
$tauriTargetRoot = Join-Path $fixtureRoot 'src\platform\win32\rust\tauri\target'
$tauriReleaseDir = Join-Path $tauriTargetRoot 'release'
$setupBuildDir = Join-Path $fixtureRoot 'build-setup-rust'
$evidenceDir = Join-Path $repoRoot 'docs\superpowers\evidence\vpn-rust-native-runtime-mvp\win32\W35-service-ui-packaging'
$cleanupBeforePath = Join-Path $evidenceDir 'cleanup-before.md'
$cleanupAfterPath = Join-Path $evidenceDir 'cleanup-after.md'
$fixtureId = [DateTime]::UtcNow.ToString('yyyyMMddHHmmssfff') + '-' + $PID

$rustDebugDir = Join-Path $rustTargetRoot 'debug'
$rustDepsDir = Join-Path $rustReleaseDir 'deps'
$rustBuildDir = Join-Path $rustReleaseDir 'build'
$rustIncrementalDir = Join-Path $rustReleaseDir 'incremental'
$tauriDebugDir = Join-Path $tauriTargetRoot 'debug'
$tauriDepsDir = Join-Path $tauriReleaseDir 'deps'
$tauriBuildDir = Join-Path $tauriReleaseDir 'build'
$tauriIncrementalDir = Join-Path $tauriReleaseDir 'incremental'
$payloadDir = Join-Path $releaseDir 'rust-payload'
$cmakeFilesDir = Join-Path $setupBuildDir 'CMakeFiles'

$fixtureFiles = @(
  (Join-Path $rustDebugDir "w35-task6-$fixtureId-debug.exe"),
  (Join-Path $rustDepsDir "w35-task6-$fixtureId-deps.rlib"),
  (Join-Path $rustBuildDir "w35-task6-$fixtureId-build.d"),
  (Join-Path $rustIncrementalDir "w35-task6-$fixtureId-incremental.marker"),
  (Join-Path $tauriDebugDir "w35-task6-$fixtureId-tauri-debug.exe"),
  (Join-Path $tauriDepsDir "w35-task6-$fixtureId-tauri-deps.rlib"),
  (Join-Path $tauriBuildDir "w35-task6-$fixtureId-tauri-build.d"),
  (Join-Path $tauriIncrementalDir "w35-task6-$fixtureId-tauri-incremental.marker"),
  (Join-Path $payloadDir "w35-task6-$fixtureId-payload.marker"),
  (Join-Path $cmakeFilesDir "w35-task6-$fixtureId-cmake.marker")
)

$rustReleaseStaleFiles = @(
  (Join-Path $rustReleaseDir "exv-vpn-win32-$fixtureId.exe"),
  (Join-Path $rustReleaseDir "exv-vpn-win32-$fixtureId.pdb"),
  (Join-Path $rustReleaseDir "exv-vpn-win32-$fixtureId.rlib"),
  (Join-Path $rustReleaseDir "exv-vpn-win32-$fixtureId.d"),
  (Join-Path $rustReleaseDir "exv-win32-$fixtureId.exe"),
  (Join-Path $rustReleaseDir "exv-win32-$fixtureId.pdb"),
  (Join-Path $rustReleaseDir "exv-win32-$fixtureId.rlib"),
  (Join-Path $rustReleaseDir "exv-win32-$fixtureId.d"),
  (Join-Path $rustReleaseDir "w35-task6-$fixtureId-test.exe"),
  (Join-Path $rustReleaseDir "w35-task6-$fixtureId-test.pdb"),
  (Join-Path $rustReleaseDir "w35-task6-$fixtureId-test.rlib"),
  (Join-Path $rustReleaseDir "w35-task6-$fixtureId-test.d")
)

$tauriReleaseStaleFiles = @(
  (Join-Path $tauriReleaseDir "exv-tauri-app-$fixtureId.exe"),
  (Join-Path $tauriReleaseDir "exv-tauri-app-$fixtureId.pdb"),
  (Join-Path $tauriReleaseDir "exv-tauri-app-$fixtureId.rlib"),
  (Join-Path $tauriReleaseDir "exv-tauri-app-$fixtureId.d"),
  (Join-Path $tauriReleaseDir "w35-task6-$fixtureId-tauri-test.exe"),
  (Join-Path $tauriReleaseDir "w35-task6-$fixtureId-tauri-test.pdb"),
  (Join-Path $tauriReleaseDir "w35-task6-$fixtureId-tauri-test.rlib"),
  (Join-Path $tauriReleaseDir "w35-task6-$fixtureId-tauri-test.d")
)

$releaseRootNegativeFixtures = @(
  (Join-Path $rustReleaseDir 'contest.exe'),
  (Join-Path $rustReleaseDir 'attest.exe'),
  (Join-Path $rustReleaseDir 'contest-old.exe'),
  (Join-Path $rustReleaseDir 'attest-build.exe'),
  (Join-Path $tauriReleaseDir 'contest.exe'),
  (Join-Path $tauriReleaseDir 'attest.exe'),
  (Join-Path $tauriReleaseDir 'contest-old.exe'),
  (Join-Path $tauriReleaseDir 'attest-build.exe')
)

$setupIntermediateFixtures = @(
  (Join-Path $setupBuildDir "w35-task6-$fixtureId.cmake"),
  (Join-Path $setupBuildDir "w35-task6-$fixtureId.ninja"),
  (Join-Path $setupBuildDir "w35-task6-$fixtureId.pdb")
)

$oldInstallerNames = @(
  "EXV-W35-T6-$fixtureId-oldest-windows-x64-setup.exe",
  "EXV-W35-T6-$fixtureId-middle-windows-x64-setup.exe",
  "EXV-W35-T6-$fixtureId-newest-windows-x64-setup.exe"
)
$oldInstallerPaths = @($oldInstallerNames | ForEach-Object { Join-Path $releaseDir $_ })
$reparsePath = Join-Path $rustDebugDir "w35-task6-$fixtureId-reparse-link"
$unknownReparsePath = Join-Path $rustBuildDir "w35-task6-$fixtureId-unknown-reparse-link"
$lockedPath = Join-Path $rustDebugDir "w35-task6-$fixtureId-locked.exe"

$protectedPaths = @(
  (Join-Path $releaseDir 'EXV-4.0.0-windows-x64-setup.exe'),
  (Join-Path $setupBuildDir 'exv-setup.exe'),
  (Join-Path $setupBuildDir 'pack_setup_payload.exe'),
  (Join-Path $rustReleaseDir 'exv-core.exe'),
  (Join-Path $rustReleaseDir 'exv-engine.exe'),
  (Join-Path $tauriReleaseDir 'exv-ui.exe'),
  (Join-Path $fixtureRoot 'src\platform\win32\rust\Cargo.toml'),
  (Join-Path $fixtureRoot 'src\platform\win32\rust\tauri\frontend\package.json'),
  (Join-Path $fixtureRoot 'docs\superpowers\evidence\vpn-rust-native-runtime-mvp\win32\W35-service-ui-packaging\package-script.md')
)

$worktreeRecords = @(& git -C $repoRoot worktree list --porcelain)
$mainWorktree = @($worktreeRecords | Where-Object { $_ -match '^worktree (.+)$' } |
  Select-Object -First 1 | ForEach-Object { $Matches[1].Trim() })[0]
$externalSentinel = Join-Path $mainWorktree 'README.md'
$externalBefore = $null
$externalAfter = $null

$beforeLines = New-Object 'System.Collections.Generic.List[string]'
$afterLines = New-Object 'System.Collections.Generic.List[string]'

function Assert-Equal([object]$Expected, [object]$Actual, [string]$Label, [string]$Detail = '') {
  if ($Expected -ne $Actual) {
    throw "$Label expected '$Expected' but got '$Actual'. $Detail"
  }
}

function Assert-True([bool]$Condition, [string]$Label, [string]$Detail = '') {
  if (-not $Condition) {
    throw "$Label failed. $Detail"
  }
}

function Assert-Contains([string]$Text, [string]$Needle, [string]$Label) {
  if ($Text.IndexOf($Needle, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "$Label did not contain '$Needle'. Output: $Text"
  }
}

function Assert-NotContains([string]$Text, [string]$Needle, [string]$Label) {
  if ($Text.IndexOf($Needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
    throw "$Label unexpectedly contained '$Needle'. Output: $Text"
  }
}

function Invoke-Cleanup([string[]]$Arguments) {
  $previousPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $output = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath @Arguments 2>&1)
    $exitCode = [int]$LASTEXITCODE
  } finally {
    $ErrorActionPreference = $previousPreference
  }
  [pscustomobject]@{
    ExitCode = $exitCode
    Output = ($output -join [Environment]::NewLine)
  }
}

function Ensure-File([string]$Path, [string]$Content = 'W35-T6 fixture') {
  $parent = Split-Path -Parent $Path
  New-Item -ItemType Directory -Path $parent -Force | Out-Null
  [IO.File]::WriteAllText($Path, $Content, [Text.Encoding]::UTF8)
}

function Get-PathSnapshot([string[]]$Paths) {
  foreach ($path in $Paths) {
    if (Test-Path -LiteralPath $path -PathType Leaf) {
      $item = Get-Item -LiteralPath $path -Force
      [pscustomobject]@{
        Path = $item.FullName
        Present = $true
        Leaf = $true
        Length = $item.Length
        SHA256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
        Attributes = [string]$item.Attributes
      }
    } else {
      [pscustomobject]@{
        Path = [IO.Path]::GetFullPath($path)
        Present = $false
        Leaf = $false
        Length = $null
        SHA256 = $null
        Attributes = $null
      }
    }
  }
}

function Write-PathSnapshot([string]$Phase, [string[]]$Paths) {
  $snapshot = @(Get-PathSnapshot $Paths)
  foreach ($entry in $snapshot) {
    if ($entry.Present) {
      Write-Host ("EVIDENCE phase={0} present=true leaf={1} path={2} size={3} sha256={4}" -f
        $Phase, $entry.Leaf, $entry.Path, $entry.Length, $entry.SHA256)
    } else {
      Write-Host ("EVIDENCE phase={0} present=false leaf=false path={1}" -f $Phase, $entry.Path)
    }
  }
  return $snapshot
}

function Assert-LeafSentinel([string]$Path, [string]$Label) {
  Assert-True (Test-Path -LiteralPath $Path -PathType Leaf) "$Label is a leaf" $Path
  $item = Get-Item -LiteralPath $Path -Force
  Assert-True (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "$Label is not reparse" $Path
}

function Assert-PathsPresent([string[]]$Paths, [string]$Label) {
  Assert-True ($Paths.Count -gt 0) "$Label has paths"
  foreach ($path in $Paths) {
    Assert-True (Test-Path -LiteralPath $path -PathType Leaf) "$Label path exists" $path
  }
}

function Add-SnapshotMarkdown([System.Collections.Generic.List[string]]$Sink, [string]$Title, $Snapshot) {
  $Sink.Add("### $Title")
  $Sink.Add('')
  $Sink.Add('| state | leaf | size | sha256 | attributes | path |')
  $Sink.Add('| --- | --- | ---: | --- | --- | --- |')
  foreach ($entry in @($Snapshot)) {
    $state = if ($entry.Present) { 'present' } else { 'absent' }
    $size = if ($entry.Present) { [string]$entry.Length } else { '' }
    $hash = if ($entry.Present) { $entry.SHA256 } else { '' }
    $attrs = if ($entry.Present) { $entry.Attributes } else { '' }
    $leaf = if ($entry.Leaf) { 'true' } else { 'false' }
    $Sink.Add("| $state | $leaf | $size | $hash | $attrs | ``$($entry.Path)`` |")
  }
  $Sink.Add('')
}

function Write-ResultMarkdown([System.Collections.Generic.List[string]]$Sink, [string]$Title, $Result) {
  $Sink.Add("### $Title")
  $Sink.Add('')
  $Sink.Add("- exit: ``$($Result.ExitCode)``")
  $Sink.Add('')
  $Sink.Add('```text')
  foreach ($line in ($Result.Output -split "`r?`n")) {
    $Sink.Add($line)
  }
  $Sink.Add('```')
  $Sink.Add('')
}

function Assert-SnapshotUnchanged($Before, $After, [string]$Label) {
  Assert-Equal $Before.Count $After.Count "$Label count"
  for ($index = 0; $index -lt $Before.Count; $index++) {
    Assert-Equal $Before[$index].Path $After[$index].Path "$Label path[$index]"
    Assert-Equal $Before[$index].Present $After[$index].Present "$Label present[$index]"
    Assert-Equal $Before[$index].Length $After[$index].Length "$Label length[$index]"
    Assert-Equal $Before[$index].SHA256 $After[$index].SHA256 "$Label hash[$index]"
  }
}

function Prepare-AllowedFixtures {
  Assert-True (-not (Test-Path -LiteralPath $fixtureRoot)) 'fixture root starts absent' $fixtureRoot
  foreach ($path in @($fixtureFiles + $rustReleaseStaleFiles + $tauriReleaseStaleFiles + $releaseRootNegativeFixtures + $setupIntermediateFixtures + $protectedPaths)) {
    Ensure-File $path
  }
  foreach ($path in $oldInstallerPaths) {
    Ensure-File $path 'MZ W35-T6 installer fixture'
  }
  $offsets = @(-30, -20, -10)
  for ($index = 0; $index -lt $oldInstallerPaths.Count; $index++) {
    (Get-Item -LiteralPath $oldInstallerPaths[$index]).LastWriteTimeUtc = [DateTime]::UtcNow.AddMinutes($offsets[$index])
  }
}

function Remove-ReparsePath([string]$Path) {
  if (Test-Path -LiteralPath $Path) {
    $null = & cmd.exe /d /c "rmdir /q `"$Path`"" 2>&1
    Assert-Equal 0 $LASTEXITCODE 'reparse fixture cleanup exit code'
  }
}

function Remove-ReparseFixture {
  Remove-ReparsePath $reparsePath
}

function Inspect-TestResidueItem([IO.FileSystemInfo]$Item, [string]$RootPath, [bool]$IsRoot) {
  try {
    $fullPath = [IO.Path]::GetFullPath($Item.FullName)
  } catch {
    throw "fixture residue path is not canonical: $($Item.FullName) ($($_.Exception.Message))"
  }

  $rootCanonical = $RootPath.TrimEnd('\')
  $rootPrefix = $rootCanonical + '\'
  if ($IsRoot) {
    if (-not [string]::Equals($fullPath.TrimEnd('\'), $rootCanonical, [StringComparison]::OrdinalIgnoreCase)) {
      throw "fixture residue root changed during inspection: $fullPath (root: $rootCanonical)"
    }
  } elseif (-not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "fixture residue path escaped fixture root: $fullPath (root: $rootCanonical)"
  }

  try {
    $rawAttributes = $Item.Attributes
  } catch {
    throw "fixture residue attributes could not be read: $fullPath ($($_.Exception.Message))"
  }
  if ($null -eq $rawAttributes) {
    throw "fixture residue attributes are missing: $fullPath"
  }
  try {
    $attributes = [int64]$rawAttributes
  } catch {
    throw "fixture residue attributes are invalid: $fullPath ($rawAttributes)"
  }

  $knownAttributes = [int64]0
  foreach ($knownAttribute in [Enum]::GetValues([IO.FileAttributes])) {
    $knownAttributes = $knownAttributes -bor ([int64]$knownAttribute)
  }
  if (($attributes -eq 0) -or (($attributes -band $knownAttributes) -ne $attributes)) {
    throw "fixture residue attributes are abnormal: $fullPath ($rawAttributes)"
  }

  $reparseFlag = [int64][IO.FileAttributes]::ReparsePoint
  if (($attributes -band $reparseFlag) -ne 0) {
    throw "fixture residue contains a reparse point: $fullPath"
  }

  $normalFlag = [int64][IO.FileAttributes]::Normal
  if (($attributes -band $normalFlag) -ne 0 -and $attributes -ne $normalFlag) {
    throw "fixture residue attributes are inconsistent: $fullPath ($rawAttributes)"
  }

  $directoryFlag = [int64][IO.FileAttributes]::Directory
  $hasDirectoryFlag = (($attributes -band $directoryFlag) -ne 0)
  $isDirectory = $Item -is [IO.DirectoryInfo]
  if ($hasDirectoryFlag -ne $isDirectory) {
    throw "fixture residue attributes do not match item kind: $fullPath ($rawAttributes)"
  }

  [pscustomobject]@{
    FullPath = $fullPath
    IsDirectory = $isDirectory
  }
}

function Get-TestResidueRemovalPlan([string]$Root) {
  if (-not (Test-Path -LiteralPath $Root)) {
    return @()
  }

  try {
    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
  } catch {
    throw "fixture residue root could not be inspected: $Root ($($_.Exception.Message))"
  }
  try {
    $rootPath = [IO.Path]::GetFullPath($rootItem.FullName)
  } catch {
    throw "fixture residue root is not canonical: $Root ($($_.Exception.Message))"
  }

  $rootInspection = Inspect-TestResidueItem $rootItem $rootPath $true
  if (-not $rootInspection.IsDirectory) {
    throw "fixture residue root is not a directory: $rootPath"
  }

  $plan = New-Object 'System.Collections.Generic.List[object]'
  $pending = New-Object 'System.Collections.Generic.Stack[object]'
  $pending.Push([pscustomobject]@{
      Item = $rootItem
      Inspection = $rootInspection
      AfterChildren = $false
    })

  while ($pending.Count -gt 0) {
    $frame = $pending.Pop()
    if ($frame.AfterChildren) {
      $null = $plan.Add($frame.Inspection)
      continue
    }

    if (-not $frame.Inspection.IsDirectory) {
      $null = $plan.Add($frame.Inspection)
      continue
    }

    $pending.Push([pscustomobject]@{
        Item = $frame.Item
        Inspection = $frame.Inspection
        AfterChildren = $true
      })
    try {
      $children = @(([IO.DirectoryInfo]$frame.Item).GetFileSystemInfos())
    } catch {
      throw "fixture residue directory could not be enumerated: $($frame.Inspection.FullPath) ($($_.Exception.Message))"
    }

    $childFrames = New-Object 'System.Collections.Generic.List[object]'
    foreach ($child in $children) {
      try {
        $childItem = Get-Item -LiteralPath $child.FullName -Force -ErrorAction Stop
      } catch {
        throw "fixture residue child could not be inspected: $($child.FullName) ($($_.Exception.Message))"
      }
      $childInspection = Inspect-TestResidueItem $childItem $rootPath $false
      $childFrames.Add([pscustomobject]@{
          Item = $childItem
          Inspection = $childInspection
          AfterChildren = $false
        })
    }
    for ($index = $childFrames.Count - 1; $index -ge 0; $index--) {
      $pending.Push($childFrames[$index])
    }
  }

  return @($plan.ToArray())
}

function Remove-TestResidue {
  Remove-ReparseFixture
  $plan = @(Get-TestResidueRemovalPlan $fixtureRoot)
  foreach ($entry in $plan) {
    Remove-Item -LiteralPath $entry.FullPath -Force -ErrorAction Stop
  }
}

function Test-ExternalSentinelBefore {
  Assert-True (-not [string]::IsNullOrWhiteSpace($mainWorktree)) 'main worktree path is present' $mainWorktree
  Assert-True (-not [string]::Equals(
      ([IO.Path]::GetFullPath($mainWorktree)).TrimEnd('\'),
      $repoRoot.TrimEnd('\'),
      [StringComparison]::OrdinalIgnoreCase)) 'main worktree is external to target worktree' $mainWorktree
  Assert-LeafSentinel $externalSentinel 'external main-worktree sentinel before'
  $snapshot = @(Write-PathSnapshot 'external-main-before' @($externalSentinel))
  Assert-Equal 1 $snapshot.Count 'external sentinel before snapshot count'
  Assert-True $snapshot[0].Present 'external sentinel before present' $externalSentinel
  Assert-True $snapshot[0].Leaf 'external sentinel before leaf' $externalSentinel
  Assert-True (-not [string]::IsNullOrWhiteSpace($snapshot[0].SHA256)) 'external sentinel before hash' $externalSentinel
  return $snapshot
}

function Test-ExternalSentinelAfter {
  Assert-LeafSentinel $externalSentinel 'external main-worktree sentinel after'
  $snapshot = @(Write-PathSnapshot 'external-main-after' @($externalSentinel))
  Assert-Equal 1 $snapshot.Count 'external sentinel after snapshot count'
  Assert-True $snapshot[0].Present 'external sentinel after present' $externalSentinel
  Assert-True $snapshot[0].Leaf 'external sentinel after leaf' $externalSentinel
  Assert-True (-not [string]::IsNullOrWhiteSpace($snapshot[0].SHA256)) 'external sentinel after hash' $externalSentinel
  return $snapshot
}

function Test-CanonicalInterface {
  Assert-True (Test-Path -LiteralPath $scriptPath -PathType Leaf) 'canonical cleanup script exists' $scriptPath
  $source = Get-Content -Raw -LiteralPath $scriptPath
  Assert-Contains $source '[ValidateRange(1, 10)]' 'KeepInstallers validation'
  Assert-Contains $source '[int]$KeepInstallers = 2' 'KeepInstallers parameter'
  Assert-Contains $source '[switch]$WhatIf' 'WhatIf parameter'
  Assert-Contains $source '[string]$FixtureRoot' 'fixture-only test root parameter'
  Assert-Contains $source '[int]$TestFailAfter = 0' 'disabled-by-default failure injection parameter'
  Assert-Contains $source '[int]$TestFailDuringRemoveAfter = 0' 'disabled-by-default delete-phase failure injection parameter'
}

function Test-WhatIfDoesNotWrite {
  Prepare-AllowedFixtures
  $tracked = @($fixtureFiles + $rustReleaseStaleFiles + $tauriReleaseStaleFiles + $releaseRootNegativeFixtures + $setupIntermediateFixtures + $oldInstallerPaths)
  Assert-PathsPresent $tracked 'WhatIf fixture set'
  $before = @(Get-PathSnapshot $tracked)
  Add-SnapshotMarkdown $beforeLines 'WhatIf before fixture snapshot/hash' $before
  $result = Invoke-Cleanup @('-FixtureRoot', $fixtureRoot, '-KeepInstallers', '2', '-WhatIf')
  Write-ResultMarkdown $beforeLines 'WhatIf raw output' $result
  Assert-Equal 0 $result.ExitCode 'WhatIf exit code' $result.Output
  Assert-Contains $result.Output 'mode=WHATIF' 'WhatIf marker'
  Assert-Contains $result.Output 'action=whatif-remove' 'WhatIf planned removal'
  foreach ($name in @('contest.exe', 'attest.exe', 'contest-old.exe', 'attest-build.exe')) {
    Assert-NotContains $result.Output $name 'Rust/Tauri release-root negative fixture plan'
  }
  $after = @(Get-PathSnapshot $tracked)
  Add-SnapshotMarkdown $afterLines 'WhatIf after fixture snapshot/hash' $after
  Assert-SnapshotUnchanged $before $after 'WhatIf snapshot'
  Remove-TestResidue
}

function Test-OutsideOutputIsRejected {
  $outside = Join-Path ([IO.Path]::GetPathRoot($repoRoot)) "w35-task6-outside-$PID"
  if (Test-Path -LiteralPath $outside) {
    throw "outside probe path already exists: $outside"
  }
  $result = Invoke-Cleanup @('-OutputRoot', $outside, '-KeepInstallers', '2', '-WhatIf')
  Write-ResultMarkdown $beforeLines 'outside output root rejection raw output' $result
  Assert-Equal 20 $result.ExitCode 'outside output exit code' $result.Output
  Assert-Contains $result.Output 'E_ALLOWLIST' 'outside output error code'
  Assert-True (-not (Test-Path -LiteralPath $outside)) 'outside output was not created'
}

function Test-FailureInjectionIsFixtureOnly {
  foreach ($parameter in @('TestFailAfter', 'TestFailDuringRemoveAfter')) {
    $result = Invoke-Cleanup @("-$parameter", '1', '-WhatIf')
    Write-ResultMarkdown $beforeLines "$parameter without FixtureRoot raw output" $result
    Assert-Equal 24 $result.ExitCode "$parameter without FixtureRoot exit code" $result.Output
    Assert-Contains $result.Output 'E_ARGUMENT' "$parameter without FixtureRoot error code"
  }
}

function Test-ReparseEscapeIsRejected {
  Prepare-AllowedFixtures
  $parent = Split-Path -Parent $reparsePath
  New-Item -ItemType Directory -Path $parent -Force | Out-Null
  Ensure-File (Join-Path $parent "w35-task6-$fixtureId-reparse-sentinel.marker")
  New-Item -ItemType Junction -Path $reparsePath -Target ([IO.Path]::GetPathRoot($repoRoot)) | Out-Null
  try {
    $result = Invoke-Cleanup @('-FixtureRoot', $fixtureRoot, '-KeepInstallers', '2', '-WhatIf')
    Write-ResultMarkdown $beforeLines 'reparse escape rejection raw output' $result
    Assert-Equal 21 $result.ExitCode 'reparse exit code' $result.Output
    Assert-Contains $result.Output 'E_REPARSE' 'reparse error code'
    Assert-True (Test-Path -LiteralPath $reparsePath) 'reparse entry remains after rejection'
  } finally {
    Remove-ReparseFixture
  }
  Remove-TestResidue
}

function Test-UnknownReparseResidueIsRejectedAndRerunnable {
  Prepare-AllowedFixtures
  New-Item -ItemType Junction -Path $unknownReparsePath -Target $fixtureRoot | Out-Null
  $externalBeforeResidue = @(Get-PathSnapshot @($externalSentinel))
  Add-SnapshotMarkdown $beforeLines 'Unknown reparse residue external sentinel before hash' $externalBeforeResidue
  try {
    $rejected = $false
    $rejectionMessage = ''
    try {
      Remove-TestResidue
    } catch {
      $rejected = $true
      $rejectionMessage = [string]$_.Exception.Message
    }
    Write-Host "EXPECTED residue cleanup rejection: $rejectionMessage"
    Assert-True $rejected 'unknown reparse residue cleanup is rejected' $rejectionMessage
    Assert-Contains $rejectionMessage 'reparse point' 'unknown reparse rejection explains reparse point'
    Assert-True (Test-Path -LiteralPath $unknownReparsePath) 'unknown reparse entry remains after rejection'
    $externalAfterRejection = @(Get-PathSnapshot @($externalSentinel))
    Add-SnapshotMarkdown $beforeLines 'Unknown reparse residue external sentinel after rejection hash' $externalAfterRejection
    Assert-SnapshotUnchanged $externalBeforeResidue $externalAfterRejection 'external sentinel after unknown reparse rejection'

    Remove-ReparsePath $unknownReparsePath
    Assert-True (-not (Test-Path -LiteralPath $unknownReparsePath)) 'unknown reparse entry explicitly removed'
    Remove-TestResidue
    Assert-True (-not (Test-Path -LiteralPath $fixtureRoot)) 'ordinary residue cleanup removes fixture root'
    Remove-TestResidue
    Assert-True (-not (Test-Path -LiteralPath $fixtureRoot)) 'rerun after residue cleanup is a no-op'
  } finally {
    Remove-ReparsePath $unknownReparsePath
    if (Test-Path -LiteralPath $fixtureRoot) {
      Remove-TestResidue
    }
  }
}

function Test-ApplyFailureReportsPartial {
  Prepare-AllowedFixtures
  $tracked = @($fixtureFiles + $rustReleaseStaleFiles + $tauriReleaseStaleFiles + $releaseRootNegativeFixtures + $setupIntermediateFixtures + $oldInstallerPaths)
  Assert-PathsPresent $tracked 'partial Apply fixture set'
  $result = Invoke-Cleanup @('-FixtureRoot', $fixtureRoot, '-KeepInstallers', '2', '-TestFailAfter', '3')
  Write-ResultMarkdown $beforeLines 'partial Apply injected-failure raw output' $result
  Assert-Equal 26 $result.ExitCode 'partial Apply exit code' $result.Output
  Assert-Contains $result.Output 'code=E_PARTIAL' 'partial error code'
  Assert-Contains $result.Output 'status=partial' 'partial status'
  Assert-Contains $result.Output 'partial-deleted-count=2' 'partial deleted count'
  Assert-Contains $result.Output 'partial-not-executed-count=33' 'partial not-executed count'
  Assert-Contains $result.Output 'action=test-inject-failure' 'controlled failure injection marker'
  $removeLines = @($result.Output -split "`r?`n" | Where-Object { $_ -match '^W35-T6 action=remove ' })
  Assert-Equal 2 $removeLines.Count 'partial Apply remove count' $result.Output
  Assert-True (-not (Test-Path -LiteralPath $rustDebugDir)) 'partial Apply first plan item removed' $rustDebugDir
  Assert-True (-not (Test-Path -LiteralPath $rustDepsDir)) 'partial Apply second plan item removed' $rustDepsDir
  Assert-True (Test-Path -LiteralPath $rustBuildDir) 'partial Apply failed item remains' $rustBuildDir
  foreach ($path in @($rustReleaseStaleFiles + $tauriReleaseStaleFiles + $releaseRootNegativeFixtures + $setupIntermediateFixtures + $oldInstallerPaths)) {
    Assert-True (Test-Path -LiteralPath $path -PathType Leaf) 'partial Apply later item remains unexecuted' $path
  }
  Remove-TestResidue
}

function Test-DeletePhaseFailureReportsAttemptedUnknown {
  Prepare-AllowedFixtures
  $tracked = @($fixtureFiles + $rustReleaseStaleFiles + $tauriReleaseStaleFiles + $releaseRootNegativeFixtures + $setupIntermediateFixtures + $oldInstallerPaths)
  Assert-PathsPresent $tracked 'delete-phase partial fixture set'
  $result = Invoke-Cleanup @('-FixtureRoot', $fixtureRoot, '-KeepInstallers', '2', '-TestFailDuringRemoveAfter', '3')
  Write-ResultMarkdown $beforeLines 'delete-phase partial injected-failure raw output' $result
  Assert-Equal 26 $result.ExitCode 'delete-phase partial exit code' $result.Output
  Assert-Contains $result.Output 'code=E_PARTIAL' 'delete-phase partial error code'
  Assert-Contains $result.Output 'status=partial' 'delete-phase partial status'
  Assert-Contains $result.Output 'partial-deleted-count=2' 'delete-phase partial deleted count'
  Assert-Contains $result.Output 'partial-attempted-count=3' 'delete-phase partial attempted count'
  Assert-Contains $result.Output 'partial-unknown-count=1' 'delete-phase partial unknown count'
  Assert-Contains $result.Output 'partial-not-executed-count=32' 'delete-phase partial not-executed count'
  Assert-Contains $result.Output 'action=test-inject-during-remove-failure' 'delete-phase controlled failure injection marker'
  Assert-Contains $result.Output "partial-unknown path=$rustBuildDir" 'delete-phase unknown path'
  Assert-NotContains $result.Output "partial-not-executed path=$rustBuildDir" 'delete-phase unknown item is not not-executed'
  $removeLines = @($result.Output -split "`r?`n" | Where-Object { $_ -match '^W35-T6 action=remove ' })
  Assert-Equal 2 $removeLines.Count 'delete-phase partial remove count' $result.Output
  Assert-True (-not (Test-Path -LiteralPath $rustDebugDir)) 'delete-phase first plan item removed' $rustDebugDir
  Assert-True (-not (Test-Path -LiteralPath $rustDepsDir)) 'delete-phase second plan item removed' $rustDepsDir
  Assert-True (Test-Path -LiteralPath $rustBuildDir) 'delete-phase failed directory remains observable' $rustBuildDir
  foreach ($path in @($fixtureFiles[3..9] + $rustReleaseStaleFiles + $tauriReleaseStaleFiles + $releaseRootNegativeFixtures + $setupIntermediateFixtures + $oldInstallerPaths)) {
    Assert-True (Test-Path -LiteralPath $path -PathType Leaf) 'delete-phase later item remains unexecuted' $path
  }
  Remove-TestResidue
}

function Test-ApplyIdempotentSecondCleanup {
  param(
    [object[]]$ProtectedBefore,
    [object[]]$NegativeBefore,
    [object[]]$ExternalBefore
  )

  Assert-True (Test-Path -LiteralPath $fixtureRoot -PathType Container) 'FixtureRoot remains before second Apply' $fixtureRoot
  Assert-PathsPresent $releaseRootNegativeFixtures 'negative fixture set before second Apply'
  Assert-Equal 1 $ExternalBefore.Count 'external sentinel before second Apply snapshot count'
  Add-SnapshotMarkdown $afterLines 'Idempotent Apply before second cleanup protected snapshot/hash' $ProtectedBefore
  Add-SnapshotMarkdown $afterLines 'Idempotent Apply before second cleanup negative fixture snapshot/hash' $NegativeBefore
  Add-SnapshotMarkdown $afterLines 'Idempotent Apply before second cleanup external sentinel/hash' $ExternalBefore

  $result = Invoke-Cleanup @('-FixtureRoot', $fixtureRoot, '-KeepInstallers', '2')
  Write-ResultMarkdown $afterLines 'Idempotent Apply raw output (second cleanup before fixture removal)' $result
  Write-Host 'RAW idempotent Apply second cleanup result:'
  Write-Host $result.Output
  Assert-Equal 0 $result.ExitCode 'idempotent Apply exit code' $result.Output
  Assert-Contains $result.Output 'mode=APPLY' 'idempotent Apply marker'
  Assert-Contains $result.Output 'planned=0' 'idempotent Apply planned count'
  Assert-Contains $result.Output 'deleted=0' 'idempotent Apply deleted count'
  Assert-NotContains $result.Output 'action=remove' 'idempotent Apply removal log'

  $protectedAfter = @(Get-PathSnapshot $protectedPaths)
  $negativeAfter = @(Get-PathSnapshot $releaseRootNegativeFixtures)
  $externalAfter = @(Get-PathSnapshot @($externalSentinel))
  Add-SnapshotMarkdown $afterLines 'Idempotent Apply after second cleanup protected snapshot/hash' $protectedAfter
  Add-SnapshotMarkdown $afterLines 'Idempotent Apply after second cleanup negative fixture snapshot/hash' $negativeAfter
  Add-SnapshotMarkdown $afterLines 'Idempotent Apply after second cleanup external sentinel/hash' $externalAfter

  foreach ($path in $protectedPaths) {
    Assert-LeafSentinel $path 'protected fixture after idempotent Apply'
  }
  Assert-SnapshotUnchanged $ProtectedBefore $protectedAfter 'protected snapshot after idempotent Apply'
  Assert-SnapshotUnchanged $NegativeBefore $negativeAfter 'negative fixture snapshot after idempotent Apply'
  Assert-SnapshotUnchanged $ExternalBefore $externalAfter 'external sentinel snapshot after idempotent Apply'
  Assert-Equal 1 $externalAfter.Count 'external sentinel after second Apply snapshot count'
  Assert-True $externalAfter[0].Present 'external sentinel after second Apply present' $externalSentinel
  Assert-True $externalAfter[0].Leaf 'external sentinel after second Apply leaf' $externalSentinel
  Assert-True (-not [string]::IsNullOrWhiteSpace($externalAfter[0].SHA256)) 'external sentinel after second Apply hash' $externalSentinel
  Write-Host 'PASS second FixtureRoot Apply is idempotent before fixture removal'
}

function Test-AllowedItemsCleanedAndProtectedItemsRemain {
  foreach ($path in $protectedPaths) {
    Assert-True (-not (Test-Path -LiteralPath $path)) 'protected fixture starts absent' $path
  }
  Prepare-AllowedFixtures
  $tracked = @($fixtureFiles + $rustReleaseStaleFiles + $tauriReleaseStaleFiles + $releaseRootNegativeFixtures + $setupIntermediateFixtures + $oldInstallerPaths)
  Assert-PathsPresent $tracked 'Apply fixture set'
  $before = @(Get-PathSnapshot $tracked)
  $beforeProtected = @(Get-PathSnapshot $protectedPaths)
  $beforeExternal = @(Get-PathSnapshot @($externalSentinel))
  Assert-Equal 1 $beforeExternal.Count 'external sentinel before snapshot count'
  Add-SnapshotMarkdown $beforeLines 'Apply before fixture snapshot/hash' $before
  Add-SnapshotMarkdown $beforeLines 'Apply before protected snapshot/hash' $beforeProtected
  Add-SnapshotMarkdown $beforeLines 'Apply before external leaf sentinel' $beforeExternal
  $result = Invoke-Cleanup @('-FixtureRoot', $fixtureRoot, '-KeepInstallers', '2')
  Write-ResultMarkdown $afterLines 'Apply fixture raw output' $result
  Assert-Equal 0 $result.ExitCode 'fixture Apply exit code' $result.Output
  Assert-Contains $result.Output 'mode=APPLY' 'fixture Apply marker'
  Assert-Contains $result.Output 'action=remove' 'fixture removal log'
  Assert-Contains $result.Output 'action=retain' 'retention log'
  foreach ($name in @('contest.exe', 'attest.exe', 'contest-old.exe', 'attest-build.exe')) {
    Assert-NotContains $result.Output $name 'Rust/Tauri release-root negative fixture removal'
  }
  foreach ($path in @($fixtureFiles + $rustReleaseStaleFiles + $tauriReleaseStaleFiles + $setupIntermediateFixtures + $oldInstallerPaths[0..1])) {
    Assert-True (-not (Test-Path -LiteralPath $path)) 'allowed fixture removed' $path
  }
  foreach ($path in $releaseRootNegativeFixtures) {
    Assert-True (Test-Path -LiteralPath $path -PathType Leaf) 'release-root negative fixture retained' $path
  }
  Assert-True (Test-Path -LiteralPath $oldInstallerPaths[2] -PathType Leaf) 'newest installer fixture retained' $oldInstallerPaths[2]
  Assert-True (Test-Path -LiteralPath $protectedPaths[0] -PathType Leaf) 'delivered installer fixture retained' $protectedPaths[0]
  foreach ($path in $protectedPaths) {
    Assert-LeafSentinel $path 'protected fixture after Apply'
  }
  $after = @(Get-PathSnapshot $tracked)
  $afterProtected = @(Get-PathSnapshot $protectedPaths)
  $afterExternal = @(Get-PathSnapshot @($externalSentinel))
  Assert-Equal 1 $afterExternal.Count 'external sentinel after snapshot count'
  Add-SnapshotMarkdown $afterLines 'Apply after fixture snapshot/hash' $after
  Add-SnapshotMarkdown $afterLines 'Apply after protected snapshot/hash' $afterProtected
  Add-SnapshotMarkdown $afterLines 'Apply after external leaf sentinel' $afterExternal
  Assert-SnapshotUnchanged $beforeProtected $afterProtected 'protected snapshot'
  Assert-SnapshotUnchanged $beforeExternal $afterExternal 'external sentinel snapshot'
  Assert-Equal $before[$before.Count - 1].SHA256 $after[$after.Count - 1].SHA256 'newest installer hash'
  $remainingInstallers = @(Get-ChildItem -LiteralPath $releaseDir -File -Force |
    Where-Object { $_.Name -match '^EXV-.+-windows-x64-setup\.exe$' })
  Assert-Equal 2 $remainingInstallers.Count 'installer retention count' $remainingInstallers.Count
  $idempotentBeforeProtected = @(Get-PathSnapshot $protectedPaths)
  $idempotentBeforeNegative = @(Get-PathSnapshot $releaseRootNegativeFixtures)
  $idempotentBeforeExternal = @(Get-PathSnapshot @($externalSentinel))
  Test-ApplyIdempotentSecondCleanup `
    -ProtectedBefore $idempotentBeforeProtected `
    -NegativeBefore $idempotentBeforeNegative `
    -ExternalBefore $idempotentBeforeExternal
  Remove-TestResidue
}

try {
  $externalBefore = @(Test-ExternalSentinelBefore)
  Add-SnapshotMarkdown $beforeLines 'External main-worktree sentinel before hash' $externalBefore
  Test-CanonicalInterface
  Write-Host 'PASS canonical interface'
  Test-WhatIfDoesNotWrite
  Write-Host 'PASS WhatIf does not write'
  Test-OutsideOutputIsRejected
  Write-Host 'PASS outside output is rejected'
  Test-FailureInjectionIsFixtureOnly
  Write-Host 'PASS failure injection is fixture-only'
  Test-ReparseEscapeIsRejected
  Write-Host 'PASS reparse escape is rejected'
  Test-UnknownReparseResidueIsRejectedAndRerunnable
  Write-Host 'PASS unknown reparse residue is rejected and rerunnable'
  Test-ApplyFailureReportsPartial
  Write-Host 'PASS apply failure reports partial'
  Test-DeletePhaseFailureReportsAttemptedUnknown
  Write-Host 'PASS delete-phase failure reports attempted unknown'
  Test-AllowedItemsCleanedAndProtectedItemsRemain
  Write-Host 'PASS allowed items clean and protected items remain'

  $externalAfter = @(Test-ExternalSentinelAfter)
  Assert-SnapshotUnchanged $externalBefore $externalAfter 'external sentinel snapshot'
  Add-SnapshotMarkdown $afterLines 'External main-worktree sentinel after hash' $externalAfter

  $beforeLines.Insert(0, '# W35-Task6 cleanup-before evidence')
  $beforeLines.Insert(1, '')
  $beforeLines.Add('## Boundary notes')
  $beforeLines.Add('')
  $beforeLines.Add('- The script targets only explicit paths and controlled filename patterns inside the linked worktree; it does not touch Windows SCM, `%TEMP%`, the main worktree, or other external state.')
  $beforeLines.Add('- The external sentinel is asserted to be a present leaf before and after testing, with a non-empty SHA256; an empty list is not used as proof of non-deletion.')
  $beforeLines.Add('- Identity, attributes, and reparse state are checked during full-plan preflight and immediately before each deletion; this is controlled single-user path-level protection, not a handle-level sandbox.')
  $beforeLines.Add('')
  $afterLines.Insert(0, '# W35-Task6 cleanup-after evidence')
  $afterLines.Insert(1, '')
  $afterLines.Add('## Governance and status')
  $afterLines.Add('')
  $afterLines.Add('- `validate-common-first-governance.py` and the range gate report `historical_non_authoritative`; the missing lane record/Common manifest is recorded only, not created or forged.')
  $afterLines.Add('- Task6 remains `FLIGHT`; Task7 remains `BLOCKED_BY_TASK`.')
  $afterLines.Add('- Script tests, AST, static checks, governance checks, and `git diff --check` are run before commit.')
  $afterLines.Add('- A path-level TOCTOU boundary remains between identity/reparse recheck and deletion; it is a disclosed, non-blocking controlled single-user limitation.')
  $afterLines.Add('')
  $afterLines.Add('- Fixture-only Apply ran against the controlled .w35-task6-fixture; no real target or product artifact was applied.')
  while ($beforeLines.Count -gt 0 -and [string]::IsNullOrEmpty($beforeLines[$beforeLines.Count - 1])) {
    $beforeLines.RemoveAt($beforeLines.Count - 1)
  }
  while ($afterLines.Count -gt 0 -and [string]::IsNullOrEmpty($afterLines[$afterLines.Count - 1])) {
    $afterLines.RemoveAt($afterLines.Count - 1)
  }
  New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
  Set-Content -LiteralPath $cleanupBeforePath -Value ([string[]]$beforeLines) -Encoding UTF8
  Set-Content -LiteralPath $cleanupAfterPath -Value ([string[]]$afterLines) -Encoding UTF8
  Write-Host ('PASS cleanup-before.md and cleanup-after.md written')
} catch {
  Write-Error $_
  exit 1
} finally {
  if ($null -ne $externalBefore -and $null -eq $externalAfter) {
    try {
      $externalAfter = @(Test-ExternalSentinelAfter)
    } catch {
      Write-Error $_
    }
  }
  Remove-TestResidue
}

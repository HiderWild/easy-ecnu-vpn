param(
  [switch]$ContinueOnFailure
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

$testRoot = Get-FullPath (Split-Path -Parent $PSScriptRoot) 'scripts test root'
$repoRoot = Get-FullPath (Split-Path -Parent $testRoot) 'EXV worktree root'
$scriptPath = Join-Path $repoRoot 'scripts\build-rust-setup.ps1'
$buildDir = Join-Path $repoRoot 'build-setup-rust'
$runtimeRoot = Join-Path $PSScriptRoot ('.runtime-build-rust-setup-{0}' -f $PID)
$fakeBin = Join-Path $runtimeRoot 'bin'
$fakeCmake = Join-Path $fakeBin 'cmake.cmd'
$powershell = (Get-Command powershell -CommandType Application -ErrorAction Stop).Source

function Assert-Equal([int]$Expected, [int]$Actual, [string]$Name, [string]$Output) {
  if ($Expected -ne $Actual) {
    throw "$Name expected exit code $Expected but got $Actual. Output: $Output"
  }
}

function Invoke-BuildScript(
  [hashtable]$Environment = @{},
  [switch]$ConfigureOnly,
  [switch]$UseDefaultVersion
) {
  $savedPath = $env:PATH
  $savedConfigureExit = $env:EXV_TEST_CMAKE_CONFIGURE_EXIT
  $savedBuildExit = $env:EXV_TEST_CMAKE_BUILD_EXIT
  $savedErrorActionPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    $env:PATH = "$fakeBin;$savedPath"
    $env:EXV_TEST_CMAKE_CONFIGURE_EXIT = $Environment['EXV_TEST_CMAKE_CONFIGURE_EXIT']
    $env:EXV_TEST_CMAKE_BUILD_EXIT = $Environment['EXV_TEST_CMAKE_BUILD_EXIT']
    $arguments = @(
      '-NoProfile',
      '-ExecutionPolicy', 'Bypass',
      '-File', $scriptPath,
      '-Jobs', '1'
    )
    if (-not $UseDefaultVersion) {
      $arguments += @('-Version', '3.4.0')
    }
    if ($ConfigureOnly) {
      $arguments += '-ConfigureOnly'
    }
    $output = @(& $powershell @arguments 2>&1 | ForEach-Object { $_.ToString() })
    return [pscustomobject]@{
      ExitCode = [int]$LASTEXITCODE
      Output = ($output -join [Environment]::NewLine)
    }
  } finally {
    $ErrorActionPreference = $savedErrorActionPreference
    $env:PATH = $savedPath
    if ($null -eq $savedConfigureExit) {
      Remove-Item Env:EXV_TEST_CMAKE_CONFIGURE_EXIT -ErrorAction SilentlyContinue
    } else {
      $env:EXV_TEST_CMAKE_CONFIGURE_EXIT = $savedConfigureExit
    }
    if ($null -eq $savedBuildExit) {
      Remove-Item Env:EXV_TEST_CMAKE_BUILD_EXIT -ErrorAction SilentlyContinue
    } else {
      $env:EXV_TEST_CMAKE_BUILD_EXIT = $savedBuildExit
    }
  }
}

function Remove-TestBuildTree {
  if (Test-Path -LiteralPath $buildDir) {
    Remove-Item -LiteralPath $buildDir -Recurse -Force
  }
}

function New-Junction([string]$Path, [string]$Target) {
  New-Item -ItemType Junction -Path $Path -Target $Target -Force | Out-Null
}

function Test-RecursiveReparseRejected {
  Remove-TestBuildTree
  New-Item -ItemType Directory -Path $buildDir | Out-Null
  $target = Join-Path $runtimeRoot 'reparse-target'
  New-Item -ItemType Directory -Path $target | Out-Null
  $link = Join-Path $buildDir 'nested-reparse'
  New-Junction $link $target
  $result = Invoke-BuildScript -ConfigureOnly
  Assert-Equal 1 $result.ExitCode 'recursive reparse rejection' $result.Output
  if ($result.Output -notmatch 'reparse point') {
    throw "recursive reparse rejection did not identify a reparse point: $($result.Output)"
  }
}

function Test-DanglingReparseRejected {
  Remove-TestBuildTree
  New-Item -ItemType Directory -Path $buildDir | Out-Null
  $target = Join-Path $runtimeRoot 'dangling-target'
  New-Item -ItemType Directory -Path $target | Out-Null
  $link = Join-Path $buildDir 'dangling-reparse'
  New-Junction $link $target
  Remove-Item -LiteralPath $target -Recurse -Force
  $result = Invoke-BuildScript -ConfigureOnly
  Assert-Equal 1 $result.ExitCode 'dangling reparse rejection' $result.Output
  if ($result.Output -notmatch 'reparse point') {
    throw "dangling reparse rejection did not identify a reparse point: $($result.Output)"
  }
}

function Test-InaccessibleTreeRejected {
  Remove-TestBuildTree
  New-Item -ItemType Directory -Path $buildDir | Out-Null
  $blocked = Join-Path $buildDir 'inaccessible'
  New-Item -ItemType Directory -Path $blocked | Out-Null
  $originalAcl = Get-Acl -LiteralPath $blocked
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $denyRights = [Security.AccessControl.FileSystemRights]::ListDirectory -bor
    [Security.AccessControl.FileSystemRights]::ReadData -bor
    [Security.AccessControl.FileSystemRights]::ReadAndExecute
  $denyRule = New-Object Security.AccessControl.FileSystemAccessRule(
    $identity,
    $denyRights,
    [Security.AccessControl.InheritanceFlags]::None,
    [Security.AccessControl.PropagationFlags]::None,
    [Security.AccessControl.AccessControlType]::Deny
  )
  try {
    $blockedAcl = Get-Acl -LiteralPath $blocked
    $blockedAcl.AddAccessRule($denyRule)
    Set-Acl -LiteralPath $blocked -AclObject $blockedAcl
    $result = Invoke-BuildScript -ConfigureOnly
    Assert-Equal 1 $result.ExitCode 'inaccessible tree rejection' $result.Output
    if ($result.Output -notmatch 'inaccessible|access') {
      throw "inaccessible tree rejection did not identify inaccessible access: $($result.Output)"
    }
  } finally {
    Set-Acl -LiteralPath $blocked -AclObject $originalAcl
  }
}

function Test-ExistingHardlinkOutputIsNotReused {
  Remove-TestBuildTree
  New-Item -ItemType Directory -Path $buildDir | Out-Null
  $sentinel = Join-Path $runtimeRoot 'hardlink-sentinel.exe'
  [IO.File]::WriteAllBytes($sentinel, [byte[]](0x4d, 0x5a, 0x48, 0x4c))
  foreach ($name in @('exv-setup.exe', 'pack_setup_payload.exe')) {
    New-Item -ItemType HardLink -Path (Join-Path $buildDir $name) -Target $sentinel | Out-Null
  }
  $result = Invoke-BuildScript
  Assert-Equal 1 $result.ExitCode 'existing hardlink output cleanup' $result.Output
  if (Test-Path -LiteralPath (Join-Path $buildDir 'exv-setup.exe')) {
    throw 'clean build strategy left the pre-existing hardlink output in place'
  }
}

function Test-NativeConfigureExitCodePropagates {
  Remove-TestBuildTree
  $result = Invoke-BuildScript @{ EXV_TEST_CMAKE_CONFIGURE_EXIT = '37'; EXV_TEST_CMAKE_BUILD_EXIT = '0' }
  Assert-Equal 37 $result.ExitCode 'configure native exit code' $result.Output
}

function Test-NativeBuildExitCodePropagates {
  Remove-TestBuildTree
  $result = Invoke-BuildScript @{ EXV_TEST_CMAKE_CONFIGURE_EXIT = '0'; EXV_TEST_CMAKE_BUILD_EXIT = '73' }
  Assert-Equal 73 $result.ExitCode 'build native exit code' $result.Output
}

function Test-DefaultVersionIsReadFromTauriConfig {
  Remove-TestBuildTree
  $result = Invoke-BuildScript -ConfigureOnly -UseDefaultVersion
  Assert-Equal 0 $result.ExitCode 'default version configure' $result.Output
  if ($result.Output -notmatch [regex]::Escape('-DEXV_PRODUCT_VERSION=4.0.0')) {
    throw "default version did not come from tauri.conf.json: $($result.Output)"
  }
}

New-Item -ItemType Directory -Path $fakeBin -Force | Out-Null
@'
@echo off
if "%~1"=="--build" (
  if defined EXV_TEST_CMAKE_BUILD_EXIT exit /b %EXV_TEST_CMAKE_BUILD_EXIT%
) else (
  if defined EXV_TEST_CMAKE_CONFIGURE_EXIT exit /b %EXV_TEST_CMAKE_CONFIGURE_EXIT%
)
exit /b 0
'@ | Set-Content -LiteralPath $fakeCmake -Encoding ASCII

try {
  $tests = @(
    @{ Name = 'recursive reparse'; Action = { Test-RecursiveReparseRejected } },
    @{ Name = 'dangling reparse'; Action = { Test-DanglingReparseRejected } },
    @{ Name = 'inaccessible tree'; Action = { Test-InaccessibleTreeRejected } },
    @{ Name = 'existing hardlink output'; Action = { Test-ExistingHardlinkOutputIsNotReused } },
    @{ Name = 'configure exit code'; Action = { Test-NativeConfigureExitCodePropagates } },
    @{ Name = 'build exit code'; Action = { Test-NativeBuildExitCodePropagates } },
    @{ Name = 'default version from Tauri config'; Action = { Test-DefaultVersionIsReadFromTauriConfig } }
  )
  $failures = @()
  foreach ($test in $tests) {
    try {
      & $test.Action
      Write-Host "PASS $($test.Name)"
    } catch {
      $failures += "$($test.Name): $($_.Exception.Message)"
      Write-Host "FAIL $($test.Name): $($_.Exception.Message)"
      if (-not $ContinueOnFailure) {
        throw
      }
    }
  }
  if ($failures.Count -gt 0) {
    throw ('Regression failures: ' + ($failures -join ' | '))
  }
} finally {
  Remove-TestBuildTree
  if (Test-Path -LiteralPath $runtimeRoot) {
    Remove-Item -LiteralPath $runtimeRoot -Recurse -Force
  }
}

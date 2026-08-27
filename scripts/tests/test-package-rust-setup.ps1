param(
  [switch]$ContinueOnFailure
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-FullPath([string]$Candidate, [string]$Label) {
  if ([string]::IsNullOrWhiteSpace($Candidate)) {
    throw "$Label must not be empty"
  }
  return [IO.Path]::GetFullPath($Candidate)
}

function Assert-Equal([int]$Expected, [int]$Actual, [string]$Name, [string]$Output) {
  if ($Expected -ne $Actual) {
    throw "$Name expected exit code $Expected but got $Actual. Output: $Output"
  }
}

function Assert-Contains([string]$Output, [string]$Needle, [string]$Name) {
  if ($Output -notmatch [regex]::Escape($Needle)) {
    throw "$Name did not contain '$Needle'. Output: $Output"
  }
}

$testRoot = Get-FullPath (Split-Path -Parent $PSScriptRoot) 'scripts test root'
$repoRoot = Get-FullPath (Split-Path -Parent $testRoot) 'EXV worktree root'
$scriptPath = Join-Path $repoRoot 'scripts\package-rust-setup.ps1'
$powershell = (Get-Command powershell -CommandType Application -ErrorAction Stop).Source
$runtimeRoot = Join-Path $PSScriptRoot ('.runtime-package-rust-setup-{0}' -f $PID)
$outputDir = Join-Path $repoRoot ("build\release\package-rust-test-{0}" -f $PID)
$payloadDir = Join-Path $outputDir 'rust-payload'
$outsideDir = Join-Path ([IO.Path]::GetPathRoot($repoRoot)) ("exv-outside-project-{0}" -f $PID)
$outsideSetupDir = Join-Path ([IO.Path]::GetPathRoot($repoRoot)) ("exv-outside-setup-{0}" -f $PID)
$fakeToolsDir = Join-Path $runtimeRoot 'tools'

function Invoke-Package([string[]]$Arguments) {
  $savedErrorActionPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    $output = @(& $powershell @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $scriptPath) @Arguments 2>&1 |
      ForEach-Object { $_.ToString() })
    return [pscustomobject]@{
      ExitCode = [int]$LASTEXITCODE
      Output = ($output -join [Environment]::NewLine)
    }
  } finally {
    $ErrorActionPreference = $savedErrorActionPreference
  }
}

function Remove-TestOutput {
  if (Test-Path -LiteralPath $outputDir) {
    Remove-Item -LiteralPath $outputDir -Recurse -Force
  }
}

function Remove-TestRuntime {
  foreach ($path in @($runtimeRoot)) {
    if (Test-Path -LiteralPath $path) {
      Remove-Item -LiteralPath $path -Recurse -Force
    }
  }
}

function New-FakePacker {
  if (Test-Path -LiteralPath (Join-Path $fakeToolsDir 'pack_setup_payload.exe') -PathType Leaf) {
    return
  }
  New-Item -ItemType Directory -Path $fakeToolsDir -Force | Out-Null
  [IO.File]::WriteAllBytes((Join-Path $fakeToolsDir 'exv-setup.exe'), [byte[]](0x4d, 0x5a))
  $source = @'
using System;
using System.IO;

public static class ExvPackageFakePacker {
  public static int Main(string[] args) {
    var exitText = Environment.GetEnvironmentVariable("EXV_TEST_PACKER_EXIT");
    var exitCode = 0;
    if (!String.IsNullOrEmpty(exitText)) {
      Int32.TryParse(exitText, out exitCode);
    }
    if (exitCode == 0) {
      string output = null;
      for (var i = 0; i + 1 < args.Length; ++i) {
        if (args[i] == "--out") {
          output = args[i + 1];
          break;
        }
      }
      if (!String.IsNullOrEmpty(output)) {
        if (Environment.GetEnvironmentVariable("EXV_TEST_PACKER_VALID_PE") == "1") {
          byte[] installer = new byte[128];
          installer[0] = 0x4d;
          installer[1] = 0x5a;
          installer[0x3c] = 0x40;
          installer[0x40] = 0x50;
          installer[0x41] = 0x45;
          byte[] magic = System.Text.Encoding.ASCII.GetBytes("EXVP01");
          Array.Copy(magic, 0, installer, 0x50, magic.Length);
          File.WriteAllBytes(output, installer);
        } else {
          File.WriteAllBytes(output, new byte[] { 0x4d, 0x5a });
        }
        File.WriteAllBytes(output + ".exvp", new byte[] { 0x45, 0x58, 0x56, 0x50, 0x30, 0x31 });
      }
    }
    Console.WriteLine("fake packer exit=" + exitCode);
    return exitCode;
  }
}
'@
  Add-Type -TypeDefinition $source -Language CSharp -OutputType ConsoleApplication -OutputAssembly (Join-Path $fakeToolsDir 'pack_setup_payload.exe')
}

function Invoke-FakePackage([int]$ExitCode) {
  New-FakePacker
  $savedExit = $env:EXV_TEST_PACKER_EXIT
  try {
    $env:EXV_TEST_PACKER_EXIT = [string]$ExitCode
    return Invoke-Package @(
      '-Version', '3.4.0',
      '-SetupToolsDir', $fakeToolsDir,
      '-OutDir', $outputDir,
      '-Compression', 'store',
      '-KeepInstallers', '2'
    )
  } finally {
    if ($null -eq $savedExit) {
      Remove-Item Env:EXV_TEST_PACKER_EXIT -ErrorAction SilentlyContinue
    } else {
      $env:EXV_TEST_PACKER_EXIT = $savedExit
    }
  }
}

function Test-DryRunDoesNotWrite {
  Remove-TestOutput
  New-FakePacker
  $result = Invoke-Package @('-Version', '3.4.0', '-SetupToolsDir', $fakeToolsDir, '-OutDir', $outputDir, '-DryRun')
  Assert-Equal 0 $result.ExitCode 'DryRun' $result.Output
  Assert-Contains $result.Output 'DRY-RUN' 'DryRun marker'
  Assert-Contains $result.Output 'exv-core.exe' 'DryRun source manifest'
  if (Test-Path -LiteralPath $outputDir) {
    throw "DryRun created output directory: $outputDir"
  }
}

function Invoke-ValidFakePackage([string[]]$Arguments) {
  $savedValidInstaller = $env:EXV_TEST_PACKER_VALID_PE
  try {
    $env:EXV_TEST_PACKER_VALID_PE = '1'
    return Invoke-Package $Arguments
  } finally {
    if ($null -eq $savedValidInstaller) {
      Remove-Item Env:EXV_TEST_PACKER_VALID_PE -ErrorAction SilentlyContinue
    } else {
      $env:EXV_TEST_PACKER_VALID_PE = $savedValidInstaller
    }
  }
}

function Test-DryRunUsesTauriDefaultVersion {
  Remove-TestOutput
  New-FakePacker
  $result = Invoke-Package @('-SetupToolsDir', $fakeToolsDir, '-OutDir', $outputDir, '-DryRun')
  Assert-Equal 0 $result.ExitCode 'default version DryRun' $result.Output
  Assert-Contains $result.Output 'EXV-4.0.0-windows-x64-setup.exe' 'default version installer name'
  if (Test-Path -LiteralPath $outputDir) {
    throw "default version DryRun created output directory: $outputDir"
  }
}

function Test-OutsideOutputIsRejected {
  Remove-TestOutput
  if (Test-Path -LiteralPath $outsideDir) {
    throw "outside probe path unexpectedly exists before test: $outsideDir"
  }
  $result = Invoke-Package @('-Version', '3.4.0', '-OutDir', $outsideDir, '-DryRun')
  Assert-Equal 1 $result.ExitCode 'outside output rejection' $result.Output
  Assert-Contains $result.Output 'inside the EXV worktree' 'outside output rejection message'
  if (Test-Path -LiteralPath $outsideDir) {
    throw "outside output rejection created a directory: $outsideDir"
  }
}

function Test-OutsideSetupToolsIsRejected {
  Remove-TestOutput
  if (Test-Path -LiteralPath $outsideSetupDir) {
    throw "outside setup probe path unexpectedly exists before test: $outsideSetupDir"
  }
  $result = Invoke-Package @('-Version', '3.4.0', '-SetupToolsDir', $outsideSetupDir, '-DryRun')
  Assert-Equal 1 $result.ExitCode 'outside setup tools rejection' $result.Output
  Assert-Contains $result.Output 'inside the EXV worktree' 'outside setup tools rejection message'
  if (Test-Path -LiteralPath $outsideSetupDir) {
    throw "outside setup tools rejection created a directory: $outsideSetupDir"
  }
}

function Test-PreflightFailureCleansStaging {
  Remove-TestOutput
  New-Item -ItemType Directory -Path $payloadDir -Force | Out-Null
  [IO.File]::WriteAllBytes((Join-Path $payloadDir 'preflight-marker.bin'), [byte[]](0x50, 0x52, 0x45))
  $missingToolsDir = Join-Path $runtimeRoot 'missing-tools'
  $result = Invoke-Package @('-Version', '3.4.0', '-SetupToolsDir', $missingToolsDir, '-OutDir', $outputDir)
  Assert-Equal 1 $result.ExitCode 'preflight failure' $result.Output
  if (Test-Path -LiteralPath $payloadDir) {
    throw "preflight failure left staging directory: $payloadDir"
  }
}

function Test-PackerExitCodeIsPreservedAndOldInstallerProtected {
  Remove-TestOutput
  New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
  $oldInstaller = Join-Path $outputDir 'EXV-3.3.9-windows-x64-setup.exe'
  $oldArchive = $oldInstaller + '.exvp'
  [IO.File]::WriteAllBytes($oldInstaller, [byte[]](0x4d, 0x5a, 0x4f, 0x4c, 0x44))
  [IO.File]::WriteAllBytes($oldArchive, [byte[]](0x4f, 0x4c, 0x44))
  $oldHash = (Get-FileHash -LiteralPath $oldInstaller -Algorithm SHA256).Hash
  $result = Invoke-FakePackage 37
  Assert-Equal 37 $result.ExitCode 'packer raw exit code' $result.Output
  if (Test-Path -LiteralPath $payloadDir) {
    throw "packer failure left staging directory: $payloadDir"
  }
  foreach ($path in @(
      (Join-Path $outputDir 'EXV-3.4.0-windows-x64-setup.exe'),
      (Join-Path $outputDir 'EXV-3.4.0-windows-x64-setup.exe.exvp'))) {
    if (Test-Path -LiteralPath $path) {
      throw "packer failure left generated file: $path"
    }
  }
  if (-not (Test-Path -LiteralPath $oldInstaller) -or
      (Get-FileHash -LiteralPath $oldInstaller -Algorithm SHA256).Hash -ne $oldHash -or
      -not (Test-Path -LiteralPath $oldArchive)) {
    throw 'packer failure changed a protected old installer or archive'
  }
}

function Test-ValidationFailureCleansGeneratedFiles {
  Remove-TestOutput
  New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
  $oldInstaller = Join-Path $outputDir 'EXV-3.3.8-windows-x64-setup.exe'
  [IO.File]::WriteAllBytes($oldInstaller, [byte[]](0x4d, 0x5a, 0x4f, 0x4c, 0x44))
  $oldHash = (Get-FileHash -LiteralPath $oldInstaller -Algorithm SHA256).Hash
  $result = Invoke-FakePackage 0
  Assert-Equal 1 $result.ExitCode 'validation failure' $result.Output
  if (Test-Path -LiteralPath $payloadDir) {
    throw "validation failure left staging directory: $payloadDir"
  }
  foreach ($path in @(
      (Join-Path $outputDir 'EXV-3.4.0-windows-x64-setup.exe'),
      (Join-Path $outputDir 'EXV-3.4.0-windows-x64-setup.exe.exvp'))) {
    if (Test-Path -LiteralPath $path) {
      throw "validation failure left generated file: $path"
    }
  }
  if (-not (Test-Path -LiteralPath $oldInstaller) -or
      (Get-FileHash -LiteralPath $oldInstaller -Algorithm SHA256).Hash -ne $oldHash) {
    throw 'validation failure changed a protected old installer'
  }
}

function Test-PayloadManifestMagicAndRetention {
  Remove-TestOutput
  New-FakePacker
  New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
  foreach ($name in @(
      'EXV-oldest-windows-x64-setup.exe',
      'EXV-older-windows-x64-setup.exe',
      'EXV-stale-windows-x64-setup.exe')) {
    [IO.File]::WriteAllBytes((Join-Path $outputDir $name), [byte[]](0x4d, 0x5a, 0x53, 0x54))
  }
  (Get-Item -LiteralPath (Join-Path $outputDir 'EXV-oldest-windows-x64-setup.exe')).LastWriteTimeUtc = [DateTime]::UtcNow.AddMinutes(-30)
  (Get-Item -LiteralPath (Join-Path $outputDir 'EXV-older-windows-x64-setup.exe')).LastWriteTimeUtc = [DateTime]::UtcNow.AddMinutes(-20)
  (Get-Item -LiteralPath (Join-Path $outputDir 'EXV-stale-windows-x64-setup.exe')).LastWriteTimeUtc = [DateTime]::UtcNow.AddMinutes(-10)

  $result = Invoke-ValidFakePackage @(
    '-Version', '3.4.0',
    '-SetupToolsDir', $fakeToolsDir,
    '-OutDir', $outputDir,
    '-Compression', 'store',
    '-KeepInstallers', '2'
  )
  Assert-Equal 0 $result.ExitCode 'normal package' $result.Output
  foreach ($name in @('exv-core.exe', 'exv-engine.exe', 'exv-ui.exe', 'wintun.dll')) {
    Assert-Contains $result.Output $name "payload manifest $name"
    Assert-Contains $result.Output 'hash-match' "payload hash $name"
  }
  if (Test-Path -LiteralPath $payloadDir) {
    throw "payload staging directory was not removed: $payloadDir"
  }

  $installer = Join-Path $outputDir 'EXV-3.4.0-windows-x64-setup.exe'
  if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
    throw "installer was not generated: $installer"
  }
  $bytes = [IO.File]::ReadAllBytes($installer)
  if ($bytes.Length -le 0 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
    throw "installer is not a non-empty PE file: $installer"
  }
  $ascii = [Text.Encoding]::ASCII.GetString($bytes)
  Assert-Contains $ascii 'EXVP01' 'installer payload magic'
  Assert-Contains $result.Output 'pe=verified' 'installer PE signature'
  $installers = @(Get-ChildItem -LiteralPath $outputDir -Filter 'EXV-*-windows-x64-setup.exe' -File)
  if ($installers.Count -gt 2) {
    throw "retention kept $($installers.Count) installers instead of at most two"
  }
  Assert-Contains $result.Output 'retained installers=2' 'retention result'
}

function Test-RetentionProtectsCurrentInstallerWithFutureTimestamps {
  Remove-TestOutput
  New-FakePacker
  New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
  foreach ($entry in @(
      @{ Name = 'EXV-future-newest-windows-x64-setup.exe'; Offset = 2 },
      @{ Name = 'EXV-future-older-windows-x64-setup.exe'; Offset = 1 }
    )) {
    $path = Join-Path $outputDir $entry.Name
    [IO.File]::WriteAllBytes($path, [byte[]](0x4d, 0x5a, 0x46, 0x55, 0x54))
    (Get-Item -LiteralPath $path).LastWriteTimeUtc = [DateTime]::UtcNow.AddDays($entry.Offset)
  }

  $result = Invoke-ValidFakePackage @(
    '-Version', '3.4.0',
    '-SetupToolsDir', $fakeToolsDir,
    '-OutDir', $outputDir,
    '-Compression', 'store',
    '-KeepInstallers', '2'
  )
  Assert-Equal 0 $result.ExitCode 'future timestamp retention' $result.Output

  $installer = Join-Path $outputDir 'EXV-3.4.0-windows-x64-setup.exe'
  if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
    throw "successful packaging deleted the current installer: $installer"
  }
  $installers = @(Get-ChildItem -LiteralPath $outputDir -Filter 'EXV-*-windows-x64-setup.exe' -File)
  if ($installers.Count -gt 2) {
    throw "future timestamp retention kept $($installers.Count) installers instead of at most two"
  }
}

try {
  $tests = @(
    @{ Name = 'DryRun does not write'; Action = { Test-DryRunDoesNotWrite } },
    @{ Name = 'DryRun uses Tauri default version'; Action = { Test-DryRunUsesTauriDefaultVersion } },
    @{ Name = 'outside output is rejected'; Action = { Test-OutsideOutputIsRejected } },
    @{ Name = 'outside setup tools is rejected'; Action = { Test-OutsideSetupToolsIsRejected } },
    @{ Name = 'preflight failure cleans staging'; Action = { Test-PreflightFailureCleansStaging } },
    @{ Name = 'packer exit code and old installer protection'; Action = { Test-PackerExitCodeIsPreservedAndOldInstallerProtected } },
    @{ Name = 'validation failure cleans generated files'; Action = { Test-ValidationFailureCleansGeneratedFiles } },
    @{ Name = 'payload manifest, magic and retention'; Action = { Test-PayloadManifestMagicAndRetention } },
    @{ Name = 'retention protects current installer'; Action = { Test-RetentionProtectsCurrentInstallerWithFutureTimestamps } }
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
  Remove-TestOutput
  Remove-TestRuntime
}

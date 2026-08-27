# windows-packaging-smoke.ps1
# Smoke tests for EXV Windows packaging — no real VPN connection required.
# Verifies that binaries, DLLs, IPC, and service infrastructure are present
# and functional before a release candidate is shipped.
#
# Usage:
#   .\scripts\windows-packaging-smoke.ps1 [-PackageRoot <path>] [-RuntimeDir <path>]
#   .\scripts\windows-packaging-smoke.ps1 -InstalledServiceLane [-PackageRoot <path>] [-RuntimeDir <path>]
#
# Requires: PowerShell 5.1+, optionally exv-helper service installed.
# The InstalledServiceLane is opt-in and requires an elevated shell.

param(
    [string]$PackageRoot = "",
    [string]$RuntimeDir = "",
    [switch]$InstalledServiceLane
)

$ErrorActionPreference = "Continue"

# ── Helpers ──────────────────────────────────────────────────────────────────

$script:PassCount = 0
$script:FailCount = 0
$script:SkipCount = 0

function Write-Check {
    param(
        [string]$Id,
        [string]$Name,
        [string]$Result,   # PASS, FAIL, SKIP
        [string]$Detail = ""
    )
    switch ($Result) {
        "PASS" { Write-Host "  [PASS] $Id  $Name" -ForegroundColor Green; $script:PassCount++ }
        "FAIL" { Write-Host "  [FAIL] $Id  $Name" -ForegroundColor Red; if ($Detail) { Write-Host "         $Detail" -ForegroundColor DarkYellow }; $script:FailCount++ }
        "SKIP" { Write-Host "  [SKIP] $Id  $Name" -ForegroundColor Yellow; if ($Detail) { Write-Host "         $Detail" -ForegroundColor DarkGray }; $script:SkipCount++ }
    }
}

function Resolve-StableHelperPath {
    $programData = [Environment]::GetFolderPath('CommonApplicationData')
    if ([string]::IsNullOrWhiteSpace($programData)) {
        return "C:\ProgramData\EXV\Helper\exv-helper.exe"
    }
    return (Join-Path $programData "EXV\Helper\exv-helper.exe")
}

function Convert-ServicePathNameToExecutablePath {
    param([string]$PathName)

    if ([string]::IsNullOrWhiteSpace($PathName)) {
        return $null
    }

    $trimmed = $PathName.Trim()
    if ($trimmed -match '^"([^"]+)"') {
        return $Matches[1]
    }
    if ($trimmed -match '^(.+?\.exe)(?:\s|$)') {
        return $Matches[1]
    }

    return $trimmed
}

function Test-SamePath {
    param(
        [string]$Left,
        [string]$Right
    )

    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) {
        return $false
    }

    try {
        return ([System.IO.Path]::GetFullPath($Left).TrimEnd('\') -ieq
            [System.IO.Path]::GetFullPath($Right).TrimEnd('\'))
    }
    catch {
        return ($Left.TrimEnd('\') -ieq $Right.TrimEnd('\'))
    }
}

function Invoke-ExternalCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 10
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    $startInfo.Arguments = ($Arguments | ForEach-Object {
        $arg = [string]$_
        if ($arg -match '^[A-Za-z0-9._:/\\=-]+$') {
            $arg
        } else {
            '"' + ($arg -replace '"', '\"') + '"'
        }
    }) -join ' '

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        [void]$process.Start()
        $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
        if ($timedOut) {
            try {
                $process.Kill()
            } catch { }
            return [pscustomobject]@{
                ExitCode = -1
                TimedOut = $true
                Output = ""
            }
        }

        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $combined = (($stdout, $stderr) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join "`n"
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            TimedOut = $false
            Output = $combined.Trim()
        }
    }
    finally {
        if ($process) {
            $process.Dispose()
        }
    }
}

function Get-PeImportDllNames {
    param([Parameter(Mandatory = $true)][string]$Path)

    $inspector = Join-Path $repoRoot "scripts\windows_pe_imports.py"
    $result = Invoke-BoundedNativeCommand -FilePath "python" -Arguments @(
        $inspector,
        $Path
    ) -WorkingDirectory $repoRoot -TimeoutSeconds 15
    $resultDetail = (($result.Output, $result.LaunchError) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join "`n"
    if ($result.ExitCode -ne 0 -or $result.TimedOut) {
        return [pscustomobject]@{
            Ok = $false
            Names = @()
            Error = "PE_IMPORT_INSPECTION_FAILED: $resultDetail"
        }
    }
    try {
        # Windows PowerShell 5.1 preserves a top-level JSON array as one nested
        # System.Object[] pipeline item. Explicitly enumerate the parsed value
        # so the inventory has the same flat string shape on PS 5.1 and PS 7.
        $parsedNames = $result.Output | ConvertFrom-Json -ErrorAction Stop
        $names = @($parsedNames | ForEach-Object { $_ })
    } catch {
        return [pscustomobject]@{
            Ok = $false
            Names = @()
            Error = "PE_IMPORT_INSPECTION_FAILED: invalid inspector JSON for $Path"
        }
    }
    if ($names.Count -eq 0 -or
        @($names | Where-Object { $_ -isnot [string] -or $_ -notmatch '(?i)\.dll$' }).Count -gt 0) {
        return [pscustomobject]@{
            Ok = $false
            Names = @()
            Error = "PE_IMPORT_INSPECTION_FAILED: invalid import inventory for $Path"
        }
    }
    return [pscustomobject]@{
        Ok = $true
        Names = @($names | ForEach-Object { $_.ToString().ToLowerInvariant() })
        Error = ""
    }
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Get-HelperServiceSnapshot {
    param(
        [string]$ServiceName,
        [string]$StableHelperExe
    )

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $pathName = $null
    try {
        $serviceInfo = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        if ($serviceInfo) {
            $pathName = $serviceInfo.PathName
        }
    } catch { }

    $serviceExe = Convert-ServicePathNameToExecutablePath $pathName
    $matchesStable = $false
    if ($serviceExe) {
        $matchesStable = Test-SamePath $serviceExe $StableHelperExe
    }

    return [pscustomobject]@{
        Exists = [bool]$service
        Status = if ($service) { [string]$service.Status } else { "" }
        PathName = $pathName
        ExecutablePath = $serviceExe
        MatchesStablePath = $matchesStable
    }
}

function Invoke-HelperProbeJson {
    param(
        [string]$HelperExe,
        [int]$TimeoutSeconds = 5
    )

    if (-not (Test-Path -LiteralPath $HelperExe)) {
        return [pscustomobject]@{
            ExitCode = -2
            TimedOut = $false
            Output = ""
            Json = $null
            Ok = $false
            Error = "Helper executable not found: $HelperExe"
        }
    }

    $result = Invoke-ExternalCommand -FilePath $HelperExe -Arguments @(
        "--probe",
        "--json",
        "--connect-timeout-ms", "750",
        "--response-timeout-ms", "1000"
    ) -TimeoutSeconds $TimeoutSeconds

    $parsed = $null
    $parseError = ""
    if (-not [string]::IsNullOrWhiteSpace($result.Output)) {
        try {
            $parsed = $result.Output | ConvertFrom-Json -ErrorAction Stop
        } catch {
            $parseError = "Probe output was not JSON: $_"
        }
    }

    return [pscustomobject]@{
        ExitCode = $result.ExitCode
        TimedOut = $result.TimedOut
        Output = $result.Output
        Json = $parsed
        Ok = ($result.ExitCode -eq 0 -and $parsed -and $parsed.ok -eq $true)
        Error = $parseError
    }
}

function Get-FileSha256 {
    param([string]$Path)

    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            return ""
        }
        $getFileHash = Get-Command Get-FileHash -ErrorAction SilentlyContinue
        if ($getFileHash) {
            return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        }

        $stream = [System.IO.File]::OpenRead($Path)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($sha256.ComputeHash($stream))).Replace('-', '')
        }
        finally {
            $sha256.Dispose()
            $stream.Dispose()
        }
    } catch {
        return ""
    }
}

function Test-HelperBinaryMatchesPackage {
    param(
        [string]$Id,
        [string]$Name,
        [string]$PackageHelperExe,
        [string]$StableHelperExe,
        [ValidateSet("FAIL", "SKIP")]
        [string]$MismatchResult = "FAIL"
    )

    $packageHash = Get-FileSha256 -Path $PackageHelperExe
    $stableHash = Get-FileSha256 -Path $StableHelperExe
    if ([string]::IsNullOrWhiteSpace($packageHash)) {
        Write-Check $Id $Name "FAIL" "Could not hash packaged helper: $PackageHelperExe"
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($stableHash)) {
        Write-Check $Id $Name $MismatchResult "Host helper service payload is not readable for comparison: $StableHelperExe"
        return $false
    }
    if ($packageHash -ne $stableHash) {
        Write-Check $Id $Name $MismatchResult "Host helper service payload differs from this portable package. Package SHA256: $packageHash; Stable SHA256: $stableHash"
        return $false
    }

    Write-Check $Id $Name "PASS" "SHA256: $stableHash"
    return $true
}

function Test-HelperProbeRetryable {
    param([object]$ProbeResult)

    if (-not $ProbeResult) {
        return $true
    }
    if ($ProbeResult.TimedOut) {
        return $true
    }
    if ($ProbeResult.Json) {
        $status = [string]$ProbeResult.Json.status
        $errorCode = [string]$ProbeResult.Json.error_code
        return ($status -eq "timeout" -or
            $errorCode -eq "connect_failed" -or
            $errorCode -eq "response_timeout" -or
            $errorCode -eq "ipc_timeout")
    }
    return $false
}

function Wait-HelperProbeJson {
    param(
        [string]$HelperExe,
        [int]$TimeoutSeconds = 8
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastResult = $null
    do {
        $lastResult = Invoke-HelperProbeJson -HelperExe $HelperExe
        if ($lastResult -and $lastResult.Ok) {
            return $lastResult
        }
        if (-not (Test-HelperProbeRetryable -ProbeResult $lastResult)) {
            return $lastResult
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    return $lastResult
}

function Wait-HelperServiceStatus {
    param(
        [string]$ServiceName,
        [string]$Status,
        [int]$TimeoutSeconds = 20
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and [string]$service.Status -eq $Status) {
            return $true
        }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

function Write-HelperProbeCheck {
    param(
        [string]$Id,
        [string]$Name,
        [object]$ProbeResult,
        [switch]$FailWhenUnavailable
    )

    if ($ProbeResult -and $ProbeResult.Ok) {
        Write-Check $Id $Name "PASS" "Output: $($ProbeResult.Output)"
        return $true
    }

    $detail = if ($ProbeResult) {
        if ($ProbeResult.TimedOut) {
            "Probe command timed out"
        } elseif ($ProbeResult.Error) {
            $ProbeResult.Error
        } else {
            "Exit: $($ProbeResult.ExitCode), Output: $($ProbeResult.Output)"
        }
    } else {
        "Probe was not run"
    }

    if ($FailWhenUnavailable) {
        Write-Check $Id $Name "FAIL" $detail
    } else {
        Write-Check $Id $Name "SKIP" $detail
    }
    return $false
}

function Invoke-InstalledServiceLane {
    param(
        [string]$ServiceName,
        [string]$PackageHelperExe,
        [string]$StableHelperExe
    )

    Write-Host ""
    Write-Host "--- Installed Helper Service Lane (opt-in) ---" -ForegroundColor Yellow

    if (-not (Test-IsAdministrator)) {
        Write-Check "S08.admin" "Installed-service lane elevation preflight" "FAIL" "Run this opt-in lane from an elevated PowerShell session"
        return
    }
    Write-Check "S08.admin" "Installed-service lane elevation preflight" "PASS"

    if (-not (Test-Path -LiteralPath $PackageHelperExe)) {
        Write-Check "S08.admin.helper" "Packaged helper available for installed-service lane" "FAIL" "Not found at $PackageHelperExe"
        return
    }
    Write-Check "S08.admin.helper" "Packaged helper available for installed-service lane" "PASS" "Path: $PackageHelperExe"

    $initialSnapshot = Get-HelperServiceSnapshot -ServiceName $ServiceName -StableHelperExe $StableHelperExe
    $installedBySmoke = $false

    try {
        if ($initialSnapshot.Exists) {
            Write-Check "S08.admin.snapshot" "Existing helper service snapshot" "PASS" "Status: $($initialSnapshot.Status), Path: $($initialSnapshot.PathName)"
            if (-not $initialSnapshot.MatchesStablePath) {
                Write-Check "S08.admin.path" "Existing helper service path ownership" "FAIL" "Refusing to replace mismatched service. Expected stable path: $StableHelperExe. Actual: $($initialSnapshot.PathName)"
                return
            }
        } else {
            Write-Check "S08.admin.snapshot" "Existing helper service snapshot" "PASS" "Service '$ServiceName' is absent; smoke may install and later clean up its own service"
            $installResult = Invoke-ExternalCommand -FilePath $PackageHelperExe -Arguments @("--install-service") -TimeoutSeconds 60
            if ($installResult.ExitCode -ne 0 -or $installResult.TimedOut) {
                Write-Check "S08.admin.install" "Install helper service for opt-in lane" "FAIL" "Exit: $($installResult.ExitCode), TimedOut: $($installResult.TimedOut), Output: $($installResult.Output)"
                $failedInstallSnapshot = Get-HelperServiceSnapshot -ServiceName $ServiceName -StableHelperExe $StableHelperExe
                if ($failedInstallSnapshot.Exists -and $failedInstallSnapshot.MatchesStablePath) {
                    $installedBySmoke = $true
                    Write-Check "S08.admin.install.snapshot" "Post-failed-install helper service snapshot" "PASS" "Stable-path service now exists; cleanup will treat it as smoke-owned. Status: $($failedInstallSnapshot.Status), Path: $($failedInstallSnapshot.PathName)"
                } elseif ($failedInstallSnapshot.Exists) {
                    Write-Check "S08.admin.install.snapshot" "Post-failed-install helper service snapshot" "PASS" "A mismatched service appeared and will not be cleaned by smoke. Expected stable path: $StableHelperExe. Actual: $($failedInstallSnapshot.PathName)"
                } else {
                    Write-Check "S08.admin.install.snapshot" "Post-failed-install helper service snapshot" "PASS" "Service remains absent after failed install"
                }
                return
            }
            $installedBySmoke = $true
            Write-Check "S08.admin.install" "Install helper service for opt-in lane" "PASS" "Output: $($installResult.Output)"
        }

        $currentSnapshot = Get-HelperServiceSnapshot -ServiceName $ServiceName -StableHelperExe $StableHelperExe
        if (-not $currentSnapshot.Exists) {
            Write-Check "S08.admin.present" "Helper service present before restart probe" "FAIL" "Service was not present after install/snapshot"
            return
        }
        if (-not $currentSnapshot.MatchesStablePath) {
            Write-Check "S08.admin.present" "Helper service stable path before restart probe" "FAIL" "Refusing to operate on mismatched service path: $($currentSnapshot.PathName)"
            return
        }
        Write-Check "S08.admin.present" "Helper service stable path before restart probe" "PASS" "Path: $($currentSnapshot.PathName)"

        if (-not (Test-HelperBinaryMatchesPackage -Id "S08.admin.hash" -Name "Stable helper matches packaged helper" -PackageHelperExe $PackageHelperExe -StableHelperExe $StableHelperExe)) {
            return
        }

        if ($currentSnapshot.Status -ne "Running") {
            try {
                Start-Service -Name $ServiceName -ErrorAction Stop
            } catch {
                Write-Check "S08.admin.start" "Start helper service before probe" "FAIL" "Exception: $_"
                return
            }
            if (-not (Wait-HelperServiceStatus -ServiceName $ServiceName -Status "Running" -TimeoutSeconds 20)) {
                Write-Check "S08.admin.start" "Start helper service before probe" "FAIL" "Service did not reach Running"
                return
            }
        }
        Write-Check "S08.admin.start" "Start helper service before probe" "PASS"

        $beforeProbe = Wait-HelperProbeJson -HelperExe $StableHelperExe
        if (-not (Write-HelperProbeCheck -Id "S08.admin.probe.before" -Name "Helper probe before service restart" -ProbeResult $beforeProbe -FailWhenUnavailable)) {
            return
        }

        try {
            Restart-Service -Name $ServiceName -Force -ErrorAction Stop
        } catch {
            Write-Check "S08.admin.restart" "Controlled helper service restart" "FAIL" "Exception: $_"
            return
        }
        if (-not (Wait-HelperServiceStatus -ServiceName $ServiceName -Status "Running" -TimeoutSeconds 20)) {
            Write-Check "S08.admin.restart" "Controlled helper service restart" "FAIL" "Service did not return to Running"
            return
        }
        Write-Check "S08.admin.restart" "Controlled helper service restart" "PASS"

        $afterProbe = Wait-HelperProbeJson -HelperExe $StableHelperExe
        [void](Write-HelperProbeCheck -Id "S08.admin.probe.after" -Name "Helper probe after service restart" -ProbeResult $afterProbe -FailWhenUnavailable)
    }
    finally {
        if ($installedBySmoke) {
            $cleanupSnapshot = Get-HelperServiceSnapshot -ServiceName $ServiceName -StableHelperExe $StableHelperExe
            if (-not $cleanupSnapshot.Exists) {
                Write-Check "S08.admin.cleanup" "Cleanup helper service installed by smoke" "PASS" "Service is already absent"
            } elseif (-not $cleanupSnapshot.MatchesStablePath) {
                Write-Check "S08.admin.cleanup" "Cleanup helper service installed by smoke" "FAIL" "Refusing cleanup because helper service path no longer matches stable path. Expected: $StableHelperExe. Actual: $($cleanupSnapshot.PathName)"
            } else {
                $cleanupResult = Invoke-ExternalCommand -FilePath $PackageHelperExe -Arguments @("--uninstall-service") -TimeoutSeconds 60
                if ($cleanupResult.ExitCode -eq 0 -and -not $cleanupResult.TimedOut) {
                    Write-Check "S08.admin.cleanup" "Cleanup helper service installed by smoke" "PASS" "Output: $($cleanupResult.Output)"
                } else {
                    Write-Check "S08.admin.cleanup" "Cleanup helper service installed by smoke" "FAIL" "Exit: $($cleanupResult.ExitCode), TimedOut: $($cleanupResult.TimedOut), Output: $($cleanupResult.Output)"
                }
            }
        }
    }
}

# ── Resolve paths ────────────────────────────────────────────────────────────

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path -Parent $scriptDir

$releaseScript = Join-Path $repoRoot "scripts\package-windows-release.ps1"
$jobRunnerModule = New-Module -ScriptBlock {
    param([string]$ScriptPath)
    . $ScriptPath -FunctionsOnly
    Export-ModuleMember -Function Invoke-BoundedNativeCommand
} -ArgumentList $releaseScript
Import-Module $jobRunnerModule -Function Invoke-BoundedNativeCommand -ErrorAction Stop

if (-not $PackageRoot) { $PackageRoot = Join-Path $repoRoot "build\windows\webview\package\EXV" }
$uiShellExe    = Join-Path $PackageRoot "exv-ui.exe"
$exvExe        = Join-Path $PackageRoot "bin\exv.exe"
$exvHelperExe  = Join-Path $PackageRoot "bin\exv-helper.exe"
$stableHelperExe = Resolve-StableHelperPath

$script:RuntimeSearchDirs = New-Object System.Collections.Generic.List[string]
function Add-RuntimeSearchDir {
    param([string]$Path)
    if (-not $Path) { return }
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if (-not $script:RuntimeSearchDirs.Contains($resolved)) {
        [void]$script:RuntimeSearchDirs.Add($resolved)
    }
}

Add-RuntimeSearchDir $PackageRoot
Add-RuntimeSearchDir (Join-Path $PackageRoot "bin")
if ($RuntimeDir) {
    Add-RuntimeSearchDir $RuntimeDir
    Add-RuntimeSearchDir (Join-Path $RuntimeDir "win32-x64")
}

Write-Host ""
Write-Host "=== EXV Windows Packaging Smoke Tests ===" -ForegroundColor Cyan
Write-Host "Package root: $PackageRoot"
Write-Host "Stable helper: $stableHelperExe"
Write-Host "Runtime dirs: $($script:RuntimeSearchDirs -join '; ')"
Write-Host ""

# ── 1. Binary presence ───────────────────────────────────────────────────────

Write-Host "--- Binaries ---" -ForegroundColor Yellow

if (Test-Path $uiShellExe) {
    Write-Check "S00" "exv-ui.exe present" "PASS"
} else {
    Write-Check "S00" "exv-ui.exe present" "FAIL" "Not found at $uiShellExe"
}

if (Test-Path $exvExe) {
    Write-Check "S01" "exv.exe present" "PASS"
} else {
    Write-Check "S01" "exv.exe present" "FAIL" "Not found at $exvExe"
}

if (Test-Path $exvHelperExe) {
    Write-Check "S02" "exv-helper.exe present" "PASS"
} else {
    Write-Check "S02" "exv-helper.exe present" "FAIL" "Not found at $exvHelperExe"
}

# ── 2. Runtime DLLs ──────────────────────────────────────────────────────────

Write-Host ""
Write-Host "--- Runtime DLLs ---" -ForegroundColor Yellow

$requiredDlls = @(
    "WebView2Loader.dll"
)

$nativeDriverDlls = @(
    "wintun.dll"
)

foreach ($dll in $requiredDlls) {
    # Check in build dir first, then runtime dir
    $found = $false
    foreach ($sp in $script:RuntimeSearchDirs) {
        if (Test-Path (Join-Path $sp $dll)) { $found = $true; break }
    }
    if ($found) {
        Write-Check "S03.$dll" "$dll present" "PASS"
    } else {
        Write-Check "S03.$dll" "$dll present" "FAIL" "Not found in runtime search dirs"
    }
}

foreach ($dll in $nativeDriverDlls) {
    $found = $false
    foreach ($sp in $script:RuntimeSearchDirs) {
        if (Test-Path (Join-Path $sp $dll)) { $found = $true; break }
    }
    if ($found) {
        Write-Check "S03.$dll" "$dll present" "PASS"
    } else {
        Write-Check "S03.$dll" "$dll present" "FAIL" "Required native Wintun runtime asset not found in runtime search dirs"
    }
}

# ── 2b. Package policy ───────────────────────────────────────────────────────

Write-Host ""
Write-Host "--- WebView Package Policy ---" -ForegroundColor Yellow

if (Test-Path -LiteralPath $PackageRoot) {
    $electronPayload = Get-ChildItem -Path $PackageRoot -Recurse -Include electron.exe,chromium.pak -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($electronPayload) {
        Write-Check "S03.policy" "No Electron payload in WebView package" "FAIL" "Found $($electronPayload.FullName)"
    } else {
        Write-Check "S03.policy" "No Electron payload in WebView package" "PASS"
    }

    try {
        $verifyScript = Join-Path $repoRoot "scripts\package_ui_shell.py"
        $verifyOutput = & python $verifyScript --verify-launch-targets-only --package-dir $PackageRoot 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Check "S03.args" "exv-ui launch arguments target packaged binaries" "PASS" "Output: $verifyOutput"
        } else {
            Write-Check "S03.args" "exv-ui launch arguments target packaged binaries" "FAIL" "Exit: $LASTEXITCODE, Output: $verifyOutput"
        }
    } catch {
        Write-Check "S03.args" "exv-ui launch arguments target packaged binaries" "FAIL" "Exception: $_"
    }
} else {
    Write-Check "S03.policy" "No Electron payload in WebView package" "FAIL" "Package root not found at $PackageRoot"
    Write-Check "S03.args" "exv-ui launch arguments target packaged binaries" "SKIP" "Package root not found"
}

# ── 3. exv --version ─────────────────────────────────────────────────────────

Write-Host ""
Write-Host "--- exv CLI ---" -ForegroundColor Yellow

if (Test-Path $exvExe) {
    try {
        $versionResult = Invoke-ExternalCommand -FilePath $exvExe -Arguments @("--version") -TimeoutSeconds 10
        if ($versionResult.ExitCode -eq 0 -and $versionResult.Output) {
            Write-Check "S04" "exv --version" "PASS" "Output: $($versionResult.Output)"
        } elseif ($versionResult.TimedOut) {
            Write-Check "S04" "exv --version" "FAIL" "Command timed out"
        } else {
            Write-Check "S04" "exv --version" "FAIL" "Exit code: $($versionResult.ExitCode), Output: $($versionResult.Output)"
        }
    } catch {
        Write-Check "S04" "exv --version" "FAIL" "Exception: $_"
    }
} else {
    Write-Check "S04" "exv --version" "SKIP" "exv.exe not found"
}

# ── 4. service status ────────────────────────────────────────────────────────

Write-Host ""
Write-Host "--- Service Status ---" -ForegroundColor Yellow

if (Test-Path $exvExe) {
    try {
        $svcResult = Invoke-ExternalCommand -FilePath $exvExe -Arguments @("desktop-rpc", "service.status", "{}") -TimeoutSeconds 10
        if ($svcResult.ExitCode -eq 0) {
            Write-Check "S05" "desktop-rpc service.status" "PASS" "Output: $($svcResult.Output)"
        } elseif ($svcResult.TimedOut) {
            Write-Check "S05" "desktop-rpc service.status" "SKIP" "Service status probe timed out"
        } else {
            Write-Check "S05" "desktop-rpc service.status" "SKIP" "Service not installed or not running (exit $($svcResult.ExitCode)). Output: $($svcResult.Output)"
        }
    } catch {
        Write-Check "S05" "desktop-rpc service.status" "SKIP" "Exception: $_"
    }
} else {
    Write-Check "S05" "desktop-rpc service.status" "SKIP" "exv.exe not found"
}

# ── 5. Helper service command path ───────────────────────────────────────────

Write-Host ""
Write-Host "--- Helper Service Registration ---" -ForegroundColor Yellow

$serviceName = "exv-helper"
$svcQuery = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
$stableHelperServiceReady = $false
if ($svcQuery -and $svcQuery.Status -eq "Running") {
    $binPath = $null
    try {
        $serviceInfo = Get-WmiObject Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
        if ($serviceInfo) {
            $binPath = $serviceInfo.PathName
        }
    } catch { }
    $serviceExe = Convert-ServicePathNameToExecutablePath $binPath
    if ($serviceExe -and (Test-SamePath $serviceExe $stableHelperExe) -and (Test-Path -LiteralPath $stableHelperExe)) {
        $stableHelperServiceReady = $true
        Write-Check "S06" "Helper service binary path correct" "PASS" "Path: $binPath"
    } elseif ($serviceExe -and (Test-SamePath $serviceExe $stableHelperExe)) {
        Write-Check "S06" "Helper service binary path correct" "SKIP" "Host service points to stable helper, but the payload is not present yet. Run service repair/install before host-service validation: $stableHelperExe"
    } elseif ($binPath) {
        Write-Check "S06" "Helper service binary path correct" "SKIP" "Existing host helper service uses a legacy path. Run service repair/install to migrate it to $stableHelperExe. Actual: $binPath"
    } else {
        Write-Check "S06" "Helper service binary path correct" "SKIP" "Helper service is running, but SCM path could not be inspected"
    }
} elseif ($svcQuery) {
    Write-Check "S06" "Helper service binary path correct" "SKIP" "Service '$serviceName' is installed but not running ($($svcQuery.Status))"
} else {
    Write-Check "S06" "Helper service binary path correct" "SKIP" "Service '$serviceName' not installed"
}

$stableHelperDir = Split-Path -Parent $stableHelperExe
$mingwRuntimeDlls = @(
    "libgcc_s_seh-1.dll",
    "libstdc++-6.dll",
    "libwinpthread-1.dll"
)
$packagedHelperImports = Get-PeImportDllNames -Path $exvHelperExe
$packagedHelperHash = Get-FileSha256 -Path $exvHelperExe
$stableHelperHash = Get-FileSha256 -Path $stableHelperExe
$stableHelperPayloadMatchesPackage = (
    $stableHelperServiceReady -and
    -not [string]::IsNullOrWhiteSpace($packagedHelperHash) -and
    -not [string]::IsNullOrWhiteSpace($stableHelperHash) -and
    $packagedHelperHash -eq $stableHelperHash
)
$stableHelperRuntimeDlls = @("wintun.dll")
if ($packagedHelperImports.Ok) {
    $stableHelperRuntimeDlls += @(
        $mingwRuntimeDlls | Where-Object { $packagedHelperImports.Names -icontains $_ }
    )
    Write-Check "S06.imports" "Packaged Helper PE imports inspected" "PASS"
} else {
    Write-Check "S06.imports" "Packaged Helper PE imports inspected" "FAIL" $packagedHelperImports.Error
}
foreach ($dll in $stableHelperRuntimeDlls) {
    $stableHelperDll = Join-Path $stableHelperDir $dll
    $packagedDllFound = $false
    foreach ($sp in $script:RuntimeSearchDirs) {
        if (Test-Path (Join-Path $sp $dll)) { $packagedDllFound = $true; break }
    }
    if ($packagedDllFound -and $stableHelperServiceReady -and $stableHelperPayloadMatchesPackage) {
        if (Test-Path -LiteralPath $stableHelperDll) {
            Write-Check "S06.$dll" "Stable helper $dll present" "PASS" "Path: $stableHelperDll"
        } else {
            $missingDetail = if ($dll -eq "wintun.dll") {
                "Required native Wintun runtime asset is missing from stable helper payload: $stableHelperDll"
            } else {
                "Required stable helper runtime DLL is missing: $stableHelperDll"
            }
            Write-Check "S06.$dll" "Stable helper $dll present" "FAIL" $missingDetail
        }
    } elseif ($packagedDllFound -and $stableHelperServiceReady) {
        Write-Check "S06.$dll" "Stable helper $dll present" "SKIP" "Host helper payload differs from this portable package; its runtime directory is not current-package evidence"
    } elseif ($packagedDllFound -and $svcQuery) {
        Write-Check "S06.$dll" "Stable helper $dll present" "SKIP" "Host helper service is not currently using a complete stable helper payload"
    } else {
        Write-Check "S06.$dll" "Stable helper $dll present" "SKIP" "Helper service is not installed"
    }
}
if ($packagedHelperImports.Ok) {
    foreach ($dll in $mingwRuntimeDlls) {
        if ($packagedHelperImports.Names -icontains $dll) {
            continue
        }
        $stableHelperDll = Join-Path $stableHelperDir $dll
        if (-not $stableHelperServiceReady) {
            Write-Check "S06.surplus.$dll" "Stable helper excludes unimported $dll" "SKIP" "Helper service is not installed/running"
        } elseif (-not $stableHelperPayloadMatchesPackage) {
            Write-Check "S06.surplus.$dll" "Stable helper excludes unimported $dll" "SKIP" "Host helper payload differs from this portable package; its runtime directory is not current-package evidence"
        } elseif (Test-Path -LiteralPath $stableHelperDll) {
            Write-Check "S06.surplus.$dll" "Stable helper excludes unimported $dll" "FAIL" "Unimported MinGW runtime remains in stable Helper payload: $stableHelperDll"
        } else {
            Write-Check "S06.surplus.$dll" "Stable helper excludes unimported $dll" "PASS"
        }
    }
}

# ── 6. Helper Hello / IPC test ───────────────────────────────────────────────

Write-Host ""
Write-Host "--- Helper IPC ---" -ForegroundColor Yellow

$helperProbeResult = $null
if (Test-Path $exvHelperExe) {
    if ($stableHelperServiceReady) {
        $stableHelperPayloadMatchesPackage = Test-HelperBinaryMatchesPackage -Id "S06.hash" -Name "Stable helper matches packaged helper" -PackageHelperExe $exvHelperExe -StableHelperExe $stableHelperExe -MismatchResult "SKIP"
        if ($stableHelperPayloadMatchesPackage) {
            $helperProbeResult = Wait-HelperProbeJson -HelperExe $stableHelperExe
            [void](Write-HelperProbeCheck -Id "S07" -Name "Helper Hello handshake (IPC)" -ProbeResult $helperProbeResult -FailWhenUnavailable)
        } else {
            Write-Check "S07" "Helper Hello handshake (IPC)" "SKIP" "Host helper service payload differs from this portable package; portable smoke will not probe or modify it"
        }
    } elseif ($svcQuery -and $svcQuery.Status -eq "Running") {
        Write-Check "S07" "Helper Hello handshake (IPC)" "SKIP" "A helper service is running, but it is not the stable service payload validated by S06"
    } else {
        Write-Check "S07" "Helper Hello handshake (IPC)" "SKIP" "Helper service is not installed/running; portable smoke remains non-destructive"
    }
} else {
    Write-Check "S07" "Helper Hello handshake (IPC)" "SKIP" "exv-helper.exe not found"
}

# ── 7. Helper protocol capabilities ─────────────────────────────────────────

Write-Host ""
Write-Host "--- Helper Protocol Capabilities ---" -ForegroundColor Yellow

if ($helperProbeResult -and $helperProbeResult.Ok) {
    $capabilities = @($helperProbeResult.Json.capabilities)
    if ($capabilities.Count -gt 0) {
        Write-Check "S08" "Helper protocol capabilities" "PASS" "Capabilities: $($capabilities -join ', ')"
    } else {
        Write-Check "S08" "Helper protocol capabilities" "FAIL" "Ready helper probe did not report capabilities"
    }
} elseif ($stableHelperServiceReady -and $stableHelperPayloadMatchesPackage) {
    Write-Check "S08" "Helper protocol capabilities" "FAIL" "Stable helper service was ready, but the helper probe failed"
} elseif ($stableHelperServiceReady) {
    Write-Check "S08" "Helper protocol capabilities" "SKIP" "Host helper service payload differs from this portable package; portable smoke does not use it as package evidence"
} else {
    Write-Check "S08" "Helper protocol capabilities" "SKIP" "Helper service is not installed/running; portable smoke remains non-destructive"
}

if ($InstalledServiceLane) {
    Invoke-InstalledServiceLane -ServiceName $serviceName -PackageHelperExe $exvHelperExe -StableHelperExe $stableHelperExe
}

# ── 8. desktop-rpc status ────────────────────────────────────────────────────

Write-Host ""
Write-Host "--- App Status ---" -ForegroundColor Yellow

Write-Check "S09" "exv status" "SKIP" "Release smoke does not run exv status because it can start a persistent core/backend from the temporary package"

# ── 9. Built-in uninstall command exists ─────────────────────────────────────

Write-Host ""
Write-Host "--- Uninstall Mechanism ---" -ForegroundColor Yellow

Write-Check "S10" "Uninstall mechanism available" "SKIP" "Portable smoke runs before NSIS; installer packaging validates the uninstaller"

# ── Summary ──────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "=== Smoke Test Summary ===" -ForegroundColor Cyan
Write-Host "  PASS: $script:PassCount" -ForegroundColor Green
Write-Host "  FAIL: $script:FailCount" -ForegroundColor $(if ($script:FailCount -gt 0) { "Red" } else { "DarkGray" })
Write-Host "  SKIP: $script:SkipCount" -ForegroundColor Yellow
Write-Host ""

if ($script:FailCount -gt 0) {
    Write-Host "RESULT: FAIL — $script:FailCount check(s) failed" -ForegroundColor Red
    exit 1
} elseif ($script:SkipCount -gt 0) {
    Write-Host "RESULT: PASS (with $script:SkipCount skipped)" -ForegroundColor Yellow
    exit 0
} else {
    Write-Host "RESULT: ALL PASS" -ForegroundColor Green
    exit 0
}

# run-tests.ps1 - Local test runner for EXV
param(
    [string]$Preset = "windows-release",
    [string]$Label = "",
    [switch]$ListLabels,
    [switch]$Diagnostics,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

Write-Host "=== EXV Test Runner ===" -ForegroundColor Cyan
Write-Host "Preset: $Preset"

# List labels mode: configure, build, then show available labels
if ($ListLabels) {
    Write-Host "`n--- Configuring ---" -ForegroundColor Yellow
    cmake --preset $Preset
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed" }

    Write-Host "`n--- Available test labels ---" -ForegroundColor Yellow
    $buildDir = ""
    switch ($Preset) {
        "windows-release" { $buildDir = Join-Path $repoRoot "build-windows/cpp" }
        "linux-release"   { $buildDir = Join-Path $repoRoot "build/linux/cpp" }
        "macos-release"   { $buildDir = Join-Path $repoRoot "build/macos/cpp" }
    }

    if ($buildDir -and (Test-Path $buildDir)) {
        Push-Location $buildDir
        $tests = ctest --show-only=json-v1 2>$null | ConvertFrom-Json
        $labels = @{}
        foreach ($test in $tests.tests) {
            if ($test.properties.LABELS) {
                foreach ($lbl in $test.properties.LABELS) {
                    if (-not $labels.ContainsKey($lbl)) { $labels[$lbl] = @() }
                    $labels[$lbl] += $test.name
                }
            }
        }
        Pop-Location

        foreach ($lbl in ($labels.Keys | Sort-Object)) {
            $count = $labels[$lbl].Count
            Write-Host "`n  [$lbl] ($count tests)" -ForegroundColor Green
            foreach ($t in $labels[$lbl]) {
                Write-Host "    - $t"
            }
        }
    } else {
        Write-Host "Build directory not found. Run configure first." -ForegroundColor Red
    }
    exit 0
}

# Diagnostic mode: check DLL dependencies before running tests
if ($Diagnostics) {
    $diagScript = Join-Path $scriptDir "diagnose-mingw-dlls.ps1"
    if (Test-Path $diagScript) {
        Write-Host "`n--- DLL Dependency Diagnostic ---" -ForegroundColor Yellow
        switch ($Preset) {
            "windows-release" { & $diagScript -BuildDir "build-windows/cpp" }
            default { Write-Host "Diagnostics only supported on Windows preset." -ForegroundColor Yellow }
        }
    } else {
        Write-Host "Diagnostic script not found: $diagScript" -ForegroundColor Yellow
    }
}

# Configure
Write-Host "`n--- Configuring ---" -ForegroundColor Yellow
cmake --preset $Preset
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed" }

# Build
Write-Host "`n--- Building ---" -ForegroundColor Yellow
cmake --build --preset $Preset
if ($LASTEXITCODE -ne 0) { throw "Build failed" }

# Test
Write-Host "`n--- Running Tests ---" -ForegroundColor Yellow
$ctestArgs = @("--preset", $Preset, "--output-on-failure")
if ($Label) {
    $ctestArgs += "-L"
    $ctestArgs += $Label
}
ctest @ctestArgs
$testResult = $LASTEXITCODE

# Summary
Write-Host "`n=== Results ===" -ForegroundColor Cyan
if ($testResult -eq 0) {
    Write-Host "All tests passed!" -ForegroundColor Green
} else {
    Write-Host "Some tests failed. Check Testing/Temporary/LastTest.log" -ForegroundColor Red
}

exit $testResult

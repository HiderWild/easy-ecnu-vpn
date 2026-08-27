# diagnose-mingw-dlls.ps1 - Windows DLL dependency diagnostic for test executables
#
# For each test executable in the build directory, checks DLL dependencies
# using dumpbin (MSVC) or objdump (MinGW). Reports missing DLLs and their
# expected toolchain paths.
#
# Usage:
#   pwsh scripts/diagnose-mingw-dlls.ps1
#   pwsh scripts/diagnose-mingw-dlls.ps1 -BuildDir build-windows/cpp

param(
    [string]$BuildDir = "build-windows/cpp"
)

$ErrorActionPreference = "Continue"

Write-Host "=== MinGW DLL Dependency Diagnostic ===" -ForegroundColor Cyan
Write-Host "Build directory: $BuildDir"
Write-Host ""

# Resolve paths
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$buildPath = Join-Path $repoRoot $BuildDir

if (-not (Test-Path $buildPath)) {
    Write-Host "Build directory not found: $buildPath" -ForegroundColor Yellow
    Write-Host "Run cmake --build first, then re-run this script."
    exit 0
}

# Find all test executables (.exe files that match test names from CMakeLists)
$testExes = Get-ChildItem -Path $buildPath -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match "_test\.exe$" }

if ($testExes.Count -eq 0) {
    Write-Host "No test executables found in $buildPath" -ForegroundColor Yellow
    exit 0
}

Write-Host "Found $($testExes.Count) test executables" -ForegroundColor Green
Write-Host ""

# Detect available tools for DLL inspection
$dumpbin = $null
$objdump = $null

# Try MSVC dumpbin (available in VS Developer Command Prompt)
$vsDumpbin = Get-Command dumpbin -ErrorAction SilentlyContinue
if ($vsDumpbin) {
    $dumpbin = $vsDumpbin.Source
}

# Try MinGW objdump
$mingwObjdump = Get-Command objdump -ErrorAction SilentlyContinue
if ($mingwObjdump) {
    $objdump = $mingwObjdump.Source
}

# Collect PATH directories for matching
$pathDirs = ($env:PATH -split ";") | Where-Object { $_ -ne "" }

# Results tracking
$results = @()
$missingSummary = @{}

foreach ($exe in $testExes) {
    $exePath = $exe.FullName
    $exeName = $exe.Name
    $status = "OK"
    $missingDlls = @()
    $allDlls = @()

    if ($dumpbin) {
        # Use MSVC dumpbin
        $output = & $dumpbin /dependents $exePath 2>&1
        $dllLines = $output | Where-Object { $_ -match "^\s+\S+\.dll$" } |
            ForEach-Object { $_.Trim() }
        $allDlls = $dllLines

        foreach ($dll in $dllLines) {
            # Skip Windows system DLLs (kernel32, ntdll, etc.)
            if ($dll -match "^(api-ms-|ext-ms-|KERNEL32|ntdll|USER32|GDI32|ADVAPI32|SHELL32|ole32|OLEAUT32|MSVCRT|ucrtbase)" ) {
                continue
            }

            # Check if DLL is findable in PATH
            $found = $false
            foreach ($dir in $pathDirs) {
                $dllPath = Join-Path $dir $dll
                if (Test-Path $dllPath) {
                    $found = $true
                    break
                }
            }
            # Also check next to the executable
            if (-not $found) {
                $localDll = Join-Path $exe.DirectoryName $dll
                if (Test-Path $localDll) {
                    $found = $true
                }
            }

            if (-not $found) {
                $missingDlls += $dll
                if (-not $missingSummary.ContainsKey($dll)) {
                    $missingSummary[$dll] = @()
                }
                $missingSummary[$dll] += $exeName
            }
        }
    }
    elseif ($objdump) {
        # Use MinGW objdump
        $output = & $objdump -p $exePath 2>&1
        $dllLines = $output | Where-Object { $_ -match "DLL Name:" } |
            ForEach-Object { ($_ -split "DLL Name:\s+")[1].Trim() }
        $allDlls = $dllLines

        foreach ($dll in $dllLines) {
            if ($dll -match "^(api-ms-|ext-ms-|KERNEL32|ntdll|USER32|GDI32|ADVAPI32|SHELL32|ole32|OLEAUT32|MSVCRT|ucrtbase)" ) {
                continue
            }

            $found = $false
            foreach ($dir in $pathDirs) {
                $dllPath = Join-Path $dir $dll
                if (Test-Path $dllPath) {
                    $found = $true
                    break
                }
            }
            if (-not $found) {
                $localDll = Join-Path $exe.DirectoryName $dll
                if (Test-Path $localDll) {
                    $found = $true
                }
            }

            if (-not $found) {
                $missingDlls += $dll
                if (-not $missingSummary.ContainsKey($dll)) {
                    $missingSummary[$dll] = @()
                }
                $missingSummary[$dll] += $exeName
            }
        }
    }
    else {
        # No DLL inspection tool available; just report file existence
        $fileSize = (Get-Item $exePath).Length
        $allDlls = @("(no dumpbin/objdump available)")
        Write-Host "  [SKIP] $exeName -- no dumpbin or objdump found; cannot inspect DLLs" -ForegroundColor Yellow
        $results += [PSCustomObject]@{
            Test = $exeName
            Status = "SKIPPED"
            MissingCount = 0
            MissingDlls = ""
            FileSize = $fileSize
        }
        continue
    }

    if ($missingDlls.Count -gt 0) {
        $status = "MISSING DLLs"
        Write-Host "  [FAIL] $exeName -- missing: $($missingDlls -join ', ')" -ForegroundColor Red
    } else {
        Write-Host "  [OK]   $exeName -- all $($allDlls.Count) DLL dependencies resolved" -ForegroundColor Green
    }

    $results += [PSCustomObject]@{
        Test = $exeName
        Status = $status
        MissingCount = $missingDlls.Count
        MissingDlls = ($missingDlls -join "; ")
        FileSize = (Get-Item $exePath).Length
    }
}

# Summary table
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
$results | Format-Table -Property Test, Status, MissingCount, MissingDlls -AutoSize

# Missing DLL aggregation
if ($missingSummary.Count -gt 0) {
    Write-Host ""
    Write-Host "=== Missing DLL Details ===" -ForegroundColor Yellow
    foreach ($dll in $missingSummary.Keys | Sort-Object) {
        $affectedTests = $missingSummary[$dll]
        Write-Host "  $dll" -ForegroundColor Red
        Write-Host "    Required by: $($affectedTests -join ', ')"
        # Suggest common MinGW paths
        if ($dll -match "libstdc\+\+|libgcc|libwinpthread") {
            Write-Host "    Likely location: MinGW bin directory (e.g. C:\mingw64\bin)" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "Fix: Add the MinGW bin directory to PATH before running tests:" -ForegroundColor Yellow
    Write-Host '  $env:PATH = "C:\mingw64\bin;$env:PATH"' -ForegroundColor White
    Write-Host "Or set the ENVIRONMENT property on affected tests in CMakeLists.txt." -ForegroundColor White
    exit 1
} else {
    Write-Host "All DLL dependencies resolved." -ForegroundColor Green
    exit 0
}

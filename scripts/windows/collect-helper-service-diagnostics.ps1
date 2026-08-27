$ErrorActionPreference = "Continue"

Write-Host "== EXV helper service =="
sc.exe queryex exv-helper
sc.exe qc exv-helper

Write-Host ""
Write-Host "== EXV helper processes =="
Get-CimInstance Win32_Process |
  Where-Object { $_.Name -in @("exv-helper.exe", "exv.exe", "exv-ui.exe") } |
  Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine |
  Format-List

Write-Host ""
Write-Host "== Expected machine helper path =="
$programData = $env:ProgramData
if (-not $programData) { $programData = "C:\ProgramData" }
$expected = Join-Path $programData "EXV\Helper\exv-helper.exe"
Write-Host $expected
Write-Host ("Exists: " + (Test-Path -LiteralPath $expected))

Write-Host ""
Write-Host "== Legacy Administrator helper candidates =="
Get-ChildItem -LiteralPath "C:\Users" -Directory -ErrorAction SilentlyContinue |
  ForEach-Object {
    $candidate = Join-Path $_.FullName "AppData\Local\EXV\Helper\exv-helper.exe"
    if (Test-Path -LiteralPath $candidate) {
      Get-Item -LiteralPath $candidate
    }
  }

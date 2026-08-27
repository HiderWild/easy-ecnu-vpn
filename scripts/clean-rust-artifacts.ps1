param(
  [ValidateRange(1, 10)]
  [int]$KeepInstallers = 2,
  [switch]$WhatIf,
  [string]$OutputRoot = 'build\release'
)

$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'cleanup-rust-artifacts.ps1') @PSBoundParameters
exit $LASTEXITCODE

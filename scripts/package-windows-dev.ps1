param(
  [ValidatePattern('^$|^[0-9]+\.[0-9]+\.[0-9]+$')]
  [string]$Version = "",
  [switch]$SkipBuild,
  [string]$PackageRoot = "",
  [string]$OutputDir = "",
  [string]$NsisPath = $env:NSIS_MAKENSIS,
  [switch]$LegacyNsis,
  [ValidateSet('lzms', 'store')]
  [string]$SetupCompression = 'lzms',
  [string]$CppBuildDir = ""
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$releaseScript = Join-Path $scriptDir 'package-windows-release.ps1'

function Add-OptionalArgument {
  param(
    [Parameter(Mandatory = $true)]
    [hashtable]$Arguments,
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [string]$Value
  )

  if (-not [string]::IsNullOrWhiteSpace($Value)) {
    $Arguments[$Name] = $Value
  }
}

function Invoke-DevPackage {
  if (-not (Test-Path -LiteralPath $releaseScript -PathType Leaf)) {
    throw "Release packaging script not found: $releaseScript"
  }

  $arguments = @{
    DevBuild = $true
  }

  Add-OptionalArgument -Arguments $arguments -Name 'Version' -Value $Version
  Add-OptionalArgument -Arguments $arguments -Name 'PackageRoot' -Value $PackageRoot
  Add-OptionalArgument -Arguments $arguments -Name 'OutputDir' -Value $OutputDir
  Add-OptionalArgument -Arguments $arguments -Name 'NsisPath' -Value $NsisPath
  Add-OptionalArgument -Arguments $arguments -Name 'SetupCompression' -Value $SetupCompression
  Add-OptionalArgument -Arguments $arguments -Name 'CppBuildDir' -Value $CppBuildDir
  if ($SkipBuild) {
    $arguments['SkipBuild'] = $true
  }
  if ($LegacyNsis) {
    $arguments['LegacyNsis'] = $true
  }

  & $releaseScript @arguments
}

Invoke-DevPackage

param(
  [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$MetadataPath = "",
  [string]$WebView2SdkDir = $env:WEBVIEW2_SDK_DIR,
  [string]$WebView2LoaderDll = $env:EXV_WEBVIEW2_LOADER_DLL,
  [string]$RuntimeDir = $env:EXV_RUNTIME_DIR,
  [string]$WintunDllPath = $env:EXV_WINTUN_DLL,
  [switch]$ValidateOnly,
  [switch]$NoDownload,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Resolve-RepoPath {
  param([Parameter(Mandatory = $true)][string]$Path)

  if ([System.IO.Path]::IsPathRooted($Path)) {
    return [System.IO.Path]::GetFullPath($Path)
  }

  return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
}

function Resolve-InputPath {
  param([Parameter(Mandatory = $true)][string]$Path)

  if ([System.IO.Path]::IsPathRooted($Path)) {
    return [System.IO.Path]::GetFullPath($Path)
  }

  return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
}

function Assert-PathUnderRepo {
  param([Parameter(Mandatory = $true)][string]$Path)

  $root = [System.IO.Path]::GetFullPath($RepoRoot).TrimEnd('\', '/')
  $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  if (-not ($full.Equals($root, [System.StringComparison]::OrdinalIgnoreCase) -or
      $full.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
      $full.StartsWith($root + '/', [System.StringComparison]::OrdinalIgnoreCase))) {
    throw "Refusing to modify a path outside the repository: $Path"
  }
}

function Remove-DirectoryIfSafe {
  param([Parameter(Mandatory = $true)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) {
    return
  }

  Assert-PathUnderRepo -Path $Path
  Remove-Item -LiteralPath $Path -Recurse -Force
}

function Read-DependencyMetadata {
  $path = if ([string]::IsNullOrWhiteSpace($MetadataPath)) {
    Resolve-RepoPath 'distribution/windows/package-dependencies.json'
  } else {
    Resolve-InputPath $MetadataPath
  }

  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "Windows package dependency metadata not found: $path"
  }

  $metadata = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
  if ($metadata.schema -ne 1) {
    throw "Unsupported Windows package dependency metadata schema: $($metadata.schema)"
  }

  return $metadata
}

function Assert-DependencyArchitecture {
  param(
    [Parameter(Mandatory = $true)]$Dependency,
    [Parameter(Mandatory = $true)][string]$Name
  )

  if ($Dependency.architecture -ne 'x64') {
    throw "$Name dependency must declare architecture x64, found: $($Dependency.architecture)"
  }
}

function Assert-FileSha256 {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$ExpectedSha256,
    [Parameter(Mandatory = $true)][string]$Label
  )

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "$Label not found: $Path"
  }

  $actual = Get-FileSha256 -Path $Path
  $expected = $ExpectedSha256.ToLowerInvariant()
  if ($actual -ne $expected) {
    throw "$Label SHA-256 mismatch: expected $expected, got $actual at $Path"
  }
}

function Get-FileSha256 {
  param([Parameter(Mandatory = $true)][string]$Path)

  $getFileHash = Get-Command Get-FileHash -ErrorAction SilentlyContinue
  if ($getFileHash) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
  }

  $stream = [System.IO.File]::OpenRead($Path)
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try {
    return ([System.BitConverter]::ToString($sha256.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
  }
  finally {
    $sha256.Dispose()
    $stream.Dispose()
  }
}

function Assert-WintunAuthenticode {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)]$Dependency
  )

  if (-not $Dependency.authenticode.required) {
    return
  }

  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  if ($null -eq $signature -or $signature.Status -ne 'Valid') {
    throw "Wintun Authenticode signature is not valid: $Path (status: $($signature.Status))"
  }

  $expectedSubject = [string]$Dependency.authenticode.publisherSubjectContains
  if (-not [string]::IsNullOrWhiteSpace($expectedSubject)) {
    $actualSubject = ''
    if ($signature.SignerCertificate) {
      $actualSubject = [string]$signature.SignerCertificate.Subject
    }
    if ($actualSubject.IndexOf($expectedSubject, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
      throw "Wintun Authenticode signer mismatch: expected subject containing '$expectedSubject', got '$actualSubject'"
    }
  }
}

function Assert-WebView2SdkRoot {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)]$Dependency
  )

  $resolvedRoot = Resolve-InputPath $Root
  if (-not (Test-Path -LiteralPath $resolvedRoot -PathType Container)) {
    throw "WEBVIEW2_SDK_DIR does not exist: $resolvedRoot"
  }

  $header = Join-Path $resolvedRoot $Dependency.payloads.header.relativePath
  $loaderDll = Join-Path $resolvedRoot $Dependency.payloads.loaderDll.relativePath
  $loaderLib = Join-Path $resolvedRoot $Dependency.payloads.loaderLib.relativePath
  Assert-FileSha256 -Path $header -ExpectedSha256 $Dependency.payloads.header.sha256 -Label 'WebView2.h'
  Assert-FileSha256 -Path $loaderDll -ExpectedSha256 $Dependency.payloads.loaderDll.sha256 -Label 'WebView2 x64 loader DLL'
  Assert-FileSha256 -Path $loaderLib -ExpectedSha256 $Dependency.payloads.loaderLib.sha256 -Label 'WebView2 x64 loader import library'
  return $resolvedRoot
}

function Assert-WebView2LoaderOverride {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)]$Dependency
  )

  $resolved = Resolve-InputPath $Path
  Assert-FileSha256 -Path $resolved -ExpectedSha256 $Dependency.payloads.loaderDll.sha256 -Label 'EXV_WEBVIEW2_LOADER_DLL'
  return $resolved
}

function Assert-WintunDll {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)]$Dependency,
    [Parameter(Mandatory = $true)][string]$Label
  )

  $resolved = Resolve-InputPath $Path
  Assert-FileSha256 -Path $resolved -ExpectedSha256 $Dependency.payloads.dll.sha256 -Label $Label
  Assert-WintunAuthenticode -Path $resolved -Dependency $Dependency
  return $resolved
}

function Get-ArchivePath {
  param([Parameter(Mandatory = $true)]$Dependency)
  return Resolve-RepoPath $Dependency.cache.archivePath
}

function Save-DeclaredArchive {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)]$Dependency
  )

  $archive = Get-ArchivePath -Dependency $Dependency
  if ((Test-Path -LiteralPath $archive -PathType Leaf) -and -not $Force) {
    Assert-FileSha256 -Path $archive -ExpectedSha256 $Dependency.sha256 -Label "$Name archive"
    return $archive
  }

  if ($ValidateOnly -or $NoDownload) {
    throw "$Name archive is missing or invalid and downloads are disabled: $archive"
  }

  $parent = Split-Path -Parent $archive
  New-Item -ItemType Directory -Path $parent -Force | Out-Null
  $tempArchive = "$archive.download"
  if (Test-Path -LiteralPath $tempArchive) {
    Remove-Item -LiteralPath $tempArchive -Force
  }

  Write-Host "Fetching $Name from declared URL: $($Dependency.url)"
  Invoke-WebRequest -Uri $Dependency.url -OutFile $tempArchive -UseBasicParsing
  Assert-FileSha256 -Path $tempArchive -ExpectedSha256 $Dependency.sha256 -Label "$Name archive"
  Move-Item -LiteralPath $tempArchive -Destination $archive -Force
  return $archive
}

function Expand-DeclaredArchive {
  param(
    [Parameter(Mandatory = $true)][string]$Archive,
    [Parameter(Mandatory = $true)][string]$Destination
  )

  $parent = Split-Path -Parent $Destination
  New-Item -ItemType Directory -Path $parent -Force | Out-Null
  $tempDestination = Join-Path $parent ('.extract-' + [System.Guid]::NewGuid().ToString('N'))
  try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($Archive, $tempDestination)
    if (Test-Path -LiteralPath $Destination) {
      Remove-DirectoryIfSafe -Path $Destination
    }
    Move-Item -LiteralPath $tempDestination -Destination $Destination
  }
  finally {
    if (Test-Path -LiteralPath $tempDestination) {
      Remove-DirectoryIfSafe -Path $tempDestination
    }
  }
}

function Initialize-WebView2Sdk {
  param([Parameter(Mandatory = $true)]$Dependency)

  Assert-DependencyArchitecture -Dependency $Dependency -Name 'WebView2'

  if (-not [string]::IsNullOrWhiteSpace($WebView2LoaderDll)) {
    [void](Assert-WebView2LoaderOverride -Path $WebView2LoaderDll -Dependency $Dependency)
  }

  if (-not [string]::IsNullOrWhiteSpace($WebView2SdkDir)) {
    return Assert-WebView2SdkRoot -Root $WebView2SdkDir -Dependency $Dependency
  }

  $defaultRoot = Resolve-RepoPath $Dependency.extractPath
  if ((Test-Path -LiteralPath $defaultRoot -PathType Container) -and -not $Force) {
    try {
      return Assert-WebView2SdkRoot -Root $defaultRoot -Dependency $Dependency
    }
    catch {
      if ($ValidateOnly) {
        throw
      }
      Remove-DirectoryIfSafe -Path $defaultRoot
    }
  }

  if ($ValidateOnly) {
    throw "WebView2 SDK is not provisioned: $defaultRoot"
  }

  $archive = Save-DeclaredArchive -Name 'WebView2 SDK' -Dependency $Dependency
  Expand-DeclaredArchive -Archive $archive -Destination $defaultRoot
  return Assert-WebView2SdkRoot -Root $defaultRoot -Dependency $Dependency
}

function Resolve-WintunOverride {
  param([Parameter(Mandatory = $true)]$Dependency)

  if (-not [string]::IsNullOrWhiteSpace($WintunDllPath)) {
    return Assert-WintunDll -Path $WintunDllPath -Dependency $Dependency -Label 'EXV_WINTUN_DLL'
  }

  if (-not [string]::IsNullOrWhiteSpace($RuntimeDir)) {
    $candidate = Join-Path (Resolve-InputPath $RuntimeDir) 'wintun.dll'
    return Assert-WintunDll -Path $candidate -Dependency $Dependency -Label 'EXV_RUNTIME_DIR wintun.dll'
  }

  return ''
}

function Initialize-Wintun {
  param([Parameter(Mandatory = $true)]$Dependency)

  Assert-DependencyArchitecture -Dependency $Dependency -Name 'Wintun'

  $override = Resolve-WintunOverride -Dependency $Dependency
  if (-not [string]::IsNullOrWhiteSpace($override)) {
    return $override
  }

  $installPath = Resolve-RepoPath $Dependency.installPath
  if ((Test-Path -LiteralPath $installPath -PathType Leaf) -and -not $Force) {
    return Assert-WintunDll -Path $installPath -Dependency $Dependency -Label 'Provisioned Wintun DLL'
  }

  if ($ValidateOnly) {
    throw "Wintun DLL is not provisioned: $installPath"
  }

  $extractRoot = Resolve-RepoPath $Dependency.extractPath
  $payloadPath = Join-Path $extractRoot $Dependency.payloads.dll.relativePath
  if (-not (Test-Path -LiteralPath $payloadPath -PathType Leaf) -or $Force) {
    $archive = Save-DeclaredArchive -Name 'Wintun' -Dependency $Dependency
    Expand-DeclaredArchive -Archive $archive -Destination $extractRoot
  }

  $payload = Assert-WintunDll -Path $payloadPath -Dependency $Dependency -Label 'Wintun x64 payload'
  $installParent = Split-Path -Parent $installPath
  New-Item -ItemType Directory -Path $installParent -Force | Out-Null
  Copy-Item -LiteralPath $payload -Destination $installPath -Force
  return Assert-WintunDll -Path $installPath -Dependency $Dependency -Label 'Provisioned Wintun DLL'
}

$RepoRoot = [System.IO.Path]::GetFullPath($RepoRoot)
$metadata = Read-DependencyMetadata
$webview2Root = Initialize-WebView2Sdk -Dependency $metadata.dependencies.webview2
$wintunDll = Initialize-Wintun -Dependency $metadata.dependencies.wintun

Write-Host 'Windows package dependencies ready:'
Write-Host "  WebView2 SDK: $webview2Root"
Write-Host "  Wintun DLL: $wintunDll"

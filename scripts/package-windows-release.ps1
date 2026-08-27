param(
  [ValidatePattern('^$|^[0-9]+\.[0-9]+\.[0-9]+$')]
  [string]$Version = "",
  [switch]$DevBuild,
  [switch]$SkipBuild,
  [string]$PackageRoot = "",
  [string]$OutputDir = "",
  [string]$NsisPath = $env:NSIS_MAKENSIS,
  # Default is the custom setup engine. Pass -LegacyNsis to keep the old path.
  [switch]$LegacyNsis,
  [ValidateSet('lzms', 'store')]
  [string]$SetupCompression = 'lzms',
  [string]$CppBuildDir = "",
  [string]$SetupPayloadVerifier = "",
  [switch]$FunctionsOnly
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

function Resolve-AbsolutePath {
  param([Parameter(Mandatory = $true)][string]$Path)

  if ([System.IO.Path]::IsPathRooted($Path)) {
    return [System.IO.Path]::GetFullPath($Path)
  }

  return [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}

function Get-CmakeProjectVersion {
  param([Parameter(Mandatory = $true)][string]$CMakeListsPath)

  if (-not (Test-Path -LiteralPath $CMakeListsPath -PathType Leaf)) {
    throw "CMakeLists.txt not found: $CMakeListsPath"
  }

  $content = Get-Content -LiteralPath $CMakeListsPath -Raw
  $match = [regex]::Match(
    $content,
    '(?m)^\s*project\s*\(\s*exv\s+VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)\b'
  )
  if (-not $match.Success) {
    throw "Unable to read project(exv VERSION ...) from $CMakeListsPath"
  }

  return $match.Groups[1].Value
}

function Assert-ProductVersion {
  param([Parameter(Mandatory = $true)][string]$Value)

  if ($Value -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
    throw "Product version must be a three-part numeric version such as 3.3.0: $Value"
  }
}

function Get-NextDevBuildNumber {
  param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$OutputDir
  )

  if (-not (Test-Path -LiteralPath $OutputDir -PathType Container)) {
    return 1
  }

  $max = 0
  $pattern = "^EXV-$([regex]::Escape($Version))-dev\.([0-9]+)-windows-x64-setup\.exe$"
  foreach ($item in (Get-ChildItem -LiteralPath $OutputDir -File -Filter "EXV-$Version-dev.*-windows-x64-setup.exe" -ErrorAction SilentlyContinue)) {
    $match = [regex]::Match($item.Name, $pattern)
    if ($match.Success) {
      $value = [int]$match.Groups[1].Value
      if ($value -gt $max) {
        $max = $value
      }
    }
  }

  $next = $max + 1
  while ($true) {
    $candidateSetupName = "EXV-$Version-dev.$next-windows-x64-setup.exe"
    $candidateSetupPath = Join-Path $OutputDir $candidateSetupName
    if (-not (Test-Path -LiteralPath $candidateSetupPath -PathType Leaf)) {
      return $next
    }
    $next += 1
  }
}

function Join-ArtifactVersion {
  param(
    [Parameter(Mandatory = $true)][string]$Version,
    [switch]$DevBuild,
    [Parameter(Mandatory = $true)][string]$OutputDir
  )

  if (-not $DevBuild) {
    return $Version
  }

  $next = Get-NextDevBuildNumber -Version $Version -OutputDir $OutputDir
  return "$Version-dev.$next"
}

function Invoke-Step {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,
    [string[]]$Arguments = @()
  )

  # Clear any leftover native exit code so a previous failure cannot poison a
  # subsequent call that does not set LASTEXITCODE.
  $global:LASTEXITCODE = 0
  & $FilePath @Arguments
  $code = $global:LASTEXITCODE
  if ($null -ne $code -and $code -ne 0) {
    throw "Command failed ($code): $FilePath $($Arguments -join ' ')"
  }
}

function Resolve-MakeNsis {
  param([string]$RequestedPath)

  $candidates = New-Object System.Collections.Generic.List[string]

  if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
    if (Test-Path -LiteralPath $RequestedPath -PathType Container) {
      [void]$candidates.Add((Join-Path $RequestedPath 'makensis.exe'))
    }
    else {
      [void]$candidates.Add($RequestedPath)
    }
  }

  $pathCommand = Get-Command makensis.exe -ErrorAction SilentlyContinue
  if ($pathCommand) {
    [void]$candidates.Add($pathCommand.Source)
  }

  if ($env:ProgramFiles) {
    [void]$candidates.Add((Join-Path $env:ProgramFiles 'NSIS\makensis.exe'))
  }
  if (${env:ProgramFiles(x86)}) {
    [void]$candidates.Add((Join-Path ${env:ProgramFiles(x86)} 'NSIS\makensis.exe'))
  }
  $environmentRoot = 'D:\Development\Environment'
  if (Test-Path -LiteralPath $environmentRoot -PathType Container) {
    $nsisDirs = @(Get-ChildItem -LiteralPath $environmentRoot -Directory -Filter 'NSIS-*' -ErrorAction SilentlyContinue)
    foreach ($nsisDir in $nsisDirs) {
      [void]$candidates.Add((Join-Path $nsisDir.FullName 'Bin\makensis.exe'))
      [void]$candidates.Add((Join-Path $nsisDir.FullName 'makensis.exe'))
    }
  }

  foreach ($candidate in $candidates) {
    if (-not [string]::IsNullOrWhiteSpace($candidate) -and
        (Test-Path -LiteralPath $candidate -PathType Leaf)) {
      return (Resolve-Path -LiteralPath $candidate).Path
    }
  }

  throw 'makensis.exe was not found. Install NSIS, add makensis.exe to PATH, set NSIS_MAKENSIS, or pass -NsisPath.'
}

function Assert-PackageRoot {
  param([Parameter(Mandatory = $true)][string]$Root)

  if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
    throw "Package root does not exist: $Root"
  }

  $required = @(
    'exv-ui.exe',
    'exv-ui.args',
    'bin\exv.exe',
    'bin\exv-helper.exe',
    'webui\index.html',
    'WebView2Loader.dll',
    'wintun.dll',
    'bin\wintun.dll'
  )

  $missing = @()
  foreach ($relative in $required) {
    $candidate = Join-Path $Root $relative
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
      $missing += $relative
    }
  }

  if ($missing.Count -gt 0) {
    throw "Package root is missing required file(s): $($missing -join ', ')"
  }
}

function Invoke-PackageVerifier {
  param([Parameter(Mandatory = $true)][string]$Root)

  $verifyScript = Join-Path $repoRoot 'scripts\package_ui_shell.py'
  Invoke-Step -FilePath 'python' -Arguments @(
    $verifyScript,
    '--verify-launch-targets-only',
    '--platform',
    'windows',
    '--package-dir',
    $Root
  )
}

function New-PortableZip {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$Destination
  )

  if (Test-Path -LiteralPath $Destination) {
    Remove-Item -LiteralPath $Destination -Force
  }

  Compress-Archive -Path $Root -DestinationPath $Destination -CompressionLevel Optimal
  if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) {
    throw "Portable zip was not created: $Destination"
  }
}

function Get-RunningExvProcesses {
  $filter = "Name='exv.exe' OR Name='exv-ui.exe' OR Name='exv-helper.exe'"
  return @(Get-CimInstance Win32_Process -Filter $filter -ErrorAction SilentlyContinue)
}

function Stop-PackageSmokeProcesses {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [int[]]$KnownProcessIds = @()
  )

  $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
  $known = @{}
  foreach ($processId in $KnownProcessIds) {
    $known[[int]$processId] = $true
  }

  foreach ($process in Get-RunningExvProcesses) {
    $processId = [int]$process.ProcessId
    if ($known.ContainsKey($processId)) {
      continue
    }

    $exePath = [string]$process.ExecutablePath
    $commandLine = [string]$process.CommandLine
    $matchesPackageRoot = $false
    if (-not [string]::IsNullOrWhiteSpace($exePath)) {
      try {
        $exeFull = [System.IO.Path]::GetFullPath($exePath)
        $matchesPackageRoot = $exeFull.StartsWith($rootFull + '\', [System.StringComparison]::OrdinalIgnoreCase)
      } catch { }
    }
    if (-not $matchesPackageRoot -and
        -not [string]::IsNullOrWhiteSpace($commandLine)) {
      $matchesPackageRoot = $commandLine.IndexOf($rootFull, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
    }

    # Some short-lived MinGW processes have already lost queryable image
    # metadata by cleanup time. If they were not present before smoke and have
    # an EXV binary name, treat them as smoke children so the temp package can
    # be removed.
    $unknownImage = [string]::IsNullOrWhiteSpace($exePath) -and
      [string]::IsNullOrWhiteSpace($commandLine)
    if ($matchesPackageRoot -or $unknownImage) {
      Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
    }
  }
}

function Remove-DirectoryWithRetry {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$ProcessRoot,
    [int[]]$KnownProcessIds = @()
  )

  for ($attempt = 1; $attempt -le 6; $attempt++) {
    Stop-PackageSmokeProcesses -Root $ProcessRoot -KnownProcessIds $KnownProcessIds
    try {
      Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
      return
    } catch {
      if ($attempt -eq 6) {
        throw
      }
      Start-Sleep -Milliseconds (200 * $attempt)
    }
  }
}

function Test-PortableZip {
  param([Parameter(Mandatory = $true)][string]$Archive)

  $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("exv-portable-" + [System.Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tempRoot | Out-Null
  $knownExvProcessIds = @(Get-RunningExvProcesses | ForEach-Object { [int]$_.ProcessId })

  try {
    Expand-Archive -LiteralPath $Archive -DestinationPath $tempRoot -Force
    $children = @(Get-ChildItem -LiteralPath $tempRoot)
    if ($children.Count -ne 1 -or -not $children[0].PSIsContainer -or $children[0].Name -ne 'EXV') {
      $names = $children | ForEach-Object { $_.Name }
      throw "Portable zip must contain exactly one top-level EXV directory. Found: $($names -join ', ')"
    }

    $extractedPackage = Join-Path $tempRoot 'EXV'
    $smoke = Join-Path $repoRoot 'scripts\windows-packaging-smoke.ps1'
    Invoke-Step -FilePath 'powershell.exe' -Arguments @(
      '-NoProfile',
      '-ExecutionPolicy',
      'Bypass',
      '-File',
      $smoke,
      '-PackageRoot',
      $extractedPackage
    )
  }
  finally {
    if (Test-Path -LiteralPath $tempRoot) {
      Remove-DirectoryWithRetry -Path $tempRoot -ProcessRoot $tempRoot -KnownProcessIds $knownExvProcessIds
    }
  }
}

function New-ReleasePackageRoot {
  param([Parameter(Mandatory = $true)][string]$SourceRoot)

  $supportScripts = @(
    (Join-Path $repoRoot 'scripts\clear-local-user-config.ps1'),
    (Join-Path $repoRoot 'scripts\clear-windows-legacy-state.ps1')
  )
  foreach ($supportScript in $supportScripts) {
    if (-not (Test-Path -LiteralPath $supportScript -PathType Leaf)) {
      throw "Support script not found: $supportScript"
    }
  }

  $stageParent = Join-Path ([System.IO.Path]::GetTempPath()) ("exv-release-" + [System.Guid]::NewGuid().ToString('N'))
  $stageRoot = Join-Path $stageParent 'EXV'
  New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null

  foreach ($item in (Get-ChildItem -LiteralPath $SourceRoot -Force)) {
    Copy-Item -LiteralPath $item.FullName -Destination $stageRoot -Recurse -Force
  }

  $supportDir = Join-Path $stageRoot 'support'
  New-Item -ItemType Directory -Path $supportDir -Force | Out-Null
  foreach ($supportScript in $supportScripts) {
    Copy-Item -LiteralPath $supportScript -Destination (Join-Path $supportDir ([System.IO.Path]::GetFileName($supportScript))) -Force
  }

  return $stageRoot
}

function Convert-ToNsisPath {
  param([Parameter(Mandatory = $true)][string]$Path)

  return ($Path -replace '/', '\')
}

function Get-RelativePathFromRoot {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$Child
  )

  $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd(
    [System.IO.Path]::DirectorySeparatorChar,
    [System.IO.Path]::AltDirectorySeparatorChar
  )
  $childFull = [System.IO.Path]::GetFullPath($Child)
  $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  if (-not $childFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Path is not under source root: $Child"
  }

  return $childFull.Substring($prefix.Length)
}

function New-NsisUninstallManifest {
  param(
    [Parameter(Mandatory = $true)][string]$SourceDir,
    [Parameter(Mandatory = $true)][string]$Destination
  )

  $sourceRoot = (Resolve-Path -LiteralPath $SourceDir).Path
  $lines = New-Object System.Collections.Generic.List[string]
  [void]$lines.Add('; Generated by scripts\package-windows-release.ps1. Do not edit.')

  $files = Get-ChildItem -LiteralPath $sourceRoot -Recurse -File | Sort-Object FullName
  foreach ($file in $files) {
    $relative = Get-RelativePathFromRoot -Root $sourceRoot -Child $file.FullName
    $nsisPath = Convert-ToNsisPath $relative
    [void]$lines.Add("Delete `"`$INSTDIR\$nsisPath`"")
  }

  [void]$lines.Add('Delete "$INSTDIR\Uninstall.exe"')

  $directories = Get-ChildItem -LiteralPath $sourceRoot -Recurse -Directory | Sort-Object { $_.FullName.Length } -Descending
  foreach ($directory in $directories) {
    $relative = Get-RelativePathFromRoot -Root $sourceRoot -Child $directory.FullName
    $nsisPath = Convert-ToNsisPath $relative
    [void]$lines.Add("RMDir `"`$INSTDIR\$nsisPath`"")
  }

  [void]$lines.Add('RMDir "$INSTDIR"')
  Set-Content -LiteralPath $Destination -Value $lines -Encoding UTF8
}

function Invoke-Nsis {
  param(
    [Parameter(Mandatory = $true)][string]$MakeNsis,
    [Parameter(Mandatory = $true)][string]$SourceDir,
    [Parameter(Mandatory = $true)][string]$OutputFile,
    [Parameter(Mandatory = $true)][string]$AppVersion
  )

  $scriptPath = Join-Path $repoRoot 'distribution\windows\exv.nsi'
  if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
    throw "NSIS script not found: $scriptPath"
  }

  $manifestPath = [System.IO.Path]::ChangeExtension($OutputFile, '.uninstall.nsh')
  New-NsisUninstallManifest -SourceDir $SourceDir -Destination $manifestPath

  $defaultInstallDir = Join-Path $env:LOCALAPPDATA 'Programs\EXV'
  Invoke-Step -FilePath $MakeNsis -Arguments @(
    '/V2',
    '/INPUTCHARSET',
    'UTF8',
    "/DAPP_VERSION=$AppVersion",
    "/DSOURCE_DIR=$SourceDir",
    "/DOUTPUT_FILE=$OutputFile",
    "/DDEFAULT_INSTALL_DIR=$defaultInstallDir",
    "/DUNINSTALL_MANIFEST=$manifestPath",
    $scriptPath
  )
}

function Resolve-CppBuildDir {
  param([string]$Requested)
  if (-not [string]::IsNullOrWhiteSpace($Requested)) {
    return Resolve-AbsolutePath $Requested
  }
  $presetDir = Join-Path $repoRoot 'build-windows\cpp'
  if (Test-Path -LiteralPath $presetDir) {
    return $presetDir
  }
  $legacy = Join-Path $repoRoot 'build\windows\cpp'
  if (Test-Path -LiteralPath $legacy) {
    return $legacy
  }
  return $presetDir
}

function Ensure-CustomSetupTools {
  param(
    [Parameter(Mandatory = $true)][string]$CppBuildDir
  )

  $stub = Join-Path $CppBuildDir 'exv-setup.exe'
  $packer = Join-Path $CppBuildDir 'pack_setup_payload.exe'
  $needBuild = -not (Test-Path -LiteralPath $stub -PathType Leaf) -or
               -not (Test-Path -LiteralPath $packer -PathType Leaf)
  if (-not $needBuild) {
    return
  }

  Write-Host "Building custom setup tools (exv-setup, pack_setup_payload)..." -ForegroundColor Cyan
  $configureDir = $CppBuildDir
  if (-not (Test-Path -LiteralPath (Join-Path $configureDir 'build.ninja') -PathType Leaf) -and
      -not (Test-Path -LiteralPath (Join-Path $configureDir 'CMakeCache.txt') -PathType Leaf)) {
    Invoke-Step -FilePath 'cmake' -Arguments @(
      '--preset', 'windows-release',
      '-DEXV_BUILD_WINDOWS_SETUP=ON'
    )
  }

  Invoke-Step -FilePath 'cmake' -Arguments @(
    '--build',
    '--preset',
    'windows-release',
    '--target',
    'exv-setup',
    'pack_setup_payload'
  )

  if (-not (Test-Path -LiteralPath $stub -PathType Leaf)) {
    throw "exv-setup.exe still missing after build: $stub"
  }
  if (-not (Test-Path -LiteralPath $packer -PathType Leaf)) {
    throw "pack_setup_payload.exe still missing after build: $packer"
  }
}

function ConvertTo-NativeCommandLineArgument {
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$Value
  )

  if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
    return $Value
  }

  $builder = New-Object System.Text.StringBuilder
  [void]$builder.Append('"')
  $backslashCount = 0
  foreach ($character in $Value.ToCharArray()) {
    if ($character -eq '\') {
      $backslashCount++
      continue
    }
    if ($character -eq '"') {
      [void]$builder.Append(('\' * (($backslashCount * 2) + 1)))
      [void]$builder.Append('"')
      $backslashCount = 0
      continue
    }
    if ($backslashCount -gt 0) {
      [void]$builder.Append(('\' * $backslashCount))
      $backslashCount = 0
    }
    [void]$builder.Append($character)
  }
  if ($backslashCount -gt 0) {
    [void]$builder.Append(('\' * ($backslashCount * 2)))
  }
  [void]$builder.Append('"')
  return $builder.ToString()
}

function Initialize-NativeProcessTreeControl {
  if ('ExvWindowsJobRunner' -as [type]) {
    return
  }

  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

public sealed class ExvWindowsJobResult
{
    public bool TimedOut;
    public int ExitCode = -1;
    public string Output = "";
    public string LaunchError = "";
}

public static class ExvWindowsJobRunner
{
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint STARTF_USESTDHANDLES = 0x00000100;
    private const uint HANDLE_FLAG_INHERIT = 0x00000001;
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const uint WAIT_OBJECT_0 = 0x00000000;
    private const uint WAIT_TIMEOUT = 0x00000102;
    private const uint INFINITE = 0xFFFFFFFF;
    private const int ERROR_BROKEN_PIPE = 109;

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public uint nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(
        out IntPtr hReadPipe,
        out IntPtr hWritePipe,
        ref SECURITY_ATTRIBUTES lpPipeAttributes,
        uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(
        IntPtr hObject, uint dwMask, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateJobObject(
        IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr hJob,
        int JobObjectInfoClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInfo,
        uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcess(
        string lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(
        IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(
        IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(
        IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(
        IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(
        IntPtr hJob, uint uExitCode);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    private static void Close(ref IntPtr handle)
    {
        if (handle != IntPtr.Zero)
        {
            CloseHandle(handle);
            handle = IntPtr.Zero;
        }
    }

    private static string Win32Error()
    {
        return new Win32Exception(Marshal.GetLastWin32Error()).Message;
    }

    public static ExvWindowsJobResult Run(
        string commandLine, string workingDirectory, int timeoutSeconds)
    {
        var result = new ExvWindowsJobResult();
        IntPtr outputRead = IntPtr.Zero;
        IntPtr outputWrite = IntPtr.Zero;
        IntPtr inputRead = IntPtr.Zero;
        IntPtr inputWrite = IntPtr.Zero;
        IntPtr job = IntPtr.Zero;
        var processInfo = new PROCESS_INFORMATION();
        StreamReader outputReader = null;
        Task<string> outputTask = null;

        try
        {
            var security = new SECURITY_ATTRIBUTES();
            security.nLength =
                (uint)Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            security.bInheritHandle = true;
            if (!CreatePipe(out outputRead, out outputWrite, ref security, 0) ||
                !SetHandleInformation(
                    outputRead, HANDLE_FLAG_INHERIT, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!CreatePipe(out inputRead, out inputWrite, ref security, 0) ||
                !SetHandleInformation(
                    inputWrite, HANDLE_FLAG_INHERIT, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!SetInformationJobObject(
                    job, JobObjectExtendedLimitInformation, ref limits,
                    (uint)Marshal.SizeOf(
                        typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            var startup = new STARTUPINFO();
            startup.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
            startup.dwFlags = STARTF_USESTDHANDLES;
            startup.hStdInput = inputRead;
            startup.hStdOutput = outputWrite;
            startup.hStdError = outputWrite;
            if (!CreateProcess(
                    null, new StringBuilder(commandLine),
                    IntPtr.Zero, IntPtr.Zero, true,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW,
                    IntPtr.Zero,
                    String.IsNullOrWhiteSpace(workingDirectory)
                        ? null
                        : workingDirectory,
                    ref startup, out processInfo))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            Close(ref outputWrite);
            Close(ref inputRead);
            Close(ref inputWrite);

            if (!AssignProcessToJobObject(job, processInfo.hProcess))
            {
                int error = Marshal.GetLastWin32Error();
                TerminateProcess(processInfo.hProcess, (uint)error);
                throw new Win32Exception(error);
            }

            var safeOutputRead =
                new SafeFileHandle(outputRead, true);
            outputRead = IntPtr.Zero;
            var outputStream =
                new FileStream(safeOutputRead, FileAccess.Read, 65536, false);
            outputReader = new StreamReader(
                outputStream, new UTF8Encoding(false, false), true, 65536);
            outputTask = outputReader.ReadToEndAsync();

            if (ResumeThread(processInfo.hThread) == UInt32.MaxValue)
            {
                int error = Marshal.GetLastWin32Error();
                TerminateJobObject(job, (uint)error);
                throw new Win32Exception(error);
            }
            Close(ref processInfo.hThread);

            uint timeoutMilliseconds =
                (uint)Math.Min((long)timeoutSeconds * 1000L, 0xFFFFFFFEL);
            uint wait =
                WaitForSingleObject(processInfo.hProcess, timeoutMilliseconds);
            result.TimedOut = wait == WAIT_TIMEOUT;
            if (wait != WAIT_OBJECT_0 && wait != WAIT_TIMEOUT)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            if (result.TimedOut)
                TerminateJobObject(job, 1460);
            Close(ref job);
            if (result.TimedOut)
                WaitForSingleObject(processInfo.hProcess, 5000);

            if (outputTask != null && outputTask.Wait(2000))
            {
                result.Output = outputTask.Result;
            }
            else
            {
                result.LaunchError =
                    "Windows Job output pipe did not close after termination";
            }

            uint exitCode;
            if (!GetExitCodeProcess(processInfo.hProcess, out exitCode))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            result.ExitCode = unchecked((int)exitCode);
        }
        catch (Exception error)
        {
            result.LaunchError = error.Message;
        }
        finally
        {
            if (job != IntPtr.Zero)
                TerminateJobObject(job, 1460);
            Close(ref job);
            Close(ref processInfo.hThread);
            Close(ref processInfo.hProcess);
            Close(ref outputWrite);
            Close(ref outputRead);
            Close(ref inputWrite);
            Close(ref inputRead);
            if (outputReader != null)
                outputReader.Dispose();
        }
        return result;
    }
}
'@
}

function Invoke-BoundedNativeCommand {
  param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [string[]]$Arguments = @(),
    [string]$WorkingDirectory = '',
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 3600)]
    [int]$TimeoutSeconds
  )

  $nativeArguments = (($Arguments | ForEach-Object {
    ConvertTo-NativeCommandLineArgument -Value $_
  }) -join ' ')
  $nativeCommandLine = ConvertTo-NativeCommandLineArgument -Value $FilePath
  if (-not [string]::IsNullOrWhiteSpace($nativeArguments)) {
    $nativeCommandLine += " $nativeArguments"
  }

  try {
    Initialize-NativeProcessTreeControl
    $nativeResult = [ExvWindowsJobRunner]::Run(
      $nativeCommandLine,
      $WorkingDirectory,
      $TimeoutSeconds
    )
  } catch {
    return [pscustomobject]@{
      TimedOut = $false
      ExitCode = -1
      Output = ''
      LaunchError = $_.Exception.Message
    }
  }

  return [pscustomobject]@{
    TimedOut = $nativeResult.TimedOut
    ExitCode = $nativeResult.ExitCode
    Output = $nativeResult.Output
    LaunchError = $nativeResult.LaunchError
  }
}

function Get-PeImportDllNames {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [ValidateRange(1, 3600)]
    [int]$TimeoutSeconds = 45
  )

  $inspector = Join-Path $repoRoot 'scripts\windows_pe_imports.py'
  if (-not (Test-Path -LiteralPath $inspector -PathType Leaf)) {
    throw "PE_IMPORT_INSPECTION_FAILED: inspector not found: $inspector"
  }

  $result = Invoke-BoundedNativeCommand `
    -FilePath 'python' `
    -Arguments @($inspector, $Path) `
    -TimeoutSeconds $TimeoutSeconds
  if ($result.TimedOut) {
    throw "PE_IMPORT_INSPECTION_FAILED: PE_IMPORT_INSPECTION_TIMEOUT: inspector exceeded $TimeoutSeconds seconds for $Path"
  }
  if (-not [string]::IsNullOrWhiteSpace($result.LaunchError)) {
    throw "PE_IMPORT_INSPECTION_FAILED: unable to execute inspector for $Path`: $($result.LaunchError)"
  }
  $text = $result.Output
  if ($result.ExitCode -ne 0) {
    throw "PE_IMPORT_INSPECTION_FAILED: $Path`n$text"
  }

  try {
    $parsed = ConvertFrom-Json -InputObject $text
  } catch {
    throw "PE_IMPORT_INSPECTION_FAILED: invalid inspector JSON for $Path"
  }
  $names = @($parsed)
  if ($names.Count -eq 0 -or
      @($names | Where-Object { $_ -isnot [string] -or $_ -notmatch '(?i)\.dll$' }).Count -gt 0) {
    throw "PE_IMPORT_INSPECTION_FAILED: invalid import inventory for $Path"
  }
  return @($names | ForEach-Object { $_.ToString().ToLowerInvariant() })
}

function Assert-PackagePeRuntimeClosure {
  param([Parameter(Mandatory = $true)][string]$Root)

  $mingwRuntimeDlls = @(
    'libgcc_s_seh-1.dll',
    'libstdc++-6.dll',
    'libwinpthread-1.dll'
  )
  $groups = @(
    @{
      Directory = $Root
      Binaries = @((Join-Path $Root 'exv-ui.exe'))
    },
    @{
      Directory = (Join-Path $Root 'bin')
      Binaries = @(
        (Join-Path $Root 'bin\exv.exe'),
        (Join-Path $Root 'bin\exv-helper.exe')
      )
    }
  )

  foreach ($group in $groups) {
    $required = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($binary in $group.Binaries) {
      foreach ($import in (Get-PeImportDllNames -Path $binary)) {
        if ($mingwRuntimeDlls -icontains $import) {
          [void]$required.Add($import)
        }
      }
    }
    foreach ($dll in $mingwRuntimeDlls) {
      $payload = Join-Path $group.Directory $dll
      $present = Test-Path -LiteralPath $payload -PathType Leaf
      if ($required.Contains($dll) -and -not $present) {
        throw "WINDOWS_PACKAGE_RUNTIME_CLOSURE_FAILED: imported runtime missing beside its binary: $payload"
      }
      if (-not $required.Contains($dll) -and $present) {
        throw "WINDOWS_PACKAGE_RUNTIME_CLOSURE_FAILED: unimported MinGW runtime present beside binary: $payload"
      }
    }
  }
}

function Assert-SetupPeSelfContained {
  param([Parameter(Mandatory = $true)][string]$Path)

  # The installer is a single PE: no sidecar MinGW runtime DLLs ship beside it.
  # Fail packaging if the PE still imports them (dynamic link regression).
  $forbidden = @(
    'libgcc_s_seh-1.dll',
    'libstdc++-6.dll',
    'libwinpthread-1.dll'
  )

  $imports = Get-PeImportDllNames -Path $Path
  $hit = @($imports | Where-Object {
      $name = $_
      $forbidden | Where-Object { $_ -ieq $name }
    })
  if ($hit.Count -gt 0) {
    throw ("Installer PE still imports MinGW runtime DLL(s): {0}. " +
           "exv-setup must be built with -static/-static-libgcc/-static-libstdc++ " +
           "so user machines without MinGW can run the single-file setup.exe. " +
           "Path: {1}") -f (($hit | Select-Object -Unique) -join ', '), $Path
  }
}

function Resolve-SetupPayloadVerifier {
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$RequestedPath
  )

  if ([string]::IsNullOrWhiteSpace($RequestedPath)) {
    throw 'SETUP_PAYLOAD_VERIFIER_REQUIRED: pass -SetupPayloadVerifier with an absolute verifier executable path'
  }
  $isFullyQualified = $RequestedPath -match `
    '^(?:[A-Za-z]:[\\/]|[\\/]{2}[^\\/]+[\\/]+[^\\/]+(?:[\\/]|$))'
  if (-not $isFullyQualified) {
    throw "SETUP_PAYLOAD_VERIFIER_ABSOLUTE_REQUIRED: verifier path must be absolute: $RequestedPath"
  }
  try {
    $resolved = [System.IO.Path]::GetFullPath($RequestedPath)
  } catch {
    throw "SETUP_PAYLOAD_VERIFIER_ABSOLUTE_REQUIRED: verifier path must be absolute: $RequestedPath"
  }
  if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
    throw "SETUP_PAYLOAD_VERIFIER_NOT_FOUND: verifier executable not found: $resolved"
  }
  $application = Get-Command -Name $resolved -CommandType Application -ErrorAction SilentlyContinue
  if ([System.IO.Path]::GetExtension($resolved) -ine '.exe' -or -not $application) {
    throw "SETUP_PAYLOAD_VERIFIER_NOT_EXECUTABLE: verifier must be a Windows executable: $resolved"
  }
  return $resolved
}

function Invoke-SetupPayloadVerifier {
  param(
    [Parameter(Mandatory = $true)][string]$Verifier,
    [Parameter(Mandatory = $true)][string]$Setup,
    [Parameter(Mandatory = $true)][string]$PackageRoot,
    [ValidateRange(1, 3600)]
    [int]$TimeoutSeconds = 120
  )

  $result = Invoke-BoundedNativeCommand `
    -FilePath $Verifier `
    -Arguments @('--setup', $Setup, '--package-root', $PackageRoot) `
    -TimeoutSeconds $TimeoutSeconds
  if (-not [string]::IsNullOrWhiteSpace($result.LaunchError) -or
      $result.TimedOut -or
      $result.ExitCode -ne 0) {
    $detail = if ($result.TimedOut) {
      "SETUP_PAYLOAD_VERIFIER_TIMEOUT: verifier exceeded $TimeoutSeconds seconds"
    } elseif (-not [string]::IsNullOrWhiteSpace($result.LaunchError)) {
      $result.LaunchError
    } else {
      "verifier exited $($result.ExitCode)"
    }
    $unexpectedOutputs = @()
    foreach ($unverifiedOutput in @($Setup, "$Setup.exvp")) {
      if (Test-Path -LiteralPath $unverifiedOutput) {
        if (-not (Test-Path -LiteralPath $unverifiedOutput -PathType Leaf)) {
          $unexpectedOutputs += $unverifiedOutput
        }
        try {
          Remove-Item -LiteralPath $unverifiedOutput -Force -ErrorAction Stop
        } catch { }
      }
    }
    $remainingOutputs = @(
      $Setup,
      "$Setup.exvp"
    ) | Where-Object { Test-Path -LiteralPath $_ }
    $cleanupFailure = if ($unexpectedOutputs.Count -gt 0 -or
                          $remainingOutputs.Count -gt 0) {
      $details = @()
      if ($unexpectedOutputs.Count -gt 0) {
        $details += "unexpected non-leaf output: $($unexpectedOutputs -join ', ')"
      }
      if ($remainingOutputs.Count -gt 0) {
        $details += "unverified output remains: $($remainingOutputs -join ', ')"
      }
      "`nSETUP_PAYLOAD_CLEANUP_FAILED: $($details -join '; ')"
    } else {
      ''
    }
    throw "SETUP_PAYLOAD_VERIFIER_FAILED: $detail`n$($result.Output)$cleanupFailure"
  }
}

function Invoke-CustomSetupPack {
  param(
    [Parameter(Mandatory = $true)][string]$SourceDir,
    [Parameter(Mandatory = $true)][string]$OutputFile,
    [Parameter(Mandatory = $true)][string]$CppBuildDir,
    [Parameter(Mandatory = $true)][string]$Compression
  )

  Ensure-CustomSetupTools -CppBuildDir $CppBuildDir

  $stub = Resolve-AbsolutePath (Join-Path $CppBuildDir 'exv-setup.exe')
  $packer = Resolve-AbsolutePath (Join-Path $CppBuildDir 'pack_setup_payload.exe')
  $sourceAbs = Resolve-AbsolutePath $SourceDir
  $outputAbs = Resolve-AbsolutePath $OutputFile
  $outputParent = Split-Path -Parent $outputAbs
  if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    New-Item -ItemType Directory -Path $outputParent -Force | Out-Null
  }

  if (-not (Test-Path -LiteralPath $stub -PathType Leaf)) {
    throw "Custom setup stub missing: $stub"
  }
  if (-not (Test-Path -LiteralPath $packer -PathType Leaf)) {
    throw "Custom setup packer missing: $packer"
  }
  if (-not (Test-Path -LiteralPath $sourceAbs -PathType Container)) {
    throw "Custom setup package source missing: $sourceAbs"
  }

  Assert-SetupPeSelfContained -Path $stub

  Write-Host "Packing custom setup installer..." -ForegroundColor Cyan
  Write-Host "  Package: $sourceAbs"
  Write-Host "  Stub:    $stub"
  Write-Host "  Out:     $outputAbs"
  Write-Host "  Algo:    $Compression"

  # Pack to a unique temp path first, then move into place. This avoids false
  # negatives around still-open PE resource updates and keeps the final name free
  # until the payload inject has fully completed.
  $tempOut = Join-Path $env:TEMP ("exv-setup-" + [guid]::NewGuid().ToString('N') + ".exe")
  $tempExvp = "$tempOut.exvp"

  try {
    $packResult = Invoke-BoundedNativeCommand `
      -FilePath $packer `
      -Arguments @(
        '--package-dir', $sourceAbs,
        '--stub', $stub,
        '--out', $tempOut,
        '--algo', $Compression
      ) `
      -WorkingDirectory $outputParent `
      -TimeoutSeconds 900
    if ($packResult.TimedOut) {
      throw "SETUP_PACKER_TIMEOUT: pack_setup_payload exceeded 900 seconds: $packer"
    }
    if (-not [string]::IsNullOrWhiteSpace($packResult.LaunchError)) {
      throw "pack_setup_payload failed to execute: $($packResult.LaunchError)"
    }
    $packCode = $packResult.ExitCode
    $packOutput = $packResult.Output
    if (-not [string]::IsNullOrWhiteSpace($packOutput)) {
      Write-Host $packOutput.TrimEnd()
    }

    if ($packCode -ne 0) {
      throw ("pack_setup_payload failed ({0}): package={1} stub={2} out={3}`n{4}" -f `
        $packCode, $sourceAbs, $stub, $tempOut, $packOutput.Trim())
    }
    if (-not [System.IO.File]::Exists($tempOut)) {
      throw ("pack_setup_payload exited {0} but temp installer is missing: {1}`n{2}" -f `
        $packCode, $tempOut, $packOutput.Trim())
    }

    $tempItem = Get-Item -LiteralPath $tempOut
    if ($tempItem.Length -le 0) {
      throw "Custom setup temp installer is empty: $tempOut"
    }

    $bytes = [System.IO.File]::ReadAllBytes($tempOut)
    $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
    if ($ascii -notlike '*EXVP01*') {
      throw "Installer PE does not contain EXVP01 payload magic: $tempOut"
    }
    if ($ascii -notlike '*dpiAwareness*' -and $ascii -notlike '*PerMonitor*') {
      Write-Warning "Installer PE may be missing DPI awareness manifest markers: $tempOut"
    }

    Assert-SetupPeSelfContained -Path $tempOut

    if ([System.IO.File]::Exists($outputAbs)) {
      [System.IO.File]::Delete($outputAbs)
    }
    [System.IO.File]::Move($tempOut, $outputAbs)

    $exvpSibling = "$outputAbs.exvp"
    if ([System.IO.File]::Exists($tempExvp)) {
      if ([System.IO.File]::Exists($exvpSibling)) {
        [System.IO.File]::Delete($exvpSibling)
      }
      [System.IO.File]::Move($tempExvp, $exvpSibling)
    }

    $item = Get-Item -LiteralPath $outputAbs
    Write-Host ("Custom setup installer ready ({0:N2} MB): {1}" -f ($item.Length / 1MB), $outputAbs) `
      -ForegroundColor Green
  } finally {
    if ([System.IO.File]::Exists($tempOut)) {
      Remove-Item -LiteralPath $tempOut -Force -ErrorAction SilentlyContinue
    }
    if ([System.IO.File]::Exists($tempExvp)) {
      Remove-Item -LiteralPath $tempExvp -Force -ErrorAction SilentlyContinue
    }
  }
}

function Assert-InstallerOutput {
  param([Parameter(Mandatory = $true)][string]$Installer)

  if (-not (Test-Path -LiteralPath $Installer -PathType Leaf)) {
    throw "Installer was not created: $Installer"
  }

  $item = Get-Item -LiteralPath $Installer
  if ($item.Length -le 0) {
    throw "Installer is empty: $Installer"
  }
}

if ($FunctionsOnly) {
  return
}

$defaultPackageRoot = Join-Path $repoRoot 'build\windows\webview\package\EXV'
$resolvedPackageRoot = if ([string]::IsNullOrWhiteSpace($PackageRoot)) {
  $defaultPackageRoot
} else {
  Resolve-AbsolutePath $PackageRoot
}

$resolvedOutputDir = if ([string]::IsNullOrWhiteSpace($OutputDir)) {
  Join-Path $repoRoot 'build\windows\release'
} else {
  Resolve-AbsolutePath $OutputDir
}
$resolvedSetupPayloadVerifier = ''

$productVersion = if ([string]::IsNullOrWhiteSpace($Version)) {
  Get-CmakeProjectVersion -CMakeListsPath (Join-Path $repoRoot 'CMakeLists.txt')
} else {
  $Version
}
Assert-ProductVersion $productVersion
$artifactVersion = Join-ArtifactVersion -Version $productVersion -DevBuild:$DevBuild -OutputDir $resolvedOutputDir

if (-not $SkipBuild) {
  $buildScript = Join-Path $repoRoot 'scripts\build-windows.ps1'
  Invoke-Step -FilePath 'powershell.exe' -Arguments @(
    '-NoProfile',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    $buildScript,
    'desktop'
  )
}

Assert-PackageRoot $resolvedPackageRoot
Assert-PackagePeRuntimeClosure -Root $resolvedPackageRoot
New-Item -ItemType Directory -Path $resolvedOutputDir -Force | Out-Null

Invoke-PackageVerifier $resolvedPackageRoot

$portableZip = Join-Path $resolvedOutputDir "EXV-$artifactVersion-windows-x64-portable.zip"
$installerExe = Join-Path $resolvedOutputDir "EXV-$artifactVersion-windows-x64-setup.exe"
$resolvedSetupPayloadVerifier = Resolve-SetupPayloadVerifier -RequestedPath $SetupPayloadVerifier
$releasePackageRoot = ''
$releasePackageParent = ''

try {
  $releasePackageRoot = New-ReleasePackageRoot -SourceRoot $resolvedPackageRoot
  $releasePackageParent = Split-Path -Parent $releasePackageRoot

  New-PortableZip -Root $releasePackageRoot -Destination $portableZip
  Test-PortableZip -Archive $portableZip

  if ($LegacyNsis) {
    $makeNsis = Resolve-MakeNsis $NsisPath
    Invoke-Nsis -MakeNsis $makeNsis -SourceDir $releasePackageRoot -OutputFile $installerExe -AppVersion $productVersion
  } else {
    $cppBuildDir = Resolve-CppBuildDir $CppBuildDir
    Invoke-CustomSetupPack -SourceDir $releasePackageRoot -OutputFile $installerExe -CppBuildDir $cppBuildDir -Compression $SetupCompression
  }
  Assert-InstallerOutput $installerExe
  Assert-SetupPeSelfContained -Path $installerExe
  Invoke-SetupPayloadVerifier -Verifier $resolvedSetupPayloadVerifier -Setup $installerExe -PackageRoot $releasePackageRoot
}
finally {
  if (-not [string]::IsNullOrWhiteSpace($releasePackageParent) -and
      (Test-Path -LiteralPath $releasePackageParent)) {
    Remove-DirectoryWithRetry -Path $releasePackageParent -ProcessRoot $releasePackageParent
  }
}

Write-Host ''
Write-Host 'Windows release artifacts:' -ForegroundColor Cyan
Write-Host "  Product version: $productVersion"
if ($DevBuild) {
  Write-Host "  Dev package version: $artifactVersion"
}
Write-Host "  Portable: $portableZip"
Write-Host "  Installer: $installerExe"

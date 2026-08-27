<#
.SYNOPSIS
Probe whether the local Clash Verge Rev / Mihomo controller can toggle TUN.

.DESCRIPTION
This script uses Mihomo's external controller API:
  PATCH /configs
  {"tun":{"enable":true|false}}

By default it reads the current tun.enable state, toggles to the opposite
state, verifies it through GET /configs, then restores the original state.
The script never writes Clash Verge Rev configuration files and never prints
the controller secret.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-clash-tun-toggle.ps1

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-clash-tun-toggle.ps1 -Controller http://127.0.0.1:9097 -Secret "secret"

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-clash-tun-toggle.ps1 -Mode Enable -NoRestore
#>

[CmdletBinding()]
param(
  [string]$Controller = "",
  [string]$Pipe = "",
  [string]$Secret = "",
  [ValidateSet("ToggleRestore", "Enable", "Disable", "Probe")]
  [string]$Mode = "ToggleRestore",
  [switch]$NoRestore,
  [int]$TimeoutSeconds = 5,
  [int]$VerifyAttempts = 8,
  [int]$VerifyDelayMilliseconds = 750,
  [string]$OutputRoot = "",
  [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
  $scriptRoot = $PSScriptRoot
  if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
  }
  $OutputRoot = Join-Path (Join-Path $scriptRoot "..") "build\clash-tun-toggle-probe"
}

function Assert-SelfTest {
  param(
    [string]$Name,
    [bool]$Condition
  )

  if (-not $Condition) {
    throw "SelfTest failed: $Name"
  }
}

function Remove-YamlInlineComment {
  param([string]$Value)

  $inSingle = $false
  $inDouble = $false
  for ($index = 0; $index -lt $Value.Length; $index++) {
    $ch = $Value[$index]
    if ($ch -eq [char]39 -and -not $inDouble) {
      $inSingle = -not $inSingle
      continue
    }
    if ($ch -eq [char]34 -and -not $inSingle) {
      $inDouble = -not $inDouble
      continue
    }
    if ($ch -eq "#" -and -not $inSingle -and -not $inDouble) {
      if ($index -eq 0 -or [char]::IsWhiteSpace($Value[$index - 1])) {
        return $Value.Substring(0, $index).Trim()
      }
    }
  }

  return $Value.Trim()
}

function ConvertFrom-YamlScalarText {
  param([string]$Value)

  $trimmed = (Remove-YamlInlineComment -Value $Value).Trim()
  if ($trimmed.Length -ge 2) {
    $first = $trimmed[0]
    $last = $trimmed[$trimmed.Length - 1]
    if (($first -eq [char]39 -and $last -eq [char]39) -or
        ($first -eq [char]34 -and $last -eq [char]34)) {
      return $trimmed.Substring(1, $trimmed.Length - 2)
    }
  }

  return $trimmed
}

function Get-YamlTopLevelScalar {
  param(
    [string]$Content,
    [string]$Key
  )

  $escaped = [regex]::Escape($Key)
  foreach ($line in ($Content -split "\r?\n")) {
    if ($line -match "^\s*$escaped\s*:\s*(.*)$") {
      return ConvertFrom-YamlScalarText -Value $Matches[1]
    }
  }

  return $null
}

function ConvertTo-ControllerBaseUri {
  param([string]$Value)

  $trimmed = (ConvertFrom-YamlScalarText -Value $Value).Trim()
  if ([string]::IsNullOrWhiteSpace($trimmed)) {
    return $null
  }
  if ($trimmed -match "^unix://" -or $trimmed -match "^\\\\\.\\pipe\\") {
    return $null
  }
  if ($trimmed -notmatch "^[a-zA-Z][a-zA-Z0-9+\-.]*://") {
    $trimmed = "http://$trimmed"
  }

  return $trimmed.TrimEnd("/")
}

function ConvertTo-NamedPipeName {
  param([string]$Value)

  $trimmed = (ConvertFrom-YamlScalarText -Value $Value).Trim()
  if ([string]::IsNullOrWhiteSpace($trimmed)) {
    return $null
  }

  if ($trimmed -match '^\\\\\.\\pipe\\(.+)$') {
    return $Matches[1]
  }

  return $null
}

function ConvertTo-NamedPipeDisplay {
  param([string]$PipeName)

  if ([string]::IsNullOrWhiteSpace($PipeName)) {
    return ""
  }

  return "\\.\pipe\$PipeName"
}

function Write-StreamWithTimeout {
  param(
    [System.IO.Stream]$Stream,
    [byte[]]$Bytes,
    [int]$TimeoutMilliseconds,
    [string]$TimeoutMessage
  )

  $async = $Stream.BeginWrite($Bytes, 0, $Bytes.Length, $null, $null)
  try {
    if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) {
      throw $TimeoutMessage
    }
    $Stream.EndWrite($async)
  } finally {
    $async.AsyncWaitHandle.Close()
  }
}

function Read-StreamToEndWithTimeout {
  param(
    [System.IO.Stream]$Stream,
    [System.Text.Encoding]$Encoding,
    [int]$TimeoutMilliseconds,
    [string]$TimeoutMessage
  )

  $buffer = New-Object byte[] 8192
  $memory = New-Object System.IO.MemoryStream
  try {
    while ($true) {
      $async = $Stream.BeginRead($buffer, 0, $buffer.Length, $null, $null)
      try {
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) {
          throw $TimeoutMessage
        }
        $count = $Stream.EndRead($async)
      } finally {
        $async.AsyncWaitHandle.Close()
      }

      if ($count -le 0) {
        break
      }
      $memory.Write($buffer, 0, $count)
    }

    return $Encoding.GetString($memory.ToArray())
  } finally {
    $memory.Dispose()
  }
}

function Hide-Secret {
  param([string]$Value)

  if ([string]::IsNullOrEmpty($Value)) {
    return "not set"
  }

  return "<redacted>"
}

function New-MihomoHeaders {
  param([string]$Value)

  $headers = @{}
  if (-not [string]::IsNullOrEmpty($Value)) {
    $headers["Authorization"] = "Bearer $Value"
  }

  return $headers
}

function New-TunPatchBody {
  param([bool]$Enabled)

  return @{
    tun = @{
      enable = $Enabled
    }
  }
}

function Test-ObjectProperty {
  param(
    [object]$Value,
    [string]$Name
  )

  if ($null -eq $Value) {
    return $false
  }

  return $null -ne $Value.PSObject.Properties[$Name]
}

function Get-TunEnabledFromConfig {
  param([object]$Config)

  if (-not (Test-ObjectProperty -Value $Config -Name "tun")) {
    return $null
  }

  $tun = $Config.tun
  if (-not (Test-ObjectProperty -Value $tun -Name "enable")) {
    return $null
  }

  return [bool]$tun.enable
}

function Resolve-OutputRoot {
  param([string]$Path)

  if ([System.IO.Path]::IsPathRooted($Path)) {
    return $Path
  }

  return Join-Path (Get-Location).Path $Path
}

function New-ArtifactDirectory {
  param([string]$Root)

  $resolvedRoot = Resolve-OutputRoot -Path $Root
  New-Item -ItemType Directory -Path $resolvedRoot -Force | Out-Null
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $dir = Join-Path $resolvedRoot $stamp
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  return $dir
}

function Get-ClashConfigCandidatePaths {
  $roots = @(
    $env:APPDATA,
    $env:LOCALAPPDATA
  ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

  $relativePaths = @(
    "io.github.clash-verge-rev.clash-verge-rev\clash-verge.yaml",
    "io.github.clash-verge-rev.clash-verge-rev\config.yaml",
    "io.github.clash-verge-rev.clash-verge-rev\verge.yaml",
    "clash-verge-rev\clash-verge.yaml",
    "clash-verge-rev\config.yaml",
    "clash-verge\clash-verge.yaml",
    "Clash Verge\clash-verge.yaml",
    "mihomo\config.yaml"
  )

  $seen = @{}
  $paths = New-Object "System.Collections.Generic.List[string]"
  foreach ($root in $roots) {
    foreach ($relative in $relativePaths) {
      $candidate = Join-Path $root $relative
      if ((Test-Path -LiteralPath $candidate) -and -not $seen.ContainsKey($candidate)) {
        $seen[$candidate] = $true
        $paths.Add($candidate) | Out-Null
      }
    }
  }

  return $paths.ToArray()
}

function Get-ConfigDiscoveryRecords {
  $records = New-Object "System.Collections.Generic.List[object]"
  foreach ($path in Get-ClashConfigCandidatePaths) {
    try {
      $content = Get-Content -LiteralPath $path -Raw
      $controllerValue = Get-YamlTopLevelScalar -Content $content -Key "external-controller"
      $pipeValue = Get-YamlTopLevelScalar -Content $content -Key "external-controller-pipe"
      $secretValue = Get-YamlTopLevelScalar -Content $content -Key "secret"
      if (-not [string]::IsNullOrWhiteSpace($controllerValue) -or
          -not [string]::IsNullOrWhiteSpace($pipeValue) -or
          $null -ne $secretValue) {
        $records.Add([pscustomobject]@{
          Path = $path
          Controller = ConvertTo-ControllerBaseUri -Value ([string]$controllerValue)
          PipeName = ConvertTo-NamedPipeName -Value ([string]$pipeValue)
          Secret = [string]$secretValue
        }) | Out-Null
      }
    } catch {
      $records.Add([pscustomobject]@{
        Path = $path
        Controller = $null
        PipeName = $null
        Secret = ""
        Error = $_.Exception.Message
      }) | Out-Null
    }
  }

  return $records.ToArray()
}

function Add-MihomoHttpCandidate {
  param(
    [System.Collections.Generic.List[object]]$Candidates,
    [hashtable]$Seen,
    [string]$ControllerValue,
    [string]$SecretValue,
    [string]$Source
  )

  $baseUri = ConvertTo-ControllerBaseUri -Value $ControllerValue
  if ([string]::IsNullOrWhiteSpace($baseUri)) {
    return
  }

  $secretKey = if ([string]::IsNullOrEmpty($SecretValue)) { "" } else { "<set>" }
  $key = "$baseUri|$secretKey"
  if ($Seen.ContainsKey($key)) {
    return
  }

  $Seen[$key] = $true
  $Candidates.Add([pscustomobject]@{
    Protocol = "http"
    Controller = $baseUri
    PipeName = ""
    Secret = $SecretValue
    Source = $Source
  }) | Out-Null
}

function Add-MihomoPipeCandidate {
  param(
    [System.Collections.Generic.List[object]]$Candidates,
    [hashtable]$Seen,
    [string]$PipeValue,
    [string]$SecretValue,
    [string]$Source
  )

  $pipeName = ConvertTo-NamedPipeName -Value $PipeValue
  if ([string]::IsNullOrWhiteSpace($pipeName)) {
    return
  }

  $secretKey = if ([string]::IsNullOrEmpty($SecretValue)) { "" } else { "<set>" }
  $key = "pipe:$pipeName|$secretKey"
  if ($Seen.ContainsKey($key)) {
    return
  }

  $Seen[$key] = $true
  $Candidates.Add([pscustomobject]@{
    Protocol = "pipe"
    Controller = ConvertTo-NamedPipeDisplay -PipeName $pipeName
    PipeName = $pipeName
    Secret = $SecretValue
    Source = $Source
  }) | Out-Null
}

function Get-MihomoControllerCandidates {
  param(
    [string]$ControllerValue,
    [string]$PipeValue,
    [string]$SecretValue
  )

  $candidates = New-Object "System.Collections.Generic.List[object]"
  $seen = @{}
  if (-not [string]::IsNullOrWhiteSpace($PipeValue)) {
    Add-MihomoPipeCandidate -Candidates $candidates -Seen $seen -PipeValue $PipeValue -SecretValue $SecretValue -Source "parameter"
  }
  if (-not [string]::IsNullOrWhiteSpace($ControllerValue)) {
    Add-MihomoHttpCandidate -Candidates $candidates -Seen $seen -ControllerValue $ControllerValue -SecretValue $SecretValue -Source "parameter"
  }

  $records = @(Get-ConfigDiscoveryRecords)
  $firstDiscoveredSecret = ""
  foreach ($record in $records) {
    if ([string]::IsNullOrEmpty($firstDiscoveredSecret) -and
        (Test-ObjectProperty -Value $record -Name "Secret") -and
        -not [string]::IsNullOrEmpty($record.Secret)) {
      $firstDiscoveredSecret = $record.Secret
    }

    if ((Test-ObjectProperty -Value $record -Name "PipeName") -and
        -not [string]::IsNullOrWhiteSpace($record.PipeName)) {
      $effectiveSecret = if (-not [string]::IsNullOrEmpty($SecretValue)) { $SecretValue } else { $record.Secret }
      Add-MihomoPipeCandidate -Candidates $candidates -Seen $seen -PipeValue (ConvertTo-NamedPipeDisplay -PipeName $record.PipeName) -SecretValue $effectiveSecret -Source $record.Path
    }

    if ((Test-ObjectProperty -Value $record -Name "Controller") -and
        -not [string]::IsNullOrWhiteSpace($record.Controller)) {
      $effectiveSecret = if (-not [string]::IsNullOrEmpty($SecretValue)) { $SecretValue } else { $record.Secret }
      Add-MihomoHttpCandidate -Candidates $candidates -Seen $seen -ControllerValue $record.Controller -SecretValue $effectiveSecret -Source $record.Path
    }
  }

  if ([string]::IsNullOrEmpty($SecretValue)) {
    $SecretValue = $firstDiscoveredSecret
  }

  if ([string]::IsNullOrWhiteSpace($ControllerValue)) {
    Add-MihomoHttpCandidate -Candidates $candidates -Seen $seen -ControllerValue "http://127.0.0.1:9097" -SecretValue $SecretValue -Source "default:clash-verge-rev"
    Add-MihomoHttpCandidate -Candidates $candidates -Seen $seen -ControllerValue "http://127.0.0.1:9090" -SecretValue $SecretValue -Source "default:mihomo"
  }

  return $candidates.ToArray()
}

function Get-ErrorSummary {
  param([System.Management.Automation.ErrorRecord]$ErrorRecord)

  $response = $null
  try {
    $response = $ErrorRecord.Exception.Response
  } catch {
    $response = $null
  }

  if ($null -ne $response) {
    try {
      $statusCode = [int]$response.StatusCode
      $statusDescription = [string]$response.StatusDescription
      if (-not [string]::IsNullOrEmpty($statusDescription)) {
        return "HTTP $statusCode $statusDescription"
      }
      return "HTTP $statusCode"
    } catch {
      return $ErrorRecord.Exception.Message
    }
  }

  return $ErrorRecord.Exception.Message
}

function ConvertFrom-PipeHttpResponse {
  param([string]$ResponseText)

  $separator = "`r`n`r`n"
  $headerEnd = $ResponseText.IndexOf($separator, [System.StringComparison]::Ordinal)
  if ($headerEnd -lt 0) {
    $separator = "`n`n"
    $headerEnd = $ResponseText.IndexOf($separator, [System.StringComparison]::Ordinal)
  }
  if ($headerEnd -lt 0) {
    throw "Invalid named pipe HTTP response: missing header terminator."
  }

  $headerText = $ResponseText.Substring(0, $headerEnd)
  $bodyText = $ResponseText.Substring($headerEnd + $separator.Length)
  $statusLine = ($headerText -split "\r?\n")[0]
  if ($statusLine -notmatch '^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+(.*))?$') {
    throw "Invalid named pipe HTTP response status line: $statusLine"
  }

  $body = $null
  if (-not [string]::IsNullOrWhiteSpace($bodyText)) {
    $body = $bodyText | ConvertFrom-Json
  }

  return [pscustomobject]@{
    StatusCode = [int]$Matches[1]
    Reason = [string]$Matches[2]
    Body = $body
  }
}

function Invoke-MihomoPipeRequest {
  param(
    [ValidateSet("GET", "PATCH")]
    [string]$Method,
    [string]$PipeName,
    [string]$Path,
    [string]$SecretValue,
    [object]$Body,
    [int]$RequestTimeoutSeconds
  )

  $bodyJson = ""
  if ($null -ne $Body) {
    $bodyJson = $Body | ConvertTo-Json -Depth 8 -Compress
  }

  $timeoutMilliseconds = [Math]::Max(1, $RequestTimeoutSeconds) * 1000
  $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", $PipeName, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
  try {
    $pipe.Connect($timeoutMilliseconds)
    $crlf = [string]([char]13) + [string]([char]10)
    $request = "$Method $Path HTTP/1.1$crlf"
    $request += "Host: mihomo$crlf"
    if (-not [string]::IsNullOrEmpty($SecretValue)) {
      $request += "Authorization: Bearer $SecretValue$crlf"
    }
    if ($bodyJson.Length -gt 0) {
      $request += "Content-Type: application/json$crlf"
      $request += "Content-Length: $([System.Text.Encoding]::UTF8.GetByteCount($bodyJson))$crlf"
    }
    $request += "Connection: close$crlf$crlf"
    if ($bodyJson.Length -gt 0) {
      $request += $bodyJson
    }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($request)
    Write-StreamWithTimeout `
      -Stream $pipe `
      -Bytes $bytes `
      -TimeoutMilliseconds $timeoutMilliseconds `
      -TimeoutMessage "Timed out writing named pipe request to \\.\pipe\$PipeName"
    $pipe.Flush()

    $response = Read-StreamToEndWithTimeout `
      -Stream $pipe `
      -Encoding ([System.Text.Encoding]::UTF8) `
      -TimeoutMilliseconds $timeoutMilliseconds `
      -TimeoutMessage "Timed out reading named pipe response from \\.\pipe\$PipeName"
    $parsed = ConvertFrom-PipeHttpResponse -ResponseText $response
    if ($parsed.StatusCode -lt 200 -or $parsed.StatusCode -ge 300) {
      $reason = if ([string]::IsNullOrWhiteSpace($parsed.Reason)) { "" } else { " $($parsed.Reason)" }
      throw "HTTP $($parsed.StatusCode)$reason"
    }

    return $parsed.Body
  } finally {
    $pipe.Dispose()
  }
}

function Invoke-MihomoRequest {
  param(
    [ValidateSet("GET", "PATCH")]
    [string]$Method,
    [object]$Connection,
    [string]$Path,
    [object]$Body,
    [int]$RequestTimeoutSeconds
  )

  if ((Test-ObjectProperty -Value $Connection -Name "Protocol") -and
      $Connection.Protocol -eq "pipe") {
    return Invoke-MihomoPipeRequest -Method $Method -PipeName $Connection.PipeName -Path $Path -SecretValue $Connection.Secret -Body $Body -RequestTimeoutSeconds $RequestTimeoutSeconds
  }

  $uri = "$($Connection.Controller.TrimEnd("/"))$Path"
  $parameters = @{
    Method = $Method
    Uri = $uri
    TimeoutSec = $RequestTimeoutSeconds
    ErrorAction = "Stop"
  }

  $headers = New-MihomoHeaders -Value $Connection.Secret
  if ($headers.Count -gt 0) {
    $parameters["Headers"] = $headers
  }

  if ($null -ne $Body) {
    $parameters["Body"] = ($Body | ConvertTo-Json -Depth 8 -Compress)
    $parameters["ContentType"] = "application/json"
  }

  return Invoke-RestMethod @parameters
}

function Get-MihomoConfigs {
  param(
    [object]$Connection,
    [int]$RequestTimeoutSeconds
  )

  return Invoke-MihomoRequest -Method "GET" -Connection $Connection -Path "/configs" -Body $null -RequestTimeoutSeconds $RequestTimeoutSeconds
}

function Set-MihomoTunState {
  param(
    [object]$Connection,
    [bool]$Enabled,
    [int]$RequestTimeoutSeconds
  )

  Invoke-MihomoRequest -Method "PATCH" -Connection $Connection -Path "/configs" -Body (New-TunPatchBody -Enabled $Enabled) -RequestTimeoutSeconds $RequestTimeoutSeconds | Out-Null
}

function Wait-MihomoTunState {
  param(
    [object]$Connection,
    [bool]$Expected,
    [int]$RequestTimeoutSeconds,
    [int]$Attempts,
    [int]$DelayMilliseconds
  )

  $lastValue = $null
  for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
    if ($attempt -gt 1 -and $DelayMilliseconds -gt 0) {
      Start-Sleep -Milliseconds $DelayMilliseconds
    }

    $config = Get-MihomoConfigs -Connection $Connection -RequestTimeoutSeconds $RequestTimeoutSeconds
    $lastValue = Get-TunEnabledFromConfig -Config $config
    if ($null -ne $lastValue -and [bool]$lastValue -eq $Expected) {
      return [pscustomobject]@{
        Matched = $true
        Value = [bool]$lastValue
        Attempts = $attempt
      }
    }
  }

  return [pscustomobject]@{
    Matched = $false
    Value = $lastValue
    Attempts = $Attempts
  }
}

function Connect-MihomoController {
  param(
    [object[]]$Candidates,
    [int]$RequestTimeoutSeconds
  )

  $failures = New-Object "System.Collections.Generic.List[object]"
  foreach ($candidate in $Candidates) {
    Write-Host "Trying Mihomo controller $($candidate.Controller) (protocol: $($candidate.Protocol), source: $($candidate.Source), secret: $(Hide-Secret -Value $candidate.Secret))"
    try {
      $config = Get-MihomoConfigs -Connection $candidate -RequestTimeoutSeconds $RequestTimeoutSeconds
      return [pscustomobject]@{
        Protocol = $candidate.Protocol
        Controller = $candidate.Controller
        PipeName = $candidate.PipeName
        Secret = $candidate.Secret
        Source = $candidate.Source
        Config = $config
        Failures = $failures.ToArray()
      }
    } catch {
      $failures.Add([pscustomobject]@{
        Controller = $candidate.Controller
        Protocol = $candidate.Protocol
        Source = $candidate.Source
        Error = Get-ErrorSummary -ErrorRecord $_
      }) | Out-Null
    }
  }

  $details = ($failures | ForEach-Object { "$($_.Controller) [$($_.Protocol), $($_.Source)]: $($_.Error)" }) -join "; "
  throw "Could not connect to a Mihomo controller. Tried: $details"
}

function Get-TunAdapterSnapshot {
  $command = Get-Command Get-NetAdapter -ErrorAction SilentlyContinue
  if ($null -eq $command) {
    return @()
  }

  try {
    return @(Get-NetAdapter |
      Where-Object {
        $_.Name -match "(?i)mihomo|clash|meta|tun|wintun" -or
        $_.InterfaceDescription -match "(?i)mihomo|clash|meta|tun|wintun"
      } |
      Select-Object Name, InterfaceDescription, Status, LinkSpeed, ifIndex)
  } catch {
    return @([pscustomobject]@{
      Error = $_.Exception.Message
    })
  }
}

function Write-ProbeSummary {
  param(
    [string]$ArtifactDir,
    [hashtable]$Summary
  )

  $jsonPath = Join-Path $ArtifactDir "summary.json"
  $markdownPath = Join-Path $ArtifactDir "summary.md"

  ($Summary | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $jsonPath -Encoding UTF8

  $lines = New-Object "System.Collections.Generic.List[string]"
  $lines.Add("# Clash/Mihomo TUN toggle probe") | Out-Null
  $lines.Add("") | Out-Null
  $lines.Add("- Started: $($Summary.started_at)") | Out-Null
  $lines.Add("- Finished: $($Summary.finished_at)") | Out-Null
  $lines.Add("- Success: $($Summary.success)") | Out-Null
  $lines.Add("- Mode: $($Summary.mode)") | Out-Null
  $lines.Add("- Controller: $($Summary.controller)") | Out-Null
  $lines.Add("- Controller source: $($Summary.controller_source)") | Out-Null
  $lines.Add("- Secret: $($Summary.secret)") | Out-Null
  $lines.Add("- Initial tun.enable: $($Summary.initial_tun_enable)") | Out-Null
  $lines.Add("- Target tun.enable: $($Summary.target_tun_enable)") | Out-Null
  $lines.Add("- Changed tun.enable: $($Summary.changed_tun_enable)") | Out-Null
  $lines.Add("- Restored tun.enable: $($Summary.restored_tun_enable)") | Out-Null
  if (-not [string]::IsNullOrEmpty([string]$Summary.error)) {
    $lines.Add("- Error: $($Summary.error)") | Out-Null
  }
  $lines.Add("") | Out-Null
  $lines.Add("Raw JSON summary: $jsonPath") | Out-Null
  $lines | Set-Content -LiteralPath $markdownPath -Encoding UTF8

  return [pscustomobject]@{
    Json = $jsonPath
    Markdown = $markdownPath
  }
}

function Invoke-SelfTest {
  Assert-SelfTest -Name "controller host:port normalized" -Condition ((ConvertTo-ControllerBaseUri -Value "127.0.0.1:9097") -eq "http://127.0.0.1:9097")
  Assert-SelfTest -Name "controller trailing slash trimmed" -Condition ((ConvertTo-ControllerBaseUri -Value "http://127.0.0.1:9097/") -eq "http://127.0.0.1:9097")
  Assert-SelfTest -Name "pipe controller ignored" -Condition ($null -eq (ConvertTo-ControllerBaseUri -Value "\\.\pipe\mihomo"))
  Assert-SelfTest -Name "windows pipe normalized" -Condition ((ConvertTo-NamedPipeName -Value "\\.\pipe\verge-mihomo") -eq "verge-mihomo")

  $sampleYaml = @"
external-controller: '127.0.0.1:9097' # local API
external-controller-pipe: \\.\pipe\verge-mihomo
secret: "abc#def"
mode: rule
"@
  Assert-SelfTest -Name "yaml controller scalar" -Condition ((Get-YamlTopLevelScalar -Content $sampleYaml -Key "external-controller") -eq "127.0.0.1:9097")
  Assert-SelfTest -Name "yaml pipe scalar" -Condition ((Get-YamlTopLevelScalar -Content $sampleYaml -Key "external-controller-pipe") -eq "\\.\pipe\verge-mihomo")
  Assert-SelfTest -Name "yaml quoted secret keeps hash" -Condition ((Get-YamlTopLevelScalar -Content $sampleYaml -Key "secret") -eq "abc#def")
  Assert-SelfTest -Name "secret redacted" -Condition ((Hide-Secret -Value "abc") -eq "<redacted>")

  $bodyJson = New-TunPatchBody -Enabled $true | ConvertTo-Json -Depth 4 -Compress
  $body = $bodyJson | ConvertFrom-Json
  Assert-SelfTest -Name "tun patch body enables" -Condition ($body.tun.enable -eq $true)

  $config = (@{ tun = @{ enable = $false } } | ConvertTo-Json -Depth 4 | ConvertFrom-Json)
  Assert-SelfTest -Name "extract tun.enable false" -Condition ((Get-TunEnabledFromConfig -Config $config) -eq $false)
  $configWithoutTun = (@{ mode = "rule" } | ConvertTo-Json | ConvertFrom-Json)
  Assert-SelfTest -Name "missing tun returns null" -Condition ($null -eq (Get-TunEnabledFromConfig -Config $configWithoutTun))

  try {
    throw "plain failure"
  } catch {
    Assert-SelfTest -Name "plain error summary" -Condition ((Get-ErrorSummary -ErrorRecord $_) -match "plain failure")
  }

  $candidates = @(Get-MihomoControllerCandidates -ControllerValue "127.0.0.1:9097" -SecretValue "abc")
  Assert-SelfTest -Name "parameter candidate exists" -Condition ($candidates.Count -ge 1)
  Assert-SelfTest -Name "parameter candidate normalized" -Condition ($candidates[0].Controller -eq "http://127.0.0.1:9097")
  Assert-SelfTest -Name "parameter candidate keeps secret" -Condition ($candidates[0].Secret -eq "abc")

  $pipeResponse = "HTTP/1.1 200 OK`r`nContent-Type: application/json`r`nContent-Length: 24`r`n`r`n{""tun"":{""enable"":true}}"
  $parsedPipeResponse = ConvertFrom-PipeHttpResponse -ResponseText $pipeResponse
  Assert-SelfTest -Name "pipe response status parsed" -Condition ($parsedPipeResponse.StatusCode -eq 200)
  Assert-SelfTest -Name "pipe response body parsed" -Condition ((Get-TunEnabledFromConfig -Config $parsedPipeResponse.Body) -eq $true)

  Write-Host "SelfTest passed."
}

function Invoke-TunToggleProbe {
  $artifactDir = New-ArtifactDirectory -Root $OutputRoot
  $summary = [ordered]@{
    started_at = (Get-Date).ToString("o")
    finished_at = ""
    success = $false
    mode = $Mode
    no_restore = [bool]$NoRestore
    controller = ""
    controller_source = ""
    secret = "not set"
    initial_tun_enable = $null
    target_tun_enable = $null
    changed_tun_enable = $null
    restored_tun_enable = $null
    verify_attempts = $VerifyAttempts
    verify_delay_milliseconds = $VerifyDelayMilliseconds
    adapter_before = @()
    adapter_after_change = @()
    adapter_after_restore = @()
    candidate_failures = @()
    error = ""
  }

  $connection = $null
  $failure = $null
  $restorePending = $false
  $restoreTarget = $false

  try {
    $candidates = @(Get-MihomoControllerCandidates -ControllerValue $Controller -PipeValue $Pipe -SecretValue $Secret)
    if ($candidates.Count -eq 0) {
      throw "No Mihomo controller candidates were discovered."
    }

    $connection = Connect-MihomoController -Candidates $candidates -RequestTimeoutSeconds $TimeoutSeconds
    $summary.controller = $connection.Controller
    $summary.controller_source = $connection.Source
    $summary.secret = Hide-Secret -Value $connection.Secret
    $summary.candidate_failures = @($connection.Failures)
    $summary.adapter_before = @(Get-TunAdapterSnapshot)

    $initial = Get-TunEnabledFromConfig -Config $connection.Config
    if ($null -eq $initial) {
      throw "GET /configs did not expose tun.enable; cannot safely verify the toggle."
    }
    $summary.initial_tun_enable = [bool]$initial

    if ($Mode -eq "Probe") {
      $summary.success = $true
      return $summary
    }

    $target = -not [bool]$initial
    if ($Mode -eq "Enable") {
      $target = $true
    } elseif ($Mode -eq "Disable") {
      $target = $false
    }
    $summary.target_tun_enable = [bool]$target

    if (-not $NoRestore) {
      $restorePending = $true
      $restoreTarget = [bool]$initial
    }

    Set-MihomoTunState -Connection $connection -Enabled ([bool]$target) -RequestTimeoutSeconds $TimeoutSeconds
    $changeResult = Wait-MihomoTunState -Connection $connection -Expected ([bool]$target) -RequestTimeoutSeconds $TimeoutSeconds -Attempts $VerifyAttempts -DelayMilliseconds $VerifyDelayMilliseconds
    $summary.changed_tun_enable = $changeResult.Value
    $summary.adapter_after_change = @(Get-TunAdapterSnapshot)
    if (-not $changeResult.Matched) {
      throw "Timed out waiting for tun.enable=$target after $($changeResult.Attempts) checks; last value was $($changeResult.Value)."
    }

    if ($restorePending) {
      Set-MihomoTunState -Connection $connection -Enabled $restoreTarget -RequestTimeoutSeconds $TimeoutSeconds
      $restoreResult = Wait-MihomoTunState -Connection $connection -Expected $restoreTarget -RequestTimeoutSeconds $TimeoutSeconds -Attempts $VerifyAttempts -DelayMilliseconds $VerifyDelayMilliseconds
      $summary.restored_tun_enable = $restoreResult.Value
      $summary.adapter_after_restore = @(Get-TunAdapterSnapshot)
      $restorePending = $false
      if (-not $restoreResult.Matched) {
        throw "Timed out restoring tun.enable=$restoreTarget after $($restoreResult.Attempts) checks; last value was $($restoreResult.Value)."
      }
    }

    $summary.success = $true
    return $summary
  } catch {
    $failure = $_
    $summary.error = Get-ErrorSummary -ErrorRecord $_
    return $summary
  } finally {
    if ($restorePending -and $null -ne $connection) {
      try {
        Write-Host "Restoring original tun.enable=$restoreTarget after failure..."
        Set-MihomoTunState -Connection $connection -Enabled $restoreTarget -RequestTimeoutSeconds $TimeoutSeconds
        $restoreResult = Wait-MihomoTunState -Connection $connection -Expected $restoreTarget -RequestTimeoutSeconds $TimeoutSeconds -Attempts $VerifyAttempts -DelayMilliseconds $VerifyDelayMilliseconds
        $summary.restored_tun_enable = $restoreResult.Value
        $summary.adapter_after_restore = @(Get-TunAdapterSnapshot)
      } catch {
        $summary.error = "$($summary.error); restore failed: $(Get-ErrorSummary -ErrorRecord $_)"
      }
    }

    $summary.finished_at = (Get-Date).ToString("o")
    $paths = Write-ProbeSummary -ArtifactDir $artifactDir -Summary $summary
    Write-Host "TUN toggle probe summary written to $($paths.Markdown)"
    Write-Host "Raw JSON summary written to $($paths.Json)"

    if ($null -ne $failure -and -not [string]::IsNullOrWhiteSpace($summary.error)) {
      [Console]::Error.WriteLine($summary.error)
    }
  }
}

if ($SelfTest) {
  Invoke-SelfTest
  exit 0
}

$result = Invoke-TunToggleProbe
if (-not $result.success) {
  exit 1
}

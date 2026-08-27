[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $InputPath
)

function Collect-ServiceSnapshot {
    param(
        [string] $ServiceName = 'exv-engine'
    )

    throw 'Collect-ServiceSnapshot is not implemented in the RED contract.'
}

function Collect-ServiceTimeline {
    param(
        [string] $ServiceName = 'exv-engine',
        [datetime] $StartTime = (Get-Date)
    )

    throw 'Collect-ServiceTimeline is not implemented in the RED contract.'
}

function Assert-ServiceTimeline {
    param(
        [AllowEmptyCollection()]
        [object[]] $Events
    )

    $requiredPhases = @(
        'start_service_called'
        'scm_start_pending'
        'scm_running'
        'control_pipe_ready'
        'keepalive_probe'
        'scm_stopped'
    )

    $presentPhases = @($Events | ForEach-Object { $_.phase })
    $missingPhases = @($requiredPhases | Where-Object { $presentPhases -notcontains $_ })
    $missingTimestamp = $Events.Count -eq 0 -or @($Events | Where-Object { $null -eq $_.timestamp_unix_ms }).Count -gt 0
    $missingPid = $Events.Count -eq 0 -or @($Events | Where-Object { $null -eq $_.pid }).Count -gt 0

    $failures = [System.Collections.Generic.List[string]]::new()
    if ($missingPhases.Count -gt 0) {
        [void] $failures.Add("missing phase=$($missingPhases -join ',')")
    }
    if ($missingTimestamp) {
        [void] $failures.Add('missing timestamp_unix_ms')
    }
    if ($missingPid) {
        [void] $failures.Add('missing pid')
    }
    if ($failures.Count -gt 0) {
        throw ($failures -join '; ')
    }
}

if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) {
    throw "InputPath does not exist: $InputPath"
}

$events = @()
Assert-ServiceTimeline -Events $events

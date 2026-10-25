<#
.SYNOPSIS
    Block until the backend is ready, or give up and say why.

.DESCRIPTION
    Polls /api/v1/health/ready, which reports the database check as well as the
    process being up. That distinction is the reason this script exists: a
    container that is listening is not a backend that can serve a request, and
    a seed script run one second too early fails with a connection error that
    looks like a bug in the seed script.

    Exit codes: 0 ready, 1 reachable but not ready, 2 never reachable.

.EXAMPLE
    ./scripts/wait_for_backend.ps1
    ./scripts/wait_for_backend.ps1 -Timeout 120 -Url http://localhost:8000
#>
[CmdletBinding()]
param(
    [string]$Url = $(if ($env:MULEGUARD_BASE_URL) { $env:MULEGUARD_BASE_URL } else { 'http://localhost:8000' }),
    [int]$Timeout = 60,
    [int]$Interval = 1
)

$ErrorActionPreference = 'Stop'

$readyUrl = "$($Url.TrimEnd('/'))/api/v1/health/ready"
$deadline = (Get-Date).AddSeconds($Timeout)
$everReached = $false
$lastBody = $null

Write-Host "waiting for $readyUrl (timeout ${Timeout}s)" -NoNewline

while ((Get-Date) -lt $deadline) {
    try {
        $response = Invoke-RestMethod -Uri $readyUrl -TimeoutSec 5 -ErrorAction Stop
        $everReached = $true
        $lastBody = $response | ConvertTo-Json -Depth 6 -Compress

        # The endpoint answers 200 with ready:false while a dependency check is
        # still failing, so the status code alone is not the signal.
        if ($response.ready -eq $true) {
            Write-Host "`nready"
            exit 0
        }
    }
    catch {
        # Not up yet, or not up at all. Which one is decided after the loop.
    }

    Write-Host '.' -NoNewline
    Start-Sleep -Seconds $Interval
}

Write-Host ''

if (-not $everReached) {
    Write-Error "never reached $readyUrl in ${Timeout}s."
    Write-Host 'Is the backend running?  ./scripts/run_backend_dev.ps1'
    Write-Host 'In Docker?               docker compose logs -f backend'
    exit 2
}

Write-Error "reachable but not ready after ${Timeout}s."
Write-Host 'The process is up and a dependency check is failing. Last response:'
Write-Host ($lastBody.Substring(0, [Math]::Min(2000, $lastBody.Length)))
Write-Host ''
Write-Host 'Most often this is the database: check DATABASE_URL, and that migrations'
Write-Host 'have run (make migrate, or alembic upgrade head).'
exit 1

<#
.SYNOPSIS
    Run the frontend development server.

.DESCRIPTION
    Checks that the backend is reachable first and warns rather than refusing:
    a frontend with no backend still renders, every panel shows its error
    state, and that is occasionally what you want to look at.

.EXAMPLE
    ./scripts/run_frontend_dev.ps1
    ./scripts/run_frontend_dev.ps1 -Port 5174
#>
[CmdletBinding()]
param(
    [int]$Port = 5173,
    [switch]$SkipBackendCheck
)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

if (-not (Test-Path 'frontend/node_modules')) {
    Write-Error 'frontend/node_modules not found. Install first:'
    Write-Host '  cd frontend; npm ci'
    exit 1
}

if (-not (Test-Path 'frontend/.env')) {
    Write-Host 'frontend/.env not found; copying the example'
    Copy-Item 'frontend/.env.example' 'frontend/.env'
}

$apiBase = if ($env:VITE_API_BASE_URL) { $env:VITE_API_BASE_URL } else { 'http://localhost:8000' }

if (-not $SkipBackendCheck) {
    try {
        Invoke-WebRequest -Uri "$($apiBase.TrimEnd('/'))/health" -TimeoutSec 3 -UseBasicParsing | Out-Null
    }
    catch {
        Write-Warning "No backend at $apiBase."
        Write-Host '         The app will render with every panel in its error state.'
        Write-Host '         Start one:  ./scripts/run_backend_dev.ps1'
    }
}

Set-Location 'frontend'
Write-Host "serving on http://localhost:$Port  (API at $apiBase)"
# Passed through the environment, not as a CLI argument: PowerShell strips
# the `--` that `npm run dev -- --port` relies on, and vite ends up
# treating the bare port number as a project directory.
$env:VITE_DEV_PORT = $Port
npm run dev

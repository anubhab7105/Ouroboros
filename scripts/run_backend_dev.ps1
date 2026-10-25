<#
.SYNOPSIS
    Run the backend for development: migrate, then serve with reload.

.DESCRIPTION
    Migrations run first, every time. A backend started against a database one
    revision behind fails on the first query that touches the changed table,
    which happens in the middle of a request rather than at startup, and the
    error names a column instead of naming the cause.

.EXAMPLE
    ./scripts/run_backend_dev.ps1
    ./scripts/run_backend_dev.ps1 -Port 8080 -NoMigrate
#>
[CmdletBinding()]
param(
    [string]$BindHost = '127.0.0.1',
    [int]$Port = 8000,
    [switch]$NoMigrate,
    [switch]$NoReload
)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

if (-not (Test-Path 'backend/.env')) {
    Write-Error 'backend/.env not found.'
    Write-Host 'Start from the example:  Copy-Item backend/.env.example backend/.env'
    Write-Host 'Then set BACKEND_SECRET_KEY, which has no default by design.'
    exit 1
}

try {
    python -c 'import fastapi' 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'not importable' }
}
catch {
    Write-Error 'FastAPI is not importable. Install the requirements:'
    Write-Host '  python -m venv .venv; .\.venv\Scripts\Activate.ps1'
    Write-Host '  pip install -r backend/requirements.txt -r backend/requirements-dev.txt'
    exit 1
}

# 127.0.0.1 rather than 0.0.0.0 by default. A development server bound to every
# interface is reachable from the network it is on, and this one ships with
# known development usernames.
if ($BindHost -eq '0.0.0.0') {
    Write-Warning 'Binding to 0.0.0.0 exposes a development server with known usernames to your whole network.'
}

Set-Location 'backend'

if (-not $NoMigrate) {
    Write-Host 'running migrations'
    alembic upgrade head
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$serveArgs = @('app.main:app', '--host', $BindHost, '--port', $Port)
if (-not $NoReload) { $serveArgs += '--reload' }

Write-Host "serving on http://${BindHost}:${Port}  (docs at /docs)"
uvicorn @serveArgs

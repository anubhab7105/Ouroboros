<#
.SYNOPSIS
    Drop the demo data and start again.

.DESCRIPTION
    Destroys every row in the database the backend is configured to use. There
    is no selective version: a half-reset database is worse than either state,
    because the accounts that survive are referenced by transactions that did
    not.

    Refuses to run when BACKEND_ENV looks deployed. The check is on the
    environment name rather than a flag, because a flag is the thing somebody
    passes by accident.

.EXAMPLE
    ./scripts/reset_demo.ps1
    ./scripts/reset_demo.ps1 -Yes -Reseed
#>
[CmdletBinding()]
param(
    [Alias('y')][switch]$Yes,
    [switch]$Reseed
)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

Push-Location 'backend'
$environment = (python -c @'
from app.core.config import get_settings
print(str(getattr(get_settings(), "BACKEND_ENV", "local") or "local").lower())
'@) 2>$null
if (-not $environment) { $environment = 'unknown' }

# Host and database only. A URL with a password in it should not be echoed to a
# terminal, let alone into a CI log.
$target = (python -c @'
import re
from app.core.config import get_settings
url = str(get_settings().DATABASE_URL)
match = re.search(r"@([^/]+)/([^?]+)", url)
print(f"{match.group(1)}/{match.group(2)}" if match else "(local file)")
'@) 2>$null
Pop-Location

if ($environment -in @('production', 'prod', 'staging', 'stage', 'uat', 'preprod')) {
    Write-Error "Refusing to run: BACKEND_ENV is '$environment'."
    Write-Host 'This drops every row. If you really mean it, do it deliberately with'
    Write-Host 'your database tooling rather than with a script called reset_demo.'
    exit 1
}

Write-Host "environment: $environment"
Write-Host "target:      $target"

if (-not $Yes) {
    $reply = Read-Host 'Drop every row? Type the environment name to confirm'
    if ($reply -ne $environment) {
        Write-Host 'not confirmed; nothing was changed'
        exit 1
    }
}

Push-Location 'backend'
Write-Host 'downgrading to base'
alembic downgrade base
if ($LASTEXITCODE -ne 0) { Pop-Location; exit $LASTEXITCODE }

Write-Host 'upgrading to head'
alembic upgrade head
if ($LASTEXITCODE -ne 0) { Pop-Location; exit $LASTEXITCODE }
Pop-Location

if ($Reseed) {
    Write-Host ''
    if (-not ($env:MULEGUARD_DEV_PASSWORD -or $env:MULEGUARD_ADMIN_PASSWORD)) {
        Write-Error 'skipping users and seed: no password in the environment.'
        Write-Host 'Set $env:MULEGUARD_DEV_PASSWORD, then:'
        Write-Host '  python scripts/create_dev_users.py; ./scripts/seed_demo.ps1'
        exit 1
    }

    python scripts/create_dev_users.py
    Write-Host ''
    & "$PSScriptRoot/seed_demo.ps1"
}
else {
    Write-Host ''
    Write-Host 'database is empty. Next:'
    Write-Host '  python scripts/create_dev_users.py'
    Write-Host '  ./scripts/seed_demo.ps1'
}

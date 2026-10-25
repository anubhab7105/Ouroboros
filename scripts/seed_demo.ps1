<#
.SYNOPSIS
    Load a dataset into a running backend, in dependency order.

.DESCRIPTION
    A thin wrapper over scripts/import_json.py, which does the ordering, the
    login and the count arithmetic. This script adds the two things a demo
    needs: generating a dataset first, and running an analysis pass afterwards
    so the dashboard has something on it.

    Needs MULEGUARD_ADMIN_PASSWORD in the environment; ingestion is admin-only.

.EXAMPLE
    ./scripts/seed_demo.ps1
    ./scripts/seed_demo.ps1 -From data/generated/run-42
    ./scripts/seed_demo.ps1 -Generate 500
#>
[CmdletBinding()]
param(
    [string]$From = 'data/samples',
    [int]$Generate = 0,
    [string]$BaseUrl = $(if ($env:MULEGUARD_BASE_URL) { $env:MULEGUARD_BASE_URL } else { 'http://localhost:8000' }),
    [switch]$NoAnalyse
)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

if (-not $env:MULEGUARD_ADMIN_PASSWORD) {
    Write-Error 'MULEGUARD_ADMIN_PASSWORD is not set.'
    Write-Host 'Ingestion is admin-only. Set it in your shell:'
    Write-Host '  $env:MULEGUARD_ADMIN_PASSWORD = ''...'''
    exit 1
}

& "$PSScriptRoot/wait_for_backend.ps1" -Url $BaseUrl
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($Generate -gt 0) {
    $From = "data/generated/demo-$Generate"
    Write-Host ''
    python scripts/generate_data.py `
        --accounts $Generate `
        --transactions ($Generate * 40) `
        --complaints ([int]($Generate / 4)) `
        --out $From
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host ''
python scripts/import_json.py --dir $From --base-url $BaseUrl
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($NoAnalyse) {
    Write-Host ''
    Write-Host 'Skipped the analysis pass. Nothing is scored, so the dashboard and'
    Write-Host 'the alert queue will be empty -- which is correct, not broken.'
    exit 0
}

Write-Host ''
Write-Host 'running an analysis pass so there is something to look at'

$user = if ($env:MULEGUARD_ADMIN_USER) { $env:MULEGUARD_ADMIN_USER } else { 'admin' }
$login = Invoke-RestMethod -Method Post -Uri "$($BaseUrl.TrimEnd('/'))/api/v1/auth/login" `
    -ContentType 'application/json' `
    -Body (@{ identifier = $user; password = $env:MULEGUARD_ADMIN_PASSWORD } | ConvertTo-Json)

$auth = @{ Authorization = "Bearer $($login.access_token)" }

# The run has to name the accounts it covers.
#
# An empty body asks for all-account selection, which the API refuses unless
# ANALYSIS_ALLOW_ALL_ACCOUNTS=true:
#
#   account_ids is required unless ANALYSIS_ALLOW_ALL_ACCOUNTS=true.
#
# That refusal is the product working as designed, not a configuration gap --
# analysis is bounded on purpose, the same way graph traversal requires a root
# and refuses whole-bank queries. A demo script is exactly the wrong place to
# switch a safety bound off, so it enumerates the accounts instead and asks
# for a scope it can state.
$accountIds = [System.Collections.Generic.List[string]]::new()
$page = 1
$pageSize = 200          # PAGINATION_MAX_PAGE_SIZE
$maxAccounts = 1000      # ANALYSIS_MAX_ACCOUNTS

do {
    $listing = Invoke-RestMethod -Method Get -Headers $auth `
        -Uri "$($BaseUrl.TrimEnd('/'))/api/v1/accounts?page=$page&page_size=$pageSize"

    foreach ($item in $listing.items) {
        if ($accountIds.Count -lt $maxAccounts) {
            $accountIds.Add($item.id)
        }
    }

    $page++
} while ($listing.items.Count -eq $pageSize -and $accountIds.Count -lt $maxAccounts -and $page -le $listing.total_pages)

if ($accountIds.Count -eq 0) {
    Write-Host ''
    Write-Host 'No accounts to analyse. Load data first, then re-run this script.'
    exit 1
}

if ($listing.total -gt $accountIds.Count) {
    Write-Host "  scoring the first $($accountIds.Count) of $($listing.total) accounts (bounded run)"
}
else {
    Write-Host "  scoring $($accountIds.Count) accounts"
}

# Synchronous, so when this returns the dashboard is populated.
$run = Invoke-RestMethod -Method Post -Uri "$($BaseUrl.TrimEnd('/'))/api/v1/analysis/runs" `
    -Headers $auth -ContentType 'application/json' `
    -Body (@{ account_ids = $accountIds } | ConvertTo-Json)

Write-Host "  run $($run.id): $($run.status)"
Write-Host "  $($run.account_count) accounts, $($run.assessment_count) assessments"
foreach ($caveat in ($run.caveats | Select-Object -First 3)) {
    Write-Host "  - $caveat"
}

Write-Host ''
Write-Host 'done. Open the dashboard, or query the alert queue with your token.'

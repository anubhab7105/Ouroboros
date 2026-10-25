<#
.SYNOPSIS
    Check that a deployed backend actually works, not just that it answers.

.DESCRIPTION
    Eleven checks, in the order a problem is most likely to be found. Each
    prints pass or fail and the script exits non-zero if any failed, so it
    works as a deployment gate.

    Authenticated checks need MULEGUARD_ADMIN_PASSWORD. Without it the public
    checks still run and the rest are reported as skipped rather than passed --
    a smoke test that silently skips most of itself is worse than no smoke
    test.

.EXAMPLE
    ./scripts/smoke_test.ps1
    ./scripts/smoke_test.ps1 -BaseUrl https://muleguard.example.internal
#>
[CmdletBinding()]
param(
    [string]$BaseUrl = $(if ($env:MULEGUARD_BASE_URL) { $env:MULEGUARD_BASE_URL } else { 'http://localhost:8000' })
)

Set-Location (Join-Path $PSScriptRoot '..')
$BaseUrl = $BaseUrl.TrimEnd('/')

$script:passed = 0
$script:failed = 0
$script:skipped = 0

function Pass([string]$what) {
    Write-Host '  PASS  ' -ForegroundColor Green -NoNewline
    Write-Host $what
    $script:passed++
}

function Fail([string]$what, [string]$detail = '') {
    Write-Host '  FAIL  ' -ForegroundColor Red -NoNewline
    Write-Host $what
    if ($detail) { Write-Host "        $detail" }
    $script:failed++
}

function Skip([string]$what, [string]$detail = '') {
    Write-Host '  SKIP  ' -ForegroundColor Yellow -NoNewline
    Write-Host $what
    if ($detail) { Write-Host "        $detail" }
    $script:skipped++
}

function Get-Json([string]$path, [hashtable]$headers = @{}, [int]$timeout = 15) {
    Invoke-RestMethod -Uri "$BaseUrl$path" -Headers $headers -TimeoutSec $timeout -ErrorAction Stop
}

Write-Host "smoke test: $BaseUrl"
Write-Host ''

# 1. The process is up.
try {
    Get-Json '/health' | Out-Null
    Pass 'liveness'
}
catch {
    Fail 'liveness' $_.Exception.Message
    Write-Host ''
    Write-Host 'Nothing else can pass. Stopping.'
    exit 1
}

# 2. Dependencies are up. A process that is listening is not a backend that can
#    serve a request, and this is the check that tells them apart.
try {
    $ready = Get-Json '/api/v1/health/ready'
    if ($ready.ready) { Pass 'readiness (database reachable)' }
    else { Fail 'readiness' ($ready | ConvertTo-Json -Depth 4 -Compress) }
}
catch { Fail 'readiness' $_.Exception.Message }

# 3. The synthetic banner. If this is missing, something has been configured to
#    look like a production system, which is the one claim this prototype must
#    never make.
try {
    $health = Get-Json '/api/v1/health'
    if ($health.data_classification -eq 'synthetic' -and -not $health.production_ready) {
        Pass 'declares itself synthetic and not production-ready'
    }
    else {
        Fail 'synthetic banner' "classification=$($health.data_classification) production_ready=$($health.production_ready)"
    }
}
catch { Fail 'synthetic banner' $_.Exception.Message }

# 4. The schema generates. Catches a duplicated operation_id or an unresolved
#    forward reference, which otherwise surface as a 500 the first time
#    somebody opens the docs.
try {
    Get-Json '/api/v1/openapi.json' -timeout 20 | Out-Null
    Pass 'OpenAPI schema generates'
}
catch { Fail 'OpenAPI schema generates' $_.Exception.Message }

# 5. Protected endpoints are protected, and 6. the error envelope is flat.
try {
    Get-Json '/api/v1/accounts' | Out-Null
    Fail 'unauthenticated request is refused' 'the request succeeded'
}
catch {
    $status = [int]$_.Exception.Response.StatusCode
    if ($status -eq 401) { Pass 'unauthenticated request is refused (401)' }
    else { Fail 'unauthenticated request is refused' "got HTTP $status, expected 401" }

    $body = $null
    try {
        $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $body = $reader.ReadToEnd() | ConvertFrom-Json
    }
    catch { }

    if ($body -and $body.code -like 'MULEGUARD_*') {
        Pass "error envelope is flat and namespaced ($($body.code))"
    }
    else {
        Fail 'error envelope' 'no namespaced code in the body'
    }
}

# 7. Request ids come back. This is the thread between a screenshot, a log line
#    and an audit row.
$requestId = "smoke-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
try {
    $response = Invoke-WebRequest -Uri "$BaseUrl/api/v1/accounts" `
        -Headers @{ 'X-Request-ID' = $requestId } -TimeoutSec 10 `
        -SkipHttpErrorCheck -UseBasicParsing
    $returned = $response.Headers['X-Request-ID']
}
catch {
    $returned = $_.Exception.Response.Headers['X-Request-ID']
}

if ($returned -eq $requestId) { Pass 'X-Request-ID is echoed' }
else { Fail 'X-Request-ID is echoed' "sent $requestId, got $(if ($returned) { $returned } else { 'nothing' })" }

if (-not $env:MULEGUARD_ADMIN_PASSWORD) {
    Write-Host ''
    Skip 'authenticated checks' 'MULEGUARD_ADMIN_PASSWORD is not set'
    Skip 'login'
    Skip 'a list endpoint returns the pagination envelope'
    Skip 'a scored response carries its caveats'
    Skip 'the model endpoint states its limitations'
}
else {
    Write-Host ''
    $token = $null

    # 8. Login.
    try {
        $user = if ($env:MULEGUARD_ADMIN_USER) { $env:MULEGUARD_ADMIN_USER } else { 'admin' }
        $login = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/v1/auth/login" `
            -ContentType 'application/json' -TimeoutSec 15 `
            -Body (@{ identifier = $user; password = $env:MULEGUARD_ADMIN_PASSWORD } | ConvertTo-Json)
        $token = $login.access_token
        Pass 'login'
    }
    catch { Fail 'login' $_.Exception.Message }

    if ($token) {
        $auth = @{ Authorization = "Bearer $token" }

        # 9. The pagination envelope, on a real list endpoint.
        try {
            $page = Get-Json '/api/v1/accounts?page_size=1' $auth 20
            if ($null -ne $page.total) {
                Pass "a list endpoint returns the pagination envelope (total=$($page.total))"
            }
            else { Fail 'pagination envelope' 'no total field' }
        }
        catch { Fail 'pagination envelope' $_.Exception.Message }

        # 10. Caveats travel with the data. The platform's position is that its
        #     output is a lead rather than a finding, and the caveat list is how
        #     that travels.
        try {
            $overview = Get-Json '/api/v1/dashboard/overview' $auth 20
            if ($overview.caveats -and $overview.caveats.Count -gt 0) {
                Pass "a scored response carries its caveats ($($overview.caveats.Count))"
            }
            else { Fail 'caveats' 'the dashboard published none' }
        }
        catch { Fail 'caveats' $_.Exception.Message }

        # 11. The model says what it cannot do.
        try {
            $limits = Get-Json '/api/v1/model/limitations' $auth 20
            if (($limits | ConvertTo-Json -Depth 6) -match 'synthetic') {
                Pass 'the model endpoint states its limitations'
            }
            else { Fail 'model limitations' 'no mention of synthetic data' }
        }
        catch { Fail 'model limitations' $_.Exception.Message }
    }
}

Write-Host ''
Write-Host "$script:passed passed, $script:failed failed, $script:skipped skipped"

if ($script:failed -gt 0) { exit 1 }

if ($script:skipped -gt 0) {
    Write-Host ''
    Write-Host 'Some checks were skipped. Set MULEGUARD_ADMIN_PASSWORD to run them.'
}

# Phase 9 Verification Test Suite: Rate Limiting & DoS Protection Engine
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " [PHASE 9] TESTING RATE LIMITING & DOS MITIGATION ENGINE" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$Passed = 0
$Failed = 0

function Assert-Check {
    param(
        [string]$Name,
        [bool]$Condition,
        [string]$Details = ""
    )
    if ($Condition) {
        Write-Host "  [PASS] $Name" -ForegroundColor Green
        if ($Details) { Write-Host "         $Details" -ForegroundColor DarkGray }
        $script:Passed++
    } else {
        Write-Host "  [FAIL] $Name" -ForegroundColor Red
        if ($Details) { Write-Host "         Detail: $Details" -ForegroundColor Yellow }
        $script:Failed++
    }
}

$TargetHost = "http://127.0.0.1:8080"
$MgmtHost   = "http://127.0.0.1:8082"

# -------------------------------------------------------------
# 1. Rate Limit Policy REST API CRUD Verification
# -------------------------------------------------------------
Write-Host ""
Write-Host "--- 1. Rate Limit Policy Management Plane (CRUD) ---" -ForegroundColor Yellow

$createdID = $null
try {
    # 1.1 Create policy
    $body = @{
        path_prefix = "/api/login"
        max_requests = 5
        window_seconds = 60
        action = "BLOCK_429"
    } | ConvertTo-Json

    $createRes = Invoke-RestMethod -Uri "$MgmtHost/api/v1/rate-limits" -Method POST -ContentType "application/json" -Body $body
    $createdID = $createRes.id
    Assert-Check "Create rate limit policy on /api/login via REST" ($createRes.status -eq "created" -and $null -ne $createdID) ("Created ID=" + $createdID)
} catch {
    Assert-Check "Create rate limit policy on /api/login" $false $_.Exception.Message
}

try {
    # 1.2 Query policies
    $policies = Invoke-RestMethod -Uri "$MgmtHost/api/v1/rate-limits" -Method GET
    $found = $false
    foreach ($p in $policies) {
        if ($p.path_prefix -eq "/api/login" -and $p.id -eq $createdID) {
            $found = $true
            break
        }
    }
    Assert-Check "Verify created policy returned in GET /api/v1/rate-limits" $found
} catch {
    Assert-Check "Query rate limit policies" $false $_.Exception.Message
}

# -------------------------------------------------------------
# 2. System Diagnostics Counter Check
# -------------------------------------------------------------
Write-Host ""
Write-Host "--- 2. System Diagnostics Counter Integration ---" -ForegroundColor Yellow
try {
    $diag = Invoke-RestMethod -Uri "$MgmtHost/api/v1/diagnostics" -Method GET
    Assert-Check "Diagnostics endpoint includes active_rate_limits counter" ($null -ne $diag.counters.active_rate_limits) ("active_rate_limits=" + $diag.counters.active_rate_limits)
    Assert-Check "active_rate_limits reflects newly added policy" ($diag.counters.active_rate_limits -ge 1)
} catch {
    Assert-Check "Diagnostics rate limits counter check" $false $_.Exception.Message
}

# -------------------------------------------------------------
# 3. Envoy Data Plane Token Bucket Enforcement (HTTP 429)
# -------------------------------------------------------------
Write-Host ""
Write-Host "--- 3. Envoy Data Plane Token Bucket Flood Test ---" -ForegroundColor Yellow

# Route /api/login has token bucket max_tokens=5, tokens_per_fill=5, fill_interval=60s
# Sending 8 fast requests: First 5 should succeed (200), subsequent requests must be rate-limited (429)
$burstCount = 8
$got429 = $false
$okCount = 0
$rateLimitCount = 0

$loginPayload = '{"username":"soc_tester","password":"StrongPassword!123"}'

for ($i = 1; $i -le $burstCount; $i++) {
    $statusCode = 0
    try {
        $res = Invoke-WebRequest -Uri "$TargetHost/api/login" -Method POST -ContentType "application/json" `
            -Body $loginPayload -UseBasicParsing -ErrorAction Stop -TimeoutSec 3
        $statusCode = $res.StatusCode
    } catch {
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        } else {
            $statusCode = -1
        }
    }

    if ($statusCode -eq 200) {
        $okCount++
    } elseif ($statusCode -eq 429) {
        $rateLimitCount++
        $got429 = $true
    }
}

Assert-Check "Burst requests successfully processed under bucket limit" ($okCount -gt 0) ("Successful count=" + $okCount)
Assert-Check "Excess flood requests blocked with HTTP 429 Too Many Requests" ($got429 -and $rateLimitCount -gt 0) ("429 count=" + $rateLimitCount)

# -------------------------------------------------------------
# 4. Independent Route Immunity Verification
# -------------------------------------------------------------
Write-Host ""
Write-Host "--- 4. Route Isolation Verification ---" -ForegroundColor Yellow
# Other routes like /api/search or / must NOT be blocked by /api/login rate limit
$isolatedStatus = 0
try {
    $res = Invoke-WebRequest -Uri "$TargetHost/api/search?q=enterprise" -Method GET -UseBasicParsing -ErrorAction Stop -TimeoutSec 3
    $isolatedStatus = $res.StatusCode
} catch {
    if ($_.Exception.Response) {
        $isolatedStatus = [int]$_.Exception.Response.StatusCode
    }
}
Assert-Check "Separate route /api/search remains unaffected (HTTP 200)" ($isolatedStatus -eq 200) ("Status=" + $isolatedStatus)

# -------------------------------------------------------------
# 5. Clean up Created Policy
# -------------------------------------------------------------
Write-Host ""
Write-Host "--- 5. Cleanup Test Policy ---" -ForegroundColor Yellow
if ($null -ne $createdID) {
    try {
        $delRes = Invoke-RestMethod -Uri "$MgmtHost/api/v1/rate-limits/$createdID" -Method DELETE
        Assert-Check "Delete rate limit policy via REST" ($delRes.status -eq "deleted")
    } catch {
        Assert-Check "Delete rate limit policy" $false $_.Exception.Message
    }
}

$summaryColor = "Green"
if ($Failed -gt 0) { $summaryColor = "Red" }
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " [PHASE 9 SUMMARY] Total Passed: $Passed | Total Failed: $Failed" -ForegroundColor $summaryColor
Write-Host "=================================================================" -ForegroundColor Cyan

if ($Failed -gt 0) {
    exit 1
}

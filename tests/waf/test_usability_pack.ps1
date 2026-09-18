# Automated Verification Suite for Usability & Production-Grade Pack
# Strictly host-native PowerShell execution testing all 4 professional capabilities

$ErrorActionPreference = "Stop"
$API = "http://localhost:8082"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " RUNNING AUTOMATED SUITE: USABILITY & PRODUCTION-GRADE PACK" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$testCount = 0
$passedCount = 0

function Assert-Test([string]$name, [scriptblock]$condition) {
    $global:testCount++
    try {
        $result = & $condition
        if ($result) {
            Write-Host " [PASS] Test ${global:testCount} - $name" -ForegroundColor Green
            $global:passedCount++
        } else {
            Write-Host " [FAIL] Test ${global:testCount} - $name" -ForegroundColor Red
            exit 1
        }
    } catch {
        Write-Host " [FAIL] Test ${global:testCount} - $name (Exception: $_)" -ForegroundColor Red
        exit 1
    }
}

# -------------------------------------------------------------
# Pillar 1: 1-Click Curated CVE Virtual Patching Catalog
# -------------------------------------------------------------
Write-Host "`n--- Pillar 1: Curated CVE Catalog & 1-Click Virtual Patching ---" -ForegroundColor Yellow

# Test 1: Fetch CVE Catalog
Assert-Test "Fetch CVE Virtual Patching Catalog items" {
    $resp = Invoke-RestMethod -Uri "$API/api/v1/cve-catalog" -Method Get
    $resp.Count -ge 5 -and ($resp | Where-Object { $_.cve_id -eq "CVE-2021-44228" })
}

# Test 2: Toggle CVE-2021-44228 (Log4Shell)
Assert-Test "Toggle Log4Shell patch and trigger xDS compilation" {
    # Check current state first
    $current = Invoke-RestMethod -Uri "$API/api/v1/cve-catalog" -Method Get | Where-Object { $_.cve_id -eq "CVE-2021-44228" }
    $resp = Invoke-RestMethod -Uri "$API/api/v1/cve-catalog/CVE-2021-44228/toggle" -Method Post
    # If it was toggled to false, toggle it once more so it ends up true
    if (-not $resp.is_enabled) {
        $resp = Invoke-RestMethod -Uri "$API/api/v1/cve-catalog/CVE-2021-44228/toggle" -Method Post
    }
    $resp.cve_id -eq "CVE-2021-44228" -and $resp.is_enabled -eq $true -and $resp.xds_synchronized -eq $true
}

# Test 3: Verify Catalog item is enabled in database state
Assert-Test "Verify Catalog persistence reflects enabled state" {
    $resp = Invoke-RestMethod -Uri "$API/api/v1/cve-catalog" -Method Get
    $item = $resp | Where-Object { $_.cve_id -eq "CVE-2021-44228" }
    $item.is_enabled -eq $true
}

# Test 4: Toggle Next.js CVE-2024-34351 patch
Assert-Test "Toggle Next.js SSRF patch" {
    $resp = Invoke-RestMethod -Uri "$API/api/v1/cve-catalog/CVE-2024-34351/toggle" -Method Post
    if (-not $resp.is_enabled) {
        $resp = Invoke-RestMethod -Uri "$API/api/v1/cve-catalog/CVE-2024-34351/toggle" -Method Post
    }
    $resp.is_enabled -eq $true -and $resp.xds_synchronized -eq $true
}

# -------------------------------------------------------------
# Pillar 2: 1-Click Rule Exception Wizard directly from Events
# -------------------------------------------------------------
Write-Host "`n--- Pillar 2: 1-Click Rule Exception Wizard from Security Events ---" -ForegroundColor Yellow

# Test 5: Ingest a simulated attack event to generate an event row
Assert-Test "Ingest SQLi violation event for testing auto-exception" {
    $body = @{
        transaction = @{
            id = "tx-cve-test-$(Get-Random)"
            client_ip = "192.168.1.105"
            is_interrupted = $true
            request = @{
                method = "GET"
                uri = "/api/v1/search?q=' OR 1=1 --"
                headers = @{ "host" = @("telkomsel.co.id") }
            }
        }
        messages = @(
            @{
                message = "SQL Injection detected by libinjection"
                data = @{ id = 942100; severity = 2 }
            }
        )
    } | ConvertTo-Json -Depth 5

    $resp = Invoke-RestMethod -Uri "$API/api/v1/events" -Method Post -Body $body -ContentType "application/json"
    $resp.status -eq "received"
}

# Test 6: Fetch latest ingested event ID
$global:latestEventId = 0
Assert-Test "Retrieve latest security event ID" {
    $events = Invoke-RestMethod -Uri "$API/api/v1/events" -Method Get
    if ($events.Count -gt 0) {
        $global:latestEventId = $events[0].id
        $global:latestEventId -gt 0
    } else {
        $false
    }
}

# Test 7: Auto-generate 1-Click Rule Exception with 24h TTL
Assert-Test "Auto-generate 1-Click Rule Exception from Event" {
    $body = @{
        event_id = $global:latestEventId
        scope = "PATH_ONLY"
        ttl_seconds = 86400
        reason = "Automated test exception for false-positive validation"
    } | ConvertTo-Json

    $resp = Invoke-RestMethod -Uri "$API/api/v1/exceptions/auto-generate" -Method Post -Body $body -ContentType "application/json"
    $resp.status -eq "EXCEPTION_CREATED" -and $resp.xds_synchronized -eq $true -and $resp.applied_scope -eq "PATH_ONLY"
}

# Test 8: Auto-generate parameter-level TARGET exception
Assert-Test "Auto-generate TARGET parameter-level exception with 7-day TTL" {
    $body = @{
        event_id = $global:latestEventId
        scope = "TARGET"
        ttl_seconds = 604800
        reason = "Parameter q bypass exception"
    } | ConvertTo-Json

    $resp = Invoke-RestMethod -Uri "$API/api/v1/exceptions/auto-generate" -Method Post -Body $body -ContentType "application/json"
    $resp.status -eq "EXCEPTION_CREATED" -and $resp.applied_scope -eq "TARGET" -and $resp.exception.match_param -ne ""
}

# -------------------------------------------------------------
# Pillar 3: Self-Service Onboarding & Live Connectivity Probe
# -------------------------------------------------------------
Write-Host "`n--- Pillar 3: Self-Service Onboarding & Live Connectivity Probe ---" -ForegroundColor Yellow

# Test 9: Verify backend connectivity probe against live management plane
Assert-Test "Probe live connectivity against reachable backend" {
    $body = @{
        domain = "test-app.telkomsel.co.id"
        backend_url = "http://localhost:8082/api/v1/cve-catalog"
        test_attack = $true
    } | ConvertTo-Json

    $resp = Invoke-RestMethod -Uri "$API/api/v1/applications/verify-connectivity" -Method Post -Body $body -ContentType "application/json"
    $resp.origin_reachable -eq $true -and $resp.origin_status_code -eq 200 -and $resp.waf_attack_intercepted -eq $true
}

# Test 10: Verify backend connectivity probe against unreachable host
Assert-Test "Probe handling for unreachable host gracefully diagnostic" {
    $body = @{
        domain = "broken-app.telkomsel.co.id"
        backend_url = "http://127.0.0.1:19999/not-exist"
        test_attack = $false
    } | ConvertTo-Json

    $resp = Invoke-RestMethod -Uri "$API/api/v1/applications/verify-connectivity" -Method Post -Body $body -ContentType "application/json"
    $resp.origin_reachable -eq $false -and $resp.overall_ready -eq $false
}

# -------------------------------------------------------------
# Pillar 4: Client-Side Bot Managed JS Challenge Engine
# -------------------------------------------------------------
Write-Host "`n--- Pillar 4: Client-Side Bot Managed JS Challenge Engine ---" -ForegroundColor Yellow

# Test 11: Fetch Bot Challenge Interstitial HTML page
Assert-Test "Retrieve Bot Challenge Interstitial HTML" {
    $resp = Invoke-WebRequest -Uri "$API/api/v1/bot-challenge/interstitial" -Method Get -UseBasicParsing
    $resp.StatusCode -eq 200 -and $resp.Content.Contains("Verifying your browser") -and $resp.Content.Contains("solve()")
}

# Test 12: Verify valid Proof-of-Work Solution
Assert-Test "Verify valid Proof-of-Work solution returns clearance token" {
    $challenge = "test_challenge_abc"
    $nonce = 3549
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $str = $challenge + ":" + $nonce
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($str)
    $hash = [System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace("-", "").ToLower()

    $body = @{
        challenge = $challenge
        nonce = $nonce
        solution = $hash
    } | ConvertTo-Json

    $resp = Invoke-RestMethod -Uri "$API/api/v1/bot-challenge/verify" -Method Post -Body $body -ContentType "application/json"
    $resp.status -eq "VERIFIED" -and $resp.clearance_token.StartsWith("clearance_")
}

# Test 13: Reject invalid Proof-of-Work Solution
Assert-Test "Reject invalid Proof-of-Work challenge" {
    $body = @{
        challenge = "test_challenge_abc"
        nonce = 999999
        solution = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    } | ConvertTo-Json

    try {
        Invoke-RestMethod -Uri "$API/api/v1/bot-challenge/verify" -Method Post -Body $body -ContentType "application/json"
        $false
    } catch {
        $_.Exception.Response.StatusCode.value__ -eq 403
    }
}

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host " ALL USABILITY PACK TESTS COMPLETED: $passedCount / $testCount PASSED" -ForegroundColor Green
Write-Host "=================================================================`n" -ForegroundColor Cyan

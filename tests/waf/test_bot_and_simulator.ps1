# tests/waf/test_bot_and_simulator.ps1
# Enterprise WAF Milestone 2: Bot Management & Policy Simulator Suite

$ErrorActionPreference = "Continue"
$ProxyURL = "http://localhost:8080"
$ManagementURL = "http://localhost:8082/api/v1"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   Enterprise WAF Milestone 2: Bot Shield & Simulator Suite      " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$Passed = 0
$Failed = 0

function Assert-Test([string]$TestName, [bool]$Condition, [string]$Details = "") {
    if ($Condition) {
        Write-Host "  [PASS] $TestName" -ForegroundColor Green
        if ($Details) { Write-Host "         $Details" -ForegroundColor DarkGray }
        $script:Passed++
    } else {
        Write-Host "  [FAIL] $TestName" -ForegroundColor Red
        if ($Details) { Write-Host "         $Details" -ForegroundColor Yellow }
        $script:Failed++
    }
}

# -------------------------------------------------------------
# 1. BOT INTELLIGENCE POLICY MANAGEMENT (REST)
# -------------------------------------------------------------
Write-Host "`n[Test Group 1] Bot Intelligence Policy Management..." -ForegroundColor Yellow

$botPolicies = Invoke-RestMethod -Uri "$ManagementURL/bot-policies" -Method Get
Assert-Test "Retrieve Pre-Seeded Bot Policies" ($botPolicies.Count -ge 5) "Found $($botPolicies.Count) bot policies"

$scannerPolicy = $botPolicies | Where-Object { $_.category -eq "SECURITY_SCANNER" }
Assert-Test "Security Scanner Bot Profile Exists" ($scannerPolicy -ne $null -and $scannerPolicy.action -eq "BLOCK") "Scanner UA: $($scannerPolicy.ua_regex)"

$goodBotPolicy = $botPolicies | Where-Object { $_.category -eq "SEARCH_ENGINE" }
Assert-Test "Search Engine Bot Profile Exists" ($goodBotPolicy -ne $null -and $goodBotPolicy.action -eq "ALLOW") "Search Engine UA: $($goodBotPolicy.ua_regex)"

# Create custom bot policy
$customBotReq = @{
    name = "Custom Malicious Harvester"
    category = "SCRAPER"
    ua_regex = "(?i)(dark-scraper-bot|evil-crawler-v2)"
    action = "BLOCK"
    description = "Test custom scraper signature"
} | ConvertTo-Json

$createBotRes = Invoke-RestMethod -Uri "$ManagementURL/bot-policies" -Method Post -Body $customBotReq -ContentType "application/json"
Assert-Test "Create Custom Bot Signature" ($createBotRes.status -eq "created" -and $createBotRes.id -gt 0) "Created ID: $($createBotRes.id)"
$customBotId = $createBotRes.id

# -------------------------------------------------------------
# 2. BOT SHIELD DATA PLANE ENFORCEMENT (ENVOY XDS)
# -------------------------------------------------------------
Write-Host "`n[Test Group 2] Bot Shield Data Plane Enforcement (Envoy xDS)..." -ForegroundColor Yellow

# Explicitly trigger xDS sync
$syncRes = Invoke-RestMethod -Uri "$ManagementURL/bot-policies/sync" -Method Post
Assert-Test "Sync Bot Shield Policies to Envoy xDS" ($syncRes.status -eq "synced")
Start-Sleep -Seconds 2

# 2.1 Bad Bot: sqlmap
$sqlmapStatus = 0
try {
    $res = Invoke-WebRequest -Uri "$ProxyURL/api/search?q=normal" -Headers @{ "User-Agent" = "sqlmap/1.5#stable" } -Method Get -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    $sqlmapStatus = $res.StatusCode
} catch {
    if ($_.Exception.Response) { $sqlmapStatus = [int]$_.Exception.Response.StatusCode }
}
Assert-Test "Envoy Blocks Vulnerability Scanner (sqlmap)" ($sqlmapStatus -eq 403) "Blocked with HTTP $sqlmapStatus"

# 2.2 Bad Bot: python-requests scraper
$pythonStatus = 0
try {
    $res = Invoke-WebRequest -Uri "$ProxyURL/api/search?q=normal" -Headers @{ "User-Agent" = "python-requests/2.28.1" } -Method Get -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    $pythonStatus = $res.StatusCode
} catch {
    if ($_.Exception.Response) { $pythonStatus = [int]$_.Exception.Response.StatusCode }
}
Assert-Test "Envoy Blocks Automated Python Scraping Client" ($pythonStatus -eq 403) "Blocked with HTTP $pythonStatus"

# 2.3 Custom Bad Bot
$customStatus = 0
try {
    $res = Invoke-WebRequest -Uri "$ProxyURL/api/search?q=normal" -Headers @{ "User-Agent" = "dark-scraper-bot/1.0" } -Method Get -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    $customStatus = $res.StatusCode
} catch {
    if ($_.Exception.Response) { $customStatus = [int]$_.Exception.Response.StatusCode }
}
Assert-Test "Envoy Blocks Custom Malicious Harvester" ($customStatus -eq 403) "Blocked with HTTP $customStatus"

# 2.4 Good Bot: Googlebot
$googlebotStatus = 0
try {
    $res = Invoke-WebRequest -Uri "$ProxyURL/api/search?q=normal" -Headers @{ "User-Agent" = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" } -Method Get -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    $googlebotStatus = $res.StatusCode
} catch {
    if ($_.Exception.Response) { $googlebotStatus = [int]$_.Exception.Response.StatusCode }
}
Assert-Test "Envoy Allows Verified Good Bot (Googlebot)" ($googlebotStatus -eq 200) "Permitted with HTTP $googlebotStatus"

# 2.5 Normal User: Chrome Browser
$chromeStatus = 0
try {
    $res = Invoke-WebRequest -Uri "$ProxyURL/api/search?q=normal" -Headers @{ "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0" } -Method Get -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    $chromeStatus = $res.StatusCode
} catch {
    if ($_.Exception.Response) { $chromeStatus = [int]$_.Exception.Response.StatusCode }
}
Assert-Test "Envoy Allows Legitimate Human Browser (Chrome)" ($chromeStatus -eq 200) "Permitted with HTTP $chromeStatus"

# -------------------------------------------------------------
# 3. WAF POLICY SIMULATOR & HISTORICAL DRY-RUN ENGINE
# -------------------------------------------------------------
Write-Host "`n[Test Group 3] WAF Policy Simulator & Historical Dry-Run..." -ForegroundColor Yellow

$simPayload = @{
    seclang_code = 'SecRule REQUEST_URI "@rx ^/api/search" "id:99001,phase:1,deny,status:403,msg:Simulated Rule"'
    sample_limit = 100
} | ConvertTo-Json

$simResult = Invoke-RestMethod -Uri "$ManagementURL/policy-simulator/simulate" -Method Post -Body $simPayload -ContentType "application/json"
Assert-Test "Policy Simulator Evaluates Historical Traffic" ($simResult.total_evaluated -gt 0) "Total Evaluated: $($simResult.total_evaluated)"
Assert-Test "Simulator Computes Would-Block Count" ($simResult.simulated_blocks -gt 0) "Simulated Blocks: $($simResult.simulated_blocks)"
Assert-Test "Simulator Computes Would-Pass Count" ($simResult.simulated_passes -ge 0) "Simulated Passes: $($simResult.simulated_passes)"
Assert-Test "Simulator Computes False Positive Risk Level" ($simResult.false_positive_risk -in @("LOW", "MEDIUM", "HIGH")) "Risk Rating: $($simResult.false_positive_risk)"
Assert-Test "Simulator Performance Duration Metric" ($simResult.execution_duration_ms -ge 0) "Duration: $($simResult.execution_duration_ms)ms"

# Cleanup custom bot policy
try {
    Invoke-RestMethod -Uri "$ManagementURL/bot-policies/$customBotId" -Method Delete | Out-Null
} catch {}

# -------------------------------------------------------------
# SUMMARY REPORT
# -------------------------------------------------------------
Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "                       TEST RESULTS SUMMARY                      " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  TOTAL TESTS PASSED: $Passed" -ForegroundColor Green
Write-Host "  TOTAL TESTS FAILED: $Failed" -ForegroundColor $(if ($Failed -eq 0) { "Green" } else { "Red" })

if ($Failed -eq 0) {
    Write-Host "`n>>> MILESTONE 2 VERIFICATION COMPLETE: ALL 13/13 TESTS PASSED! <<<`n" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n>>> SOME TESTS FAILED! <<<\n" -ForegroundColor Red
    exit 1
}

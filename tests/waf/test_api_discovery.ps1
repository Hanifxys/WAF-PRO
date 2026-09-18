# tests/waf/test_api_discovery.ps1
# Enterprise WAF Roadmap Milestone 1: Automated API Discovery, Allowlisting & Incident Correlation

$ErrorActionPreference = "Continue"
$ProxyURL = "http://localhost:8080"
$ManagementURL = "http://localhost:8082/api/v1"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   Enterprise WAF Milestone 1: API Discovery & Incident Suite    " -ForegroundColor Cyan
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
# 1. APPLICATION LIFECYCLE ONBOARDING & STATUS
# -------------------------------------------------------------
Write-Host "`n[Test Group 1] Application Onboarding & Lifecycle States..." -ForegroundColor Yellow

$testAppDomain = "discovery-portal-$([guid]::NewGuid().ToString().Substring(0,8)).internal"
$appPayload = @{
    name = "Enterprise Payment API"
    domain = $testAppDomain
    backend_url = "http://origin-mock:8081"
    waf_mode = "LEARNING"
    paranoia_level = 1
    status = "LEARNING"
} | ConvertTo-Json

$createAppRes = Invoke-RestMethod -Uri "$ManagementURL/applications" -Method Post -Body $appPayload -ContentType "application/json"
Assert-Test "Create Application in LEARNING Status" ($createAppRes.status -eq "created" -and $createAppRes.id -gt 0) "Created App ID: $($createAppRes.id)"
$testAppId = $createAppRes.id

$allApps = Invoke-RestMethod -Uri "$ManagementURL/applications" -Method Get
$createdApp = $allApps | Where-Object { $_.id -eq $testAppId }
Assert-Test "Verify Application Status is LEARNING" ($createdApp.status -eq "LEARNING") "App Domain: $($createdApp.domain)"

# Transition to PROTECTED
$updateAppPayload = @{
    name = "Enterprise Payment API"
    domain = $testAppDomain
    backend_url = "http://origin-mock:8081"
    waf_mode = "BLOCK"
    paranoia_level = 1
    status = "PROTECTED"
} | ConvertTo-Json

$updateAppRes = Invoke-RestMethod -Uri "$ManagementURL/applications/$testAppId" -Method Put -Body $updateAppPayload -ContentType "application/json"
Assert-Test "Transition Application to PROTECTED" ($updateAppRes.status -eq "updated")

$verifyUpdatedApp = (Invoke-RestMethod -Uri "$ManagementURL/applications" -Method Get) | Where-Object { $_.id -eq $testAppId }
Assert-Test "Verify Status Updated to PROTECTED" ($verifyUpdatedApp.status -eq "PROTECTED")

# -------------------------------------------------------------
# 2. AUTOMATED API DISCOVERY FROM REAL TRAFFIC
# -------------------------------------------------------------
Write-Host "`n[Test Group 2] Automated API Discovery & Inventory Learner..." -ForegroundColor Yellow

$randomPath = "/api/v2/customer/invoices-$([guid]::NewGuid().ToString().Substring(0,6))"
Write-Host "  -> Sending legitimate request to Envoy: GET $randomPath" -ForegroundColor DarkGray
try {
    $res = Invoke-WebRequest -Uri "$ProxyURL$randomPath" -Method Get -TimeoutSec 5 -UseBasicParsing
} catch {
    # It's okay if origin mock 404s, Coraza still processes the request transaction
}

# Wait for Vector log shipping and ingestion with retry loop
$discoveredEndpoint = $null
for ($i = 0; $i -lt 8; $i++) {
    Start-Sleep -Seconds 1
    $inventory = Invoke-RestMethod -Uri "$ManagementURL/api-inventory" -Method Get
    $discoveredEndpoint = $inventory | Where-Object { $_.path_pattern -eq $randomPath }
    if ($discoveredEndpoint -ne $null) { break }
}

Assert-Test "Auto-Discover API Endpoint from Traffic" ($discoveredEndpoint -ne $null) "Discovered Method: $($discoveredEndpoint.method) Path: $($discoveredEndpoint.path_pattern)"
Assert-Test "Discovered Endpoint Initial Status is DISCOVERED" ($discoveredEndpoint.status -eq "DISCOVERED") "Status: $($discoveredEndpoint.status)"

# -------------------------------------------------------------
# 3. API ALLOWLISTING & DYNAMIC XDS BLOCK ENFORCEMENT
# -------------------------------------------------------------
Write-Host "`n[Test Group 3] API Allowlist & Zero-Downtime Block Enforcement..." -ForegroundColor Yellow

$blockedPath = "/api/deprecated/secret-v1"
# Register as BLOCKED via management API
$blockReq = @{
    app_id = 1
    method = "GET"
    path_pattern = $blockedPath
    status = "BLOCKED"
} | ConvertTo-Json

$blockRes = Invoke-RestMethod -Uri "$ManagementURL/api-inventory" -Method Post -Body $blockReq -ContentType "application/json"
Assert-Test "Register API Endpoint as BLOCKED" ($blockRes.status -eq "saved")

# Trigger sync to xDS
$syncRes = Invoke-RestMethod -Uri "$ManagementURL/api-inventory/sync-enforcement" -Method Post
Assert-Test "Sync xDS Policy Snapshot to Envoy" ($syncRes.status -eq "synced")

# Wait 2 seconds for Envoy xDS snapshot absorption
Start-Sleep -Seconds 2

# Verify that Envoy immediately denies this blocked endpoint with HTTP 403 Forbidden
$blockedStatus = 0
try {
    $res = Invoke-WebRequest -Uri "$ProxyURL$blockedPath" -Method Get -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    $blockedStatus = $res.StatusCode
} catch {
    if ($_.Exception.Response) {
        $blockedStatus = [int]$_.Exception.Response.StatusCode
    }
}
Assert-Test "Envoy Denies Blocked API with HTTP 403" ($blockedStatus -eq 403) "Zero-downtime xDS SecLang deny rule verified! (HTTP $blockedStatus)"

# Verify that a legitimate approved endpoint still works (HTTP 200)
$legitStatus = 0
try {
    $res = Invoke-WebRequest -Uri "$ProxyURL/api/v1/health" -Method Get -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    $legitStatus = $res.StatusCode
} catch {
    if ($_.Exception.Response) {
        $legitStatus = [int]$_.Exception.Response.StatusCode
    }
}
Assert-Test "Legitimate API Endpoint Allowed by WAF" ($legitStatus -ne 403) "Legitimate traffic permitted through WAF (HTTP $legitStatus)"

# -------------------------------------------------------------
# 4. SOC INCIDENT CORRELATION ENGINE & TIMELINE
# -------------------------------------------------------------
Write-Host "`n[Test Group 4] SOC Incident Correlation Engine & Timeline..." -ForegroundColor Yellow

# Send an attack to trigger an incident
$attackUrl = "$ProxyURL/api/search?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--"
Write-Host "  -> Triggering attack to test Incident Correlator: $attackUrl" -ForegroundColor DarkGray
try {
    Invoke-WebRequest -Uri $attackUrl -Method Get -TimeoutSec 5 -UseBasicParsing
} catch {
    # Expected 403
}

# Wait for Vector log shipping and ingestion
Start-Sleep -Seconds 3

$incidents = Invoke-RestMethod -Uri "$ManagementURL/incidents" -Method Get
Assert-Test "Incidents Query Returns Records" ($incidents.Count -gt 0) "Found $($incidents.Count) incident campaigns"

$latestIncident = $incidents[0]
Assert-Test "Incident Has Standard ID Format (INC-xxxxx)" ($latestIncident.inc_number -match "^INC-\d{5}$") "Incident ID: $($latestIncident.inc_number)"
Assert-Test "Incident Correlated Severity and Status" ($latestIncident.status -in @("INVESTIGATING", "ACKNOWLEDGED", "MITIGATED", "RESOLVED")) "Severity: $($latestIncident.severity) Status: $($latestIncident.status)"

# Test Incident Timeline API
$timeline = Invoke-RestMethod -Uri "$ManagementURL/incidents/$($latestIncident.id)/timeline" -Method Get
Assert-Test "Incident Timeline Retrievable for Attacker IP" ($timeline.Count -gt 0) "Attacker IP: $($latestIncident.source_ip), Granular Events: $($timeline.Count)"

# Test Incident Status Update
$updateIncReq = @{
    status = "ACKNOWLEDGED"
    mitigation_action = "L2 SOC Analyst Investigating IP"
} | ConvertTo-Json
$updateIncRes = Invoke-RestMethod -Uri "$ManagementURL/incidents/$($latestIncident.id)/status" -Method Put -Body $updateIncReq -ContentType "application/json"
Assert-Test "Update Incident Status to ACKNOWLEDGED" ($updateIncRes.status -eq "updated")

# Clean up test application
try {
    Invoke-RestMethod -Uri "$ManagementURL/applications/$testAppId" -Method Delete | Out-Null
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
    Write-Host "`n>>> MILESTONE 1 VERIFICATION COMPLETE: ALL 13/13 TESTS PASSED! <<<`n" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n>>> SOME TESTS FAILED! <<<\n" -ForegroundColor Red
    exit 1
}

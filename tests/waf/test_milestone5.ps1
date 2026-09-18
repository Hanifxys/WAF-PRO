# ==============================================================================
# WAF Pro SaaS - Milestone 5 Verification Suite (No Docker - Pure Native Code)
# Pillars Tested:
#   1. Pillar 6 (PLATFORM): RBAC & API Tokens / Service Accounts
#   2. Pillar 7 (INTELLIGENCE): Threat Intel IOC Engine (CIDR/IP & Subnet Match)
#   3. Pillar 5 (SOC): SIEM Log Streaming & CEF/Syslog Forwarder
#   4. Diagnostics & Cluster Observability
# ==============================================================================
param(
  [string]$BaseURL = "http://localhost:8082/api/v1"
)

$ErrorActionPreference = "Continue"
$passed = 0
$failed = 0
$total = 0

function Check-Test($name, $condition, $detail = "") {
  $script:total++
  if ($condition) {
    Write-Host "  [PASS] $name" -ForegroundColor Green
    if ($detail) { Write-Host "         $detail" -ForegroundColor DarkGray }
    $script:passed++
  } else {
    Write-Host "  [FAIL] $name $(if($detail){ '- ' + $detail })" -ForegroundColor Red
    $script:failed++
  }
}

function API($method, $path, $body = $null) {
  $params = @{
    Uri = "$BaseURL$path"
    Method = $method
    ContentType = "application/json"
  }
  if ($body) {
    $params.Body = ($body | ConvertTo-Json -Depth 10)
  }
  try {
    Invoke-RestMethod @params
  } catch {
    Write-Host "    [API ERROR][$method $path]: $($_.Exception.Message)" -ForegroundColor DarkRed
    $null
  }
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   WAF Pro SaaS Milestone 5: Platform, Threat Intel & SIEM Suite " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# 1. PLATFORM PILLAR: RBAC & USERS
# ------------------------------------------------------------------------------
Write-Host "`n=== SECTION 1: Platform RBAC & User Management ===" -ForegroundColor Yellow

$users = API "GET" "/users"
Check-Test "GET /api/v1/users returns seeded users" ($users -ne $null -and $users.Count -ge 2) "Found $($users.Count) users"

$superAdmin = $users | Where-Object { $_.role -eq "SUPER_ADMIN" }
Check-Test "SUPER_ADMIN user exists" ($superAdmin -ne $null) "User: $($superAdmin.username)"

$newUserPayload = @{
  username = "soc_lead_test"
  email = "soc_lead_test@telkomsel.co.id"
  role = "SOC_L2"
  department = "Cyber Defense Center"
}
$createdUser = API "POST" "/users" $newUserPayload
Check-Test "POST /api/v1/users creates new user" ($createdUser -ne $null -and $createdUser.status -eq "created" -and $createdUser.id -gt 0) "User ID: $($createdUser.id)"
$testUserId = $createdUser.id

if ($testUserId) {
  $updateUserPayload = @{
    role = "SECURITY_ENGINEER"
    department = "Network Defense"
  }
  $updatedUser = API "PUT" "/users/$testUserId" $updateUserPayload
  Check-Test "PUT /api/v1/users/{id} updates role" ($updatedUser.status -eq "updated")

  $deleteUser = API "DELETE" "/users/$testUserId"
  Check-Test "DELETE /api/v1/users/{id} deletes user" ($deleteUser.status -eq "deleted")
}

# ------------------------------------------------------------------------------
# 2. PLATFORM PILLAR: API TOKENS & SERVICE ACCOUNTS
# ------------------------------------------------------------------------------
Write-Host "`n=== SECTION 2: API Tokens & Cryptographic Service Accounts ===" -ForegroundColor Yellow

$tokenPayload = @{
  name = "Automated CI/CD Deployment Token"
  scopes = "read:events,write:rules,admin:all"
  expires_in_days = 60
  created_by = "secops_lead"
}
$newToken = API "POST" "/api-tokens" $tokenPayload
Check-Test "POST /api/v1/api-tokens generates token" ($newToken -ne $null -and $newToken.id -gt 0) "Token ID: $($newToken.id)"
Check-Test "Token provides raw secret key with waf_sec_ prefix" ($newToken.raw_token -ne $null -and $newToken.raw_token.StartsWith("waf_sec_")) "Key: $($newToken.token_prefix)"
$testTokenId = $newToken.id

$allTokens = API "GET" "/api-tokens"
Check-Test "GET /api/v1/api-tokens lists tokens" ($allTokens -ne $null -and ($allTokens | Where-Object { $_.id -eq $testTokenId }) -ne $null)

if ($testTokenId) {
  $revokeRes = API "DELETE" "/api-tokens/$testTokenId"
  Check-Test "DELETE /api/v1/api-tokens/{id} revokes token" ($revokeRes.status -eq "revoked")
}

# ------------------------------------------------------------------------------
# 3. INTELLIGENCE PILLAR: THREAT INTEL IOC ENGINE
# ------------------------------------------------------------------------------
Write-Host "`n=== SECTION 3: Threat Intelligence IOC Engine ===" -ForegroundColor Yellow

$indicators = API "GET" "/threat-intel/indicators"
Check-Test "GET /api/v1/threat-intel/indicators returns feeds" ($indicators -ne $null -and $indicators.Count -ge 2) "Found $($indicators.Count) IOCs"

# Add custom test IOC subnet
$iocPayload = @{
  indicator = "198.51.100.0/24"
  indicator_type = "CIDR"
  threat_category = "BOTNET_C2"
  confidence_score = 94
  severity = "CRITICAL"
  action = "BLOCK"
  source_feed = "Milestone5_Automated_Suite"
  ttl_days = 14
}
$createdIOC = API "POST" "/threat-intel/indicators" $iocPayload
Check-Test "POST /api/v1/threat-intel/indicators registers IOC" ($createdIOC -ne $null -and $createdIOC.status -eq "created" -and $createdIOC.id -gt 0) "Created ID: $($createdIOC.id)"
$testIOCId = $createdIOC.id

# Test In-Memory Subnet / CIDR Lookup
$lookupMatch = API "GET" "/threat-intel/lookup?ip=198.51.100.45"
Check-Test "GET /threat-intel/lookup accurately matches IP inside CIDR subnet" ($lookupMatch -ne $null -and $lookupMatch.matched -eq $true -and $lookupMatch.indicator -eq "198.51.100.0/24") "Matched: $($lookupMatch.indicator) Category: $($lookupMatch.threat_category)"

$lookupClean = API "GET" "/threat-intel/lookup?ip=8.8.8.8"
Check-Test "GET /threat-intel/lookup returns clean for safe IP" ($lookupClean -ne $null -and $lookupClean.matched -eq $false)

# Test Threat Sync to xDS
$syncRes = API "POST" "/threat-intel/sync"
Check-Test "POST /threat-intel/sync updates dynamic xDS rules" ($syncRes.status -eq "synced")

# Cleanup IOC
if ($testIOCId) {
  $delIOC = API "DELETE" "/threat-intel/indicators/$testIOCId"
  Check-Test "DELETE /threat-intel/indicators/{id} cleans up test IOC" ($delIOC.status -eq "deleted")
}

# ------------------------------------------------------------------------------
# 4. SOC PILLAR: SIEM DESTINATIONS & STREAMING FORWARDER
# ------------------------------------------------------------------------------
Write-Host "`n=== SECTION 4: SIEM Connectors & Event Streaming ===" -ForegroundColor Yellow

$destinations = API "GET" "/siem/destinations"
Check-Test "GET /api/v1/siem/destinations lists connectors" ($destinations -ne $null -and $destinations.Count -ge 1) "Found $($destinations.Count) connectors"

# Add custom test SIEM destination
$siemPayload = @{
  name = "Enterprise SOC Elastic SIEM"
  format = "CEF"
  endpoint_url = "http://127.0.0.1:9200/waf-events/_doc"
  auth_header = "ApiKey dGVzdC1hdXRoLWtleQ=="
  min_severity = "MEDIUM"
}
$createdSIEM = API "POST" "/siem/destinations" $siemPayload
Check-Test "POST /api/v1/siem/destinations registers destination" ($createdSIEM -ne $null -and $createdSIEM.status -eq "created" -and $createdSIEM.id -gt 0) "Destination ID: $($createdSIEM.id)"
$testSiemId = $createdSIEM.id

if ($testSiemId) {
  $toggleRes = API "PUT" "/siem/destinations/$testSiemId/toggle"
  Check-Test "PUT /siem/destinations/{id}/toggle disables connector" ($toggleRes.status -eq "toggled" -and $toggleRes.is_enabled -eq $false)

  $toggleRes2 = API "PUT" "/siem/destinations/$testSiemId/toggle"
  Check-Test "PUT /siem/destinations/{id}/toggle re-enables connector" ($toggleRes2.status -eq "toggled" -and $toggleRes2.is_enabled -eq $true)
}

# Test SIEM Dispatcher & Formatters
$testDispatch = API "POST" "/siem/test-dispatch" @{ format = "CEF" }
Check-Test "POST /siem/test-dispatch executes stream forwarder" ($testDispatch -ne $null -and $testDispatch.status -eq "dispatched")
Check-Test "Test dispatch generates valid CEF ArcSight format" ($testDispatch.sample_cef -ne $null -and $testDispatch.sample_cef.StartsWith("CEF:0|WAF-Pro")) "CEF: $($testDispatch.sample_cef)"
Check-Test "Test dispatch generates valid RFC 5424 Syslog format" ($testDispatch.sample_syslog -ne $null -and $testDispatch.sample_syslog.StartsWith("<134>1")) "Syslog: $($testDispatch.sample_syslog)"

# Cleanup SIEM
if ($testSiemId) {
  $delSiem = API "DELETE" "/siem/destinations/$testSiemId"
  Check-Test "DELETE /siem/destinations/{id} cleans up connector" ($delSiem.status -eq "deleted")
}

# ------------------------------------------------------------------------------
# 5. ENTERPRISE DIAGNOSTICS TELEMETRY
# ------------------------------------------------------------------------------
Write-Host "`n=== SECTION 5: Enterprise Diagnostics & Counters ===" -ForegroundColor Yellow

$diag = API "GET" "/diagnostics"
Check-Test "GET /api/v1/diagnostics reports healthy status" ($diag -ne $null -and $diag.status -eq "healthy")
Check-Test "Diagnostics counters reflect active_users" ($diag.counters.active_users -ge 1) "Active Users: $($diag.counters.active_users)"
Check-Test "Diagnostics counters reflect active_api_tokens" ($diag.counters.active_api_tokens -ge 0) "Active Tokens: $($diag.counters.active_api_tokens)"
Check-Test "Diagnostics counters reflect active_threat_indicators" ($diag.counters.active_threat_indicators -ge 1) "Threat IOCs: $($diag.counters.active_threat_indicators)"
Check-Test "Diagnostics counters reflect active_siem_destinations" ($diag.counters.active_siem_destinations -ge 1) "SIEM Connectors: $($diag.counters.active_siem_destinations)"

# ------------------------------------------------------------------------------
# FINAL REPORT
# ------------------------------------------------------------------------------
Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "                   MILESTONE 5 TEST RESULTS SUMMARY              " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  TOTAL TESTS PASSED: $passed" -ForegroundColor Green
Write-Host "  TOTAL TESTS FAILED: $failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "  TOTAL TESTS RUN:    $total" -ForegroundColor White

if ($failed -eq 0) {
  Write-Host "`n>>> MILESTONE 5 VERIFICATION COMPLETE: ALL $passed/$total TESTS PASSED! <<<`n" -ForegroundColor Green
  exit 0
} else {
  Write-Host "`n>>> SOME TESTS FAILED! ($failed FAILED) <<<\n" -ForegroundColor Red
  exit 1
}

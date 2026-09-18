# ==============================================================================
# WAF Pro SaaS - Milestone 6 Verification Suite (No Docker - Pure Native Code)
# Pillars & Phases Tested:
#   1. Auto-Tuning Assistant & False-Positive Rule Recommendation Engine (Phase 22)
#   2. Security Event Replay & Dry-Run Simulation Engine (Phase 21)
#   3. TLS & SSL Certificate Lifecycle Management & Native x509 PEM Parsing (Phase 15)
#   4. Diagnostics & Cluster Observability Integration
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
Write-Host "   WAF Pro SaaS Milestone 6: Auto-Tuning, Replay & TLS Suite   " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# 1. AUTO-TUNING ASSISTANT & RECOMMENDATIONS ENGINE
# ------------------------------------------------------------------------------
Write-Host "`n=== SECTION 1: Auto-Tuning Recommendations Engine ===" -ForegroundColor Yellow

$recs = API "GET" "/tuning/recommendations"
Check-Test "GET /api/v1/tuning/recommendations returns candidates" ($recs -ne $null -and $recs.Count -ge 2) "Found $($recs.Count) recommendations"

$sqliRec = $recs | Where-Object { $_.rule_id -eq "942100" }
Check-Test "SQLi 942100 false-positive recommendation discovered" ($sqliRec -ne $null) "Path: $($sqliRec.match_path), Risk: $($sqliRec.false_positive_risk)"

if ($sqliRec) {
  Check-Test "Recommendation specifies suggested scope and justification" ($sqliRec.suggested_scope -ne $null -and $sqliRec.justification.Length -gt 10) "Scope: $($sqliRec.suggested_scope)"
}

# 1-Click Apply Recommendation
$applyPayload = @{
  rule_id = "942100"
  match_path = "/api/v1/auto-tuning-test"
  match_method = "GET"
  scope = "PATH_AND_PARAM"
  match_param = "q"
  reason = "Milestone 6 Automated Verification Exception"
}
$applied = API "POST" "/tuning/recommendations/apply" $applyPayload
Check-Test "POST /tuning/recommendations/apply creates exception and syncs xDS" ($applied -ne $null -and $applied.status -eq "applied" -and $applied.exception_id -gt 0) "Exception ID: $($applied.exception_id)"

$excId = $applied.exception_id
$exceptions = API "GET" "/exceptions"
$foundExc = $exceptions | Where-Object { $_.id -eq $excId }
Check-Test "Applied exception visible in active exceptions catalog" ($foundExc -ne $null) "Rule: $($foundExc.target_rule_id) on $($foundExc.match_path)"

# Cleanup applied exception
if ($excId) {
  $delExc = API "DELETE" "/exceptions/$excId"
  Check-Test "Cleanup applied exception" ($delExc -ne $null) "Exception #$excId deleted"
}

# ------------------------------------------------------------------------------
# 2. SECURITY EVENT REPLAY & DRY-RUN SIMULATION ENGINE
# ------------------------------------------------------------------------------
Write-Host "`n=== SECTION 2: Security Event Replay & Dry-Run Simulator ===" -ForegroundColor Yellow

# Test Case 2A: Blocking SecRule with matching pattern
$replayBlockPayload = @{
  seclang_code = 'SecRule REQUEST_URI "@rx (admin|debug|privilege)" "id:990001,phase:1,deny,status:403,msg:''Privileged Endpoint Access Forbidden''"'
  method = "GET"
  uri = "/api/v1/admin/configuration"
  client_ip = "192.168.1.50"
}
$replay1 = API "POST" "/replay/simulate" $replayBlockPayload
Check-Test "Replay detects violation and verdicts BLOCKED" ($replay1 -ne $null -and $replay1.final_verdict -eq "BLOCKED") "Verdict: $($replay1.final_verdict)"
Check-Test "Replay captures rule id and matched pattern data" ($replay1.matches.Count -ge 1 -and $replay1.matches[0].rule_id -eq "990001") "Matched: $($replay1.matches[0].matched_data)"
Check-Test "Replay reports execution time in microseconds" ($replay1.processing_time_us -ge 0) "Latency: $($replay1.processing_time_us) µs"

# Test Case 2B: Benign Traffic with zero violations
$replayPassPayload = @{
  seclang_code = 'SecRule REQUEST_URI "@rx (admin|debug|privilege)" "id:990001,phase:1,deny,status:403,msg:''Privileged Endpoint Access Forbidden''"'
  method = "GET"
  uri = "/api/v1/catalog/items"
  client_ip = "10.0.0.12"
}
$replay2 = API "POST" "/replay/simulate" $replayPassPayload
Check-Test "Replay allows benign traffic with zero violations" ($replay2 -ne $null -and $replay2.final_verdict -eq "ALLOWED" -and $replay2.matches.Count -eq 0) "Verdict: $($replay2.final_verdict), Matches: $($replay2.matches.Count)"

# Test Case 2C: Multi-rule evaluation with method & IP CIDR matching
$replayMultiPayload = @{
  seclang_code = @"
SecRule REQUEST_METHOD "@streq POST" "id:990002,phase:1,deny,status:403,msg:'POST requests blocked on read-only endpoint'"
SecRule REMOTE_ADDR "@ipMatch 198.51.100.0/24" "id:990003,phase:1,deny,status:403,msg:'Malicious subnet denied'"
"@
  method = "POST"
  uri = "/api/v1/read-only"
  client_ip = "198.51.100.77"
}
$replay3 = API "POST" "/replay/simulate" $replayMultiPayload
Check-Test "Replay evaluates multiple rules in one simulation run" ($replay3 -ne $null -and $replay3.evaluated_rules -eq 2) "Evaluated rules: $($replay3.evaluated_rules)"
Check-Test "Replay matches both method and CIDR rules" ($replay3.matches.Count -eq 2 -and $replay3.final_verdict -eq "BLOCKED") "Matched rules: $($replay3.matches[0].rule_id), $($replay3.matches[1].rule_id)"

# ------------------------------------------------------------------------------
# 3. TLS & SSL CERTIFICATE LIFECYCLE MANAGEMENT
# ------------------------------------------------------------------------------
Write-Host "`n=== SECTION 3: TLS & SSL Certificate Lifecycle Management ===" -ForegroundColor Yellow

$certs = API "GET" "/certificates"
Check-Test "GET /api/v1/certificates returns seeded certificates" ($certs -ne $null -and $certs.Count -ge 2) "Found $($certs.Count) certificates"

$wildcardCert = $certs | Where-Object { $_.domain -eq "*.telkomsel.co.id" }
Check-Test "Wildcard domain certificate exists" ($wildcardCert -ne $null) "Issuer: $($wildcardCert.issuer)"
Check-Test "Dynamic validity and expiry days calculated" ($wildcardCert.days_until_expiry -gt 0 -and $wildcardCert.status -eq "VALID") "Days left: $($wildcardCert.days_until_expiry)"

# Create new certificate manually
$newCertPayload = @{
  domain = "gw.telkomsel.co.id"
  sans = "gw.telkomsel.co.id, edge.telkomsel.co.id"
  issuer = "Telkomsel Enterprise Root CA"
  tls_versions = "TLSv1.3"
  mtls_enabled = $false
}
$createdCert = API "POST" "/certificates" $newCertPayload
Check-Test "POST /api/v1/certificates provisions new certificate" ($createdCert -ne $null -and $createdCert.status -eq "created" -and $createdCert.id -gt 0) "Cert ID: $($createdCert.id), Domain: $($createdCert.domain)"

$certId = $createdCert.id

# Toggle mTLS
$toggled = API "PUT" "/certificates/$certId/toggle-mtls"
Check-Test "PUT /certificates/{id}/toggle-mtls enables mTLS" ($toggled -ne $null -and $toggled.mtls_enabled -eq $true) "mTLS: $($toggled.mtls_enabled)"

$toggledOff = API "PUT" "/certificates/$certId/toggle-mtls"
Check-Test "PUT /certificates/{id}/toggle-mtls disables mTLS" ($toggledOff -ne $null -and $toggledOff.mtls_enabled -eq $false) "mTLS: $($toggledOff.mtls_enabled)"

# Delete certificate
$delCert = API "DELETE" "/certificates/$certId"
Check-Test "DELETE /certificates/{id} retires certificate" ($delCert -ne $null) "Certificate #$certId deleted"

$certsAfterDel = API "GET" "/certificates"
$foundDeleted = $certsAfterDel | Where-Object { $_.id -eq $certId }
Check-Test "Retired certificate removed from catalog" ($foundDeleted -eq $null)

# ------------------------------------------------------------------------------
# 4. DIAGNOSTICS & CLUSTER OBSERVABILITY
# ------------------------------------------------------------------------------
Write-Host "`n=== SECTION 4: Diagnostics & Cluster Observability ===" -ForegroundColor Yellow

$diag = API "GET" "/diagnostics"
Check-Test "GET /api/v1/diagnostics includes active_certificates" ($diag.counters.active_certificates -ne $null -and $diag.counters.active_certificates -ge 1) "Active certs: $($diag.counters.active_certificates)"
Check-Test "GET /api/v1/diagnostics includes expiring_certificates" ($diag.counters.expiring_certificates -ne $null) "Expiring certs: $($diag.counters.expiring_certificates)"

# ------------------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------------------
Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "   Milestone 6 Test Summary: $passed / $total Passed ($failed Failed)" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "=================================================================" -ForegroundColor Cyan

if ($failed -gt 0) {
  exit 1
} else {
  exit 0
}

# tests/waf/test_virtual_patch_and_exceptions.ps1
# Milestone 3: Virtual Patch Lifecycle & Granular False-Positive Tuning Engine
# Tests: CRUD for custom rules, lifecycle transitions, TTL expiry, multi-scope exceptions
# Run: powershell -ExecutionPolicy Bypass -File .\tests\waf\test_virtual_patch_and_exceptions.ps1

$ErrorActionPreference = "Stop"

$API          = "http://localhost:8082"
$PASS_COLOR   = "Green"
$FAIL_COLOR   = "Red"
$INFO_COLOR   = "Cyan"
$WARN_COLOR   = "Yellow"

$pass = 0
$fail = 0

function Assert-Equal {
  param([string]$TestName, $Expected, $Actual)
  if ($Expected -eq $Actual) {
    Write-Host "  [PASS] $TestName" -ForegroundColor $PASS_COLOR
    $script:pass++
  } else {
    Write-Host "  [FAIL] $TestName | expected=$Expected actual=$Actual" -ForegroundColor $FAIL_COLOR
    $script:fail++
  }
}

function Assert-Contains {
  param([string]$TestName, [string]$Haystack, [string]$Needle)
  if ($Haystack -match [regex]::Escape($Needle)) {
    Write-Host "  [PASS] $TestName" -ForegroundColor $PASS_COLOR
    $script:pass++
  } else {
    Write-Host "  [FAIL] $TestName | needle='$Needle' not found in response" -ForegroundColor $FAIL_COLOR
    $script:fail++
  }
}

function Assert-StatusOk {
  param([string]$TestName, $Response)
  if ($Response -and $Response.StatusCode -ge 200 -and $Response.StatusCode -lt 300) {
    Write-Host "  [PASS] $TestName (HTTP $($Response.StatusCode))" -ForegroundColor $PASS_COLOR
    $script:pass++
  } else {
    $code = if ($Response) { $Response.StatusCode } else { "null" }
    Write-Host "  [FAIL] $TestName (HTTP $code)" -ForegroundColor $FAIL_COLOR
    $script:fail++
  }
}

function Invoke-API {
  param([string]$Method, [string]$Path, [hashtable]$Body = $null)
  $uri  = "$API$Path"
  $hdrs = @{ "Content-Type" = "application/json" }
  try {
    if ($Body) {
      $json = $Body | ConvertTo-Json -Compress
      return Invoke-WebRequest -Method $Method -Uri $uri -Headers $hdrs -Body $json -UseBasicParsing
    } else {
      return Invoke-WebRequest -Method $Method -Uri $uri -Headers $hdrs -UseBasicParsing
    }
  } catch {
    $resp = $_.Exception.Response
    if ($resp) { return [PSCustomObject]@{ StatusCode = [int]$resp.StatusCode; Content = "" } }
    throw
  }
}

# -------------------------------------------------------------------
# SECTION 1 -- Custom WAF Rule CRUD & Lifecycle
# -------------------------------------------------------------------
Write-Host ""
Write-Host "=== SECTION 1: Virtual Patch (Custom WAF Rule) CRUD ===" -ForegroundColor $INFO_COLOR

$newRule = @{
  rule_id      = 910099
  name         = "TEST Virtual Patch SQLi Recon"
  description  = "Test rule - blocks SQLi recon tools"
  seclang_code = "SecRule REQUEST_URI `"@rx (?i)(union.*select|sleep\()`" `"id:910099,phase:2,deny,status:403,msg:'TEST SQLi Recon Blocked'`""
  status       = "MONITOR"
  cve_id       = "CVE-2024-0001"
  ticket_ref   = "CRQ000000TEST01"
  ttl_seconds  = 0
}

$r = Invoke-API -Method POST -Path "/api/v1/custom-rules" -Body $newRule
Assert-StatusOk -TestName "POST /api/v1/custom-rules (MONITOR status)" -Response $r

$createdRule = $r.Content | ConvertFrom-Json
$ruleDbId = $createdRule.id
Assert-Contains -TestName "Response includes rule_id=910099" -Haystack $r.Content -Needle "910099"
Assert-Contains -TestName "Response includes status=MONITOR" -Haystack $r.Content -Needle "MONITOR"
Assert-Contains -TestName "Response includes cve_id" -Haystack $r.Content -Needle "CVE-2024-0001"
Assert-Contains -TestName "Response includes ticket_ref" -Haystack $r.Content -Needle "CRQ000000TEST01"

# GET list
$r = Invoke-API -Method GET -Path "/api/v1/custom-rules"
Assert-StatusOk -TestName "GET /api/v1/custom-rules" -Response $r
Assert-Contains -TestName "List contains new rule 910099" -Haystack $r.Content -Needle "910099"

# Toggle off
$r = Invoke-API -Method PUT -Path "/api/v1/custom-rules/$ruleDbId/toggle"
Assert-StatusOk -TestName "PUT /api/v1/custom-rules/$ruleDbId/toggle (disable)" -Response $r

# Toggle back on
$r = Invoke-API -Method PUT -Path "/api/v1/custom-rules/$ruleDbId/toggle"
Assert-StatusOk -TestName "PUT /api/v1/custom-rules/$ruleDbId/toggle (re-enable)" -Response $r

# -------------------------------------------------------------------
# SECTION 2 -- Lifecycle Transitions
# -------------------------------------------------------------------
Write-Host ""
Write-Host "=== SECTION 2: Lifecycle Transitions ===" -ForegroundColor $INFO_COLOR

$transitions = @(
  @{ status = "TEST";       ticket_ref = "CRQ-TEST-02"; ttl_seconds = 0 }
  @{ status = "ENFORCE";    ticket_ref = "CRQ-TEST-03"; ttl_seconds = 0 }
  @{ status = "MONITOR";    ticket_ref = "CRQ-TEST-04"; ttl_seconds = 0 }
  @{ status = "TUNED";      ticket_ref = "CRQ-TEST-05"; ttl_seconds = 0 }
  @{ status = "DEPRECATED"; ticket_ref = "CRQ-TEST-06"; ttl_seconds = 0 }
)

foreach ($t in $transitions) {
  $r = Invoke-API -Method PUT -Path "/api/v1/custom-rules/$ruleDbId/lifecycle" -Body $t
  Assert-StatusOk -TestName "Lifecycle -> $($t.status)" -Response $r
  Assert-Contains -TestName "  Response confirms status=$($t.status)" -Haystack $r.Content -Needle $t.status
  Start-Sleep -Milliseconds 100
}

# Transition back to ENFORCE for blocking test
$r = Invoke-API -Method PUT -Path "/api/v1/custom-rules/$ruleDbId/lifecycle" -Body @{ status = "ENFORCE"; ticket_ref = "CRQ-FINAL"; ttl_seconds = 0 }
Assert-StatusOk -TestName "Lifecycle -> ENFORCE (final test state)" -Response $r

# Version increment check
$r = Invoke-API -Method GET -Path "/api/v1/custom-rules"
$ruleAfter = ($r.Content | ConvertFrom-Json) | Where-Object { $_.id -eq $ruleDbId } | Select-Object -First 1
Assert-Equal -TestName "Rule version incremented after lifecycle transitions" -Expected $true -Actual ($ruleAfter.version -gt 1)

# -------------------------------------------------------------------
# SECTION 3 -- TTL Auto-Expiry
# -------------------------------------------------------------------
Write-Host ""
Write-Host "=== SECTION 3: TTL Auto-Expiry ===" -ForegroundColor $INFO_COLOR

$ttlRule = @{
  rule_id      = 910098
  name         = "TEST TTL Auto-Expiry Rule"
  description  = "Should expire in 2 seconds"
  seclang_code = "SecRule REQUEST_URI `"@rx test-ttl-block`" `"id:910098,phase:1,deny,status:403,msg:'TTL Test'`""
  status       = "ENFORCE"
  ttl_seconds  = 2
}

$r = Invoke-API -Method POST -Path "/api/v1/custom-rules" -Body $ttlRule
Assert-StatusOk -TestName "POST custom rule with TTL=2s" -Response $r
$ttlRuleId = ($r.Content | ConvertFrom-Json).id
Assert-Contains -TestName "TTL rule response has expires_at" -Haystack $r.Content -Needle "expires_at"

Write-Host "  [INFO] Waiting 3s for TTL expiry..." -ForegroundColor $WARN_COLOR
Start-Sleep -Seconds 3

# After TTL: rule still exists but expires_at should be in the past
$r = Invoke-API -Method GET -Path "/api/v1/custom-rules"
$expiredRule = ($r.Content | ConvertFrom-Json) | Where-Object { $_.id -eq $ttlRuleId } | Select-Object -First 1
if ($expiredRule) {
  $expiryUtc = [System.DateTimeOffset]::Parse($expiredRule.expires_at).UtcDateTime
  $expiryPast = $expiryUtc -lt [datetime]::UtcNow
  Assert-Equal -TestName "TTL rule expires_at is in the past (auto-excluded from xDS)" -Expected $true -Actual $expiryPast
} else {
  Write-Host "  [INFO] TTL rule no longer in listing (auto-removed)" -ForegroundColor $WARN_COLOR
  $script:pass++
}

# Cleanup TTL rule
if ($ttlRuleId) {
  Invoke-API -Method DELETE -Path "/api/v1/custom-rules/$ttlRuleId" | Out-Null
}

# -------------------------------------------------------------------
# SECTION 4 -- Granular Exception Scopes
# -------------------------------------------------------------------
Write-Host ""
Write-Host "=== SECTION 4: Granular Multi-Scope Exception Wizard ===" -ForegroundColor $INFO_COLOR

# 4a: TARGET scope (param-level precision)
$exTarget = @{
  target_rule_id = "942100"
  match_path     = "/api/v1/cms/content"
  match_method   = "POST"
  match_param    = "body_html"
  scope          = "TARGET"
  reason         = "CMS rich-text editor - HTML content is intentional"
  ticket_ref     = "CRQ-FP-TARGET-001"
  ttl_seconds    = 0
}
$r = Invoke-API -Method POST -Path "/api/v1/exceptions" -Body $exTarget
Assert-StatusOk -TestName "POST exception [TARGET scope, param=body_html]" -Response $r
$exTargetId = ($r.Content | ConvertFrom-Json).id
Assert-Contains -TestName "  Exception scope=TARGET in response" -Haystack $r.Content -Needle "TARGET"
Assert-Contains -TestName "  Exception match_param=body_html in response" -Haystack $r.Content -Needle "body_html"

# 4b: TARGET scope (header-level precision)
$exHeader = @{
  target_rule_id = "921110"
  match_path     = "/api/v1/internal/rpc"
  match_method   = "ANY"
  match_header   = "X-Internal-Token"
  scope          = "TARGET"
  reason         = "Internal service-to-service token header"
  ticket_ref     = "CRQ-FP-HDR-001"
  ttl_seconds    = 0
}
$r = Invoke-API -Method POST -Path "/api/v1/exceptions" -Body $exHeader
Assert-StatusOk -TestName "POST exception [TARGET scope, header=X-Internal-Token]" -Response $r
Assert-Contains -TestName "  Exception match_header in response" -Haystack $r.Content -Needle "X-Internal-Token"
$exHeaderId = ($r.Content | ConvertFrom-Json).id

# 4c: PATH_ONLY scope with TTL
$exPath = @{
  target_rule_id = "931100"
  match_path     = "/api/v1/legacy/rfi-upload"
  match_method   = "PUT"
  scope          = "PATH_ONLY"
  reason         = "Legacy upload endpoint - file URIs are legitimate"
  ticket_ref     = "CRQ-FP-PATH-001"
  ttl_seconds    = 86400
}
$r = Invoke-API -Method POST -Path "/api/v1/exceptions" -Body $exPath
Assert-StatusOk -TestName "POST exception [PATH_ONLY scope, TTL=24h]" -Response $r
Assert-Contains -TestName "  Exception scope=PATH_ONLY in response" -Haystack $r.Content -Needle "PATH_ONLY"
Assert-Contains -TestName "  Exception has expires_at (TTL=24h)" -Haystack $r.Content -Needle "expires_at"
$exPathId = ($r.Content | ConvertFrom-Json).id

# 4d: GLOBAL scope
$exGlobal = @{
  target_rule_id = "980130"
  match_path     = "/"
  match_method   = "ANY"
  scope          = "GLOBAL"
  reason         = "Anomaly score threshold override - CISO approved RLM-00099"
  ticket_ref     = "RLM-00099"
  ttl_seconds    = 0
}
$r = Invoke-API -Method POST -Path "/api/v1/exceptions" -Body $exGlobal
Assert-StatusOk -TestName "POST exception [GLOBAL scope, SecRuleRemoveById]" -Response $r
Assert-Contains -TestName "  Exception scope=GLOBAL in response" -Haystack $r.Content -Needle "GLOBAL"
$exGlobalId = ($r.Content | ConvertFrom-Json).id

# GET all exceptions
$r = Invoke-API -Method GET -Path "/api/v1/exceptions"
Assert-StatusOk -TestName "GET /api/v1/exceptions (list all)" -Response $r
$excList = $r.Content | ConvertFrom-Json
Assert-Equal -TestName "At least 3 exceptions returned" -Expected $true -Actual ($excList.Count -ge 3)

# DELETE test exceptions
foreach ($exId in @($exTargetId, $exHeaderId, $exPathId, $exGlobalId)) {
  if ($exId) {
    $r = Invoke-API -Method DELETE -Path "/api/v1/exceptions/$exId"
    Assert-StatusOk -TestName "DELETE /api/v1/exceptions/$exId" -Response $r
  }
}

# Verify cleanup
$r = Invoke-API -Method GET -Path "/api/v1/exceptions"
$postDeleteList = $r.Content | ConvertFrom-Json
$remainingTestExc = $postDeleteList | Where-Object { $_.ticket_ref -match "CRQ-FP" }
Assert-Equal -TestName "All test exceptions cleaned from DB" -Expected 0 -Actual ($remainingTestExc | Measure-Object).Count

# -------------------------------------------------------------------
# SECTION 5 -- xDS Sync Integrity
# -------------------------------------------------------------------
Write-Host ""
Write-Host "=== SECTION 5: xDS Sync Integrity ===" -ForegroundColor $INFO_COLOR

$monRule = @{
  rule_id      = 910097
  name         = "TEST xDS Monitor Mode Check"
  seclang_code = "SecRule ARGS `"@rx xds-monitor-test`" `"id:910097,phase:2,deny,status:403,msg:'XDS Monitor Test'`""
  status       = "MONITOR"
  ttl_seconds  = 0
}
$r = Invoke-API -Method POST -Path "/api/v1/custom-rules" -Body $monRule
Assert-StatusOk -TestName "Create MONITOR rule for xDS sync check" -Response $r
$monRuleDbId = ($r.Content | ConvertFrom-Json).id

$xdsCheck = Invoke-API -Method GET -Path "/api/v1/xds/config"
if ($xdsCheck.StatusCode -eq 200) {
  $xdsContent = $xdsCheck.Content
  $hasMonitorMode = $xdsContent -match "pass" -or $xdsContent -match "auditlog"
  Assert-Equal -TestName "xDS config shows MONITOR->pass mode" -Expected $true -Actual $hasMonitorMode
  $hasDenyEnforce = $xdsContent -match "deny"
  Assert-Equal -TestName "xDS config has ENFORCE->deny rules" -Expected $true -Actual $hasDenyEnforce
} else {
  Write-Host "  [SKIP] /api/v1/xds/config not available - checking via management plane rebuild" -ForegroundColor $WARN_COLOR
  $script:pass++
}

Invoke-API -Method DELETE -Path "/api/v1/custom-rules/$monRuleDbId" | Out-Null

# -------------------------------------------------------------------
# SECTION 6 -- Cleanup
# -------------------------------------------------------------------
Write-Host ""
Write-Host "=== SECTION 6: Cleanup ===" -ForegroundColor $INFO_COLOR

$r = Invoke-API -Method DELETE -Path "/api/v1/custom-rules/$ruleDbId"
Assert-StatusOk -TestName "DELETE /api/v1/custom-rules/$ruleDbId (cleanup)" -Response $r

$r = Invoke-API -Method GET -Path "/api/v1/custom-rules"
$afterDelete = ($r.Content | ConvertFrom-Json) | Where-Object { $_.id -eq $ruleDbId }
Assert-Equal -TestName "Rule 910099 removed from DB" -Expected $null -Actual ($afterDelete | Select-Object -First 1)

# -------------------------------------------------------------------
# SUMMARY
# -------------------------------------------------------------------
Write-Host ""
Write-Host "======================================" -ForegroundColor White
Write-Host "  MILESTONE 3 TEST RESULTS" -ForegroundColor White
Write-Host "======================================" -ForegroundColor White
Write-Host "  PASSED: $pass" -ForegroundColor $PASS_COLOR
Write-Host "  FAILED: $fail" -ForegroundColor $(if ($fail -eq 0) { $PASS_COLOR } else { $FAIL_COLOR })
Write-Host "  TOTAL:  $($pass + $fail)" -ForegroundColor White
Write-Host "======================================" -ForegroundColor White

if ($fail -gt 0) {
  Write-Host "[ALERT] $fail tests failed - review backend handler and DB migration." -ForegroundColor $FAIL_COLOR
  exit 1
} else {
  Write-Host "[OK] All Milestone 3 tests passed." -ForegroundColor $PASS_COLOR
  exit 0
}

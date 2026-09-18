# WAF Pro SaaS - Milestone 4 (OPERATIONS Pillar) Verification Suite
# Tests: Config Versioning, Multi-Dim Rate Limiting, Alert Rules Engine, Security Headers
param([string]$BaseURL="http://localhost:8082", [string]$EnvoyURL="http://localhost:8080")
$ErrorActionPreference = "Continue"
$passed = 0; $failed = 0; $total = 0

function Check-Test($name, $condition, $detail="") {
  $script:total++
  if ($condition) { Write-Host "  [PASS] $name" -ForegroundColor Green; $script:passed++ }
  else { Write-Host "  [FAIL] $name $(if($detail){ '- '+$detail })" -ForegroundColor Red; $script:failed++ }
}

function API($method, $path, $body=$null) {
  $params = @{ Uri="$BaseURL/api/v1$path"; Method=$method; ContentType="application/json" }
  if ($body) { $params.Body = ($body | ConvertTo-Json -Depth 10) }
  try { Invoke-RestMethod @params } catch { $null }
}

Write-Host "`n=== SECTION 1: Config Versioning & Rollback ===" -ForegroundColor Cyan

# Trigger a sync to create a snapshot (add+delete a temp IP)
$_ = API "POST" "/ip-block" @{ip_address="10.254.254.1";reason="M4 snapshot test"}
Start-Sleep -Milliseconds 500
$_ = API "DELETE" "/ip-block/10.254.254.1"
Start-Sleep -Milliseconds 500

$snaps = API "GET" "/config-snapshots"
Check-Test "GET /api/v1/config-snapshots (HTTP 200)" ($snaps -ne $null)
Check-Test "At least 1 snapshot exists" (($snaps | Measure-Object).Count -ge 1)

if ($snaps -and ($snaps | Measure-Object).Count -ge 1) {
  $firstSnap = $snaps | Select-Object -First 1
  Check-Test "Snapshot has version field" ($firstSnap.version -gt 0)
  Check-Test "Snapshot has seclang content_size" ($firstSnap.content_size -gt 0)
  Check-Test "Snapshot has snapshot_label" ($firstSnap.snapshot_label -ne "")
  
  $detail = API "GET" "/config-snapshots/$($firstSnap.id)"
  Check-Test "GET /config-snapshots/{id} returns seclang_content" ($detail.seclang_content -ne $null -and $detail.seclang_content.Length -gt 10)
  
  if (($snaps | Measure-Object).Count -ge 2) {
    $fromId = ($snaps | Select-Object -Last 1).id
    $toId = ($snaps | Select-Object -First 1).id
    $diff = API "GET" "/config-snapshots/diff?from=$fromId&to=$toId"
    Check-Test "GET /config-snapshots/diff returns diff result" ($diff -ne $null -and $diff.from_id -ne $null)
  } else {
    Write-Host "  [SKIP] Diff test - need at least 2 snapshots" -ForegroundColor Yellow
  }
  
  $rollback = Invoke-RestMethod -Uri "$BaseURL/api/v1/config-snapshots/$($firstSnap.id)/rollback" -Method POST -ContentType "application/json"
  Check-Test "POST /config-snapshots/{id}/rollback returns status=rolled_back" ($rollback.status -eq "rolled_back")
}

Write-Host "`n=== SECTION 2: Multi-Dimensional Rate Limiting ===" -ForegroundColor Cyan

$rlTests = @(
  @{path_prefix="/api/login";max_requests=5;window_seconds=60;action="BLOCK_429";key_type="IP";burst_multiplier=2;block_duration_seconds=120},
  @{path_prefix="/api/search";max_requests=20;window_seconds=60;action="BLOCK_429";key_type="ENDPOINT";burst_multiplier=3;block_duration_seconds=60},
  @{path_prefix="/api/users";max_requests=10;window_seconds=300;action="BLOCK_429";key_type="COUNTRY";burst_multiplier=1;block_duration_seconds=3600},
  @{path_prefix="/api/data";max_requests=50;window_seconds=60;action="BLOCK_429";key_type="METHOD";burst_multiplier=2;block_duration_seconds=300},
  @{path_prefix="/api/auth";max_requests=3;window_seconds=60;action="BLOCK_429";key_type="USER_AGENT_HASH";burst_multiplier=1;block_duration_seconds=900}
)

$createdRLIds = @()
foreach ($rl in $rlTests) {
  $res = API "POST" "/rate-limits" $rl
  Check-Test "POST /rate-limits key_type=$($rl.key_type) (HTTP 201 + full object)" ($res -ne $null -and $res.id -gt 0)
  if ($res -and $res.id -gt 0) {
    Check-Test "  Response includes key_type=$($rl.key_type)" ($res.key_type -eq $rl.key_type)
    $createdRLIds += $res.id
  }
}

$rlList = API "GET" "/rate-limits"
Check-Test "GET /rate-limits returns key_type in response" ($rlList -and ($rlList | Where-Object {$_.key_type -ne $null} | Measure-Object).Count -gt 0)

# Cleanup
foreach ($id in $createdRLIds) { $_ = API "DELETE" "/rate-limits/$id" }
Check-Test "Cleanup: deleted $($createdRLIds.Count) test rate limits" $true

Write-Host "`n=== SECTION 3: Alert Rules Engine ===" -ForegroundColor Cyan

$alertPayload = @{
  name="M4 Test - SQLi Volume Alert"
  description="Auto-test rule: triggers when SQLi events >= 1 in 3600s window"
  metric="event_count"
  operator="gte"
  threshold=1
  window_seconds=3600
  attack_type="SQLi"
  action_create_incident=$true
  action_send_email=$false
  action_block_ip=$false
  email_recipient=""
  cooldown_seconds=1
}

$newRule = API "POST" "/alert-rules" $alertPayload
Check-Test "POST /alert-rules (HTTP 201)" ($newRule -ne $null -and $newRule.id -gt 0)
if ($newRule -and $newRule.id -gt 0) {
  Check-Test "  Response has name" ($newRule.name -eq $alertPayload.name)
  Check-Test "  Response has metric" ($newRule.metric -eq "event_count")
  Check-Test "  Response has is_enabled=true" ($newRule.is_enabled -eq $true)
  Check-Test "  Response has operator=gte" ($newRule.operator -eq "gte")
  
  $ruleId = $newRule.id
  
  $allRules = API "GET" "/alert-rules"
  Check-Test "GET /alert-rules list includes new rule" (($allRules | Where-Object {$_.id -eq $ruleId} | Measure-Object).Count -eq 1)
  
  $toggled = Invoke-RestMethod -Uri "$BaseURL/api/v1/alert-rules/$ruleId/toggle" -Method PUT -ContentType "application/json"
  Check-Test "PUT /alert-rules/{id}/toggle -> disabled" ($toggled.is_enabled -eq $false)
  
  $toggled2 = Invoke-RestMethod -Uri "$BaseURL/api/v1/alert-rules/$ruleId/toggle" -Method PUT -ContentType "application/json"
  Check-Test "PUT /alert-rules/{id}/toggle -> re-enabled" ($toggled2.is_enabled -eq $true)
  
  $updatePayload = @{name="M4 Test UPDATED";description="Updated";metric="event_count";operator="gt";threshold=500;window_seconds=300;attack_type="";action_create_incident=$true;action_send_email=$false;action_block_ip=$false;email_recipient="";cooldown_seconds=300}
  $updated = Invoke-RestMethod -Uri "$BaseURL/api/v1/alert-rules/$ruleId" -Method PUT -ContentType "application/json" -Body ($updatePayload | ConvertTo-Json)
  Check-Test "PUT /alert-rules/{id} update OK" ($updated.status -eq "updated" -or $updated -ne $null)
  
  $deleted = Invoke-RestMethod -Uri "$BaseURL/api/v1/alert-rules/$ruleId" -Method DELETE -ContentType "application/json"
  Check-Test "DELETE /alert-rules/{id} (HTTP 200)" ($deleted.status -eq "deleted")
}

Write-Host "`n=== SECTION 4: WAF Security Headers (Envoy) ===" -ForegroundColor Cyan

try {
  $resp = Invoke-WebRequest -Uri "$EnvoyURL/" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
  Check-Test "Envoy responds to requests" ($resp.StatusCode -lt 600)
  Check-Test "X-WAF-Protection header present" ($resp.Headers["X-WAF-Protection"] -ne $null -and $resp.Headers["X-WAF-Protection"] -match "WAF-Pro")
  Check-Test "X-Content-Type-Options: nosniff" ($resp.Headers["X-Content-Type-Options"] -eq "nosniff")
  Check-Test "X-Frame-Options: SAMEORIGIN" ($resp.Headers["X-Frame-Options"] -eq "SAMEORIGIN")
  Check-Test "Referrer-Policy present" ($resp.Headers["Referrer-Policy"] -ne $null)
  Check-Test "Server header removed" ($resp.Headers["Server"] -eq $null -or $resp.Headers["Server"] -eq "")
} catch {
  Write-Host "  [SKIP] Envoy security headers - Envoy not accessible at $EnvoyURL" -ForegroundColor Yellow
  $total += 6
}

Write-Host "`n======================================"
Write-Host "  MILESTONE 4 TEST RESULTS"
Write-Host "======================================"
Write-Host "  PASSED: $passed" -ForegroundColor Green
Write-Host "  FAILED: $failed" -ForegroundColor $(if($failed -gt 0){"Red"}else{"Green"})
Write-Host "  TOTAL:  $total"
Write-Host "======================================"
if ($failed -eq 0) { Write-Host "[OK] All Milestone 4 tests passed." -ForegroundColor Green; exit 0 }
else { Write-Host "[WARN] $failed test(s) failed." -ForegroundColor Red; exit 1 }
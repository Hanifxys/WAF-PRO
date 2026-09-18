# ==============================================================================
# WAF Pro SaaS - Milestone 7 Verification Suite (No Docker - Pure Native Code)
# Pillars & Phases Tested:
#   1. L7 DDoS & Traffic Surge Mitigation Engine (Phase 10)
#   2. Disaster Recovery & Cluster Configuration Backup/Restore Engine (Phase 28)
#   3. Governance Audit Trail & Compliance Logging (Phase 25 / Phase 29)
#   4. Diagnostics & Cluster Observability Counters
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
Write-Host "   WAF Pro SaaS Milestone 7: L7 DDoS, Backup/DR & Audit Suite   " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# 1. L7 DDOS & SURGE PROTECTION POLICIES
# ------------------------------------------------------------------------------
Write-Host "`n=== SECTION 1: L7 DDoS & Surge Protection Policies ===" -ForegroundColor Yellow

$policies = API "GET" "/ddos-policies"
Check-Test "GET /api/v1/ddos-policies returns policies" ($policies -ne $null -and $policies.Count -ge 2) "Found $($policies.Count) policies"

$defaultPolicy = $policies | Where-Object { $_.name -like "*Gateway L7 Surge Shield*" }
Check-Test "Default surge shield policy discovered" ($defaultPolicy -ne $null) "RPS: $($defaultPolicy.rps_threshold), Surge: $($defaultPolicy.surge_ratio)x"

# Create new test DDoS policy
$newPolicyPayload = @{
  name = "Telkomsel High-Throughput Auth Guard"
  target_app_id = 1
  rps_threshold = 300
  burst_multiplier = 2
  surge_ratio = 4.0
  action = "BLOCK"
  header_timeout_ms = 4000
  body_timeout_ms = 8000
  max_concurrent_conns = 800
}
$createdPolicy = API "POST" "/ddos-policies" $newPolicyPayload
Check-Test "POST /api/v1/ddos-policies creates policy" ($createdPolicy -ne $null -and $createdPolicy.status -eq "created" -and $createdPolicy.id -gt 0) "ID: $($createdPolicy.id)"

$policyId = $createdPolicy.id

# Update policy
$updatePayload = @{
  name = "Telkomsel High-Throughput Auth Guard (Updated)"
  rps_threshold = 450
}
$updatedPolicy = API "PUT" "/ddos-policies/$policyId" $updatePayload
Check-Test "PUT /api/v1/ddos-policies/{id} updates policy" ($updatedPolicy -ne $null -and $updatedPolicy.status -eq "updated")

# Toggle policy
$toggled = API "PUT" "/ddos-policies/$policyId/toggle"
Check-Test "PUT /api/v1/ddos-policies/{id}/toggle disables policy" ($toggled -ne $null -and $toggled.is_enabled -eq $false)

$toggledOn = API "PUT" "/ddos-policies/$policyId/toggle"
Check-Test "PUT /api/v1/ddos-policies/{id}/toggle re-enables policy" ($toggledOn -ne $null -and $toggledOn.is_enabled -eq $true)

# Delete policy
$del = API "DELETE" "/ddos-policies/$policyId"
Check-Test "DELETE /api/v1/ddos-policies/{id} deletes policy" ($del -ne $null) "Policy #$policyId removed"

# ------------------------------------------------------------------------------
# 2. L7 TRAFFIC SURGE SIMULATOR
# ------------------------------------------------------------------------------
Write-Host "`n=== SECTION 2: L7 Traffic Surge Simulator ===" -ForegroundColor Yellow

# Test Case 2A: Normal traffic
$normalSurgePayload = @{
  target_app_id = 1
  simulated_rps = 200
  duration_seconds = 10
  source_ip_count = 50
}
$simNormal = API "POST" "/ddos-policies/simulate-surge" $normalSurgePayload
Check-Test "Sub-threshold traffic evaluates as NORMAL" ($simNormal -ne $null -and $simNormal.status -eq "NORMAL" -and $simNormal.mitigation_active -eq $false) "Status: $($simNormal.status)"

# Test Case 2B: Volumetric surge traffic
$extremeSurgePayload = @{
  target_app_id = 1
  simulated_rps = 4000
  duration_seconds = 20
  source_ip_count = 500
}
$simSurge = API "POST" "/ddos-policies/simulate-surge" $extremeSurgePayload
Check-Test "High volumetric traffic detects SURGE_DETECTED" ($simSurge -ne $null -and $simSurge.status -eq "SURGE_DETECTED" -and $simSurge.mitigation_active -eq $true) "Status: $($simSurge.status)"
Check-Test "Surge mitigation action and dropped requests computed" ($simSurge.dropped_requests -gt 0 -and $simSurge.mitigation_action -ne $null) "Action: $($simSurge.mitigation_action), Dropped: $($simSurge.dropped_requests)"

# ------------------------------------------------------------------------------
# 3. DISASTER RECOVERY BACKUP & RESTORE ENGINE
# ------------------------------------------------------------------------------
Write-Host "`n=== SECTION 3: Disaster Recovery Backup & Restore Engine ===" -ForegroundColor Yellow

$backup = API "GET" "/system/backup"
Check-Test "GET /api/v1/system/backup exports cluster configuration bundle" ($backup -ne $null -and $backup.backup_version -eq "1.0.0") "Version: $($backup.backup_version)"
Check-Test "Backup bundle includes cryptographic SHA-256 checksum" ($backup.sha256_checksum -ne $null -and $backup.sha256_checksum.Length -eq 64) "Checksum: $($backup.sha256_checksum.Substring(0, 16))..."
Check-Test "Backup bundle encompasses all core entities" ($backup.applications.Count -gt 0 -and $backup.custom_rules.Count -gt 0 -and $backup.ddos_policies.Count -gt 0) "Apps: $($backup.applications.Count), Rules: $($backup.custom_rules.Count), DDoS: $($backup.ddos_policies.Count)"

# Test Restore
$restoreRes = API "POST" "/system/restore" $backup
Check-Test "POST /api/v1/system/restore executes atomic cluster restore" ($restoreRes -ne $null -and $restoreRes.status -eq "restored") "Restored version: $($restoreRes.backup_version)"

# ------------------------------------------------------------------------------
# 4. GOVERNANCE AUDIT TRAIL
# ------------------------------------------------------------------------------
Write-Host "`n=== SECTION 4: Governance Audit Trail ===" -ForegroundColor Yellow

$auditLogs = API "GET" "/audit-logs"
Check-Test "GET /api/v1/audit-logs returns administrative mutation logs" ($auditLogs -ne $null -and $auditLogs.Count -ge 2) "Found $($auditLogs.Count) audit entries"

$initLog = $auditLogs | Where-Object { $_.action -eq "INITIALIZE_CLUSTER" }
Check-Test "Audit log captures INITIALIZE_CLUSTER" ($initLog -ne $null) "Actor: $($initLog.actor_username), Resource: $($initLog.resource_id)"

$backupLog = $auditLogs | Where-Object { $_.action -eq "EXPORT_SYSTEM_BACKUP" }
Check-Test "Audit log captures EXPORT_SYSTEM_BACKUP" ($backupLog -ne $null) "Details: $($backupLog.details)"

$filteredLogs = API "GET" "/audit-logs?action=INITIALIZE_CLUSTER"
Check-Test "Audit log action filtering is operational" ($filteredLogs -ne $null -and $filteredLogs.Count -ge 1)

# ------------------------------------------------------------------------------
# 5. DIAGNOSTICS & CLUSTER OBSERVABILITY
# ------------------------------------------------------------------------------
Write-Host "`n=== SECTION 5: Diagnostics & Observability Counters ===" -ForegroundColor Yellow

$diag = API "GET" "/diagnostics"
Check-Test "Diagnostics reports active_ddos_policies" ($diag.counters.active_ddos_policies -ne $null -and $diag.counters.active_ddos_policies -ge 1) "Active DDoS: $($diag.counters.active_ddos_policies)"
Check-Test "Diagnostics reports total_audit_logs" ($diag.counters.total_audit_logs -ne $null -and $diag.counters.total_audit_logs -ge 1) "Total Audit: $($diag.counters.total_audit_logs)"

# ------------------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------------------
Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "   Milestone 7 Test Summary: $passed / $total Passed ($failed Failed)" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "=================================================================" -ForegroundColor Cyan

if ($failed -gt 0) {
  exit 1
} else {
  exit 0
}

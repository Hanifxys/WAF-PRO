# ==============================================================================
# Enterprise WAF Pro SaaS - Milestone 9 Automated Verification Suite
# Pillars: SIGNATURE WORKFLOW (Phase 3) + RESPONSE SECURITY (Phase 14) +
#          MULTI-TENANCY (Phase 27) + CAPACITY INTELLIGENCE (Phase 29)
# ==============================================================================

$baseUrl = "http://localhost:8082/api/v1"
$testsPassed = 0
$testsFailed = 0

function Assert-Condition($testName, $condition, $details = "") {
    if ($condition) {
        Write-Host "  [PASS] $testName" -ForegroundColor Green
        $global:testsPassed++
    } else {
        Write-Host "  [FAIL] $testName" -ForegroundColor Red
        if ($details) {
            Write-Host "         Details: $details" -ForegroundColor Yellow
        }
        $global:testsFailed++
    }
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   WAF PRO ENTERPRISE - MILESTONE 9 AUTOMATED VERIFICATION SUITE       " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# 1. Signature Enterprise Workflow: Application Learning & Auto-Promotion
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 1] Signature Enterprise Workflow: Learning -> Review -> Protect" -ForegroundColor Yellow

# Create test application in LEARNING status
$createAppBody = @{
    name = "Digital Banking Transfer Service"
    domain = "transfers.bank-test.internal"
    backend_url = "http://backend-transfer:8080"
    waf_mode = "MONITOR"
    paranoia_level = 1
    status = "LEARNING"
} | ConvertTo-Json

$createdApp = Invoke-RestMethod -Uri "$baseUrl/applications" -Method POST -Body $createAppBody -ContentType "application/json"
$testAppId = $createdApp.id
Assert-Condition "1.1 Application onboarded in LEARNING mode" ($testAppId -gt 0 -and $createdApp.status -eq "created")

# Step lifecycle to REVIEW
$reviewLifecycleBody = @{ status = "REVIEW" } | ConvertTo-Json
$reviewApp = Invoke-RestMethod -Uri "$baseUrl/applications/$testAppId/lifecycle" -Method PUT -Body $reviewLifecycleBody -ContentType "application/json"
Assert-Condition "1.2 Lifecycle stepped to REVIEW" ($reviewApp.status -eq "REVIEW")

# Register discovered API endpoint during learning
$apiEndpointBody = @{
    app_id = $testAppId
    method = "POST"
    path_pattern = "/api/v2/transfers/wire"
    avg_latency_ms = 35
} | ConvertTo-Json

$discoveredApi = Invoke-RestMethod -Uri "$baseUrl/api-inventory" -Method POST -Body $apiEndpointBody -ContentType "application/json"
Assert-Condition "1.3 Discovered API registered during learning" ($discoveredApi.status -eq "saved")

# Execute Signature Promotion
$promoteBody = @{
    target_status = "PROTECTED"
    auto_approve_discovered_apis = $true
} | ConvertTo-Json

$promoteRes = Invoke-RestMethod -Uri "$baseUrl/applications/$testAppId/promote-learning" -Method POST -Body $promoteBody -ContentType "application/json"
Assert-Condition "1.4 Signature promotion executed" ($promoteRes.status -eq "promoted")
Assert-Condition "1.5 Application state transitioned to PROTECTED" ($promoteRes.new_state -eq "PROTECTED")
Assert-Condition "1.6 Application WAF mode set to BLOCK" ($promoteRes.waf_mode -eq "BLOCK")
Assert-Condition "1.7 Discovered APIs automatically approved" ($promoteRes.newly_approved_endpoints -ge 1)
Assert-Condition "1.8 Paranoia level stepped up for protection" ($promoteRes.paranoia_level -ge 2)

# ------------------------------------------------------------------------------
# 2. Application Security Response Headers (Phase 14)
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 2] HTTP Security Response Headers Engine" -ForegroundColor Yellow

$headers = Invoke-RestMethod -Uri "$baseUrl/applications/$testAppId/security-headers" -Method GET
Assert-Condition "2.1 Security headers retrieved" ($headers.hsts_enabled -eq $true -and $headers.nosniff -eq $true)

# Update security headers
$updateHeadersBody = @{
    hsts_enabled = $true
    nosniff = $true
    frame_options = "DENY"
    csp = "default-src 'self'; script-src 'self' 'nonce-waf'"
    referrer_policy = "strict-origin-when-cross-origin"
} | ConvertTo-Json

$updatedHeaders = Invoke-RestMethod -Uri "$baseUrl/applications/$testAppId/security-headers" -Method PUT -Body $updateHeadersBody -ContentType "application/json"
Assert-Condition "2.2 Security headers updated with strict frame_options=DENY" ($updatedHeaders.frame_options -eq "DENY")
Assert-Condition "2.3 Custom Content-Security-Policy applied" ($updatedHeaders.csp -match "nonce-waf")

# ------------------------------------------------------------------------------
# 3. Multi-Tenant Isolation & Quota Management (Phase 27)
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 3] Multi-Tenant Isolation & Quotas" -ForegroundColor Yellow

$tenants = Invoke-RestMethod -Uri "$baseUrl/tenants" -Method GET
Assert-Condition "3.1 Seeded enterprise tenants retrieved" ($tenants.Count -ge 2) "Tenants: $($tenants.Count)"

$seededCore = $tenants | Where-Object { $_.slug -eq "telkomsel-core" }
Assert-Condition "3.2 Telkomsel Enterprise Core tenant active" ($seededCore -ne $null -and $seededCore.plan_tier -eq "ENTERPRISE")

# Provision new tenant
$tenantSlug = "ecomm-cloud-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
$createTenantBody = @{
    name = "E-Commerce Cloud Division"
    slug = $tenantSlug
    plan_tier = "ENTERPRISE"
    max_applications = 30
    max_rps = 15000
    status = "ACTIVE"
} | ConvertTo-Json

$createdTenant = Invoke-RestMethod -Uri "$baseUrl/tenants" -Method POST -Body $createTenantBody -ContentType "application/json"
$createdTenantId = $createdTenant.id
Assert-Condition "3.3 Provisioned new enterprise tenant partition" ($createdTenantId -gt 0 -and $createdTenant.slug -eq $tenantSlug)

# Query tenant usage & quota analysis
$usage = Invoke-RestMethod -Uri "$baseUrl/tenants/$createdTenantId/usage" -Method GET
Assert-Condition "3.4 Tenant usage analysis calculates quota headroom" ($usage.rps_headroom_pct -gt 0) "Headroom: $($usage.rps_headroom_pct)%"
Assert-Condition "3.5 Tenant plan tier matched" ($usage.plan_tier -eq "ENTERPRISE")

# ------------------------------------------------------------------------------
# 4. Performance & Capacity Management Engine (Phase 29)
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 4] Performance, Capacity & Headroom Telemetry" -ForegroundColor Yellow

$capacity = Invoke-RestMethod -Uri "$baseUrl/capacity/metrics" -Method GET
Assert-Condition "4.1 Retrieved cluster capacity ceiling" ($capacity.cluster_max_rps -ge 1000) "Max RPS: $($capacity.cluster_max_rps)"
Assert-Condition "4.2 Real-time cluster headroom estimated" ($capacity.estimated_headroom_pct -gt 0) "Headroom: $($capacity.estimated_headroom_pct)%"
Assert-Condition "4.3 Coraza WAF latency p50 reported" ($capacity.waf_latency_p50_us -gt 0) "p50: $($capacity.waf_latency_p50_us) us"
Assert-Condition "4.4 Coraza WAF latency p95 reported" ($capacity.waf_latency_p95_us -gt 0) "p95: $($capacity.waf_latency_p95_us) us"
Assert-Condition "4.5 Coraza WAF latency p99 reported" ($capacity.waf_latency_p99_us -gt 0) "p99: $($capacity.waf_latency_p99_us) us"
Assert-Condition "4.6 Upstream origin latency telemetry reported" ($capacity.upstream_latency_avg_ms -gt 0) "Origin: $($capacity.upstream_latency_avg_ms) ms"

# ------------------------------------------------------------------------------
# 5. Disaster Recovery Backup & Restore with Tenants
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 5] Disaster Recovery with Multi-Tenant Schemas" -ForegroundColor Yellow

$backupBundle = Invoke-RestMethod -Uri "$baseUrl/system/backup" -Method GET
Assert-Condition "5.1 Backup export includes tenants" ($backupBundle.tenants.Count -ge 2) "Tenants count: $($backupBundle.tenants.Count)"

$restoreBody = $backupBundle | ConvertTo-Json -Depth 10
$restoreRes = Invoke-RestMethod -Uri "$baseUrl/system/restore" -Method POST -Body $restoreBody -ContentType "application/json"
Assert-Condition "5.2 System restore processed with tenants table" ($restoreRes.status -eq "restored")
Assert-Condition "5.3 Restored tables list includes tenants" ($restoreRes.restored_tables -contains "tenants")

# ------------------------------------------------------------------------------
# 6. Governance Audit Trail
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 6] Governance Audit Trail Verification" -ForegroundColor Yellow

$auditLogs = Invoke-RestMethod -Uri "$baseUrl/audit-logs" -Method GET
$promoteAudit = $auditLogs | Where-Object { $_.action -eq "PROMOTE_APPLICATION_LEARNING" }
Assert-Condition "6.1 Audit log recorded PROMOTE_APPLICATION_LEARNING" ($promoteAudit -ne $null)

$headerAudit = $auditLogs | Where-Object { $_.action -eq "UPDATE_SECURITY_HEADERS" }
Assert-Condition "6.2 Audit log recorded UPDATE_SECURITY_HEADERS" ($headerAudit -ne $null)

$tenantAudit = $auditLogs | Where-Object { $_.action -eq "CREATE_TENANT" }
Assert-Condition "6.3 Audit log recorded CREATE_TENANT" ($tenantAudit -ne $null)

# ------------------------------------------------------------------------------
# 7. System Diagnostics Counters
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 7] System Diagnostics Milestone 9 Counters" -ForegroundColor Yellow

$diag = Invoke-RestMethod -Uri "$baseUrl/diagnostics" -Method GET
Assert-Condition "7.1 Diagnostics active_tenants counter" ($diag.counters.active_tenants -ge 2) "Val: $($diag.counters.active_tenants)"

# Cleanup test application and tenant
Invoke-RestMethod -Uri "$baseUrl/applications/$testAppId" -Method DELETE | Out-Null
if ($createdTenantId) {
    Invoke-RestMethod -Uri "$baseUrl/tenants/$createdTenantId" -Method DELETE | Out-Null
}

# ------------------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------------------
$summaryColor = "Green"
if ($testsFailed -gt 0) { $summaryColor = "Red" }
Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "   MILESTONE 9 TEST SUMMARY: PASSED: $testsPassed | FAILED: $testsFailed" -ForegroundColor $summaryColor
Write-Host "======================================================================" -ForegroundColor Cyan

if ($testsFailed -gt 0) {
    exit 1
}
exit 0

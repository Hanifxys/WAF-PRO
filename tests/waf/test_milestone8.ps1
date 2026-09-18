# ==============================================================================
# Enterprise WAF Pro SaaS - Milestone 8 Automated Verification Suite
# Pillar: ADVANCED PROTOCOL & CREDENTIAL ABUSE (Phase 13) + HA CLUSTER TOPOLOGY (Phase 24)
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
Write-Host "   WAF PRO ENTERPRISE - MILESTONE 8 AUTOMATED VERIFICATION SUITE       " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# 1. HTTP Protocol Enforcement Policies
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 1] Advanced HTTP Protocol Enforcement Policies" -ForegroundColor Yellow

$protoList = Invoke-RestMethod -Uri "$baseUrl/protocol-policies" -Method GET
Assert-Condition "1.1 Seeded protocol policies retrieved" ($protoList.Count -ge 2) "Count: $($protoList.Count)"

$seededMethodPolicy = $protoList | Where-Object { $_.policy_type -eq "METHOD_ENFORCEMENT" }
Assert-Condition "1.2 Method enforcement policy exists" ($seededMethodPolicy -ne $null -and $seededMethodPolicy.disallowed_methods -match "TRACE")

# Create custom protocol policy
$createProtoBody = @{
    name = "Zero-Trust REST Verb Boundary"
    policy_type = "METHOD_ENFORCEMENT"
    disallowed_methods = "PUT, PATCH, DELETE"
    max_headers_count = 50
    max_header_size_bytes = 8192
    action = "BLOCK"
    is_enabled = $true
} | ConvertTo-Json

$createdProto = Invoke-RestMethod -Uri "$baseUrl/protocol-policies" -Method POST -Body $createProtoBody -ContentType "application/json"
$createdProtoId = $createdProto.id
Assert-Condition "1.3 Created custom protocol policy" ($createdProtoId -gt 0 -and $createdProto.name -eq "Zero-Trust REST Verb Boundary")

# Toggle protocol policy
$toggledProto = Invoke-RestMethod -Uri "$baseUrl/protocol-policies/$createdProtoId/toggle" -Method PUT
Assert-Condition "1.4 Toggled protocol policy to disabled" ($toggledProto.is_enabled -eq $false)

$toggledProto2 = Invoke-RestMethod -Uri "$baseUrl/protocol-policies/$createdProtoId/toggle" -Method PUT
Assert-Condition "1.5 Re-enabled protocol policy" ($toggledProto2.is_enabled -eq $true)

# Delete protocol policy
$deleteProtoRes = Invoke-RestMethod -Uri "$baseUrl/protocol-policies/$createdProtoId" -Method DELETE
Assert-Condition "1.6 Deleted protocol policy" ($deleteProtoRes.status -eq "deleted")

# ------------------------------------------------------------------------------
# 2. Credential Abuse & Brute-Force Shield
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 2] Credential Stuffing & Brute-Force Shield" -ForegroundColor Yellow

$abuseList = Invoke-RestMethod -Uri "$baseUrl/abuse-policies" -Method GET
Assert-Condition "2.1 Seeded credential abuse policies retrieved" ($abuseList.Count -ge 2) "Count: $($abuseList.Count)"

$seededAbuse = $abuseList | Where-Object { $_.login_path -eq "/api/login" }
Assert-Condition "2.2 Portal login brute-force policy configured" ($seededAbuse -ne $null -and $seededAbuse.max_failed_attempts -eq 5)

# Create custom credential abuse policy
$createAbuseBody = @{
    name = "Admin Privileged Console Anti-Brute"
    login_path = "/admin/authenticate"
    max_failed_attempts = 3
    observation_window_seconds = 180
    action = "BLOCK"
    is_enabled = $true
} | ConvertTo-Json

$createdAbuse = Invoke-RestMethod -Uri "$baseUrl/abuse-policies" -Method POST -Body $createAbuseBody -ContentType "application/json"
$createdAbuseId = $createdAbuse.id
Assert-Condition "2.3 Created privileged credential abuse policy" ($createdAbuseId -gt 0 -and $createdAbuse.max_failed_attempts -eq 3)

# Delete credential abuse policy
$deleteAbuseRes = Invoke-RestMethod -Uri "$baseUrl/abuse-policies/$createdAbuseId" -Method DELETE
Assert-Condition "2.4 Deleted credential abuse policy" ($deleteAbuseRes.status -eq "deleted")

# ------------------------------------------------------------------------------
# 3. High Availability & Distributed Cluster Node Topology
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 3] HA Distributed Data Plane Node Topology" -ForegroundColor Yellow

$clusterData = Invoke-RestMethod -Uri "$baseUrl/cluster/nodes" -Method GET
Assert-Condition "3.1 Retrieved cluster node topology" ($clusterData.total_nodes -ge 2) "Nodes: $($clusterData.total_nodes)"
Assert-Condition "3.2 Cluster healthy quorum maintained" ($clusterData.healthy_nodes -ge 2) "Healthy: $($clusterData.healthy_nodes)"
Assert-Condition "3.3 Active xDS version reported" ($clusterData.active_xds_version -ne "") "xDS Version: $($clusterData.active_xds_version)"

# Register new edge node heartbeat
$heartbeatBody = @{
    node_id = "node-envoy-replica-02"
    hostname = "edge-gw-03.internal"
    ip_address = "10.0.1.12"
    role = "EDGE_REPLICA"
    status = "HEALTHY"
    current_rps = 340
    active_connections = 68
} | ConvertTo-Json

$hbRes = Invoke-RestMethod -Uri "$baseUrl/cluster/nodes/heartbeat" -Method POST -Body $heartbeatBody -ContentType "application/json"
Assert-Condition "3.4 Node heartbeat acknowledged" ($hbRes.status -eq "acknowledged" -and $hbRes.node_id -eq "node-envoy-replica-02")
Assert-Condition "3.5 Node synchronized with active xDS version" ($hbRes.synced -eq $true)

# Graceful Traffic Drain on node-envoy-replica-02
$drainRes = Invoke-RestMethod -Uri "$baseUrl/cluster/nodes/node-envoy-replica-02/drain" -Method POST
Assert-Condition "3.6 Graceful node drain initiated" ($drainRes.status -eq "DRAINING" -and $drainRes.node_id -eq "node-envoy-replica-02")

# Verify node topology reflects draining status
$clusterDataAfterDrain = Invoke-RestMethod -Uri "$baseUrl/cluster/nodes" -Method GET
Assert-Condition "3.7 Cluster topology tracks draining node" ($clusterDataAfterDrain.draining_nodes -ge 1) "Draining count: $($clusterDataAfterDrain.draining_nodes)"

# ------------------------------------------------------------------------------
# 4. Disaster Recovery Backup & Restore with Protocol & Abuse Policies
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 4] Disaster Recovery Backup/Restore with Milestone 8 Schemas" -ForegroundColor Yellow

$backupBundle = Invoke-RestMethod -Uri "$baseUrl/system/backup" -Method GET
Assert-Condition "4.1 Backup export includes protocol policies" ($backupBundle.protocol_policies.Count -ge 2) "Protocol policies: $($backupBundle.protocol_policies.Count)"
Assert-Condition "4.2 Backup export includes abuse policies" ($backupBundle.abuse_policies.Count -ge 2) "Abuse policies: $($backupBundle.abuse_policies.Count)"
Assert-Condition "4.3 Backup export includes cluster nodes" ($backupBundle.cluster_nodes.Count -ge 2) "Cluster nodes: $($backupBundle.cluster_nodes.Count)"

$restoreBody = $backupBundle | ConvertTo-Json -Depth 10
$restoreRes = Invoke-RestMethod -Uri "$baseUrl/system/restore" -Method POST -Body $restoreBody -ContentType "application/json"
Assert-Condition "4.4 System restore processed with Milestone 8 tables" ($restoreRes.status -eq "restored")

# ------------------------------------------------------------------------------
# 5. Governance Audit Trail Verification
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 5] Governance Audit Trail Recording" -ForegroundColor Yellow

$auditLogs = Invoke-RestMethod -Uri "$baseUrl/audit-logs" -Method GET
$protoAudit = $auditLogs | Where-Object { $_.action -eq "CREATE_PROTOCOL_POLICY" }
Assert-Condition "5.1 Audit log recorded protocol policy creation" ($protoAudit -ne $null)

$drainAudit = $auditLogs | Where-Object { $_.action -eq "DRAIN_CLUSTER_NODE" }
Assert-Condition "5.2 Audit log recorded cluster node drain" ($drainAudit -ne $null)

# ------------------------------------------------------------------------------
# 6. System Diagnostics Counter Validation
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 6] System Diagnostics Milestone 8 Counters" -ForegroundColor Yellow

$diag = Invoke-RestMethod -Uri "$baseUrl/diagnostics" -Method GET
Assert-Condition "6.1 Diagnostics active_protocol_policies counter" ($diag.counters.active_protocol_policies -ge 2) "Val: $($diag.counters.active_protocol_policies)"
Assert-Condition "6.2 Diagnostics active_abuse_policies counter" ($diag.counters.active_abuse_policies -ge 2) "Val: $($diag.counters.active_abuse_policies)"
Assert-Condition "6.3 Diagnostics active_cluster_nodes counter" ($diag.counters.active_cluster_nodes -ge 2) "Val: $($diag.counters.active_cluster_nodes)"

# ------------------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------------------
$summaryColor = "Green"
if ($testsFailed -gt 0) { $summaryColor = "Red" }
Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "   MILESTONE 8 TEST SUMMARY: PASSED: $testsPassed | FAILED: $testsFailed" -ForegroundColor $summaryColor
Write-Host "======================================================================" -ForegroundColor Cyan

if ($testsFailed -gt 0) {
    exit 1
}
exit 0

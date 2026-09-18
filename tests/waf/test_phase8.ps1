# Phase 8 Verification Test Suite: Analytics & System Diagnostics Engine
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " [PHASE 8] TESTING ANALYTICS ENGINE & SYSTEM DIAGNOSTICS" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$Passed = 0
$Failed = 0

function Assert-Check {
    param(
        [string]$Name,
        [bool]$Condition,
        [string]$Details = ""
    )
    if ($Condition) {
        Write-Host "  [PASS] $Name" -ForegroundColor Green
        if ($Details) { Write-Host "         $Details" -ForegroundColor DarkGray }
        $script:Passed++
    } else {
        Write-Host "  [FAIL] $Name" -ForegroundColor Red
        if ($Details) { Write-Host "         Detail: $Details" -ForegroundColor Yellow }
        $script:Failed++
    }
}

# 1. Analytics Summary Contract & Metrics
try {
    $analytics = Invoke-RestMethod -Uri "http://127.0.0.1:8082/api/v1/analytics/summary" -Method GET
    Assert-Check "Analytics summary endpoint returns HTTP 200" ($null -ne $analytics)
    Assert-Check "Analytics contains total_events counter" ($analytics.total_events -ge 0) ("total_events=" + $analytics.total_events)
    Assert-Check "Analytics contains block_rate percentage" ($analytics.block_rate -ge 0 -and $analytics.block_rate -le 100) ("block_rate=" + $analytics.block_rate + "%")
    Assert-Check "Analytics contains top_attacking_ips array" ($null -ne $analytics.top_attacking_ips) ("top_ips count=" + $analytics.top_attacking_ips.Count)
    Assert-Check "Analytics categorizes attack_types dictionary" ($null -ne $analytics.attack_types)
    Assert-Check "Analytics categorizes severity_split dictionary" ($null -ne $analytics.severity_split)
} catch {
    Assert-Check "Analytics summary endpoint call failed" $false $_.Exception.Message
}

# 2. System Diagnostics Engine
try {
    $diag = Invoke-RestMethod -Uri "http://127.0.0.1:8082/api/v1/diagnostics" -Method GET
    Assert-Check "Diagnostics endpoint returns status=healthy" ($diag.status -eq "healthy")
    Assert-Check "Diagnostics reports Data Plane proxy & WASM runtime" ($diag.cluster.data_plane.proxy -like "*Envoy*" -and $diag.cluster.data_plane.waf_runtime -like "*Coraza*")
    Assert-Check "Diagnostics reports Control Plane xDS gRPC port 18000" ($diag.cluster.control_plane.xds_grpc_port -eq 18000)
    Assert-Check "Diagnostics reports Database PostgreSQL healthy" ($diag.cluster.database.healthy -eq $true)
    Assert-Check "Diagnostics reports Telemetry Vector agent status" ($diag.cluster.telemetry.status -eq "INGESTING")
    Assert-Check "Diagnostics reports active entities counters" ($null -ne $diag.counters.protected_applications)
} catch {
    Assert-Check "Diagnostics endpoint call failed" $false $_.Exception.Message
}

# 3. Next.js Dashboard UI HTTP Response Verification
$uiPort = 3000
try {
    $null = Invoke-WebRequest -Uri "http://127.0.0.1:3000/" -Method GET -UseBasicParsing -TimeoutSec 1
    $uiPort = 3000
} catch {
    $uiPort = 3050
}

try {
    $dashRes = Invoke-WebRequest -Uri "http://127.0.0.1:$uiPort/" -Method GET -UseBasicParsing
    Assert-Check "Next.js Root Dashboard UI responds with HTTP 200" ($dashRes.StatusCode -eq 200)
} catch {
    Assert-Check "Next.js Root Dashboard UI response" $false $_.Exception.Message
}

try {
    $settingsRes = Invoke-WebRequest -Uri "http://127.0.0.1:$uiPort/settings" -Method GET -UseBasicParsing
    Assert-Check "Next.js /settings page responds with HTTP 200" ($settingsRes.StatusCode -eq 200)
} catch {
    Assert-Check "Next.js /settings page response" $false $_.Exception.Message
}

$summaryColor = "Green"
if ($Failed -gt 0) { $summaryColor = "Red" }
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " [PHASE 8 SUMMARY] Total Passed: $Passed | Total Failed: $Failed" -ForegroundColor $summaryColor
Write-Host "=================================================================" -ForegroundColor Cyan

if ($Failed -gt 0) {
    exit 1
}

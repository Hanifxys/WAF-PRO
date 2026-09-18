# =================================================================
# [PHASE 11] ENTERPRISE ALERTING & TELKOMSEL RISK ACCEPTANCE TEST SUITE
# =================================================================
$ErrorActionPreference = "Continue"

$MgmtHost = "http://127.0.0.1:8082"
$TargetHost = "http://127.0.0.1:8080"
$UIHost = "http://127.0.0.1:3050"

$Passed = 0
$Failed = 0

function Assert-Check {
    param(
        [string]$TestName,
        [bool]$Condition,
        [string]$Details = ""
    )
    if ($Condition) {
        Write-Host "  [PASS] $TestName" -ForegroundColor Green
        if ($Details) { Write-Host "         $Details" -ForegroundColor DarkGray }
        $script:Passed++
    } else {
        Write-Host "  [FAIL] $TestName" -ForegroundColor Red
        if ($Details) { Write-Host "         Details: $Details" -ForegroundColor Yellow }
        $script:Failed++
    }
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " [PHASE 11] TESTING ENTERPRISE ALERTING & TELKOMSEL RISK ACCEPTANCE" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# -------------------------------------------------------------
# 1. Notification Settings Management (CRUD)
# -------------------------------------------------------------
Write-Host ""
Write-Host "--- 1. Notification Settings & SMTP Gateway Management ---" -ForegroundColor Yellow

try {
    # 1.1 Fetch current settings
    $settings = Invoke-RestMethod -Uri "$MgmtHost/api/v1/notification-settings" -Method GET
    Assert-Check "Retrieve default notification settings" ($settings.sender_email -eq "csop-it-waf@telkomsel.co.id") ("Sender: " + $settings.sender_email)

    # 1.2 Update notification settings
    $updateBody = @{
        smtp_host = "smtp.internal.corp"
        smtp_port = 587
        smtp_user = "itsecops_service"
        sender_email = "csop-it-waf@telkomsel.co.id"
        default_recipient = "tower-app-lead@telkomsel.co.id"
        default_cc = "CSOP-L, CSOP-IT-WAF-L, MO ITSecOps Network, NetSecPlat-L"
        min_severity = "HIGH"
        enabled = $true
    } | ConvertTo-Json

    $updateRes = Invoke-RestMethod -Uri "$MgmtHost/api/v1/notification-settings" -Method PUT -ContentType "application/json" -Body $updateBody
    Assert-Check "Update notification settings via REST" ($updateRes.status -eq "updated")

} catch {
    Assert-Check "Notification Settings Execution" $false $_.Exception.Message
}

# -------------------------------------------------------------
# 2. Security Event Ingestion & Reference Selection
# -------------------------------------------------------------
Write-Host ""
Write-Host "--- 2. Trigger Violation & Security Event Acquisition ---" -ForegroundColor Yellow

$refEventID = 0
try {
    # Trigger an attack to ensure we have fresh security event
    try {
        $null = Invoke-WebRequest -Uri "$TargetHost/api/program-service/post?input=SELECT%20*%20FROM%20users%20WHERE%201=1" -Method GET -UseBasicParsing -ErrorAction SilentlyContinue -TimeoutSec 3
    } catch {}

    Start-Sleep -Milliseconds 1500

    $events = Invoke-RestMethod -Uri "$MgmtHost/api/v1/events" -Method GET
    Assert-Check "Events endpoint returns ingested security incidents" ($events.Count -gt 0) ("Total events: " + $events.Count)
    $refEventID = $events[0].id
    Assert-Check "Acquired incident event reference ID" ($refEventID -gt 0) ("Event ID: " + $refEventID)

} catch {
    Assert-Check "Event Acquisition" $false $_.Exception.Message
}

# -------------------------------------------------------------
# 3. Telkomsel CSOP-IT-WAF Risk Acceptance Dispatcher
# -------------------------------------------------------------
Write-Host ""
Write-Host "--- 3. Telkomsel CSOP-IT-WAF Risk Acceptance Email Generation ---" -ForegroundColor Yellow

try {
    $riskBody = @{
        event_id = "$refEventID"
        crq_number = "CRQ000000858920"
        rlm_number = "RLM000000413504"
        app_name = "RMS AJAKTEMAN"
        policy_name = "WAF_RMS_AJAKTEMAN"
        recipient = "Budi_Satrio <budi_satrio@telkomsel.co.id>"
        cc = "CSOP-L, CSOP-IT-WAF-L, MO ITSecOps Network <mo_itsecops_network@metrocom.co.id>, NetSecPlat-L"
        reason = "Activity Enable Full Blocking RMS AJAKTEMAN"
        send_email = $true
    } | ConvertTo-Json

    $riskRes = Invoke-RestMethod -Uri "$MgmtHost/api/v1/alerts/risk-acceptance" -Method POST -ContentType "application/json" -Body $riskBody

    # 3.1 Verify status & delivery
    Assert-Check "Dispatch Telkomsel Risk Acceptance request" ($riskRes.status -eq "success")
    Assert-Check "Email dispatched via production-safe mock delivery" ($riskRes.delivery_mode -eq "DELIVERED_MOCK" -or $riskRes.delivery_mode -eq "SENT_SMTP")

    # 3.2 Verify Subject Line
    $expectedSubject = "Risk Acceptance Allow Specific Attack Signature in Specific Parameter Apps RMS AJAKTEMAN"
    Assert-Check "Email Subject strictly matches Telkomsel enterprise standard" ($riskRes.subject -eq $expectedSubject) ("Subject: " + $riskRes.subject)

    # 3.3 Verify Telkomsel CSOP body clauses
    $body = $riskRes.body
    $hasCRQ = $body -match "CRQ000000858920 - RLM000000413504"
    $hasPolicy = $body -match "Policy: WAF_RMS_AJAKTEMAN"
    $hasURI = $body -match "URI: "
    $hasSigID = $body -match "Sig ID: "
    $hasAction = $body -match "Action: Allow Specific Attack Signature in Specific Parameter in URL"
    $has3DaySLA = $body -match "3 hari kerja"

    Assert-Check "Email Body contains CRQ and RLM tracking numbers" $hasCRQ
    Assert-Check "Email Body contains Policy & URI signature context" ($hasPolicy -and $hasURI -and $hasSigID)
    Assert-Check "Email Body contains Telkomsel 3-day SLA risk acceptance clause" ($hasAction -and $has3DaySLA)

} catch {
    Assert-Check "Risk Acceptance Dispatch Execution" $false $_.Exception.Message
}

# -------------------------------------------------------------
# 4. Audit Log Persistence Check
# -------------------------------------------------------------
Write-Host ""
Write-Host "--- 4. Sent Alerts Database Audit Log Verification ---" -ForegroundColor Yellow

try {
    $logs = Invoke-RestMethod -Uri "$MgmtHost/api/v1/alerts/logs" -Method GET
    Assert-Check "Audit log contains dispatched alerts" ($logs.Count -gt 0) ("Logged alerts: " + $logs.Count)

    $latest = $logs[0]
    Assert-Check "Audit log records email type TELKOMSEL_RISK_ACCEPTANCE" ($latest.email_type -eq "TELKOMSEL_RISK_ACCEPTANCE")
    Assert-Check "Audit log records CRQ number" ($latest.crq_number -eq "CRQ000000858920")

} catch {
    Assert-Check "Alert Log Verification" $false $_.Exception.Message
}

# -------------------------------------------------------------
# 5. Direct Test Email Alert Dispatcher
# -------------------------------------------------------------
Write-Host ""
Write-Host "--- 5. Direct Alert Dispatcher Test ---" -ForegroundColor Yellow

try {
    $testBody = @{
        recipient = "soc-oncall@telkomsel.co.id"
        subject = "[SEV-1] Critical Violation Detected on VS_RMS_AJAKTEMAN"
        message = "Coraza WASM intercepted anomalous command injection attempt."
    } | ConvertTo-Json

    $testRes = Invoke-RestMethod -Uri "$MgmtHost/api/v1/alerts/test-email" -Method POST -ContentType "application/json" -Body $testBody
    Assert-Check "Dispatch ad-hoc security incident alert" ($testRes.status -eq "dispatched")

} catch {
    Assert-Check "Direct Alert Dispatch Execution" $false $_.Exception.Message
}

# -------------------------------------------------------------
# 6. Enterprise Diagnostics Integration
# -------------------------------------------------------------
Write-Host ""
Write-Host "--- 6. Diagnostics Telemetry Verification ---" -ForegroundColor Yellow

try {
    $diag = Invoke-RestMethod -Uri "$MgmtHost/api/v1/diagnostics" -Method GET
    Assert-Check "Diagnostics reflects notifications cluster status" ($diag.cluster.notifications.status -eq "ONLINE")
    Assert-Check "Diagnostics tracks total_alerts_sent counter" ($diag.counters.total_alerts_sent -ge 1) ("total_alerts_sent: " + $diag.counters.total_alerts_sent)

} catch {
    Assert-Check "Diagnostics Check" $false $_.Exception.Message
}

# -------------------------------------------------------------
# 7. Frontend Dashboard UI Verification
# -------------------------------------------------------------
Write-Host ""
Write-Host "--- 7. Frontend Dashboard UI Health ---" -ForegroundColor Yellow

try {
    $resEvents = Invoke-WebRequest -Uri "$UIHost/events" -Method GET -UseBasicParsing -TimeoutSec 5
    Assert-Check "Next.js Security Events & F5 ASM Inspector page responds with HTTP 200" ($resEvents.StatusCode -eq 200)

    $resSettings = Invoke-WebRequest -Uri "$UIHost/settings" -Method GET -UseBasicParsing -TimeoutSec 5
    Assert-Check "Next.js System Settings page responds with HTTP 200" ($resSettings.StatusCode -eq 200)

} catch {
    Assert-Check "Frontend UI Verification" $false $_.Exception.Message
}

$summaryColor = "Green"
if ($Failed -gt 0) { $summaryColor = "Red" }
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " [PHASE 11 SUMMARY] Total Passed: $Passed | Total Failed: $Failed" -ForegroundColor $summaryColor
Write-Host "=================================================================" -ForegroundColor Cyan

if ($Failed -gt 0) {
    exit 1
}

# Phase 10 Verification Test Suite: Top-of-Power Enterprise Suite
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " [PHASE 10] TESTING TOP-OF-POWER ENTERPRISE WAF SUITE" -ForegroundColor Cyan
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

$TargetHost = "http://127.0.0.1:8080"
$MgmtHost   = "http://127.0.0.1:8082"

# -------------------------------------------------------------
# 1. Geo-IP Perimeter Fencing Verification
# -------------------------------------------------------------
Write-Host ""
Write-Host "--- 1. Perimeter Geo-IP Fencing Enforcement ---" -ForegroundColor Yellow

$geoID = 0
try {
    # 1.1 Create Geo-IP Fence for "KP" (North Korea)
    $geoBody = @{
        country_code = "KP"
        policy_action = "BLOCK"
        reason = "Enterprise Sanctioned Territory Block"
    } | ConvertTo-Json

    $geoRes = Invoke-RestMethod -Uri "$MgmtHost/api/v1/geo-policies" -Method POST -ContentType "application/json" -Body $geoBody
    $geoID = $geoRes.id
    Assert-Check "Create Geo-IP block policy for country 'KP' via REST" ($geoRes.status -eq "created" -and $geoID -gt 0)

    Start-Sleep -Milliseconds 1500

    # 1.2 Normal traffic without header should pass (200 OK)
    $normalStatus = 0
    try {
        $res = Invoke-WebRequest -Uri "$TargetHost/api/search?q=normal" -Method GET -UseBasicParsing -ErrorAction Stop -TimeoutSec 3
        $normalStatus = $res.StatusCode
    } catch {
        if ($_.Exception.Response) { $normalStatus = [int]$_.Exception.Response.StatusCode }
    }
    Assert-Check "Domestic / Unfenced Traffic passes (HTTP 200)" ($normalStatus -eq 200)

    # 1.3 Fenced country traffic must be blocked (HTTP 403) with convergence check
    $geoBlockedStatus = 0
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        try {
            $headers = @{ "CF-IPCountry" = "KP" }
            $res = Invoke-WebRequest -Uri "$TargetHost/api/search?q=normal" -Headers $headers -Method GET -UseBasicParsing -ErrorAction Stop -TimeoutSec 3
            $geoBlockedStatus = $res.StatusCode
        } catch {
            if ($_.Exception.Response) { $geoBlockedStatus = [int]$_.Exception.Response.StatusCode }
        }
        if ($geoBlockedStatus -eq 403) { break }
        Start-Sleep -Seconds 1
    }
    Assert-Check "Fenced Geo-IP Country (KP) instantly rejected at Phase 1 (HTTP $geoBlockedStatus)" ($geoBlockedStatus -eq 403)

    # Clean up Geo policy
    $delGeo = Invoke-RestMethod -Uri "$MgmtHost/api/v1/geo-policies/$geoID" -Method DELETE
    Assert-Check "Cleanup Geo-IP Policy via REST" ($delGeo.status -eq "deleted")
    Start-Sleep -Seconds 3

} catch {
    Assert-Check "Geo-IP Fencing Test Execution" $false $_.Exception.Message
}

# -------------------------------------------------------------
# 2. Custom SecLang Policy Studio & Zero-Day Virtual Patching
# -------------------------------------------------------------
Write-Host ""
Write-Host "--- 2. Custom SecLang Policy Studio & Virtual Patching ---" -ForegroundColor Yellow

$customRuleID = 100501
$dbCustomID = 0
try {
    # 2.1 Virtual Patch to block zero-day attacker tool "recon-bot-x"
    $customBody = @{
        rule_id = $customRuleID
        name = "Zero-Day Virtual Patch: Anti Recon-Bot-X"
        description = "Instant virtual patch pushed via xDS without Envoy reload"
        seclang_code = "SecRule REQUEST_HEADERS:User-Agent ""@rx (?i)recon-bot-x"" ""id:$customRuleID,phase:1,deny,status:403,msg:'Virtual Patch: Recon-Bot-X Denied'"""
    } | ConvertTo-Json

    $custRes = Invoke-RestMethod -Uri "$MgmtHost/api/v1/custom-rules" -Method POST -ContentType "application/json" -Body $customBody
    $dbCustomID = $custRes.id
    Assert-Check "Deploy Zero-Day Virtual Patch via Policy Studio REST" ($custRes.status -eq "created")

    Start-Sleep -Milliseconds 1500

    # 2.2 Verify patch intercepts attacker User-Agent with convergence check
    $botStatus = 0
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        try {
            $res = Invoke-WebRequest -Uri "$TargetHost/api/search?q=normal" -UserAgent "recon-bot-x/v2.1" -Method GET -UseBasicParsing -ErrorAction Stop -TimeoutSec 3
            $botStatus = $res.StatusCode
        } catch {
            if ($_.Exception.Response) { $botStatus = [int]$_.Exception.Response.StatusCode }
        }
        if ($botStatus -eq 403) { break }
        Start-Sleep -Seconds 1
    }
    Assert-Check "Zero-day attacker tool immediately blocked by Virtual Patch (HTTP $botStatus)" ($botStatus -eq 403)

    # 2.3 Cleanup custom rule
    $delCust = Invoke-RestMethod -Uri "$MgmtHost/api/v1/custom-rules/$dbCustomID" -Method DELETE
    Assert-Check "Remove Virtual Patch via REST" ($delCust.status -eq "deleted")
    Start-Sleep -Seconds 3

} catch {
    Assert-Check "Custom Rule Studio Test Execution" $false $_.Exception.Message
}

# -------------------------------------------------------------
# 3. Response Body Data Loss Prevention (DLP)
# -------------------------------------------------------------
Write-Host ""
Write-Host "--- 3. Response Body Data Loss Prevention (DLP) ---" -ForegroundColor Yellow

$dlpRuleID = 950001
$dbDLPID = 0
try {
    # 3.1 Deploy PCI-DSS Credit Card Exfiltration Blocker
    $dlpBody = @{
        rule_id = $dlpRuleID
        name = "PCI-DSS Credit Card Exfiltration Blocker"
        data_type = "CREDIT_CARD"
        pattern_regex = "4[0-9]{15}"
        action = "BLOCK"
    } | ConvertTo-Json

    $dlpRes = Invoke-RestMethod -Uri "$MgmtHost/api/v1/dlp-rules" -Method POST -ContentType "application/json" -Body $dlpBody
    $dbDLPID = $dlpRes.id
    Assert-Check "Deploy Outbound DLP Policy for Credit Cards via REST" ($dlpRes.status -eq "created")

    Start-Sleep -Milliseconds 1500

    # 3.2 Clean endpoint without cards must succeed (HTTP 200)
    $cleanStatus = 0
    try {
        $res = Invoke-WebRequest -Uri "$TargetHost/api/search?q=test" -Method GET -UseBasicParsing -ErrorAction Stop -TimeoutSec 3
        $cleanStatus = $res.StatusCode
    } catch {
        if ($_.Exception.Response) { $cleanStatus = [int]$_.Exception.Response.StatusCode }
    }
    Assert-Check "Clean outbound response allowed without DLP trigger (HTTP 200)" ($cleanStatus -eq 200)

    # 3.3 Endpoint leaking credit card data must be intercepted (HTTP 502/403 or sensitive card scrubbed/body replaced by WASM intervention)
    $leakStatus = 0
    $bodyContent = ""
    $cardLeaked = $true
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        try {
            $res = Invoke-WebRequest -Uri "$TargetHost/api/user-data" -Method GET -UseBasicParsing -ErrorAction Stop -TimeoutSec 3
            $leakStatus = $res.StatusCode
            $bodyContent = $res.Content
        } catch {
            if ($_.Exception.Response) { 
                $leakStatus = [int]$_.Exception.Response.StatusCode 
                try {
                    $stream = $_.Exception.Response.GetResponseStream()
                    if ($null -ne $stream) {
                        $reader = New-Object System.IO.StreamReader($stream)
                        $bodyContent = $reader.ReadToEnd()
                    }
                } catch {}
            }
        }
        $cardLeaked = ($bodyContent -match "4532123456789012" -or $bodyContent -match "4532-1234-5678-9012")
        if ($leakStatus -eq 502 -or $leakStatus -eq 403 -or (-not $cardLeaked)) { break }
        Start-Sleep -Seconds 1
    }
    # Coraza WASM interventions either deny with status 502/403 OR replace/scrub the response body
    $dlpProtected = ($leakStatus -eq 502 -or $leakStatus -eq 403 -or (-not $cardLeaked))
    Assert-Check "Outbound Credit Card Leak Intercepted & Blocked by DLP (Status: $leakStatus, Card Leaked: $cardLeaked)" $dlpProtected

    # Cleanup DLP Rule
    $delDLP = Invoke-RestMethod -Uri "$MgmtHost/api/v1/dlp-rules/$dbDLPID" -Method DELETE
    Assert-Check "Cleanup DLP Policy via REST" ($delDLP.status -eq "deleted")
    Start-Sleep -Seconds 3

} catch {
    Assert-Check "DLP Test Execution" $false $_.Exception.Message
}

# -------------------------------------------------------------
# 4. Enterprise Cluster Diagnostics Verification
# -------------------------------------------------------------
Write-Host ""
Write-Host "--- 4. Enterprise Diagnostics Health ---" -ForegroundColor Yellow
try {
    $diag = Invoke-RestMethod -Uri "$MgmtHost/api/v1/diagnostics" -Method GET
    Assert-Check "Diagnostics confirms active_geo_policies field" ($null -ne $diag.counters.active_geo_policies)
    Assert-Check "Diagnostics confirms active_custom_rules field" ($null -ne $diag.counters.active_custom_rules)
    Assert-Check "Diagnostics confirms active_dlp_rules field" ($null -ne $diag.counters.active_dlp_rules)
} catch {
    Assert-Check "Diagnostics verification" $false $_.Exception.Message
}

$summaryColor = "Green"
if ($Failed -gt 0) { $summaryColor = "Red" }
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " [PHASE 10 SUMMARY] Total Passed: $Passed | Total Failed: $Failed" -ForegroundColor $summaryColor
Write-Host "=================================================================" -ForegroundColor Cyan

if ($Failed -gt 0) {
    exit 1
}

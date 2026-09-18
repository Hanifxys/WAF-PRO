param(
    [string]$TargetHost = "http://127.0.0.1:8080",
    [string]$MgmtHost = "http://127.0.0.1:8082"
)

$ErrorActionPreference = "Continue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   ENTERPRISE WAF - PHASE 7 MULTI-APP & EXCEPTION TEST SUITE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Target Envoy Proxy  : $TargetHost"
Write-Host "Management Plane API: $MgmtHost"
Write-Host ""

$testsPassed = 0
$testsFailed = 0

function Assert-WafResult {
    param(
        [string]$TestID,
        [string]$Description,
        [string]$Method = "GET",
        [string]$Path,
        [string]$Body = "",
        [hashtable]$Headers = @{},
        [int]$ExpectedStatus = 403
    )

    Write-Host "[$TestID] $Description... " -NoNewline
    
    $url = "$TargetHost$Path"
    $actualStatus = 0
    try {
        $params = @{
            Uri = $url
            Method = $Method
            UseBasicParsing = $true
            ErrorAction = "SilentlyContinue"
            TimeoutSec = 4
        }
        if ($Headers.Count -gt 0) {
            $params["Headers"] = $Headers
        }
        if ($Body -ne "") {
            $params["Body"] = $Body
            if (-not $Headers.ContainsKey("Content-Type")) {
                $params["ContentType"] = "application/json"
            }
        }

        $res = Invoke-WebRequest @params
        $actualStatus = $res.StatusCode
    } catch {
        if ($_.Exception.Response) {
            $actualStatus = [int]$_.Exception.Response.StatusCode
        } else {
            Write-Host " [ERR: $($_.Exception.Message)] " -ForegroundColor Red -NoNewline
            $actualStatus = -1
        }
    }

    if ($actualStatus -eq $ExpectedStatus) {
        Write-Host "PASS (HTTP $actualStatus)" -ForegroundColor Green
        $script:testsPassed++
    } else {
        Write-Host "FAIL (Expected HTTP $ExpectedStatus, Got HTTP $actualStatus)" -ForegroundColor Red
        $script:testsFailed++
    }
}

# -------------------------------------------------------------
# 1. Application Onboarding & Configuration Test
# -------------------------------------------------------------
Write-Host "--- 1. Application Lifecycle and Onboarding Management ---" -ForegroundColor Yellow

$testAppName = "CRM Production API"
$testDomain = "crm.company.internal"
$testBackend = "http://origin-mock:8081"

try {
    # Create App
    $createAppRes = Invoke-RestMethod -Uri "$MgmtHost/api/v1/applications" -Method POST -ContentType "application/json" `
        -Body (@{
            name = $testAppName
            domain = $testDomain
            backend_url = $testBackend
            waf_mode = "BLOCK"
            paranoia_level = 2
        } | ConvertTo-Json)

    $appId = $createAppRes.id
    if ($appId -gt 0) {
        Write-Host "[APP-01] Onboard new application via REST API... PASS" -ForegroundColor Green
        $testsPassed++
    } else {
        Write-Host "[APP-01] Onboard new application via REST API... FAIL" -ForegroundColor Red
        $testsFailed++
    }

    # Verify App listed
    $appsList = Invoke-RestMethod -Uri "$MgmtHost/api/v1/applications" -Method GET
    $found = $appsList | Where-Object { $_.domain -eq $testDomain }
    if ($found -ne $null) {
        Write-Host "[APP-02] Verify application persisted in PostgreSQL... PASS" -ForegroundColor Green
        $testsPassed++
    } else {
        Write-Host "[APP-02] Verify application persisted in PostgreSQL... FAIL" -ForegroundColor Red
        $testsFailed++
    }

    # Update App Mode
    $updateRes = Invoke-RestMethod -Uri "$MgmtHost/api/v1/applications/$appId" -Method PUT -ContentType "application/json" `
        -Body (@{
            name = $testAppName
            domain = $testDomain
            backend_url = $testBackend
            waf_mode = "MONITOR"
            paranoia_level = 3
        } | ConvertTo-Json)
    if ($updateRes.status -eq "updated") {
        Write-Host "[APP-03] Update WAF Mode to MONITOR... PASS" -ForegroundColor Green
        $testsPassed++
    } else {
        Write-Host "[APP-03] Update WAF Mode to MONITOR... FAIL" -ForegroundColor Red
        $testsFailed++
    }

    # Clean up App
    $delAppRes = Invoke-RestMethod -Uri "$MgmtHost/api/v1/applications/$appId" -Method DELETE
    if ($delAppRes.status -eq "deleted") {
        Write-Host "[APP-04] Delete application entry... PASS" -ForegroundColor Green
        $testsPassed++
    } else {
        Write-Host "[APP-04] Delete application entry... FAIL" -ForegroundColor Red
        $testsFailed++
    }

} catch {
    Write-Host "[APP-ERR] Application management exception: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

Write-Host ""
# -------------------------------------------------------------
# 2. False-Positive Rule Exception / Whitelisting Cycle
# -------------------------------------------------------------
Write-Host "--- 2. False-Positive Rule Tuning and Whitelist Engine ---" -ForegroundColor Yellow

$testPath = "/api/legacy-upload"
$testQuery = "1%27%20OR%20%271%27%3D%271"
$targetRuleID = "942100"

# Step A: Pre-check - Without exception, SQLi on this endpoint must be blocked (HTTP 403)
$fullAttackPath = $testPath + "?q=" + $testQuery
Assert-WafResult -TestID "TUNE-01" -Description "Pre-Check: Attack payload blocked by default" `
    -Method "GET" -Path $fullAttackPath -ExpectedStatus 403

# Step B: Add Rule Exception for Rule 942100 on /api/legacy-upload
$exceptionId = 0
try {
    $excRes = Invoke-RestMethod -Uri "$MgmtHost/api/v1/exceptions" -Method POST -ContentType "application/json" `
        -Body (@{
            target_rule_id = $targetRuleID
            match_path = $testPath
            match_method = "ANY"
            reason = "False positive on legacy schema"
        } | ConvertTo-Json)
    $exceptionId = $excRes.id
    if ($exceptionId -gt 0) {
        Write-Host "[TUNE-02] Create Rule Exception and trigger xDS push... PASS" -ForegroundColor Green
        $testsPassed++
    } else {
        Write-Host "[TUNE-02] Create Rule Exception and trigger xDS push... FAIL" -ForegroundColor Red
        $testsFailed++
    }

    # Give xDS ECDS 1.5 seconds to propagate to Envoy
    Start-Sleep -Milliseconds 1500

    # Step C: Post-check - Payload that triggered Rule 942100 should now be allowed (HTTP 200)
    Assert-WafResult -TestID "TUNE-03" -Description "Post-Check: Whitelisted payload passes through (200 OK)" `
        -Method "GET" -Path $fullAttackPath -ExpectedStatus 200

    # Step D: Verify that OTHER attack vectors (like XSS) on the same path are STILL strictly blocked!
    $xssPath = $testPath + "?q=%3Cscript%3Ealert(1)%3C/script%3E"
    Assert-WafResult -TestID "TUNE-04" -Description "Scope Check: Un-whitelisted attack vectors (XSS) remain blocked" `
        -Method "GET" -Path $xssPath -ExpectedStatus 403

    # Step E: Delete exception and verify protection is instantly restored
    $delExcRes = Invoke-RestMethod -Uri "$MgmtHost/api/v1/exceptions/$exceptionId" -Method DELETE
    if ($delExcRes.status -eq "deleted") {
        Write-Host "[TUNE-05] Delete Rule Exception and restore CRS... PASS" -ForegroundColor Green
        $testsPassed++
    } else {
        Write-Host "[TUNE-05] Delete Rule Exception and restore CRS... FAIL" -ForegroundColor Red
        $testsFailed++
    }

    Start-Sleep -Milliseconds 1500

    # Step F: Revert check - SQLi attack blocked again (HTTP 403)
    Assert-WafResult -TestID "TUNE-06" -Description "Revert Check: SQLi attack immediately blocked again (403)" `
        -Method "GET" -Path $fullAttackPath -ExpectedStatus 403

} catch {
    Write-Host "[TUNE-ERR] Rule tuning exception test failed: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
if ($testsFailed -eq 0) {
    Write-Host "SUMMARY: $testsPassed PASSED | $testsFailed FAILED - ALL PHASE 7 GOALS ACHIEVED" -ForegroundColor Green
} else {
    Write-Host "SUMMARY: $testsPassed PASSED | $testsFailed FAILED" -ForegroundColor Red
}
Write-Host "============================================================" -ForegroundColor Cyan

if ($testsFailed -gt 0) {
    exit 1
}

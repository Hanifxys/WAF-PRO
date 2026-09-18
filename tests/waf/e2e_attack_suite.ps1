param(
    [string]$TargetHost = "http://127.0.0.1:8080",
    [string]$MgmtHost = "http://127.0.0.1:8082"
)

$ErrorActionPreference = "Continue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   ENTERPRISE WAF - PHASE 6 COMPREHENSIVE E2E TEST SUITE    " -ForegroundColor Cyan
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
            ErrorAction = "Stop"
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

Write-Host "--- 1. OWASP CRS Attack Vectors and Policy Enforcement ---" -ForegroundColor Yellow
Assert-WafResult -TestID "SEC-01" -Description "SQLi in URI Query Parameter" `
    -Method "GET" -Path "/api/search?q=1%27%20OR%20%271%27%3D%271" -ExpectedStatus 403

Assert-WafResult -TestID "SEC-02" -Description "SQLi in JSON POST Request Body" `
    -Method "POST" -Path "/api/login" -Body '{"username":"admin", "password":"1'' OR ''1''=''1"}' -ExpectedStatus 403

Assert-WafResult -TestID "SEC-03" -Description "XSS Attack (<script> Injection)" `
    -Method "GET" -Path "/api/comment?text=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E" -ExpectedStatus 403

Assert-WafResult -TestID "SEC-04" -Description "Path Traversal (etc/passwd access)" `
    -Method "GET" -Path "/api/files?download=../../../../etc/passwd" -ExpectedStatus 403

Assert-WafResult -TestID "SEC-05" -Description "Remote OS Command Injection" `
    -Method "GET" -Path "/api/status?host=127.0.0.1%3Bcat%20%2Fetc%2Fshadow" -ExpectedStatus 403

Assert-WafResult -TestID "SEC-06" -Description "Automated Vulnerability Scanner UA (Nikto)" `
    -Method "GET" -Path "/api/health" -Headers @{"User-Agent" = "Nikto/2.1.6"} -ExpectedStatus 403

Assert-WafResult -TestID "SEC-07" -Description "Custom SecLang Policy (/admin restricted)" `
    -Method "GET" -Path "/admin" -ExpectedStatus 403

Assert-WafResult -TestID "SEC-08" -Description "Custom SecLang Policy (/secret restricted)" `
    -Method "GET" -Path "/secret" -ExpectedStatus 403

Write-Host ""
Write-Host "--- 2. Legitimate Traffic Verification (False Positive Check) ---" -ForegroundColor Yellow
Assert-WafResult -TestID "LEG-01" -Description "Legitimate GET /api/search?q=enterprise" `
    -Method "GET" -Path "/api/search?q=enterprise" -ExpectedStatus 200

Assert-WafResult -TestID "LEG-02" -Description "Legitimate JSON POST /api/login" `
    -Method "POST" -Path "/api/login" -Body '{"username":"validuser", "password":"StrongPassword!123"}' -ExpectedStatus 200

Assert-WafResult -TestID "LEG-03" -Description "Legitimate Origin Service Root /" `
    -Method "GET" -Path "/" -ExpectedStatus 200

Write-Host ""
Write-Host "--- 3. L2 SOC Dynamic IP Denylist and xDS Sync Verification ---" -ForegroundColor Yellow
# Discover actual IP of origin-mock container
$mockAttackerIP = (docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" engineering-brain-prd-origin-mock-1).Trim()
if ([string]::IsNullOrWhiteSpace($mockAttackerIP)) { $mockAttackerIP = "172.20.0.4" }
Write-Host "[SOC-01] Testing Dynamic IP Block propagation for IP: $mockAttackerIP..."

try {
    # 1. Add IP block via Management Plane
    $blockRes = Invoke-RestMethod -Uri "$MgmtHost/api/v1/ip-block" -Method POST -ContentType "application/json" `
        -Body (@{ ip_address = $mockAttackerIP; reason = "E2E Dynamic Denylist Verification" } | ConvertTo-Json)
    Write-Host "  -> IP $mockAttackerIP added to denylist (Status: $($blockRes.status))" -ForegroundColor Gray

    # Give xDS 1.5 seconds to sync snapshot to Envoy
    Start-Sleep -Milliseconds 1500

    # 2. Test query from this blocked container IP
    $dockerRes = docker exec engineering-brain-prd-origin-mock-1 wget -qO- -S http://envoy:8080/api/search?q=enterprise 2>&1
    $dockerResStr = [string]::Join("`n", $dockerRes)
    if ($dockerResStr -match "403 Forbidden") {
        Write-Host "  -> Dynamic IP Block Verified: Envoy returned 403 Forbidden without restart!" -ForegroundColor Green
        $script:testsPassed++
    } else {
        Write-Host "  -> Dynamic IP Block Failed to enforce immediately: $dockerResStr" -ForegroundColor Red
        $script:testsFailed++
    }

    # 3. Clean up (Unblock IP)
    $delRes = Invoke-RestMethod -Uri "$MgmtHost/api/v1/ip-block/$mockAttackerIP" -Method DELETE
    Write-Host "  -> IP $mockAttackerIP unblocked (Status: $($delRes.status))" -ForegroundColor Gray
    Start-Sleep -Milliseconds 1500

    $dockerRestore = docker exec engineering-brain-prd-origin-mock-1 wget -qO- -S http://envoy:8080/api/search?q=enterprise 2>&1
    $dockerRestoreStr = [string]::Join("`n", $dockerRestore)
    if ($dockerRestoreStr -match "200 OK") {
        Write-Host "  -> Dynamic IP Unblock Verified: Envoy immediately restored 200 OK!" -ForegroundColor Green
        $script:testsPassed++
    } else {
        Write-Host "  -> Dynamic IP Unblock Failed: $dockerRestoreStr" -ForegroundColor Red
        $script:testsFailed++
    }

} catch {
    Write-Host "  -> Dynamic IP test threw exception: $($_.Exception.Message)" -ForegroundColor Red
    $script:testsFailed++
}

Write-Host ""
Write-Host "--- 4. Telemetry Pipeline and Database Persistence Check ---" -ForegroundColor Yellow
try {
    $events = Invoke-RestMethod -Uri "$MgmtHost/api/v1/events" -Method GET
    if ($events.Count -gt 0) {
        Write-Host "  -> Security Events successfully captured in DB! Total recorded: $($events.Count)" -ForegroundColor Green
        Write-Host "  -> Latest Event ID: $($events[0].id) | Rule: $($events[0].rule_id) | Path: $($events[0].path)" -ForegroundColor Gray
        $script:testsPassed++
    } else {
        Write-Host "  -> No events found in database." -ForegroundColor Red
        $script:testsFailed++
    }
} catch {
    Write-Host "  -> Telemetry verification error: $($_.Exception.Message)" -ForegroundColor Red
    $script:testsFailed++
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
if ($testsFailed -eq 0) {
    Write-Host "SUMMARY: $testsPassed PASSED | $testsFailed FAILED - ALL SYSTEMS GREEN" -ForegroundColor Green
} else {
    Write-Host "SUMMARY: $testsPassed PASSED | $testsFailed FAILED" -ForegroundColor Red
}
Write-Host "============================================================" -ForegroundColor Cyan

if ($testsFailed -gt 0) {
    exit 1
}

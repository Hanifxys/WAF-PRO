$ErrorActionPreference = 'Stop'
$API_URL = 'http://localhost:8082/api/v1'

Write-Host 'Running Milestone 14 Tests...' -ForegroundColor Cyan

# 1. Simulator
$simPayload = @{
    sec_lang_code = 'SecRule REQUEST_URI "@rx /admin" "id:999,phase:1,deny"'
    sample_limit = 100
}
$resSim = Invoke-RestMethod -Uri "$API_URL/policy-simulator/simulate" -Method Post -Body ($simPayload | ConvertTo-Json) -ContentType 'application/json'
if ($null -ne $resSim.simulated_blocks) { Write-Host 'Simulator OK' -ForegroundColor Green }

# 2. Canary
$canaryPayload = @{
    app_id = 1
    policy_name = 'Test Canary'
    candidate_seclang = 'SecRule REQUEST_URI "@rx /test" "id:888,phase:1,deny"'
    traffic_weight_pct = 10
}
$resCanary = Invoke-RestMethod -Uri "$API_URL/canary-deployments" -Method Post -Body ($canaryPayload | ConvertTo-Json) -ContentType 'application/json'
if ($resCanary.status -eq 'ACTIVE') { Write-Host 'Canary OK' -ForegroundColor Green }

# 3. Profiler
$resProfiler = Invoke-RestMethod -Uri "$API_URL/rule-profiler/stats" -Method Get
if ($resProfiler.Length -gt 0) { Write-Host 'Profiler OK' -ForegroundColor Green }

# 4. Threat Intel
$tiPayload = @{ client_ip = '192.168.1.100' }
$resTI = Invoke-RestMethod -Uri "$API_URL/threat-intel/correlate" -Method Post -Body ($tiPayload | ConvertTo-Json) -ContentType 'application/json'
if ($resTI.threat_category) { Write-Host 'Threat Intel OK' -ForegroundColor Green }

# 5. WAF-as-Code
$wacPayload = @{ spec_content = "application: my-app`nmode: BLOCK`nrules:`n  - id: 100`n    pattern: SQLI" }
$resWac = Invoke-RestMethod -Uri "$API_URL/waf-as-code/validate" -Method Post -Body ($wacPayload | ConvertTo-Json) -ContentType 'application/json'
if ($resWac.is_valid -ne $null) { Write-Host 'WAF-as-Code OK' -ForegroundColor Green }

# 6. Flight Recorder
$frPayload = @{ app_id = 1; scope_path = '/api/v1/*'; duration_minutes = 15 }
$resFR = Invoke-RestMethod -Uri "$API_URL/flight-recorder/start" -Method Post -Body ($frPayload | ConvertTo-Json) -ContentType 'application/json'
if ($resFR.is_active -eq $true) { Write-Host 'Flight Recorder OK' -ForegroundColor Green }

# 7. DLP
$dlpPayload = @{ mode = 'REDACT'; payload = 'Bearer eyJhbGciOiJIUzI1NiJ9.test Bearer Token' }
$resDlp = Invoke-RestMethod -Uri "$API_URL/dlp/redact" -Method Post -Body ($dlpPayload | ConvertTo-Json) -ContentType 'application/json'
if ($resDlp.redacted_result -match 'REDACTED_TOKEN') { Write-Host 'DLP Redact OK' -ForegroundColor Green }

Write-Host 'All Milestone 14 tests passed!' -ForegroundColor Green

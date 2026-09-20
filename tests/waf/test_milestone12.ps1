$ErrorActionPreference = "Stop"

$API_URL = "http://localhost:8082/api/v1"

Write-Host "Running Milestone 12 Tests (Advanced Enterprise Pillar 1 & 2)..." -ForegroundColor Cyan

# 1. Test Phase 32: API Schema Enforcement
Write-Host "`n[Test 1] Importing OpenAPI Schema and verifying xDS..."
$schemaPayload = @{
    app_id = 1
    title = "Test API Schema"
    spec_version = "3.0.0"
    enforcement_mode = "BLOCK"
    raw_openapi_json = '{ "paths": { "/api/v1/test": { "get": {} } } }'
}
$res = Invoke-RestMethod -Uri "$API_URL/schemas/import" -Method Post -Body ($schemaPayload | ConvertTo-Json -Depth 10) -ContentType "application/json"
if ($res.id) {
    Write-Host "✓ Schema imported successfully" -ForegroundColor Green
} else {
    throw "Failed to import schema"
}

# Give time for syncDynamicWAFRules
Start-Sleep -Seconds 2

# Verify schema translated to WAF rules by checking config snapshots
$configRes = Invoke-RestMethod -Uri "$API_URL/config-snapshots" -Method Get
$latestConfig = $configRes[0]
if ($latestConfig.seclang_content -match "OpenAPI Schema Violation") {
    Write-Host "✓ OpenAPI Schema successfully compiled into WAF SecRules" -ForegroundColor Green
} else {
    throw "OpenAPI Schema was not compiled into xDS"
}

# 2. Test Phase 33: Identity Policy
Write-Host "`n[Test 2] Creating Identity Policy and verifying xDS..."
$idPayload = @{
    app_id = 1
    role = "ADMIN"
    restricted_path = "/api/v1/admin"
    action = "BLOCK"
    is_enabled = $true
}
$resId = Invoke-RestMethod -Uri "$API_URL/identity-policies" -Method Post -Body ($idPayload | ConvertTo-Json) -ContentType "application/json"
if ($resId.id) {
    Write-Host "✓ Identity Policy created successfully" -ForegroundColor Green
} else {
    throw "Failed to create Identity Policy"
}

Start-Sleep -Seconds 2
$configRes2 = Invoke-RestMethod -Uri "$API_URL/config-snapshots" -Method Get
$latestConfig2 = $configRes2[0]
if ($latestConfig2.seclang_content -match "Identity RBAC Violation") {
    Write-Host "✓ Identity Policy successfully compiled into WAF SecRules" -ForegroundColor Green
} else {
    throw "Identity Policy was not compiled into xDS"
}

Write-Host "`nAll Milestone 12 tests passed!" -ForegroundColor Green

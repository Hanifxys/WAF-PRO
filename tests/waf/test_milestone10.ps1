# ==============================================================================
# Enterprise WAF Pro SaaS - Milestone 10 Automated Verification Suite
# Comprehensive Delivery: Extended Roadmap Phases 31 - 45
# 
# Pillars:
#   Pillar 1: Advanced Application Discovery & Schema Enforcement (Phases 31, 32)
#   Pillar 2: Identity & Session Security + JWT Cryptographic Token (Phases 33, 34)
#   Pillar 3: Modern Protocols: GraphQL, WebSocket & gRPC Shields (Phases 35, 36, 37)
#   Pillar 4: Credential Stuffing, ATO Risk & Scraping Shields (Phases 38, 39, 40)
#   Pillar 5: Policy Impact Analysis, Canary Deployments & Rule Profiler (Phases 41, 42, 43)
#   Pillar 6: Multi-Source Threat Intelligence Correlation (Phase 44)
#   Pillar 7: Detection Engineering & WAF-as-Code GitOps (Phase 45)
#   Forensics: Explain This Block, Why Not Blocked, Flight Recorder, Sensitive Redactor
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
Write-Host "   WAF PRO ENTERPRISE - MILESTONE 10 AUTOMATED VERIFICATION SUITE      " -ForegroundColor Cyan
Write-Host "          Covering Extended Enterprise Roadmap Phases 31-45             " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# 1. Pillar 1: Advanced Application Discovery (Phase 31)
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 1] Pillar 1: Advanced Application Discovery (Phase 31)" -ForegroundColor Yellow

$assets = Invoke-RestMethod -Uri "$baseUrl/assets" -Method GET
Assert-Condition "1.1 Default discovered assets retrieved" ($assets.Length -ge 6)

$classifyBody = @{
    app_id = 1
    path_pattern = "/api/v1/payments/crypto"
    method = "POST"
} | ConvertTo-Json

$classified = Invoke-RestMethod -Uri "$baseUrl/assets/classify" -Method POST -Body $classifyBody -ContentType "application/json"
Assert-Condition "1.2 Heuristic auto-classified as REST API" ($classified.asset_type -eq "REST" -and $classified.id -gt 0)

$tagBody = @{ is_sensitive = $true } | ConvertTo-Json
$tagged = Invoke-RestMethod -Uri "$baseUrl/assets/$($classified.id)/tag-sensitive" -Method PUT -Body $tagBody -ContentType "application/json"
Assert-Condition "1.3 Sensitive tag updated on asset" ($tagged.is_sensitive -eq $true)

# ------------------------------------------------------------------------------
# 2. Pillar 1: API Schema Enforcement (Phase 32)
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 2] Pillar 1: API Schema Enforcement (Phase 32)" -ForegroundColor Yellow

$schemaJson = '{"openapi":"3.0.0","info":{"title":"Telkomsel Digital Banking"},"paths":{"/api/v1/accounts":{"get":{}},"/api/v1/transfer":{"post":{}}}}'
$importBody = @{
    app_id = 1
    title = "Telkomsel Digital Banking API"
    spec_version = "3.0.0"
    raw_openapi_json = $schemaJson
    enforcement_mode = "MONITOR"
} | ConvertTo-Json

$importedSchema = Invoke-RestMethod -Uri "$baseUrl/schemas/import" -Method POST -Body $importBody -ContentType "application/json"
Assert-Condition "2.1 OpenAPI specification imported with endpoints parsed" ($importedSchema.id -gt 0 -and $importedSchema.endpoints_count -eq 2)

$schemas = Invoke-RestMethod -Uri "$baseUrl/schemas/1" -Method GET
Assert-Condition "2.2 Queried imported schemas for application" ($schemas.Length -ge 1)

$modeBody = @{ enforcement_mode = "BLOCK" } | ConvertTo-Json
$updatedMode = Invoke-RestMethod -Uri "$baseUrl/schemas/$($importedSchema.id)/mode" -Method PUT -Body $modeBody -ContentType "application/json"
Assert-Condition "2.3 Schema enforcement mode stepped to BLOCK" ($updatedMode.enforcement_mode -eq "BLOCK")

# ------------------------------------------------------------------------------
# 3. Pillar 2: Identity & Session Security + JWT Validation (Phases 33, 34)
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 3] Pillar 2: Identity & Session Security + JWT Validation (Phases 33, 34)" -ForegroundColor Yellow

# Identity Policy
$idPolicyBody = @{
    app_id = 1
    role = "ANONYMOUS"
    restricted_path = "/api/v1/sensitive/*"
    action = "BLOCK"
} | ConvertTo-Json

$createdIdPolicy = Invoke-RestMethod -Uri "$baseUrl/identity-policies" -Method POST -Body $idPolicyBody -ContentType "application/json"
Assert-Condition "3.1 Identity-to-route restriction policy created" ($createdIdPolicy.id -gt 0 -and $createdIdPolicy.role -eq "ANONYMOUS")

$idPolicies = Invoke-RestMethod -Uri "$baseUrl/identity-policies" -Method GET
Assert-Condition "3.2 Queried active identity policies" ($idPolicies.Length -ge 1)

$deletedId = Invoke-RestMethod -Uri "$baseUrl/identity-policies/$($createdIdPolicy.id)" -Method DELETE
Assert-Condition "3.3 Identity policy deleted" ($deletedId.status -eq "deleted")

# JWT Policy
$jwtPolicyBody = @{
    app_id = 1
    issuer = "https://iam.internal.telkomsel.co.id"
    expected_audience = "rms-microservices"
    allowed_algorithms = "RS256, ES256"
    enforce_expiry = $true
    action = "BLOCK"
} | ConvertTo-Json

$createdJWTPolicy = Invoke-RestMethod -Uri "$baseUrl/jwt-policies" -Method POST -Body $jwtPolicyBody -ContentType "application/json"
Assert-Condition "3.4 Cryptographic JWT validation policy registered" ($createdJWTPolicy.id -gt 0 -and $createdJWTPolicy.expected_audience -eq "rms-microservices")

$jwtPolicies = Invoke-RestMethod -Uri "$baseUrl/jwt-policies" -Method GET
Assert-Condition "3.5 Queried active JWT policies" ($jwtPolicies.Length -ge 1)

$deletedJWT = Invoke-RestMethod -Uri "$baseUrl/jwt-policies/$($createdJWTPolicy.id)" -Method DELETE
Assert-Condition "3.6 JWT policy deleted" ($deletedJWT.status -eq "deleted")

# ------------------------------------------------------------------------------
# 4. Pillar 3: Modern Protocol Protection: GraphQL, WebSocket & gRPC (Phases 35, 36, 37)
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 4] Pillar 3: Modern Protocols (GraphQL, WebSocket, gRPC)" -ForegroundColor Yellow

# GraphQL
$gqlBody = @{
    app_id = 1
    policy_config = @{
        max_depth = 10
        max_complexity = 600
        max_aliases = 15
        disable_introspection = $true
    }
    action = "BLOCK"
    is_enabled = $true
} | ConvertTo-Json -Depth 5

$gqlShield = Invoke-RestMethod -Uri "$baseUrl/protocol-shields/graphql" -Method POST -Body $gqlBody -ContentType "application/json"
Assert-Condition "4.1 GraphQL Shield configured (maxDepth 10, introspection disabled)" ($gqlShield.protocol -eq "graphql" -and $gqlShield.action -eq "BLOCK")

# WebSocket
$wsBody = @{
    app_id = 1
    policy_config = @{
        allowed_origins = "*.telkomsel.co.id"
        max_concurrent_connections = 100
        max_message_size_kb = 2048
        idle_timeout_sec = 600
    }
    action = "BLOCK"
    is_enabled = $true
} | ConvertTo-Json -Depth 5

$wsShield = Invoke-RestMethod -Uri "$baseUrl/protocol-shields/websocket" -Method POST -Body $wsBody -ContentType "application/json"
Assert-Condition "4.2 WebSocket Shield configured with concurrency and frame limit" ($wsShield.protocol -eq "websocket")

# gRPC
$grpcBody = @{
    app_id = 1
    policy_config = @{
        allowed_packages = "telkomsel.services.*"
        restricted_methods = "DeleteUser, PurgeDatabase"
        max_message_size_mb = 8
    }
    action = "BLOCK"
    is_enabled = $true
} | ConvertTo-Json -Depth 5

$grpcShield = Invoke-RestMethod -Uri "$baseUrl/protocol-shields/grpc" -Method POST -Body $grpcBody -ContentType "application/json"
Assert-Condition "4.3 gRPC Shield configured with package allowlist" ($grpcShield.protocol -eq "grpc")

# ------------------------------------------------------------------------------
# 5. Pillar 4: Advanced Abuse Protection & Account Takeover (Phases 38, 39, 40)
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 5] Pillar 4: Abuse & Account Takeover (ATO) Protection (Phases 38, 39, 40)" -ForegroundColor Yellow

$atoBody = @{
    client_ip = "185.220.101.44"
    username = "corporate_admin"
    country = "RU"
    asn = "AS9009 Hosting Provider"
    failed_mfa_count = 4
    velocity_rpm = 85
} | ConvertTo-Json

$atoRisk = Invoke-RestMethod -Uri "$baseUrl/ato-risk/evaluate" -Method POST -Body $atoBody -ContentType "application/json"
Assert-Condition "5.1 Multi-signal ATO risk evaluated as HIGH" ($atoRisk.risk_score -ge 75 -and $atoRisk.risk_level -eq "HIGH" -and $atoRisk.recommended_action -eq "BLOCK")

$scrapingBody = @{
    app_id = 1
    name = "Catalog Price Harvester Shield"
    target_path = "/products/catalog"
    max_pages = 50
    window_seconds = 300
    action = "BLOCK"
} | ConvertTo-Json

$createdScraping = Invoke-RestMethod -Uri "$baseUrl/scraping-policies" -Method POST -Body $scrapingBody -ContentType "application/json"
Assert-Condition "5.2 Business Scraping Shield policy created" ($createdScraping.id -gt 0 -and $createdScraping.name -eq "Catalog Price Harvester Shield")

$delScraping = Invoke-RestMethod -Uri "$baseUrl/scraping-policies/$($createdScraping.id)" -Method DELETE
Assert-Condition "5.3 Scraping policy deleted" ($delScraping.status -eq "deleted")

# ------------------------------------------------------------------------------
# 6. Pillar 5: Safe Canary Deployments & Rule Performance Profiler (Phases 41, 42, 43)
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 6] Pillar 5: Canary Safe Deployment & Rule Profiler (Phases 41, 42, 43)" -ForegroundColor Yellow

$impactBody = @{
    candidate_rule = 'SecRule ARGS:test "@rx drop table" "id:300001,deny,status:403"'
    target_app_id = 1
} | ConvertTo-Json

$impact = Invoke-RestMethod -Uri "$baseUrl/policy-impact/analyze" -Method POST -Body $impactBody -ContentType "application/json"
Assert-Condition "6.1 Pre-deployment policy impact analysis completed" ($impact.historical_requests -gt 0 -and $impact.affected_applications -ge 1)

$canaryBody = @{
    app_id = 1
    policy_name = "Candidate CRS 942100 Paranoia Level 3"
    candidate_seclang = 'SecRule ARGS:q "@rx (?i)select.*from" "id:942100,deny,status:403"'
    traffic_weight_pct = 5
    error_threshold_5xx_pct = 1.0
} | ConvertTo-Json

$canary = Invoke-RestMethod -Uri "$baseUrl/canary-deployments" -Method POST -Body $canaryBody -ContentType "application/json"
Assert-Condition "6.2 Canary deployment initiated at 5% traffic weight" ($canary.id -gt 0 -and $canary.traffic_weight_pct -eq 5 -and $canary.status -eq "ACTIVE")

$stepBody = @{ action = "STEP_UP" } | ConvertTo-Json
$steppedCanary = Invoke-RestMethod -Uri "$baseUrl/canary-deployments/$($canary.id)/step" -Method POST -Body $stepBody -ContentType "application/json"
Assert-Condition "6.3 Canary stepped up (+15% to 20%)" ($steppedCanary.traffic_weight_pct -eq 20)

$promoteBody = @{ action = "PROMOTE" } | ConvertTo-Json
$promotedCanary = Invoke-RestMethod -Uri "$baseUrl/canary-deployments/$($canary.id)/step" -Method POST -Body $promoteBody -ContentType "application/json"
Assert-Condition "6.4 Canary safely promoted to 100% production traffic" ($promotedCanary.status -eq "PROMOTED" -and $promotedCanary.traffic_weight_pct -eq 100)

$profilerStats = Invoke-RestMethod -Uri "$baseUrl/rule-profiler/stats" -Method GET
Assert-Condition "6.5 Real Coraza rule execution profiling stats retrieved" ($profilerStats.Length -ge 4 -and $profilerStats[0].avg_eval_ms -gt 0)

# ------------------------------------------------------------------------------
# 7. Pillar 6 & 7: Threat Correlation & WAF-as-Code (Phases 44, 45)
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 7] Pillar 6 & 7: Threat Correlation & WAF-as-Code (Phases 44, 45)" -ForegroundColor Yellow

$threatCorrelateBody = @{ client_ip = "185.220.101.5" } | ConvertTo-Json
$correlated = Invoke-RestMethod -Uri "$baseUrl/threat-intel/correlate" -Method POST -Body $threatCorrelateBody -ContentType "application/json"
Assert-Condition "7.1 Multi-signal threat intelligence correlation retrieved" ($correlated.client_ip -eq "185.220.101.5" -and $correlated.asn_org -ne "")

$validYaml = "application: rms-production`nmode: blocking`nrules:`n  - crs: 942100"
$wafCodeValidate = Invoke-RestMethod -Uri "$baseUrl/waf-as-code/validate" -Method POST -Body (@{ spec_content = $validYaml } | ConvertTo-Json) -ContentType "application/json"
Assert-Condition "7.2 Declarative WAF-as-Code YAML validated successfully" ($wafCodeValidate.is_valid -eq $true -and $wafCodeValidate.application -eq "rms-production")

$wafCodeApply = Invoke-RestMethod -Uri "$baseUrl/waf-as-code/apply" -Method POST -Body (@{ spec_content = $validYaml; author = "gitops-pipeline" } | ConvertTo-Json) -ContentType "application/json"
Assert-Condition "7.3 WAF-as-Code applied and pushed to xDS plane" ($wafCodeApply.status -eq "applied")

# ------------------------------------------------------------------------------
# 8. Forensics & Investigation UX Operations Suite
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 8] Forensics & Investigation UX Suite" -ForegroundColor Yellow

# Seed a test security event to explain
$eventBody = @(
    @{
        transaction = @{
            id = "tx-test-sql-942100"
            client_ip = "192.168.1.105"
            is_interrupted = $true
            request = @{
                method = "GET"
                uri = "/api/v1/search?q=' OR 1=1 --"
                headers = @{}
            }
        }
        messages = @(
            @{
                message = "SQL Injection Libinjection Attack Detected"
                data = @{
                    id = 942100
                    severity = 2
                }
            }
        )
    }
) | ConvertTo-Json -Depth 5

$ingestRes = Invoke-RestMethod -Uri "$baseUrl/events" -Method POST -Body $eventBody -ContentType "application/json"

# Get the latest security event id
$events = Invoke-RestMethod -Uri "$baseUrl/events" -Method GET
$eventId = $events[0].id

$explained = Invoke-RestMethod -Uri "$baseUrl/investigation/explain-block/$eventId" -Method GET
Assert-Condition "8.1 'Explain This Block' provides complete decision forensics" ($explained.rule_id -eq "942100" -and $explained.anomaly_score -eq 7 -and $explained.category -eq "SQL Injection (SQLi)")

$whyNotBody = @{
    request_id = "test-req-allowed-01"
    path = "/api/v1/health"
    client_ip = "127.0.0.1"
} | ConvertTo-Json

$whyNot = Invoke-RestMethod -Uri "$baseUrl/investigation/why-not-blocked" -Method POST -Body $whyNotBody -ContentType "application/json"
Assert-Condition "8.2 'Why Wasn't This Blocked' lists itemized verdicts" ($whyNot.final_verdict -eq "ALLOWED" -and $whyNot.reasons.Length -ge 3)

$flightBody = @{
    app_id = 1
    scope_path = "/api/checkout/*"
    duration_minutes = 15
} | ConvertTo-Json

$flight = Invoke-RestMethod -Uri "$baseUrl/flight-recorder/start" -Method POST -Body $flightBody -ContentType "application/json"
Assert-Condition "8.3 WAF Flight Recorder started 15-minute diagnostic session" ($flight.id -gt 0 -and $flight.is_active -eq $true)

$flightStatus = Invoke-RestMethod -Uri "$baseUrl/flight-recorder/status" -Method GET
Assert-Condition "8.4 Active flight recorder session returned in telemetry" ($flightStatus.Length -ge 1)

$flightStop = Invoke-RestMethod -Uri "$baseUrl/flight-recorder/stop" -Method POST
Assert-Condition "8.5 Flight recorder session safely stopped" ($flightStop.status -eq "stopped")

$redactBody = @{
    raw_text = "Login request: password=MySecretP@ssw0rd123 and Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test"
    mode = "REDACT"
} | ConvertTo-Json

$redacted = Invoke-RestMethod -Uri "$baseUrl/dlp/redact" -Method POST -Body $redactBody -ContentType "application/json"
Assert-Condition "8.6 Sensitive data scrubbed (passwords and tokens masked)" ($redacted.redacted_result -notmatch "MySecretP@ssw0rd123" -and $redacted.redacted_result -match "\[REDACTED_PASSWORD\]")

# ------------------------------------------------------------------------------
# 9. Backup & Diagnostics Integrity
# ------------------------------------------------------------------------------
Write-Host "`n>>> [SECTION 9] Backup & Diagnostics Integrity" -ForegroundColor Yellow

$backup = Invoke-RestMethod -Uri "$baseUrl/system/backup" -Method GET
Assert-Condition "9.1 Backup bundle includes discovered_assets, protocol_shields, and canary_deployments" ($backup.discovered_assets.Length -ge 1 -and $backup.protocol_shields.Length -ge 1)

$diag = Invoke-RestMethod -Uri "$baseUrl/diagnostics" -Method GET
Assert-Condition "9.2 Diagnostics counters track all Milestone 10 entities" ($diag.counters.active_discovered_assets -ge 6 -and $diag.counters.active_protocol_shields -ge 3 -and $diag.counters.active_canary_deployments -ge 1)

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "MILESTONE 10 TEST SUMMARY" -ForegroundColor Cyan
Write-Host "Total Tests Passed : $global:testsPassed" -ForegroundColor Green
Write-Host "Total Tests Failed : $global:testsFailed" -ForegroundColor $(if ($global:testsFailed -eq 0) { "Green" } else { "Red" })
Write-Host "======================================================================" -ForegroundColor Cyan

if ($global:testsFailed -gt 0) {
    exit 1
} else {
    exit 0
}

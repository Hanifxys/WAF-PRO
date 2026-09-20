$ErrorActionPreference = 'SilentlyContinue'

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " WAF-PRO Phase 57-61: Advanced Business Logic & ATO  " -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1] Testing Phase 61: Product Catalog Scraping" -ForegroundColor Yellow
for ($i=1; $i -le 11; $i++) {
    $response = Invoke-WebRequest -Uri "http://localhost:8080/api/product/$i" -Method GET -SkipHttpError
    if ($i -eq 11) {
        Write-Host "    Request 11 Status: $($response.StatusCode) - $($response.StatusDescription)"
    }
}
Write-Host ""

Write-Host "[2] Testing Phase 61: Promotional Voucher Abuse" -ForegroundColor Yellow
for ($i=1; $i -le 4; $i++) {
    $response = Invoke-WebRequest -Uri "http://localhost:8080/api/voucher/redeem" -Method POST -Body "{}" -SkipHttpError
    Write-Host "    Attempt $i Status: $($response.StatusCode) - $($response.StatusDescription)"
}
Write-Host ""

Write-Host "[3] Testing Phase 61: Fake Account Registration" -ForegroundColor Yellow
for ($i=1; $i -le 4; $i++) {
    $response = Invoke-WebRequest -Uri "http://localhost:8080/api/register" -Method POST -Body "{}" -SkipHttpError
    Write-Host "    Attempt $i Status: $($response.StatusCode) - $($response.StatusDescription)"
}
Write-Host ""

Write-Host "[4] Testing Phase 59: Credential Stuffing (Global Rate Limit)" -ForegroundColor Yellow
# Simulating 6 login attempts with the same username.
# In a real environment, this would come from 6 different IPs. We simulate it by using the same username.
for ($i=1; $i -le 6; $i++) {
    $response = Invoke-WebRequest -Uri "http://localhost:8080/api/login" -Method POST -Body "username=admin&password=try$i" -SkipHttpError
    Write-Host "    Login $i Status: $($response.StatusCode) - $($response.StatusDescription)"
}
Write-Host ""

Write-Host "[5] Testing Phase 60: Account Takeover (Impossible Travel)" -ForegroundColor Yellow
# Send request with a token from one IP (simulated by sequence engine seeing it)
# We can't easily fake the client IP via Invoke-WebRequest to localhost without X-Forwarded-For (if Envoy trusts it).
# Envoy usually sets client_ip to 127.0.0.1.
# Let's send a fake X-Forwarded-For if we enabled use_remote_address.
Write-Host "    Sending from IP 1..."
$response1 = Invoke-WebRequest -Uri "http://localhost:8080/api/profile" -Method GET -Headers @{ "Authorization" = "Bearer stolen-token-123" } -SkipHttpError
Write-Host "    Status: $($response1.StatusCode) - $($response1.StatusDescription)"

Write-Host "    Sending from IP 2 (Simulating via different header / wait)... Note: Requires Envoy XFF trust to simulate properly in powershell."
$response2 = Invoke-WebRequest -Uri "http://localhost:8080/api/profile" -Method GET -Headers @{ "Authorization" = "Bearer stolen-token-123", "X-Forwarded-For" = "203.0.113.1" } -SkipHttpError
Write-Host "    Status: $($response2.StatusCode) - $($response2.StatusDescription)"
Write-Host ""

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Tests Completed." -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

$baseUrl = "http://localhost:8080"

function Test-Waf {
    param(
        [string]$Name,
        [string]$Method,
        [string]$Path,
        [string]$Body = "",
        [string]$ContentType = "application/json"
    )
    
    Write-Host "Running: $Name"
    
    try {
        if ($Method -eq "GET") {
            $response = Invoke-WebRequest -Uri "$baseUrl$Path" -Method GET -ErrorAction SilentlyContinue
        } else {
            $response = Invoke-WebRequest -Uri "$baseUrl$Path" -Method $Method -Body $Body -ContentType $ContentType -ErrorAction SilentlyContinue
        }
        
        Write-Host "Result: HTTP $($response.StatusCode) - ALLOWED" -ForegroundColor Green
    } catch {
        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode.value__
            if ($statusCode -eq 403) {
                Write-Host "Result: HTTP $statusCode - BLOCKED" -ForegroundColor Yellow
            } else {
                Write-Host "Result: HTTP $statusCode" -ForegroundColor Red
            }
        } else {
            Write-Host "Result: Request Failed - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host "---"
}

Test-Waf -Name "01 Normal GET" -Method "GET" -Path "/api/search?q=hello"
Test-Waf -Name "02 Normal POST" -Method "POST" -Path "/api/login" -Body '{"username":"admin", "password":"password123"}'
Test-Waf -Name "03 SQLi Query" -Method "GET" -Path "/api/search?q=1' OR '1'='1"
Test-Waf -Name "04 SQLi Body" -Method "POST" -Path "/api/login" -Body '{"username":"admin", "password":"1'' OR ''1''=''1"}'
Test-Waf -Name "05 XSS Query" -Method "GET" -Path "/api/search?q=<script>alert(1)</script>"
Test-Waf -Name "07 Path Traversal" -Method "GET" -Path "/api/search?q=../../../../etc/passwd"

package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type HealthResponse struct {
	Status string `json:"status"`
	Time   string `json:"time"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type DefaultResponse struct {
	Message string `json:"message"`
	Path    string `json:"path"`
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(HealthResponse{
			Status: "healthy",
			Time:   time.Now().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(DefaultResponse{
			Message: "Login attempt processed",
			Path:    r.URL.Path,
		})
	})

	mux.HandleFunc("/api/search", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Search executed",
			"query":   query,
			"path":    r.URL.Path,
		})
	})

	// Phase 10: DLP Simulation Endpoints
	mux.HandleFunc("/api/user-data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Simulates credit card leak in payload (PCI-DSS compliance exfiltration test)
		w.Write([]byte(`{"user":"john_doe","card_number":"4532123456789012","card_formatted":"4532-1234-5678-9012","status":"active"}`))
	})

	mux.HandleFunc("/api/debug", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Simulates database stack trace leak
		w.Write([]byte(`{"error":"Internal Error: SQLSTATE[42P01]: Undefined table: pg_query() failed in /var/www/db.php"}`))
	})

	mux.HandleFunc("/simulator", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
<!DOCTYPE html>
<html>
<head>
    <title>WAF-PRO Simulator</title>
    <style>
        body { font-family: system-ui; margin: 40px; background: #0f172a; color: #f8fafc; }
        button { padding: 10px 20px; margin: 5px; background: #3b82f6; color: white; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background: #2563eb; }
        .danger { background: #ef4444; }
        .danger:hover { background: #dc2626; }
        #log { background: #1e293b; padding: 20px; border-radius: 5px; font-family: monospace; height: 300px; overflow-y: auto; margin-top: 20px; }
        .success { color: #4ade80; }
        .error { color: #f87171; }
    </style>
</head>
<body>
    <h1>🛡️ WAF-PRO Attack Simulator</h1>

    <div>
        <h3>Phase 57 & 58: Bot Challenge</h3>
        <button onclick="spamRequests()">Spam 16 Requests (Trigger Bot Score Drop)</button>
    </div>

    <div>
        <h3>Phase 59: Credential Stuffing</h3>
        <button onclick="bruteForce()">Send 6 Logins for 'admin' (Trigger Multi-Dim Rate Limit)</button>
    </div>

    <div>
        <h3>Phase 60: Account Takeover (ATO)</h3>
        <button onclick="triggerATO()">Send 2 Profile Requests (Simulate Impossible Travel)</button>
    </div>

    <div>
        <h3>Phase 61: Business Logic Abuse</h3>
        <button onclick="scrape()">Scrape 11 Products</button>
        <button class="danger" onclick="voucherAbuse()">Redeem Voucher 4x</button>
        <button class="danger" onclick="botFarm()">Register Account 4x</button>
    </div>

    <div>
        <h3>Phase 62: Adaptive Rate Limiting</h3>
        <button onclick="searchAnon()">Search as Anonymous (11x)</button>
        <button onclick="searchAuth()">Search as Authenticated (11x)</button>
    </div>

    <div>
        <h3>Phase 63: L7 DDoS Behaviour Engine</h3>
        <button class="danger" onclick="ddosAttack()">Launch L7 Volumetric Attack (5,000 reqs)</button>
    </div>

    <div id="log"></div>

    <script>
        function log(msg, isError) {
            const l = document.getElementById('log');
            l.innerHTML += '<div class="' + (isError ? 'error' : 'success') + '">[' + new Date().toLocaleTimeString() + '] ' + msg + '</div>';
            l.scrollTop = l.scrollHeight;
        }

        async function spamRequests() {
            log('Starting Request Spam...');
            for(let i=0; i<16; i++) {
                try {
                    let r = await fetch('/api/health');
                    log('Spam ' + (i+1) + ': ' + r.status + (r.status === 302 ? ' (Redirected to Challenge)' : ''), r.status !== 200);
                } catch(e) { log('Spam ' + (i+1) + ' failed: ' + e.message, true); }
            }
        }

        async function bruteForce() {
            log('Starting Credential Stuffing...');
            for(let i=0; i<6; i++) {
                try {
                    let r = await fetch('/api/login', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({username: 'admin', password: 'pw'+i})
                    });
                    log('Login ' + (i+1) + ': ' + r.status + (r.status === 429 ? ' (Blocked by Envoy Global Rate Limit)' : ''), r.status !== 200);
                } catch(e) { log('Login ' + (i+1) + ' failed: ' + e.message, true); }
            }
        }

        async function triggerATO() {
            log('Simulating ATO...');
            try {
                let r1 = await fetch('/api/profile', { headers: { 'Authorization': 'Bearer stolen-token' } });
                log('Req 1 (IP 1): ' + r1.status, r1.status !== 200);

                let r2 = await fetch('/api/profile', { headers: { 'Authorization': 'Bearer stolen-token', 'X-Forwarded-For': '203.0.113.1' } });
                log('Req 2 (Fake IP 2): ' + r2.status + (r2.status === 401 ? ' (ATO Detected & Session Revoked)' : ''), r2.status !== 200);
            } catch(e) { log('ATO Test failed: ' + e.message, true); }
        }

        async function scrape() {
            log('Starting Scraper...');
            for(let i=1; i<=11; i++) {
                try {
                    let r = await fetch('/api/product/' + i);
                    log('Scrape Prod ' + i + ': ' + r.status + (r.status === 403 ? ' (Blocked by Business Logic Rule)' : ''), r.status !== 200);
                } catch(e) { log('Scrape failed: ' + e.message, true); }
            }
        }

        async function voucherAbuse() {
            log('Starting Voucher Abuse...');
            for(let i=1; i<=4; i++) {
                try {
                    let r = await fetch('/api/voucher/redeem', { method: 'POST', body: '{}' });
                    log('Redeem ' + i + ': ' + r.status, r.status !== 200);
                } catch(e) { log('Redeem failed: ' + e.message, true); }
            }
        }

        async function botFarm() {
            log('Starting Bot Farm...');
            for(let i=1; i<=4; i++) {
                try {
                    let r = await fetch('/api/register', { method: 'POST', body: '{}' });
                    log('Register ' + i + ': ' + r.status, r.status !== 200);
                } catch(e) { log('Register failed: ' + e.message, true); }
            }
        }

        async function searchAnon() {
            log('Searching Anonymous...');
            for(let i=1; i<=11; i++) {
                try {
                    let r = await fetch('/api/search?q=test');
                    log('Anon Search ' + i + ': ' + r.status + (r.status === 429 ? ' (Blocked: Anon Limit Reached)' : ''), r.status !== 200);
                } catch(e) { log('Search failed: ' + e.message, true); }
            }
        }

        async function searchAuth() {
            log('Searching Authenticated...');
            for(let i=1; i<=11; i++) {
                try {
                    let r = await fetch('/api/search?q=test', { headers: { 'Authorization': 'Bearer test' } });
                    log('Auth Search ' + i + ': ' + r.status + (r.status === 200 ? ' (Success: Auth Limit is 100)' : ''), r.status !== 200);
                } catch(e) { log('Search failed: ' + e.message, true); }
            }
        }

        async function ddosAttack() {
            log('WARNING: Launching L7 Search Flood (5,000 requests in background)...');
            let promises = [];
            for(let i=0; i<5000; i++) {
                // Fire and forget to simulate high concurrency
                promises.push(fetch('/api/search?q=flood').catch(e => {}));
            }
            log('All 5,000 requests dispatched. Check docker logs of management-api to see the DDoS classification!');
        }
    </script>
</body>
</html>
		`))
	})

	// Catch-all
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(DefaultResponse{
			Message: "Mock Origin Default Response",
			Path:    r.URL.Path,
		})
	})

	log.Println("Starting mock origin server on :8081...")
	if err := http.ListenAndServe(":8081", mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

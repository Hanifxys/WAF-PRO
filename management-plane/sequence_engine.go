package main

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"
)

type AccessLogEntry struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	ClientIP     string `json:"client_ip"`
	Token        string `json:"token,omitempty"`
	Timestamp    int64  `json:"timestamp,omitempty"`
	ResponseCode string `json:"response_code,omitempty"`
}

type SequenceWindow struct {
	Requests []AccessLogEntry
	mu       sync.Mutex
}

type SessionWindow struct {
	IPs []string
	mu  sync.Mutex
}

var sequenceTracker = sync.Map{}
var sessionTracker = sync.Map{}

func getSequenceWindow(ip string) *SequenceWindow {
	if val, ok := sequenceTracker.Load(ip); ok {
		return val.(*SequenceWindow)
	}
	window := &SequenceWindow{
		Requests: make([]AccessLogEntry, 0, 20),
	}
	sequenceTracker.Store(ip, window)
	return window
}

// Evaluate sequences for anomalies
func evaluateSequenceAnomalies(ip string, window *SequenceWindow) {
	window.mu.Lock()
	defer window.mu.Unlock()

	reqs := window.Requests
	if len(reqs) < 3 {
		return
	}

	// Bot Intelligence: Calculate Bot Score (Phase 57)
	// Base score is 100
	botScore := 100
	
	// Fast request velocity penalty
	if len(reqs) >= 15 {
		timeDiff := reqs[len(reqs)-1].Timestamp - reqs[0].Timestamp
		if timeDiff < 5 {
			// 15 requests in under 5 seconds is highly suspicious
			botScore -= 60
		} else if timeDiff < 10 {
			botScore -= 30
		}
	}

	// Rule 1: Fast IDOR / Enumeration Detection
	idorPattern := regexp.MustCompile(`^(/api/[^/]+)/(\d+)$`)
	idorCount := 0
	lastPrefix := ""
	lastID := ""

	// Phase 61: Business Logic Abuse Patterns
	scrapingPattern := regexp.MustCompile(`^/api/product/(\d+)$`)
	scrapingCount := 0
	lastScrapeID := ""

	voucherCount := 0
	registerCount := 0

	// Rule 2: Business Logic Flow
	loginCount := 0
	hasCart := false
	for _, req := range reqs {
		// IDOR logic
		matches := idorPattern.FindStringSubmatch(req.Path)
		if len(matches) == 3 {
			prefix := matches[1]
			id := matches[2]
			if prefix == lastPrefix && id != lastID {
				idorCount++
			}
			lastPrefix = prefix
			lastID = id
		}

		// Phase 61: Scraping logic
		scrapeMatches := scrapingPattern.FindStringSubmatch(req.Path)
		if len(scrapeMatches) == 2 {
			id := scrapeMatches[1]
			if req.Method == "GET" && id != lastScrapeID {
				scrapingCount++
			}
			lastScrapeID = id
		}

		// Phase 61: Voucher Abuse
		if req.Path == "/api/voucher/redeem" && req.Method == "POST" {
			voucherCount++
		}

		// Phase 61: Bot Registration
		if req.Path == "/api/register" && req.Method == "POST" {
			registerCount++
		}

		// Login brute force logic
		if req.Path == "/login" && req.Method == "POST" {
			loginCount++
		}
		
		// Business Logic Flow logic
		if req.Path == "/cart" {
			hasCart = true
		}
	}

	// Trigger IDOR Violation
	if idorCount >= 5 {
		triggerSequenceViolation(ip, "API Enumeration / BOLA Detected (Sequence)", "BLOCK")
		window.Requests = nil // Reset window
		return
	}

	// Trigger Login Brute Force Violation
	if loginCount >= 5 {
		triggerSequenceViolation(ip, "Rapid Login Sequence Detected", "BLOCK")
		window.Requests = nil // Reset window
		return
	}

	// Trigger Business Logic Violation
	lastReq := reqs[len(reqs)-1]
	if lastReq.Path == "/checkout" && lastReq.Method == "POST" && !hasCart {
		triggerSequenceViolation(ip, "Business Logic Bypass: /checkout accessed without /cart", "BLOCK")
		window.Requests = nil // Reset window
		return
	}

	// Phase 61: Business Logic Triggers
	if scrapingCount >= 10 {
		triggerSequenceViolation(ip, "Business Logic Abuse: High-Volume Catalog Scraping", "BLOCK")
		window.Requests = nil
		return
	}
	if voucherCount >= 3 {
		triggerSequenceViolation(ip, "Business Logic Abuse: Promotional Voucher Abuse", "BLOCK")
		window.Requests = nil
		return
	}
	if registerCount >= 3 {
		triggerSequenceViolation(ip, "Business Logic Abuse: Automated Account Creation", "BLOCK")
		window.Requests = nil
		return
	}

	// Bot Challenge Trigger
	if botScore <= 40 {
		triggerSequenceViolation(ip, "Low Bot Score (High Velocity/Anomalous Behavior)", "CHALLENGE")
		window.Requests = nil
		return
	}
}

// Evaluate Account Takeover (Phase 60)
func evaluateAccountTakeover(token string, ip string) {
	var window *SessionWindow
	if val, ok := sessionTracker.Load(token); ok {
		window = val.(*SessionWindow)
	} else {
		window = &SessionWindow{
			IPs: make([]string, 0, 5),
		}
		sessionTracker.Store(token, window)
	}

	window.mu.Lock()
	defer window.mu.Unlock()

	// Add IP if new
	isNew := true
	for _, existingIP := range window.IPs {
		if existingIP == ip {
			isNew = false
			break
		}
	}
	
	if isNew {
		window.IPs = append(window.IPs, ip)
	}

	if len(window.IPs) >= 2 {
		// If 2 unique IPs hit this token within the timeframe (the window implies recent active sessions), block token
		log.Printf("[ATO-Engine] Impossible Travel / Concurrent Session detected for token %s. IPs: %v", token[:8]+"...", window.IPs)
		
		_, err := db.Exec(`
			INSERT INTO threat_indicators (indicator, indicator_type, threat_category, confidence_score, severity, action, source_feed, is_active)
			VALUES ($1, 'SESSION_TOKEN', 'ACCOUNT_TAKEOVER', 99, 'CRITICAL', 'REAUTH', 'WAF_PRO_ATO', TRUE)
			ON CONFLICT (indicator) DO UPDATE SET 
				confidence_score = 99,
				severity = 'CRITICAL',
				action = 'REAUTH',
				updated_at = CURRENT_TIMESTAMP
		`, token)
		if err != nil {
			log.Printf("[ATO-Engine] Failed to revoke session: %v", err)
		} else {
			go syncDynamicWAFRules()
		}
		
		window.IPs = nil // reset
	}
}

func triggerSequenceViolation(clientIP, reason, action string) {
	log.Printf("[SequenceEngine] Anomaly Detected for IP %s: %s (Action: %s)", clientIP, reason, action)

	// Block or Challenge the IP in threat_indicators
	_, err := db.Exec(`
		INSERT INTO threat_indicators (indicator, indicator_type, threat_category, confidence_score, severity, action, source_feed, is_active)
		VALUES ($1, 'IP', 'SEQUENCE_ANOMALY', 90, 'HIGH', $2, 'WAF_PRO_SEQUENCE', TRUE)
		ON CONFLICT (indicator) DO UPDATE SET 
			confidence_score = 90,
			severity = 'HIGH',
			action = $2,
			updated_at = CURRENT_TIMESTAMP
	`, clientIP, action)

	if err != nil {
		log.Printf("[SequenceEngine] Failed to insert threat indicator: %v", err)
		return
	}

	// Correlate Incident
	correlateIncident(clientIP, "Sequence Anomaly", "SEQ-001")

	// Trigger sync so Envoy immediately bans the IP
	go syncDynamicWAFRules()
}

// Ingest access logs from Envoy
func ingestAccessLogTelemetry(w http.ResponseWriter, r *http.Request) {
	var payload AccessLogEntry
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if payload.ClientIP == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	payload.Timestamp = time.Now().Unix()

	window := getSequenceWindow(payload.ClientIP)
	window.mu.Lock()
	
	// Keep sliding window of last 15 requests
	window.Requests = append(window.Requests, payload)
	if len(window.Requests) > 15 {
		window.Requests = window.Requests[1:]
	}
	window.mu.Unlock()

	// Evaluate sequence rules asynchronously
	go evaluateSequenceAnomalies(payload.ClientIP, window)
	
	// Evaluate ATO asynchronously if token is present
	if payload.Token != "" && payload.Token != "-" {
		go evaluateAccountTakeover(payload.Token, payload.ClientIP)
	}

	// Phase 63: Ingest to Global DDoS Engine
	go ingestToDDoS(payload)

	w.WriteHeader(http.StatusOK)
}

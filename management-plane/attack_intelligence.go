package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// Attack Intelligence, Dynamic Confidence & Attack Campaign Correlation Models

type AttackTaxonomy struct {
	ID              int       `json:"id"`
	RuleID          int       `json:"rule_id"`
	Family          string    `json:"family"` // SQL_INJECTION, XSS, PATH_TRAVERSAL, RCE, SSRF, BOT
	Subtype         string    `json:"subtype"` // UNION_BASED, BOOLEAN_BASED, SCRIPT_TAG, JNDI_LOOKUP, etc.
	CWEID           string    `json:"cwe_id"`
	MITREAttackID   string    `json:"mitre_attack_id"` // e.g. T1190, T1059
	SeverityDefault string    `json:"severity_default"` // LOW, MEDIUM, HIGH, CRITICAL
	Description     string    `json:"description"`
	Remediation     string    `json:"remediation"`
	CreatedAt       time.Time `json:"created_at"`
}

type DynamicConfidenceRequest struct {
	RuleID          int    `json:"rule_id"`
	Method          string `json:"method"`
	Path            string `json:"path"`
	PayloadLocation string `json:"payload_location"` // BODY, QUERY, HEADER, COOKIE
	PayloadContent  string `json:"payload_content"`
	ClientIP        string `json:"client_ip"`
}

type DynamicConfidenceResult struct {
	RuleID            int      `json:"rule_id"`
	TaxonomyFamily    string   `json:"taxonomy_family"`
	TaxonomySubtype   string   `json:"taxonomy_subtype"`
	BaseConfidence    int      `json:"base_confidence"` // %
	AdjustedConfidence int     `json:"adjusted_confidence"` // %
	Severity          string   `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	RecommendedAction string   `json:"recommended_action"` // BLOCK, CHALLENGE, MONITOR
	ScoringFactors    []string `json:"scoring_factors"`
	EvaluatedAt       time.Time `json:"evaluated_at"`
}

type AttackCampaign struct {
	ID                 int               `json:"id"`
	CampaignCode       string            `json:"campaign_code"` // e.g. AC-1092
	SourceIP           string            `json:"source_ip"`
	TargetApp          string            `json:"target_app"`
	ThreatActorProfile string            `json:"threat_actor_profile"` // e.g. Automated Tool (Nikto/Sqlmap), APT-Like, Script Kiddie
	StagesObserved     []string          `json:"stages_observed"` // RECONNAISSANCE, PROBE, EXPLOITATION, EXFILTRATION
	TotalRequests      int               `json:"total_requests"`
	BlockedRequests    int               `json:"blocked_requests"`
	AllowedRequests    int               `json:"allowed_requests"`
	DurationSeconds    int               `json:"duration_seconds"`
	Status             string            `json:"status"` // ACTIVE, CONTAINED, RESOLVED
	CreatedAt          time.Time         `json:"created_at"`
	LastSeenAt         time.Time         `json:"last_seen_at"`
	Events             []CampaignEvent   `json:"events,omitempty"`
}

type CampaignEvent struct {
	ID          int       `json:"id"`
	CampaignID  int       `json:"campaign_id"`
	Stage       string    `json:"stage"` // RECONNAISSANCE, PROBE, EXPLOITATION, EXFILTRATION
	AttackType  string    `json:"attack_type"`
	RuleID      int       `json:"rule_id"`
	Endpoint    string    `json:"endpoint"`
	Method      string    `json:"method"`
	ActionTaken string    `json:"action_taken"` // BLOCK, CHALLENGE, ALLOW
	Timestamp   time.Time `json:"timestamp"`
}

// Database schema initialization
func initAttackIntelligenceSchema(database *sql.DB) {
	query := `
	CREATE TABLE IF NOT EXISTS attack_taxonomies (
		id SERIAL PRIMARY KEY,
		rule_id INT UNIQUE NOT NULL,
		family VARCHAR(50) NOT NULL,
		subtype VARCHAR(100) NOT NULL,
		cwe_id VARCHAR(50) NOT NULL,
		mitre_attack_id VARCHAR(50) NOT NULL,
		severity_default VARCHAR(20) NOT NULL DEFAULT 'HIGH',
		description TEXT NOT NULL,
		remediation TEXT NOT NULL,
		created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS attack_campaigns (
		id SERIAL PRIMARY KEY,
		campaign_code VARCHAR(50) UNIQUE NOT NULL,
		source_ip VARCHAR(50) NOT NULL,
		target_app VARCHAR(100) NOT NULL,
		threat_actor_profile VARCHAR(100) NOT NULL,
		stages_observed JSONB NOT NULL DEFAULT '[]',
		total_requests INT DEFAULT 1,
		blocked_requests INT DEFAULT 1,
		allowed_requests INT DEFAULT 0,
		duration_seconds INT DEFAULT 60,
		status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
		created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
		last_seen_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS campaign_events (
		id SERIAL PRIMARY KEY,
		campaign_id INT NOT NULL,
		stage VARCHAR(50) NOT NULL,
		attack_type VARCHAR(100) NOT NULL,
		rule_id INT NOT NULL,
		endpoint VARCHAR(255) NOT NULL,
		method VARCHAR(20) NOT NULL,
		action_taken VARCHAR(20) NOT NULL,
		timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
	);

	-- Seed comprehensive attack taxonomies
	INSERT INTO attack_taxonomies (rule_id, family, subtype, cwe_id, mitre_attack_id, severity_default, description, remediation)
	VALUES 
	(942100, 'SQL_INJECTION', 'UNION-Based Injection', 'CWE-89', 'T1190', 'CRITICAL', 'Attacker attempts to append results from adjacent database tables via UNION SELECT statements', 'Use parameterized queries / prepared statements. Disable raw string interpolation in ORM/SQL drivers.'),
	(942101, 'SQL_INJECTION', 'Boolean-Blind Injection', 'CWE-89', 'T1190', 'HIGH', 'Attacker enumerates database schema character-by-character using TRUE/FALSE conditionals', 'Enforce prepared statements and disable verbose database query error reporting in production.'),
	(941100, 'XSS', 'Script Tag Injection', 'CWE-79', 'T1059.007', 'HIGH', 'Malicious JavaScript payload delivered directly inside <script> tags for DOM execution', 'Implement strict Content Security Policy (CSP) and sanitize inputs using DOMPurify or server-side HTML entity encoding.'),
	(941101, 'XSS', 'Inline Event Handler Polyglot', 'CWE-79', 'T1059.007', 'HIGH', 'Execution via HTML attributes like onerror=, onload=, or autofocus without requiring script tags', 'Context-aware output escaping and disable dangerous attributes via CSP directives.'),
	(930100, 'PATH_TRAVERSAL', 'Dot-Dot-Slash (../) Traversal', 'CWE-22', 'T1083', 'CRITICAL', 'Directory traversal attempt to escape web root directory and read local system configuration', 'Normalize file paths using secure path resolution (filepath.Clean) and reject paths containing ../ or null bytes.'),
	(950001, 'SSRF', 'Cloud Instance Metadata Exfiltration', 'CWE-918', 'T1552.005', 'CRITICAL', 'Unauthorized request targeting 169.254.169.254 to steal AWS/GCP IAM role credentials and STS tokens', 'Enforce IMDSv2 with token hops restricted, and block outbound proxy connections to 169.254.0.0/16.'),
	(950003, 'RCE', 'Log4j JNDI Lookup Injection', 'CWE-94', 'T1190', 'CRITICAL', 'Zero-day remote code execution via ${jndi:ldap://...} lookup syntax in headers or body', 'Upgrade logging library to log4j >= 2.17.1 or set log4j2.formatMsgNoLookups=true system property.')
	ON CONFLICT (rule_id) DO NOTHING;

	-- Seed sample active attack campaign
	INSERT INTO attack_campaigns (campaign_code, source_ip, target_app, threat_actor_profile, stages_observed, total_requests, blocked_requests, allowed_requests, duration_seconds, status)
	VALUES 
	('AC-1092', '198.51.100.99', 'rms-core', 'Automated Penetration Scanner (Nikto / SQLmap)', '["RECONNAISSANCE", "PROBE", "EXPLOITATION"]', 482, 476, 6, 342, 'ACTIVE')
	ON CONFLICT (campaign_code) DO NOTHING;

	INSERT INTO campaign_events (campaign_id, stage, attack_type, rule_id, endpoint, method, action_taken)
	SELECT id, 'RECONNAISSANCE', 'Scanner Fingerprint Probe', 9901, '/robots.txt', 'GET', 'ALLOW'
	FROM attack_campaigns WHERE campaign_code = 'AC-1092' LIMIT 1
	ON CONFLICT DO NOTHING;

	INSERT INTO campaign_events (campaign_id, stage, attack_type, rule_id, endpoint, method, action_taken)
	SELECT id, 'PROBE', 'Sensitive Admin Path Enumeration', 9902, '/admin/config.php', 'GET', 'BLOCK'
	FROM attack_campaigns WHERE campaign_code = 'AC-1092' LIMIT 1
	ON CONFLICT DO NOTHING;

	INSERT INTO campaign_events (campaign_id, stage, attack_type, rule_id, endpoint, method, action_taken)
	SELECT id, 'EXPLOITATION', 'UNION-Based SQL Injection', 942100, '/api/customer', 'POST', 'BLOCK'
	FROM attack_campaigns WHERE campaign_code = 'AC-1092' LIMIT 1
	ON CONFLICT DO NOTHING;
	`

	_, err := database.Exec(query)
	if err != nil {
		log.Printf("Error initializing attack intelligence schema: %v", err)
	} else {
		log.Println("Attack Intelligence, Dynamic Confidence and Campaign Correlation schema initialized successfully")
	}
}

func registerAttackIntelligenceRoutes(r chi.Router) {
	// Pillar 7: Attack Taxonomy Hierarchy
	r.Get("/intelligence/taxonomy", getAttackTaxonomyHandler)
	r.Get("/intelligence/taxonomy/{rule_id}", resolveRuleTaxonomyHandler)

	// Pillar 8: Dynamic Confidence Scoring
	r.Post("/intelligence/calculate-confidence", calculateConfidenceHandler)

	// Pillar 9: Attack Campaign Correlation
	r.Get("/intelligence/campaigns", getAttackCampaignsHandler)
	r.Get("/intelligence/campaigns/{id}", getAttackCampaignDetailHandler)
	r.Post("/intelligence/campaigns/{id}/contain", containCampaignHandler)
}

// 1. GET /api/v1/intelligence/taxonomy
func getAttackTaxonomyHandler(w http.ResponseWriter, r *http.Request) {
	familyFilter := r.URL.Query().Get("family")

	query := `
		SELECT id, rule_id, family, subtype, cwe_id, mitre_attack_id, severity_default, description, remediation, created_at
		FROM attack_taxonomies
	`
	var rows *sql.Rows
	var err error

	if familyFilter != "" {
		query += " WHERE family = $1 ORDER BY rule_id ASC"
		rows, err = db.Query(query, familyFilter)
	} else {
		query += " ORDER BY family ASC, rule_id ASC"
		rows, err = db.Query(query)
	}

	if err != nil {
		http.Error(w, "Failed to query taxonomy", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	taxonomies := make([]AttackTaxonomy, 0)
	for rows.Next() {
		var at AttackTaxonomy
		if err := rows.Scan(&at.ID, &at.RuleID, &at.Family, &at.Subtype, &at.CWEID, &at.MITREAttackID, &at.SeverityDefault, &at.Description, &at.Remediation, &at.CreatedAt); err == nil {
			taxonomies = append(taxonomies, at)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(taxonomies)
}

// 2. GET /api/v1/intelligence/taxonomy/{rule_id}
func resolveRuleTaxonomyHandler(w http.ResponseWriter, r *http.Request) {
	ruleIDStr := chi.URLParam(r, "rule_id")
	ruleID, err := strconv.Atoi(ruleIDStr)
	if err != nil {
		http.Error(w, "Invalid rule ID", http.StatusBadRequest)
		return
	}

	var at AttackTaxonomy
	err = db.QueryRow(`
		SELECT id, rule_id, family, subtype, cwe_id, mitre_attack_id, severity_default, description, remediation, created_at
		FROM attack_taxonomies
		WHERE rule_id = $1
	`, ruleID).Scan(&at.ID, &at.RuleID, &at.Family, &at.Subtype, &at.CWEID, &at.MITREAttackID, &at.SeverityDefault, &at.Description, &at.Remediation, &at.CreatedAt)

	if err != nil {
		http.Error(w, "Rule taxonomy node not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(at)
}

// 3. POST /api/v1/intelligence/calculate-confidence
func calculateConfidenceHandler(w http.ResponseWriter, r *http.Request) {
	var req DynamicConfidenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	// Fetch taxonomy details for rule
	var family, subtype, severity string
	err := db.QueryRow(`
		SELECT family, subtype, severity_default
		FROM attack_taxonomies
		WHERE rule_id = $1
	`, req.RuleID).Scan(&family, &subtype, &severity)

	if err != nil {
		family = "CUSTOM_OR_GENERIC"
		subtype = "Signature Hit"
		severity = "MEDIUM"
	}

	baseConfidence := 60
	adjustedConfidence := baseConfidence
	factors := make([]string, 0)

	// Factor 1: Location of payload
	if req.PayloadLocation == "BODY" {
		adjustedConfidence += 20
		factors = append(factors, "+20% (Payload located inside POST/PUT request body with deliberate intent)")
	} else if req.PayloadLocation == "QUERY" {
		adjustedConfidence += 10
		factors = append(factors, "+10% (Payload located in query parameter string)")
	} else if req.PayloadLocation == "HEADER" {
		// Headers frequently have false positives (cookies, referers)
		adjustedConfidence -= 10
		factors = append(factors, "-10% (Payload located in header; prone to benign tracking tokens)")
	}

	// Factor 2: String length and syntax clarity
	if len(req.PayloadContent) > 25 {
		adjustedConfidence += 10
		factors = append(factors, "+10% (Substantial attack payload length > 25 bytes)")
	} else if len(req.PayloadContent) < 6 {
		adjustedConfidence -= 25
		factors = append(factors, "-25% (Extremely short trigger snippet < 6 chars; elevated false-positive risk)")
	}

	// Factor 3: Known exploit syntax triggers
	lowered := strings.ToLower(req.PayloadContent)
	if strings.Contains(lowered, "union select") || strings.Contains(lowered, "${jndi:") || strings.Contains(lowered, "../") || strings.Contains(lowered, "<script>") {
		adjustedConfidence += 15
		factors = append(factors, "+15% (Confirmed explicit exploit signature grammar detected)")
	}

	// Factor 4: Threat Intelligence / Malicious IP Check
	var isThreatIP bool
	_ = db.QueryRow("SELECT EXISTS(SELECT 1 FROM blocked_ips WHERE ip_address = $1)", req.ClientIP).Scan(&isThreatIP)
	if isThreatIP {
		adjustedConfidence += 20
		factors = append(factors, "+20% (Origin IP has active record in threat intelligence blocklist)")
	}

	// Clamp confidence to [1, 99]%
	if adjustedConfidence > 99 {
		adjustedConfidence = 99
	}
	if adjustedConfidence < 1 {
		adjustedConfidence = 1
	}

	// Determine mitigation action
	recommendedAction := "MONITOR"
	if adjustedConfidence >= 85 {
		recommendedAction = "BLOCK"
	} else if adjustedConfidence >= 50 {
		recommendedAction = "CHALLENGE"
	}

	res := DynamicConfidenceResult{
		RuleID:             req.RuleID,
		TaxonomyFamily:     family,
		TaxonomySubtype:    subtype,
		BaseConfidence:     baseConfidence,
		AdjustedConfidence: adjustedConfidence,
		Severity:           severity,
		RecommendedAction:  recommendedAction,
		ScoringFactors:     factors,
		EvaluatedAt:        time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// 4. GET /api/v1/intelligence/campaigns
func getAttackCampaignsHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT id, campaign_code, source_ip, target_app, threat_actor_profile, stages_observed, total_requests, blocked_requests, allowed_requests, duration_seconds, status, created_at, last_seen_at
		FROM attack_campaigns
		ORDER BY id DESC
	`)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	campaigns := make([]AttackCampaign, 0)
	for rows.Next() {
		var c AttackCampaign
		var stagesJSON []byte
		if err := rows.Scan(&c.ID, &c.CampaignCode, &c.SourceIP, &c.TargetApp, &c.ThreatActorProfile, &stagesJSON, &c.TotalRequests, &c.BlockedRequests, &c.AllowedRequests, &c.DurationSeconds, &c.Status, &c.CreatedAt, &c.LastSeenAt); err == nil {
			_ = json.Unmarshal(stagesJSON, &c.StagesObserved)
			campaigns = append(campaigns, c)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(campaigns)
}

// 5. GET /api/v1/intelligence/campaigns/{id}
func getAttackCampaignDetailHandler(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	campaignID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid campaign ID", http.StatusBadRequest)
		return
	}

	var c AttackCampaign
	var stagesJSON []byte
	err = db.QueryRow(`
		SELECT id, campaign_code, source_ip, target_app, threat_actor_profile, stages_observed, total_requests, blocked_requests, allowed_requests, duration_seconds, status, created_at, last_seen_at
		FROM attack_campaigns
		WHERE id = $1
	`, campaignID).Scan(&c.ID, &c.CampaignCode, &c.SourceIP, &c.TargetApp, &c.ThreatActorProfile, &stagesJSON, &c.TotalRequests, &c.BlockedRequests, &c.AllowedRequests, &c.DurationSeconds, &c.Status, &c.CreatedAt, &c.LastSeenAt)

	if err != nil {
		http.Error(w, "Campaign not found", http.StatusNotFound)
		return
	}
	_ = json.Unmarshal(stagesJSON, &c.StagesObserved)

	// Fetch timeline events
	eventRows, err := db.Query(`
		SELECT id, campaign_id, stage, attack_type, rule_id, endpoint, method, action_taken, timestamp
		FROM campaign_events
		WHERE campaign_id = $1
		ORDER BY timestamp ASC
	`, campaignID)
	if err == nil {
		defer eventRows.Close()
		events := make([]CampaignEvent, 0)
		for eventRows.Next() {
			var ev CampaignEvent
			if err := eventRows.Scan(&ev.ID, &ev.CampaignID, &ev.Stage, &ev.AttackType, &ev.RuleID, &ev.Endpoint, &ev.Method, &ev.ActionTaken, &ev.Timestamp); err == nil {
				events = append(events, ev)
			}
		}
		c.Events = events
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(c)
}

// 6. POST /api/v1/intelligence/campaigns/{id}/contain
func containCampaignHandler(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	campaignID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid campaign ID", http.StatusBadRequest)
		return
	}

	var sourceIP string
	var code string
	err = db.QueryRow(`
		UPDATE attack_campaigns
		SET status = 'CONTAINED'
		WHERE id = $1
		RETURNING source_ip, campaign_code
	`, campaignID).Scan(&sourceIP, &code)

	if err != nil {
		http.Error(w, "Campaign not found", http.StatusNotFound)
		return
	}

	// Automatically add source IP to emergency blocked_ips table
	_, _ = db.Exec(`
		INSERT INTO blocked_ips (ip_address, reason)
		VALUES ($1, $2)
		ON CONFLICT (ip_address) DO UPDATE SET reason = EXCLUDED.reason
	`, sourceIP, fmt.Sprintf("Auto-Contained from Attack Campaign %s", code))

	recordAuditLog("soc-lead", "CONTAIN_ATTACK_CAMPAIGN", "ATTACK_CAMPAIGN", code, fmt.Sprintf("Auto-contained campaign %s. Attacker IP %s added to emergency blocklist.", code, sourceIP), r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"campaign_id": campaignID,
		"code":        code,
		"source_ip":   sourceIP,
		"status":      "CONTAINED",
		"message":     fmt.Sprintf("Campaign %s successfully contained. Source IP %s permanently blocked across all clusters.", code, sourceIP),
	})
}

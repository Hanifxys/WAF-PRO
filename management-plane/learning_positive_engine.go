package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// WAF Learning Mode 2.0 & Positive Security Model

type LearningProfile struct {
	AppID              string              `json:"app_id"`
	Status             string              `json:"status"` // NOT_PROFILED, LEARNING, READY_FOR_REVIEW, ENFORCED
	TotalRequestsSeen  int                 `json:"total_requests_seen"`
	EndpointsCount     int                 `json:"endpoints_count"`
	MethodsObserved    []string            `json:"methods_observed"`
	ContentTypesSeen   []string            `json:"content_types_seen"`
	MaxBodyBytesSeen   int                 `json:"max_body_bytes_seen"`
	SensitiveEndpoints []string            `json:"sensitive_endpoints"`
	DiscoveredParams   map[string][]string `json:"discovered_params"` // endpoint -> list of params
	StartedAt          time.Time           `json:"started_at"`
	UpdatedAt          time.Time           `json:"updated_at"`
}

type LearningObservation struct {
	AppID       string            `json:"app_id"`
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	ContentType string            `json:"content_type"`
	BodyBytes   int               `json:"body_bytes"`
	Params      map[string]string `json:"params"`
	ClientIP    string            `json:"client_ip"`
}

type SuggestedPolicy struct {
	AppID             string             `json:"app_id"`
	GeneratedAt       time.Time          `json:"generated_at"`
	Status            string             `json:"status"` // PENDING_REVIEW, APPROVED, ENFORCED
	AllowedMethods    []string           `json:"allowed_methods"`
	AllowedContentTypes []string         `json:"allowed_content_types"`
	MaxBodyBytesLimit int                `json:"max_body_bytes_limit"`
	Controls          []SuggestedControl `json:"controls"`
}

type SuggestedControl struct {
	ControlID   string `json:"control_id"`
	Category    string `json:"category"` // PROTOCOL, API_SECURITY, DOS_PROTECTION, BOT
	Description string `json:"description"`
	Action      string `json:"action"` // BLOCK, RATE_LIMIT, CHALLENGE, MONITOR
	Target      string `json:"target"`
	IsSelected  bool   `json:"is_selected"`
}

type PositiveSecuritySchema struct {
	ID                           int      `json:"id"`
	AppID                        string   `json:"app_id"`
	Endpoint                     string   `json:"endpoint"`
	Method                       string   `json:"method"`
	AllowedContentTypes          []string `json:"allowed_content_types"`
	MaxBodyBytes                 int      `json:"max_body_bytes"`
	RequiredFields               []string `json:"required_fields"`
	AllowedFields                []string `json:"allowed_fields"`
	DisallowAdditionalProperties bool     `json:"disallow_additional_properties"`
	IsActive                     bool     `json:"is_active"`
	CreatedAt                    time.Time `json:"created_at"`
}

type PositiveValidationRequest struct {
	AppID       string                 `json:"app_id"`
	Endpoint    string                 `json:"endpoint"`
	Method      string                 `json:"method"`
	ContentType string                 `json:"content_type"`
	BodyJSON    map[string]interface{} `json:"body_json"`
	RawBodyLen  int                    `json:"raw_body_len"`
}

type PositiveValidationResponse struct {
	IsValid     bool     `json:"is_valid"`
	Decision    string   `json:"decision"` // ALLOW or BLOCK
	Violations  []string `json:"violations,omitempty"`
	Reason      string   `json:"reason"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// Database schema initialization
func initLearningPositiveSchema(database *sql.DB) {
	query := `
	CREATE TABLE IF NOT EXISTS learning_profiles (
		app_id VARCHAR(100) PRIMARY KEY,
		status VARCHAR(50) NOT NULL DEFAULT 'LEARNING',
		total_requests_seen INT DEFAULT 0,
		endpoints_count INT DEFAULT 0,
		methods_observed TEXT[] DEFAULT '{}',
		content_types_seen TEXT[] DEFAULT '{}',
		max_body_bytes_seen INT DEFAULT 0,
		sensitive_endpoints TEXT[] DEFAULT '{}',
		discovered_params JSONB DEFAULT '{}',
		started_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS suggested_learning_policies (
		id SERIAL PRIMARY KEY,
		app_id VARCHAR(100) NOT NULL,
		status VARCHAR(30) NOT NULL DEFAULT 'PENDING_REVIEW',
		allowed_methods TEXT[] NOT NULL,
		allowed_content_types TEXT[] NOT NULL,
		max_body_bytes_limit INT NOT NULL,
		controls JSONB NOT NULL,
		created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
		enforced_at TIMESTAMPTZ
	);

	CREATE TABLE IF NOT EXISTS positive_security_schemas (
		id SERIAL PRIMARY KEY,
		app_id VARCHAR(100) NOT NULL,
		endpoint VARCHAR(255) NOT NULL,
		method VARCHAR(20) NOT NULL,
		allowed_content_types TEXT[] NOT NULL,
		max_body_bytes INT NOT NULL DEFAULT 10240,
		required_fields TEXT[] NOT NULL,
		allowed_fields TEXT[] NOT NULL,
		disallow_additional_properties BOOLEAN NOT NULL DEFAULT TRUE,
		is_active BOOLEAN NOT NULL DEFAULT TRUE,
		created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
	);

	-- Seed sample active positive security schema
	INSERT INTO positive_security_schemas (app_id, endpoint, method, allowed_content_types, max_body_bytes, required_fields, allowed_fields, disallow_additional_properties, is_active)
	VALUES 
	('rms-core', '/api/payment', 'POST', ARRAY['application/json'], 10240, ARRAY['amount', 'currency', 'customerId'], ARRAY['amount', 'currency', 'customerId'], TRUE, TRUE),
	('rms-core', '/api/v1/auth/login', 'POST', ARRAY['application/json'], 4096, ARRAY['username', 'password'], ARRAY['username', 'password', 'remember_me'], TRUE, TRUE)
	ON CONFLICT DO NOTHING;

	-- Seed learning profile for rms-core
	INSERT INTO learning_profiles (app_id, status, total_requests_seen, endpoints_count, methods_observed, content_types_seen, max_body_bytes_seen, sensitive_endpoints, discovered_params)
	VALUES 
	('rms-core', 'READY_FOR_REVIEW', 1450, 6, ARRAY['GET', 'POST'], ARRAY['application/json'], 8192, ARRAY['/admin', '/api/v1/auth/login', '/metrics'], '{"/api/payment": ["amount", "currency", "customerId"], "/api/v1/auth/login": ["username", "password"]}')
	ON CONFLICT (app_id) DO NOTHING;
	`

	_, err := database.Exec(query)
	if err != nil {
		log.Printf("Error initializing learning positive schema: %v", err)
	} else {
		log.Println("WAF Learning Mode 2.0 and Positive Security schema initialized successfully")
	}
}

func registerLearningPositiveRoutes(r chi.Router) {
	// Learning Mode 2.0
	r.Post("/learning/{app_id}/start", startLearningHandler)
	r.Post("/learning/{app_id}/observe", ingestObservationHandler)
	r.Get("/learning/{app_id}/profile", getLearningProfileHandler)
	r.Post("/learning/{app_id}/generate-policy", generateSuggestedPolicyHandler)
	r.Post("/learning/{app_id}/approve-policy", approveSuggestedPolicyHandler)

	// Positive Security Model
	r.Get("/positive-security/{app_id}/schemas", getPositiveSchemasHandler)
	r.Post("/positive-security/{app_id}/schemas", createPositiveSchemaHandler)
	r.Post("/positive-security/validate", validatePositiveSecurityHandler)
}

// 1. POST /api/v1/learning/{app_id}/start
func startLearningHandler(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "app_id")
	if appID == "" {
		http.Error(w, "App ID is required", http.StatusBadRequest)
		return
	}

	_, err := db.Exec(`
		INSERT INTO learning_profiles (app_id, status, total_requests_seen, endpoints_count, methods_observed, content_types_seen, max_body_bytes_seen, sensitive_endpoints, discovered_params, started_at, updated_at)
		VALUES ($1, 'LEARNING', 0, 0, '{}', '{}', 0, '{}', '{}', NOW(), NOW())
		ON CONFLICT (app_id) DO UPDATE SET
			status = 'LEARNING',
			updated_at = NOW()
	`, appID)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	recordAuditLog("sec-admin", "START_WAF_LEARNING_MODE", "APPLICATION", appID, fmt.Sprintf("Started self-profiling learning mode for application %s", appID), r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"app_id":  appID,
		"status":  "LEARNING",
		"message": fmt.Sprintf("Application %s is now in WAF Learning Mode 2.0. Traffic patterns are being observed.", appID),
	})
}

// 2. POST /api/v1/learning/{app_id}/observe
func ingestObservationHandler(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "app_id")
	var req LearningObservation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid observation payload", http.StatusBadRequest)
		return
	}

	// Fetch current profile
	var profile LearningProfile
	var methods, contentTypes, sensitive []string
	var methodsJSON, ctsJSON, sensJSON, discoveredParamsJSON []byte

	err := db.QueryRow(`
		SELECT app_id, status, total_requests_seen, endpoints_count, COALESCE(array_to_json(methods_observed), '[]'::json), COALESCE(array_to_json(content_types_seen), '[]'::json), max_body_bytes_seen, COALESCE(array_to_json(sensitive_endpoints), '[]'::json), discovered_params
		FROM learning_profiles
		WHERE app_id = $1
	`, appID).Scan(&profile.AppID, &profile.Status, &profile.TotalRequestsSeen, &profile.EndpointsCount, &methodsJSON, &ctsJSON, &profile.MaxBodyBytesSeen, &sensJSON, &discoveredParamsJSON)

	if err != nil {
		http.Error(w, "Learning profile not found, please start learning first", http.StatusNotFound)
		return
	}

	_ = json.Unmarshal(methodsJSON, &methods)
	_ = json.Unmarshal(ctsJSON, &contentTypes)
	_ = json.Unmarshal(sensJSON, &sensitive)

	// Update observed methods
	methodMap := make(map[string]bool)
	for _, m := range methods {
		methodMap[m] = true
	}
	if req.Method != "" {
		methodMap[req.Method] = true
	}
	updatedMethods := make([]string, 0, len(methodMap))
	for m := range methodMap {
		updatedMethods = append(updatedMethods, m)
	}

	// Update observed content types
	ctMap := make(map[string]bool)
	for _, ct := range contentTypes {
		ctMap[ct] = true
	}
	if req.ContentType != "" {
		ctMap[req.ContentType] = true
	}
	updatedCTs := make([]string, 0, len(ctMap))
	for ct := range ctMap {
		updatedCTs = append(updatedCTs, ct)
	}

	// Update sensitive endpoints
	sensMap := make(map[string]bool)
	for _, s := range sensitive {
		sensMap[s] = true
	}
	if strings.Contains(req.Path, "admin") || strings.Contains(req.Path, "login") || strings.Contains(req.Path, "metrics") {
		sensMap[req.Path] = true
	}
	updatedSens := make([]string, 0, len(sensMap))
	for s := range sensMap {
		updatedSens = append(updatedSens, s)
	}

	// Update max body bytes
	newMaxBody := profile.MaxBodyBytesSeen
	if req.BodyBytes > newMaxBody {
		newMaxBody = req.BodyBytes
	}

	// Update discovered parameters
	var paramsMap map[string][]string
	if len(discoveredParamsJSON) > 0 {
		_ = json.Unmarshal(discoveredParamsJSON, &paramsMap)
	}
	if paramsMap == nil {
		paramsMap = make(map[string][]string)
	}
	if len(req.Params) > 0 {
		existing := paramsMap[req.Path]
		pSet := make(map[string]bool)
		for _, p := range existing {
			pSet[p] = true
		}
		for p := range req.Params {
			pSet[p] = true
		}
		newParams := make([]string, 0, len(pSet))
		for p := range pSet {
			newParams = append(newParams, p)
		}
		paramsMap[req.Path] = newParams
	}

	newParamsJSON, _ := json.Marshal(paramsMap)

	// Save back to DB
	_, _ = db.Exec(`
		UPDATE learning_profiles
		SET total_requests_seen = total_requests_seen + 1,
		    endpoints_count = (SELECT count(distinct key) FROM jsonb_each($1::jsonb)),
		    methods_observed = $2,
		    content_types_seen = $3,
		    max_body_bytes_seen = $4,
		    sensitive_endpoints = $5,
		    discovered_params = $1::jsonb,
		    updated_at = NOW()
		WHERE app_id = $6
	`, string(newParamsJSON), updatedMethods, updatedCTs, newMaxBody, updatedSens, appID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"app_id":  appID,
		"status":  "OBSERVED",
		"message": "Traffic event successfully ingested into Learning Model",
	})
}

// 3. GET /api/v1/learning/{app_id}/profile
func getLearningProfileHandler(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "app_id")

	var profile LearningProfile
	var methods, contentTypes, sensitive []string
	var methodsJSON, ctsJSON, sensJSON, discoveredParamsJSON []byte

	err := db.QueryRow(`
		SELECT app_id, status, total_requests_seen, endpoints_count, COALESCE(array_to_json(methods_observed), '[]'::json), COALESCE(array_to_json(content_types_seen), '[]'::json), max_body_bytes_seen, COALESCE(array_to_json(sensitive_endpoints), '[]'::json), discovered_params, started_at, updated_at
		FROM learning_profiles
		WHERE app_id = $1
	`, appID).Scan(&profile.AppID, &profile.Status, &profile.TotalRequestsSeen, &profile.EndpointsCount, &methodsJSON, &ctsJSON, &profile.MaxBodyBytesSeen, &sensJSON, &discoveredParamsJSON, &profile.StartedAt, &profile.UpdatedAt)

	if err != nil {
		http.Error(w, "Profile not found", http.StatusNotFound)
		return
	}

	_ = json.Unmarshal(methodsJSON, &methods)
	_ = json.Unmarshal(ctsJSON, &contentTypes)
	_ = json.Unmarshal(sensJSON, &sensitive)

	profile.MethodsObserved = methods
	profile.ContentTypesSeen = contentTypes
	profile.SensitiveEndpoints = sensitive
	if len(discoveredParamsJSON) > 0 {
		_ = json.Unmarshal(discoveredParamsJSON, &profile.DiscoveredParams)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}

// 4. POST /api/v1/learning/{app_id}/generate-policy
func generateSuggestedPolicyHandler(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "app_id")

	var profile LearningProfile
	var methods, contentTypes, sensitive []string
	var methodsJSON, ctsJSON, sensJSON, discoveredParamsJSON []byte

	err := db.QueryRow(`
		SELECT app_id, status, total_requests_seen, endpoints_count, COALESCE(array_to_json(methods_observed), '[]'::json), COALESCE(array_to_json(content_types_seen), '[]'::json), max_body_bytes_seen, COALESCE(array_to_json(sensitive_endpoints), '[]'::json), discovered_params
		FROM learning_profiles
		WHERE app_id = $1
	`, appID).Scan(&profile.AppID, &profile.Status, &profile.TotalRequestsSeen, &profile.EndpointsCount, &methodsJSON, &ctsJSON, &profile.MaxBodyBytesSeen, &sensJSON, &discoveredParamsJSON)

	if err != nil {
		http.Error(w, "Profile not found", http.StatusNotFound)
		return
	}

	_ = json.Unmarshal(methodsJSON, &methods)
	_ = json.Unmarshal(ctsJSON, &contentTypes)
	_ = json.Unmarshal(sensJSON, &sensitive)

	// Synthesize suggested controls based on observations
	controls := make([]SuggestedControl, 0)

	// Control 1: Restrict HTTP methods
	if len(methods) > 0 {
		controls = append(controls, SuggestedControl{
			ControlID:   "POL-RESTRICT-VERBS",
			Category:    "PROTOCOL",
			Description: fmt.Sprintf("Restrict HTTP verbs strictly to observed methods (%s), blocking TRACE/CONNECT/PUT/DELETE", strings.Join(methods, ", ")),
			Action:      "BLOCK",
			Target:      "GLOBAL",
			IsSelected:  true,
		})
	}

	// Control 2: Restrict Content Types
	if len(contentTypes) > 0 {
		controls = append(controls, SuggestedControl{
			ControlID:   "POL-RESTRICT-CONTENT-TYPE",
			Category:    "API_SECURITY",
			Description: fmt.Sprintf("Disallow unexpected MIME types, enforce: %s", strings.Join(contentTypes, ", ")),
			Action:      "BLOCK",
			Target:      "GLOBAL",
			IsSelected:  true,
		})
	}

	// Control 3: Protect sensitive endpoints
	for _, sens := range sensitive {
		if strings.Contains(sens, "admin") {
			controls = append(controls, SuggestedControl{
				ControlID:   "POL-PROTECT-ADMIN",
				Category:    "ACCESS_CONTROL",
				Description: fmt.Sprintf("Apply MFA/IP Restriction and alert on access to %s", sens),
				Action:      "CHALLENGE",
				Target:      sens,
				IsSelected:  true,
			})
		}
		if strings.Contains(sens, "login") || strings.Contains(sens, "auth") {
			controls = append(controls, SuggestedControl{
				ControlID:   "POL-RATELIMIT-LOGIN",
				Category:    "DOS_PROTECTION",
				Description: fmt.Sprintf("Enforce strict 10 requests/minute rate limit on %s to defeat brute force", sens),
				Action:      "RATE_LIMIT",
				Target:      sens,
				IsSelected:  true,
			})
		}
	}

	// Control 4: Generate Positive Security Schema for discovered POST endpoints
	var paramsMap map[string][]string
	if len(discoveredParamsJSON) > 0 {
		_ = json.Unmarshal(discoveredParamsJSON, &paramsMap)
	}
	for path, params := range paramsMap {
		controls = append(controls, SuggestedControl{
			ControlID:   fmt.Sprintf("POL-POSITIVE-SCHEMA-%s", strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "-")),
			Category:    "API_SECURITY",
			Description: fmt.Sprintf("Enforce Positive Security Schema on %s with allowed fields: [%s]", path, strings.Join(params, ", ")),
			Action:      "BLOCK",
			Target:      path,
			IsSelected:  true,
		})
	}

	maxLimit := profile.MaxBodyBytesSeen * 2
	if maxLimit < 10240 {
		maxLimit = 10240
	}

	controlsJSON, _ := json.Marshal(controls)

	var insertedID int
	_ = db.QueryRow(`
		INSERT INTO suggested_learning_policies (app_id, status, allowed_methods, allowed_content_types, max_body_bytes_limit, controls)
		VALUES ($1, 'PENDING_REVIEW', $2, $3, $4, $5)
		RETURNING id
	`, appID, methods, contentTypes, maxLimit, string(controlsJSON)).Scan(&insertedID)

	_, _ = db.Exec("UPDATE learning_profiles SET status = 'READY_FOR_REVIEW' WHERE app_id = $1", appID)

	resp := SuggestedPolicy{
		AppID:               appID,
		GeneratedAt:         time.Now(),
		Status:              "PENDING_REVIEW",
		AllowedMethods:      methods,
		AllowedContentTypes: contentTypes,
		MaxBodyBytesLimit:   maxLimit,
		Controls:            controls,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// 5. POST /api/v1/learning/{app_id}/approve-policy
func approveSuggestedPolicyHandler(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "app_id")

	// Update status
	_, err := db.Exec(`
		UPDATE suggested_learning_policies
		SET status = 'ENFORCED', enforced_at = NOW()
		WHERE app_id = $1 AND status = 'PENDING_REVIEW'
	`, appID)

	if err != nil {
		http.Error(w, "Failed to approve policy", http.StatusInternalServerError)
		return
	}

	_, _ = db.Exec("UPDATE learning_profiles SET status = 'ENFORCED', updated_at = NOW() WHERE app_id = $1", appID)

	recordAuditLog("soc-manager", "APPROVE_LEARNING_POLICY", "SECURITY_POLICY", appID, fmt.Sprintf("Approved and enforced Suggested Policy for app %s", appID), r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"app_id":  appID,
		"status":  "ENFORCED",
		"message": fmt.Sprintf("Suggested policy for application %s has been approved and deployed to production WAF.", appID),
	})
}

// --- Positive Security Model Handlers ---

// 6. GET /api/v1/positive-security/{app_id}/schemas
func getPositiveSchemasHandler(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "app_id")

	rows, err := db.Query(`
		SELECT id, app_id, endpoint, method, COALESCE(array_to_json(allowed_content_types), '[]'::json), max_body_bytes, COALESCE(array_to_json(required_fields), '[]'::json), COALESCE(array_to_json(allowed_fields), '[]'::json), disallow_additional_properties, is_active, created_at
		FROM positive_security_schemas
		WHERE app_id = $1 OR app_id = '*'
		ORDER BY id ASC
	`, appID)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	schemas := make([]PositiveSecuritySchema, 0)
	for rows.Next() {
		var s PositiveSecuritySchema
		var ctsJSON, reqFieldsJSON, allowFieldsJSON []byte
		if err := rows.Scan(&s.ID, &s.AppID, &s.Endpoint, &s.Method, &ctsJSON, &s.MaxBodyBytes, &reqFieldsJSON, &allowFieldsJSON, &s.DisallowAdditionalProperties, &s.IsActive, &s.CreatedAt); err == nil {
			_ = json.Unmarshal(ctsJSON, &s.AllowedContentTypes)
			_ = json.Unmarshal(reqFieldsJSON, &s.RequiredFields)
			_ = json.Unmarshal(allowFieldsJSON, &s.AllowedFields)
			schemas = append(schemas, s)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(schemas)
}

// 7. POST /api/v1/positive-security/{app_id}/schemas
func createPositiveSchemaHandler(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "app_id")
	var req PositiveSecuritySchema
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	req.AppID = appID
	if req.MaxBodyBytes == 0 {
		req.MaxBodyBytes = 10240 // 10 KB default
	}

	var newID int
	err := db.QueryRow(`
		INSERT INTO positive_security_schemas (app_id, endpoint, method, allowed_content_types, max_body_bytes, required_fields, allowed_fields, disallow_additional_properties, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE)
		RETURNING id
	`, req.AppID, req.Endpoint, req.Method, req.AllowedContentTypes, req.MaxBodyBytes, req.RequiredFields, req.AllowedFields, req.DisallowAdditionalProperties).Scan(&newID)

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to insert schema: %v", err), http.StatusBadRequest)
		return
	}

	req.ID = newID
	req.IsActive = true

	recordAuditLog("sec-admin", "CREATE_POSITIVE_SCHEMA", "API_SECURITY", fmt.Sprintf("%d", newID), fmt.Sprintf("Registered Positive Security Schema on %s %s (Disallow Wildcards: %v)", req.Method, req.Endpoint, req.DisallowAdditionalProperties), r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(req)
}

// 8. POST /api/v1/positive-security/validate
func validatePositiveSecurityHandler(w http.ResponseWriter, r *http.Request) {
	var req PositiveValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid validation payload", http.StatusBadRequest)
		return
	}

	var s PositiveSecuritySchema
	var ctsJSON, reqFieldsJSON, allowFieldsJSON []byte

	err := db.QueryRow(`
		SELECT id, app_id, endpoint, method, COALESCE(array_to_json(allowed_content_types), '[]'::json), max_body_bytes, COALESCE(array_to_json(required_fields), '[]'::json), COALESCE(array_to_json(allowed_fields), '[]'::json), disallow_additional_properties, is_active
		FROM positive_security_schemas
		WHERE (app_id = $1 OR app_id = '*') AND endpoint = $2 AND (method = $3 OR method = 'ANY') AND is_active = TRUE
		LIMIT 1
	`, req.AppID, req.Endpoint, req.Method).Scan(&s.ID, &s.AppID, &s.Endpoint, &s.Method, &ctsJSON, &s.MaxBodyBytes, &reqFieldsJSON, &allowFieldsJSON, &s.DisallowAdditionalProperties, &s.IsActive)

	if err != nil {
		// No strict positive schema registered for this endpoint -> pass to other tiers
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PositiveValidationResponse{
			IsValid:     true,
			Decision:    "ALLOW",
			Reason:      "No Positive Security Schema enforced on this endpoint; request permitted",
			EvaluatedAt: time.Now(),
		})
		return
	}

	_ = json.Unmarshal(ctsJSON, &s.AllowedContentTypes)
	_ = json.Unmarshal(reqFieldsJSON, &s.RequiredFields)
	_ = json.Unmarshal(allowFieldsJSON, &s.AllowedFields)

	violations := make([]string, 0)

	// Check 1: Max Body Size
	if req.RawBodyLen > s.MaxBodyBytes {
		violations = append(violations, fmt.Sprintf("Payload size (%d bytes) exceeds strict limit of %d bytes", req.RawBodyLen, s.MaxBodyBytes))
	}

	// Check 2: Content-Type match
	ctAllowed := false
	for _, ct := range s.AllowedContentTypes {
		if strings.Contains(strings.ToLower(req.ContentType), strings.ToLower(ct)) {
			ctAllowed = true
			break
		}
	}
	if !ctAllowed && req.ContentType != "" {
		violations = append(violations, fmt.Sprintf("Disallowed Content-Type '%s'; expected one of: %s", req.ContentType, strings.Join(s.AllowedContentTypes, ", ")))
	}

	// Check 3: Required Fields
	for _, rf := range s.RequiredFields {
		if _, exists := req.BodyJSON[rf]; !exists {
			violations = append(violations, fmt.Sprintf("Missing mandatory field '%s'", rf))
		}
	}

	// Check 4: Disallow Additional Properties (Wildcard Injection Defense!)
	if s.DisallowAdditionalProperties {
		allowedSet := make(map[string]bool)
		for _, af := range s.AllowedFields {
			allowedSet[af] = true
		}
		for field := range req.BodyJSON {
			if !allowedSet[field] {
				violations = append(violations, fmt.Sprintf("Unauthorized injected property '%s' rejected by Positive Security Policy", field))
			}
		}
	}

	isValid := len(violations) == 0
	decision := "ALLOW"
	reason := "Payload strictly conformant with Positive Security Schema"
	if !isValid {
		decision = "BLOCK"
		reason = fmt.Sprintf("Positive Security Violation: %s", strings.Join(violations, "; "))
	}

	w.Header().Set("Content-Type", "application/json")
	if !isValid {
		w.WriteHeader(http.StatusForbidden)
	}
	json.NewEncoder(w).Encode(PositiveValidationResponse{
		IsValid:     isValid,
		Decision:    decision,
		Violations:  violations,
		Reason:      reason,
		EvaluatedAt: time.Now(),
	})
}

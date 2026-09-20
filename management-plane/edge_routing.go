package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// Phase 75: Global Edge Routing Models

type EdgeEndpoint struct {
	ID                int       `json:"id"`
	PoolID            int       `json:"pool_id"`
	Region            string    `json:"region"`
	Address           string    `json:"address"`
	Weight            int       `json:"weight"`
	Priority          int       `json:"priority"` // 1 = Primary, 2 = Failover/DR
	HealthStatus      string    `json:"health_status"` // HEALTHY, DEGRADED, UNHEALTHY
	MaintenanceMode   bool      `json:"maintenance_mode"`
	Draining          bool      `json:"draining"`
	MaxConnections    int       `json:"max_connections"`
	ActiveConnections int       `json:"active_connections"`
	LatencyMs         int       `json:"latency_ms"`
	CreatedAt         time.Time `json:"created_at"`
}

type EdgeOriginPool struct {
	ID                  int            `json:"id"`
	Name                string         `json:"name"`
	Domain              string         `json:"domain"`
	HealthCheckPath     string         `json:"health_check_path"`
	HealthCheckInterval int            `json:"health_check_interval"`
	Status              string         `json:"status"` // HEALTHY, DEGRADED, FAILOVER_ACTIVE
	Endpoints           []EdgeEndpoint `json:"endpoints"`
	CreatedAt           time.Time      `json:"created_at"`
}

type EdgeRoutingPolicy struct {
	ID                  int       `json:"id"`
	Name                string    `json:"name"`
	Domain              string    `json:"domain"`
	Strategy            string    `json:"strategy"` // GEO_LATENCY, FAILOVER_ACTIVE_PASSIVE, ROUND_ROBIN, WEIGHTED
	FallbackRegion      string    `json:"fallback_region"`
	ConnectionTimeoutMs int       `json:"connection_timeout_ms"`
	IdleTimeoutMs       int       `json:"idle_timeout_ms"`
	MaxRetries          int       `json:"max_retries"`
	MaintenanceMode     bool      `json:"maintenance_mode"`
	MaintenancePageHTML string    `json:"maintenance_page_html"`
	CreatedAt           time.Time `json:"created_at"`
}

type EdgeHealthSummary struct {
	TotalPools           int            `json:"total_pools"`
	TotalEndpoints       int            `json:"total_endpoints"`
	HealthyEndpoints     int            `json:"healthy_endpoints"`
	DrainingEndpoints    int            `json:"draining_endpoints"`
	MaintenanceEndpoints int            `json:"maintenance_endpoints"`
	ActiveConnections    int            `json:"active_connections"`
	FailoverActiveCount  int            `json:"failover_active_count"`
	RegionalHealth       map[string]int `json:"regional_health"` // region -> latency ms
}

func initEdgeRoutingSchema(database *sql.DB) {
	query := `
	CREATE TABLE IF NOT EXISTS edge_origin_pools (
		id SERIAL PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		domain VARCHAR(255) NOT NULL,
		health_check_path VARCHAR(255) NOT NULL DEFAULT '/healthz',
		health_check_interval INT NOT NULL DEFAULT 10,
		status VARCHAR(50) NOT NULL DEFAULT 'HEALTHY',
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS edge_endpoints (
		id SERIAL PRIMARY KEY,
		pool_id INT NOT NULL,
		region VARCHAR(100) NOT NULL,
		address VARCHAR(255) NOT NULL,
		weight INT NOT NULL DEFAULT 100,
		priority INT NOT NULL DEFAULT 1,
		health_status VARCHAR(50) NOT NULL DEFAULT 'HEALTHY',
		maintenance_mode BOOLEAN NOT NULL DEFAULT FALSE,
		draining BOOLEAN NOT NULL DEFAULT FALSE,
		max_connections INT NOT NULL DEFAULT 10000,
		active_connections INT NOT NULL DEFAULT 0,
		latency_ms INT NOT NULL DEFAULT 15,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS edge_routing_policies (
		id SERIAL PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		domain VARCHAR(255) NOT NULL UNIQUE,
		strategy VARCHAR(50) NOT NULL DEFAULT 'GEO_LATENCY',
		fallback_region VARCHAR(100) NOT NULL DEFAULT 'Singapore (ap-southeast-1)',
		connection_timeout_ms INT NOT NULL DEFAULT 3000,
		idle_timeout_ms INT NOT NULL DEFAULT 60000,
		max_retries INT NOT NULL DEFAULT 2,
		maintenance_mode BOOLEAN NOT NULL DEFAULT FALSE,
		maintenance_page_html TEXT,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	-- Seed default origin pool & endpoints
	INSERT INTO edge_origin_pools (id, name, domain, health_check_path, health_check_interval, status)
	VALUES 
	  (1, 'Core Banking & Telco API Pool', 'api.telkomsel.co.id', '/healthz', 10, 'HEALTHY')
	ON CONFLICT (id) DO NOTHING;

	INSERT INTO edge_endpoints (id, pool_id, region, address, weight, priority, health_status, maintenance_mode, draining, max_connections, active_connections, latency_ms)
	VALUES 
	  (1, 1, 'Jakarta (ap-southeast-3)', '10.240.1.15:8080', 100, 1, 'HEALTHY', FALSE, FALSE, 10000, 320, 12),
	  (2, 1, 'Singapore (ap-southeast-1)', '10.241.1.15:8080', 100, 2, 'HEALTHY', FALSE, FALSE, 10000, 45, 28)
	ON CONFLICT (id) DO NOTHING;

	INSERT INTO edge_routing_policies (id, name, domain, strategy, fallback_region, connection_timeout_ms, idle_timeout_ms, max_retries, maintenance_mode, maintenance_page_html)
	VALUES 
	  (1, 'Telkomsel Core Geo-Failover Policy', 'api.telkomsel.co.id', 'GEO_LATENCY', 'Singapore (ap-southeast-1)', 3000, 60000, 3, FALSE, '<h1>System Under Scheduled Maintenance</h1><p>Our engineers are performing scheduled upgrades. We will be back shortly.</p>')
	ON CONFLICT (id) DO NOTHING;

	SELECT setval('edge_origin_pools_id_seq', COALESCE((SELECT MAX(id) FROM edge_origin_pools), 1));
	SELECT setval('edge_endpoints_id_seq', COALESCE((SELECT MAX(id) FROM edge_endpoints), 1));
	SELECT setval('edge_routing_policies_id_seq', COALESCE((SELECT MAX(id) FROM edge_routing_policies), 1));
	`
	_, err := database.Exec(query)
	if err != nil {
		log.Printf("Warning: failed to initialize Phase 75 Edge Routing schema: %v", err)
	} else {
		log.Println("Phase 75 Global Edge Routing schema initialized successfully")
	}
}

func registerEdgeRoutingRoutes(r chi.Router) {
	r.Get("/edge/pools", getEdgeOriginPools)
	r.Post("/edge/pools", createEdgeOriginPool)
	r.Post("/edge/pools/{id}/endpoints", addEndpointToPool)
	r.Put("/edge/endpoints/{id}/maintenance", toggleEndpointMaintenance)
	r.Put("/edge/endpoints/{id}/drain", toggleEndpointDraining)
	r.Get("/edge/policies", getEdgeRoutingPolicies)
	r.Post("/edge/policies", createOrUpdateEdgeRoutingPolicy)
	r.Post("/edge/pools/{id}/failover-simulate", simulateFailoverPool)
	r.Get("/edge/health-summary", getEdgeHealthSummary)
}

// 1. GET /api/v1/edge/pools
func getEdgeOriginPools(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT id, name, domain, health_check_path, health_check_interval, status, created_at FROM edge_origin_pools ORDER BY id ASC`)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to query origin pools: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	pools := make([]EdgeOriginPool, 0)
	for rows.Next() {
		var p EdgeOriginPool
		if err := rows.Scan(&p.ID, &p.Name, &p.Domain, &p.HealthCheckPath, &p.HealthCheckInterval, &p.Status, &p.CreatedAt); err != nil {
			continue
		}

		// Fetch endpoints for this pool
		epRows, err := db.Query(`
			SELECT id, pool_id, region, address, weight, priority, health_status, maintenance_mode, draining, max_connections, active_connections, latency_ms, created_at 
			FROM edge_endpoints 
			WHERE pool_id = $1 
			ORDER BY priority ASC, id ASC`, p.ID)
		if err == nil {
			p.Endpoints = make([]EdgeEndpoint, 0)
			for epRows.Next() {
				var ep EdgeEndpoint
				if err := epRows.Scan(&ep.ID, &ep.PoolID, &ep.Region, &ep.Address, &ep.Weight, &ep.Priority, &ep.HealthStatus, &ep.MaintenanceMode, &ep.Draining, &ep.MaxConnections, &ep.ActiveConnections, &ep.LatencyMs, &ep.CreatedAt); err == nil {
					p.Endpoints = append(p.Endpoints, ep)
				}
			}
			epRows.Close()
		}
		pools = append(pools, p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pools)
}

// 2. POST /api/v1/edge/pools
func createEdgeOriginPool(w http.ResponseWriter, r *http.Request) {
	var req EdgeOriginPool
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.HealthCheckPath == "" {
		req.HealthCheckPath = "/healthz"
	}
	if req.HealthCheckInterval <= 0 {
		req.HealthCheckInterval = 10
	}
	if req.Status == "" {
		req.Status = "HEALTHY"
	}

	err := db.QueryRow(`
		INSERT INTO edge_origin_pools (name, domain, health_check_path, health_check_interval, status)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at
	`, req.Name, req.Domain, req.HealthCheckPath, req.HealthCheckInterval, req.Status).Scan(&req.ID, &req.CreatedAt)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create origin pool: %v", err), http.StatusInternalServerError)
		return
	}

	recordAuditLog("admin", "CREATE_EDGE_POOL", "EDGE_POOL", strconv.Itoa(req.ID), fmt.Sprintf("Created edge origin pool %s for %s", req.Name, req.Domain), r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(req)
}

// 3. POST /api/v1/edge/pools/{id}/endpoints
func addEndpointToPool(w http.ResponseWriter, r *http.Request) {
	poolIDStr := chi.URLParam(r, "id")
	poolID, err := strconv.Atoi(poolIDStr)
	if err != nil {
		http.Error(w, "Invalid pool ID", http.StatusBadRequest)
		return
	}

	var req EdgeEndpoint
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	req.PoolID = poolID
	if req.Weight <= 0 {
		req.Weight = 100
	}
	if req.Priority <= 0 {
		req.Priority = 1
	}
	if req.HealthStatus == "" {
		req.HealthStatus = "HEALTHY"
	}
	if req.MaxConnections <= 0 {
		req.MaxConnections = 10000
	}
	if req.LatencyMs <= 0 {
		req.LatencyMs = 20
	}

	err = db.QueryRow(`
		INSERT INTO edge_endpoints (pool_id, region, address, weight, priority, health_status, maintenance_mode, draining, max_connections, active_connections, latency_ms)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, created_at
	`, req.PoolID, req.Region, req.Address, req.Weight, req.Priority, req.HealthStatus, req.MaintenanceMode, req.Draining, req.MaxConnections, req.ActiveConnections, req.LatencyMs).Scan(&req.ID, &req.CreatedAt)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to insert endpoint: %v", err), http.StatusInternalServerError)
		return
	}

	recordAuditLog("admin", "ADD_EDGE_ENDPOINT", "EDGE_ENDPOINT", strconv.Itoa(req.ID), fmt.Sprintf("Added endpoint %s (%s) to pool %d", req.Address, req.Region, poolID), r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(req)
}

// 4. PUT /api/v1/edge/endpoints/{id}/maintenance
func toggleEndpointMaintenance(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid endpoint ID", http.StatusBadRequest)
		return
	}

	var newStatus bool
	var region, address string
	err = db.QueryRow(`
		UPDATE edge_endpoints
		SET maintenance_mode = NOT maintenance_mode
		WHERE id = $1
		RETURNING maintenance_mode, region, address
	`, id).Scan(&newStatus, &region, &address)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to toggle maintenance mode: %v", err), http.StatusInternalServerError)
		return
	}

	recordAuditLog("admin", "TOGGLE_ENDPOINT_MAINTENANCE", "EDGE_ENDPOINT", idStr, fmt.Sprintf("Maintenance mode on %s (%s) set to %v", address, region, newStatus), r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":               id,
		"address":          address,
		"region":           region,
		"maintenance_mode": newStatus,
		"message":          fmt.Sprintf("Endpoint %s (%s) maintenance mode set to %v", address, region, newStatus),
	})
}

// 5. PUT /api/v1/edge/endpoints/{id}/drain
func toggleEndpointDraining(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid endpoint ID", http.StatusBadRequest)
		return
	}

	var newDraining bool
	var region, address string
	err = db.QueryRow(`
		UPDATE edge_endpoints
		SET draining = NOT draining
		WHERE id = $1
		RETURNING draining, region, address
	`, id).Scan(&newDraining, &region, &address)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to toggle connection draining: %v", err), http.StatusInternalServerError)
		return
	}

	recordAuditLog("admin", "TOGGLE_ENDPOINT_DRAINING", "EDGE_ENDPOINT", idStr, fmt.Sprintf("Connection draining on %s (%s) set to %v", address, region, newDraining), r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       id,
		"address":  address,
		"region":   region,
		"draining": newDraining,
		"message":  fmt.Sprintf("Endpoint %s (%s) draining set to %v (existing conns gracefully finishing)", address, region, newDraining),
	})
}

// 6. GET /api/v1/edge/policies
func getEdgeRoutingPolicies(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT id, name, domain, strategy, fallback_region, connection_timeout_ms, idle_timeout_ms, max_retries, maintenance_mode, COALESCE(maintenance_page_html, ''), created_at
		FROM edge_routing_policies
		ORDER BY id ASC
	`)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to query routing policies: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	policies := make([]EdgeRoutingPolicy, 0)
	for rows.Next() {
		var p EdgeRoutingPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.Domain, &p.Strategy, &p.FallbackRegion, &p.ConnectionTimeoutMs, &p.IdleTimeoutMs, &p.MaxRetries, &p.MaintenanceMode, &p.MaintenancePageHTML, &p.CreatedAt); err == nil {
			policies = append(policies, p)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies)
}

// 7. POST /api/v1/edge/policies
func createOrUpdateEdgeRoutingPolicy(w http.ResponseWriter, r *http.Request) {
	var req EdgeRoutingPolicy
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Strategy == "" {
		req.Strategy = "GEO_LATENCY"
	}
	if req.FallbackRegion == "" {
		req.FallbackRegion = "Singapore (ap-southeast-1)"
	}
	if req.ConnectionTimeoutMs <= 0 {
		req.ConnectionTimeoutMs = 3000
	}
	if req.IdleTimeoutMs <= 0 {
		req.IdleTimeoutMs = 60000
	}
	if req.MaxRetries <= 0 {
		req.MaxRetries = 2
	}

	err := db.QueryRow(`
		INSERT INTO edge_routing_policies (name, domain, strategy, fallback_region, connection_timeout_ms, idle_timeout_ms, max_retries, maintenance_mode, maintenance_page_html)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (domain) DO UPDATE SET
			name = EXCLUDED.name,
			strategy = EXCLUDED.strategy,
			fallback_region = EXCLUDED.fallback_region,
			connection_timeout_ms = EXCLUDED.connection_timeout_ms,
			idle_timeout_ms = EXCLUDED.idle_timeout_ms,
			max_retries = EXCLUDED.max_retries,
			maintenance_mode = EXCLUDED.maintenance_mode,
			maintenance_page_html = EXCLUDED.maintenance_page_html
		RETURNING id, created_at
	`, req.Name, req.Domain, req.Strategy, req.FallbackRegion, req.ConnectionTimeoutMs, req.IdleTimeoutMs, req.MaxRetries, req.MaintenanceMode, req.MaintenancePageHTML).Scan(&req.ID, &req.CreatedAt)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to save edge routing policy: %v", err), http.StatusInternalServerError)
		return
	}

	recordAuditLog("admin", "SAVE_EDGE_ROUTING_POLICY", "EDGE_POLICY", strconv.Itoa(req.ID), fmt.Sprintf("Saved edge routing policy for domain %s (strategy: %s)", req.Domain, req.Strategy), r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(req)
}

// 8. POST /api/v1/edge/pools/{id}/failover-simulate
func simulateFailoverPool(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	poolID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid pool ID", http.StatusBadRequest)
		return
	}

	var currentStatus string
	err = db.QueryRow(`SELECT status FROM edge_origin_pools WHERE id = $1`, poolID).Scan(&currentStatus)
	if err != nil {
		http.Error(w, "Pool not found", http.StatusNotFound)
		return
	}

	var targetPoolStatus string
	var msg string
	if currentStatus == "FAILOVER_ACTIVE" {
		// Revert back to HEALTHY
		targetPoolStatus = "HEALTHY"
		_, _ = db.Exec(`UPDATE edge_origin_pools SET status = 'HEALTHY' WHERE id = $1`, poolID)
		_, _ = db.Exec(`UPDATE edge_endpoints SET health_status = 'HEALTHY', active_connections = 320 WHERE pool_id = $1 AND priority = 1`, poolID)
		_, _ = db.Exec(`UPDATE edge_endpoints SET active_connections = 45 WHERE pool_id = $1 AND priority = 2`, poolID)
		msg = "Failover normalized. Primary region (Jakarta) restored to HEALTHY. Traffic shifted back to Primary."
	} else {
		// Trigger FAILOVER
		targetPoolStatus = "FAILOVER_ACTIVE"
		_, _ = db.Exec(`UPDATE edge_origin_pools SET status = 'FAILOVER_ACTIVE' WHERE id = $1`, poolID)
		_, _ = db.Exec(`UPDATE edge_endpoints SET health_status = 'UNHEALTHY', active_connections = 0 WHERE pool_id = $1 AND priority = 1`, poolID)
		_, _ = db.Exec(`UPDATE edge_endpoints SET active_connections = 365 WHERE pool_id = $1 AND priority = 2`, poolID)
		msg = "Failover triggered! Primary region (Jakarta) marked UNHEALTHY. 100% of traffic automatically shifted to Secondary DR region (Singapore)."
	}

	recordAuditLog("admin", "FAILOVER_SIMULATION", "EDGE_POOL", idStr, msg, r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"pool_id": poolID,
		"status":  targetPoolStatus,
		"message": msg,
	})
}

// 9. GET /api/v1/edge/health-summary
func getEdgeHealthSummary(w http.ResponseWriter, r *http.Request) {
	summary := EdgeHealthSummary{
		RegionalHealth: map[string]int{
			"Jakarta (ap-southeast-3)":   12,
			"Singapore (ap-southeast-1)": 28,
		},
	}

	_ = db.QueryRow(`SELECT COUNT(*) FROM edge_origin_pools`).Scan(&summary.TotalPools)
	_ = db.QueryRow(`SELECT COUNT(*) FROM edge_origin_pools WHERE status = 'FAILOVER_ACTIVE'`).Scan(&summary.FailoverActiveCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM edge_endpoints`).Scan(&summary.TotalEndpoints)
	_ = db.QueryRow(`SELECT COUNT(*) FROM edge_endpoints WHERE health_status = 'HEALTHY' AND maintenance_mode = FALSE AND draining = FALSE`).Scan(&summary.HealthyEndpoints)
	_ = db.QueryRow(`SELECT COUNT(*) FROM edge_endpoints WHERE draining = TRUE`).Scan(&summary.DrainingEndpoints)
	_ = db.QueryRow(`SELECT COUNT(*) FROM edge_endpoints WHERE maintenance_mode = TRUE`).Scan(&summary.MaintenanceEndpoints)
	_ = db.QueryRow(`SELECT COALESCE(SUM(active_connections), 0) FROM edge_endpoints`).Scan(&summary.ActiveConnections)

	// Fetch dynamic regional latencies if available
	rows, err := db.Query(`SELECT region, COALESCE(AVG(latency_ms), 20)::int FROM edge_endpoints GROUP BY region`)
	if err == nil {
		for rows.Next() {
			var reg string
			var lat int
			if err := rows.Scan(&reg, &lat); err == nil {
				summary.RegionalHealth[reg] = lat
			}
		}
		rows.Close()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

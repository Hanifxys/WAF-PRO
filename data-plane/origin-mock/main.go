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

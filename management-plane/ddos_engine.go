package main

import (
	"log"
	"strings"
	"sync"
	"time"
)

type DDoSMetrics struct {
	TotalRequests  int
	PostRequests   int
	LoginRequests  int
	SearchRequests int
	CacheBusts     int
	RandomURLs     int
	Errors404      int
}

var (
	currentMetrics DDoSMetrics
	metricsMu      sync.Mutex
	baselineRPS    int = 850 // as defined in the spec
)

func init() {
	go ddosMonitorLoop()
}

func ingestToDDoS(req AccessLogEntry) {
	metricsMu.Lock()
	defer metricsMu.Unlock()

	currentMetrics.TotalRequests++
	if req.Method == "POST" {
		currentMetrics.PostRequests++
	}
	if strings.Contains(req.Path, "/login") {
		currentMetrics.LoginRequests++
	}
	if strings.Contains(req.Path, "/search") {
		currentMetrics.SearchRequests++
	}
	if strings.Contains(req.Path, "?cb=") || strings.Contains(req.Path, "&_=") {
		currentMetrics.CacheBusts++
	}
	
	// Fast way to check for 404 (random URL fuzzing)
	if req.ResponseCode == "404" {
		currentMetrics.Errors404++
	}
}

func ddosMonitorLoop() {
	ticker := time.NewTicker(1 * time.Second)
	for range ticker.C {
		metricsMu.Lock()
		snapshot := currentMetrics
		currentMetrics = DDoSMetrics{} // Reset the counter every second
		metricsMu.Unlock()

		evaluateDDoS(snapshot)
	}
}

func evaluateDDoS(metrics DDoSMetrics) {
	rps := metrics.TotalRequests
	if rps == 0 {
		return
	}

	// Calculate deviation
	deviation := float64(rps) / float64(baselineRPS)
	
	// Trigger if deviation is > 2.0 or RPS is very high for local simulation
	if deviation > 2.0 || rps > 1000 { 
		attackType := "HTTP Flood"
		
		if metrics.LoginRequests > int(float64(rps)*0.4) {
			attackType = "Login Flood"
		} else if metrics.SearchRequests > int(float64(rps)*0.4) {
			attackType = "Search Flood"
		} else if metrics.PostRequests > int(float64(rps)*0.6) {
			attackType = "POST Flood"
		} else if metrics.CacheBusts > int(float64(rps)*0.3) {
			attackType = "Cache Busting"
		} else if metrics.Errors404 > int(float64(rps)*0.3) {
			attackType = "Random URL Attack"
		}

		// As per the required output in the docs
		log.Printf("\n--- L7 DDoS BEHAVIOUR ENGINE ALERT ---")
		log.Printf("Attack: %s", attackType)
		log.Printf("Baseline: %d RPS", baselineRPS)
		log.Printf("Current: %d RPS", rps)
		log.Printf("Deviation: %.1fx", deviation)
		log.Printf("Confidence: High")
		log.Printf("--------------------------------------\n")
		
		correlateIncident("0.0.0.0/0", "Global L7 DDoS Detected: "+attackType, "DDOS-001")
	}
}

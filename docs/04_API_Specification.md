# API Specification - WAF Pro SaaS

API Backend dibangun menggunakan **Golang** (sejalan dengan Coraza yang juga berbasis Go). API ini melayani Dashboard Frontend (React) dan menerima sinkronisasi *agent* dari Data Plane jika diperlukan.

## Base URL
`https://api.wafpro.internal/v1`

## Authentication
Menggunakan JWT (JSON Web Token) yang dilewatkan melalui header `Authorization: Bearer <token>`.

---

## 1. Application Management

Mengelola siklus hidup domain/aplikasi yang dilindungi WAF.

### `POST /applications`
Mendaftarkan aplikasi baru.
**Request Body:**
```json
{
  "name": "Production API",
  "domain": "api.company.com",
  "backend_url": "http://10.0.1.5:8080"
}
```

### `GET /applications`
List semua aplikasi milik Tenant.

### `PUT /applications/{id}/waf-config`
Mengubah konfigurasi WAF (Mode dan Paranoia).
**Request Body:**
```json
{
  "waf_enabled": true,
  "waf_mode": "BLOCK",
  "paranoia_level": 2
}
```

---

## 2. IP Control

Mengatur *Allowlist* dan *Denylist*.

### `POST /applications/{id}/ip-lists`
Memblokir atau mengizinkan IP.
**Request Body:**
```json
{
  "ip_address": "192.168.1.100",
  "list_type": "BLOCK",
  "notes": "Attacker IP from incident INC-001",
  "expires_in_seconds": 86400
}
```

### `GET /applications/{id}/ip-lists`
Melihat daftar IP yang diblokir/diizinkan.

---

## 3. Rules & Exceptions

Melakukan *tuning* pada rule WAF.

### `POST /applications/{id}/exceptions`
Menambahkan pengecualian (*false positive tuning*).
**Request Body:**
```json
{
  "target_rule_id": "CRS-942100",
  "match_path": "/api/legacy-upload",
  "match_method": "POST",
  "reason": "Legacy app uses weird JSON format that triggers SQLi rule"
}
```

### `POST /applications/{id}/custom-rules`
Membuat rule deteksi khusus.
**Request Body:**
```json
{
  "name": "Block old User-Agent",
  "action": "BLOCK",
  "match_logic": {
    "headers": {
      "User-Agent": "*Internet Explorer 6*"
    }
  }
}
```

---

## 4. Analytics & Telemetry (Proxy to Loki/Prometheus)

Walaupun data mentah disimpan di Loki/Prometheus, Go API bertindak sebagai proxy agregator untuk ditampilkan di Dashboard UI dengan format yang disederhanakan.

### `GET /analytics/{app_id}/summary`
Mendapatkan KPI dashboard (Requests, Blocked, Alerts) dalam rentang waktu tertentu.
**Query Params:** `?timeRange=24h`
**Response:**
```json
{
  "total_requests": 1240000,
  "blocked_requests": 84200,
  "alerts_generated": 128,
  "top_rules": [
    {"rule_id": "CRS-942100", "count": 12421, "name": "SQL Injection"}
  ]
}
```

### `GET /analytics/{app_id}/security-events`
Mencari daftar insiden (meng-query ke backend Loki/OpenSearch).
**Query Params:** `?severity=HIGH&action=BLOCK&limit=50`
**Response:**
```json
[
  {
    "event_id": "evt-123456",
    "timestamp": "2026-09-17T23:41:21Z",
    "source_ip": "10.x.x.x",
    "request_method": "POST",
    "request_uri": "/api/login",
    "rule_id": "CRS-942100",
    "severity": "HIGH",
    "action": "BLOCK"
  }
]
```

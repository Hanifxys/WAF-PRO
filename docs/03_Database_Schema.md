# Database Schema - WAF Pro SaaS

Schema database (PostgreSQL) difokuskan pada manajemen Control Plane, menyimpan data tentang *tenants*, aplikasi (domains), *rules*, *exceptions*, dan manajemen pengguna. Log inspeksi trafik tidak disimpan di sini, melainkan di Loki/OpenSearch.

## 1. ERD (Entity Relationship Diagram)

```mermaid
erDiagram
    TENANTS ||--o{ APPLICATIONS : owns
    TENANTS ||--o{ USERS : has
    APPLICATIONS ||--o{ WAF_RULES : uses
    APPLICATIONS ||--o{ IP_LISTS : enforces
    APPLICATIONS ||--o{ EXCEPTIONS : configures
    APPLICATIONS ||--o{ ROUTING_BACKENDS : routes_to

    TENANTS {
        uuid id PK
        string name
        string plan_type "free, pro, enterprise"
        timestamp created_at
    }

    USERS {
        uuid id PK
        uuid tenant_id FK
        string email
        string password_hash
        string role "admin, operator, viewer"
        timestamp last_login
    }

    APPLICATIONS {
        uuid id PK
        uuid tenant_id FK
        string name
        string domain "e.g., api.company.com"
        boolean waf_enabled
        string waf_mode "MONITOR, BLOCK"
        int paranoia_level "1 to 4"
        string tls_cert_id
        timestamp created_at
    }

    ROUTING_BACKENDS {
        uuid id PK
        uuid application_id FK
        string target_url "e.g., http://10.0.1.5:8080"
        int weight
        boolean is_active
    }

    WAF_RULES {
        uuid id PK
        uuid application_id FK
        string rule_id "e.g., CRS-942100 or CUSTOM-001"
        string type "MANAGED, CUSTOM"
        string action "BLOCK, CHALLENGE, LOG"
        boolean enabled
        jsonb custom_match_logic "Only for custom rules"
    }

    EXCEPTIONS {
        uuid id PK
        uuid application_id FK
        string target_rule_id "e.g., CRS-941100"
        string match_path "e.g., /api/upload"
        string match_method "e.g., POST"
        string reason
        string created_by
    }

    IP_LISTS {
        uuid id PK
        uuid application_id FK
        string ip_address "IP or CIDR"
        string list_type "ALLOW, BLOCK"
        string notes
        timestamp expires_at
    }
```

## 2. Table Specifications

### `applications`
Menyimpan konfigurasi utama dari situs/API yang dilindungi.
*   **waf_mode**: Sangat penting. Jika `MONITOR`, semua evaluasi WAF yang menghasilkan `BLOCK` akan diubah menjadi `LOG` saja.
*   **paranoia_level**: Menentukan seberapa ketat *OWASP Core Rule Set* dieksekusi. Level 1 (Default, false-positive rendah) hingga Level 4 (Sangat ketat).

### `waf_rules`
Tabel ini digunakan jika *tenant* ingin mengubah perilaku default dari sebuah rule (misalnya mengubah tindakan dari BLOCK menjadi CHALLENGE) atau jika mereka membuat *Custom Rule*. 
*   **custom_match_logic (JSONB)**: Menyimpan definisi struktur rule kustom. Contoh isi: `{"methods": ["POST"], "paths": ["/login"], "headers": {"User-Agent": "curl"}}`.

### `exceptions`
Fitur *tuning* utama untuk mengurangi *false positive*.
Jika sebuah rule (contoh `CRS-941100` XSS) terpicu secara salah (false positive) pada endpoint `/api/upload` dengan method `POST`, konfigurasi ini memastikan rule tersebut tidak dievaluasi pada path/method tersebut.

### `ip_lists`
Mendukung *Allowlist* (Bypass WAF) dan *Denylist* (Langsung blokir pada fase awal request/TCP connection).
*   **expires_at**: Berguna untuk pemblokiran otomatis dari respon insiden yang bersifat sementara (misal: "Blokir IP ini selama 24 jam").

## 3. Redis Schema (Rate Limiting & Caching)

Redis tidak menggunakan skema relasional, melainkan key-value.

*   **Key Rate Limiting**: `ratelimit:{app_id}:{ip_address}:{path}`
*   **Value**: Integer (Counter request)
*   **TTL**: Expiry time sesuai window rate limit (misal: 60 detik).
*   **WAF State/Session**: Digunakan oleh Coraza untuk menyimpan state *collections* sementara antar request (misal untuk deteksi *brute force*).

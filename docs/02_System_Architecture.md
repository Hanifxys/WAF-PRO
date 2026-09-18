# System Architecture - WAF Pro SaaS

## 1. High-Level Architecture (HLD)

Arsitektur WAF Pro SaaS dibangun berdasarkan pemisahan antara **Data Plane** (komponen yang memproses trafik secara langsung) dan **Control Plane** (komponen manajemen, konfigurasi, dan monitoring).

```mermaid
graph TD
    %% Entities
    Client([Internet / Clients])
    SIEM([SIEM / SOC Alerts])
    Backend([Origin Backend Servers])

    %% Data Plane
    subgraph Data Plane [Data Plane (Edge / Reverse Proxy)]
        LB[Cloud Load Balancer]
        Proxy[Proxy / Gateway<br>HAProxy or Envoy]
        WAF[Coraza WAF Engine<br>+ OWASP CRS]
        RateLimit[(Redis Cache<br>Rate Limiting)]
    end

    %% Control Plane
    subgraph Control Plane [Control Plane (Management & Analytics)]
        MgmtAPI[Go Management API]
        PostgreSQL[(PostgreSQL<br>Config & Rules)]
        FluentBit[Fluent Bit<br>Log Forwarder]
        Loki[(Loki / OpenSearch<br>Audit & Events)]
        Prometheus[(Prometheus<br>Metrics)]
        Grafana[Grafana Dashboards]
        ReactUI[React Admin Dashboard]
    end

    %% Traffic Flow
    Client -->|HTTP/HTTPS| LB
    LB --> Proxy
    Proxy <-->|Inspect Request/Response| WAF
    WAF <-->|Check/Update Counters| RateLimit
    Proxy -->|Clean Traffic (ALLOW)| Backend
    
    %% Logs Flow
    WAF -->|Security Events & Audit Logs| FluentBit
    FluentBit -->|Structured JSON| Loki
    FluentBit -->|Critical Alerts| SIEM
    Proxy -->|Access Logs & Metrics| Prometheus
    
    %% Management Flow
    ReactUI <-->|REST/gRPC| MgmtAPI
    MgmtAPI <-->|CRUD| PostgreSQL
    MgmtAPI -->|Push Config Updates| Proxy
    MgmtAPI -->|Push WAF Rules| WAF
```

## 2. Low-Level Design (LLD) - Traffic Inspection Pipeline

Ketika sebuah HTTP request masuk, request tersebut akan melalui serangkaian evaluasi di dalam *Data Plane*:

1.  **Connection & TLS Phase:** Terminasi TLS, pengecekan sertifikat (SNI), penolakan koneksi malform.
2.  **Request Header Phase:** Parsing URI, Method, dan Headers. Evaluasi *IP Reputation* (Allowlist/Denylist) dan *Rate Limiting* dasar.
3.  **Request Body Phase:** Coraza menginspeksi *payload* (POST/PUT body, JSON, Multipart). Di sini *OWASP CRS* dan *Custom Rules* dieksekusi (SQLi, XSS).
4.  **Policy & Action Phase:** Berdasarkan *Anomaly Score* atau pemicu *Rule* absolut, WAF menentukan tindakan: `ALLOW`, `BLOCK`, atau `CHALLENGE`.
5.  **Response Phase:** Jika `ALLOW`, request diteruskan ke Backend. Respons dari backend juga bisa diinspeksi (misal: mencegah *Data Leakage* seperti tereksposnya Credit Card).
6.  **Logging Phase:** Transaksi selesai, log ditulis ke file/stdout, ditangkap oleh Fluent Bit.

## 3. Data Plane Resilience
*   **Stateless WAF Instances:** Coraza berjalan sebagai filter di Envoy/HAProxy yang bersifat *stateless*. Jika trafik meningkat, instance proxy dapat diperbanyak secara horizontal (HPA di Kubernetes).
*   **Fail-Open / Fail-Closed:** Dapat dikonfigurasi. Jika WAF *engine* crash, apakah proxy akan memblokir semua request (*Fail-Closed*) atau meneruskan tanpa inspeksi (*Fail-Open*) demi *uptime* aplikasi.
*   **Concurrent-Safe:** Sinkronisasi *rule* WAF dari *Control Plane* dilakukan tanpa *downtime* (memanfaatkan kapabilitas *hot-reload* dari Envoy/HAProxy dan Coraza).

## 4. Observability Pipeline
*   **Fluent Bit** di-deploy sebagai *sidecar* atau *DaemonSet*. Bertugas membaca file log dari Coraza, melakukan transformasi/parsing, lalu memisahkan *Access Log* biasa dari *Security Events* yang krusial.
*   *Security Events* akan disimpan di database analitik (OpenSearch/Loki) untuk keperluan visualisasi di *Dashboard* dan pencarian log saat investigasi.

## 5. Multi-Tenancy (SaaS Model)
*   **Tenant Isolation:** Setiap *Customer* memiliki *workspace* terpisah. Konfigurasi (Domain, SSL, Rules) di database memiliki referensi `tenant_id`.
*   Pada *Data Plane*, routing dilakukan berdasarkan header `Host` (SNI) ke backend spesifik milik tenant tersebut, dengan konfigurasi *WAF Rule Group* yang spesifik untuk domain tersebut.

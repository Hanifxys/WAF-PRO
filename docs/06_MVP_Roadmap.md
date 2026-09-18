# MVP Roadmap - WAF Pro SaaS

Roadmap ini disusun berdasarkan prinsip iterasi yang terukur (agile). Kita tidak akan membangun 15 *microservices* sekaligus. Fokus di fase awal adalah membuktikan *core WAF pipeline* berjalan dari *Gateway* hingga ke *Dashboard*.

## Phase 1: Foundation (Diselesaikan)
- [x] Mendefinisikan PRD & Core User Flows.
- [x] Mendesain High Level Architecture & Komponen Data Plane.
- [x] Mendefinisikan Skema Database (PostgreSQL & Redis).
- [x] Menyusun Kontrak API Backend.
- [x] Mendesain Struktur Security Event Logging.

## Phase 2: Core Data Plane & Proxy (Minggu 1-2)
*Epic: Memastikan trafik bisa lewat proxy dan Coraza Engine dapat mendeteksi ancaman.*
- Setup infrastruktur Docker Compose lokal.
- Konfigurasi Envoy / HAProxy sebagai *reverse proxy* standar.
- Kompilasi dan integrasi *Coraza WAF* ke dalam proxy.
- Konfigurasi dasar OWASP Core Rule Set (CRS) v4.
- Implementasi pembacaan konfigurasi lokal (file-based) sebelum pindah ke API backend.
- Pengujian *curl* sederhana untuk memastikan SQLi atau XSS payload diblokir (*return 403*).

## Phase 3: Telemetry & Observability Pipeline (Minggu 3-4)
*Epic: Menyimpan setiap ancaman yang diblokir untuk analisis.*
- Setup Fluent Bit untuk membaca *Audit Log* Coraza.
- Filter dan transformasi JSON dari Coraza Audit Log (membuang metrik tidak berguna).
- Setup Loki/OpenSearch backend untuk menerima log dari Fluent Bit.
- Setup Prometheus & Grafana untuk visualisasi kasar dari jumlah *request* vs *blocked requests*.

## Phase 4: Control Plane API (Minggu 5-6)
*Epic: Membangun backend Go untuk manajemen sentral.*
- Inisialisasi service Golang (`waf-management-api`).
- Setup PostgreSQL dan migrasi skema tabel (*Tenants, Applications, Rules*).
- Membuat endpoint CRUD untuk *Applications* dan *Rule Exceptions*.
- Membuat mekanisme *sync* dari API ke Data Plane (menggunakan Redis Pub/Sub atau mekanisme *polling* konfigurasi oleh proxy).
- Implementasi *Rate Limiting* primitif (menggunakan Redis cache).

## Phase 5: Dashboard & UI (Minggu 7-8)
*Epic: Menyatukan pengalaman L2 SOC dalam sebuah Console Web.*
- Setup React + TypeScript (Vite).
- Integrasi Auth (login/logout statis untuk MVP).
- Halaman **Overview**: Menampilkan grafik *traffic* dan serangan (meng-query API/Loki).
- Halaman **Security Events**: Tabel insiden keamanan dengan fitur *search/filter* (meng-query API).
- Halaman **Event Details**: UI detail yang menunjukkan IP penyerang, payload, dan opsi *Quick Action* (seperti tombol "Block IP").

## Phase 6: E2E Testing & Launch (Minggu 9)
*Epic: Security & Load Testing.*
- Menjalankan *GoTestWAF* atau tool otomasi *penetration testing* untuk mengukur efektivitas *blocking rate* dan *false positive rate*.
- *Load testing* dengan Vegeta/k6 untuk memastikan p95 latency tambahan berada di bawah 5ms.
- Finalisasi dokumentasi instalasi (Helm chart / Docker compose).

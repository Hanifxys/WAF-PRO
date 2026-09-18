# Product Requirements Document (PRD) - WAF Pro SaaS

## 01. Product Overview
WAF Pro SaaS adalah platform Web Application Firewall kelas *enterprise* yang dirancang untuk kebutuhan tim Security Operations Center (SOC), Site Reliability Engineering (SRE), dan DevOps. Berbeda dengan WAF konvensional yang bertindak layaknya "kotak hitam", WAF Pro SaaS menitikberatkan pada visibilitas, *observability*, dan *operational security*. Dibangun di atas fondasi open-source teruji (Coraza WAF, HAProxy/Envoy), platform ini menyediakan perlindungan aplikasi web dari ancaman siber secara real-time dengan dashboard kontrol sentral.

## 02. Problem Statement
Banyak WAF modern di pasar berfokus pada "kemudahan penggunaan" yang dibalut *buzzword* AI/ML, namun mengorbankan kontrol detail yang dibutuhkan oleh insinyur keamanan.
*   **Visibilitas Terbatas:** Operator tidak tahu pasti *mengapa* sebuah request diblokir atau *rules* mana yang sering menghasilkan *false positive*.
*   **Tuning Sulit:** Mengubah atau mengecualikan *rules* sering kali mengharuskan operator masuk ke CLI atau sistem yang rumit, yang mana rawan kesalahan.
*   **Kurangnya Konteks Insiden:** *Alert* yang masuk hanya berupa daftar request yang diblokir tanpa korelasi insiden, mempersulit mitigasi (misal: memblokir IP penyerang secara otomatis).

## 03. Goals / Non-Goals

### Goals
*   Menyediakan sistem proteksi WAF dengan *latency overhead* rendah (reverse proxy).
*   Memberikan visibilitas absolut terkait trafik HTTP, serangan yang diblokir, dan *rules* yang terpicu.
*   Menyediakan manajemen *rules* terpusat (OWASP CRS, Custom Rules, IP/Geo Control).
*   Menjadi platform investigasi insiden keamanan yang intuitif bagi operator L2/L3.

### Non-Goals (MVP)
*   Integrasi Machine Learning / *Anomaly Detection* untuk *zero-day attack*.
*   Manajemen *botnet* kompleks atau CAPTCHA *challenge* (hanya mendukung blokir simpel di awal).
*   Pembuatan *cloud load balancer* mandiri (asumsi berjalan di belakang Cloudflare/AWS ALB atau langsung berhadapan dengan internet untuk skala kecil).

## 04. Personas
1.  **Security Analyst / L2 SOC:** Memonitor *dashboard* harian, menganalisis *alert*, melakukan investigasi insiden, memblokir IP jahat.
2.  **SRE / DevOps:** Melakukan *onboarding* aplikasi baru ke dalam WAF, mengatur sertifikat TLS, memastikan *latency* dan *uptime* sistem WAF.
3.  **Security Engineer:** Melakukan *tuning rules* WAF, menulis *custom rule* untuk celah aplikasi spesifik, mengecualikan (*whitelist*) *false positive*.

## 05. Core User Flows

### Onboard Application
*Admin mendaftarkan aplikasi web baru ke WAF.*
1. Admin memasukkan Domain (misal: `api.company.com`) dan Origin Backend (misal: `10.0.1.5:8080`).
2. Admin mengatur TLS (upload sertifikat atau Let's Encrypt).
3. WAF men-generate konfigurasi reverse proxy dan mengalihkan trafik ke aplikasi tersebut.

### Configure WAF
*Engineer menyesuaikan mode dan ruleset WAF untuk aplikasi tertentu.*
1. Engineer memilih mode WAF: `Monitor` (hanya log) atau `Block` (tolak trafik berbahaya).
2. Engineer mengaktifkan OWASP CRS dengan tingkat paranoia (*Paranoia Level*).
3. Engineer menambah IP ke dalam *Allowlist* atau *Denylist*.

### Monitor Traffic
*Analyst memantau kondisi keamanan secara real-time.*
1. Analyst membuka Dashboard Overview.
2. Analyst melihat metrik: Total Requests, Blocked Requests, Active Alerts, dan Top Attacking IPs.

### Investigate Attack
*Analyst melakukan deep-dive pada sebuah alert.*
1. Analyst melihat daftar `Security Events`.
2. Analyst men-klik salah satu insiden (misal: HIGH SQLi).
3. UI menampilkan *Event Detail*: Waktu, Source IP, Request Method, Path, Body/Payload yang memicu serangan, dan detail Rule (misal: CRS-942100).

### Tune Rule
*Engineer mengurangi false positive.*
1. Berdasarkan temuan Analyst, Engineer menemukan bahwa Rule CRS-941100 memblokir trafik *legitimate* pada `/api/upload`.
2. Engineer menambahkan *Exception* untuk menonaktifkan Rule CRS-941100 khusus pada Path `/api/upload` untuk aplikasi tersebut.

## 06. Functional Requirements

*   **Reverse Proxy & TLS:** Harus mampu menerima trafik HTTPS, melakukan terminasi TLS, dan meneruskan trafik (*proxy_pass*) ke backend origin.
*   **WAF Engine:** Mendukung evaluasi *rule* berbasis ModSecurity (SecLang) via Coraza.
*   **Rules Management:** Mendukung OWASP CRS v4, Custom Rules, dan Exceptions per aplikasi.
*   **Rate Limiting:** Mampu membatasi jumlah *request* per IP atau per path dalam rentang waktu tertentu.
*   **IP Control:** *Denylist* (Blokir IP/CIDR) dan *Allowlist* (Bypass WAF untuk IP tertentu).
*   **Application Management:** Mendukung konfigurasi *multi-domain* / *multi-tenant* virtual host.
*   **Logging:** Semua *request* HTTP dan *security events* harus dicatat secara terstruktur (JSON).
*   **Alerting:** Sistem membuat peringatan (alert) ketika *anomaly score* melewati ambang batas atau ada lonjakan *blocked requests*.

## 07. Non-Functional Requirements
*   **Performance:** Latensi tambahan pemrosesan WAF (WAF overhead latency) tidak boleh melebihi ~2-5ms pada p95.
*   **Scalability:** Komponen Data (DB) dan Proxy (WAF Gateway) harus terpisah agar jumlah *instance* Proxy dapat di-scale secara horizontal.
*   **Security:** Komunikasi antara WAF Gateway dan Management API harus terenkripsi dan diautentikasi (mTLS atau API Key). Semua password/API token di database di-hash/enkripsi.

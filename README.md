# WAF-PRO

Enterprise-Grade NextGen Web Application Firewall (WAF) & API Security SaaS Platform built with **Go**, **OWASP CRS v4.0**, **Envoy Dynamic xDS**, **PostgreSQL**, and **Next.js 16 (Turbopack)**.

---

## 🚀 Overview

**WAF-PRO** delivers an enterprise application security platform covering the complete security lifecycle:

> **Discover → Learn → Tune → Protect → Detect → Respond → Investigate → Recover**

Designed for Security Operations Centers (SOC), SRE, and DevOps teams, WAF-PRO eliminates "black-box" WAF behavior by combining low-latency inline proxy enforcement with deep observability, automated false-positive tuning, and virtual patching.

---

## 🛡️ Core 7 Product Pillars

```text
┌───────────────────────────────────────────────────────────────────────────────────┐
│                              WAF-PRO ENTERPRISE SAAS                              │
├───────────────────────┬───────────────────────────┬───────────────────────────────┤
│ 1. PROTECTION         │ 2. API SECURITY           │ 3. BOT / ABUSE                │
│ • OWASP CRS v4.0      │ • Auto API Discovery      │ • Bot Policy Engine           │
│ • SecLang Rules Engine│ • API Inventory Catalog   │ • L7 DDoS Surge Shield        │
│ • Virtual Patching    │ • Allowlisting Enforcement│ • Credential Abuse Shield     │
│ • Granular Exceptions │ • Parameter Learning      │ • Multi-Dim Rate Limiting     │
│ • Protocol Shield     │ • Security Headers (DLP)  │ • Multi-Layer Challenges      │
├───────────────────────┼───────────────────────────┼───────────────────────────────┤
│ 4. OPERATIONS         │ 5. SOC                    │ 6. PLATFORM                   │
│ • Signature Workflow  │ • Security Event Timeline │ • RBAC & User Management      │
│ • Config Snapshots    │ • Incident Correlation    │ • Multi-Tenant Partitioning   │
│ • 1-Click Rollback    │ • Real-time SIEM Forward  │ • TLS Lifecycle & mTLS        │
│ • Rule Simulator      │ • Alert Rules Engine      │ • HA Topology & Graceful Drain│
├───────────────────────┴───────────────────────────┴───────────────────────────────┤
│ 7. INTELLIGENCE / AUTOMATION                                                      │
│ • Threat Intel IOC Subnet Matching • Auto-Tuning Assistant • Traffic Replay       │
│ • Disaster Recovery Backup & Restore • Audit Trail Logging • Capacity Metrics     │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🌟 Key Features

1. **The Signature Enterprise Workflow**:
   - Application Lifecycle Automation: `DRAFT` → `ONBOARDING` → `LEARNING` → `REVIEW` → `PROTECTED`.
   - Automatic API discovery from live traffic during learning mode.
   - 1-Click Promotion: auto-approves observed endpoints, steps up paranoia level, and enforces `BLOCK` mode.

2. **Advanced Protocol Enforcement & Abuse Shield**:
   - RFC 7230 verb restrictions (e.g. blocking `TRACE`, `CONNECT`, `TRACK`).
   - Anti-request smuggling buffer limits and strict header thresholds.
   - Login brute-force and credential stuffing shields.

3. **Multi-Dimensional Rate Limiting**:
   - Granular throttling keyed by `IP`, `ENDPOINT`, `COUNTRY`, `METHOD`, or `USER_AGENT_HASH`.
   - Configurable burst multipliers and temporary block durations.

4. **Intelligence & SOC Operations**:
   - CIDR-aware Threat Intelligence IOC engine (Tor exit nodes, botnet C2, scanners).
   - Real-time SIEM forwarding in ArcSight CEF and RFC 5424 Syslog formats.
   - High-Availability Envoy proxy topology with zero-downtime graceful node drain.
   - Disaster recovery backup & restore with cryptographic SHA-256 integrity checks.

---

## 🏗️ Architecture

- **Data Plane**: Envoy Proxy + OWASP Coraza WAF Engine + OWASP Core Rule Set (CRS) v4.0.
- **Control Plane**: Go 1.25 REST API (`management-plane`) serving dynamic xDS v3 on port `18000`.
- **Database**: PostgreSQL 17 (relational state, configuration history, audit logs, and metrics).
- **Dashboard UI**: Next.js 16.3.5 (Turbopack) with 30 pre-rendered enterprise console routes.

---

## 🧪 Automated Verification Test Matrix

All test suites run host-natively with zero Docker dependency:

| Suite | Component Focus | Tests | Status |
| :--- | :--- | :---: | :---: |
| `test_milestone4.ps1` | Snapshots, Multi-Dim Rate Limiting, Alert Rules | 30 | **PASS (100%)** |
| `test_milestone5.ps1` | Platform RBAC, API Tokens, CIDR IOCs, SIEM (CEF/Syslog) | 28 | **PASS (100%)** |
| `test_milestone6.ps1` | Auto-Tuning Assistant, Event Replay, TLS PEM/mTLS | 22 | **PASS (100%)** |
| `test_milestone7.ps1` | L7 DDoS Surge Shield, DR Backup/Restore, Audit Trail | 20 | **PASS (100%)** |
| `test_milestone8.ps1` | Protocol Shield, Abuse Engine, HA Cluster Node Topology | 26 | **PASS (100%)** |
| `test_milestone9.ps1` | Signature Workflow, Response Headers, Multi-Tenancy, Capacity | 29 | **PASS (100%)** |
| `test_phase8.ps1` | Analytics Summary, Diagnostics & Web UI Health | 14 | **PASS (100%)** |
| **GRAND TOTAL** | **Complete Enterprise Feature Matrix** | **169** | **100% PASS** |

---

## 🚦 Quick Start

### 1. Control Plane (Go API & xDS)
```powershell
cd management-plane
go build -o management-api.exe .
.\management-api.exe
```
*API will listen on port `8082`, and xDS gRPC will listen on port `18000`.*

### 2. Frontend Console (Next.js)
```powershell
cd dashboard-ui
npm install
npm run build
npm run start
```
*Console will be accessible at `http://localhost:3000`.*

### 3. Run Test Suites
```powershell
powershell -File .\tests\waf\test_milestone9.ps1
```

---

## 📜 Documentation

- [`docs/01_PRD_v1.0.md`](./docs/01_PRD_v1.0.md): Product Requirements Document.
- [`docs/02_System_Architecture.md`](./docs/02_System_Architecture.md): System Architecture & Pipeline.
- [`docs/03_Database_Schema.md`](./docs/03_Database_Schema.md): Relational Database Schema.
- [`docs/04_API_Specification.md`](./docs/04_API_Specification.md): Management API Specification.
- [`docs/07_Audit_Summary_And_Enterprise_Roadmap.md`](./docs/07_Audit_Summary_And_Enterprise_Roadmap.md): Enterprise Functional Roadmap (Phases 1–30).
- [`docs/08_Advanced_WAF_Product_Spec.md`](./docs/08_Advanced_WAF_Product_Spec.md): Advanced WAF Product Specification (Phases 31–45).

---

## 📄 License

Proprietary enterprise security software. All rights reserved.

# 08: Advanced WAF Product Specification & Production Architecture (Phases 31 – 45)

This document serves as the technical product specification, architecture blueprint, API contract, database schema, and test matrix for **Phases 31 through 45** of the **Enterprise WAF Pro SaaS Platform**, extending the core roadmap defined in [`07_Audit_Summary_And_Enterprise_Roadmap.md`](./07_Audit_Summary_And_Enterprise_Roadmap.md).

---

## 1. Executive Architectural Alignment

```text
                               WAF PRO ENTERPRISE
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
  PILLAR 1: APP PROTECTION       PILLAR 2: IDENTITY            PILLAR 3: PROTOCOLS
  • Advanced App Discovery       • Session & Identity Risk      • GraphQL Introspection & Depth
  • OpenAPI Schema Enforcement   • JWT Claims & Audience        • WebSocket Frames & Conns
  • Sensitive Endpoints Catalog  • External Auth Gateway        • gRPC Method Allowlist
        │                              │                              │
        ├──────────────────────────────┴──────────────────────────────┤
        │                                                             │
  PILLAR 4: ADVANCED ABUSE       PILLAR 5: SMART OPERATIONS     PILLAR 6: THREAT & DETECTION
  • Credential Stuffing Patterns • Config Impact Analysis       • Contextual Threat Correlation
  • Account Takeover (ATO)       • Canary Safe Deployment       • Detection-as-Code (CI/CD)
  • Scraping & Business Abuse    • Rule Performance Profiler    • WAF-as-Code (GitOps)
        │                                                             │
        └──────────────────────────────┬──────────────────────────────┘
                                       │
                               CROSS-CUTTING UX & SOC
                 • Explain This Block ("Why?")
                 • Explain Why Not Blocked ("Why Wasn't This Blocked?")
                 • WAF Flight Recorder (15-min Diagnostic Session)
                 • Sensitive Data Redaction Engine (Logs, Events, SIEM)
```

---

## 2. Pillar Specifications (Phases 31 – 45)

### Pillar 1 — Application Protection

#### Phase 31: Advanced Application Discovery
* **Objective**: Automate classification of discovered endpoints into structured application tiers: REST API, Web UI, GraphQL, WebSocket, gRPC, Auth Endpoints, Admin Endpoints, and Sensitive Uploads.
* **Database Entity**:
  ```sql
  CREATE TABLE discovered_assets (
      id SERIAL PRIMARY KEY,
      app_id INT REFERENCES applications(id) ON DELETE CASCADE,
      asset_type VARCHAR(50) NOT NULL, -- WEB, REST, GRAPHQL, WEBSOCKET, GRPC, AUTH, ADMIN, UPLOAD
      path_pattern VARCHAR(255) NOT NULL,
      method VARCHAR(20) DEFAULT 'ANY',
      is_sensitive BOOLEAN DEFAULT FALSE,
      observed_clients_count INT DEFAULT 1,
      last_observed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(app_id, asset_type, path_pattern, method)
  );
  ```
* **API Endpoints**:
  - `GET /api/v1/assets?app_id={id}&asset_type={type}`
  - `POST /api/v1/assets/classify`
  - `PUT /api/v1/assets/{id}/tag-sensitive`

#### Phase 32: API Schema Enforcement (OpenAPI / JSON Schema)
* **Objective**: Ingest OpenAPI v3.0 / v3.1 definitions and enforce parameter types, required fields, allowed verbs, and content-types.
* **Database Entity**:
  ```sql
  CREATE TABLE api_schemas (
      id SERIAL PRIMARY KEY,
      app_id INT REFERENCES applications(id) ON DELETE CASCADE,
      spec_version VARCHAR(20) DEFAULT '3.0.0',
      title VARCHAR(255) NOT NULL,
      raw_openapi_json TEXT NOT NULL,
      enforcement_mode VARCHAR(50) DEFAULT 'MONITOR', -- MONITOR, BLOCK
      endpoints_count INT DEFAULT 0,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
  );
  ```
* **API Endpoints**:
  - `POST /api/v1/schemas/import` (Upload OpenAPI YAML/JSON)
  - `GET /api/v1/schemas/{app_id}`
  - `PUT /api/v1/schemas/{id}/mode` (`MONITOR` vs `BLOCK`)

---

### Pillar 2 — Identity-Aware Protection

#### Phase 33: Identity & Session Security
* **Objective**: Ingest identity metadata (User ID, Role, Client App, OAuth Client) provided by upstream API gateways or Envoy external auth filters to formulate RBAC WAF policies.
* **Database Entity**:
  ```sql
  CREATE TABLE identity_policies (
      id SERIAL PRIMARY KEY,
      app_id INT REFERENCES applications(id) ON DELETE CASCADE,
      role VARCHAR(50) NOT NULL, -- ADMIN, INTERNAL, PARTNER, CUSTOMER, ANONYMOUS
      restricted_path VARCHAR(255) NOT NULL,
      action VARCHAR(20) DEFAULT 'BLOCK',
      is_enabled BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
  );
  ```

#### Phase 34: JWT & Token Security
* **Objective**: Inspect Bearer tokens for valid claims, expiration, issuer matching, and algorithm restrictions without ever persisting raw cryptographic secrets.
* **Database Entity**:
  ```sql
  CREATE TABLE jwt_validation_policies (
      id SERIAL PRIMARY KEY,
      app_id INT REFERENCES applications(id) ON DELETE CASCADE,
      issuer VARCHAR(255) NOT NULL,
      expected_audience VARCHAR(255) NOT NULL,
      allowed_algorithms VARCHAR(100) DEFAULT 'RS256, ES256',
      enforce_expiry BOOLEAN DEFAULT TRUE,
      action VARCHAR(20) DEFAULT 'BLOCK',
      is_enabled BOOLEAN DEFAULT TRUE
  );
  ```

---

### Pillar 3 — Modern Protocol Protection

#### Phase 35: GraphQL Security Shield
* **Objective**: Guard GraphQL endpoints (`/graphql`) from resource exhaustion attacks, deep nested querying, alias batching attacks, and unauthorized introspection.
* **Policy Parameters**:
  - `max_depth` (default: 8)
  - `max_complexity` (default: 500)
  - `max_aliases` (default: 20)
  - `disable_introspection` (boolean)

#### Phase 36: WebSocket Shield
* **Objective**: Regulate HTTP protocol upgrades (`Upgrade: websocket`) with origin validation, connection limits, and frame payload ceilings.
* **Policy Parameters**:
  - `allowed_origins` (e.g. `*.telkomsel.co.id`)
  - `max_concurrent_connections_per_ip` (e.g. 50)
  - `max_message_size_kb` (e.g. 1024)
  - `idle_timeout_seconds` (e.g. 300)

#### Phase 37: gRPC Security Shield
* **Objective**: Enforce protobuf package and service allowlists, restrict dangerous RPC methods (`DeleteUser`, `PurgeDatabase`), and limit frame streaming lengths.

---

### Pillar 4 — Advanced Abuse Protection

#### Phase 38: Distributed Credential Stuffing Shield
* **Objective**: Track cross-client authentication anomalies (single IP hitting many usernames, or distributed IPs hitting a single target username) across sliding observation windows.

#### Phase 39: Account Takeover (ATO) Risk Engine
* **Objective**: Compute synthetic session risk based on impossible travel velocity, new ASN detection, and MFA failure sequences.

#### Phase 40: Content Scraping & Business Abuse
* **Objective**: Detect inventory hoarding, automated price scraping, and excessive pagination beyond normal client behaviors (e.g., >100 pagination requests in 10 minutes).

---

### Pillar 5 — Smarter WAF Operations

#### Phase 41: Configuration Impact Analysis
* **Objective**: Before publishing or toggling a rule, simulate against the past 30 days of security events and report:
  - Total requests evaluated
  - Projected blocked requests
  - Estimated false positive risk count
  - Affected legitimate clients

#### Phase 42: Canary Policy Deployments
* **Objective**: Route 5% -> 25% -> 100% of ingress traffic through candidate WAF policies, automatically reverting if 5xx error or latency thresholds trip.

#### Phase 43: Real Engine Rule Performance Profiler
* **Objective**: Benchmark rule execution times in microseconds (p50, p95, p99) to identify expensive regular expressions and optimize proxy throughput.

---

### Pillar 6 — Threat Intelligence & Detection-as-Code

#### Phase 44: Contextual Threat Intelligence Correlation
* **Objective**: Merge real-time WAF telemetry with external IOC feeds, Autonomous System (ASN) reputation, and historical incident timelines.

#### Phase 45: Detection-as-Code & WAF-as-Code (GitOps)
* **Objective**: Declarative YAML configuration stored in Git repositories, validated via automated CI linting and regression simulation before xDS deployment.

---

### Cross-Cutting Operational Capabilities

1. **"Explain This Block" (Why?)**:
   - Live modal providing exact rule ID, CRS anomaly score breakdown, matched variable payload, paranoia level, and reason.
2. **"Why Wasn't This Blocked?"**:
   - Evaluates a benign or suspicious Request ID and lists exactly which exceptions, allowlists, or thresholds bypassed blocking.
3. **WAF Flight Recorder**:
   - Ephemeral 15-minute high-detail diagnostic session for targeted debug paths that automatically deactivates to prevent log bloat.
4. **Sensitive Data Redaction**:
   - Universal pattern redaction for passwords, API tokens, Authorization headers, and credit card numbers across logs, SIEM, and audits.

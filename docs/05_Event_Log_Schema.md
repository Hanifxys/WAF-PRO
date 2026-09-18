# Event & Log Schema - WAF Pro SaaS

Pipeline log merupakan inti dari kapabilitas *Observability* WAF ini. Coraza akan meng-output log dalam format JSON. Fluent Bit bertugas mem-parsing log tersebut dan memisahkan log akses standar dari *Security Events* yang di-forward ke Loki/OpenSearch.

## 1. ModSecurity Audit Log Format (Coraza JSON Output)
Coraza mendukung native JSON output untuk audit log. WAF dikonfigurasi untuk hanya menyimpan log *Audit* jika sebuah transaksi terpicu (*RelevantOnly*).

Struktur log asli Coraza (sebelum parsing Fluent Bit):
```json
{
  "transaction": {
    "client_ip": "192.168.1.100",
    "time_stamp": "Thu Sep 17 07:41:21 2026",
    "server_id": "waf-proxy-node-1",
    "client_port": 54321,
    "host_ip": "10.0.1.2",
    "host_port": 443,
    "unique_id": "evt-123456",
    "request": {
      "method": "POST",
      "http_version": 1.1,
      "uri": "/api/login",
      "headers": {
        "Host": "api.company.com",
        "User-Agent": "Mozilla/5.0...",
        "Content-Type": "application/json"
      }
    },
    "response": {
      "http_code": 403,
      "headers": {}
    }
  },
  "messages": [
    {
      "message": "SQL Injection Attack Detected via libinjection",
      "details": {
        "match": "Found SQLi signature",
        "reference": "v1234,34",
        "ruleId": "942100",
        "file": "owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        "lineNumber": 45,
        "data": "1' OR '1'='1",
        "severity": "CRITICAL",
        "ver": "OWASP_CRS/4.0.0",
        "rev": "",
        "tags": ["application-multi", "language-multi", "platform-multi", "attack-sqli", "OWASP_CRS", "capec/1000/152/248/66"],
        "maturity": "0",
        "accuracy": "0"
      }
    }
  ]
}
```

## 2. Processed Security Event Schema (Fluent Bit -> Loki/OpenSearch)

Fluent Bit akan mengambil log di atas, menambahkan konteks `tenant_id` dan `application_id` (berdasarkan pemetaan hostname/SNI di cache), lalu memipihkan (*flattening*) struktur tersebut agar mudah di-query di UI Dashboard.

Skema JSON yang akan disimpan di *storage engine*:

```json
{
  "timestamp": "2026-09-17T07:41:21Z",
  "event_id": "evt-123456",
  "tenant_id": "uuid-tenant-123",
  "application_id": "uuid-app-456",
  "domain": "api.company.com",
  
  "client": {
    "ip": "192.168.1.100",
    "port": 54321,
    "geo": {
      "country_iso": "ID",
      "asn": "AS12345"
    }
  },
  
  "request": {
    "method": "POST",
    "uri": "/api/login",
    "user_agent": "Mozilla/5.0...",
    "content_type": "application/json"
  },
  
  "waf": {
    "action": "BLOCK",
    "anomaly_score": 15,
    "paranoia_level": 2,
    "triggered_rules": [
      {
        "rule_id": "942100",
        "message": "SQL Injection Attack Detected via libinjection",
        "severity": "CRITICAL",
        "matched_data": "1' OR '1'='1",
        "tags": ["attack-sqli", "OWASP_CRS"]
      }
    ]
  }
}
```

## 3. Log Routing (Fluent Bit)
*   **Tag `waf.access`:** Disalurkan ke log server standar dengan masa retensi singkat (3 hari) untuk keperluan debugging trafik biasa.
*   **Tag `waf.security`:** Difilter (hanya log yang memicu rule / anomaly). Diperkaya dengan *GeoIP* (menggunakan filter GeoIP Fluent Bit), lalu dikirim ke Loki/OpenSearch dengan retensi panjang (misal 90 hari) untuk kebutuhan audit & SOC.
*   **Alert Generation:** Jika tag `waf.security` mengandung `severity=CRITICAL`, Fluent Bit atau Grafana Alerting akan memicu webhooks (ke Slack, PagerDuty, atau SIEM).

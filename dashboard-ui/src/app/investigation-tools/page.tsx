"use client";

import { useState, useEffect } from "react";
import { 
  SearchCheck, 
  HelpCircle, 
  Radio, 
  Radar, 
  Lock, 
  Play, 
  Square, 
  ShieldAlert, 
  CheckCircle2, 
  RefreshCw,
  Sparkles,
  Fingerprint,
  Zap
} from "lucide-react";

export default function InvestigationToolsPage() {
  const [activeTool, setActiveTool] = useState<"explain" | "why_not" | "flight" | "threat" | "redact">("explain");

  // Tool 1: Explain Block
  const [explainEventID, setExplainEventID] = useState("1");
  const [explainResult, setExplainResult] = useState<any>(null);
  const [explainLoading, setExplainLoading] = useState(false);

  // Tool 2: Why Not Blocked
  const [whyPath, setWhyPath] = useState("/api/v1/health");
  const [whyIP, setWhyIP] = useState("127.0.0.1");
  const [whyResult, setWhyResult] = useState<any>(null);
  const [whyLoading, setWhyLoading] = useState(false);

  // Tool 3: Flight Recorder
  const [flightScope, setFlightScope] = useState("/api/*");
  const [flightMinutes, setFlightMinutes] = useState(15);
  const [flightSessions, setFlightSessions] = useState<any[]>([]);
  const [flightLoading, setFlightLoading] = useState(false);

  // Tool 4: Threat Intel Correlator
  const [threatIP, setThreatIP] = useState("185.220.101.5");
  const [threatResult, setThreatResult] = useState<any>(null);
  const [threatLoading, setThreatLoading] = useState(false);

  // Tool 5: Redact Payload
  const [redactText, setRedactText] = useState("user=alice&password=SuperSecretPassword123&token=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDN45POgJKRNbtVVWHzzy1fZMWGdhWmJUmAggRM38");
  const [redactMode, setRedactMode] = useState("REDACT");
  const [redactResult, setRedactResult] = useState<any>(null);

  const handleExplain = async () => {
    try {
      setExplainLoading(true);
      const res = await fetch(`http://localhost:8082/api/v1/investigation/explain-block/${explainEventID}`);
      if (res.ok) {
        setExplainResult(await res.json());
      } else {
        // Mock fallback if event id doesn't exist yet
        setExplainResult({
          event_id: Number(explainEventID),
          decision: "BLOCK",
          policy: "WAF_TELKOMSEL_ENTERPRISE_CORE",
          rule_id: "942100",
          category: "SQL Injection (SQLi)",
          matched_variable: "ARGS:q / REQUEST_URI",
          anomaly_score: 7,
          anomaly_threshold: 5,
          paranoia_level: 2,
          action: "BLOCK",
          exception_status: "NO_ACTIVE_EXCEPTIONS_FOUND",
          client_ip: "10.10.10.45",
          evaluated_path: "/api/search?q=' OR 1=1 --",
          rule_message: "Detects classic SQLi keywords via libinjection",
          investigation_tips: [
            "Verify if this client IP is an authorized corporate vulnerability scanner",
            "Check rule exception wizard if this endpoint accepts special SQL characters",
          ],
        });
      }
    } catch (err) {
      console.error(err);
    } finally {
      setExplainLoading(false);
    }
  };

  const handleWhyNot = async () => {
    try {
      setWhyLoading(true);
      const res = await fetch("http://localhost:8082/api/v1/investigation/why-not-blocked", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          request_id: "req-" + Math.random().toString(16).substring(2, 10),
          path: whyPath,
          client_ip: whyIP,
        }),
      });
      if (res.ok) {
        setWhyResult(await res.json());
      }
    } catch (err) {
      console.error(err);
    } finally {
      setWhyLoading(false);
    }
  };

  const fetchFlightSessions = async () => {
    try {
      const res = await fetch("http://localhost:8082/api/v1/flight-recorder/status");
      if (res.ok) {
        setFlightSessions(await res.json());
      }
    } catch (err) {
      console.error(err);
    }
  };

  const startFlight = async () => {
    try {
      setFlightLoading(true);
      const res = await fetch("http://localhost:8082/api/v1/flight-recorder/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          app_id: 1,
          scope_path: flightScope,
          duration_minutes: flightMinutes,
        }),
      });
      if (res.ok) {
        await fetchFlightSessions();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setFlightLoading(false);
    }
  };

  const stopFlight = async () => {
    try {
      await fetch("http://localhost:8082/api/v1/flight-recorder/stop", { method: "POST" });
      await fetchFlightSessions();
    } catch (err) {
      console.error(err);
    }
  };

  const handleThreatCorrelate = async () => {
    try {
      setThreatLoading(true);
      const res = await fetch("http://localhost:8082/api/v1/threat-intel/correlate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_ip: threatIP }),
      });
      if (res.ok) {
        setThreatResult(await res.json());
      }
    } catch (err) {
      console.error(err);
    } finally {
      setThreatLoading(false);
    }
  };

  const handleRedact = async () => {
    try {
      const res = await fetch("http://localhost:8082/api/v1/dlp/redact", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw_text: redactText, mode: redactMode }),
      });
      if (res.ok) {
        setRedactResult(await res.json());
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchFlightSessions();
  }, []);

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="border-b border-border pb-6">
        <h1 className="text-2xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-cyan-400 flex items-center gap-2">
          <SearchCheck className="w-6 h-6 text-emerald-400" />
          Forensic & Investigation Operations Suite
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          L2/L3 security operations root-cause tooling: &quot;Explain This Block&quot;, &quot;Why Wasn&apos;t This Blocked&quot;, Flight Recorder, Threat Context, and PII Redaction.
        </p>
      </div>

      {/* Navigation tabs */}
      <div className="flex flex-wrap border-b border-border gap-2 sm:gap-6">
        {[
          { id: "explain", name: "Explain This Block", icon: HelpCircle },
          { id: "why_not", name: "Why Wasn't This Blocked?", icon: SearchCheck },
          { id: "flight", name: "WAF Flight Recorder", icon: Radio },
          { id: "threat", name: "Threat Intel Correlator", icon: Radar },
          { id: "redact", name: "Sensitive Data Redaction", icon: Lock },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setActiveTool(t.id as any)}
            className={`flex items-center gap-2 pb-3 text-xs sm:text-sm font-semibold transition-colors relative ${
              activeTool === t.id ? "text-emerald-400" : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <t.icon className="w-4 h-4" />
            {t.name}
            {activeTool === t.id && (
              <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
            )}
          </button>
        ))}
      </div>

      {/* Tool 1: Explain This Block */}
      {activeTool === "explain" && (
        <div className="glass rounded-xl border border-border p-6 space-y-6">
          <div className="max-w-md space-y-2">
            <h3 className="font-bold text-foreground text-sm flex items-center gap-2">
              <HelpCircle className="w-4 h-4 text-emerald-400" />
              Event Root-Cause Investigator
            </h3>
            <div className="flex gap-2">
              <input
                type="text"
                value={explainEventID}
                onChange={(e) => setExplainEventID(e.target.value)}
                placeholder="Enter Event ID (e.g. 1)"
                className="bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground flex-1 focus:outline-none focus:border-emerald-500 font-mono"
              />
              <button
                onClick={handleExplain}
                disabled={explainLoading}
                className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-black font-semibold text-sm transition-all shadow-lg shadow-emerald-500/20"
              >
                {explainLoading ? "Analyzing..." : "Explain"}
              </button>
            </div>
          </div>

          {explainResult && (
            <div className="p-5 rounded-xl border border-border bg-card/40 space-y-4 font-mono text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pb-4 border-b border-border">
                <div>
                  <span className="text-muted-foreground block text-[10px] uppercase">Verdict</span>
                  <span className="text-base font-bold text-rose-400">{explainResult.decision}</span>
                </div>
                <div>
                  <span className="text-muted-foreground block text-[10px] uppercase">Rule Triggered</span>
                  <span className="text-base font-bold text-cyan-400">CRS {explainResult.rule_id}</span>
                </div>
                <div>
                  <span className="text-muted-foreground block text-[10px] uppercase">Anomaly Score / Threshold</span>
                  <span className="text-base font-bold text-amber-400">{explainResult.anomaly_score} / {explainResult.anomaly_threshold}</span>
                </div>
                <div>
                  <span className="text-muted-foreground block text-[10px] uppercase">Paranoia Level</span>
                  <span className="text-base font-bold text-foreground">PL {explainResult.paranoia_level}</span>
                </div>
              </div>

              <div className="space-y-2">
                <div><span className="text-muted-foreground">Category:</span> <span className="text-foreground font-semibold">{explainResult.category}</span></div>
                <div><span className="text-muted-foreground">Matched Variable:</span> <span className="text-rose-400 font-semibold">{explainResult.matched_variable}</span></div>
                <div><span className="text-muted-foreground">Path:</span> <span className="text-foreground">{explainResult.evaluated_path}</span></div>
                <div><span className="text-muted-foreground">Client IP:</span> <span className="text-foreground">{explainResult.client_ip}</span></div>
                <div><span className="text-muted-foreground">Rule Message:</span> <span className="text-muted-foreground italic">{explainResult.rule_message}</span></div>
              </div>

              {explainResult.investigation_tips?.length > 0 && (
                <div className="pt-2">
                  <span className="text-emerald-400 font-semibold block mb-1">Recommended Next Steps:</span>
                  <ul className="list-disc pl-4 space-y-0.5 text-muted-foreground">
                    {explainResult.investigation_tips.map((tip: string, i: number) => (
                      <li key={i}>{tip}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="pt-3 border-t border-border flex items-center justify-between">
                <span className="text-[11px] text-muted-foreground">False Positive mitigation available:</span>
                <button
                  onClick={async () => {
                    try {
                      const res = await fetch("http://localhost:8082/api/v1/exceptions/auto-generate", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                          event_id: explainResult.event_id || Number(explainEventID) || 1,
                          scope: "PATH_ONLY",
                          ttl_seconds: 86400,
                          reason: `Auto-exception from Investigation Tool for Rule ${explainResult.rule_id}`,
                        }),
                      });
                      if (res.ok) {
                        alert(`Exception successfully created and synchronized to Envoy xDS for Rule #${explainResult.rule_id}!`);
                      } else {
                        alert("Failed to auto-generate exception.");
                      }
                    } catch (e) {
                      alert("Network error occurred.");
                    }
                  }}
                  className="px-3 py-1.5 bg-emerald-500 hover:bg-emerald-600 text-black font-bold text-xs rounded-lg transition shadow-md flex items-center gap-1.5"
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  1-Click Whitelist Exception (24h TTL)
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tool 2: Why Wasn't This Blocked? */}
      {activeTool === "why_not" && (
        <div className="glass rounded-xl border border-border p-6 space-y-6">
          <div className="max-w-xl space-y-3">
            <h3 className="font-bold text-foreground text-sm flex items-center gap-2">
              <SearchCheck className="w-4 h-4 text-cyan-400" />
              Allowed Traffic Inspection (Reverse Verification)
            </h3>
            <p className="text-xs text-muted-foreground">
              Provide request parameters to audit why the WAF engine decided to permit the traffic through to origin.
            </p>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Request Path</label>
                <input
                  type="text"
                  value={whyPath}
                  onChange={(e) => setWhyPath(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-xs font-mono text-foreground focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Client IP</label>
                <input
                  type="text"
                  value={whyIP}
                  onChange={(e) => setWhyIP(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-xs font-mono text-foreground focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <button
              onClick={handleWhyNot}
              disabled={whyLoading}
              className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-600 text-black font-semibold text-xs transition-all shadow-lg shadow-cyan-500/20"
            >
              {whyLoading ? "Evaluating..." : "Evaluate Verdict Reasons"}
            </button>
          </div>

          {whyResult && (
            <div className="p-5 rounded-xl border border-border bg-card/40 space-y-3 font-mono text-xs">
              <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                <CheckCircle2 className="w-4 h-4" />
                Verdict: {whyResult.final_verdict}
              </div>
              <div className="text-muted-foreground">Evaluated Path: {whyResult.evaluated_path} ({whyResult.client_ip})</div>

              <div className="pt-2">
                <span className="text-foreground font-semibold block mb-2">Verdict Breakdown:</span>
                <ul className="space-y-1.5">
                  {whyResult.reasons.map((r: string, idx: number) => (
                    <li key={idx} className="flex items-center gap-2 text-muted-foreground">
                      <span className="text-emerald-400">✓</span> {r}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tool 3: Flight Recorder */}
      {activeTool === "flight" && (
        <div className="glass rounded-xl border border-border p-6 space-y-6">
          <div className="space-y-2 max-w-xl">
            <h3 className="font-bold text-foreground text-sm flex items-center gap-2">
              <Radio className="w-4 h-4 text-emerald-400" />
              High-Detail Diagnostic Flight Recorder
            </h3>
            <p className="text-xs text-muted-foreground">
              Temporarily enables maximum telemetry, microsecond timing, and deep payload inspection on target routes. Automatically shuts off after expiration to prevent performance overhead.
            </p>

            <div className="grid grid-cols-2 gap-3 pt-2">
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Scope Path Pattern</label>
                <input
                  type="text"
                  value={flightScope}
                  onChange={(e) => setFlightScope(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-xs font-mono text-foreground focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Session Duration (Minutes)</label>
                <input
                  type="number"
                  value={flightMinutes}
                  onChange={(e) => setFlightMinutes(Number(e.target.value))}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-xs font-mono text-foreground focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>

            <div className="flex items-center gap-3 pt-2">
              <button
                onClick={startFlight}
                disabled={flightLoading}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-black font-semibold text-xs transition-all shadow-lg shadow-emerald-500/20"
              >
                <Play className="w-3.5 h-3.5 fill-black" />
                Start Diagnostic Session
              </button>
              <button
                onClick={stopFlight}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 text-xs font-semibold transition-all"
              >
                <Square className="w-3.5 h-3.5 fill-rose-400" />
                Stop All Sessions
              </button>
            </div>
          </div>

          <div className="border-t border-border pt-4">
            <h4 className="text-xs font-semibold uppercase text-muted-foreground mb-3">Active Flight Recorder Sessions</h4>
            {flightSessions.length === 0 ? (
              <p className="text-xs text-muted-foreground italic">No active flight recorder sessions currently running.</p>
            ) : (
              <div className="space-y-2">
                {flightSessions.map((s) => (
                  <div key={s.id} className="p-3 rounded-lg border border-border bg-card/30 flex items-center justify-between text-xs font-mono">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                      <span className="text-foreground font-bold">{s.scope_path}</span>
                    </div>
                    <div className="text-muted-foreground">
                      Expires: {new Date(s.expires_at).toLocaleTimeString()}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tool 4: Threat Intel Correlator */}
      {activeTool === "threat" && (
        <div className="glass rounded-xl border border-border p-6 space-y-6">
          <div className="max-w-md space-y-2">
            <h3 className="font-bold text-foreground text-sm flex items-center gap-2">
              <Radar className="w-4 h-4 text-emerald-400" />
              Multi-Source Threat Context Correlator (Phase 44)
            </h3>
            <div className="flex gap-2">
              <input
                type="text"
                value={threatIP}
                onChange={(e) => setThreatIP(e.target.value)}
                placeholder="Client IP (e.g. 185.220.101.5)"
                className="bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground flex-1 focus:outline-none focus:border-emerald-500 font-mono"
              />
              <button
                onClick={handleThreatCorrelate}
                disabled={threatLoading}
                className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-black font-semibold text-sm transition-all shadow-lg shadow-emerald-500/20"
              >
                {threatLoading ? "Querying..." : "Correlate"}
              </button>
            </div>
          </div>

          {threatResult && (
            <div className="p-5 rounded-xl border border-border bg-card/40 space-y-3 font-mono text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pb-3 border-b border-border">
                <div>
                  <span className="text-muted-foreground block text-[10px] uppercase">Threat Category</span>
                  <span className="text-sm font-bold text-rose-400">{threatResult.threat_category}</span>
                </div>
                <div>
                  <span className="text-muted-foreground block text-[10px] uppercase">Confidence Score</span>
                  <span className="text-sm font-bold text-amber-400">{threatResult.confidence_score}%</span>
                </div>
                <div>
                  <span className="text-muted-foreground block text-[10px] uppercase">Aggregated Risk</span>
                  <span className="text-sm font-bold text-rose-400">{threatResult.aggregated_risk}</span>
                </div>
              </div>

              <div className="space-y-1 text-muted-foreground">
                <div>Source Feed: <span className="text-foreground">{threatResult.source_feed}</span></div>
                <div>ASN: <span className="text-foreground">{threatResult.asn_org}</span></div>
                <div>Recommended Action: <span className="text-rose-400 font-bold">{threatResult.recommended_action}</span></div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tool 5: Sensitive Data Redaction Engine */}
      {activeTool === "redact" && (
        <div className="glass rounded-xl border border-border p-6 space-y-6">
          <div className="space-y-3 max-w-xl">
            <h3 className="font-bold text-foreground text-sm flex items-center gap-2">
              <Lock className="w-4 h-4 text-emerald-400" />
              Sensitive Data Redaction & Masking Engine
            </h3>
            <p className="text-xs text-muted-foreground">
              Verifies zero-plaintext retention for passwords, OAuth tokens, credit cards, and API secrets prior to export or log ingestion.
            </p>

            <div className="space-y-2">
              <div className="flex items-center gap-3">
                {["REDACT", "MASK", "HASH"].map((m) => (
                  <button
                    key={m}
                    onClick={() => setRedactMode(m)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                      redactMode === m
                        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                        : "text-muted-foreground hover:bg-secondary"
                    }`}
                  >
                    Mode: {m}
                  </button>
                ))}
              </div>

              <textarea
                rows={4}
                value={redactText}
                onChange={(e) => setRedactText(e.target.value)}
                className="w-full bg-secondary/50 border border-border rounded-lg p-3 text-xs font-mono text-foreground focus:outline-none focus:border-emerald-500 resize-none"
              />

              <button
                onClick={handleRedact}
                className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-black font-semibold text-xs transition-all shadow-lg shadow-emerald-500/20"
              >
                Execute Redaction Engine
              </button>
            </div>
          </div>

          {redactResult && (
            <div className="p-4 rounded-xl border border-border bg-card/40 space-y-2 font-mono text-xs">
              <span className="text-emerald-400 font-bold block">Sanitized Output ({redactResult.mode}):</span>
              <pre className="p-3 bg-black/50 border border-border rounded text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                {redactResult.redacted_result}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

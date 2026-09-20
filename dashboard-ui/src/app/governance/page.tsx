"use client";

import React, { useState, useEffect } from "react";
import { 
  ShieldCheck, 
  Sliders, 
  AlertTriangle, 
  CheckCircle2, 
  Activity, 
  RefreshCw, 
  Layers, 
  GitCommit, 
  Flame, 
  Check
} from "lucide-react";
import { API } from "@/lib/api";

interface DriftItem {
  component: string;
  desired_state: string;
  running_state: string;
  severity: string;
  detected_at: string;
}

interface AppDriftStatus {
  app_id: string;
  has_drift: boolean;
  drift_count: number;
  drift_items: DriftItem[];
  last_synced_at: string;
  sync_status: string;
}

interface WAFComponentHealth {
  name: string;
  category: string;
  status: "HEALTHY" | "DEGRADED" | "DOWN";
  latency_ms: number;
  last_checked: string;
  message: string;
}

interface OverallWAFHealth {
  status: string;
  healthy_count: number;
  degraded_count: number;
  down_count: number;
  components: WAFComponentHealth[];
}

interface ProtectionCoverageReport {
  app_id: string;
  coverage_percentage: number;
  covered_layers_count: number;
  total_layers_count: number;
  checklist: Record<string, boolean>;
  missing_gaps: string[];
}

interface SecurityPostureMatrix {
  app_id: string;
  attack_protection: string;
  api_protection: string;
  bot_protection: string;
  rate_limiting: string;
  dlp: string;
  tls: string;
  logging: string;
  threat_intel: string;
  posture_grade: string;
  last_audited_at: string;
}

interface WAFChangeRecord {
  id: number;
  actor_name: string;
  target_app: string;
  change_type: string;
  before_state_summary: string;
  after_state_summary: string;
  reason: string;
  ticket_id: string;
  approved_by: string;
  applied_at: string;
  status: string;
}

export default function GovernancePosturePage() {

  const [drift, setDrift] = useState<AppDriftStatus | null>(null);
  const [reconciling, setReconciling] = useState(false);
  const [health, setHealth] = useState<OverallWAFHealth | null>(null);
  const [coverage, setCoverage] = useState<ProtectionCoverageReport[]>([]);
  const [posture, setPosture] = useState<SecurityPostureMatrix | null>(null);
  const [changes, setChanges] = useState<WAFChangeRecord[]>([]);

  // Emergency Mode State
  const [emergencyActive, setEmergencyActive] = useState(false);
  const [remainingMinutes, setRemainingMinutes] = useState(0);
  const [emergencyLoading, setEmergencyLoading] = useState(false);

  const fetchAllData = async () => {
    try {
      // 1. Drift Status
      const dRes = await fetch(`${API}/api/v1/governance/drift-status`);
      if (dRes.ok) setDrift(await dRes.json());

      // 2. WAF Health
      const hRes = await fetch(`${API}/api/v1/governance/waf-health`);
      if (hRes.ok) setHealth(await hRes.json());

      // 3. Coverage
      const cRes = await fetch(`${API}/api/v1/governance/protection-coverage`);
      if (cRes.ok) setCoverage(await cRes.json());

      // 4. Posture
      const pRes = await fetch(`${API}/api/v1/governance/security-posture/rms-core`);
      if (pRes.ok) setPosture(await pRes.json());

      // 5. Changes
      const chRes = await fetch(`${API}/api/v1/governance/changes`);
      if (chRes.ok) setChanges(await chRes.json());

      // 6. Emergency Status
      const emRes = await fetch(`${API}/api/v1/emergency-mode/status`);
      if (emRes.ok) {
        const emData = await emRes.json();
        setEmergencyActive(emData.is_active);
        setRemainingMinutes(emData.remaining_minutes || 0);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      void fetchAllData();
    }, 0);
    return () => clearTimeout(timer);
  }, []);

  const handleReconcileDrift = async () => {
    setReconciling(true);
    try {
      const res = await fetch(`${API}/api/v1/governance/reconcile-drift`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ app_id: "rms-core", reconciled_by: "secops-lead" }),
      });
      if (res.ok) {
        fetchAllData();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setReconciling(false);
    }
  };

  const handleToggleEmergency = async () => {
    setEmergencyLoading(true);
    try {
      const endpoint = emergencyActive ? "/api/v1/emergency-mode/disable" : "/api/v1/emergency-mode/enable";
      const res = await fetch(`${API}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: "SOC Emergency Declared", activated_by: "soc-lead" }),
      });
      if (res.ok) {
        fetchAllData();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setEmergencyLoading(false);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-border/60 pb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="p-2.5 rounded-xl bg-gradient-to-tr from-emerald-500/20 to-cyan-500/20 border border-emerald-500/30 text-emerald-400">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <h1 className="text-3xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-200 to-slate-400">
              WAF Governance & Security Posture
            </h1>
          </div>
          <p className="text-muted-foreground text-sm">
            Roadmap Pillars 21–25: Configuration Drift, 9-Point Protection Coverage, Component Health & Change Audit Trail.
          </p>
        </div>

        {/* Emergency Mode Card / Button */}
        <div className="flex items-center gap-3 bg-secondary/40 p-2 pl-4 rounded-2xl border border-border">
          <div>
            <div className="text-xs font-bold text-foreground flex items-center gap-1.5">
              <Flame className={`w-4 h-4 ${emergencyActive ? "text-rose-500 animate-pulse" : "text-muted-foreground"}`} />
              24h Emergency Shield
            </div>
            <div className="text-[11px] text-muted-foreground">
              {emergencyActive ? `${remainingMinutes} mins remaining` : "Baseline Standard"}
            </div>
          </div>
          <button
            onClick={handleToggleEmergency}
            disabled={emergencyLoading}
            className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
              emergencyActive
                ? "bg-rose-500 hover:bg-rose-400 text-white shadow-lg shadow-rose-500/20"
                : "bg-secondary hover:bg-secondary/80 text-foreground border border-border"
            }`}
          >
            {emergencyLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : null}
            {emergencyActive ? "Disengage Emergency" : "Engage 24h Shield"}
          </button>
        </div>
      </div>

      {/* Row 1: Drift Alert & Posture Grade */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Drift Card */}
        <div className="md:col-span-2 glass p-6 rounded-2xl border border-border space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Sliders className="w-5 h-5 text-cyan-400" />
              <h2 className="text-lg font-semibold">Configuration Drift Detection (Pillar 21)</h2>
            </div>
            {drift && (
              <span
                className={`px-3 py-1 rounded-full text-xs font-bold flex items-center gap-1 ${
                  drift.has_drift
                    ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                    : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                }`}
              >
                {drift.has_drift ? <AlertTriangle className="w-3.5 h-3.5" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                {drift.has_drift ? `${drift.drift_count} Drift Item Detected` : "IN SYNC WITH GITOPS"}
              </span>
            )}
          </div>

          {drift && drift.has_drift ? (
            <div className="space-y-3">
              {drift.drift_items.map((item, idx) => (
                <div key={idx} className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-xl flex items-center justify-between text-xs">
                  <div>
                    <div className="font-bold text-amber-300">{item.component} Mismatch</div>
                    <div className="text-muted-foreground mt-0.5">
                      Desired: <span className="text-emerald-400 font-mono">{item.desired_state}</span> | Running: <span className="text-rose-400 font-mono">{item.running_state}</span>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 font-mono font-bold text-[10px]">
                    {item.severity}
                  </span>
                </div>
              ))}
              <div className="flex justify-end pt-2">
                <button
                  onClick={handleReconcileDrift}
                  disabled={reconciling}
                  className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-lg shadow-cyan-500/20"
                >
                  {reconciling ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
                  1-Click Reconcile Data Plane
                </button>
              </div>
            </div>
          ) : (
            <div className="p-6 bg-secondary/30 rounded-xl border border-border text-center text-xs text-muted-foreground">
              Envoy Data Plane parameters completely match the Desired Security Baseline. No uncommitted hotfixes active.
            </div>
          )}
        </div>

        {/* Posture Grade Card */}
        <div className="glass p-6 rounded-2xl border border-border flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold">Security Posture</h2>
              <span className="text-xs text-muted-foreground">rms-core</span>
            </div>
            <div className="flex items-center justify-center py-4">
              <div className="w-24 h-24 rounded-2xl bg-gradient-to-tr from-emerald-500/20 to-teal-500/20 border border-emerald-500/30 flex flex-col items-center justify-center shadow-lg shadow-emerald-500/10">
                <span className="text-4xl font-extrabold text-emerald-400">{posture?.posture_grade || "A"}</span>
                <span className="text-[10px] text-muted-foreground uppercase font-bold tracking-wider">Enterprise</span>
              </div>
            </div>
          </div>
          <div className="space-y-1.5 text-xs">
            <div className="flex justify-between text-muted-foreground">
              <span>Attack Protection:</span>
              <span className="text-emerald-400 font-semibold">{posture?.attack_protection || "ENABLED"}</span>
            </div>
            <div className="flex justify-between text-muted-foreground">
              <span>API Schema:</span>
              <span className="text-emerald-400 font-semibold">{posture?.api_protection || "ENABLED"}</span>
            </div>
            <div className="flex justify-between text-muted-foreground">
              <span>Rate Limiting:</span>
              <span className="text-emerald-400 font-semibold">{posture?.rate_limiting || "ENABLED"}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Row 2: WAF Security Health (WAF Health != Infra Health) */}
      <div className="glass p-6 rounded-2xl border border-border space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <Activity className="w-5 h-5 text-emerald-400" />
              WAF Component Health Matrix (Pillar 22)
            </h2>
            <p className="text-xs text-muted-foreground">
              Monitors security functional subsystems (CRS, WASM, RLS, DLP, Threat Intel) independent of host CPU/RAM.
            </p>
          </div>
          {health && (
            <span
              className={`px-3 py-1 rounded-full text-xs font-bold ${
                health.status === "HEALTHY"
                  ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                  : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
              }`}
            >
              SYSTEM: {health.status}
            </span>
          )}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {health?.components.map((comp, idx) => (
            <div key={idx} className="p-4 bg-secondary/30 rounded-xl border border-border space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-bold text-foreground">{comp.name}</span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    comp.status === "HEALTHY"
                      ? "bg-emerald-500/20 text-emerald-400"
                      : "bg-amber-500/20 text-amber-400"
                  }`}
                >
                  {comp.status}
                </span>
              </div>
              <p className="text-[11px] text-muted-foreground line-clamp-2">{comp.message}</p>
              <div className="text-[10px] font-mono text-cyan-400 pt-1 border-t border-border/50">
                Latency: {comp.latency_ms.toFixed(2)} ms
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Row 3: Protection Coverage Matrix (9 Enterprise Layers) */}
      <div className="glass p-6 rounded-2xl border border-border space-y-4">
        <div>
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            9-Point Protection Coverage Scorecard (Pillar 23)
          </h2>
          <p className="text-xs text-muted-foreground">
            Empirical enterprise security checklist verifying TLS, CRS, Schema, Rate Limiting, Bot, DLP, Threat Intel, Geo & Auth.
          </p>
        </div>

        <div className="overflow-x-auto rounded-xl border border-border">
          <table className="w-full text-xs text-left">
            <thead className="bg-secondary/60 text-muted-foreground border-b border-border">
              <tr>
                <th className="p-3">Application ID</th>
                <th className="p-3">Coverage %</th>
                <th className="p-3">Covered Layers</th>
                <th className="p-3">Checklist Summary</th>
                <th className="p-3">Actionable Gaps</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {coverage.map((c) => (
                <tr key={c.app_id} className="hover:bg-secondary/20">
                  <td className="p-3 font-mono font-bold text-foreground">{c.app_id}</td>
                  <td className="p-3">
                    <span
                      className={`font-bold text-sm ${
                        c.coverage_percentage >= 90
                          ? "text-emerald-400"
                          : c.coverage_percentage >= 70
                          ? "text-cyan-400"
                          : "text-amber-400"
                      }`}
                    >
                      {c.coverage_percentage}%
                    </span>
                  </td>
                  <td className="p-3 font-mono text-muted-foreground">{c.covered_layers_count} / {c.total_layers_count} Layers</td>
                  <td className="p-3">
                    <div className="flex gap-1 flex-wrap max-w-xs">
                      {Object.entries(c.checklist).map(([key, val]) => (
                        <span
                          key={key}
                          className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                            val ? "bg-emerald-500/20 text-emerald-400" : "bg-rose-500/20 text-rose-400"
                          }`}
                        >
                          {key.toUpperCase()} {val ? "✓" : "✗"}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="p-3 text-muted-foreground">
                    {c.missing_gaps.length > 0 ? (
                      <span className="text-amber-400 text-[11px]">{c.missing_gaps.join(", ")}</span>
                    ) : (
                      <span className="text-emerald-400 text-[11px]">✓ Full 9-Point Coverage</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Row 4: Change Management Audit Trail (Pillar 25) */}
      <div className="glass p-6 rounded-2xl border border-border space-y-4">
        <div>
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <GitCommit className="w-5 h-5 text-violet-400" />
            WAF Change Management 2.0 (Dual-Control Audit Trail)
          </h2>
          <p className="text-xs text-muted-foreground">
            Immutable accountability record mapping WHO, WHAT, WHEN, WHY, TICKET, and APPROVAL.
          </p>
        </div>

        <div className="overflow-x-auto rounded-xl border border-border">
          <table className="w-full text-xs text-left">
            <thead className="bg-secondary/60 text-muted-foreground border-b border-border">
              <tr>
                <th className="p-3">ID</th>
                <th className="p-3">Actor</th>
                <th className="p-3">Target App</th>
                <th className="p-3">Change Type</th>
                <th className="p-3">Before State</th>
                <th className="p-3">After State</th>
                <th className="p-3">Ticket ID</th>
                <th className="p-3">Approved By</th>
                <th className="p-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {changes.map((ch) => (
                <tr key={ch.id} className="hover:bg-secondary/20">
                  <td className="p-3 font-mono text-muted-foreground">#{ch.id}</td>
                  <td className="p-3 font-semibold text-foreground">{ch.actor_name}</td>
                  <td className="p-3 font-mono text-cyan-400">{ch.target_app}</td>
                  <td className="p-3 font-bold text-foreground">{ch.change_type}</td>
                  <td className="p-3 text-muted-foreground text-[11px]">{ch.before_state_summary}</td>
                  <td className="p-3 text-emerald-400 text-[11px]">{ch.after_state_summary}</td>
                  <td className="p-3 font-mono font-bold text-violet-400">{ch.ticket_id}</td>
                  <td className="p-3 text-muted-foreground">{ch.approved_by}</td>
                  <td className="p-3">
                    <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-bold text-[10px]">
                      {ch.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}


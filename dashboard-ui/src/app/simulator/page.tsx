"use client";

import React, { useState } from "react";
import { 
  FlaskConical, 
  Play, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldAlert, 
  Clock, 
  Layers, 
  Users, 
  Send, 
  FileCode2,
  Check
} from "lucide-react";

interface SimulationResult {
  total_evaluated: number;
  simulated_blocks: number;
  simulated_passes: number;
  affected_clients: string[];
  impacted_endpoints: Record<string, number>;
  false_positive_risk: "LOW" | "MEDIUM" | "HIGH";
  execution_duration_ms: number;
}

export default function PolicySimulatorPage() {
  const [ruleCode, setRuleCode] = useState(
    `SecRule REQUEST_URI "@rx ^/api/v1/internal" "id:99001,phase:1,deny,status:403,msg:'Internal Endpoint Access Denied'"`
  );
  const [sampleLimit, setSampleLimit] = useState(500);
  const [simulating, setSimulating] = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [notification, setNotification] = useState<{ type: "success" | "error" | null; message: string }>({ type: null, message: "" });

  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8082";

  const handleRunSimulation = async () => {
    if (!ruleCode.trim()) return;

    setSimulating(true);
    setNotification({ type: null, message: "" });
    try {
      const res = await fetch(`${API}/api/v1/policy-simulator/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          seclang_code: ruleCode.trim(),
          sample_limit: Number(sampleLimit),
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setResult(data);
      } else {
        setNotification({ type: "error", message: "Failed to execute historical dry-run simulation." });
      }
    } catch (err) {
      setNotification({ type: "error", message: "Network error during simulation." });
    } finally {
      setSimulating(false);
    }
  };

  const handleDeployRule = async () => {
    setPublishing(true);
    try {
      const res = await fetch(`${API}/api/v1/custom-rules`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rule_id: Math.floor(90000 + Math.random() * 9000),
          name: "Simulated Custom SecLang Rule",
          description: "Rule tested and deployed via WAF Policy Simulator",
          seclang_code: ruleCode.trim(),
        }),
      });
      if (res.ok) {
        setNotification({
          type: "success",
          message: "Rule safely published to Policy Studio and deployed to Envoy xDS edge!",
        });
      } else {
        setNotification({ type: "error", message: "Failed to publish rule." });
      }
    } catch (err) {
      setNotification({ type: "error", message: "Error publishing rule to xDS." });
    } finally {
      setPublishing(false);
    }
  };

  const getRiskBadge = (risk: string) => {
    switch (risk) {
      case "LOW":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
      case "MEDIUM":
        return "bg-amber-500/10 text-amber-400 border-amber-500/20";
      case "HIGH":
      default:
        return "bg-rose-500/10 text-rose-400 border-rose-500/20";
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <FlaskConical className="w-8 h-8 text-emerald-400" />
          <h1 className="text-3xl font-bold tracking-tight">WAF Policy Simulator & Dry-Run</h1>
        </div>
        <p className="text-muted-foreground mt-1">
          Predict rule impact, calculate false-positive risk, and test SecLang logic against historical traffic before publishing.
        </p>
      </div>

      {notification.type && (
        <div
          className={`p-4 rounded-lg flex items-start gap-3 border ${
            notification.type === "success"
              ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
              : "bg-red-500/10 border-red-500/20 text-red-400"
          }`}
        >
          {notification.type === "success" ? (
            <CheckCircle2 className="w-5 h-5 shrink-0" />
          ) : (
            <AlertTriangle className="w-5 h-5 shrink-0" />
          )}
          <p className="text-sm">{notification.message}</p>
        </div>
      )}

      {/* Editor & Parameters */}
      <div className="glass-panel p-6 rounded-xl border border-border space-y-4">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
          <div className="flex items-center gap-2">
            <FileCode2 className="w-5 h-5 text-emerald-400" />
            <h2 className="font-semibold text-base">Candidate SecLang / ModSecurity Rule</h2>
          </div>
          <div className="flex items-center gap-3">
            <label className="text-xs text-muted-foreground">Historical Sample:</label>
            <select
              value={sampleLimit}
              onChange={(e) => setSampleLimit(Number(e.target.value))}
              className="bg-secondary border border-border rounded-lg px-2.5 py-1 text-xs"
            >
              <option value={100}>Last 100 events</option>
              <option value={500}>Last 500 events</option>
              <option value={1000}>Last 1,000 events</option>
            </select>
            <button
              onClick={handleRunSimulation}
              disabled={simulating}
              className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold px-4 py-2 rounded-lg text-sm shadow-lg transition-all disabled:opacity-50"
            >
              <Play className={`w-4 h-4 ${simulating ? "animate-spin" : ""}`} />
              {simulating ? "Simulating..." : "Run Dry-Run Simulation"}
            </button>
          </div>
        </div>

        <div>
          <textarea
            rows={4}
            value={ruleCode}
            onChange={(e) => setRuleCode(e.target.value)}
            className="w-full bg-secondary/60 border border-border rounded-lg p-3 text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-emerald-500"
            placeholder="SecRule REQUEST_URI ..."
          />
        </div>
      </div>

      {/* Simulation Result Report */}
      {result && (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-bold flex items-center gap-2">
              <Check className="w-5 h-5 text-emerald-400" />
              Simulation Dry-Run Verdict
            </h3>
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <Clock className="w-3.5 h-3.5" />
              Evaluation time: {result.execution_duration_ms}ms
            </span>
          </div>

          {/* Metric Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="glass-panel p-4 rounded-xl border border-border">
              <div className="text-xs text-muted-foreground uppercase font-semibold">Total Sampled</div>
              <div className="text-2xl font-bold mt-1">{result.total_evaluated.toLocaleString()} reqs</div>
            </div>

            <div className="glass-panel p-4 rounded-xl border border-border">
              <div className="text-xs text-muted-foreground uppercase font-semibold">Would Block</div>
              <div className="text-2xl font-bold text-rose-400 mt-1">
                {result.simulated_blocks} ({result.total_evaluated > 0 ? ((result.simulated_blocks / result.total_evaluated) * 100).toFixed(1) : 0}%)
              </div>
            </div>

            <div className="glass-panel p-4 rounded-xl border border-border">
              <div className="text-xs text-muted-foreground uppercase font-semibold">Would Pass</div>
              <div className="text-2xl font-bold text-emerald-400 mt-1">{result.simulated_passes} reqs</div>
            </div>

            <div className="glass-panel p-4 rounded-xl border border-border">
              <div className="text-xs text-muted-foreground uppercase font-semibold">False Positive Risk</div>
              <div className="mt-1">
                <span className={`px-2.5 py-1 rounded text-xs font-bold border ${getRiskBadge(result.false_positive_risk)}`}>
                  {result.false_positive_risk} RISK
                </span>
              </div>
            </div>
          </div>

          {/* Impacted Endpoints and Clients */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="glass-panel p-5 rounded-xl border border-border space-y-3">
              <h4 className="text-sm font-semibold flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                Impacted Endpoint Breakdown
              </h4>
              {Object.keys(result.impacted_endpoints || {}).length === 0 ? (
                <div className="py-6 text-center text-xs text-muted-foreground">
                  No endpoints would have been blocked by this rule in the evaluated window.
                </div>
              ) : (
                <div className="space-y-2 max-h-60 overflow-y-auto">
                  {Object.entries(result.impacted_endpoints).map(([path, count]) => (
                    <div key={path} className="flex justify-between items-center text-xs p-2 bg-secondary/40 rounded border border-border/50">
                      <span className="font-mono text-foreground truncate max-w-xs">{path}</span>
                      <span className="font-mono font-bold text-rose-400">{count} blocks</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="glass-panel p-5 rounded-xl border border-border space-y-3">
              <h4 className="text-sm font-semibold flex items-center gap-2">
                <Users className="w-4 h-4 text-amber-400" />
                Affected Client IP Addresses
              </h4>
              {(result.affected_clients || []).length === 0 ? (
                <div className="py-6 text-center text-xs text-muted-foreground">
                  Zero client IPs affected.
                </div>
              ) : (
                <div className="space-y-2 max-h-60 overflow-y-auto">
                  {result.affected_clients.map((ip) => (
                    <div key={ip} className="flex justify-between items-center text-xs p-2 bg-secondary/40 rounded border border-border/50">
                      <span className="font-mono text-foreground">{ip}</span>
                      <span className="text-muted-foreground">Triggered Match</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Action Bar */}
          <div className="glass-panel p-4 rounded-xl border border-border flex items-center justify-between">
            <div>
              <div className="text-sm font-semibold">Ready to Enforce?</div>
              <div className="text-xs text-muted-foreground">
                Deploy this verified rule directly into Envoy active policy via xDS ECDS.
              </div>
            </div>
            <button
              onClick={handleDeployRule}
              disabled={publishing}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-semibold shadow-lg"
            >
              <Send className="w-4 h-4" />
              {publishing ? "Deploying..." : "Deploy Rule Safely"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

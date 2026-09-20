"use client";

import { useState, useEffect } from "react";
import { 
  GitBranch, 
  Play, 
  RotateCcw, 
  CheckCircle2, 
  Activity, 
  Gauge, 
  Plus, 
  RefreshCw, 
  Sliders, 
  ShieldCheck, 
  Cpu, 
  Flame,
  AlertTriangle,
  FileCode2,
  TrendingUp,
  Radio
} from "lucide-react";
import { API } from "@/lib/api";

interface CanaryDeployment {
  id: number;
  app_id: number;
  policy_name: string;
  candidate_seclang: string;
  traffic_weight_pct: number;
  status: string;
  error_threshold_5xx_pct: number;
  created_at: string;
}

interface RuleProfilerStat {
  rule_id: string;
  rule_name: string;
  hit_count: number;
  avg_eval_ms: number;
  p95_eval_ms: number;
  memory_footprint_kb: number;
  latency_impact: string;
}

interface ScrapingPolicy {
  id: number;
  app_id: number;
  name: string;
  target_path: string;
  max_pages: number;
  window_seconds: number;
  action: string;
  is_enabled: boolean;
}

export default function CanaryGitOpsPage() {
  const [canaries, setCanaries] = useState<CanaryDeployment[]>([]);
  const [profilerStats, setProfilerStats] = useState<RuleProfilerStat[]>([]);
  const [scrapingPolicies, setScrapingPolicies] = useState<ScrapingPolicy[]>([]);
  const [loading, setLoading] = useState(true);

  // WAF as code
  const [specContent, setSpecContent] = useState(`application: rms-production
mode: blocking

rules:
  - crs: "942100"
  - crs: "941100"

exceptions:
  - rule: "942100"
    path: "/api/search"
    parameter: "q"

rate_limits:
  - path: "/api/login"
    requests: 10
    window: "1m"
`);
  const [wafCodeResult, setWafCodeResult] = useState<any>(null);

  // New Canary Form
  const [showCanaryModal, setShowCanaryModal] = useState(false);
  const [canaryName, setCanaryName] = useState("");
  const [canarySecLang, setCanarySecLang] = useState(`SecRule ARGS:promo_code "@rx (?i)voucher_[0-9]+" "id:200001,phase:2,deny,status:403,msg:'Strict Promo Code Validator'"`);
  const [initialWeight, setInitialWeight] = useState(5);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [cRes, pRes, sRes] = await Promise.all([
        fetch(`${API}/api/v1/canary-deployments`),
        fetch(`${API}/api/v1/rule-profiler/stats`),
        fetch(`${API}/api/v1/scraping-policies`),
      ]);
      if (cRes.ok) setCanaries((await cRes.json()) || []);
      if (pRes.ok) setProfilerStats((await pRes.json()) || []);
      if (sRes.ok) setScrapingPolicies((await sRes.json()) || []);
    } catch (err) {
      console.error("Failed to fetch canary/gitops data", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleCreateCanary = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API}/api/v1/canary-deployments`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          app_id: 1,
          policy_name: canaryName,
          candidate_seclang: canarySecLang,
          traffic_weight_pct: initialWeight,
          error_threshold_5xx_pct: 1.0,
        }),
      });
      if (res.ok) {
        setShowCanaryModal(false);
        setCanaryName("");
        await fetchData();
      }
    } catch (err) {
      console.error("Failed to start canary", err);
    }
  };

  const stepCanary = async (id: number, action: "STEP_UP" | "PROMOTE" | "ROLLBACK") => {
    try {
      const res = await fetch(`${API}/api/v1/canary-deployments/${id}/step`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      });
      if (res.ok) {
        await fetchData();
      }
    } catch (err) {
      console.error("Failed to step canary", err);
    }
  };

  const validateWafCode = async () => {
    try {
      const res = await fetch(`${API}/api/v1/waf-as-code/validate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ spec_content: specContent }),
      });
      if (res.ok) {
        setWafCodeResult(await res.json());
      }
    } catch (err) {
      console.error("Failed to validate WAF as code", err);
    }
  };

  const applyWafCode = async () => {
    try {
      const res = await fetch(`${API}/api/v1/waf-as-code/apply`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          spec_content: specContent,
          author: "console-operator",
          commit_hash: "git-" + Math.random().toString(16).substring(2, 8),
        }),
      });
      if (res.ok) {
        const json = await res.json();
        alert(`Success: ${json.message}`);
      }
    } catch (err) {
      console.error("Failed to apply WAF as code", err);
    }
  };

  return (
    <div className="space-y-8 pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-cyan-400 flex items-center gap-2">
            <GitBranch className="w-6 h-6 text-emerald-400" />
            Pillars 4, 5 & 7: Canary Deployments & WAF-as-Code (Phases 41-45)
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Safe staged canary deployments (5% → 25% → 100%), Coraza engine rule profiling, scraping shields, and GitOps policy automation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchData}
            disabled={loading}
            className="p-2.5 rounded-lg border border-border bg-card/50 text-foreground hover:bg-card hover:text-emerald-400 transition-colors"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
          <button
            onClick={() => setShowCanaryModal(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-black font-semibold text-sm shadow-lg shadow-emerald-500/20 transition-all"
          >
            <Plus className="w-4 h-4" />
            Launch Canary Policy
          </button>
        </div>
      </div>

      {/* Section 1: Canary Deployments */}
      <div className="glass rounded-xl border border-border overflow-hidden">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-emerald-400" />
            <h2 className="font-bold text-foreground text-sm">Safe Progressive Canary Rollouts (Phase 42)</h2>
          </div>
          <span className="text-xs text-muted-foreground">Automatic 5xx/latency tripwire guards</span>
        </div>

        <div className="p-4 space-y-4">
          {canaries.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground text-sm">
              No active canary deployments. Launch one to safely test candidate SecLang rules on a fractional percentage of traffic.
            </div>
          ) : (
            canaries.map((c) => (
              <div key={c.id} className="p-4 rounded-xl border border-border bg-card/40 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <span className="font-bold text-foreground text-sm">{c.policy_name}</span>
                    <span className="text-xs text-muted-foreground ml-2">ID #{c.id}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-0.5 rounded text-xs font-semibold ${
                      c.status === "ACTIVE" 
                        ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                        : c.status === "PROMOTED"
                        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                        : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                    }`}>
                      {c.status}
                    </span>
                    <span className="text-xs font-mono font-bold text-foreground">{c.traffic_weight_pct}% Traffic</span>
                  </div>
                </div>

                {/* Progress bar */}
                <div className="w-full bg-secondary h-2.5 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-emerald-500 to-cyan-500 transition-all duration-300"
                    style={{ width: `${c.traffic_weight_pct}%` }}
                  />
                </div>

                <div className="flex items-center justify-between pt-1 text-xs">
                  <span className="font-mono text-muted-foreground truncate max-w-md">{c.candidate_seclang}</span>
                  {c.status === "ACTIVE" && (
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => stepCanary(c.id, "STEP_UP")}
                        className="px-3 py-1 rounded bg-secondary hover:bg-emerald-500/20 hover:text-emerald-400 border border-border font-medium transition-colors"
                      >
                        +15% Step Up
                      </button>
                      <button
                        onClick={() => stepCanary(c.id, "PROMOTE")}
                        className="px-3 py-1 rounded bg-emerald-500 hover:bg-emerald-600 text-black font-semibold transition-colors"
                      >
                        Promote 100%
                      </button>
                      <button
                        onClick={() => stepCanary(c.id, "ROLLBACK")}
                        className="px-3 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 font-medium transition-colors"
                      >
                        Rollback
                      </button>
                    </div>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Section 2: Coraza Engine Rule Performance Profiler */}
      <div className="glass rounded-xl border border-border overflow-hidden">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Gauge className="w-5 h-5 text-cyan-400" />
            <h2 className="font-bold text-foreground text-sm">Rule Performance Profiler (Phase 43)</h2>
          </div>
          <span className="text-xs text-muted-foreground">Real-time Coraza WASM latency benchmark</span>
        </div>

        <table className="w-full text-left border-collapse text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/20 text-xs font-semibold uppercase text-muted-foreground">
              <th className="p-4">Rule ID</th>
              <th className="p-4">Rule Name</th>
              <th className="p-4">Evaluations / Hits</th>
              <th className="p-4">Avg Eval</th>
              <th className="p-4">P95 Eval</th>
              <th className="p-4">Memory Footprint</th>
              <th className="p-4">Latency Impact</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {profilerStats.map((r) => (
              <tr key={r.rule_id} className="hover:bg-muted/10 transition-colors">
                <td className="p-4 font-mono font-semibold text-cyan-400">{r.rule_id}</td>
                <td className="p-4 font-medium text-foreground">{r.rule_name}</td>
                <td className="p-4 font-mono text-muted-foreground">{r.hit_count.toLocaleString()}</td>
                <td className="p-4 font-mono text-foreground">{r.avg_eval_ms}ms</td>
                <td className="p-4 font-mono text-muted-foreground">{r.p95_eval_ms}ms</td>
                <td className="p-4 font-mono text-muted-foreground">{r.memory_footprint_kb} KB</td>
                <td className="p-4">
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                    r.latency_impact === "LOW" || r.latency_impact === "VERY_LOW" || r.latency_impact === "NEGLIGIBLE"
                      ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                      : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                  }`}>
                    {r.latency_impact}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Section 3: WAF-as-Code GitOps Studio */}
      <div className="glass rounded-xl border border-border p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div className="flex items-center gap-2">
            <FileCode2 className="w-5 h-5 text-indigo-400" />
            <h2 className="font-bold text-foreground text-sm">WAF-as-Code GitOps Pipeline (Phase 45)</h2>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={validateWafCode}
              className="px-3 py-1.5 rounded-lg bg-secondary hover:bg-card border border-border text-xs font-semibold transition-colors"
            >
              Validate Spec
            </button>
            <button
              onClick={applyWafCode}
              className="px-3 py-1.5 rounded-lg bg-indigo-500 hover:bg-indigo-600 text-white text-xs font-semibold transition-colors shadow-lg shadow-indigo-500/20"
            >
              Apply via CI/CD
            </button>
          </div>
        </div>

        <p className="text-xs text-muted-foreground">
          Define application security policies declaratively in YAML. Changes go through automated syntax verification, false-positive regression checks, and Git review before promotion to the data plane.
        </p>

        <textarea
          rows={10}
          value={specContent}
          onChange={(e) => setSpecContent(e.target.value)}
          className="w-full bg-secondary/50 border border-border rounded-lg p-3 text-xs font-mono text-emerald-400 focus:outline-none focus:border-indigo-500 resize-none"
        />

        {wafCodeResult && (
          <div className={`p-4 rounded-lg border text-xs font-mono ${
            wafCodeResult.is_valid
              ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
              : "bg-rose-500/10 border-rose-500/20 text-rose-400"
          }`}>
            <div className="font-bold mb-1">
              {wafCodeResult.is_valid ? "✓ Spec Validated Successfully" : "✗ Spec Validation Failed"}
            </div>
            <div>Application: {wafCodeResult.application} | Mode: {wafCodeResult.mode} | Analyzed: {wafCodeResult.lines_analyzed} lines</div>
            {wafCodeResult.syntax_errors?.length > 0 && (
              <ul className="list-disc pl-4 mt-2">
                {wafCodeResult.syntax_errors.map((err: string, i: number) => (
                  <li key={i}>{err}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>

      {/* Modal: Launch Canary */}
      {showCanaryModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass border border-border rounded-xl max-w-lg w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-foreground">Launch Safe Canary Policy</h3>
            <form onSubmit={handleCreateCanary} className="space-y-4 pt-2">
              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Canary Policy Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Promo Abuse Anti-Voucher Farmer"
                  value={canaryName}
                  onChange={(e) => setCanaryName(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Initial Traffic Percentage</label>
                <select
                  value={initialWeight}
                  onChange={(e) => setInitialWeight(Number(e.target.value))}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-emerald-500"
                >
                  <option value={5}>5% of traffic</option>
                  <option value={10}>10% of traffic</option>
                  <option value={25}>25% of traffic</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Candidate SecLang Rule</label>
                <textarea
                  rows={4}
                  required
                  value={canarySecLang}
                  onChange={(e) => setCanarySecLang(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg p-3 text-xs font-mono text-foreground focus:outline-none focus:border-emerald-500 resize-none"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-border">
                <button
                  type="button"
                  onClick={() => setShowCanaryModal(false)}
                  className="px-4 py-2 rounded-lg text-sm text-muted-foreground hover:bg-secondary transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-black font-semibold text-sm transition-all"
                >
                  Start Canary
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}


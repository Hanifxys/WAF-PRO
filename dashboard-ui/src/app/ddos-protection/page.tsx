"use client";

import { useState, useEffect } from "react";
import { 
  Waves, 
  ShieldAlert, 
  Zap, 
  Plus, 
  Trash2, 
  RefreshCw, 
  CheckCircle2, 
  Clock, 
  Gauge, 
  Activity, 
  AlertTriangle,
  Play,
  Settings2,
  Lock
} from "lucide-react";

interface DDoSPolicy {
  id: number;
  name: string;
  target_app_id: number;
  rps_threshold: number;
  burst_multiplier: number;
  surge_ratio: number;
  action: string;
  header_timeout_ms: number;
  body_timeout_ms: number;
  max_concurrent_conns: number;
  is_enabled: boolean;
  created_at: string;
}

interface SurgeSimulationResult {
  status: string;
  simulated_rps: number;
  baseline_rps: number;
  surge_threshold_rps: number;
  mitigation_action: string;
  dropped_requests: number;
  concurrency_limit: number;
  mitigation_active: boolean;
}

export default function DDoSProtectionPage() {
  const [policies, setPolicies] = useState<DDoSPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Form State
  const [name, setName] = useState("");
  const [rpsThreshold, setRpsThreshold] = useState(500);
  const [burstMultiplier, setBurstMultiplier] = useState(3);
  const [surgeRatio, setSurgeRatio] = useState(5.0);
  const [action, setAction] = useState("BLOCK");
  const [headerTimeoutMs, setHeaderTimeoutMs] = useState(5000);
  const [bodyTimeoutMs, setBodyTimeoutMs] = useState(10000);
  const [maxConcurrentConns, setMaxConcurrentConns] = useState(1000);

  // Surge Simulator State
  const [simRps, setSimRps] = useState(2500);
  const [simDuration, setSimDuration] = useState(30);
  const [simClients, setSimClients] = useState(150);
  const [simResult, setSimResult] = useState<SurgeSimulationResult | null>(null);
  const [simulating, setSimulating] = useState(false);

  const fetchPolicies = async () => {
    try {
      setLoading(true);
      const res = await fetch("http://localhost:8082/api/v1/ddos-policies");
      if (res.ok) {
        const data = await res.json();
        setPolicies(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      console.error("Failed to load DDoS policies", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setIsSubmitting(true);
      const res = await fetch("http://localhost:8082/api/v1/ddos-policies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.trim(),
          target_app_id: 1,
          rps_threshold: Number(rpsThreshold),
          burst_multiplier: Number(burstMultiplier),
          surge_ratio: Number(surgeRatio),
          action,
          header_timeout_ms: Number(headerTimeoutMs),
          body_timeout_ms: Number(bodyTimeoutMs),
          max_concurrent_conns: Number(maxConcurrentConns)
        })
      });
      if (res.ok) {
        setShowModal(false);
        setName("");
        fetchPolicies();
      }
    } catch (err) {
      console.error("Failed to create DDoS policy", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleToggle = async (id: number) => {
    try {
      const res = await fetch(`http://localhost:8082/api/v1/ddos-policies/${id}/toggle`, {
        method: "PUT"
      });
      if (res.ok) fetchPolicies();
    } catch (err) {
      console.error("Failed to toggle policy", err);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Are you sure you want to delete this L7 DDoS mitigation policy?")) return;
    try {
      const res = await fetch(`http://localhost:8082/api/v1/ddos-policies/${id}`, {
        method: "DELETE"
      });
      if (res.ok) fetchPolicies();
    } catch (err) {
      console.error("Failed to delete policy", err);
    }
  };

  const handleRunSurgeSim = async () => {
    try {
      setSimulating(true);
      const res = await fetch("http://localhost:8082/api/v1/ddos-policies/simulate-surge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_app_id: 1,
          simulated_rps: Number(simRps),
          duration_seconds: Number(simDuration),
          source_ip_count: Number(simClients)
        })
      });
      if (res.ok) {
        const data = await res.json();
        setSimResult(data);
      }
    } catch (err) {
      console.error("Surge simulation failed", err);
    } finally {
      setSimulating(false);
    }
  };

  const enabledCount = policies.filter(p => p.is_enabled).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-5">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <Waves className="w-7 h-7 text-cyan-400" />
            L7 DDoS &amp; Traffic Surge Mitigation Shield
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Application-layer surge protection, anti-Slowloris connection timeouts, and automatic multi-factor throttling on Envoy edge.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchPolicies}
            className="p-2.5 rounded-lg border border-border bg-secondary/50 hover:bg-secondary text-foreground transition-colors"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin text-cyan-400" : ""}`} />
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-600 text-slate-950 font-bold shadow-lg shadow-cyan-500/20 transition-all text-sm"
          >
            <Plus className="w-4 h-4 stroke-[3]" />
            New DDoS Policy
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl border border-border bg-card/60 backdrop-blur-sm relative overflow-hidden">
          <div className="flex justify-between items-start">
            <div className="space-y-1">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Active Policies</span>
              <h2 className="text-3xl font-bold text-foreground">{enabledCount} / {policies.length}</h2>
            </div>
            <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <Waves className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-muted-foreground flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" /> Real-time edge evaluation
          </div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/60 backdrop-blur-sm relative overflow-hidden">
          <div className="flex justify-between items-start">
            <div className="space-y-1">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Baseline Capacity</span>
              <h2 className="text-3xl font-bold text-emerald-400">500 RPS</h2>
            </div>
            <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Gauge className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-muted-foreground flex items-center gap-1.5">
            Normal operational baseline
          </div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/60 backdrop-blur-sm relative overflow-hidden">
          <div className="flex justify-between items-start">
            <div className="space-y-1">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Surge Threshold</span>
              <h2 className="text-3xl font-bold text-amber-400">5.0x (2,500 RPS)</h2>
            </div>
            <div className="p-2.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <Zap className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-muted-foreground flex items-center gap-1.5">
            Automatic isolation trigger
          </div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/60 backdrop-blur-sm relative overflow-hidden">
          <div className="flex justify-between items-start">
            <div className="space-y-1">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Anti-Slowloris</span>
              <h2 className="text-3xl font-bold text-rose-400">5,000 ms</h2>
            </div>
            <div className="p-2.5 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
              <Clock className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-muted-foreground flex items-center gap-1.5">
            Header timeout threshold
          </div>
        </div>
      </div>

      {/* Policies Table */}
      <div className="rounded-xl border border-border bg-card/40 backdrop-blur-sm overflow-hidden">
        <div className="p-4 border-b border-border/60 flex items-center justify-between bg-card/60">
          <div className="flex items-center gap-2">
            <Settings2 className="w-4 h-4 text-cyan-400" />
            <h3 className="font-semibold text-sm text-foreground">Enforced L7 DDoS &amp; Surge Profiles</h3>
          </div>
          <span className="text-xs text-muted-foreground font-mono">Envoy Token Bucket &amp; Timeouts</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-secondary/40 text-muted-foreground uppercase font-mono text-[11px] tracking-wider border-b border-border/40">
              <tr>
                <th className="py-3 px-4 font-semibold">Policy Name</th>
                <th className="py-3 px-4 font-semibold">RPS Baseline</th>
                <th className="py-3 px-4 font-semibold">Burst Mult.</th>
                <th className="py-3 px-4 font-semibold">Surge Ratio</th>
                <th className="py-3 px-4 font-semibold">Mitigation Action</th>
                <th className="py-3 px-4 font-semibold">Timeouts (Hdr / Body)</th>
                <th className="py-3 px-4 font-semibold">Status</th>
                <th className="py-3 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/30 font-sans">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-muted-foreground">
                    <RefreshCw className="w-6 h-6 animate-spin text-cyan-400 mx-auto mb-2" />
                    Loading DDoS protection profiles...
                  </td>
                </tr>
              ) : policies.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-muted-foreground">
                    <ShieldAlert className="w-8 h-8 text-muted-foreground mx-auto mb-2 opacity-50" />
                    No DDoS policies defined. Click &quot;New DDoS Policy&quot; to configure L7 surge defense.
                  </td>
                </tr>
              ) : (
                policies.map((p) => (
                  <tr key={p.id} className="hover:bg-secondary/20 transition-colors group">
                    <td className="py-3.5 px-4 font-semibold text-foreground">
                      <div className="flex items-center gap-2">
                        <Waves className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                        <span>{p.name}</span>
                      </div>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-xs text-foreground">
                      {p.rps_threshold} req/s
                    </td>
                    <td className="py-3.5 px-4 font-mono text-xs text-muted-foreground">
                      {p.burst_multiplier}x
                    </td>
                    <td className="py-3.5 px-4 font-mono text-xs text-amber-400 font-bold">
                      {p.surge_ratio}x ({p.rps_threshold * p.surge_ratio} RPS)
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono border ${
                        p.action === "BLOCK"
                          ? "bg-rose-500/15 text-rose-400 border-rose-500/30"
                          : p.action === "RATE_LIMIT"
                          ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
                          : "bg-cyan-500/15 text-cyan-400 border-cyan-500/30"
                      }`}>
                        {p.action}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[11px] text-muted-foreground">
                      {p.header_timeout_ms}ms / {p.body_timeout_ms}ms
                    </td>
                    <td className="py-3.5 px-4">
                      <button
                        onClick={() => handleToggle(p.id)}
                        className={`px-2.5 py-1 rounded text-xs font-semibold border transition-all ${
                          p.is_enabled
                            ? "bg-emerald-500/15 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/25"
                            : "bg-secondary/40 border-border text-muted-foreground hover:text-foreground"
                        }`}
                      >
                        {p.is_enabled ? "ACTIVE" : "DISABLED"}
                      </button>
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={() => handleDelete(p.id)}
                        className="p-1.5 rounded-md hover:bg-rose-500/15 text-muted-foreground hover:text-rose-400 transition-colors"
                        title="Delete Policy"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Interactive Traffic Surge Simulator */}
      <div className="rounded-xl border border-border bg-card/40 backdrop-blur-sm p-6 space-y-6">
        <div className="flex items-center justify-between border-b border-border/60 pb-4">
          <div>
            <h2 className="text-lg font-bold text-foreground flex items-center gap-2">
              <Play className="w-5 h-5 text-amber-400" />
              L7 Traffic Surge &amp; Stress Simulator
            </h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              Simulate high-volume volumetric HTTP surges and test whether active thresholds correctly engage drop, challenge, or throttle actions.
            </p>
          </div>
          <button
            onClick={handleRunSurgeSim}
            disabled={simulating}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-600 text-slate-950 font-bold text-sm shadow-lg shadow-amber-500/20 transition-all disabled:opacity-50"
          >
            <Play className={`w-4 h-4 fill-current ${simulating ? "animate-spin" : ""}`} />
            {simulating ? "Simulating Surge..." : "Simulate Surge Traffic"}
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Controls */}
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-xs font-semibold text-foreground mb-1.5">
                <span>Simulated Traffic Rate</span>
                <span className="font-mono text-cyan-400">{simRps} RPS</span>
              </div>
              <input
                type="range"
                min={200}
                max={10000}
                step={100}
                value={simRps}
                onChange={(e) => setSimRps(Number(e.target.value))}
                className="w-full h-2 bg-secondary rounded-lg appearance-none cursor-pointer accent-cyan-400"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-foreground mb-1">Surge Duration (seconds)</label>
                <input
                  type="number"
                  value={simDuration}
                  onChange={(e) => setSimDuration(Number(e.target.value))}
                  className="w-full rounded-lg border border-border bg-secondary/50 p-2 text-xs font-mono text-foreground"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-foreground mb-1">Simulated Source IPs</label>
                <input
                  type="number"
                  value={simClients}
                  onChange={(e) => setSimClients(Number(e.target.value))}
                  className="w-full rounded-lg border border-border bg-secondary/50 p-2 text-xs font-mono text-foreground"
                />
              </div>
            </div>
          </div>

          {/* Outcome */}
          <div className="rounded-lg border border-border/70 bg-black/40 p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-border/50">
                <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider font-mono">
                  Protection Response
                </span>
                {simResult && (
                  <span className={`text-xs font-bold px-2.5 py-0.5 rounded border ${
                    simResult.mitigation_active 
                      ? "bg-rose-500/20 text-rose-400 border-rose-500/30"
                      : "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                  }`}>
                    {simResult.status}
                  </span>
                )}
              </div>

              {!simResult ? (
                <div className="py-12 text-center text-muted-foreground text-xs">
                  <Activity className="w-8 h-8 mx-auto mb-2 text-muted-foreground/40" />
                  Select simulated RPS and duration, then click &quot;Simulate Surge Traffic&quot;.
                </div>
              ) : (
                <div className="mt-4 space-y-3 font-mono text-xs">
                  <div className="flex justify-between py-1 border-b border-border/30">
                    <span className="text-muted-foreground">Inbound Peak Load:</span>
                    <span className="text-foreground font-bold">{simResult.simulated_rps} RPS</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-border/30">
                    <span className="text-muted-foreground">Threshold Ratio:</span>
                    <span className="text-amber-400 font-bold">{simResult.surge_threshold_rps} RPS trigger</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-border/30">
                    <span className="text-muted-foreground">Action Engaged:</span>
                    <span className="text-cyan-400 font-bold">{simResult.mitigation_action}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-border/30">
                    <span className="text-muted-foreground">Estimated Mitigated Requests:</span>
                    <span className="text-rose-400 font-bold">{simResult.dropped_requests.toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-muted-foreground">Edge Concurrency Limit:</span>
                    <span className="text-foreground">{simResult.concurrency_limit} concurrent conns</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Modal: Create Policy */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-2xl border border-border bg-card p-6 shadow-2xl relative animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between pb-4 border-b border-border/60">
              <div className="flex items-center gap-2 text-foreground font-bold text-lg">
                <Waves className="w-5 h-5 text-cyan-400" />
                Configure L7 DDoS Mitigation Policy
              </div>
              <button 
                onClick={() => setShowModal(false)}
                className="text-muted-foreground hover:text-foreground p-1 rounded-lg"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreate} className="space-y-4 pt-4">
              <div>
                <label className="block text-xs font-medium text-foreground mb-1">Policy Profile Name</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Ingress Gateway Strict Surge Guard"
                  className="w-full rounded-lg border border-border bg-background p-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-foreground mb-1">RPS Threshold</label>
                  <input
                    type="number"
                    value={rpsThreshold}
                    onChange={(e) => setRpsThreshold(Number(e.target.value))}
                    className="w-full rounded-lg border border-border bg-background p-2 text-sm text-foreground font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-foreground mb-1">Burst Multiplier</label>
                  <input
                    type="number"
                    value={burstMultiplier}
                    onChange={(e) => setBurstMultiplier(Number(e.target.value))}
                    className="w-full rounded-lg border border-border bg-background p-2 text-sm text-foreground font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-foreground mb-1">Surge Ratio Multiplier</label>
                  <input
                    type="number"
                    step="0.5"
                    value={surgeRatio}
                    onChange={(e) => setSurgeRatio(Number(e.target.value))}
                    className="w-full rounded-lg border border-border bg-background p-2 text-sm text-foreground font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-foreground mb-1">Mitigation Action</label>
                  <select
                    value={action}
                    onChange={(e) => setAction(e.target.value)}
                    className="w-full rounded-lg border border-border bg-background p-2 text-sm text-foreground"
                  >
                    <option value="BLOCK">BLOCK (Drop Connection)</option>
                    <option value="RATE_LIMIT">RATE_LIMIT (HTTP 429)</option>
                    <option value="CHALLENGE">CHALLENGE (JS Bot Challenge)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-foreground mb-1">Header Timeout (ms)</label>
                  <input
                    type="number"
                    value={headerTimeoutMs}
                    onChange={(e) => setHeaderTimeoutMs(Number(e.target.value))}
                    className="w-full rounded-lg border border-border bg-background p-2 text-sm text-foreground font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-foreground mb-1">Body Timeout (ms)</label>
                  <input
                    type="number"
                    value={bodyTimeoutMs}
                    onChange={(e) => setBodyTimeoutMs(Number(e.target.value))}
                    className="w-full rounded-lg border border-border bg-background p-2 text-sm text-foreground font-mono"
                  />
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-border/60">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 rounded-lg border border-border hover:bg-secondary text-sm font-medium transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-600 text-slate-950 font-bold text-sm transition-all shadow-lg shadow-cyan-500/20 disabled:opacity-50"
                >
                  {isSubmitting ? "Deploying..." : "Deploy DDoS Shield"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

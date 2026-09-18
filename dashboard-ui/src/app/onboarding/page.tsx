"use client";

import { useState, useEffect } from "react";
import { 
  Sparkles, 
  ArrowRight, 
  CheckCircle2, 
  RefreshCw, 
  ShieldCheck, 
  Activity, 
  Globe, 
  Sliders, 
  Lock, 
  ChevronRight, 
  Play,
  Layers,
  Check,
  AlertCircle
} from "lucide-react";

interface Application {
  id: number;
  name: string;
  domain: string;
  backend_url: string;
  waf_mode: string;
  paranoia_level: number;
  status: string;
  learning_traffic_count: number;
  tenant_id?: string;
  created_at: string;
}

export default function ApplicationOnboardingPage() {
  const [apps, setApps] = useState<Application[]>([]);
  const [loading, setLoading] = useState(true);
  const [step, setStep] = useState(1);
  const [promotingId, setPromotingId] = useState<number | null>(null);
  const [promoteResult, setPromoteResult] = useState<any | null>(null);

  // Wizard Form State
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [backendUrl, setBackendUrl] = useState("http://");
  const [tenantId, setTenantId] = useState("telkomsel-core");
  const [paranoiaLevel, setParanoiaLevel] = useState(1);
  const [hsts, setHsts] = useState(true);
  const [nosniff, setNosniff] = useState(true);
  const [frameOptions, setFrameOptions] = useState("SAMEORIGIN");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const fetchApps = async () => {
    try {
      setLoading(true);
      const res = await fetch("http://localhost:8082/api/v1/applications");
      if (res.ok) {
        const json = await res.json();
        setApps(json || []);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchApps();
  }, []);

  const handleCreateOnboard = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      // 1. Create Application in LEARNING status
      const res = await fetch("http://localhost:8082/api/v1/applications", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          domain,
          backend_url: backendUrl,
          waf_mode: "MONITOR",
          paranoia_level: Number(paranoiaLevel),
          status: "LEARNING"
        })
      });

      if (res.ok) {
        const created = await res.json();
        // 2. Set Security Headers
        await fetch(`http://localhost:8082/api/v1/applications/${created.id}/security-headers`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            hsts_enabled: hsts,
            nosniff: nosniff,
            frame_options: frameOptions,
            csp: "default-src 'self'",
            referrer_policy: "strict-origin-when-cross-origin"
          })
        });

        // Reset wizard
        setStep(1);
        setName("");
        setDomain("");
        setBackendUrl("http://");
        fetchApps();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handlePromoteLearning = async (appId: number) => {
    setPromotingId(appId);
    try {
      const res = await fetch(`http://localhost:8082/api/v1/applications/${appId}/promote-learning`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_status: "PROTECTED",
          auto_approve_discovered_apis: true
        })
      });

      if (res.ok) {
        const result = await res.json();
        setPromoteResult(result);
        fetchApps();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setPromotingId(null);
    }
  };

  return (
    <div className="space-y-8 pb-12">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-amber-400 via-emerald-400 to-teal-400">
            Enterprise Application Onboarding & Learning Engine
          </h1>
          <p className="text-muted-foreground mt-1">
            Discover → Learn → Tune → Protect: Transition services from traffic observation to full enforcement with automated API allowlisting.
          </p>
        </div>
        <button 
          onClick={fetchApps} 
          className="flex items-center gap-2 px-3 py-2 bg-secondary/50 hover:bg-secondary text-foreground rounded-lg border border-border text-sm transition"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {promoteResult && (
        <div className="p-5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 flex items-start justify-between glass">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold text-sm text-foreground">{promoteResult.message}</div>
              <div className="text-xs text-muted-foreground mt-1">
                New State: <span className="text-emerald-400 font-semibold">{promoteResult.new_state}</span> • 
                Mode: <span className="text-emerald-400 font-semibold">{promoteResult.waf_mode}</span> • 
                Paranoia Level: <span className="text-emerald-400 font-semibold">PL {promoteResult.paranoia_level}</span> • 
                Discovered Endpoints Auto-Approved: <span className="text-cyan-400 font-semibold">{promoteResult.newly_approved_endpoints}</span>
              </div>
            </div>
          </div>
          <button onClick={() => setPromoteResult(null)} className="text-xs text-muted-foreground hover:text-foreground">
            Dismiss
          </button>
        </div>
      )}

      {/* Onboarding Wizard Card */}
      <div className="p-6 rounded-xl border border-border bg-card/60 glass backdrop-blur-md">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-amber-400" />
            <h2 className="text-lg font-semibold text-foreground">Application Onboarding Wizard</h2>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
            <span className={step >= 1 ? "text-amber-400 font-bold" : ""}>1. Target Host</span>
            <ChevronRight className="w-3 h-3" />
            <span className={step >= 2 ? "text-amber-400 font-bold" : ""}>2. Origin & Quota</span>
            <ChevronRight className="w-3 h-3" />
            <span className={step >= 3 ? "text-amber-400 font-bold" : ""}>3. Headers & Learning</span>
          </div>
        </div>

        <form onSubmit={handleCreateOnboard} className="space-y-4">
          {step === 1 && (
            <div className="space-y-4 animate-in fade-in">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-muted-foreground block mb-1">Application Name</label>
                  <input 
                    type="text" 
                    required
                    placeholder="e.g. MyTelkomsel Core API"
                    value={name} 
                    onChange={(e) => setName(e.target.value)}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-400"
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground block mb-1">Domain / Hostname</label>
                  <input 
                    type="text" 
                    required
                    placeholder="api.telkomsel.co.id"
                    value={domain} 
                    onChange={(e) => setDomain(e.target.value)}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-400 font-mono"
                  />
                </div>
              </div>
              <div className="flex justify-end">
                <button 
                  type="button" 
                  disabled={!name || !domain}
                  onClick={() => setStep(2)}
                  className="px-4 py-2 bg-amber-500 hover:bg-amber-600 disabled:opacity-50 text-black font-semibold text-sm rounded-lg flex items-center gap-2 transition"
                >
                  Next: Origin & Quota <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="space-y-4 animate-in fade-in">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-muted-foreground block mb-1">Backend Origin URL</label>
                  <input 
                    type="text" 
                    required
                    placeholder="http://internal-api-gw:8080"
                    value={backendUrl} 
                    onChange={(e) => setBackendUrl(e.target.value)}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-400 font-mono"
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground block mb-1">Tenant Partition</label>
                  <select 
                    value={tenantId} 
                    onChange={(e) => setTenantId(e.target.value)}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-400"
                  >
                    <option value="telkomsel-core">Telkomsel Enterprise Core (Enterprise)</option>
                    <option value="fintech-cluster">Fintech Merchant Cluster (Pro)</option>
                  </select>
                </div>
              </div>
              <div className="flex justify-between">
                <button 
                  type="button" 
                  onClick={() => setStep(1)}
                  className="px-4 py-2 bg-secondary text-foreground text-sm rounded-lg hover:bg-secondary/80 transition"
                >
                  Back
                </button>
                <button 
                  type="button" 
                  disabled={!backendUrl}
                  onClick={() => setStep(3)}
                  className="px-4 py-2 bg-amber-500 hover:bg-amber-600 disabled:opacity-50 text-black font-semibold text-sm rounded-lg flex items-center gap-2 transition"
                >
                  Next: Security Headers <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {step === 3 && (
            <div className="space-y-4 animate-in fade-in">
              <div className="p-4 rounded-lg bg-secondary/30 border border-border space-y-3">
                <div className="text-xs font-semibold text-foreground uppercase tracking-wider">
                  Automated Security Headers Configuration
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer">
                    <input type="checkbox" checked={hsts} onChange={(e) => setHsts(e.target.checked)} className="rounded" />
                    Strict-Transport-Security (HSTS)
                  </label>
                  <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer">
                    <input type="checkbox" checked={nosniff} onChange={(e) => setNosniff(e.target.checked)} className="rounded" />
                    X-Content-Type-Options (nosniff)
                  </label>
                  <div>
                    <label className="text-xs text-muted-foreground block mb-1">X-Frame-Options</label>
                    <select 
                      value={frameOptions} 
                      onChange={(e) => setFrameOptions(e.target.value)}
                      className="w-full bg-secondary/50 border border-border rounded px-2 py-1 text-xs focus:outline-none"
                    >
                      <option value="SAMEORIGIN">SAMEORIGIN</option>
                      <option value="DENY">DENY</option>
                    </select>
                  </div>
                </div>
              </div>

              <div className="p-4 rounded-lg bg-amber-500/10 border border-amber-500/20 text-xs text-amber-300 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>
                  Initial deployment will enter <strong>LEARNING</strong> mode to observe baseline API traffic and discover schemas before transitioning to enforcement.
                </span>
              </div>

              <div className="flex justify-between pt-2">
                <button 
                  type="button" 
                  onClick={() => setStep(2)}
                  className="px-4 py-2 bg-secondary text-foreground text-sm rounded-lg hover:bg-secondary/80 transition"
                >
                  Back
                </button>
                <button 
                  type="submit" 
                  disabled={isSubmitting}
                  className="px-5 py-2 bg-gradient-to-r from-amber-500 to-emerald-500 hover:from-amber-600 hover:to-emerald-600 text-black font-bold text-sm rounded-lg flex items-center gap-2 transition"
                >
                  {isSubmitting ? "Deploying..." : "Complete Onboarding & Start Learning"}
                </button>
              </div>
            </div>
          )}
        </form>
      </div>

      {/* Applications Lifecycle Catalog */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="w-5 h-5 text-emerald-400" />
            <h2 className="text-xl font-semibold text-foreground">Application Lifecycle Inventory</h2>
          </div>
          <span className="text-xs text-muted-foreground">{apps.length} total applications onboarded</span>
        </div>

        <div className="rounded-xl border border-border bg-card/40 glass overflow-hidden">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border bg-secondary/30 text-xs text-muted-foreground uppercase font-medium">
              <tr>
                <th className="px-5 py-3">Application</th>
                <th className="px-5 py-3">Domain</th>
                <th className="px-5 py-3">Lifecycle State</th>
                <th className="px-5 py-3">WAF Mode</th>
                <th className="px-5 py-3">Traffic Observed</th>
                <th className="px-5 py-3">Paranoia</th>
                <th className="px-5 py-3 text-right">Signature Promotion</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-5 py-8 text-center text-muted-foreground">Loading applications...</td>
                </tr>
              ) : apps.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-5 py-8 text-center text-muted-foreground">No applications found.</td>
                </tr>
              ) : (
                apps.map((app) => (
                  <tr key={app.id} className="hover:bg-secondary/20 transition">
                    <td className="px-5 py-3.5 font-medium text-foreground">{app.name}</td>
                    <td className="px-5 py-3.5 font-mono text-xs text-cyan-400">{app.domain}</td>
                    <td className="px-5 py-3.5">
                      <span className={`text-xs px-2.5 py-0.5 rounded-full font-semibold border flex items-center gap-1.5 w-fit ${
                        app.status === "PROTECTED"
                          ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                          : app.status === "LEARNING"
                          ? "bg-amber-500/10 text-amber-400 border-amber-500/20 animate-pulse"
                          : app.status === "REVIEW"
                          ? "bg-blue-500/10 text-blue-400 border-blue-500/20"
                          : "bg-secondary text-muted-foreground border-border"
                      }`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          app.status === "PROTECTED" ? "bg-emerald-400" : app.status === "LEARNING" ? "bg-amber-400" : "bg-blue-400"
                        }`} />
                        {app.status}
                      </span>
                    </td>
                    <td className="px-5 py-3.5">
                      <span className={`text-xs px-2 py-0.5 rounded font-mono font-medium ${
                        app.waf_mode === "BLOCK" ? "bg-rose-500/10 text-rose-400" : "bg-blue-500/10 text-blue-400"
                      }`}>
                        {app.waf_mode}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-xs text-muted-foreground">
                      {app.learning_traffic_count || 142} requests
                    </td>
                    <td className="px-5 py-3.5 font-mono text-xs text-purple-300">
                      PL {app.paranoia_level}
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      {app.status === "LEARNING" || app.status === "REVIEW" ? (
                        <button
                          onClick={() => handlePromoteLearning(app.id)}
                          disabled={promotingId === app.id}
                          className="px-3 py-1.5 bg-gradient-to-r from-amber-500 to-emerald-500 hover:from-amber-600 hover:to-emerald-600 text-black font-semibold rounded-lg text-xs transition shadow flex items-center gap-1.5 ml-auto"
                        >
                          <Sparkles className="w-3.5 h-3.5" />
                          {promotingId === app.id ? "Promoting..." : "Promote to Protected"}
                        </button>
                      ) : (
                        <span className="text-xs text-emerald-400 flex items-center gap-1 justify-end">
                          <Check className="w-3.5 h-3.5" /> Enforced
                        </span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

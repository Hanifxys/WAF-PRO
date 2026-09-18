"use client";

import { useState, useEffect } from "react";
import { 
  Building2, 
  Plus, 
  RefreshCw, 
  CheckCircle2, 
  Layers, 
  Zap, 
  Gauge, 
  ShieldCheck, 
  Lock,
  PieChart
} from "lucide-react";

interface Tenant {
  id: number;
  name: string;
  slug: string;
  plan_tier: string;
  max_applications: number;
  max_rps: number;
  status: string;
  created_at: string;
}

interface TenantUsage {
  tenant_id: number;
  tenant_name: string;
  plan_tier: string;
  max_applications: number;
  used_applications: number;
  max_rps: number;
  current_rps: number;
  rps_headroom_pct: number;
  status: string;
}

export default function TenantsPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [usages, setUsages] = useState<Record<number, TenantUsage>>({});
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Form State
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [planTier, setPlanTier] = useState("ENTERPRISE");
  const [maxApps, setMaxApps] = useState(20);
  const [maxRps, setMaxRps] = useState(10000);

  const fetchTenants = async () => {
    try {
      setLoading(true);
      const res = await fetch("http://localhost:8082/api/v1/tenants");
      if (res.ok) {
        const json: Tenant[] = await res.json();
        setTenants(json || []);

        // Fetch usage for each tenant
        const usageMap: Record<number, TenantUsage> = {};
        for (const t of json) {
          try {
            const uRes = await fetch(`http://localhost:8082/api/v1/tenants/${t.id}/usage`);
            if (uRes.ok) {
              usageMap[t.id] = await uRes.json();
            }
          } catch (e) {
            console.error(e);
          }
        }
        setUsages(usageMap);
      }
    } catch (err) {
      console.error("Failed to load tenants", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTenants();
  }, []);

  const handleCreateTenant = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      const res = await fetch("http://localhost:8082/api/v1/tenants", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          slug,
          plan_tier: planTier,
          max_applications: Number(maxApps),
          max_rps: Number(maxRps),
          status: "ACTIVE"
        })
      });

      if (res.ok) {
        setShowModal(false);
        setName("");
        setSlug("");
        fetchTenants();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-8 pb-12">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-orange-400 via-amber-400 to-yellow-400">
            Multi-Tenant Isolation & Quota Management
          </h1>
          <p className="text-muted-foreground mt-1">
            Strict tenant-level policy boundaries, application quotas, and capacity allocation across SaaS client partitions.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={fetchTenants} 
            className="flex items-center gap-2 px-3 py-2 bg-secondary/50 hover:bg-secondary text-foreground rounded-lg border border-border text-sm transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button 
            onClick={() => setShowModal(true)} 
            className="flex items-center gap-2 px-4 py-2 bg-amber-500 hover:bg-amber-600 text-black font-semibold rounded-lg text-sm shadow-lg shadow-amber-500/20 transition"
          >
            <Plus className="w-4 h-4" />
            Provision Tenant
          </button>
        </div>
      </div>

      {/* Tenant Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {loading ? (
          <div className="col-span-full py-12 text-center text-muted-foreground">Loading tenants...</div>
        ) : (
          tenants.map((t) => {
            const usage = usages[t.id];
            const headroom = usage ? usage.rps_headroom_pct : 100;
            return (
              <div key={t.id} className="p-6 rounded-xl border border-border bg-card/60 glass backdrop-blur-md space-y-4 hover:border-amber-400/50 transition">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <Building2 className="w-5 h-5 text-amber-400" />
                      <h3 className="font-semibold text-lg text-foreground">{t.name}</h3>
                    </div>
                    <div className="text-xs font-mono text-muted-foreground mt-1">slug: {t.slug}</div>
                  </div>
                  <span className={`text-xs px-2.5 py-0.5 rounded-full font-bold border ${
                    t.plan_tier === "ENTERPRISE" 
                      ? "bg-purple-500/10 text-purple-400 border-purple-500/20" 
                      : "bg-blue-500/10 text-blue-400 border-blue-500/20"
                  }`}>
                    {t.plan_tier}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 pt-2">
                  <div className="p-3 rounded-lg bg-secondary/30 border border-border">
                    <div className="text-xs text-muted-foreground">Applications</div>
                    <div className="text-lg font-bold text-foreground mt-1">
                      {usage?.used_applications || 1} / {t.max_applications}
                    </div>
                    <div className="text-[10px] text-muted-foreground mt-0.5">Quota Limit</div>
                  </div>

                  <div className="p-3 rounded-lg bg-secondary/30 border border-border">
                    <div className="text-xs text-muted-foreground">Throughput Quota</div>
                    <div className="text-lg font-bold text-cyan-400 mt-1">
                      {t.max_rps} RPS
                    </div>
                    <div className="text-[10px] text-muted-foreground mt-0.5">Max Ingress</div>
                  </div>
                </div>

                <div className="space-y-1.5 pt-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">Throughput Headroom</span>
                    <span className="font-semibold text-emerald-400">{headroom.toFixed(1)}% Available</span>
                  </div>
                  <div className="w-full bg-secondary/60 h-2 rounded-full overflow-hidden">
                    <div 
                      className="bg-gradient-to-r from-emerald-500 to-amber-400 h-full rounded-full transition-all duration-500"
                      style={{ width: `${headroom}%` }}
                    />
                  </div>
                </div>

                <div className="pt-2 border-t border-border flex items-center justify-between text-xs text-muted-foreground">
                  <span className="flex items-center gap-1 text-emerald-400 font-medium">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Isolated Namespace
                  </span>
                  <span>Created {new Date(t.created_at).toLocaleDateString()}</span>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Provision Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-card border border-border rounded-xl p-6 w-full max-w-md shadow-2xl glass space-y-4">
            <h3 className="text-lg font-semibold text-foreground">Provision New Tenant Partition</h3>
            <form onSubmit={handleCreateTenant} className="space-y-4">
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Organization / Tenant Name</label>
                <input 
                  type="text" 
                  required
                  placeholder="e.g. Bank Mandiri Digital Service"
                  value={name} 
                  onChange={(e) => {
                    setName(e.target.value);
                    if (!slug) setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9]/g, "-"));
                  }}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-400"
                />
              </div>

              <div>
                <label className="text-xs text-muted-foreground block mb-1">Tenant Slug (Unique ID)</label>
                <input 
                  type="text" 
                  required
                  placeholder="bank-mandiri-digital"
                  value={slug} 
                  onChange={(e) => setSlug(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-400 font-mono"
                />
              </div>

              <div>
                <label className="text-xs text-muted-foreground block mb-1">Subscription Tier</label>
                <select 
                  value={planTier} 
                  onChange={(e) => setPlanTier(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-400"
                >
                  <option value="ENTERPRISE">ENTERPRISE (50 Apps / 25K RPS)</option>
                  <option value="PRO">PRO (15 Apps / 8K RPS)</option>
                  <option value="COMMUNITY">COMMUNITY (3 Apps / 1K RPS)</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-muted-foreground block mb-1">Max Applications</label>
                  <input 
                    type="number" 
                    value={maxApps} 
                    onChange={(e) => setMaxApps(Number(e.target.value))}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-400"
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground block mb-1">Max RPS Quota</label>
                  <input 
                    type="number" 
                    value={maxRps} 
                    onChange={(e) => setMaxRps(Number(e.target.value))}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-400"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button 
                  type="button" 
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 bg-secondary text-foreground text-sm rounded-lg hover:bg-secondary/80 transition"
                >
                  Cancel
                </button>
                <button 
                  type="submit" 
                  disabled={isSubmitting}
                  className="px-4 py-2 bg-amber-500 hover:bg-amber-600 text-black font-semibold text-sm rounded-lg transition"
                >
                  {isSubmitting ? "Provisioning..." : "Provision Tenant"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

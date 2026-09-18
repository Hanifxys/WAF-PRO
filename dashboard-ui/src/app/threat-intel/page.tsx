"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Radar, Plus, Trash2, Search, ShieldAlert, RefreshCw, Globe, Zap, AlertTriangle, CheckCircle2, ShieldCheck, Flame, Cpu } from "lucide-react";

const API = "http://localhost:8082/api/v1";

interface ThreatIndicator {
  id: number;
  indicator: string;
  indicator_type: string;
  threat_category: string;
  confidence_score: number;
  severity: string;
  action: string;
  source_feed: string;
  is_active: boolean;
  expires_at?: string;
  created_at: string;
}

interface LookupResult {
  matched: boolean;
  queried_ip: string;
  indicator?: string;
  indicator_type?: string;
  threat_category?: string;
  confidence_score?: number;
  severity?: string;
  action?: string;
  source_feed?: string;
}

export default function ThreatIntelPage() {
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState<{ msg: string; type: "ok" | "err" } | null>(null);

  // Filter & Search
  const [filterType, setFilterType] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Lookup Tool
  const [lookupIP, setLookupIP] = useState<string>("185.220.101.5");
  const [lookupResult, setLookupResult] = useState<LookupResult | null>(null);
  const [lookingUp, setLookingUp] = useState(false);

  // Sync state
  const [syncing, setSyncing] = useState(false);

  // Modal
  const [showAddModal, setShowAddModal] = useState(false);
  const [form, setForm] = useState({
    indicator: "",
    indicator_type: "IP",
    threat_category: "MALICIOUS_IP",
    confidence_score: 90,
    severity: "HIGH",
    action: "BLOCK",
    source_feed: "INTERNAL_SOC_ANALYST",
    ttl_days: 30,
  });

  const showToast = (msg: string, type: "ok" | "err" = "ok") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  };

  const fetchIndicators = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (filterType) params.append("type", filterType);
      if (searchQuery) params.append("search", searchQuery);
      const res = await fetch(`${API}/threat-intel/indicators?${params.toString()}`);
      if (res.ok) {
        setIndicators(await res.json());
      }
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  }, [filterType, searchQuery]);

  useEffect(() => {
    fetchIndicators();
  }, [fetchIndicators]);

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupIP.trim()) return;
    setLookingUp(true);
    try {
      const res = await fetch(`${API}/threat-intel/lookup?ip=${encodeURIComponent(lookupIP.trim())}`);
      if (res.ok) {
        setLookupResult(await res.json());
      }
    } catch {
      showToast("Lookup request failed", "err");
    } finally {
      setLookingUp(false);
    }
  };

  const handleSyncWAF = async () => {
    setSyncing(true);
    try {
      const res = await fetch(`${API}/threat-intel/sync`, { method: "POST" });
      if (res.ok) {
        showToast("Threat indicators synchronized to Envoy xDS rules!");
      }
    } catch {
      showToast("Sync failed", "err");
    } finally {
      setSyncing(false);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.indicator.trim()) {
      showToast("Indicator address/domain required", "err");
      return;
    }
    try {
      const res = await fetch(`${API}/threat-intel/indicators`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (!res.ok) throw new Error(await res.text());
      showToast("Threat indicator registered & pushed to xDS");
      setShowAddModal(false);
      setForm({
        indicator: "",
        indicator_type: "IP",
        threat_category: "MALICIOUS_IP",
        confidence_score: 90,
        severity: "HIGH",
        action: "BLOCK",
        source_feed: "INTERNAL_SOC_ANALYST",
        ttl_days: 30,
      });
      fetchIndicators();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Creation failed";
      showToast(msg, "err");
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Remove this indicator from threat database?")) return;
    try {
      await fetch(`${API}/threat-intel/indicators/${id}`, { method: "DELETE" });
      showToast("Indicator deleted");
      fetchIndicators();
    } catch {
      showToast("Failed to delete indicator", "err");
    }
  };

  const totalIOCs = indicators.length;
  const torExits = indicators.filter((i) => i.threat_category === "TOR_EXIT").length;
  const botnets = indicators.filter((i) => i.threat_category === "BOTNET_C2").length;
  const cidrs = indicators.filter((i) => i.indicator_type === "CIDR").length;

  return (
    <div className="flex-1 p-6 space-y-6">
      {toast && (
        <div className={`fixed top-4 right-4 z-50 px-4 py-3 rounded-xl text-sm font-medium shadow-2xl border ${
          toast.type === "ok" ? "bg-emerald-500/20 border-emerald-500/40 text-emerald-300" : "bg-red-500/20 border-red-500/40 text-red-300"
        }`}>
          {toast.msg}
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-gradient-to-tr from-rose-500/20 to-amber-500/20 border border-rose-500/30">
            <Radar className="w-6 h-6 text-rose-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
              Threat Intelligence IOC Engine
              <span className="text-xs px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20">Pillar 7</span>
            </h1>
            <p className="text-sm text-muted-foreground">Dynamic Indicators of Compromise (IOC), Subnet CIDRs, and feed enforcement</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button onClick={fetchIndicators} className="p-2 rounded-xl border border-border bg-secondary/50 text-muted-foreground hover:text-foreground">
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={handleSyncWAF}
            disabled={syncing}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition"
          >
            <Zap className={`w-4 h-4 ${syncing ? "animate-spin" : ""}`} /> Sync to xDS
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold bg-rose-500 text-white hover:bg-rose-400 transition"
          >
            <Plus className="w-4 h-4" /> Add Indicator
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass p-5 rounded-2xl border border-border">
          <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Total Active IOCs</div>
          <div className="text-2xl font-bold text-foreground mt-2">{totalIOCs}</div>
          <div className="text-xs text-rose-400 mt-1 flex items-center gap-1">
            <ShieldAlert className="w-3.5 h-3.5" /> Synchronized to SecLang
          </div>
        </div>
        <div className="glass p-5 rounded-2xl border border-border">
          <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Subnet CIDR Ranges</div>
          <div className="text-2xl font-bold text-foreground mt-2">{cidrs}</div>
          <div className="text-xs text-amber-400 mt-1 flex items-center gap-1">
            <Globe className="w-3.5 h-3.5" /> High-speed subnet match
          </div>
        </div>
        <div className="glass p-5 rounded-2xl border border-border">
          <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Botnet C2 Nodes</div>
          <div className="text-2xl font-bold text-foreground mt-2">{botnets}</div>
          <div className="text-xs text-red-400 mt-1 flex items-center gap-1">
            <Flame className="w-3.5 h-3.5" /> Automated blocking active
          </div>
        </div>
        <div className="glass p-5 rounded-2xl border border-border">
          <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Tor Exit Nodes</div>
          <div className="text-2xl font-bold text-foreground mt-2">{torExits}</div>
          <div className="text-xs text-cyan-400 mt-1 flex items-center gap-1">
            <ShieldCheck className="w-3.5 h-3.5" /> Anonymizer protection
          </div>
        </div>
      </div>

      {/* Live IOC Lookup Tool */}
      <div className="glass p-6 rounded-2xl border border-border space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-foreground flex items-center gap-2">
            <Search className="w-4 h-4 text-cyan-400" /> Live Threat Intel Lookup Engine
          </h2>
          <span className="text-xs text-muted-foreground">Tests IP against CIDR subnets & single IPs</span>
        </div>

        <form onSubmit={handleLookup} className="flex gap-3">
          <input
            type="text"
            required
            placeholder="Enter IPv4 or IPv6 (e.g. 185.220.101.5 or 45.154.255.42)"
            value={lookupIP}
            onChange={(e) => setLookupIP(e.target.value)}
            className="flex-1 p-3 rounded-xl border border-border bg-secondary/50 font-mono text-sm focus:outline-none focus:border-cyan-400"
          />
          <button
            type="submit"
            disabled={lookingUp}
            className="px-6 py-3 rounded-xl bg-cyan-500 text-black font-semibold text-sm hover:bg-cyan-400 transition"
          >
            {lookingUp ? "Evaluating..." : "Check Reputation"}
          </button>
        </form>

        {lookupResult && (
          <div className={`p-4 rounded-xl border text-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
            lookupResult.matched
              ? "bg-rose-500/10 border-rose-500/30 text-rose-200"
              : "bg-emerald-500/10 border-emerald-500/30 text-emerald-200"
          }`}>
            <div className="space-y-1">
              <div className="font-bold flex items-center gap-2">
                {lookupResult.matched ? (
                  <>
                    <AlertTriangle className="w-5 h-5 text-rose-400" />
                    THREAT DETECTED: Matches {lookupResult.indicator} ({lookupResult.indicator_type})
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    CLEAN: No active IOC match found for {lookupResult.queried_ip}
                  </>
                )}
              </div>
              {lookupResult.matched && (
                <div className="text-xs opacity-90">
                  Category: <span className="font-semibold">{lookupResult.threat_category}</span> | 
                  Feed: <span className="font-semibold">{lookupResult.source_feed}</span> | 
                  Action: <span className="font-semibold">{lookupResult.action}</span>
                </div>
              )}
            </div>
            {lookupResult.matched && (
              <div className="flex items-center gap-3">
                <div className="text-right">
                  <div className="text-[10px] uppercase tracking-wider opacity-80">Confidence</div>
                  <div className="text-base font-bold text-rose-300">{lookupResult.confidence_score}%</div>
                </div>
                <span className="px-3 py-1 rounded-lg text-xs font-bold bg-rose-500 text-white">
                  {lookupResult.action}
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Filter and Table */}
      <div className="glass rounded-2xl border border-border overflow-hidden">
        <div className="p-4 border-b border-border flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 w-full sm:w-auto">
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="p-2 rounded-xl border border-border bg-secondary/50 text-xs text-foreground focus:outline-none focus:border-rose-400"
            >
              <option value="">All Types (IP, CIDR, DOMAIN)</option>
              <option value="IP">Single IP</option>
              <option value="CIDR">Subnet CIDR</option>
              <option value="DOMAIN">Host Domain</option>
            </select>
          </div>
          <div className="w-full sm:w-64">
            <input
              type="text"
              placeholder="Search indicators..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full p-2 rounded-xl border border-border bg-secondary/50 text-xs text-foreground focus:outline-none focus:border-rose-400"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-secondary/40 text-muted-foreground text-xs uppercase tracking-wider border-b border-border">
              <tr>
                <th className="px-6 py-4">Indicator Pattern</th>
                <th className="px-6 py-4">Type</th>
                <th className="px-6 py-4">Threat Classification</th>
                <th className="px-6 py-4">Confidence</th>
                <th className="px-6 py-4">WAF Action</th>
                <th className="px-6 py-4">Source Feed</th>
                <th className="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50">
              {indicators.map((ind) => (
                <tr key={ind.id} className="hover:bg-secondary/20 transition">
                  <td className="px-6 py-4 font-mono font-semibold text-rose-300">
                    {ind.indicator}
                  </td>
                  <td className="px-6 py-4">
                    <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-secondary text-foreground border border-border">
                      {ind.indicator_type}
                    </span>
                  </td>
                  <td className="px-6 py-4 font-medium text-foreground">
                    {ind.threat_category}
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-2 rounded-full bg-secondary overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-amber-500 to-rose-500"
                          style={{ width: `${ind.confidence_score}%` }}
                        />
                      </div>
                      <span className="text-xs text-muted-foreground">{ind.confidence_score}%</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${
                      ind.action === "BLOCK"
                        ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                        : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                    }`}>
                      {ind.action}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-xs text-muted-foreground">{ind.source_feed}</td>
                  <td className="px-6 py-4 text-right">
                    <button
                      onClick={() => handleDelete(ind.id)}
                      className="p-1.5 rounded-lg text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
              {indicators.length === 0 && !loading && (
                <tr>
                  <td colSpan={7} className="px-6 py-8 text-center text-muted-foreground">No indicators match criteria.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass rounded-2xl border border-border w-full max-w-md p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold text-foreground">Add Threat Indicator</h2>
              <button onClick={() => setShowAddModal(false)} className="text-muted-foreground hover:text-foreground">✕</button>
            </div>
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-muted-foreground uppercase">Indicator (IP / CIDR / Domain)</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 198.51.100.0/24 or attacker.c2.net"
                  value={form.indicator}
                  onChange={(e) => setForm({ ...form, indicator: e.target.value })}
                  className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 font-mono text-sm focus:outline-none focus:border-rose-400"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-semibold text-muted-foreground uppercase">Category</label>
                  <select
                    value={form.threat_category}
                    onChange={(e) => setForm({ ...form, threat_category: e.target.value })}
                    className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 text-sm focus:outline-none focus:border-rose-400"
                  >
                    <option value="MALICIOUS_IP">MALICIOUS_IP</option>
                    <option value="BOTNET_C2">BOTNET_C2</option>
                    <option value="TOR_EXIT">TOR_EXIT</option>
                    <option value="SCANNER">SCANNER</option>
                    <option value="PHISHING">PHISHING</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs font-semibold text-muted-foreground uppercase">Action</label>
                  <select
                    value={form.action}
                    onChange={(e) => setForm({ ...form, action: e.target.value })}
                    className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 text-sm focus:outline-none focus:border-rose-400"
                  >
                    <option value="BLOCK">BLOCK (Drop 403)</option>
                    <option value="CHALLENGE">CHALLENGE</option>
                    <option value="MONITOR">MONITOR (Log Only)</option>
                  </select>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-semibold text-muted-foreground uppercase">Confidence (0-100)</label>
                  <input
                    type="number"
                    min="1"
                    max="100"
                    value={form.confidence_score}
                    onChange={(e) => setForm({ ...form, confidence_score: parseInt(e.target.value) || 85 })}
                    className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 text-sm focus:outline-none focus:border-rose-400"
                  />
                </div>
                <div>
                  <label className="text-xs font-semibold text-muted-foreground uppercase">TTL Expiry (Days)</label>
                  <input
                    type="number"
                    value={form.ttl_days}
                    onChange={(e) => setForm({ ...form, ttl_days: parseInt(e.target.value) || 30 })}
                    className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 text-sm focus:outline-none focus:border-rose-400"
                  />
                </div>
              </div>
              <div>
                <label className="text-xs font-semibold text-muted-foreground uppercase">Source Threat Feed</label>
                <input
                  type="text"
                  value={form.source_feed}
                  onChange={(e) => setForm({ ...form, source_feed: e.target.value })}
                  className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 text-sm focus:outline-none focus:border-rose-400"
                />
              </div>
              <div className="flex justify-end gap-3 pt-4 border-t border-border">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded-xl text-sm border border-border text-muted-foreground hover:text-foreground"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 rounded-xl text-sm font-semibold bg-rose-500 text-white hover:bg-rose-400"
                >
                  Save & Push to xDS
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

"use client";

import React, { useState, useEffect } from "react";
import { format } from "date-fns";
import {
  ShieldCheck, Plus, Trash2, ShieldAlert, CheckCircle2, Globe,
  FileCode2, Power, Clock, Tag, AlertTriangle, ChevronRight, RefreshCw
} from "lucide-react";
import { API } from "@/lib/api";

interface CustomRule {
  id: number;
  rule_id: number;
  name: string;
  description: string;
  seclang_code: string;
  is_enabled: boolean;
  status: string;
  expires_at: string | null;
  ticket_ref: string;
  cve_id: string;
  target_app_id: number;
  version: number;
  action: string;
  created_at: string;
}

interface GeoPolicy {
  id: number;
  country_code: string;
  policy_action: string;
  reason: string;
  created_at: string;
}

const LIFECYCLE_STATES = ["DRAFT", "TEST", "MONITOR", "ENFORCE", "TUNED", "DEPRECATED"];

const lifecycleBadge = (status: string) => {
  const map: Record<string, string> = {
    DRAFT: "bg-gray-500/20 text-gray-400 border-gray-500/30",
    TEST: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    MONITOR: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    ENFORCE: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
    TUNED: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
    DEPRECATED: "bg-red-500/20 text-red-400 border-red-500/30",
  };
  return map[status] || "bg-gray-500/20 text-gray-400";
};

export default function PolicyStudioPage() {
  const [customRules, setCustomRules] = useState<CustomRule[]>([]);
  const [geoPolicies, setGeoPolicies] = useState<GeoPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [ruleID, setRuleID] = useState("100001");
  const [ruleName, setRuleName] = useState("");
  const [ruleDesc, setRuleDesc] = useState("");
  const [ruleStatus, setRuleStatus] = useState("ENFORCE");
  const [ruleCVE, setRuleCVE] = useState("");
  const [ruleTicket, setRuleTicket] = useState("");
  const [ruleTTL, setRuleTTL] = useState("0");
  const [secLangCode, setSecLangCode] = useState(
    'SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(masscan|zgrab|sqlmap)" "id:100001,phase:1,deny,status:403,msg:\'Virtual Patch: Malicious Reconnaissance Bot Blocked\'"'
  );
  const [lifecycleTarget, setLifecycleTarget] = useState<CustomRule | null>(null);
  const [newLifecycleStatus, setNewLifecycleStatus] = useState("ENFORCE");
  const [lcTicket, setLcTicket] = useState("");
  const [lcTTL, setLcTTL] = useState("0");
  const [geoCountry, setGeoCountry] = useState("RU");
  const [geoReason, setGeoReason] = useState("Enterprise Perimeter Threat Fencing");
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);


  const TTL_OPTIONS = [
    { label: "Permanent", value: "0" },
    { label: "24 Hours", value: "86400" },
    { label: "7 Days", value: "604800" },
    { label: "30 Days", value: "2592000" },
  ];

  const fetchData = async () => {
    setLoading(true);
    try {
      const [rRes, gRes] = await Promise.all([
        fetch(`${API}/api/v1/custom-rules`),
        fetch(`${API}/api/v1/geo-policies`),
      ]);
      if (rRes.ok) setCustomRules((await rRes.json()) || []);
      if (gRes.ok) setGeoPolicies((await gRes.json()) || []);
    } catch (err) {
      console.error("Failed to fetch policies:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API}/api/v1/custom-rules`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rule_id: parseInt(ruleID, 10),
          name: ruleName.trim(),
          description: ruleDesc.trim(),
          seclang_code: secLangCode.trim(),
          status: ruleStatus,
          cve_id: ruleCVE.trim(),
          ticket_ref: ruleTicket.trim(),
          ttl_seconds: parseInt(ruleTTL, 10) || 0,
        }),
      });
      if (res.ok) {
        setMessage({ type: "success", text: `Virtual Patch #${ruleID} (${ruleStatus}) pushed via xDS.` });
        setRuleName(""); setRuleDesc(""); setRuleCVE(""); setRuleTicket(""); setRuleTTL("0");
        setRuleID(String(parseInt(ruleID, 10) + 1));
        fetchData();
      } else {
        setMessage({ type: "error", text: "Failed to create custom rule." });
      }
    } catch { setMessage({ type: "error", text: "Connection error." }); }
  };

  const handleLifecycleTransition = async () => {
    if (!lifecycleTarget) return;
    try {
      const res = await fetch(`${API}/api/v1/custom-rules/${lifecycleTarget.id}/lifecycle`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newLifecycleStatus, ticket_ref: lcTicket.trim(), ttl_seconds: parseInt(lcTTL, 10) || 0 }),
      });
      if (res.ok) {
        setMessage({ type: "success", text: `Rule #${lifecycleTarget.rule_id} transitioned to ${newLifecycleStatus}.` });
        setLifecycleTarget(null); fetchData();
      } else { setMessage({ type: "error", text: "Lifecycle transition failed." }); }
    } catch { setMessage({ type: "error", text: "Connection error." }); }
  };

  const handleToggleRule = async (id: number) => {
    const res = await fetch(`${API}/api/v1/custom-rules/${id}/toggle`, { method: "PUT" });
    if (res.ok) fetchData();
  };

  const handleDeleteRule = async (id: number, rId: number) => {
    if (!confirm(`Delete Virtual Patch #${rId}?`)) return;
    const res = await fetch(`${API}/api/v1/custom-rules/${id}`, { method: "DELETE" });
    if (res.ok) { setMessage({ type: "success", text: `Patch #${rId} removed.` }); fetchData(); }
  };

  const handleCreateGeo = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await fetch(`${API}/api/v1/geo-policies`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ country_code: geoCountry, policy_action: "BLOCK", reason: geoReason }),
    });
    if (res.ok) { setMessage({ type: "success", text: `Geo fence [${geoCountry}] enforced.` }); setGeoCountry(""); fetchData(); }
  };

  const handleDeleteGeo = async (id: number) => {
    const res = await fetch(`${API}/api/v1/geo-policies/${id}`, { method: "DELETE" });
    if (res.ok) { setMessage({ type: "success", text: "Geo fence removed." }); fetchData(); }
  };

  const lifecycleModeHint: Record<string, string> = {
    DRAFT: "DRAFT — excluded from xDS compilation. Safe for authoring.",
    TEST: "TEST — compiled but scoped to test traffic only.",
    MONITOR: "MONITOR — compiled as pass+auditlog. No active blocking.",
    ENFORCE: "ENFORCE — compiled as deny rule. Active blocking in Envoy.",
    TUNED: "TUNED — finalized and enforcing. Version locked.",
    DEPRECATED: "DEPRECATED — retired from Envoy data plane.",
  };

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-12">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-cyan-400 flex items-center gap-2.5">
            <ShieldCheck className="w-7 h-7 text-emerald-400" />
            Enterprise Policy Studio & Virtual Patching
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Lifecycle-managed SecLang: DRAFT → TEST → MONITOR → ENFORCE → TUNED → DEPRECATED. Zero-downtime xDS push.
          </p>
        </div>
        <button onClick={fetchData} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-secondary border border-border text-xs hover:bg-secondary/80">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {message && (
        <div className={`p-4 rounded-lg flex items-center gap-3 border text-sm ${message.type === "success" ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400" : "bg-red-500/10 border-red-500/20 text-red-400"}`}>
          {message.type === "success" ? <CheckCircle2 className="w-4 h-4 flex-shrink-0" /> : <ShieldAlert className="w-4 h-4 flex-shrink-0" />}
          {message.text}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 glass-panel p-6 rounded-xl border border-border space-y-4">
          <h2 className="text-base font-semibold flex items-center gap-2">
            <FileCode2 className="w-4 h-4 text-emerald-400" />Deploy Virtual Patch / Custom SecLang Rule
          </h2>
          <form onSubmit={handleCreateRule} className="space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div>
                <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Rule ID</label>
                <input type="number" value={ruleID} onChange={(e) => setRuleID(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-emerald-500" required />
              </div>
              <div className="col-span-2">
                <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Rule Name</label>
                <input type="text" placeholder="CVE-2026-X Anti-Exploit Patch" value={ruleName} onChange={(e) => setRuleName(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500" required />
              </div>
              <div>
                <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Status</label>
                <select value={ruleStatus} onChange={(e) => setRuleStatus(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500">
                  {LIFECYCLE_STATES.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">CVE Reference</label>
                <input type="text" placeholder="CVE-2024-3400" value={ruleCVE} onChange={(e) => setRuleCVE(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-emerald-500" />
              </div>
              <div>
                <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Ticket / CRQ</label>
                <input type="text" placeholder="CRQ000000858920" value={ruleTicket} onChange={(e) => setRuleTicket(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-emerald-500" />
              </div>
              <div>
                <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Auto-Expiry</label>
                <select value={ruleTTL} onChange={(e) => setRuleTTL(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500">
                  {TTL_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </div>
            </div>
            <div>
              <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">SecLang Directive</label>
              <textarea rows={4} value={secLangCode} onChange={(e) => setSecLangCode(e.target.value)}
                className="w-full bg-slate-950 border border-border rounded-lg p-3 text-xs font-mono text-emerald-400 focus:outline-none focus:border-emerald-500" required />
            </div>
            <div className={`p-3 rounded-lg border text-xs flex items-center gap-2 ${lifecycleBadge(ruleStatus)}`}>
              <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
              {lifecycleModeHint[ruleStatus] || ""}
            </div>
            <button type="submit" className="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold rounded-lg text-sm flex items-center gap-2">
              <Plus className="w-4 h-4" /> Compile & Push Virtual Patch
            </button>
          </form>
        </div>

        <div className="glass-panel p-6 rounded-xl border border-border space-y-4">
          <h2 className="text-base font-semibold flex items-center gap-2">
            <Globe className="w-4 h-4 text-cyan-400" />Perimeter Geo-IP Fencing
          </h2>
          <form onSubmit={handleCreateGeo} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Country ISO Code</label>
              <input type="text" maxLength={2} placeholder="RU, CN, KP..." value={geoCountry} onChange={(e) => setGeoCountry(e.target.value.toUpperCase())}
                className="w-full bg-secondary/50 border border-border rounded-lg px-3.5 py-2 text-sm font-mono font-bold focus:outline-none focus:border-cyan-500" required />
            </div>
            <div>
              <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Reason / Ticket</label>
              <input type="text" value={geoReason} onChange={(e) => setGeoReason(e.target.value)}
                className="w-full bg-secondary/50 border border-border rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:border-cyan-500" required />
            </div>
            <button type="submit" className="w-full py-2 bg-cyan-500 hover:bg-cyan-600 text-slate-950 font-semibold rounded-lg text-sm flex items-center justify-center gap-2">
              <Plus className="w-4 h-4" /> Add Geo Block
            </button>
          </form>
          <div className="pt-2 border-t border-border space-y-2">
            <span className="text-xs font-semibold text-muted-foreground uppercase">Active Fences ({geoPolicies.length})</span>
            <div className="space-y-1.5 max-h-40 overflow-y-auto">
              {geoPolicies.map((gp) => (
                <div key={gp.id} className="flex items-center justify-between p-2 rounded bg-secondary/30 text-xs border border-border">
                  <div className="flex items-center gap-2">
                    <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 font-mono font-bold">{gp.country_code}</span>
                    <span className="text-muted-foreground truncate max-w-[120px]">{gp.reason}</span>
                  </div>
                  <button onClick={() => handleDeleteGeo(gp.id)} className="text-red-400 hover:text-red-300">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
              {geoPolicies.length === 0 && <div className="text-xs text-muted-foreground text-center py-4">No active geo fences.</div>}
            </div>
          </div>
        </div>
      </div>

      <div className="glass-panel rounded-xl border border-border overflow-hidden">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <h2 className="text-base font-semibold flex items-center gap-2">
            <FileCode2 className="w-4 h-4 text-emerald-400" />Virtual Patches & Custom Rules ({customRules.length})
          </h2>
          <span className="text-xs text-muted-foreground">Lifecycle-managed — pushed via xDS ECDS</span>
        </div>
        {loading ? (
          <div className="p-8 text-center text-sm text-muted-foreground">Loading policies...</div>
        ) : customRules.length === 0 ? (
          <div className="p-8 text-center text-sm text-muted-foreground">No custom rules active.</div>
        ) : (
          <div className="divide-y divide-border">
            {customRules.map((cr) => (
              <div key={cr.id} className="p-4 hover:bg-secondary/20 transition-colors space-y-3">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Rule #{cr.rule_id}</span>
                    <span className="font-semibold text-sm">{cr.name}</span>
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${lifecycleBadge(cr.status || "ENFORCE")}`}>{cr.status || "ENFORCE"}</span>
                    {cr.version > 1 && <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-purple-500/10 text-purple-400 border border-purple-500/20">v{cr.version}</span>}
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${cr.is_enabled ? "bg-emerald-500/10 text-emerald-400" : "bg-muted text-muted-foreground"}`}>
                      {cr.is_enabled ? "ON" : "OFF"}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button onClick={() => { setLifecycleTarget(cr); setNewLifecycleStatus(cr.status || "ENFORCE"); setLcTicket(cr.ticket_ref || ""); setLcTTL("0"); }}
                      className="flex items-center gap-1 px-2 py-1 text-[11px] font-semibold rounded bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 border border-blue-500/20">
                      <ChevronRight className="w-3 h-3" /> Lifecycle
                    </button>
                    <button onClick={() => handleToggleRule(cr.id)}
                      className={`p-1.5 rounded ${cr.is_enabled ? "hover:bg-amber-500/10 text-amber-400" : "hover:bg-emerald-500/10 text-emerald-400"}`}>
                      <Power className="w-4 h-4" />
                    </button>
                    <button onClick={() => handleDeleteRule(cr.id, cr.rule_id)} className="p-1.5 hover:bg-red-500/10 text-red-400 rounded">
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
                <div className="flex flex-wrap gap-2 text-[10px]">
                  {cr.cve_id && <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/20 font-mono"><Tag className="w-2.5 h-2.5" /> {cr.cve_id}</span>}
                  {cr.ticket_ref && <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono"><Tag className="w-2.5 h-2.5" /> {cr.ticket_ref}</span>}
                  {cr.expires_at && <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20"><Clock className="w-2.5 h-2.5" /> Expires: {format(new Date(cr.expires_at), "MMM d HH:mm")}</span>}
                </div>
                <pre className="p-2.5 rounded bg-slate-950 text-xs font-mono text-emerald-400 overflow-x-auto border border-border">{cr.seclang_code}</pre>
                <div className="text-[11px] text-muted-foreground">Created: {format(new Date(cr.created_at), "MMM d, yyyy HH:mm:ss")}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      {lifecycleTarget && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#121722] border border-emerald-500/30 rounded-xl w-full max-w-md p-6 space-y-5 shadow-2xl animate-in zoom-in-95 duration-200">
            <h3 className="text-base font-bold text-emerald-400 flex items-center gap-2">
              <ChevronRight className="w-5 h-5" /> Lifecycle Transition — Rule #{lifecycleTarget.rule_id}
            </h3>
            <div className="flex items-center gap-1 text-[10px] overflow-x-auto pb-1">
              {LIFECYCLE_STATES.map((s, i) => (
                <React.Fragment key={s}>
                  <button onClick={() => setNewLifecycleStatus(s)}
                    className={`px-2 py-1 rounded font-bold border whitespace-nowrap ${newLifecycleStatus === s ? lifecycleBadge(s) + " ring-1 ring-current" : "bg-secondary/30 text-muted-foreground border-border"}`}>
                    {s}
                  </button>
                  {i < LIFECYCLE_STATES.length - 1 && <span className="text-muted-foreground">→</span>}
                </React.Fragment>
              ))}
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-semibold text-muted-foreground mb-1">Ticket / CRQ</label>
                <input type="text" placeholder="CRQ000000858920" value={lcTicket} onChange={(e) => setLcTicket(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-xs font-mono focus:outline-none focus:border-emerald-500" />
              </div>
              <div>
                <label className="block text-xs font-semibold text-muted-foreground mb-1">Auto-Expiry TTL</label>
                <select value={lcTTL} onChange={(e) => setLcTTL(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-xs focus:outline-none focus:border-emerald-500">
                  {TTL_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </div>
            </div>
            <div className={`p-3 rounded-lg border text-xs flex items-center gap-2 ${lifecycleBadge(newLifecycleStatus)}`}>
              <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
              {lifecycleModeHint[newLifecycleStatus] || ""}
            </div>
            <div className="flex gap-3">
              <button onClick={handleLifecycleTransition} className="flex-1 py-2 bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold rounded-lg text-sm">
                Confirm Transition
              </button>
              <button onClick={() => setLifecycleTarget(null)} className="px-4 py-2 bg-secondary hover:bg-secondary/80 rounded-lg text-sm border border-border">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


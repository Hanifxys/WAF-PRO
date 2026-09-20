"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Share2, Plus, Trash2, Send, ShieldAlert, RefreshCw, Terminal, CheckCircle2, ToggleLeft, ToggleRight, Server, Zap, Radio } from "lucide-react";
import { API } from "@/lib/api";
interface SIEMDestination {
  id: number;
  name: string;
  format: string;
  endpoint_url: string;
  auth_header?: string;
  min_severity: string;
  is_enabled: boolean;
  created_at: string;
}

export default function SIEMPage() {
  const [destinations, setDestinations] = useState<SIEMDestination[]>([]);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState<{ msg: string; type: "ok" | "err" } | null>(null);

  // Test dispatch state
  const [dispatching, setDispatching] = useState(false);
  const [testResult, setTestResult] = useState<{ sample_cef?: string; sample_syslog?: string; status?: string } | null>(null);

  // Modal
  const [showAddModal, setShowAddModal] = useState(false);
  const [form, setForm] = useState({
    name: "",
    format: "CEF",
    endpoint_url: "",
    auth_header: "Splunk 8b21c432-1234-abcd-9876-feed00112233",
    min_severity: "HIGH",
  });

  const showToast = (msg: string, type: "ok" | "err" = "ok") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  };

  const fetchDestinations = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/siem/destinations`);
      if (res.ok) {
        setDestinations(await res.json());
      }
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDestinations();
  }, [fetchDestinations]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim() || !form.endpoint_url.trim()) {
      showToast("Name and Endpoint URL required", "err");
      return;
    }
    try {
      const res = await fetch(`${API}/siem/destinations`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (!res.ok) throw new Error(await res.text());
      showToast("SIEM connector registered successfully");
      setShowAddModal(false);
      setForm({
        name: "",
        format: "CEF",
        endpoint_url: "",
        auth_header: "",
        min_severity: "HIGH",
      });
      fetchDestinations();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Creation failed";
      showToast(msg, "err");
    }
  };

  const handleToggle = async (id: number) => {
    try {
      await fetch(`${API}/siem/destinations/${id}/toggle`, { method: "PUT" });
      fetchDestinations();
    } catch {
      showToast("Failed to toggle connector", "err");
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Delete this SIEM destination?")) return;
    try {
      await fetch(`${API}/siem/destinations/${id}`, { method: "DELETE" });
      showToast("Destination deleted");
      fetchDestinations();
    } catch {
      showToast("Failed to delete", "err");
    }
  };

  const handleTestDispatch = async () => {
    setDispatching(true);
    try {
      const res = await fetch(`${API}/siem/test-dispatch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ format: "CEF" }),
      });
      if (res.ok) {
        const data = await res.json();
        setTestResult(data);
        showToast("Test security event dispatched to all enabled collectors!");
      }
    } catch {
      showToast("Test dispatch failed", "err");
    } finally {
      setDispatching(false);
    }
  };

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
          <div className="p-2.5 rounded-xl bg-gradient-to-tr from-blue-500/20 to-indigo-500/20 border border-blue-500/30">
            <Share2 className="w-6 h-6 text-blue-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
              SIEM & Central Log Streaming
              <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">Pillar 5</span>
            </h1>
            <p className="text-sm text-muted-foreground">Stream real-time WAF telemetry to Splunk, Elastic, QRadar, and RFC 5424 Syslog</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button onClick={fetchDestinations} className="p-2 rounded-xl border border-border bg-secondary/50 text-muted-foreground hover:text-foreground">
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={handleTestDispatch}
            disabled={dispatching}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold border border-indigo-500/30 bg-indigo-500/10 text-indigo-400 hover:bg-indigo-500/20 transition"
          >
            <Send className={`w-4 h-4 ${dispatching ? "animate-pulse" : ""}`} /> Dispatch Test Incident
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold bg-blue-500 text-white hover:bg-blue-400 transition"
          >
            <Plus className="w-4 h-4" /> Add Destination
          </button>
        </div>
      </div>

      {/* Format Preview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="glass p-5 rounded-2xl border border-border space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
              <Terminal className="w-4 h-4" /> Common Event Format (CEF)
            </span>
            <span className="text-[11px] px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">Splunk / ArcSight</span>
          </div>
          <div className="p-3 rounded-xl bg-black/60 border border-border font-mono text-[11px] text-emerald-400 break-all select-all">
            {testResult?.sample_cef || "CEF:0|WAF-Pro|NextGen-WAF|1.0|942100|WAF Security Incident|10|src=198.51.100.25 request=/api/v1/auth/login requestMethod=POST act=BLOCKED externalId=TEST-REQ-99999"}
          </div>
        </div>

        <div className="glass p-5 rounded-2xl border border-border space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-amber-400 flex items-center gap-1.5">
              <Radio className="w-4 h-4" /> Syslog (RFC 5424)
            </span>
            <span className="text-[11px] px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">Central SOC Rsyslog</span>
          </div>
          <div className="p-3 rounded-xl bg-black/60 border border-border font-mono text-[11px] text-amber-300 break-all select-all">
            {testResult?.sample_syslog || `<134>1 2026-09-19T03:00:00Z waf-pro envoy - - - [waf@32473 ruleId="942100" clientIp="198.51.100.25" path="/api/v1/auth/login" action="BLOCKED" reqId="TEST-REQ-99999"] Security Violation Intercepted`}
          </div>
        </div>
      </div>

      {/* Destinations Table */}
      <div className="glass rounded-2xl border border-border overflow-hidden">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <h2 className="text-sm font-bold text-foreground flex items-center gap-2">
            <Server className="w-4 h-4 text-blue-400" /> Configured Streaming Connectors ({destinations.length})
          </h2>
          <span className="text-xs text-muted-foreground">Events dispatched asynchronously via non-blocking goroutines</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-secondary/40 text-muted-foreground text-xs uppercase tracking-wider border-b border-border">
              <tr>
                <th className="px-6 py-4">Connector Name</th>
                <th className="px-6 py-4">Payload Format</th>
                <th className="px-6 py-4">Target Ingestion URL / Host</th>
                <th className="px-6 py-4">Severity Filter</th>
                <th className="px-6 py-4">Streaming Status</th>
                <th className="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50">
              {destinations.map((d) => (
                <tr key={d.id} className="hover:bg-secondary/20 transition">
                  <td className="px-6 py-4 font-semibold text-foreground">{d.name}</td>
                  <td className="px-6 py-4">
                    <span className="px-2.5 py-1 rounded-lg text-xs font-bold bg-secondary border border-border text-cyan-400">
                      {d.format}
                    </span>
                  </td>
                  <td className="px-6 py-4 font-mono text-xs text-muted-foreground">{d.endpoint_url}</td>
                  <td className="px-6 py-4">
                    <span className="text-xs font-semibold px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                      ≥ {d.min_severity}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <button
                      onClick={() => handleToggle(d.id)}
                      className="flex items-center gap-1 text-xs font-medium"
                    >
                      {d.is_enabled ? (
                        <span className="flex items-center gap-1.5 text-emerald-400">
                          <ToggleRight className="w-5 h-5 text-emerald-400" /> Active
                        </span>
                      ) : (
                        <span className="flex items-center gap-1.5 text-muted-foreground">
                          <ToggleLeft className="w-5 h-5 text-muted-foreground" /> Disabled
                        </span>
                      )}
                    </button>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <button
                      onClick={() => handleDelete(d.id)}
                      className="p-1.5 rounded-lg text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
              {destinations.length === 0 && !loading && (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-muted-foreground">No SIEM collectors registered.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Destination Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass rounded-2xl border border-border w-full max-w-md p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold text-foreground">Add SIEM Streaming Connector</h2>
              <button onClick={() => setShowAddModal(false)} className="text-muted-foreground hover:text-foreground">✕</button>
            </div>
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-muted-foreground uppercase">Connector Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Telkomsel Enterprise Splunk HEC"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 text-sm focus:outline-none focus:border-blue-400"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-semibold text-muted-foreground uppercase">Format Standard</label>
                  <select
                    value={form.format}
                    onChange={(e) => setForm({ ...form, format: e.target.value })}
                    className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 text-sm focus:outline-none focus:border-blue-400"
                  >
                    <option value="CEF">CEF (ArcSight / Splunk)</option>
                    <option value="SYSLOG_RFC5424">Syslog (RFC 5424)</option>
                    <option value="JSON_WEBHOOK">JSON Webhook</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs font-semibold text-muted-foreground uppercase">Minimum Severity</label>
                  <select
                    value={form.min_severity}
                    onChange={(e) => setForm({ ...form, min_severity: e.target.value })}
                    className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 text-sm focus:outline-none focus:border-blue-400"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="text-xs font-semibold text-muted-foreground uppercase">Target Endpoint URL</label>
                <input
                  type="text"
                  required
                  placeholder="http://splunk.internal:8088/services/collector/raw"
                  value={form.endpoint_url}
                  onChange={(e) => setForm({ ...form, endpoint_url: e.target.value })}
                  className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 font-mono text-xs focus:outline-none focus:border-blue-400"
                />
              </div>
              <div>
                <label className="text-xs font-semibold text-muted-foreground uppercase">Authorization Header (Optional)</label>
                <input
                  type="text"
                  placeholder="Splunk <token> or Bearer <key>"
                  value={form.auth_header}
                  onChange={(e) => setForm({ ...form, auth_header: e.target.value })}
                  className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 font-mono text-xs focus:outline-none focus:border-blue-400"
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
                  className="px-5 py-2 rounded-xl text-sm font-semibold bg-blue-500 text-white hover:bg-blue-400"
                >
                  Save Connector
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

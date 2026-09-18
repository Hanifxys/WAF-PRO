"use client";

import React, { useState, useEffect } from "react";
import { format } from "date-fns";
import { Lock, Plus, Trash2, ShieldAlert, CheckCircle2, ShieldCheck, Power, AlertTriangle } from "lucide-react";

interface DLPRule {
  id: number;
  rule_id: number;
  name: string;
  data_type: string;
  pattern_regex: string;
  action: string;
  is_enabled: boolean;
  created_at: string;
}

export default function DLPPage() {
  const [dlpRules, setDlpRules] = useState<DLPRule[]>([]);
  const [loading, setLoading] = useState(true);

  // Form State
  const [ruleID, setRuleID] = useState("950001");
  const [name, setName] = useState("");
  const [dataType, setDataType] = useState("CREDIT_CARD");
  const [patternRegex, setPatternRegex] = useState(
    "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b"
  );
  const [action, setAction] = useState("BLOCK");
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8082";

  const fetchDLP = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/dlp-rules`);
      if (res.ok) {
        const data = await res.json();
        setDlpRules(data || []);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDLP();
  }, []);

  const handleTemplateChange = (type: string) => {
    setDataType(type);
    if (type === "CREDIT_CARD") {
      setName("PCI-DSS Credit Card Exfiltration Blocker");
      setPatternRegex("\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b");
    } else if (type === "NIK_ID") {
      setName("Indonesian NIK / KTP Leak Prevention");
      setPatternRegex("\\b[1-9][0-9]{15}\\b");
    } else if (type === "DB_STACKTRACE") {
      setName("Database Stack Trace & Internal Error Shield");
      setPatternRegex("(?i)(pg_query\\(\\)|SQLSTATE\\[|ORA-[0-9]{5}|mysql_connect\\(\\))");
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API}/api/v1/dlp-rules`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rule_id: parseInt(ruleID, 10),
          name: name.trim(),
          data_type: dataType,
          pattern_regex: patternRegex.trim(),
          action: action,
        }),
      });
      if (res.ok) {
        setMessage({ type: "success", text: `DLP Inspection Rule #${ruleID} deployed successfully.` });
        setName("");
        setRuleID(String(parseInt(ruleID, 10) + 1));
        fetchDLP();
      } else {
        setMessage({ type: "error", text: "Failed to create DLP rule." });
      }
    } catch {
      setMessage({ type: "error", text: "Connection error." });
    }
  };

  const handleToggle = async (id: number) => {
    try {
      const res = await fetch(`${API}/api/v1/dlp-rules/${id}/toggle`, { method: "PUT" });
      if (res.ok) fetchDLP();
    } catch (err) {
      console.error(err);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Delete this DLP rule?")) return;
    try {
      const res = await fetch(`${API}/api/v1/dlp-rules/${id}`, { method: "DELETE" });
      if (res.ok) fetchDLP();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-cyan-400 flex items-center gap-2.5">
            <Lock className="w-7 h-7 text-cyan-400" />
            Response Data Loss Prevention (DLP)
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Prevent sensitive enterprise data leakage (Credit Cards, NIK/PII, Database Errors) in outbound HTTP responses (Phase 4).
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <ShieldCheck className="w-3.5 h-3.5" />
            PCI-DSS Enforcement Ready
          </span>
        </div>
      </div>

      {message && (
        <div
          className={`p-4 rounded-lg flex items-center gap-3 border text-sm ${
            message.type === "success"
              ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
              : "bg-red-500/10 border-red-500/20 text-red-400"
          }`}
        >
          {message.type === "success" ? <CheckCircle2 className="w-4 h-4" /> : <ShieldAlert className="w-4 h-4" />}
          {message.text}
        </div>
      )}

      {/* DLP Rule Form */}
      <div className="glass-panel p-6 rounded-xl border border-border space-y-4">
        <h2 className="text-base font-semibold flex items-center gap-2">
          <Plus className="w-4 h-4 text-cyan-400" />
          Deploy Outbound DLP Inspection Rule
        </h2>

        {/* Templates quick selector */}
        <div className="flex items-center gap-2 text-xs">
          <span className="text-muted-foreground font-semibold">Preset Templates:</span>
          <button
            type="button"
            onClick={() => handleTemplateChange("CREDIT_CARD")}
            className={`px-2.5 py-1 rounded border transition-colors ${
              dataType === "CREDIT_CARD" ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40" : "border-border text-muted-foreground"
            }`}
          >
            Credit Cards (PCI)
          </button>
          <button
            type="button"
            onClick={() => handleTemplateChange("NIK_ID")}
            className={`px-2.5 py-1 rounded border transition-colors ${
              dataType === "NIK_ID" ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40" : "border-border text-muted-foreground"
            }`}
          >
            Indonesian NIK/PII
          </button>
          <button
            type="button"
            onClick={() => handleTemplateChange("DB_STACKTRACE")}
            className={`px-2.5 py-1 rounded border transition-colors ${
              dataType === "DB_STACKTRACE" ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40" : "border-border text-muted-foreground"
            }`}
          >
            Database Stack Traces
          </button>
        </div>

        <form onSubmit={handleCreate} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div>
            <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
              Rule ID (e.g. 950001+)
            </label>
            <input
              type="number"
              value={ruleID}
              onChange={(e) => setRuleID(e.target.value)}
              className="w-full bg-secondary/50 border border-border rounded-lg px-3.5 py-2 text-sm text-foreground focus:outline-none focus:border-cyan-500 font-mono"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
              Rule Name
            </label>
            <input
              type="text"
              placeholder="e.g. PCI-DSS Shield"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-secondary/50 border border-border rounded-lg px-3.5 py-2 text-sm text-foreground focus:outline-none focus:border-cyan-500"
              required
            />
          </div>

          <div className="lg:col-span-2">
            <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
              Inspection Pattern (Regex)
            </label>
            <input
              type="text"
              value={patternRegex}
              onChange={(e) => setPatternRegex(e.target.value)}
              className="w-full bg-slate-950 border border-border rounded-lg px-3.5 py-2 text-xs font-mono text-cyan-400 focus:outline-none focus:border-cyan-500"
              required
            />
          </div>

          <div className="lg:col-span-4 flex justify-end">
            <button
              type="submit"
              className="px-5 py-2 bg-cyan-500 hover:bg-cyan-600 text-slate-950 font-semibold rounded-lg text-sm transition-colors flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              Deploy DLP Rule
            </button>
          </div>
        </form>
      </div>

      {/* Active DLP Rules Table */}
      <div className="glass-panel rounded-xl border border-border overflow-hidden">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <h2 className="text-base font-semibold flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            Active Response DLP Filters ({dlpRules.length})
          </h2>
          <span className="text-xs text-muted-foreground">Intercepts response body on Phase 4</span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-sm text-muted-foreground">Loading DLP rules...</div>
        ) : dlpRules.length === 0 ? (
          <div className="p-8 text-center text-sm text-muted-foreground">
            No DLP rules configured. Deploy a template above to protect sensitive outbound data.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-secondary/40 border-b border-border text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="px-6 py-3">Rule ID</th>
                  <th className="px-6 py-3">Name</th>
                  <th className="px-6 py-3">Data Type</th>
                  <th className="px-6 py-3">Pattern</th>
                  <th className="px-6 py-3">Status</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {dlpRules.map((r) => (
                  <tr key={r.id} className="hover:bg-secondary/20 transition-colors">
                    <td className="px-6 py-4 font-mono font-bold text-cyan-400">#{r.rule_id}</td>
                    <td className="px-6 py-4 font-semibold">{r.name}</td>
                    <td className="px-6 py-4">
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                        {r.data_type}
                      </span>
                    </td>
                    <td className="px-6 py-4 font-mono text-xs text-muted-foreground truncate max-w-xs" title={r.pattern_regex}>
                      {r.pattern_regex}
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                          r.is_enabled ? "bg-emerald-500/10 text-emerald-400" : "bg-muted text-muted-foreground"
                        }`}
                      >
                        {r.is_enabled ? "ACTIVE" : "DISABLED"}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => handleToggle(r.id)}
                          className={`p-1.5 rounded transition-colors ${
                            r.is_enabled ? "hover:bg-amber-500/10 text-amber-400" : "hover:bg-emerald-500/10 text-emerald-400"
                          }`}
                          title={r.is_enabled ? "Disable" : "Enable"}
                        >
                          <Power className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDelete(r.id)}
                          className="p-1.5 hover:bg-red-500/10 text-red-400 rounded transition-colors"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

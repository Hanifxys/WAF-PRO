"use client";
import React, { useState, useEffect } from "react";
import { ShieldAlert, Save, RefreshCw, CheckCircle2, AlertCircle } from "lucide-react";
import { API } from "@/lib/api";
export default function RulesPage() {
  const [rules, setRules] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState<{ type: "success" | "error" | null; message: string }>({ type: null, message: "" });

  const fetchRules = async () => {
    setLoading(true);
    setStatus({ type: null, message: "" });
    try {
      const res = await fetch(`${API}/api/v1/configs`);
      if (res.ok) {
        const data = await res.json();
        if (data && data.length > 0) {
          setRules(data[0].custom_rules);
        }
      } else {
        setStatus({ type: "error", message: "Failed to fetch rules" });
      }
    } catch (err) {
      console.error("Failed to fetch rules:", err);
      setStatus({ type: "error", message: "Network error fetching rules" });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleSave = async () => {
    setSaving(true);
    setStatus({ type: null, message: "" });
    try {
      // The API endpoint handles PUT to /configs/{id}
      // Since it's MVP, we just use /configs/1
      const res = await fetch(`${API}/api/v1/configs/1`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ custom_rules: rules }),
      });

      if (res.ok) {
        setStatus({ type: "success", message: "Rules updated successfully! WAF is now using the new configuration." });
      } else {
        setStatus({ type: "error", message: "Failed to update rules." });
      }
    } catch (err) {
      console.error("Failed to update rules:", err);
      setStatus({ type: "error", message: "Network error updating rules." });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-700 h-full flex flex-col">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div className="flex flex-col gap-1">
          <h1 className="text-3xl font-bold tracking-tight">WAF Rules</h1>
          <p className="text-muted-foreground">
            Manage SecLang rules directly. Changes are pushed to Envoy instantly via xDS.
          </p>
        </div>
        
        <div className="flex items-center gap-2">
          <button 
            onClick={fetchRules}
            disabled={loading || saving}
            className="flex items-center gap-2 bg-secondary/80 hover:bg-secondary text-secondary-foreground border border-border px-4 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button 
            onClick={handleSave}
            disabled={loading || saving}
            className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
          >
            {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
            Deploy Rules
          </button>
        </div>
      </div>

      {status.type && (
        <div className={`p-4 rounded-lg flex items-start gap-3 border ${
          status.type === 'success' 
            ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' 
            : 'bg-red-500/10 border-red-500/20 text-red-400'
        }`}>
          {status.type === 'success' ? (
            <CheckCircle2 className="w-5 h-5 shrink-0" />
          ) : (
            <AlertCircle className="w-5 h-5 shrink-0" />
          )}
          <p className="text-sm">{status.message}</p>
        </div>
      )}

      <div className="glass-panel rounded-xl overflow-hidden border border-border flex-1 flex flex-col relative min-h-[500px]">
        {loading && (
          <div className="absolute inset-0 bg-background/50 backdrop-blur-sm z-10 flex items-center justify-center">
            <div className="flex flex-col items-center gap-2 text-emerald-500">
              <RefreshCw className="w-8 h-8 animate-spin" />
              <span className="text-sm font-medium">Loading rules...</span>
            </div>
          </div>
        )}
        
        <div className="bg-secondary/50 border-b border-border p-3 flex items-center gap-2 text-sm text-muted-foreground">
          <ShieldAlert className="w-4 h-4" />
          <span>SecLang Directives</span>
        </div>
        
        <textarea
          value={rules}
          onChange={(e) => setRules(e.target.value)}
          className="w-full flex-1 bg-transparent border-0 p-4 font-mono text-sm focus:outline-none resize-none text-foreground"
          placeholder="# Add your SecLang rules here..."
          spellCheck={false}
        />
      </div>
    </div>
  );
}

"use client";

import React, { useState, useEffect } from "react";
import { 
  Bot, 
  RefreshCw, 
  ShieldAlert, 
  ShieldCheck, 
  Ban, 
  CheckCircle2, 
  AlertCircle, 
  Zap, 
  PlusCircle, 
  Trash2, 
  Layers, 
  Eye, 
  Cpu
} from "lucide-react";
import { API } from "@/lib/api";

interface BotPolicy {
  id: number;
  name: string;
  category: string;
  ua_regex: string;
  action: "BLOCK" | "CHALLENGE" | "MONITOR" | "ALLOW";
  description: string;
  is_enabled: boolean;
  created_at: string;
}

export default function BotManagementPage() {
  const [policies, setPolicies] = useState<BotPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [notification, setNotification] = useState<{ type: "success" | "error" | null; message: string }>({ type: null, message: "" });

  // Modal State
  const [showModal, setShowModal] = useState(false);
  const [formName, setFormName] = useState("");
  const [formCategory, setFormCategory] = useState("SCRAPER");
  const [formRegex, setFormRegex] = useState("");
  const [formAction, setFormAction] = useState<BotPolicy["action"]>("BLOCK");
  const [formDesc, setFormDesc] = useState("");


  const fetchPolicies = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/bot-policies`);
      if (res.ok) {
        const data = await res.json();
        setPolicies(data || []);
      }
    } catch (err) {
      console.error("Failed to fetch bot policies:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleUpdateAction = async (id: number, nextAction: BotPolicy["action"]) => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/bot-policies/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: nextAction }),
      });
      if (res.ok) {
        setNotification({
          type: "success",
          message: `Bot action updated to ${nextAction}. Envoy xDS policy compiled!`,
        });
        fetchPolicies();
      }
    } catch (err) {
      setNotification({ type: "error", message: "Failed to update bot action." });
    } finally {
      setActionLoading(false);
    }
  };

  const handleToggleEnabled = async (id: number, current: boolean) => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/bot-policies/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ is_enabled: !current }),
      });
      if (res.ok) {
        setNotification({
          type: "success",
          message: `Bot policy ${!current ? "enabled" : "disabled"}.`,
        });
        fetchPolicies();
      }
    } catch (err) {
      setNotification({ type: "error", message: "Failed to toggle bot policy." });
    } finally {
      setActionLoading(false);
    }
  };

  const handleDeletePolicy = async (id: number, name: string) => {
    if (!confirm(`Delete bot policy "${name}"?`)) return;
    setActionLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/bot-policies/${id}`, { method: "DELETE" });
      if (res.ok) {
        setNotification({ type: "success", message: `Policy "${name}" deleted.` });
        fetchPolicies();
      }
    } catch (err) {
      setNotification({ type: "error", message: "Failed to delete bot policy." });
    } finally {
      setActionLoading(false);
    }
  };

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formName.trim() || !formRegex.trim()) return;

    setActionLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/bot-policies`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: formName.trim(),
          category: formCategory,
          ua_regex: formRegex.trim(),
          action: formAction,
          description: formDesc.trim(),
        }),
      });
      if (res.ok) {
        setNotification({
          type: "success",
          message: `Bot signature "${formName}" created and compiled!`,
        });
        setShowModal(false);
        setFormName("");
        setFormRegex("");
        setFormDesc("");
        fetchPolicies();
      }
    } catch (err) {
      setNotification({ type: "error", message: "Failed to create bot signature." });
    } finally {
      setActionLoading(false);
    }
  };

  const handleSyncBotShield = async () => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/bot-policies/sync`, { method: "POST" });
      if (res.ok) {
        setNotification({
          type: "success",
          message: "Bot Shield SecLang rules compiled and synced to Envoy xDS edge!",
        });
      }
    } catch (err) {
      setNotification({ type: "error", message: "Failed to sync Bot Shield." });
    } finally {
      setActionLoading(false);
    }
  };

  const blockedCount = policies.filter((p) => p.action === "BLOCK" && p.is_enabled).length;
  const allowedCount = policies.filter((p) => p.action === "ALLOW" && p.is_enabled).length;
  const challengedCount = policies.filter((p) => p.action === "CHALLENGE" && p.is_enabled).length;

  const getActionBadge = (action: BotPolicy["action"]) => {
    switch (action) {
      case "BLOCK":
        return "bg-rose-500/10 text-rose-400 border-rose-500/20";
      case "CHALLENGE":
        return "bg-amber-500/10 text-amber-400 border-amber-500/20";
      case "ALLOW":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
      case "MONITOR":
      default:
        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/20";
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Bot className="w-8 h-8 text-cyan-400" />
            <h1 className="text-3xl font-bold tracking-tight">Bot Shield & Management</h1>
          </div>
          <p className="text-muted-foreground mt-1">
            Layered bot intelligence, automated crawler defense, and zero-downtime xDS bot protection.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => window.open(`${API}/api/v1/bot-challenge/interstitial`, "_blank")}
            className="flex items-center gap-2 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/30 px-3 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            <Cpu className="w-4 h-4" />
            Preview JS Challenge
          </button>
          <button
            onClick={handleSyncBotShield}
            disabled={actionLoading}
            className="flex items-center gap-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white px-4 py-2 rounded-lg text-sm font-medium shadow-lg transition-all"
          >
            <Zap className="w-4 h-4" />
            Sync Bot Shield (xDS)
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-2 bg-secondary/80 hover:bg-secondary text-secondary-foreground border border-border px-3 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            <PlusCircle className="w-4 h-4 text-emerald-400" />
            Add Bot Signature
          </button>
          <button
            onClick={fetchPolicies}
            disabled={loading || actionLoading}
            className="flex items-center gap-2 bg-secondary/80 hover:bg-secondary text-secondary-foreground border border-border px-3 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
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
            <AlertCircle className="w-5 h-5 shrink-0" />
          )}
          <p className="text-sm">{notification.message}</p>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="glass-panel p-4 rounded-xl border border-border flex items-center gap-4">
          <div className="p-3 bg-cyan-500/10 rounded-lg text-cyan-400">
            <Layers className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-muted-foreground uppercase font-semibold">Total Signatures</div>
            <div className="text-2xl font-bold">{policies.length}</div>
          </div>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-border flex items-center gap-4">
          <div className="p-3 bg-rose-500/10 rounded-lg text-rose-400">
            <Ban className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-muted-foreground uppercase font-semibold">Bad Bots Blocked</div>
            <div className="text-2xl font-bold text-rose-400">{blockedCount}</div>
          </div>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-border flex items-center gap-4">
          <div className="p-3 bg-emerald-500/10 rounded-lg text-emerald-400">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-muted-foreground uppercase font-semibold">Good Bots Allowed</div>
            <div className="text-2xl font-bold text-emerald-400">{allowedCount}</div>
          </div>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-border flex items-center gap-4">
          <div className="p-3 bg-amber-500/10 rounded-lg text-amber-400">
            <Cpu className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-muted-foreground uppercase font-semibold">Challenge Actions</div>
            <div className="text-2xl font-bold text-amber-400">{challengedCount}</div>
          </div>
        </div>
      </div>

      {/* Policies Table */}
      <div className="glass-panel rounded-xl overflow-hidden border border-border">
        <div className="p-4 bg-secondary/30 border-b border-border flex items-center justify-between">
          <span className="font-semibold text-sm">Active Bot Defense Signatures</span>
          <span className="text-xs text-muted-foreground">Evaluating at Phase 1 before CRS inspection</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-muted-foreground uppercase bg-secondary/50 border-b border-border">
              <tr>
                <th className="px-6 py-4 font-semibold tracking-wider">Bot Profile</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Category</th>
                <th className="px-6 py-4 font-semibold tracking-wider">User-Agent Regex Pattern</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Shield Action</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Status</th>
                <th className="px-6 py-4 font-semibold tracking-wider text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50">
              {loading && policies.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-muted-foreground">
                    Loading bot signatures...
                  </td>
                </tr>
              ) : (
                policies.map((p) => (
                  <tr key={p.id} className="hover:bg-secondary/40 transition-colors">
                    <td className="px-6 py-4">
                      <div className="font-semibold text-foreground">{p.name}</div>
                      <div className="text-xs text-muted-foreground">{p.description}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded text-xs font-mono bg-secondary border border-border">
                        {p.category}
                      </span>
                    </td>
                    <td className="px-6 py-4 font-mono text-xs text-muted-foreground max-w-xs truncate">
                      {p.ua_regex}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <select
                        value={p.action}
                        onChange={(e) => handleUpdateAction(p.id, e.target.value as BotPolicy["action"])}
                        className={`text-xs font-semibold rounded-md px-2 py-1 border bg-secondary/80 focus:outline-none ${getActionBadge(p.action)}`}
                      >
                        <option value="BLOCK">BLOCK</option>
                        <option value="CHALLENGE">CHALLENGE</option>
                        <option value="MONITOR">MONITOR</option>
                        <option value="ALLOW">ALLOW</option>
                      </select>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <button
                        onClick={() => handleToggleEnabled(p.id, p.is_enabled)}
                        className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${
                          p.is_enabled
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                            : "bg-secondary text-muted-foreground border-border"
                        }`}
                      >
                        {p.is_enabled ? "Enabled" : "Disabled"}
                      </button>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      <button
                        onClick={() => handleDeletePolicy(p.id, p.name)}
                        className="p-1.5 rounded-lg hover:bg-rose-500/20 text-muted-foreground hover:text-rose-400"
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

      {/* Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-card border border-border p-6 rounded-xl max-w-md w-full space-y-4 shadow-2xl">
            <h3 className="text-lg font-bold">Add Custom Bot Signature</h3>
            <form onSubmit={handleCreatePolicy} className="space-y-3">
              <div>
                <label className="block text-xs text-muted-foreground mb-1">Bot Profile Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Scrapy Crawler Bot"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  className="w-full bg-secondary border border-border rounded-lg p-2 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-muted-foreground mb-1">Category</label>
                <select
                  value={formCategory}
                  onChange={(e) => setFormCategory(e.target.value)}
                  className="w-full bg-secondary border border-border rounded-lg p-2 text-sm"
                >
                  <option value="SCRAPER">SCRAPER</option>
                  <option value="SECURITY_SCANNER">SECURITY_SCANNER</option>
                  <option value="AI_BOT">AI_BOT</option>
                  <option value="HEADLESS">HEADLESS</option>
                  <option value="SEARCH_ENGINE">SEARCH_ENGINE</option>
                  <option value="CUSTOM">CUSTOM</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-muted-foreground mb-1">User-Agent Regex Pattern</label>
                <input
                  type="text"
                  required
                  placeholder="(?i)(scrapy|custom-bot)"
                  value={formRegex}
                  onChange={(e) => setFormRegex(e.target.value)}
                  className="w-full bg-secondary border border-border rounded-lg p-2 text-sm font-mono"
                />
              </div>
              <div>
                <label className="block text-xs text-muted-foreground mb-1">Mitigation Action</label>
                <select
                  value={formAction}
                  onChange={(e) => setFormAction(e.target.value as BotPolicy["action"])}
                  className="w-full bg-secondary border border-border rounded-lg p-2 text-sm"
                >
                  <option value="BLOCK">BLOCK</option>
                  <option value="CHALLENGE">CHALLENGE</option>
                  <option value="MONITOR">MONITOR</option>
                  <option value="ALLOW">ALLOW</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-muted-foreground mb-1">Description</label>
                <input
                  type="text"
                  placeholder="Reason / context for this bot policy"
                  value={formDesc}
                  onChange={(e) => setFormDesc(e.target.value)}
                  className="w-full bg-secondary border border-border rounded-lg p-2 text-sm"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 rounded-lg border border-border text-sm hover:bg-secondary"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-semibold"
                >
                  Save Signature
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}


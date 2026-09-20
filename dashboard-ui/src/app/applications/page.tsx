"use client";

import React, { useState, useEffect } from "react";
import { format } from "date-fns";
import { 
  Globe, 
  PlusCircle, 
  Trash2, 
  RefreshCw, 
  Shield, 
  AlertCircle, 
  CheckCircle2, 
  Server, 
  Sliders, 
  BookOpen, 
  ArrowRight, 
  Check, 
  X, 
  Zap,
  Activity
} from "lucide-react";
import { API } from "@/lib/api";

interface Application {
  id: number;
  name: string;
  domain: string;
  backend_url: string;
  waf_mode: string;
  paranoia_level: number;
  status: "DRAFT" | "ONBOARDING" | "LEARNING" | "REVIEW" | "PROTECTED" | "SUSPENDED" | "DECOMMISSIONED";
  learning_traffic_count: number;
  created_at: string;
}

export default function ApplicationsPage() {
  const [apps, setApps] = useState<Application[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [notification, setNotification] = useState<{ type: "success" | "error" | null; message: string }>({ type: null, message: "" });

  // Onboarding Wizard Modal State
  const [showWizard, setShowWizard] = useState(false);
  const [wizardStep, setWizardStep] = useState(1);
  const [wizName, setWizName] = useState("");
  const [wizDomain, setWizDomain] = useState("");
  const [wizBackend, setWizBackend] = useState("");
  const [wizMode, setWizMode] = useState("LEARNING");
  const [wizParanoia, setWizParanoia] = useState(1);
  const [wizStatus, setWizStatus] = useState<Application["status"]>("LEARNING");


  const fetchApps = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/applications`);
      if (res.ok) {
        const data = await res.json();
        setApps(data || []);
      }
    } catch (err) {
      console.error("Failed to fetch apps:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchApps();
  }, []);

  const handleLaunchApp = async () => {
    if (!wizName.trim() || !wizDomain.trim() || !wizBackend.trim()) return;

    setActionLoading(true);
    setNotification({ type: null, message: "" });
    try {
      const res = await fetch(`${API}/api/v1/applications`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: wizName.trim(),
          domain: wizDomain.trim(),
          backend_url: wizBackend.trim(),
          waf_mode: wizMode,
          paranoia_level: wizParanoia,
          status: wizStatus,
        }),
      });

      if (res.ok) {
        setNotification({
          type: "success",
          message: `Application "${wizName}" successfully launched in ${wizStatus} mode!`,
        });
        setShowWizard(false);
        setWizardStep(1);
        setWizName("");
        setWizDomain("");
        setWizBackend("");
        setWizMode("LEARNING");
        setWizParanoia(1);
        setWizStatus("LEARNING");
        fetchApps();
      } else {
        setNotification({ type: "error", message: "Failed to onboard application." });
      }
    } catch (err) {
      setNotification({ type: "error", message: "Network error occurred." });
    } finally {
      setActionLoading(false);
    }
  };

  const handleUpdateStatus = async (app: Application, nextStatus: Application["status"]) => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/applications/${app.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...app,
          status: nextStatus,
          waf_mode: nextStatus === "PROTECTED" ? "BLOCK" : nextStatus === "LEARNING" ? "LEARNING" : app.waf_mode,
        }),
      });
      if (res.ok) {
        setNotification({ type: "success", message: `Application ${app.name} transitioned to ${nextStatus}!` });
        fetchApps();
      }
    } catch (err) {
      setNotification({ type: "error", message: "Failed to update lifecycle status." });
    } finally {
      setActionLoading(false);
    }
  };

  const handleToggleMode = async (app: Application) => {
    const nextMode = app.waf_mode === "BLOCK" ? "MONITOR" : "BLOCK";
    setActionLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/applications/${app.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...app,
          waf_mode: nextMode,
        }),
      });
      if (res.ok) {
        setNotification({ type: "success", message: `WAF mode for ${app.domain} set to ${nextMode}!` });
        fetchApps();
      }
    } catch (err) {
      setNotification({ type: "error", message: "Failed to update mode." });
    } finally {
      setActionLoading(false);
    }
  };

  const handleDeleteApp = async (id: number, name: string) => {
    if (!confirm(`Are you sure you want to delete application "${name}"?`)) return;
    setActionLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/applications/${id}`, { method: "DELETE" });
      if (res.ok) {
        setNotification({ type: "success", message: `Application "${name}" removed.` });
        fetchApps();
      }
    } catch (err) {
      setNotification({ type: "error", message: "Failed to delete application." });
    } finally {
      setActionLoading(false);
    }
  };

  const getStatusBadge = (status: Application["status"]) => {
    switch (status) {
      case "PROTECTED":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
      case "LEARNING":
        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/20 animate-pulse";
      case "REVIEW":
        return "bg-amber-500/10 text-amber-400 border-amber-500/20";
      case "ONBOARDING":
        return "bg-purple-500/10 text-purple-400 border-purple-500/20";
      case "SUSPENDED":
        return "bg-red-500/10 text-red-400 border-red-500/20";
      default:
        return "bg-secondary text-muted-foreground border-border";
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Protected Applications</h1>
          <p className="text-muted-foreground">
            Enterprise application lifecycle management: Onboarding Wizard, Traffic Learning, and Active Protection.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowWizard(true)}
            className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg text-sm font-medium shadow-lg shadow-emerald-950/40 transition-all"
          >
            <PlusCircle className="w-4 h-4" />
            Launch Onboarding Wizard
          </button>
          <button
            onClick={fetchApps}
            disabled={loading || actionLoading}
            className="flex items-center gap-2 bg-secondary/80 hover:bg-secondary text-secondary-foreground border border-border px-4 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {notification.type && (
        <div className={`p-4 rounded-lg flex items-start gap-3 border ${
          notification.type === "success" 
            ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400" 
            : "bg-red-500/10 border-red-500/20 text-red-400"
        }`}>
          {notification.type === "success" ? (
            <CheckCircle2 className="w-5 h-5 shrink-0" />
          ) : (
            <AlertCircle className="w-5 h-5 shrink-0" />
          )}
          <p className="text-sm">{notification.message}</p>
        </div>
      )}

      {/* Applications List */}
      <div className="glass-panel rounded-xl overflow-hidden border border-border">
        <div className="p-4 bg-secondary/30 border-b border-border flex items-center justify-between">
          <span className="font-semibold text-sm">Active Applications Portfolio ({apps.length})</span>
          <span className="text-xs text-muted-foreground flex items-center gap-1">
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
            Dynamic Envoy xDS Virtual Hosts
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-muted-foreground uppercase bg-secondary/50 border-b border-border">
              <tr>
                <th className="px-6 py-4 font-semibold tracking-wider">Application</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Domain / Host</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Origin Backend</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Lifecycle Status</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Learning Volume</th>
                <th className="px-6 py-4 font-semibold tracking-wider">WAF Mode</th>
                <th className="px-6 py-4 font-semibold tracking-wider text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50">
              {loading && apps.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center text-muted-foreground">
                    Loading applications...
                  </td>
                </tr>
              ) : apps.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center text-muted-foreground">
                    No applications registered yet. Click &quot;Launch Onboarding Wizard&quot; to begin.
                  </td>
                </tr>
              ) : (
                apps.map((app) => (
                  <tr key={app.id} className="hover:bg-secondary/40 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap font-medium">
                      {app.name}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap font-mono text-xs text-emerald-400">
                      {app.domain}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap font-mono text-xs text-muted-foreground">
                      <div className="flex items-center gap-1.5">
                        <Server className="w-3.5 h-3.5 text-muted-foreground" />
                        <span>{app.backend_url}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2.5 py-1 rounded-full text-xs font-semibold border ${getStatusBadge(app.status)}`}>
                        {app.status || "PROTECTED"}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap font-mono text-xs text-muted-foreground">
                      <div className="flex items-center gap-1">
                        <Activity className="w-3.5 h-3.5 text-cyan-400" />
                        <span>{(app.learning_traffic_count || 0).toLocaleString()} reqs</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <button
                        onClick={() => handleToggleMode(app)}
                        disabled={actionLoading}
                        title="Click to toggle between BLOCK and MONITOR"
                        className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold border transition-all ${
                          app.waf_mode === "BLOCK"
                            ? "bg-red-500/10 text-red-400 border-red-500/20 hover:bg-red-500/20"
                            : "bg-amber-500/10 text-amber-400 border-amber-500/20 hover:bg-amber-500/20"
                        }`}
                      >
                        {app.waf_mode}
                      </button>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right space-x-2">
                      {app.status === "LEARNING" && (
                        <button
                          onClick={() => handleUpdateStatus(app, "PROTECTED")}
                          className="px-2.5 py-1 rounded-md text-xs font-medium bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/20"
                        >
                          Enforce Protect
                        </button>
                      )}
                      {app.status === "PROTECTED" && (
                        <button
                          onClick={() => handleUpdateStatus(app, "LEARNING")}
                          className="px-2.5 py-1 rounded-md text-xs font-medium bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 border border-cyan-500/20"
                        >
                          Re-Learn
                        </button>
                      )}
                      <button
                        onClick={() => handleDeleteApp(app.id, app.name)}
                        disabled={actionLoading}
                        title="Delete application"
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-md bg-secondary/60 hover:bg-red-500/20 hover:text-red-400 text-muted-foreground text-xs font-medium border border-border transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        Delete
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Roadmap Phase 3: Application Onboarding Wizard Modal */}
      {showWizard && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="bg-card border border-border p-6 rounded-2xl max-w-xl w-full space-y-6 shadow-2xl animate-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between border-b border-border pb-4">
              <div>
                <span className="text-xs uppercase font-bold tracking-wider text-emerald-400">
                  Phase 3 Wizard • Step {wizardStep} of 3
                </span>
                <h3 className="text-xl font-bold mt-1">Application Onboarding & Learning</h3>
              </div>
              <button onClick={() => setShowWizard(false)} className="text-muted-foreground hover:text-foreground">
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Stepper indicator */}
            <div className="grid grid-cols-3 gap-2">
              <div className={`h-1.5 rounded-full ${wizardStep >= 1 ? "bg-emerald-400" : "bg-secondary"}`} />
              <div className={`h-1.5 rounded-full ${wizardStep >= 2 ? "bg-emerald-400" : "bg-secondary"}`} />
              <div className={`h-1.5 rounded-full ${wizardStep >= 3 ? "bg-emerald-400" : "bg-secondary"}`} />
            </div>

            {wizardStep === 1 && (
              <div className="space-y-4">
                <h4 className="text-sm font-semibold text-foreground">1. Application Identity & Host Domain</h4>
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Application Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Telkomsel MyEnterprise Portal"
                    value={wizName}
                    onChange={(e) => setWizName(e.target.value)}
                    className="w-full bg-secondary border border-border rounded-lg p-2.5 text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Domain FQDN / Host</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. myenterprise.telkomsel.co.id"
                    value={wizDomain}
                    onChange={(e) => setWizDomain(e.target.value)}
                    className="w-full bg-secondary border border-border rounded-lg p-2.5 text-sm font-mono"
                  />
                  <p className="text-[11px] text-muted-foreground mt-1">
                    Envoy xDS will automatically route requests with matching Host headers to this application cluster.
                  </p>
                </div>
              </div>
            )}

            {wizardStep === 2 && (
              <div className="space-y-4">
                <h4 className="text-sm font-semibold text-foreground">2. Origin Target & Health Check</h4>
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Origin Backend URL</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. http://origin-mock:8081"
                    value={wizBackend}
                    onChange={(e) => setWizBackend(e.target.value)}
                    className="w-full bg-secondary border border-border rounded-lg p-2.5 text-sm font-mono"
                  />
                </div>
                <div className="p-3 bg-secondary/50 rounded-lg border border-border text-xs text-muted-foreground space-y-1">
                  <div className="font-semibold text-foreground">TLS & Upstream Routing</div>
                  <div>• Default upstream timeout: 30s</div>
                  <div>• Active TCP health checking enabled automatically on Envoy cluster.</div>
                </div>
              </div>
            )}

            {wizardStep === 3 && (
              <div className="space-y-4">
                <h4 className="text-sm font-semibold text-foreground">3. Policy Strategy & Initial Lifecycle Mode</h4>
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Initial Lifecycle Mode</label>
                  <div className="grid grid-cols-2 gap-3">
                    <button
                      type="button"
                      onClick={() => { setWizStatus("LEARNING"); setWizMode("LEARNING"); }}
                      className={`p-3 rounded-lg border text-left transition-all ${
                        wizStatus === "LEARNING"
                          ? "bg-cyan-500/10 border-cyan-500/40 text-cyan-400"
                          : "bg-secondary/40 border-border text-muted-foreground"
                      }`}
                    >
                      <div className="font-bold text-xs">LEARNING MODE (Recommended)</div>
                      <div className="text-[11px] mt-1 text-muted-foreground">
                        Passively profiles traffic, builds API Inventory, and discovers schemas without blocking users.
                      </div>
                    </button>
                    <button
                      type="button"
                      onClick={() => { setWizStatus("PROTECTED"); setWizMode("BLOCK"); }}
                      className={`p-3 rounded-lg border text-left transition-all ${
                        wizStatus === "PROTECTED"
                          ? "bg-emerald-500/10 border-emerald-500/40 text-emerald-400"
                          : "bg-secondary/40 border-border text-muted-foreground"
                      }`}
                    >
                      <div className="font-bold text-xs">PROTECTED (Active WAF)</div>
                      <div className="text-[11px] mt-1 text-muted-foreground">
                        Enforces OWASP CRS and blocks malicious attacks immediately at Phase 1.
                      </div>
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Paranoia Level</label>
                  <select
                    value={wizParanoia}
                    onChange={(e) => setWizParanoia(Number(e.target.value))}
                    className="w-full bg-secondary border border-border rounded-lg p-2.5 text-sm"
                  >
                    <option value={1}>PL 1 - Standard baseline protection (Low false positives)</option>
                    <option value={2}>PL 2 - Advanced protection for high-value APIs</option>
                    <option value={3}>PL 3 - High security banking / telecommunication</option>
                    <option value={4}>PL 4 - Paranoia maximum</option>
                  </select>
                </div>
              </div>
            )}

            <div className="flex justify-between items-center pt-4 border-t border-border">
              {wizardStep > 1 ? (
                <button
                  type="button"
                  onClick={() => setWizardStep(wizardStep - 1)}
                  className="px-4 py-2 rounded-lg border border-border text-sm hover:bg-secondary"
                >
                  Back
                </button>
              ) : <div />}

              {wizardStep < 3 ? (
                <button
                  type="button"
                  disabled={wizardStep === 1 ? (!wizName || !wizDomain) : !wizBackend}
                  onClick={() => setWizardStep(wizardStep + 1)}
                  className="px-5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-semibold flex items-center gap-1.5 disabled:opacity-50"
                >
                  Next
                  <ArrowRight className="w-4 h-4" />
                </button>
              ) : (
                <button
                  type="button"
                  disabled={actionLoading}
                  onClick={handleLaunchApp}
                  className="px-5 py-2 rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-sm font-bold shadow-lg flex items-center gap-2"
                >
                  <Zap className="w-4 h-4" />
                  Launch Application
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


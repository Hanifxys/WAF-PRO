"use client";

import React, { useState, useEffect, useCallback } from "react";
import { format } from "date-fns";
import {
  Sliders, PlusCircle, Trash2, RefreshCw, Shield, AlertCircle,
  CheckCircle2, Clock, Tag, ChevronRight, ChevronLeft, Info,
  Target, Globe, ScanLine, Sparkles, Play, Zap, Check, Activity,
  FileCode2, ShieldAlert
} from "lucide-react";
import { API } from "@/lib/api";

interface RuleException {
  id: number;
  target_rule_id: string;
  match_path: string;
  match_method: string;
  match_param?: string;
  match_header?: string;
  scope?: string;
  reason: string;
  ticket_ref?: string;
  expires_at?: string | null;
  created_at: string;
}

interface TuningRecommendation {
  id: string;
  rule_id: string;
  rule_name: string;
  match_path: string;
  match_param?: string;
  occurrences: number;
  false_positive_risk: string;
  suggested_scope: string;
  justification: string;
  sample_clients: string[];
}

interface ReplayMatch {
  rule_id: string;
  phase: number;
  operator: string;
  action: string;
  message: string;
  matched_data: string;
}

interface ReplayResult {
  request_id: string;
  evaluated_rules: number;
  matches: ReplayMatch[];
  final_verdict: string;
  processing_time_us: number;
}

const SCOPE_OPTIONS = [
  { value: "TARGET", label: "Target Precision", icon: <Target className="w-3.5 h-3.5" />, desc: "Suppress rule only on specific param or header (ctl:ruleRemoveTargetById — most precise)" },
  { value: "PATH_ONLY", label: "Path Scoped", icon: <ScanLine className="w-3.5 h-3.5" />, desc: "Suppress rule for all traffic on this path + method (ctl:ruleRemoveById in location block)" },
  { value: "GLOBAL", label: "Global Override", icon: <Globe className="w-3.5 h-3.5" />, desc: "Suppress rule globally across ALL paths — use only as last resort" },
];

const TTL_OPTIONS = [
  { label: "Permanent", value: "0" },
  { label: "24 Hours", value: "86400" },
  { label: "7 Days", value: "604800" },
  { label: "30 Days", value: "2592000" },
  { label: "90 Days", value: "7776000" },
];

const WIZARD_STEPS = ["Rule & Scope", "Path & Method", "Precision Target", "Review & Deploy"];

export default function TuningPage() {
  const [exceptions, setExceptions] = useState<RuleException[]>([]);
  const [recommendations, setRecommendations] = useState<TuningRecommendation[]>([]);
  const [loading, setLoading] = useState(true);
  const [recLoading, setRecLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [notification, setNotification] = useState<{ type: "success" | "error" | null; message: string }>({ type: null, message: "" });
  const [showWizard, setShowWizard] = useState(false);
  const [wizardStep, setWizardStep] = useState(0);

  // Wizard fields
  const [formRuleID, setFormRuleID] = useState("");
  const [formScope, setFormScope] = useState("TARGET");
  const [formPath, setFormPath] = useState("");
  const [formMethod, setFormMethod] = useState("ANY");
  const [formParam, setFormParam] = useState("");
  const [formHeader, setFormHeader] = useState("");
  const [formReason, setFormReason] = useState("");
  const [formTicket, setFormTicket] = useState("");
  const [formTTL, setFormTTL] = useState("0");

  // Replay Simulator state
  const [replayCode, setReplayCode] = useState(
    `SecRule REQUEST_URI "@rx (admin|debug|bypass)" "id:990001,phase:1,deny,status:403,msg:'Privileged URI pattern match'"`
  );
  const [replayMethod, setReplayMethod] = useState("GET");
  const [replayURI, setReplayURI] = useState("/api/v1/admin/dashboard?debug=true");
  const [replayBody, setReplayBody] = useState("");
  const [replayIP, setReplayIP] = useState("198.51.100.25");
  const [replayResult, setReplayResult] = useState<ReplayResult | null>(null);
  const [replayRunning, setReplayRunning] = useState(false);


  const fetchExceptions = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/exceptions`);
      if (res.ok) setExceptions((await res.json()) || []);
    } catch (err) {
      console.error("Failed to fetch exceptions:", err);
    } finally {
      setLoading(false);
    }
  }, [API]);

  const fetchRecommendations = useCallback(async () => {
    setRecLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/tuning/recommendations`);
      if (res.ok) {
        const data = await res.json();
        setRecommendations(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      console.error("Failed to fetch recommendations:", err);
    } finally {
      setRecLoading(false);
    }
  }, [API]);

  useEffect(() => { 
    fetchExceptions(); 
    fetchRecommendations();
  }, [fetchExceptions, fetchRecommendations]);

  // Pre-fill wizard from URL query (coming from Events page "Whitelist" button)
  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const ruleId = params.get("rule_id");
    const path = params.get("path");
    const method = params.get("method");
    if (ruleId) {
      setFormRuleID(ruleId);
      if (path) setFormPath(path);
      if (method) setFormMethod(method);
      setShowWizard(true);
      setWizardStep(0);
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, []);

  const resetWizard = () => {
    setFormRuleID(""); setFormScope("TARGET"); setFormPath(""); setFormMethod("ANY");
    setFormParam(""); setFormHeader(""); setFormReason(""); setFormTicket(""); setFormTTL("0");
    setWizardStep(0); setShowWizard(false);
  };

  const canAdvance = () => {
    if (wizardStep === 0) return formRuleID.trim().length > 0;
    if (wizardStep === 1) return formPath.trim().length > 0;
    if (wizardStep === 2) return formScope === "GLOBAL" || formParam.trim().length > 0 || formHeader.trim().length > 0 || formScope === "PATH_ONLY";
    return true;
  };

  const handleCreateException = async () => {
    if (!formRuleID.trim() || !formPath.trim()) return;
    setActionLoading(true);
    setNotification({ type: null, message: "" });
    try {
      const res = await fetch(`${API}/api/v1/exceptions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_rule_id: formRuleID.trim(),
          match_path: formPath.trim(),
          match_method: formMethod,
          match_param: formParam.trim() || undefined,
          match_header: formHeader.trim() || undefined,
          scope: formScope,
          reason: formReason.trim() || "False positive tuning exception",
          ticket_ref: formTicket.trim() || undefined,
          ttl_seconds: parseInt(formTTL, 10) || 0,
        }),
      });
      if (res.ok) {
        setNotification({ type: "success", message: `Exception for rule #${formRuleID} [${formScope}] deployed to Envoy xDS via ctl:ruleRemoveTargetById.` });
        resetWizard(); 
        fetchExceptions();
      } else {
        setNotification({ type: "error", message: "Failed to create rule exception." });
      }
    } catch {
      setNotification({ type: "error", message: "Network error occurred." });
    } finally {
      setActionLoading(false);
    }
  };

  const handleApplyRecommendation = async (rec: TuningRecommendation) => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/tuning/recommendations/apply`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rule_id: rec.rule_id,
          match_path: rec.match_path,
          match_method: "ANY",
          scope: rec.suggested_scope,
          match_param: rec.match_param || undefined,
          reason: `Auto-Tuning Engine: ${rec.justification}`
        })
      });
      if (res.ok) {
        setNotification({
          type: "success",
          message: `Auto-Tuning recommendation applied for Rule #${rec.rule_id} on ${rec.match_path}! Dynamic xDS synced.`
        });
        fetchExceptions();
        fetchRecommendations();
      }
    } catch {
      setNotification({ type: "error", message: "Failed to apply recommendation." });
    } finally {
      setActionLoading(false);
    }
  };

  const handleRunReplay = async () => {
    setReplayRunning(true);
    try {
      const res = await fetch(`${API}/api/v1/replay/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          seclang_code: replayCode,
          method: replayMethod,
          uri: replayURI,
          body: replayBody,
          client_ip: replayIP
        })
      });
      if (res.ok) {
        const data = await res.json();
        setReplayResult(data);
      }
    } catch (err) {
      console.error("Replay simulation failed:", err);
    } finally {
      setReplayRunning(false);
    }
  };

  const handleDeleteException = async (id: number, rule: string) => {
    if (!confirm(`Remove exception for rule #${rule}? OWASP CRS rule will be re-enforced immediately on next xDS push.`)) return;
    setActionLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/exceptions/${id}`, { method: "DELETE" });
      if (res.ok) {
        setNotification({ type: "success", message: `Exception for rule #${rule} removed. Rule re-enforced.` });
        fetchExceptions();
      }
    } catch {
      setNotification({ type: "error", message: "Network error occurred." });
    } finally {
      setActionLoading(false);
    }
  };

  const renderSecLangPreview = () => {
    const id = formRuleID || "942100";
    const path = formPath || "/api/search";
    if (formScope === "TARGET") {
      const target = formParam ? `REQUEST_BODY:${formParam}` : `REQUEST_HEADERS:${formHeader}`;
      return (
        <pre className="text-[10px] font-mono text-emerald-400 whitespace-pre-wrap">
{`# Precision target suppression (most granular)
SecRule REQUEST_URI "@beginsWith ${path}" \\
  "id:${id},phase:2,pass,nolog,\\
  ctl:ruleRemoveTargetById=${id};${target}"`}
        </pre>
      );
    }
    if (formScope === "PATH_ONLY") {
      return (
        <pre className="text-[10px] font-mono text-amber-400 whitespace-pre-wrap">
{`# Path-scoped suppression
SecRule REQUEST_URI "@beginsWith ${path}" \\
  "id:${id},phase:2,pass,nolog,\\
  ctl:ruleRemoveById=${id}"`}
        </pre>
      );
    }
    return (
      <pre className="text-[10px] font-mono text-red-400 whitespace-pre-wrap">
{`# Global rule removal — applies to ALL paths
SecRuleRemoveById ${id}`}
      </pre>
    );
  };

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-12 animate-in fade-in slide-in-from-bottom-4 duration-700">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-border pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-amber-400 via-emerald-400 to-cyan-400">
            Intelligent False-Positive Tuning &amp; Replay Studio
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Automated tuning assistant, precision parameter-level exceptions (ctl:ruleRemoveTargetById), and offline SecRule event replay simulation.
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => { fetchExceptions(); fetchRecommendations(); }} disabled={loading}
            className="flex items-center gap-1.5 bg-secondary/80 hover:bg-secondary border border-border px-3 py-2 rounded-lg text-sm transition-colors">
            <RefreshCw className={`w-3.5 h-3.5 ${loading || recLoading ? "animate-spin" : ""}`} /> Refresh
          </button>
          <button onClick={() => { setShowWizard(true); setWizardStep(0); }}
            className="flex items-center gap-2 bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold px-4 py-2 rounded-lg text-sm transition-colors">
            <PlusCircle className="w-4 h-4" /> New Exception
          </button>
        </div>
      </div>

      {notification.type && (
        <div className={`p-4 rounded-lg flex items-start gap-3 border text-sm ${notification.type === "success" ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400" : "bg-red-500/10 border-red-500/20 text-red-400"}`}>
          {notification.type === "success" ? <CheckCircle2 className="w-5 h-5 shrink-0" /> : <AlertCircle className="w-5 h-5 shrink-0" />}
          <p>{notification.message}</p>
        </div>
      )}

      {/* Auto-Tuning Assistant Recommendations */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-amber-400" />
            <h2 className="text-base font-bold text-foreground">Auto-Tuning Assistant — AI Rule Recommendations</h2>
          </div>
          <span className="text-xs text-muted-foreground font-mono">Real-Time Pattern Analysis</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {recommendations.map((rec) => (
            <div key={rec.id} className="p-4 rounded-xl border border-border bg-card/60 backdrop-blur-sm flex flex-col justify-between hover:border-amber-500/40 transition-all group">
              <div>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <span className="font-mono text-xs font-bold text-amber-400">
                    Rule #{rec.rule_id}
                  </span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                    rec.false_positive_risk === "HIGH"
                      ? "bg-rose-500/10 text-rose-400 border-rose-500/20"
                      : rec.false_positive_risk === "MEDIUM"
                      ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                      : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                  }`}>
                    {rec.false_positive_risk} FP Risk
                  </span>
                </div>
                <h3 className="font-semibold text-sm text-foreground mb-1 group-hover:text-emerald-300 transition-colors">
                  {rec.rule_name}
                </h3>
                <div className="text-xs text-muted-foreground font-mono mb-2 truncate">
                  Path: <span className="text-foreground">{rec.match_path}</span>
                  {rec.match_param && <span className="text-cyan-400 ml-1.5">[{rec.match_param}]</span>}
                </div>
                <p className="text-xs text-muted-foreground line-clamp-3 mb-3">
                  {rec.justification}
                </p>
              </div>

              <div className="pt-3 border-t border-border/50 flex items-center justify-between">
                <span className="text-[11px] text-muted-foreground font-mono">
                  {rec.occurrences} triggers recorded
                </span>
                <button
                  onClick={() => handleApplyRecommendation(rec)}
                  disabled={actionLoading}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 text-xs font-semibold transition-colors"
                >
                  <Check className="w-3.5 h-3.5" /> Apply Exception
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Wizard Modal */}
      {showWizard && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f1520] border border-amber-500/20 rounded-xl w-full max-w-lg p-6 space-y-5 shadow-2xl animate-in zoom-in-95 duration-200">
            <div>
              <h3 className="text-base font-bold text-amber-400 flex items-center gap-2">
                <Sliders className="w-5 h-5" /> Exception Wizard — {WIZARD_STEPS[wizardStep]}
              </h3>
              <div className="flex gap-1 mt-3">
                {WIZARD_STEPS.map((s, i) => (
                  <div key={s} className={`h-1 flex-1 rounded-full transition-colors ${i <= wizardStep ? "bg-amber-400" : "bg-secondary"}`} />
                ))}
              </div>
            </div>

            {/* Step 0: Rule & Scope */}
            {wizardStep === 0 && (
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-muted-foreground uppercase mb-2">Target Rule ID</label>
                  <input type="text" placeholder="e.g. 942100" value={formRuleID} onChange={(e) => setFormRuleID(e.target.value)}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm font-mono text-foreground focus:outline-none focus:border-amber-400" />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-muted-foreground uppercase mb-2">Suppression Scope</label>
                  <div className="space-y-2">
                    {SCOPE_OPTIONS.map((opt) => (
                      <label key={opt.value} className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${formScope === opt.value ? "border-amber-400 bg-amber-400/5" : "border-border bg-secondary/20 hover:bg-secondary/40"}`}>
                        <input type="radio" name="scope" value={opt.value} checked={formScope === opt.value} onChange={() => setFormScope(opt.value)} className="mt-1" />
                        <div>
                          <div className="flex items-center gap-2 text-sm font-semibold">{opt.icon} {opt.label}</div>
                          <p className="text-xs text-muted-foreground mt-0.5">{opt.desc}</p>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Step 1: Path & Method */}
            {wizardStep === 1 && (
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-muted-foreground uppercase mb-2">Endpoint Path Pattern</label>
                  <input type="text" placeholder="/api/search or /v1/user/*" value={formPath} onChange={(e) => setFormPath(e.target.value)}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm font-mono text-foreground focus:outline-none focus:border-amber-400" />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-muted-foreground uppercase mb-2">HTTP Method</label>
                  <select value={formMethod} onChange={(e) => setFormMethod(e.target.value)}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-amber-400">
                    {["ANY", "GET", "POST", "PUT", "DELETE", "PATCH"].map((m) => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </select>
                </div>
              </div>
            )}

            {/* Step 2: Precision Target */}
            {wizardStep === 2 && (
              <div className="space-y-4">
                {formScope === "TARGET" && (
                  <>
                    <div>
                      <label className="block text-xs font-semibold text-muted-foreground uppercase mb-2">Target Body Parameter (ARGS / REQUEST_BODY)</label>
                      <input type="text" placeholder="e.g. query, comment, search_term" value={formParam} onChange={(e) => setFormParam(e.target.value)}
                        className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm font-mono text-foreground focus:outline-none focus:border-amber-400" />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-muted-foreground uppercase mb-2">Target Header (REQUEST_HEADERS)</label>
                      <input type="text" placeholder="e.g. User-Agent, X-Custom-Token" value={formHeader} onChange={(e) => setFormHeader(e.target.value)}
                        className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm font-mono text-foreground focus:outline-none focus:border-amber-400" />
                    </div>
                  </>
                )}
                <div>
                  <label className="block text-xs font-semibold text-muted-foreground uppercase mb-2">Business Justification / Reason</label>
                  <textarea rows={2} placeholder="Legitimate search terms trigger SQLi regex; Telkomsel tower app ticket ref." value={formReason} onChange={(e) => setFormReason(e.target.value)}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-amber-400" />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-semibold text-muted-foreground uppercase mb-1">Ticket / CRQ Ref</label>
                    <input type="text" placeholder="CRQ-100234" value={formTicket} onChange={(e) => setFormTicket(e.target.value)}
                      className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-xs font-mono text-foreground focus:outline-none focus:border-amber-400" />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-muted-foreground uppercase mb-1">TTL Expiration</label>
                    <select value={formTTL} onChange={(e) => setFormTTL(e.target.value)}
                      className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-xs text-foreground focus:outline-none focus:border-amber-400">
                      {TTL_OPTIONS.map((t) => (
                        <option key={t.value} value={t.value}>{t.label}</option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>
            )}

            {/* Step 3: Review & Deploy */}
            {wizardStep === 3 && (
              <div className="space-y-4">
                <div className="bg-secondary/30 rounded-lg p-3 border border-border text-xs space-y-1">
                  <div><span className="text-muted-foreground">Rule:</span> <span className="font-mono font-bold text-amber-400">#{formRuleID}</span></div>
                  <div><span className="text-muted-foreground">Scope:</span> <span className="font-semibold text-foreground">{formScope}</span></div>
                  <div><span className="text-muted-foreground">Path:</span> <span className="font-mono text-foreground">{formPath}</span></div>
                  <div><span className="text-muted-foreground">Method:</span> <span className="font-mono text-foreground">{formMethod}</span></div>
                  {formParam && <div><span className="text-muted-foreground">Param:</span> <span className="font-mono text-emerald-400">{formParam}</span></div>}
                  {formHeader && <div><span className="text-muted-foreground">Header:</span> <span className="font-mono text-cyan-400">{formHeader}</span></div>}
                </div>
                <div className="bg-black/50 rounded-lg p-3 border border-border">
                  <div className="text-[10px] text-muted-foreground uppercase font-mono mb-1">Generated SecLang Directive</div>
                  {renderSecLangPreview()}
                </div>
              </div>
            )}

            {/* Wizard Nav */}
            <div className="flex justify-between items-center pt-3 border-t border-border">
              <button onClick={() => wizardStep === 0 ? resetWizard() : setWizardStep((s) => s - 1)}
                className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
                <ChevronLeft className="w-3.5 h-3.5" /> {wizardStep === 0 ? "Cancel" : "Back"}
              </button>
              {wizardStep < WIZARD_STEPS.length - 1 ? (
                <button onClick={() => setWizardStep((s) => s + 1)} disabled={!canAdvance()}
                  className="flex items-center gap-1 bg-amber-400 hover:bg-amber-500 disabled:opacity-40 text-slate-950 font-bold px-4 py-2 rounded-lg text-xs transition-colors">
                  Next <ChevronRight className="w-3.5 h-3.5" />
                </button>
              ) : (
                <button onClick={handleCreateException} disabled={actionLoading}
                  className="flex items-center gap-1.5 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-40 text-slate-950 font-bold px-4 py-2 rounded-lg text-xs transition-colors">
                  <Check className="w-3.5 h-3.5" /> Deploy to Ingress xDS
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Active Exceptions Table */}
      <div className="glass-panel rounded-xl overflow-hidden border border-border">
        <div className="p-4 bg-secondary/30 border-b border-border flex items-center justify-between">
          <span className="font-semibold text-sm flex items-center gap-2">
            <Shield className="w-4 h-4 text-amber-400" />
            Active Rule Exceptions ({exceptions.length})
          </span>
          <span className="text-xs text-muted-foreground">Compiled as SecLang ctl:ruleRemoveTargetById / ruleRemoveById / SecRuleRemoveById</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-muted-foreground uppercase bg-secondary/50 border-b border-border">
              <tr>
                <th className="px-4 py-3 font-semibold tracking-wider">Rule ID</th>
                <th className="px-4 py-3 font-semibold tracking-wider">Scope</th>
                <th className="px-4 py-3 font-semibold tracking-wider">Path / Target</th>
                <th className="px-4 py-3 font-semibold tracking-wider">Method</th>
                <th className="px-4 py-3 font-semibold tracking-wider">Reason</th>
                <th className="px-4 py-3 font-semibold tracking-wider">Meta</th>
                <th className="px-4 py-3 font-semibold tracking-wider text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50">
              {loading && exceptions.length === 0 ? (
                <tr><td colSpan={7} className="px-4 py-12 text-center text-muted-foreground">Loading exceptions...</td></tr>
              ) : exceptions.length === 0 ? (
                <tr><td colSpan={7} className="px-4 py-12 text-center text-muted-foreground">No active exceptions — Full OWASP CRS enforced.</td></tr>
              ) : (
                exceptions.map((item) => (
                  <tr key={item.id} className="hover:bg-secondary/30 transition-colors">
                    <td className="px-4 py-3 font-mono font-bold text-amber-400 whitespace-nowrap">#{item.target_rule_id}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${
                        item.scope === "TARGET" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" :
                        item.scope === "GLOBAL" ? "bg-red-500/10 text-red-400 border-red-500/20" :
                        "bg-amber-500/10 text-amber-400 border-amber-500/20"
                      }`}>{item.scope || "PATH_ONLY"}</span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                      <div>{item.match_path}</div>
                      {item.match_param && <div className="text-emerald-400 mt-0.5">param:{item.match_param}</div>}
                      {item.match_header && <div className="text-cyan-400 mt-0.5">hdr:{item.match_header}</div>}
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded bg-secondary text-xs font-mono">{item.match_method}</span>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground max-w-[160px] truncate" title={item.reason}>{item.reason}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-1">
                        {item.ticket_ref && (
                          <span className="flex items-center gap-1 text-[10px] text-blue-400 font-mono">
                            <Tag className="w-2.5 h-2.5" />{item.ticket_ref}
                          </span>
                        )}
                        {item.expires_at && (
                          <span className="flex items-center gap-1 text-[10px] text-red-400">
                            <Clock className="w-2.5 h-2.5" />{format(new Date(item.expires_at), "MMM d")}
                          </span>
                        )}
                        <span className="text-[10px] text-muted-foreground">{format(new Date(item.created_at), "MMM dd, HH:mm")}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button onClick={() => handleDeleteException(item.id, item.target_rule_id)} disabled={actionLoading}
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-md bg-secondary/60 hover:bg-red-500/20 hover:text-red-400 text-muted-foreground text-xs font-medium border border-border transition-colors">
                        <Trash2 className="w-3.5 h-3.5" /> Remove
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Security Event Replay & Dry-Run Simulation Studio */}
      <div className="glass-panel rounded-xl overflow-hidden border border-border p-6 space-y-6">
        <div className="flex items-center justify-between border-b border-border pb-4">
          <div>
            <h2 className="text-lg font-bold text-foreground flex items-center gap-2">
              <Play className="w-5 h-5 text-cyan-400" />
              SecRule Dry-Run &amp; Event Replay Simulator
            </h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              Simulate candidate SecLang rules and virtual patches against synthetic traffic or historical security events before edge deployment.
            </p>
          </div>
          <button
            onClick={handleRunReplay}
            disabled={replayRunning}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-600 text-slate-950 font-bold text-sm shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-50"
          >
            <Play className={`w-4 h-4 fill-current ${replayRunning ? "animate-spin" : ""}`} />
            {replayRunning ? "Simulating..." : "Run Replay Simulation"}
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Inputs */}
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-muted-foreground uppercase mb-1.5">
                SecLang Candidate Rule
              </label>
              <textarea
                rows={4}
                value={replayCode}
                onChange={(e) => setReplayCode(e.target.value)}
                className="w-full rounded-lg border border-border bg-black/40 p-3 text-xs font-mono text-cyan-300 focus:outline-none focus:ring-1 focus:ring-cyan-400"
              />
            </div>

            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="block text-xs font-medium text-foreground mb-1">Method</label>
                <select
                  value={replayMethod}
                  onChange={(e) => setReplayMethod(e.target.value)}
                  className="w-full rounded-lg border border-border bg-secondary/50 p-2 text-xs font-mono text-foreground"
                >
                  {["GET", "POST", "PUT", "DELETE"].map((m) => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </div>

              <div className="col-span-2">
                <label className="block text-xs font-medium text-foreground mb-1">Target URI / Path</label>
                <input
                  type="text"
                  value={replayURI}
                  onChange={(e) => setReplayURI(e.target.value)}
                  className="w-full rounded-lg border border-border bg-secondary/50 p-2 text-xs font-mono text-foreground"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-foreground mb-1">Simulated Client IP</label>
                <input
                  type="text"
                  value={replayIP}
                  onChange={(e) => setReplayIP(e.target.value)}
                  className="w-full rounded-lg border border-border bg-secondary/50 p-2 text-xs font-mono text-foreground"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-foreground mb-1">Request Body / Payload</label>
                <input
                  type="text"
                  value={replayBody}
                  onChange={(e) => setReplayBody(e.target.value)}
                  placeholder='{"username": "admin"}'
                  className="w-full rounded-lg border border-border bg-secondary/50 p-2 text-xs font-mono text-foreground"
                />
              </div>
            </div>
          </div>

          {/* Results Output */}
          <div className="rounded-lg border border-border/70 bg-black/40 p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-border/50">
                <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider font-mono">
                  Simulation Outcome
                </span>
                {replayResult && (
                  <span className="text-[11px] font-mono text-muted-foreground">
                    Latency: {replayResult.processing_time_us}µs
                  </span>
                )}
              </div>

              {!replayResult ? (
                <div className="py-16 text-center text-muted-foreground text-xs">
                  <Play className="w-8 h-8 mx-auto mb-2 text-muted-foreground/40" />
                  Enter SecRule and HTTP parameters, then click &quot;Run Replay Simulation&quot;.
                </div>
              ) : (
                <div className="mt-3 space-y-4">
                  <div className="flex items-center gap-3">
                    <span className={`px-3 py-1 rounded-full text-xs font-bold font-mono border ${
                      replayResult.final_verdict === "BLOCKED"
                        ? "bg-rose-500/20 text-rose-400 border-rose-500/30"
                        : "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                    }`}>
                      {replayResult.final_verdict === "BLOCKED" ? "INTERCEPTED & BLOCKED" : "TRAFFIC ALLOWED"}
                    </span>
                    <span className="text-xs text-muted-foreground font-mono">
                      Rules evaluated: {replayResult.evaluated_rules}
                    </span>
                  </div>

                  <div>
                    <h4 className="text-xs font-semibold text-foreground mb-2">
                      Matched Rule Directives ({replayResult.matches.length})
                    </h4>
                    {replayResult.matches.length === 0 ? (
                      <div className="text-xs text-emerald-400 bg-emerald-500/10 p-2.5 rounded border border-emerald-500/20">
                        Zero rule violations. Traffic passed through all evaluated phases.
                      </div>
                    ) : (
                      <div className="space-y-2">
                        {replayResult.matches.map((m, idx) => (
                          <div key={idx} className="p-2.5 rounded bg-secondary/50 border border-rose-500/20 text-xs font-mono space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="text-amber-400 font-bold">Rule #{m.rule_id}</span>
                              <span className="text-rose-400 text-[10px]">{m.action}</span>
                            </div>
                            <div className="text-foreground text-[11px]">{m.message}</div>
                            <div className="text-muted-foreground text-[10px]">
                              Match: <span className="text-cyan-300 font-bold">{m.matched_data}</span> ({m.operator})
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {replayResult && (
              <div className="pt-3 border-t border-border/40 text-[10px] text-muted-foreground font-mono">
                Simulation ID: {replayResult.request_id}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}


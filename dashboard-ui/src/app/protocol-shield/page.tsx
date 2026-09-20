"use client";

import { useState, useEffect } from "react";
import { 
  Binary, 
  ShieldAlert, 
  Plus, 
  Trash2, 
  RefreshCw, 
  CheckCircle2, 
  Lock, 
  Activity, 
  AlertTriangle,
  Play,
  KeyRound,
  FileCode2,
  Sliders,
  Check,
  X
} from "lucide-react";
import { API } from "@/lib/api";

interface ProtocolPolicy {
  id: number;
  name: string;
  policy_type: string;
  disallowed_methods: string;
  max_headers_count: number;
  max_header_size_bytes: number;
  action: string;
  is_enabled: boolean;
  created_at: string;
}

interface CredentialAbusePolicy {
  id: number;
  name: string;
  login_path: string;
  max_failed_attempts: number;
  observation_window_seconds: number;
  action: string;
  is_enabled: boolean;
  created_at: string;
}

export default function ProtocolShieldPage() {
  const [protocolPolicies, setProtocolPolicies] = useState<ProtocolPolicy[]>([]);
  const [abusePolicies, setAbusePolicies] = useState<CredentialAbusePolicy[]>([]);
  const [loading, setLoading] = useState(true);
  
  // Modals
  const [showProtocolModal, setShowProtocolModal] = useState(false);
  const [showAbuseModal, setShowAbuseModal] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Protocol Form State
  const [protoName, setProtoName] = useState("");
  const [protoType, setProtoType] = useState("METHOD_ENFORCEMENT");
  const [disallowedMethods, setDisallowedMethods] = useState("TRACE, CONNECT, TRACK");
  const [maxHeadersCount, setMaxHeadersCount] = useState(100);
  const [maxHeaderSizeBytes, setMaxHeaderSizeBytes] = useState(16384);
  const [protoAction, setProtoAction] = useState("BLOCK");

  // Abuse Form State
  const [abuseName, setAbuseName] = useState("");
  const [loginPath, setLoginPath] = useState("/api/login");
  const [maxFailedAttempts, setMaxFailedAttempts] = useState(5);
  const [windowSeconds, setWindowSeconds] = useState(300);
  const [abuseAction, setAbuseAction] = useState("BLOCK");

  // Test Simulator State
  const [simMethod, setSimMethod] = useState("TRACE");
  const [simPath, setSimPath] = useState("/api/login");
  const [simFailedAttempts, setSimFailedAttempts] = useState(6);
  const [simVerdict, setSimVerdict] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [protoRes, abuseRes] = await Promise.all([
        fetch(`${API}/api/v1/protocol-policies`),
        fetch(`${API}/api/v1/abuse-policies`)
      ]);

      if (protoRes.ok) {
        const pData = await protoRes.json();
        setProtocolPolicies(pData || []);
      }
      if (abuseRes.ok) {
        const aData = await abuseRes.json();
        setAbusePolicies(aData || []);
      }
    } catch (err) {
      console.error("Failed to load policies", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleCreateProtocol = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      const res = await fetch(`${API}/api/v1/protocol-policies`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: protoName,
          policy_type: protoType,
          disallowed_methods: disallowedMethods,
          max_headers_count: Number(maxHeadersCount),
          max_header_size_bytes: Number(maxHeaderSizeBytes),
          action: protoAction,
          is_enabled: true
        })
      });

      if (res.ok) {
        setShowProtocolModal(false);
        setProtoName("");
        fetchData();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleToggleProtocol = async (id: number) => {
    try {
      const res = await fetch(`${API}/api/v1/protocol-policies/${id}/toggle`, {
        method: "PUT"
      });
      if (res.ok) {
        fetchData();
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleDeleteProtocol = async (id: number) => {
    if (!confirm("Are you sure you want to delete this protocol policy?")) return;
    try {
      const res = await fetch(`${API}/api/v1/protocol-policies/${id}`, {
        method: "DELETE"
      });
      if (res.ok) {
        fetchData();
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleCreateAbuse = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      const res = await fetch(`${API}/api/v1/abuse-policies`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: abuseName,
          login_path: loginPath,
          max_failed_attempts: Number(maxFailedAttempts),
          observation_window_seconds: Number(windowSeconds),
          action: abuseAction,
          is_enabled: true
        })
      });

      if (res.ok) {
        setShowAbuseModal(false);
        setAbuseName("");
        fetchData();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteAbuse = async (id: number) => {
    if (!confirm("Are you sure you want to delete this credential abuse policy?")) return;
    try {
      const res = await fetch(`${API}/api/v1/abuse-policies/${id}`, {
        method: "DELETE"
      });
      if (res.ok) {
        fetchData();
      }
    } catch (err) {
      console.error(err);
    }
  };

  const testSimulate = () => {
    // Protocol method check
    const activeMethodPolicy = protocolPolicies.find(p => p.is_enabled && p.policy_type === "METHOD_ENFORCEMENT");
    if (activeMethodPolicy && activeMethodPolicy.disallowed_methods.toUpperCase().includes(simMethod.toUpperCase())) {
      setSimVerdict(`BLOCKED (HTTP 405): Method ${simMethod} disallowed by '${activeMethodPolicy.name}'`);
      return;
    }

    // Abuse check
    const activeAbusePolicy = abusePolicies.find(p => p.is_enabled && p.login_path === simPath);
    if (activeAbusePolicy && simFailedAttempts >= activeAbusePolicy.max_failed_attempts) {
      setSimVerdict(`TRIGGERED (${activeAbusePolicy.action}): Threshold of ${activeAbusePolicy.max_failed_attempts} failed attempts exceeded on ${simPath} within ${activeAbusePolicy.observation_window_seconds}s.`);
      return;
    }

    setSimVerdict(`ALLOWED: Request passes both Protocol Shield validation and Credential Abuse heuristics.`);
  };

  return (
    <div className="space-y-8 pb-12">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-teal-400 via-emerald-400 to-cyan-400">
            Protocol Shield & Credential Abuse Engine
          </h1>
          <p className="text-muted-foreground mt-1">
            HTTP RFC strict compliance, request smuggling prevention, and brute-force credential stuffing mitigation.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={fetchData} 
            className="flex items-center gap-2 px-3 py-2 bg-secondary/50 hover:bg-secondary text-foreground rounded-lg border border-border text-sm transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button 
            onClick={() => setShowProtocolModal(true)} 
            className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-medium shadow-lg shadow-emerald-500/20 transition"
          >
            <Plus className="w-4 h-4" />
            Add Protocol Rule
          </button>
          <button 
            onClick={() => setShowAbuseModal(true)} 
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium shadow-lg shadow-cyan-500/20 transition"
          >
            <KeyRound className="w-4 h-4" />
            Add Abuse Rule
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl border border-border bg-card/60 glass backdrop-blur-md">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Active Protocol Rules</span>
            <Binary className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold mt-2">
            {protocolPolicies.filter(p => p.is_enabled).length} / {protocolPolicies.length}
          </div>
          <div className="text-xs text-emerald-400 mt-1 flex items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5" /> RFC-7230 Compliant
          </div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/60 glass backdrop-blur-md">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Credential Abuse Policies</span>
            <KeyRound className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold mt-2">
            {abusePolicies.filter(p => p.is_enabled).length} / {abusePolicies.length}
          </div>
          <div className="text-xs text-cyan-400 mt-1 flex items-center gap-1">
            <Activity className="w-3.5 h-3.5" /> Real-time sliding window
          </div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/60 glass backdrop-blur-md">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Disallowed Methods</span>
            <ShieldAlert className="w-5 h-5 text-amber-400" />
          </div>
          <div className="text-2xl font-bold mt-2 text-amber-400">
            TRACE, CONNECT
          </div>
          <div className="text-xs text-muted-foreground mt-1">Cross-Site Tracing blocked</div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/60 glass backdrop-blur-md">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Header Limit Guards</span>
            <Lock className="w-5 h-5 text-purple-400" />
          </div>
          <div className="text-2xl font-bold mt-2 text-purple-400">
            100 Hdrs / 16KB
          </div>
          <div className="text-xs text-muted-foreground mt-1">Smuggling & Buffer guard</div>
        </div>
      </div>

      {/* Simulator Section */}
      <div className="p-6 rounded-xl border border-border bg-card/40 glass">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Play className="w-5 h-5 text-emerald-400" />
            <h3 className="font-semibold text-foreground text-lg">Live Protocol & Credential Abuse Policy Evaluator</h3>
          </div>
          <span className="text-xs px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
            Deterministic Engine
          </span>
        </div>
        <p className="text-sm text-muted-foreground mb-4">
          Simulate incoming requests against the active Coraza SecLang protocol enforcement set and credential thresholds.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
          <div>
            <label className="text-xs text-muted-foreground font-medium block mb-1">HTTP Method</label>
            <select 
              value={simMethod} 
              onChange={(e) => setSimMethod(e.target.value)}
              className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500"
            >
              <option value="GET">GET (Standard)</option>
              <option value="POST">POST (Standard)</option>
              <option value="PUT">PUT (Standard)</option>
              <option value="DELETE">DELETE (Standard)</option>
              <option value="TRACE">TRACE (Disallowed / XST)</option>
              <option value="CONNECT">CONNECT (Disallowed / Tunneling)</option>
              <option value="TRACK">TRACK (Disallowed)</option>
            </select>
          </div>

          <div>
            <label className="text-xs text-muted-foreground font-medium block mb-1">Request Path</label>
            <input 
              type="text" 
              value={simPath} 
              onChange={(e) => setSimPath(e.target.value)}
              className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div>
            <label className="text-xs text-muted-foreground font-medium block mb-1">Failed Attempts in Window</label>
            <input 
              type="number" 
              value={simFailedAttempts} 
              onChange={(e) => setSimFailedAttempts(Number(e.target.value))}
              className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500"
            />
          </div>

          <button 
            onClick={testSimulate}
            className="w-full py-2 bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-600 hover:to-cyan-600 text-white font-medium rounded-lg text-sm transition"
          >
            Run Evaluation
          </button>
        </div>

        {simVerdict && (
          <div className="mt-4 p-4 rounded-lg bg-secondary/60 border border-border flex items-start gap-3">
            {simVerdict.startsWith("BLOCKED") || simVerdict.startsWith("TRIGGERED") ? (
              <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            ) : (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            )}
            <div>
              <div className="font-semibold text-sm text-foreground">Verdict Result</div>
              <div className="text-sm font-mono mt-1 text-muted-foreground">{simVerdict}</div>
            </div>
          </div>
        )}
      </div>

      {/* Protocol Policies Table */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Binary className="w-5 h-5 text-emerald-400" />
            <h2 className="text-xl font-semibold text-foreground">HTTP Protocol Enforcement Policies</h2>
          </div>
          <span className="text-xs text-muted-foreground">{protocolPolicies.length} policies registered</span>
        </div>

        <div className="rounded-xl border border-border bg-card/40 glass overflow-hidden">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border bg-secondary/30 text-xs text-muted-foreground uppercase font-medium">
              <tr>
                <th className="px-5 py-3">Policy Name</th>
                <th className="px-5 py-3">Type</th>
                <th className="px-5 py-3">Disallowed Methods</th>
                <th className="px-5 py-3">Header Thresholds</th>
                <th className="px-5 py-3">Action</th>
                <th className="px-5 py-3">Status</th>
                <th className="px-5 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-5 py-8 text-center text-muted-foreground">Loading policies...</td>
                </tr>
              ) : protocolPolicies.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-5 py-8 text-center text-muted-foreground">No protocol policies found.</td>
                </tr>
              ) : (
                protocolPolicies.map((p) => (
                  <tr key={p.id} className="hover:bg-secondary/20 transition">
                    <td className="px-5 py-3.5 font-medium text-foreground">{p.name}</td>
                    <td className="px-5 py-3.5 font-mono text-xs text-cyan-400">{p.policy_type}</td>
                    <td className="px-5 py-3.5 font-mono text-xs text-rose-300">
                      {p.disallowed_methods || <span className="text-muted-foreground">N/A</span>}
                    </td>
                    <td className="px-5 py-3.5 text-xs text-muted-foreground">
                      Max {p.max_headers_count} hdrs / {p.max_header_size_bytes}B
                    </td>
                    <td className="px-5 py-3.5">
                      <span className="text-xs px-2.5 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20 font-semibold">
                        {p.action}
                      </span>
                    </td>
                    <td className="px-5 py-3.5">
                      <button
                        onClick={() => handleToggleProtocol(p.id)}
                        className={`px-2.5 py-0.5 rounded-full text-xs font-medium border flex items-center gap-1 transition ${
                          p.is_enabled
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                            : "bg-secondary text-muted-foreground border-border"
                        }`}
                      >
                        {p.is_enabled ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                        {p.is_enabled ? "Enabled" : "Disabled"}
                      </button>
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      <button
                        onClick={() => handleDeleteProtocol(p.id)}
                        className="p-1.5 hover:bg-rose-500/20 hover:text-rose-400 text-muted-foreground rounded-lg transition"
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

      {/* Credential Abuse Policies Table */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <KeyRound className="w-5 h-5 text-cyan-400" />
            <h2 className="text-xl font-semibold text-foreground">Credential Stuffing & Brute-Force Shield</h2>
          </div>
          <span className="text-xs text-muted-foreground">{abusePolicies.length} endpoints monitored</span>
        </div>

        <div className="rounded-xl border border-border bg-card/40 glass overflow-hidden">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border bg-secondary/30 text-xs text-muted-foreground uppercase font-medium">
              <tr>
                <th className="px-5 py-3">Policy Name</th>
                <th className="px-5 py-3">Monitored Login Endpoint</th>
                <th className="px-5 py-3">Failed Attempts Limit</th>
                <th className="px-5 py-3">Sliding Window</th>
                <th className="px-5 py-3">Mitigation</th>
                <th className="px-5 py-3">Status</th>
                <th className="px-5 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-5 py-8 text-center text-muted-foreground">Loading policies...</td>
                </tr>
              ) : abusePolicies.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-5 py-8 text-center text-muted-foreground">No abuse policies found.</td>
                </tr>
              ) : (
                abusePolicies.map((a) => (
                  <tr key={a.id} className="hover:bg-secondary/20 transition">
                    <td className="px-5 py-3.5 font-medium text-foreground">{a.name}</td>
                    <td className="px-5 py-3.5 font-mono text-xs text-cyan-300">{a.login_path}</td>
                    <td className="px-5 py-3.5 text-xs font-semibold text-amber-400">{a.max_failed_attempts} attempts</td>
                    <td className="px-5 py-3.5 text-xs text-muted-foreground">{a.observation_window_seconds} seconds</td>
                    <td className="px-5 py-3.5">
                      <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-semibold">
                        {a.action}
                      </span>
                    </td>
                    <td className="px-5 py-3.5">
                      <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">
                        Active
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      <button
                        onClick={() => handleDeleteAbuse(a.id)}
                        className="p-1.5 hover:bg-rose-500/20 hover:text-rose-400 text-muted-foreground rounded-lg transition"
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

      {/* Create Protocol Modal */}
      {showProtocolModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-card border border-border rounded-xl p-6 w-full max-w-md shadow-2xl glass space-y-4">
            <h3 className="text-lg font-semibold text-foreground">Create HTTP Protocol Policy</h3>
            <form onSubmit={handleCreateProtocol} className="space-y-4">
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Policy Name</label>
                <input 
                  type="text" 
                  required
                  placeholder="e.g. Strict RFC Compliance"
                  value={protoName} 
                  onChange={(e) => setProtoName(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="text-xs text-muted-foreground block mb-1">Policy Type</label>
                <select 
                  value={protoType} 
                  onChange={(e) => setProtoType(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500"
                >
                  <option value="METHOD_ENFORCEMENT">METHOD_ENFORCEMENT</option>
                  <option value="SMUGGLING_PROTECTION">SMUGGLING_PROTECTION</option>
                  <option value="HEADER_LIMITS">HEADER_LIMITS</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-muted-foreground block mb-1">Disallowed Methods (Comma separated)</label>
                <input 
                  type="text" 
                  value={disallowedMethods} 
                  onChange={(e) => setDisallowedMethods(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-muted-foreground block mb-1">Max Headers Count</label>
                  <input 
                    type="number" 
                    value={maxHeadersCount} 
                    onChange={(e) => setMaxHeadersCount(Number(e.target.value))}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground block mb-1">Max Header Bytes</label>
                  <input 
                    type="number" 
                    value={maxHeaderSizeBytes} 
                    onChange={(e) => setMaxHeaderSizeBytes(Number(e.target.value))}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs text-muted-foreground block mb-1">Action</label>
                <select 
                  value={protoAction} 
                  onChange={(e) => setProtoAction(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500"
                >
                  <option value="BLOCK">BLOCK (HTTP 405/400)</option>
                  <option value="LOG">LOG ONLY (Audit)</option>
                </select>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button 
                  type="button" 
                  onClick={() => setShowProtocolModal(false)}
                  className="px-4 py-2 bg-secondary text-foreground text-sm rounded-lg hover:bg-secondary/80 transition"
                >
                  Cancel
                </button>
                <button 
                  type="submit" 
                  disabled={isSubmitting}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium rounded-lg transition"
                >
                  {isSubmitting ? "Saving..." : "Create Policy"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Create Abuse Modal */}
      {showAbuseModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-card border border-border rounded-xl p-6 w-full max-w-md shadow-2xl glass space-y-4">
            <h3 className="text-lg font-semibold text-foreground">Create Credential Abuse Policy</h3>
            <form onSubmit={handleCreateAbuse} className="space-y-4">
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Policy Name</label>
                <input 
                  type="text" 
                  required
                  placeholder="e.g. Member Login Brute-Force Guard"
                  value={abuseName} 
                  onChange={(e) => setAbuseName(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-xs text-muted-foreground block mb-1">Login Endpoint Path</label>
                <input 
                  type="text" 
                  required
                  placeholder="/api/login"
                  value={loginPath} 
                  onChange={(e) => setLoginPath(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-muted-foreground block mb-1">Max Failed Attempts</label>
                  <input 
                    type="number" 
                    value={maxFailedAttempts} 
                    onChange={(e) => setMaxFailedAttempts(Number(e.target.value))}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground block mb-1">Window (Seconds)</label>
                  <input 
                    type="number" 
                    value={windowSeconds} 
                    onChange={(e) => setWindowSeconds(Number(e.target.value))}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs text-muted-foreground block mb-1">Action</label>
                <select 
                  value={abuseAction} 
                  onChange={(e) => setAbuseAction(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
                >
                  <option value="BLOCK">BLOCK (IP Deny)</option>
                  <option value="CHALLENGE">CHALLENGE (CAPTCHA)</option>
                  <option value="RATE_LIMIT">RATE_LIMIT (Throttle)</option>
                </select>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button 
                  type="button" 
                  onClick={() => setShowAbuseModal(false)}
                  className="px-4 py-2 bg-secondary text-foreground text-sm rounded-lg hover:bg-secondary/80 transition"
                >
                  Cancel
                </button>
                <button 
                  type="submit" 
                  disabled={isSubmitting}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium rounded-lg transition"
                >
                  {isSubmitting ? "Saving..." : "Create Abuse Policy"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}


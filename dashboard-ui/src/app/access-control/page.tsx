"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Users, KeyRound, Plus, Trash2, ShieldCheck, CheckCircle2, Copy, AlertTriangle, RefreshCw, Lock, Sparkles, UserCheck } from "lucide-react";

const API = "http://localhost:8082/api/v1";

interface User {
  id: number;
  username: string;
  email: string;
  role: string;
  department: string;
  is_active: boolean;
  created_at: string;
  last_login?: string;
}

interface APIToken {
  id: number;
  name: string;
  token_prefix: string;
  raw_token?: string;
  scopes: string;
  created_by: string;
  expires_at?: string;
  is_revoked: boolean;
  created_at: string;
}

export default function AccessControlPage() {
  const [tab, setTab] = useState<"users" | "tokens">("users");
  const [users, setUsers] = useState<User[]>([]);
  const [tokens, setTokens] = useState<APIToken[]>([]);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState<{ msg: string; type: "ok" | "err" } | null>(null);

  // Modals
  const [showUserModal, setShowUserModal] = useState(false);
  const [userForm, setUserForm] = useState({ username: "", email: "", role: "SOC_L2", department: "SOC Team" });

  const [showTokenModal, setShowTokenModal] = useState(false);
  const [tokenForm, setTokenForm] = useState({ name: "", scopes: "read:events,write:rules", expires_in_days: 90 });
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);

  const showToast = (msg: string, type: "ok" | "err" = "ok") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  };

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [uRes, tRes] = await Promise.all([
        fetch(`${API}/users`),
        fetch(`${API}/api-tokens`)
      ]);
      if (uRes.ok) setUsers(await uRes.json());
      if (tRes.ok) setTokens(await tRes.json());
    } catch {
      // Graceful fallback
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!userForm.username.trim() || !userForm.email.trim()) {
      showToast("Username and Email are required", "err");
      return;
    }
    try {
      const res = await fetch(`${API}/users`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(userForm),
      });
      if (!res.ok) throw new Error(await res.text());
      showToast("User account registered successfully");
      setShowUserModal(false);
      setUserForm({ username: "", email: "", role: "SOC_L2", department: "SOC Team" });
      fetchData();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Creation failed";
      showToast(msg, "err");
    }
  };

  const handleDeleteUser = async (id: number) => {
    if (!confirm("Are you sure you want to remove this user?")) return;
    try {
      await fetch(`${API}/users/${id}`, { method: "DELETE" });
      showToast("User deleted");
      fetchData();
    } catch {
      showToast("Failed to delete user", "err");
    }
  };

  const handleCreateToken = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tokenForm.name.trim()) {
      showToast("Token description name is required", "err");
      return;
    }
    try {
      const res = await fetch(`${API}/api-tokens`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(tokenForm),
      });
      if (!res.ok) throw new Error(await res.text());
      const data: APIToken = await res.json();
      if (data.raw_token) {
        setCreatedSecret(data.raw_token);
      }
      showToast("Service token minted successfully");
      fetchData();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Creation failed";
      showToast(msg, "err");
    }
  };

  const handleRevokeToken = async (id: number) => {
    if (!confirm("Immediately revoke this API token? It will cease working across all services.")) return;
    try {
      await fetch(`${API}/api-tokens/${id}`, { method: "DELETE" });
      showToast("API token revoked");
      fetchData();
    } catch {
      showToast("Failed to revoke token", "err");
    }
  };

  const roleColors: Record<string, string> = {
    SUPER_ADMIN: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    WAF_ADMIN: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    SECURITY_ENGINEER: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
    SOC_L2: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    SOC_L1: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    VIEWER: "bg-slate-500/10 text-slate-400 border-slate-500/20",
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
          <div className="p-2.5 rounded-xl bg-gradient-to-tr from-cyan-500/20 to-emerald-500/20 border border-cyan-500/30">
            <KeyRound className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
              Access Control & API Tokens
              <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">Pillar 6</span>
            </h1>
            <p className="text-sm text-muted-foreground">Multi-tenant RBAC permissions & cryptographic service account tokens</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button onClick={fetchData} className="p-2 rounded-xl border border-border bg-secondary/50 text-muted-foreground hover:text-foreground">
            <RefreshCw className="w-4 h-4" />
          </button>
          {tab === "users" ? (
            <button
              onClick={() => setShowUserModal(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium bg-emerald-500 text-black font-semibold hover:bg-emerald-400 transition"
            >
              <Plus className="w-4 h-4" /> Add User
            </button>
          ) : (
            <button
              onClick={() => { setShowTokenModal(true); setCreatedSecret(null); }}
              className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium bg-cyan-500 text-black font-semibold hover:bg-cyan-400 transition"
            >
              <Sparkles className="w-4 h-4" /> Generate Token
            </button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-border gap-6">
        <button
          onClick={() => setTab("users")}
          className={`pb-3 text-sm font-medium flex items-center gap-2 border-b-2 transition ${
            tab === "users" ? "border-emerald-400 text-emerald-400" : "border-transparent text-muted-foreground hover:text-foreground"
          }`}
        >
          <Users className="w-4 h-4" /> System Users & RBAC Roles ({users.length})
        </button>
        <button
          onClick={() => setTab("tokens")}
          className={`pb-3 text-sm font-medium flex items-center gap-2 border-b-2 transition ${
            tab === "tokens" ? "border-cyan-400 text-cyan-400" : "border-transparent text-muted-foreground hover:text-foreground"
          }`}
        >
          <KeyRound className="w-4 h-4" /> Service Tokens ({tokens.length})
        </button>
      </div>

      {/* Users Tab */}
      {tab === "users" && (
        <div className="glass rounded-2xl border border-border overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-secondary/40 text-muted-foreground text-xs uppercase tracking-wider border-b border-border">
                <tr>
                  <th className="px-6 py-4">User</th>
                  <th className="px-6 py-4">Department</th>
                  <th className="px-6 py-4">Assigned Role</th>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4">Created</th>
                  <th className="px-6 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/50">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-secondary/20 transition">
                    <td className="px-6 py-4">
                      <div className="font-semibold text-foreground flex items-center gap-2">
                        <UserCheck className="w-4 h-4 text-emerald-400" />
                        {u.username}
                      </div>
                      <div className="text-xs text-muted-foreground">{u.email}</div>
                    </td>
                    <td className="px-6 py-4 text-muted-foreground">{u.department || "Enterprise SecOps"}</td>
                    <td className="px-6 py-4">
                      <span className={`inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-semibold border ${roleColors[u.role] || roleColors.VIEWER}`}>
                        {u.role}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400">
                        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" /> Active
                      </span>
                    </td>
                    <td className="px-6 py-4 text-xs text-muted-foreground">{new Date(u.created_at).toLocaleDateString()}</td>
                    <td className="px-6 py-4 text-right">
                      {u.role !== "SUPER_ADMIN" && (
                        <button
                          onClick={() => handleDeleteUser(u.id)}
                          className="p-1.5 rounded-lg text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {users.length === 0 && !loading && (
                  <tr>
                    <td colSpan={6} className="px-6 py-8 text-center text-muted-foreground">No users registered yet.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tokens Tab */}
      {tab === "tokens" && (
        <div className="space-y-6">
          {createdSecret && (
            <div className="p-5 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-200 space-y-3">
              <div className="flex items-center gap-2 font-bold text-base text-cyan-300">
                <ShieldCheck className="w-5 h-5 text-cyan-400" /> API Token Generated Successfully!
              </div>
              <p className="text-xs text-cyan-200/80">
                Copy this raw secret now. For security purposes, this secret key will never be shown again:
              </p>
              <div className="flex items-center gap-3 bg-black/50 p-3 rounded-xl border border-cyan-500/20 font-mono text-sm">
                <span className="flex-1 break-all text-emerald-300 select-all">{createdSecret}</span>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(createdSecret);
                    showToast("Token copied to clipboard");
                  }}
                  className="px-3 py-1.5 rounded-lg bg-cyan-500 text-black font-semibold text-xs flex items-center gap-1 hover:bg-cyan-400"
                >
                  <Copy className="w-3.5 h-3.5" /> Copy
                </button>
              </div>
            </div>
          )}

          <div className="glass rounded-2xl border border-border overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="bg-secondary/40 text-muted-foreground text-xs uppercase tracking-wider border-b border-border">
                  <tr>
                    <th className="px-6 py-4">Token Name</th>
                    <th className="px-6 py-4">Key Prefix</th>
                    <th className="px-6 py-4">Authorized Scopes</th>
                    <th className="px-6 py-4">Created By</th>
                    <th className="px-6 py-4">Status</th>
                    <th className="px-6 py-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50">
                  {tokens.map((t) => (
                    <tr key={t.id} className="hover:bg-secondary/20 transition">
                      <td className="px-6 py-4 font-semibold text-foreground">{t.name}</td>
                      <td className="px-6 py-4 font-mono text-xs text-cyan-400">{t.token_prefix}</td>
                      <td className="px-6 py-4">
                        <div className="flex flex-wrap gap-1">
                          {t.scopes.split(",").map((s) => (
                            <span key={s} className="px-2 py-0.5 rounded text-[11px] bg-secondary text-foreground border border-border">
                              {s.trim()}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-6 py-4 text-xs text-muted-foreground">{t.created_by}</td>
                      <td className="px-6 py-4">
                        {t.is_revoked ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-red-500/10 text-red-400 border border-red-500/20">
                            Revoked
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            Active
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-right">
                        {!t.is_revoked && (
                          <button
                            onClick={() => handleRevokeToken(t.id)}
                            className="px-3 py-1 rounded-lg text-xs font-semibold bg-red-500/10 text-red-400 hover:bg-red-500 hover:text-white transition"
                          >
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                  {tokens.length === 0 && !loading && (
                    <tr>
                      <td colSpan={6} className="px-6 py-8 text-center text-muted-foreground">No API tokens configured.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* User Modal */}
      {showUserModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass rounded-2xl border border-border w-full max-w-md p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold text-foreground">Add New User</h2>
              <button onClick={() => setShowUserModal(false)} className="text-muted-foreground hover:text-foreground">✕</button>
            </div>
            <form onSubmit={handleCreateUser} className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-muted-foreground uppercase">Username</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. bobby_soc"
                  value={userForm.username}
                  onChange={(e) => setUserForm({ ...userForm, username: e.target.value })}
                  className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 text-sm focus:outline-none focus:border-emerald-400"
                />
              </div>
              <div>
                <label className="text-xs font-semibold text-muted-foreground uppercase">Email Address</label>
                <input
                  type="email"
                  required
                  placeholder="e.g. user@telkomsel.co.id"
                  value={userForm.email}
                  onChange={(e) => setUserForm({ ...userForm, email: e.target.value })}
                  className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 text-sm focus:outline-none focus:border-emerald-400"
                />
              </div>
              <div>
                <label className="text-xs font-semibold text-muted-foreground uppercase">Department</label>
                <input
                  type="text"
                  placeholder="e.g. IT Security Operations"
                  value={userForm.department}
                  onChange={(e) => setUserForm({ ...userForm, department: e.target.value })}
                  className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 text-sm focus:outline-none focus:border-emerald-400"
                />
              </div>
              <div>
                <label className="text-xs font-semibold text-muted-foreground uppercase">Role Permission</label>
                <select
                  value={userForm.role}
                  onChange={(e) => setUserForm({ ...userForm, role: e.target.value })}
                  className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 text-sm focus:outline-none focus:border-emerald-400"
                >
                  <option value="SUPER_ADMIN">SUPER_ADMIN (Full Platform Authority)</option>
                  <option value="WAF_ADMIN">WAF_ADMIN (Policies & Tuning)</option>
                  <option value="SECURITY_ENGINEER">SECURITY_ENGINEER (Rules & Inspections)</option>
                  <option value="SOC_L2">SOC_L2 (Incident Response & Mitigations)</option>
                  <option value="SOC_L1">SOC_L1 (Monitoring & Triage)</option>
                  <option value="VIEWER">VIEWER (Read-Only Access)</option>
                </select>
              </div>
              <div className="flex justify-end gap-3 pt-4 border-t border-border">
                <button
                  type="button"
                  onClick={() => setShowUserModal(false)}
                  className="px-4 py-2 rounded-xl text-sm border border-border text-muted-foreground hover:text-foreground"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 rounded-xl text-sm font-semibold bg-emerald-500 text-black hover:bg-emerald-400"
                >
                  Create User
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Token Modal */}
      {showTokenModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass rounded-2xl border border-border w-full max-w-md p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold text-foreground">Mint API / Service Token</h2>
              <button onClick={() => setShowTokenModal(false)} className="text-muted-foreground hover:text-foreground">✕</button>
            </div>
            <form onSubmit={handleCreateToken} className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-muted-foreground uppercase">Token Name / Client ID</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. CI/CD WAF Deployment Pipeline"
                  value={tokenForm.name}
                  onChange={(e) => setTokenForm({ ...tokenForm, name: e.target.value })}
                  className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 text-sm focus:outline-none focus:border-cyan-400"
                />
              </div>
              <div>
                <label className="text-xs font-semibold text-muted-foreground uppercase">Scopes (Comma separated)</label>
                <input
                  type="text"
                  value={tokenForm.scopes}
                  onChange={(e) => setTokenForm({ ...tokenForm, scopes: e.target.value })}
                  className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 text-sm focus:outline-none focus:border-cyan-400"
                />
                <p className="text-[11px] text-muted-foreground mt-1">Available: read:events, write:rules, admin:all, audit:export</p>
              </div>
              <div>
                <label className="text-xs font-semibold text-muted-foreground uppercase">Validity Period (Days)</label>
                <input
                  type="number"
                  value={tokenForm.expires_in_days}
                  onChange={(e) => setTokenForm({ ...tokenForm, expires_in_days: parseInt(e.target.value) || 30 })}
                  className="w-full mt-1.5 p-2.5 rounded-xl border border-border bg-secondary/50 text-sm focus:outline-none focus:border-cyan-400"
                />
              </div>
              <div className="flex justify-end gap-3 pt-4 border-t border-border">
                <button
                  type="button"
                  onClick={() => setShowTokenModal(false)}
                  className="px-4 py-2 rounded-xl text-sm border border-border text-muted-foreground hover:text-foreground"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 rounded-xl text-sm font-semibold bg-cyan-500 text-black hover:bg-cyan-400"
                >
                  Generate Secret
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

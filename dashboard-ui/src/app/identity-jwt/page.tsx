"use client";

import { useState, useEffect } from "react";
import { 
  Fingerprint, 
  KeyRound, 
  Plus, 
  RefreshCw, 
  Trash2, 
  CheckCircle2, 
  AlertTriangle, 
  Lock, 
  ShieldAlert, 
  ShieldCheck,
  Cpu
} from "lucide-react";

interface IdentityPolicy {
  id: number;
  app_id: number;
  role: string;
  restricted_path: string;
  action: string;
  is_enabled: boolean;
  created_at: string;
}

interface JWTPolicy {
  id: number;
  app_id: number;
  issuer: string;
  expected_audience: string;
  allowed_algorithms: string;
  enforce_expiry: boolean;
  action: string;
  is_enabled: boolean;
  created_at: string;
}

export default function IdentityJWTPage() {
  const [activeTab, setActiveTab] = useState<"identity" | "jwt">("identity");
  const [identityPolicies, setIdentityPolicies] = useState<IdentityPolicy[]>([]);
  const [jwtPolicies, setJwtPolicies] = useState<JWTPolicy[]>([]);
  const [loading, setLoading] = useState(true);

  // Identity Form
  const [showIdentityModal, setShowIdentityModal] = useState(false);
  const [role, setRole] = useState("CUSTOMER");
  const [restrictedPath, setRestrictedPath] = useState("");
  const [identityAction, setIdentityAction] = useState("BLOCK");

  // JWT Form
  const [showJWTModal, setShowJWTModal] = useState(false);
  const [issuer, setIssuer] = useState("");
  const [expectedAudience, setExpectedAudience] = useState("");
  const [algorithms, setAlgorithms] = useState("RS256, ES256");
  const [enforceExpiry, setEnforceExpiry] = useState(true);
  const [jwtAction, setJwtAction] = useState("BLOCK");

  const [isSubmitting, setIsSubmitting] = useState(false);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [idRes, jwtRes] = await Promise.all([
        fetch("http://localhost:8082/api/v1/identity-policies"),
        fetch("http://localhost:8082/api/v1/jwt-policies"),
      ]);
      if (idRes.ok) setIdentityPolicies((await idRes.json()) || []);
      if (jwtRes.ok) setJwtPolicies((await jwtRes.json()) || []);
    } catch (err) {
      console.error("Failed to fetch identity/jwt policies", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleCreateIdentity = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setIsSubmitting(true);
      const res = await fetch("http://localhost:8082/api/v1/identity-policies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          app_id: 1,
          role,
          restricted_path: restrictedPath,
          action: identityAction,
        }),
      });
      if (res.ok) {
        setShowIdentityModal(false);
        setRestrictedPath("");
        await fetchData();
      }
    } catch (err) {
      console.error("Error creating identity policy", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteIdentity = async (id: number) => {
    try {
      const res = await fetch(`http://localhost:8082/api/v1/identity-policies/${id}`, { method: "DELETE" });
      if (res.ok) {
        setIdentityPolicies(identityPolicies.filter(p => p.id !== id));
      }
    } catch (err) {
      console.error("Failed to delete identity policy", err);
    }
  };

  const handleCreateJWT = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setIsSubmitting(true);
      const res = await fetch("http://localhost:8082/api/v1/jwt-policies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          app_id: 1,
          issuer,
          expected_audience: expectedAudience,
          allowed_algorithms: algorithms,
          enforce_expiry: enforceExpiry,
          action: jwtAction,
        }),
      });
      if (res.ok) {
        setShowJWTModal(false);
        setIssuer("");
        setExpectedAudience("");
        await fetchData();
      }
    } catch (err) {
      console.error("Error creating JWT policy", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteJWT = async (id: number) => {
    try {
      const res = await fetch(`http://localhost:8082/api/v1/jwt-policies/${id}`, { method: "DELETE" });
      if (res.ok) {
        setJwtPolicies(jwtPolicies.filter(p => p.id !== id));
      }
    } catch (err) {
      console.error("Failed to delete JWT policy", err);
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-cyan-400 flex items-center gap-2">
            <Fingerprint className="w-6 h-6 text-emerald-400" />
            Pillar 2: Identity & Session Security (Phases 33, 34)
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Identity-aware access control mapping Gateway JWT claims to restricted routes, plus cryptographic JWT validation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchData}
            disabled={loading}
            className="p-2.5 rounded-lg border border-border bg-card/50 text-foreground hover:bg-card hover:text-emerald-400 transition-colors"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
          {activeTab === "identity" ? (
            <button
              onClick={() => setShowIdentityModal(true)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-black font-semibold text-sm shadow-lg shadow-emerald-500/20 transition-all"
            >
              <Plus className="w-4 h-4" />
              Add Identity Route Policy
            </button>
          ) : (
            <button
              onClick={() => setShowJWTModal(true)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-600 text-black font-semibold text-sm shadow-lg shadow-cyan-500/20 transition-all"
            >
              <Plus className="w-4 h-4" />
              Add JWT Validation Policy
            </button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-border gap-6">
        <button
          onClick={() => setActiveTab("identity")}
          className={`pb-3 text-sm font-semibold transition-colors relative ${
            activeTab === "identity" ? "text-emerald-400" : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Identity & Role Access Policies
          {activeTab === "identity" && (
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
          )}
        </button>

        <button
          onClick={() => setActiveTab("jwt")}
          className={`pb-3 text-sm font-semibold transition-colors relative ${
            activeTab === "jwt" ? "text-cyan-400" : "text-muted-foreground hover:text-foreground"
          }`}
        >
          JWT Token Cryptographic Security
          {activeTab === "jwt" && (
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.8)]" />
          )}
        </button>
      </div>

      {activeTab === "identity" ? (
        <div className="glass rounded-xl border border-border overflow-hidden">
          <div className="p-4 border-b border-border flex items-center justify-between">
            <h2 className="text-sm font-semibold text-foreground">Role-to-Route WAF Policies (Phase 33)</h2>
            <span className="text-xs text-muted-foreground">Consumes trusted claims from Envoy JWT filter</span>
          </div>

          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20 text-xs font-semibold uppercase text-muted-foreground">
                <th className="p-4">Target Role</th>
                <th className="p-4">Restricted Endpoint Pattern</th>
                <th className="p-4">Action</th>
                <th className="p-4">Status</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {identityPolicies.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-muted-foreground">
                    No identity route restrictions defined.
                  </td>
                </tr>
              ) : (
                identityPolicies.map((p) => (
                  <tr key={p.id} className="hover:bg-muted/10 transition-colors">
                    <td className="p-4 font-mono font-semibold text-emerald-400">{p.role}</td>
                    <td className="p-4 font-mono text-foreground">{p.restricted_path}</td>
                    <td className="p-4">
                      <span className="px-2 py-0.5 rounded text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                        {p.action}
                      </span>
                    </td>
                    <td className="p-4">
                      <span className="inline-flex items-center gap-1 text-xs text-emerald-400 font-medium">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Enforced
                      </span>
                    </td>
                    <td className="p-4 text-right">
                      <button
                        onClick={() => handleDeleteIdentity(p.id)}
                        className="p-1.5 rounded-lg border border-border text-muted-foreground hover:text-rose-400 hover:border-rose-500/20 transition-colors"
                        title="Delete Policy"
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
      ) : (
        <div className="glass rounded-xl border border-border overflow-hidden">
          <div className="p-4 border-b border-border flex items-center justify-between">
            <h2 className="text-sm font-semibold text-foreground">JWT Token Security & Claims Validation (Phase 34)</h2>
            <span className="text-xs text-muted-foreground">Tokens are never logged raw in telemetry</span>
          </div>

          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20 text-xs font-semibold uppercase text-muted-foreground">
                <th className="p-4">Issuer (iss)</th>
                <th className="p-4">Expected Audience (aud)</th>
                <th className="p-4">Allowed Algorithms</th>
                <th className="p-4">Expiry Strictness</th>
                <th className="p-4">Action</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {jwtPolicies.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-muted-foreground">
                    No JWT token validation profiles configured.
                  </td>
                </tr>
              ) : (
                jwtPolicies.map((p) => (
                  <tr key={p.id} className="hover:bg-muted/10 transition-colors">
                    <td className="p-4 font-mono font-medium text-foreground">{p.issuer}</td>
                    <td className="p-4 font-mono text-cyan-400">{p.expected_audience}</td>
                    <td className="p-4 font-mono text-xs text-muted-foreground">{p.allowed_algorithms}</td>
                    <td className="p-4">
                      {p.enforce_expiry ? (
                        <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Strict exp & nbf
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground">Permissive</span>
                      )}
                    </td>
                    <td className="p-4">
                      <span className="px-2 py-0.5 rounded text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                        {p.action}
                      </span>
                    </td>
                    <td className="p-4 text-right">
                      <button
                        onClick={() => handleDeleteJWT(p.id)}
                        className="p-1.5 rounded-lg border border-border text-muted-foreground hover:text-rose-400 hover:border-rose-500/20 transition-colors"
                        title="Delete Policy"
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
      )}

      {/* Modal: Identity Policy */}
      {showIdentityModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass border border-border rounded-xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-foreground">Add Identity Route Restriction</h3>
            <form onSubmit={handleCreateIdentity} className="space-y-4 pt-2">
              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Target Role</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. CUSTOMER, ANONYMOUS, PARTNER"
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Restricted Path Pattern</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. /api/admin or /internal/*"
                  value={restrictedPath}
                  onChange={(e) => setRestrictedPath(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Violation Action</label>
                <select
                  value={identityAction}
                  onChange={(e) => setIdentityAction(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-emerald-500"
                >
                  <option value="BLOCK">BLOCK (403 Forbidden)</option>
                  <option value="CHALLENGE">CHALLENGE</option>
                  <option value="ALERT">ALERT ONLY</option>
                </select>
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-border">
                <button
                  type="button"
                  onClick={() => setShowIdentityModal(false)}
                  className="px-4 py-2 rounded-lg text-sm text-muted-foreground hover:bg-secondary transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-black font-semibold text-sm transition-all"
                >
                  {isSubmitting ? "Creating..." : "Save Policy"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: JWT Policy */}
      {showJWTModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass border border-border rounded-xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-foreground">Add JWT Validation Policy</h3>
            <form onSubmit={handleCreateJWT} className="space-y-4 pt-2">
              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Issuer URL (iss)</label>
                <input
                  type="text"
                  required
                  placeholder="https://auth.telkomsel.co.id/oauth2"
                  value={issuer}
                  onChange={(e) => setIssuer(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Expected Audience (aud)</label>
                <input
                  type="text"
                  required
                  placeholder="telkomsel-api-gateway"
                  value={expectedAudience}
                  onChange={(e) => setExpectedAudience(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Allowed Algorithms</label>
                <input
                  type="text"
                  value={algorithms}
                  onChange={(e) => setAlgorithms(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="enforce_expiry"
                  checked={enforceExpiry}
                  onChange={(e) => setEnforceExpiry(e.target.checked)}
                  className="rounded border-border bg-secondary text-cyan-500 focus:ring-cyan-500"
                />
                <label htmlFor="enforce_expiry" className="text-xs text-muted-foreground font-medium">
                  Enforce Expiry (Reject expired or not-yet-valid tokens)
                </label>
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-border">
                <button
                  type="button"
                  onClick={() => setShowJWTModal(false)}
                  className="px-4 py-2 rounded-lg text-sm text-muted-foreground hover:bg-secondary transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-600 text-black font-semibold text-sm transition-all"
                >
                  {isSubmitting ? "Creating..." : "Save JWT Policy"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

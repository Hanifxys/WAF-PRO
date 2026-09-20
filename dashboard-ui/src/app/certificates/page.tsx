"use client";

import { useState, useEffect } from "react";
import { 
  BadgeCheck, 
  ShieldAlert, 
  Clock, 
  Plus, 
  Trash2, 
  Lock, 
  RefreshCw, 
  CheckCircle2, 
  AlertTriangle,
  FileCode,
  FileCheck,
  Radio
} from "lucide-react";
import { API } from "@/lib/api";

interface Certificate {
  id: number;
  domain: string;
  sans: string;
  issuer: string;
  valid_from: string;
  valid_to: string;
  days_until_expiry: number;
  status: string;
  tls_versions: string;
  mtls_enabled: boolean;
  cert_pem?: string;
  created_at: string;
}

export default function CertificatesPage() {
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Form State
  const [domain, setDomain] = useState("");
  const [sans, setSans] = useState("");
  const [issuer, setIssuer] = useState("Telkomsel Enterprise Sub-CA");
  const [tlsVersions, setTlsVersions] = useState("TLSv1.2, TLSv1.3");
  const [mtlsEnabled, setMtlsEnabled] = useState(false);
  const [certPem, setCertPem] = useState("");

  const fetchCertificates = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API}/api/v1/certificates`);
      if (res.ok) {
        const data = await res.json();
        setCerts(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      console.error("Failed to load certificates", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCertificates();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setIsSubmitting(true);
      const res = await fetch(`${API}/api/v1/certificates`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain: domain.trim(),
          sans: sans.trim(),
          issuer: issuer.trim(),
          tls_versions: tlsVersions,
          mtls_enabled: mtlsEnabled,
          cert_pem: certPem.trim()
        })
      });
      if (res.ok) {
        setShowModal(false);
        setDomain("");
        setSans("");
        setCertPem("");
        fetchCertificates();
      }
    } catch (err) {
      console.error("Failed to add certificate", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleToggleMTLS = async (id: number) => {
    try {
      const res = await fetch(`${API}/api/v1/certificates/${id}/toggle-mtls`, {
        method: "PUT"
      });
      if (res.ok) {
        fetchCertificates();
      }
    } catch (err) {
      console.error("Failed to toggle mTLS", err);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Are you sure you want to retire this TLS certificate? Edge TLS termination may be disrupted.")) return;
    try {
      const res = await fetch(`${API}/api/v1/certificates/${id}`, {
        method: "DELETE"
      });
      if (res.ok) {
        fetchCertificates();
      }
    } catch (err) {
      console.error("Failed to delete certificate", err);
    }
  };

  const activeCount = certs.filter(c => c.status === "VALID").length;
  const expiringSoonCount = certs.filter(c => c.status === "EXPIRING_SOON" || (c.days_until_expiry <= 30 && c.days_until_expiry >= 0)).length;
  const mtlsCount = certs.filter(c => c.mtls_enabled).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-5">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <BadgeCheck className="w-7 h-7 text-emerald-400" />
            TLS & SSL Certificate Lifecycle Manager
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Enterprise x509 certificate provisioning, automated expiration tracking, and Mutual TLS (mTLS) enforcement across Envoy ingress.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchCertificates}
            className="p-2.5 rounded-lg border border-border bg-secondary/50 hover:bg-secondary text-foreground transition-colors"
            title="Refresh Certificates"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin text-emerald-400" : ""}`} />
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-black font-semibold shadow-lg shadow-emerald-500/20 transition-all text-sm"
          >
            <Plus className="w-4 h-4 stroke-[3]" />
            Install Certificate
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl border border-border bg-card/60 backdrop-blur-sm relative overflow-hidden">
          <div className="flex justify-between items-start">
            <div className="space-y-1">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Total Managed</span>
              <h2 className="text-3xl font-bold text-foreground">{certs.length}</h2>
            </div>
            <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <FileCheck className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-muted-foreground flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> Active on Envoy edge
          </div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/60 backdrop-blur-sm relative overflow-hidden">
          <div className="flex justify-between items-start">
            <div className="space-y-1">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Healthy & Valid</span>
              <h2 className="text-3xl font-bold text-emerald-400">{activeCount}</h2>
            </div>
            <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <BadgeCheck className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-muted-foreground flex items-center gap-1.5">
            &gt; 30 days validity remaining
          </div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/60 backdrop-blur-sm relative overflow-hidden">
          <div className="flex justify-between items-start">
            <div className="space-y-1">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Expiring Soon</span>
              <h2 className={`text-3xl font-bold ${expiringSoonCount > 0 ? "text-amber-400" : "text-foreground"}`}>{expiringSoonCount}</h2>
            </div>
            <div className="p-2.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <Clock className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-muted-foreground flex items-center gap-1.5">
            {expiringSoonCount > 0 ? (
              <span className="text-amber-400 flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5" /> Renewal required</span>
            ) : "All certificates valid"}
          </div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/60 backdrop-blur-sm relative overflow-hidden">
          <div className="flex justify-between items-start">
            <div className="space-y-1">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">mTLS Enabled</span>
              <h2 className="text-3xl font-bold text-cyan-400">{mtlsCount}</h2>
            </div>
            <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <Lock className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-muted-foreground flex items-center gap-1.5">
            <Radio className="w-3.5 h-3.5 text-cyan-400" /> Client Cert Authentication
          </div>
        </div>
      </div>

      {/* Certificates Table */}
      <div className="rounded-xl border border-border bg-card/40 backdrop-blur-sm overflow-hidden">
        <div className="p-4 border-b border-border/60 flex items-center justify-between bg-card/60">
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-emerald-400" />
            <h3 className="font-semibold text-sm text-foreground">Active Ingress SSL / TLS Bindings</h3>
          </div>
          <span className="text-xs text-muted-foreground font-mono">x509 ASN.1 Parser</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-secondary/40 text-muted-foreground uppercase font-mono text-[11px] tracking-wider border-b border-border/40">
              <tr>
                <th className="py-3 px-4 font-semibold">Domain / Common Name</th>
                <th className="py-3 px-4 font-semibold">Subject Alt Names (SANs)</th>
                <th className="py-3 px-4 font-semibold">Issuer Authority</th>
                <th className="py-3 px-4 font-semibold">TLS Ciphers</th>
                <th className="py-3 px-4 font-semibold">Expiry / Days Left</th>
                <th className="py-3 px-4 font-semibold">mTLS Policy</th>
                <th className="py-3 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/30 font-sans">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-muted-foreground">
                    <RefreshCw className="w-6 h-6 animate-spin text-emerald-400 mx-auto mb-2" />
                    Querying TLS keyvault and certificates...
                  </td>
                </tr>
              ) : certs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-muted-foreground">
                    <ShieldAlert className="w-8 h-8 text-muted-foreground mx-auto mb-2 opacity-50" />
                    No TLS certificates registered. Click &quot;Install Certificate&quot; to import an x509 PEM.
                  </td>
                </tr>
              ) : (
                certs.map((c) => {
                  const isExpired = c.days_until_expiry < 0;
                  const isExpiring = c.days_until_expiry <= 30 && !isExpired;

                  return (
                    <tr key={c.id} className="hover:bg-secondary/20 transition-colors group">
                      <td className="py-3.5 px-4 font-semibold text-foreground">
                        <div className="flex items-center gap-2">
                          <BadgeCheck className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                          <span className="font-mono text-emerald-300">{c.domain}</span>
                        </div>
                      </td>
                      <td className="py-3.5 px-4 text-muted-foreground text-xs font-mono max-w-xs truncate">
                        {c.sans || "None"}
                      </td>
                      <td className="py-3.5 px-4 text-muted-foreground text-xs font-medium">
                        {c.issuer}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-xs text-foreground/80">
                        <span className="px-2 py-0.5 rounded bg-secondary/80 border border-border/50 text-[11px]">
                          {c.tls_versions}
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="flex flex-col gap-1">
                          <div className="flex items-center gap-1.5">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold font-mono ${
                              isExpired 
                                ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                                : isExpiring
                                ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                                : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                            }`}>
                              {isExpired ? "EXPIRED" : `${c.days_until_expiry} days left`}
                            </span>
                          </div>
                          <span className="text-[10px] text-muted-foreground font-mono">
                            Valid to {new Date(c.valid_to).toLocaleDateString()}
                          </span>
                        </div>
                      </td>
                      <td className="py-3.5 px-4">
                        <button
                          onClick={() => handleToggleMTLS(c.id)}
                          className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-semibold border transition-all ${
                            c.mtls_enabled
                              ? "bg-cyan-500/15 border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/25"
                              : "bg-secondary/40 border-border/60 text-muted-foreground hover:text-foreground"
                          }`}
                        >
                          <Lock className="w-3 h-3" />
                          {c.mtls_enabled ? "Enforced (mTLS)" : "Disabled"}
                        </button>
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => handleDelete(c.id)}
                          className="p-1.5 rounded-md hover:bg-rose-500/15 text-muted-foreground hover:text-rose-400 transition-colors"
                          title="Retire Certificate"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal: Install Certificate */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm">
          <div className="w-full max-w-xl rounded-2xl border border-border bg-card p-6 shadow-2xl relative animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between pb-4 border-b border-border/60">
              <div className="flex items-center gap-2 text-foreground font-bold text-lg">
                <BadgeCheck className="w-5 h-5 text-emerald-400" />
                Install New TLS Certificate
              </div>
              <button 
                onClick={() => setShowModal(false)}
                className="text-muted-foreground hover:text-foreground p-1 rounded-lg"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreate} className="space-y-4 pt-4">
              <div>
                <label className="block text-xs font-bold text-foreground uppercase tracking-wider mb-1.5">
                  Paste x509 Certificate PEM (Auto-detects SANs, Subject &amp; Validity)
                </label>
                <textarea
                  rows={5}
                  value={certPem}
                  onChange={(e) => setCertPem(e.target.value)}
                  placeholder="-----BEGIN CERTIFICATE-----&#10;MIIE...&#10;-----END CERTIFICATE-----"
                  className="w-full rounded-lg border border-border bg-background p-3 text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-emerald-400"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-foreground mb-1">
                    Primary Domain / FQDN
                  </label>
                  <input
                    type="text"
                    required
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    placeholder="*.telkomsel.co.id or api.internal"
                    className="w-full rounded-lg border border-border bg-background p-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-emerald-400"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-foreground mb-1">
                    Issuer Authority
                  </label>
                  <input
                    type="text"
                    value={issuer}
                    onChange={(e) => setIssuer(e.target.value)}
                    placeholder="DigiCert, Let's Encrypt, Sub-CA"
                    className="w-full rounded-lg border border-border bg-background p-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-emerald-400"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-foreground mb-1">
                  Subject Alternative Names (SANs, comma-separated)
                </label>
                <input
                  type="text"
                  value={sans}
                  onChange={(e) => setSans(e.target.value)}
                  placeholder="my.telkomsel.co.id, app.telkomsel.co.id"
                  className="w-full rounded-lg border border-border bg-background p-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-emerald-400"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-foreground mb-1">
                    Supported TLS Versions
                  </label>
                  <input
                    type="text"
                    value={tlsVersions}
                    onChange={(e) => setTlsVersions(e.target.value)}
                    placeholder="TLSv1.2, TLSv1.3"
                    className="w-full rounded-lg border border-border bg-background p-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-emerald-400"
                  />
                </div>

                <div className="flex items-center pt-6">
                  <label className="flex items-center gap-2 cursor-pointer text-sm font-medium text-foreground">
                    <input
                      type="checkbox"
                      checked={mtlsEnabled}
                      onChange={(e) => setMtlsEnabled(e.target.checked)}
                      className="w-4 h-4 rounded border-border text-emerald-500 focus:ring-emerald-400"
                    />
                    Require Mutual TLS (mTLS)
                  </label>
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-border/60">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 rounded-lg border border-border hover:bg-secondary text-sm font-medium transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-5 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-black font-semibold text-sm transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50"
                >
                  {isSubmitting ? "Provisioning..." : "Install & Bind Certificate"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}


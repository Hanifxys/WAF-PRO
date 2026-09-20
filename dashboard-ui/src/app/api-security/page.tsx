"use client";

import React, { useState, useEffect } from "react";
import { format } from "date-fns";
import {
  Network,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  Ban,
  CheckCircle2,
  AlertCircle,
  Search,
  Filter,
  Zap,
  PlusCircle,
  Eye,
  Layers
} from "lucide-react";
import { API } from "@/lib/api";

interface APIEndpoint {
  id: number;
  app_id: number;
  method: string;
  path_pattern: string;
  request_count: number;
  unique_clients: number;
  avg_latency_ms: number;
  status: "DISCOVERED" | "REVIEW_REQUIRED" | "APPROVED" | "BLOCKED" | "RESTRICTED";
  parameter_schema: string;
  waf_violations: number;
  last_seen: string;
}

export default function APISecurityPage() {
  const [endpoints, setEndpoints] = useState<APIEndpoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [filterQuery, setFilterQuery] = useState("");
  const [filterStatus, setFilterStatus] = useState("ALL");
  const [notification, setNotification] = useState<{ type: "success" | "error" | null; message: string }>({ type: null, message: "" });
  
  // New manual modal
  const [showModal, setShowModal] = useState(false);
  const [manualMethod, setManualMethod] = useState("GET");
  const [manualPath, setManualPath] = useState("");
  const [manualStatus, setManualStatus] = useState("APPROVED");


  const fetchEndpoints = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/api-inventory`);
      if (res.ok) {
        const data = await res.json();
        setEndpoints(data || []);
      }
    } catch (err) {
      console.error("Failed to fetch API inventory:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEndpoints();
  }, []);

  const handleUpdateStatus = async (id: number, nextStatus: string) => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/api-inventory/${id}/status`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: nextStatus }),
      });
      if (res.ok) {
        setNotification({
          type: "success",
          message: `Endpoint updated to ${nextStatus}. xDS Envoy policy compiled and synced!`,
        });
        fetchEndpoints();
      } else {
        setNotification({ type: "error", message: "Failed to update endpoint status." });
      }
    } catch (err) {
      setNotification({ type: "error", message: "Network error updating endpoint." });
    } finally {
      setActionLoading(false);
    }
  };

  const handleSyncEnforcement = async () => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/api-inventory/sync-enforcement`, {
        method: "POST",
      });
      if (res.ok) {
        setNotification({
          type: "success",
          message: "Real-time xDS snapshot pushed to Envoy. All BLOCKED endpoints enforced!",
        });
      }
    } catch (err) {
      setNotification({ type: "error", message: "Failed to sync xDS enforcement." });
    } finally {
      setActionLoading(false);
    }
  };

  const handleCreateEndpoint = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualPath.trim()) return;

    setActionLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/api-inventory`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          method: manualMethod,
          path_pattern: manualPath.trim(),
          status: manualStatus,
        }),
      });
      if (res.ok) {
        setNotification({
          type: "success",
          message: `Endpoint ${manualMethod} ${manualPath} registered as ${manualStatus}!`,
        });
        setManualPath("");
        setShowModal(false);
        fetchEndpoints();
      }
    } catch (err) {
      setNotification({ type: "error", message: "Failed to register endpoint." });
    } finally {
      setActionLoading(false);
    }
  };

  const filteredEndpoints = endpoints.filter((ep) => {
    const matchesQuery =
      ep.path_pattern.toLowerCase().includes(filterQuery.toLowerCase()) ||
      ep.method.toLowerCase().includes(filterQuery.toLowerCase());
    const matchesStatus = filterStatus === "ALL" || ep.status === filterStatus;
    return matchesQuery && matchesStatus;
  });

  const totalEndpoints = endpoints.length;
  const approvedCount = endpoints.filter((e) => e.status === "APPROVED").length;
  const blockedCount = endpoints.filter((e) => e.status === "BLOCKED").length;
  const discoveredCount = endpoints.filter((e) => e.status === "DISCOVERED").length;
  const totalViolations = endpoints.reduce((acc, e) => acc + (e.waf_violations || 0), 0);

  const getMethodBadge = (method: string) => {
    switch (method.toUpperCase()) {
      case "GET":
        return "bg-blue-500/10 text-blue-400 border-blue-500/20";
      case "POST":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
      case "PUT":
        return "bg-amber-500/10 text-amber-400 border-amber-500/20";
      case "DELETE":
        return "bg-rose-500/10 text-rose-400 border-rose-500/20";
      default:
        return "bg-purple-500/10 text-purple-400 border-purple-500/20";
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "APPROVED":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
      case "BLOCKED":
        return "bg-red-500/10 text-red-400 border-red-500/20";
      case "REVIEW_REQUIRED":
        return "bg-amber-500/10 text-amber-400 border-amber-500/20";
      case "DISCOVERED":
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
            <Network className="w-8 h-8 text-cyan-400" />
            <h1 className="text-3xl font-bold tracking-tight">API Discovery & Inventory</h1>
          </div>
          <p className="text-muted-foreground mt-1">
            Autonomous API endpoint learning, parameter telemetry, and zero-downtime allowlisting enforcement.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleSyncEnforcement}
            disabled={actionLoading}
            className="flex items-center gap-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white px-4 py-2 rounded-lg text-sm font-medium shadow-lg shadow-emerald-950/40 transition-all disabled:opacity-50"
          >
            <Zap className="w-4 h-4" />
            Sync xDS Policy
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-2 bg-secondary/80 hover:bg-secondary text-secondary-foreground border border-border px-3 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            <PlusCircle className="w-4 h-4 text-emerald-400" />
            Add Endpoint
          </button>
          <button
            onClick={fetchEndpoints}
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
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div className="glass-panel p-4 rounded-xl border border-border flex items-center gap-4">
          <div className="p-3 bg-cyan-500/10 rounded-lg text-cyan-400">
            <Layers className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-muted-foreground uppercase font-semibold">Total Learned</div>
            <div className="text-2xl font-bold">{totalEndpoints}</div>
          </div>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-border flex items-center gap-4">
          <div className="p-3 bg-emerald-500/10 rounded-lg text-emerald-400">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-muted-foreground uppercase font-semibold">Approved</div>
            <div className="text-2xl font-bold text-emerald-400">{approvedCount}</div>
          </div>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-border flex items-center gap-4">
          <div className="p-3 bg-rose-500/10 rounded-lg text-rose-400">
            <Ban className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-muted-foreground uppercase font-semibold">Blocked (xDS)</div>
            <div className="text-2xl font-bold text-rose-400">{blockedCount}</div>
          </div>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-border flex items-center gap-4">
          <div className="p-3 bg-amber-500/10 rounded-lg text-amber-400">
            <Eye className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-muted-foreground uppercase font-semibold">Discovered</div>
            <div className="text-2xl font-bold text-amber-400">{discoveredCount}</div>
          </div>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-border flex items-center gap-4">
          <div className="p-3 bg-red-500/10 rounded-lg text-red-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-muted-foreground uppercase font-semibold">Violations</div>
            <div className="text-2xl font-bold text-red-400">{totalViolations}</div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="glass-panel p-4 rounded-xl border border-border flex flex-col sm:flex-row gap-4 justify-between items-center">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Filter by path or method..."
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
            className="w-full bg-secondary/40 border border-border rounded-lg pl-9 pr-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
        </div>
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-4 h-4 text-muted-foreground" />
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="bg-secondary/40 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="DISCOVERED">Discovered</option>
            <option value="REVIEW_REQUIRED">Review Required</option>
            <option value="APPROVED">Approved (Allowlist)</option>
            <option value="BLOCKED">Blocked (xDS 403)</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="glass-panel rounded-xl overflow-hidden border border-border">
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-muted-foreground uppercase bg-secondary/50 border-b border-border">
              <tr>
                <th className="px-6 py-4 font-semibold tracking-wider">Method</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Endpoint Path Pattern</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Traffic Volume</th>
                <th className="px-6 py-4 font-semibold tracking-wider">WAF Violations</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Enforcement Status</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Last Activity</th>
                <th className="px-6 py-4 font-semibold tracking-wider text-right">Policy Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50">
              {loading && endpoints.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center text-muted-foreground">
                    Learning API traffic and compiling schema...
                  </td>
                </tr>
              ) : filteredEndpoints.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center text-muted-foreground">
                    No matching API endpoints recorded yet. Send live HTTP traffic to learn endpoints.
                  </td>
                </tr>
              ) : (
                filteredEndpoints.map((ep) => (
                  <tr key={ep.id} className="hover:bg-secondary/40 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2.5 py-1 rounded-md text-xs font-mono font-bold border ${getMethodBadge(ep.method)}`}>
                        {ep.method}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap font-mono text-sm text-foreground">
                      {ep.path_pattern}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap font-mono text-xs text-muted-foreground">
                      {ep.request_count.toLocaleString()} reqs
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {ep.waf_violations > 0 ? (
                        <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-red-500/10 text-red-400 border border-red-500/20">
                          {ep.waf_violations} blocked
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground">0 violations</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2.5 py-1 rounded-full text-xs font-semibold border ${getStatusBadge(ep.status)}`}>
                        {ep.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-xs text-muted-foreground">
                      {format(new Date(ep.last_seen), "MMM dd, HH:mm:ss")}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right space-x-2">
                      {ep.status !== "APPROVED" && (
                        <button
                          onClick={() => handleUpdateStatus(ep.id, "APPROVED")}
                          disabled={actionLoading}
                          title="Approve and allowlist this API endpoint"
                          className="px-2.5 py-1 rounded-md text-xs font-medium bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/20 transition-colors"
                        >
                          Approve
                        </button>
                      )}
                      {ep.status !== "BLOCKED" && (
                        <button
                          onClick={() => handleUpdateStatus(ep.id, "BLOCKED")}
                          disabled={actionLoading}
                          title="Block this API endpoint immediately via xDS"
                          className="px-2.5 py-1 rounded-md text-xs font-medium bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 border border-rose-500/20 transition-colors"
                        >
                          Block
                        </button>
                      )}
                      {ep.status !== "REVIEW_REQUIRED" && (
                        <button
                          onClick={() => handleUpdateStatus(ep.id, "REVIEW_REQUIRED")}
                          disabled={actionLoading}
                          title="Flag for security team review"
                          className="px-2.5 py-1 rounded-md text-xs font-medium bg-secondary text-muted-foreground hover:text-foreground border border-border transition-colors"
                        >
                          Review
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Manual Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-card border border-border p-6 rounded-xl max-w-md w-full space-y-4 shadow-2xl">
            <h3 className="text-lg font-bold">Add Pre-Approved / Blocked API Endpoint</h3>
            <form onSubmit={handleCreateEndpoint} className="space-y-3">
              <div>
                <label className="block text-xs text-muted-foreground mb-1">HTTP Method</label>
                <select
                  value={manualMethod}
                  onChange={(e) => setManualMethod(e.target.value)}
                  className="w-full bg-secondary border border-border rounded-lg p-2 text-sm"
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                  <option value="PATCH">PATCH</option>
                  <option value="ANY">ANY</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-muted-foreground mb-1">Endpoint Path Pattern</label>
                <input
                  type="text"
                  required
                  placeholder="/api/program-service/post"
                  value={manualPath}
                  onChange={(e) => setManualPath(e.target.value)}
                  className="w-full bg-secondary border border-border rounded-lg p-2 text-sm font-mono"
                />
              </div>
              <div>
                <label className="block text-xs text-muted-foreground mb-1">Initial Policy Status</label>
                <select
                  value={manualStatus}
                  onChange={(e) => setManualStatus(e.target.value)}
                  className="w-full bg-secondary border border-border rounded-lg p-2 text-sm"
                >
                  <option value="APPROVED">APPROVED (Allowlist)</option>
                  <option value="BLOCKED">BLOCKED (Deny 403 via xDS)</option>
                  <option value="REVIEW_REQUIRED">REVIEW REQUIRED</option>
                </select>
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
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium"
                >
                  Save & Compile
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}


"use client";

import React, { useState, useEffect } from "react";
import { format } from "date-fns";
import { Ban, Trash2, PlusCircle, RefreshCw, Shield, AlertCircle, CheckCircle2 } from "lucide-react";

interface BlockedIP {
  id: number;
  ip_address: string;
  reason: string;
  created_at: string;
}

export default function BlockedIPsPage() {
  const [blockedIPs, setBlockedIPs] = useState<BlockedIP[]>([]);
  const [loading, setLoading] = useState(true);
  const [newIP, setNewIP] = useState("");
  const [newReason, setNewReason] = useState("");
  const [actionLoading, setActionLoading] = useState(false);
  const [notification, setNotification] = useState<{ type: "success" | "error" | null; message: string }>({ type: null, message: "" });

  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8082";

  const fetchBlockedIPs = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/ip-block`);
      if (res.ok) {
        const data = await res.json();
        setBlockedIPs(data || []);
      }
    } catch (err) {
      console.error("Failed to fetch blocked IPs:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBlockedIPs();
  }, []);

  const handleAddIP = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIP.trim()) return;

    setActionLoading(true);
    setNotification({ type: null, message: "" });
    try {
      const res = await fetch(`${API}/api/v1/ip-block`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip_address: newIP.trim(), reason: newReason.trim() || "Manual block via SOC console" }),
      });

      if (res.ok) {
        setNotification({ type: "success", message: `IP ${newIP.trim()} successfully blocked and pushed to Envoy via xDS!` });
        setNewIP("");
        setNewReason("");
        fetchBlockedIPs();
      } else {
        setNotification({ type: "error", message: "Failed to block IP." });
      }
    } catch (err) {
      setNotification({ type: "error", message: "Network error occurred." });
    } finally {
      setActionLoading(false);
    }
  };

  const handleDeleteIP = async (ip: string) => {
    if (!confirm(`Are you sure you want to unblock IP ${ip}?`)) return;

    setActionLoading(true);
    setNotification({ type: null, message: "" });
    try {
      const res = await fetch(`${API}/api/v1/ip-block/${encodeURIComponent(ip)}`, {
        method: "DELETE",
      });

      if (res.ok) {
        setNotification({ type: "success", message: `IP ${ip} unblocked and active rule removed instantly via xDS!` });
        fetchBlockedIPs();
      } else {
        setNotification({ type: "error", message: `Failed to unblock IP ${ip}.` });
      }
    } catch (err) {
      setNotification({ type: "error", message: "Network error occurred." });
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Dynamic IP Denylist</h1>
          <p className="text-muted-foreground">
            Enforce real-time perimeter blocklists directly into Envoy xDS pipeline without downtime.
          </p>
        </div>
        <button
          onClick={fetchBlockedIPs}
          disabled={loading || actionLoading}
          className="flex items-center gap-2 bg-secondary/80 hover:bg-secondary text-secondary-foreground border border-border px-4 py-2 rounded-lg text-sm font-medium transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {notification.type && (
        <div className={`p-4 rounded-lg flex items-start gap-3 border ${
          notification.type === 'success' 
            ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' 
            : 'bg-red-500/10 border-red-500/20 text-red-400'
        }`}>
          {notification.type === 'success' ? (
            <CheckCircle2 className="w-5 h-5 shrink-0" />
          ) : (
            <AlertCircle className="w-5 h-5 shrink-0" />
          )}
          <p className="text-sm">{notification.message}</p>
        </div>
      )}

      {/* Manual Block Form */}
      <div className="glass-panel p-6 rounded-xl border border-border">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Ban className="w-5 h-5 text-red-400" />
          Block New IP / CIDR
        </h2>
        <form onSubmit={handleAddIP} className="grid grid-cols-1 sm:grid-cols-12 gap-4 items-end">
          <div className="sm:col-span-4">
            <label className="block text-xs font-medium text-muted-foreground mb-1">IP Address / Host</label>
            <input
              type="text"
              required
              placeholder="e.g. 192.168.1.100 or 10.0.0.5"
              value={newIP}
              onChange={(e) => setNewIP(e.target.value)}
              className="w-full bg-secondary/40 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-red-500 font-mono"
            />
          </div>
          <div className="sm:col-span-6">
            <label className="block text-xs font-medium text-muted-foreground mb-1">Reason / Incident ID</label>
            <input
              type="text"
              placeholder="e.g. SQL Injection attack from INC-1049"
              value={newReason}
              onChange={(e) => setNewReason(e.target.value)}
              className="w-full bg-secondary/40 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-red-500"
            />
          </div>
          <div className="sm:col-span-2">
            <button
              type="submit"
              disabled={actionLoading || !newIP.trim()}
              className="w-full flex items-center justify-center gap-2 bg-red-600 hover:bg-red-700 text-white font-medium py-2 px-4 rounded-lg text-sm transition-colors disabled:opacity-50"
            >
              <PlusCircle className="w-4 h-4" />
              Enforce Block
            </button>
          </div>
        </form>
      </div>

      {/* Blocked IP Table */}
      <div className="glass-panel rounded-xl overflow-hidden border border-border">
        <div className="p-4 bg-secondary/30 border-b border-border flex items-center justify-between">
          <span className="font-semibold text-sm">Active Blocked IP Entries ({blockedIPs.length})</span>
          <span className="text-xs text-muted-foreground flex items-center gap-1">
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
            Synchronized with Envoy ECDS
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-muted-foreground uppercase bg-secondary/50 border-b border-border">
              <tr>
                <th className="px-6 py-4 font-semibold tracking-wider">IP Address</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Reason</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Blocked At</th>
                <th className="px-6 py-4 font-semibold tracking-wider text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50">
              {loading && blockedIPs.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-6 py-12 text-center text-muted-foreground">
                    Loading blocked IPs...
                  </td>
                </tr>
              ) : blockedIPs.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-6 py-12 text-center text-muted-foreground">
                    No active blocked IP addresses.
                  </td>
                </tr>
              ) : (
                blockedIPs.map((item) => (
                  <tr key={item.id} className="hover:bg-secondary/40 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap font-mono font-medium text-red-400">
                      {item.ip_address}
                    </td>
                    <td className="px-6 py-4 text-muted-foreground text-sm">
                      {item.reason}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-muted-foreground text-xs">
                      {format(new Date(item.created_at), "MMM dd, yyyy HH:mm:ss")}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      <button
                        onClick={() => handleDeleteIP(item.ip_address)}
                        disabled={actionLoading}
                        title="Unblock IP"
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-md bg-secondary/60 hover:bg-red-500/20 hover:text-red-400 text-muted-foreground text-xs font-medium border border-border transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        Unblock
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

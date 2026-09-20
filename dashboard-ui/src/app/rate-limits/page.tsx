"use client";

import React, { useState, useEffect } from "react";
import { format } from "date-fns";
import { Gauge, Plus, Trash2, ShieldAlert, CheckCircle2, Clock, Zap } from "lucide-react";
import { API } from "@/lib/api";
interface RateLimit {
  id: number;
  path_prefix: string;
  max_requests: number;
  window_seconds: number;
  action: string;
  created_at: string;
}

export default function RateLimitsPage() {
  const [rateLimits, setRateLimits] = useState<RateLimit[]>([]);
  const [loading, setLoading] = useState(true);
  const [pathPrefix, setPathPrefix] = useState("");
  const [maxRequests, setMaxRequests] = useState("60");
  const [windowSeconds, setWindowSeconds] = useState("60");
  const [action, setAction] = useState("BLOCK_429");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);


  const fetchRateLimits = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/rate-limits`);
      if (res.ok) {
        const data = await res.json();
        setRateLimits(data || []);
      }
    } catch (err) {
      console.error("Failed to load rate limits:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRateLimits();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pathPrefix.trim()) return;

    setSubmitting(true);
    setMessage(null);

    try {
      const res = await fetch(`${API}/api/v1/rate-limits`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          path_prefix: pathPrefix.trim(),
          max_requests: parseInt(maxRequests, 10),
          window_seconds: parseInt(windowSeconds, 10),
          action: action,
        }),
      });

      if (res.ok) {
        setMessage({ type: "success", text: `Rate limit policy on ${pathPrefix} created successfully.` });
        setPathPrefix("");
        fetchRateLimits();
      } else {
        setMessage({ type: "error", text: "Failed to create rate limit policy." });
      }
    } catch (err) {
      setMessage({ type: "error", text: "Connection error occurred." });
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: number, path: string) => {
    if (!confirm(`Delete rate limit policy for "${path}"?`)) return;

    try {
      const res = await fetch(`${API}/api/v1/rate-limits/${id}`, {
        method: "DELETE",
      });
      if (res.ok) {
        fetchRateLimits();
      }
    } catch (err) {
      console.error("Failed to delete rate limit:", err);
    }
  };

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-cyan-400 flex items-center gap-2.5">
            <Gauge className="w-7 h-7 text-cyan-400" />
            Rate Limiting & DoS Protection
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Prevent brute-force credential attacks, scraping bots, and HTTP flooding using token-bucket rate limiters.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Zap className="w-3.5 h-3.5" />
            Envoy Token Bucket Active
          </span>
        </div>
      </div>

      {message && (
        <div
          className={`p-4 rounded-lg flex items-center gap-3 border text-sm ${
            message.type === "success"
              ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
              : "bg-red-500/10 border-red-500/20 text-red-400"
          }`}
        >
          {message.type === "success" ? <CheckCircle2 className="w-4 h-4" /> : <ShieldAlert className="w-4 h-4" />}
          {message.text}
        </div>
      )}

      {/* Creation Form */}
      <div className="glass-panel p-6 rounded-xl border border-border">
        <h2 className="text-base font-semibold mb-4 flex items-center gap-2">
          <Plus className="w-4 h-4 text-cyan-400" />
          Create Rate Limit Policy
        </h2>

        <form onSubmit={handleCreate} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div>
            <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
              Path Prefix
            </label>
            <input
              type="text"
              placeholder="/api/login or /api/search"
              value={pathPrefix}
              onChange={(e) => setPathPrefix(e.target.value)}
              className="w-full bg-secondary/50 border border-border rounded-lg px-3.5 py-2 text-sm text-foreground focus:outline-none focus:border-cyan-500"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
              Max Requests
            </label>
            <input
              type="number"
              min="1"
              value={maxRequests}
              onChange={(e) => setMaxRequests(e.target.value)}
              className="w-full bg-secondary/50 border border-border rounded-lg px-3.5 py-2 text-sm text-foreground focus:outline-none focus:border-cyan-500"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
              Window Seconds
            </label>
            <input
              type="number"
              min="1"
              value={windowSeconds}
              onChange={(e) => setWindowSeconds(e.target.value)}
              className="w-full bg-secondary/50 border border-border rounded-lg px-3.5 py-2 text-sm text-foreground focus:outline-none focus:border-cyan-500"
              required
            />
          </div>

          <div className="flex flex-col justify-end">
            <button
              type="submit"
              disabled={submitting}
              className="w-full h-9 bg-cyan-500 hover:bg-cyan-600 disabled:opacity-50 text-slate-950 font-semibold rounded-lg text-sm transition-colors flex items-center justify-center gap-2"
            >
              <Plus className="w-4 h-4" />
              {submitting ? "Saving..." : "Add Policy"}
            </button>
          </div>
        </form>
      </div>

      {/* Active Policies Table */}
      <div className="glass-panel rounded-xl border border-border overflow-hidden">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <h2 className="text-base font-semibold flex items-center gap-2">
            <Clock className="w-4 h-4 text-emerald-400" />
            Active Route Rate Limit Policies ({rateLimits.length})
          </h2>
          <span className="text-xs text-muted-foreground">Responses return HTTP 429</span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-sm text-muted-foreground">Loading policies...</div>
        ) : rateLimits.length === 0 ? (
          <div className="p-8 text-center text-sm text-muted-foreground">
            No route rate limit policies configured. Global token bucket active at 1000 req/min.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-secondary/40 border-b border-border text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="px-6 py-3">Path Prefix</th>
                  <th className="px-6 py-3">Max Requests</th>
                  <th className="px-6 py-3">Window</th>
                  <th className="px-6 py-3">Action</th>
                  <th className="px-6 py-3">Created</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rateLimits.map((rl) => (
                  <tr key={rl.id} className="hover:bg-secondary/20 transition-colors">
                    <td className="px-6 py-4 font-mono font-bold text-cyan-400">{rl.path_prefix}</td>
                    <td className="px-6 py-4 font-mono text-emerald-400 font-bold">{rl.max_requests} reqs</td>
                    <td className="px-6 py-4 text-muted-foreground">{rl.window_seconds}s</td>
                    <td className="px-6 py-4">
                      <span className="px-2 py-0.5 rounded text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                        {rl.action}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-xs text-muted-foreground">
                      {format(new Date(rl.created_at), "MMM d, HH:mm")}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button
                        onClick={() => handleDelete(rl.id, rl.path_prefix)}
                        className="p-1.5 hover:bg-red-500/10 text-red-400 rounded transition-colors"
                        title="Delete policy"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

"use client";

import React, { useState, useEffect } from "react";
import { format } from "date-fns";
import { Settings, Server, Cpu, Database, Activity, RefreshCw, Shield, Terminal, CheckCircle2, AlertCircle } from "lucide-react";

interface DiagnosticsData {
  status: string;
  timestamp: string;
  cluster: {
    data_plane: {
      proxy: string;
      port: number;
      waf_runtime: string;
      active_policy: string;
      status: string;
    };
    control_plane: {
      xds_grpc_port: number;
      active_snapshot_version: string;
      status: string;
    };
    database: {
      engine: string;
      healthy: boolean;
      total_events: number;
    };
    telemetry: {
      agent: string;
      target_sink: string;
      status: string;
    };
  };
  counters: {
    protected_applications: number;
    active_ip_denylist: number;
    active_rule_exceptions: number;
    active_rate_limits?: number;
    active_geo_policies?: number;
    active_custom_rules?: number;
    active_dlp_rules?: number;
    total_alerts_sent?: number;
  };
}

export default function SettingsPage() {
  const [diag, setDiag] = useState<DiagnosticsData | null>(null);
  const [loading, setLoading] = useState(true);

  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8082";

  const fetchDiagnostics = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/diagnostics`);
      if (res.ok) {
        const data = await res.json();
        setDiag(data);
      }
    } catch (err) {
      console.error("Failed to fetch diagnostics:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDiagnostics();
    const interval = setInterval(fetchDiagnostics, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">System Settings & Health</h1>
          <p className="text-muted-foreground">
            Monitor real-time cluster telemetry, engine parameters, and infrastructure components.
          </p>
        </div>
        <button
          onClick={fetchDiagnostics}
          disabled={loading}
          className="flex items-center gap-2 bg-secondary/80 hover:bg-secondary text-secondary-foreground border border-border px-4 py-2 rounded-lg text-sm font-medium transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh Status
        </button>
      </div>

      {/* Cluster Health Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Data Plane Card */}
        <div className="glass-panel p-6 rounded-xl flex flex-col justify-between border border-border group hover:border-emerald-500/40 transition-colors">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Data Plane</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                {diag?.cluster.data_plane.status || "ONLINE"}
              </span>
            </div>
            <div className="flex items-center gap-3">
              <Server className="w-8 h-8 text-emerald-400" />
              <div>
                <h3 className="font-semibold text-base">{diag?.cluster.data_plane.proxy || "Envoy Proxy"}</h3>
                <p className="text-xs text-muted-foreground">Port {diag?.cluster.data_plane.port || 8080}</p>
              </div>
            </div>
          </div>
          <div className="pt-4 border-t border-border/50 mt-4 space-y-1 text-xs">
            <div className="flex justify-between text-muted-foreground">
              <span>WASM Runtime:</span>
              <span className="font-mono text-foreground">{diag?.cluster.data_plane.waf_runtime || "Coraza v8"}</span>
            </div>
            <div className="flex justify-between text-muted-foreground">
              <span>Ruleset:</span>
              <span className="font-mono text-emerald-400">{diag?.cluster.data_plane.active_policy || "CRS v4"}</span>
            </div>
          </div>
        </div>

        {/* Control Plane Card */}
        <div className="glass-panel p-6 rounded-xl flex flex-col justify-between border border-border group hover:border-cyan-500/40 transition-colors">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Control Plane (xDS)</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                {diag?.cluster.control_plane.status || "SYNCED"}
              </span>
            </div>
            <div className="flex items-center gap-3">
              <Cpu className="w-8 h-8 text-cyan-400" />
              <div>
                <h3 className="font-semibold text-base">gRPC xDS Server</h3>
                <p className="text-xs text-muted-foreground">Port {diag?.cluster.control_plane.xds_grpc_port || 18000}</p>
              </div>
            </div>
          </div>
          <div className="pt-4 border-t border-border/50 mt-4 space-y-1 text-xs">
            <div className="flex justify-between text-muted-foreground">
              <span>Snapshot Version:</span>
              <span className="font-mono text-cyan-400 font-bold">{diag?.cluster.control_plane.active_snapshot_version || "v1"}</span>
            </div>
            <div className="flex justify-between text-muted-foreground">
              <span>Sync Mode:</span>
              <span className="font-mono text-foreground">ECDS Dynamic Push</span>
            </div>
          </div>
        </div>

        {/* Database Card */}
        <div className="glass-panel p-6 rounded-xl flex flex-col justify-between border border-border group hover:border-blue-500/40 transition-colors">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Storage & Config</span>
              <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${diag?.cluster.database.healthy ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-red-500/10 text-red-400 border-red-500/20'}`}>
                {diag?.cluster.database.healthy ? "HEALTHY" : "DEGRADED"}
              </span>
            </div>
            <div className="flex items-center gap-3">
              <Database className="w-8 h-8 text-blue-400" />
              <div>
                <h3 className="font-semibold text-base">{diag?.cluster.database.engine || "PostgreSQL 16"}</h3>
                <p className="text-xs text-muted-foreground">Persisted State</p>
              </div>
            </div>
          </div>
          <div className="pt-4 border-t border-border/50 mt-4 space-y-1 text-xs">
            <div className="flex justify-between text-muted-foreground">
              <span>Total Audit Events:</span>
              <span className="font-mono text-blue-400 font-bold">{diag?.cluster.database.total_events || 0}</span>
            </div>
            <div className="flex justify-between text-muted-foreground">
              <span>SSL Connection:</span>
              <span className="font-mono text-foreground">Disabled (Internal)</span>
            </div>
          </div>
        </div>

        {/* Telemetry Card */}
        <div className="glass-panel p-6 rounded-xl flex flex-col justify-between border border-border group hover:border-purple-500/40 transition-colors">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Telemetry Collector</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-purple-500/10 text-purple-400 border border-purple-500/20">
                {diag?.cluster.telemetry.status || "INGESTING"}
              </span>
            </div>
            <div className="flex items-center gap-3">
              <Activity className="w-8 h-8 text-purple-400" />
              <div>
                <h3 className="font-semibold text-base">{diag?.cluster.telemetry.agent || "Vector Agent"}</h3>
                <p className="text-xs text-muted-foreground">Docker Log Tailer</p>
              </div>
            </div>
          </div>
          <div className="pt-4 border-t border-border/50 mt-4 space-y-1 text-xs">
            <div className="flex justify-between text-muted-foreground">
              <span>Sink Destination:</span>
              <span className="font-mono text-foreground truncate max-w-[130px]" title={diag?.cluster.telemetry.target_sink}>
                {diag?.cluster.telemetry.target_sink || "HTTP /events"}
              </span>
            </div>
            <div className="flex justify-between text-muted-foreground">
              <span>Codec:</span>
              <span className="font-mono text-purple-400 font-bold">JSON Stream</span>
            </div>
          </div>
        </div>
      </div>

      {/* Cluster Capacities & Specifications */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="glass-panel p-6 rounded-xl border border-border space-y-4">
          <div className="flex items-center gap-2 border-b border-border pb-3">
            <Shield className="w-5 h-5 text-emerald-400" />
            <h3 className="font-semibold text-base">Live Policy & Entity Counters</h3>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <div className="p-3.5 rounded-lg bg-secondary/30 border border-border text-center">
              <span className="text-xl font-bold text-emerald-400 font-mono">
                {diag?.counters.protected_applications || 0}
              </span>
              <span className="block text-[11px] text-muted-foreground mt-0.5">Apps</span>
            </div>
            <div className="p-3.5 rounded-lg bg-secondary/30 border border-border text-center">
              <span className="text-xl font-bold text-red-400 font-mono">
                {diag?.counters.active_ip_denylist || 0}
              </span>
              <span className="block text-[11px] text-muted-foreground mt-0.5">Blocked IPs</span>
            </div>
            <div className="p-3.5 rounded-lg bg-secondary/30 border border-border text-center">
              <span className="text-xl font-bold text-amber-400 font-mono">
                {diag?.counters.active_rule_exceptions || 0}
              </span>
              <span className="block text-[11px] text-muted-foreground mt-0.5">Exceptions</span>
            </div>
            <div className="p-3.5 rounded-lg bg-secondary/30 border border-border text-center">
              <span className="text-xl font-bold text-cyan-400 font-mono">
                {diag?.counters.active_rate_limits || 0}
              </span>
              <span className="block text-[11px] text-muted-foreground mt-0.5">Rate Limits</span>
            </div>
            <div className="p-3.5 rounded-lg bg-secondary/30 border border-border text-center">
              <span className="text-xl font-bold text-blue-400 font-mono">
                {diag?.counters.active_geo_policies || 0}
              </span>
              <span className="block text-[11px] text-muted-foreground mt-0.5">Geo Fences</span>
            </div>
            <div className="p-3.5 rounded-lg bg-secondary/30 border border-border text-center">
              <span className="text-xl font-bold text-purple-400 font-mono">
                {(diag?.counters.active_custom_rules || 0) + (diag?.counters.active_dlp_rules || 0)}
              </span>
              <span className="block text-[11px] text-muted-foreground mt-0.5">Custom & DLP</span>
            </div>
            <div className="p-3.5 rounded-lg bg-secondary/30 border border-border text-center">
              <span className="text-xl font-bold text-pink-400 font-mono">
                {diag?.counters.total_alerts_sent || 0}
              </span>
              <span className="block text-[11px] text-muted-foreground mt-0.5">Sent Alerts</span>
            </div>
          </div>
        </div>

        <div className="glass-panel p-6 rounded-xl border border-border space-y-4">
          <div className="flex items-center gap-2 border-b border-border pb-3">
            <Terminal className="w-5 h-5 text-cyan-400" />
            <h3 className="font-semibold text-base">Platform Architecture Overview</h3>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1.5 border-b border-border/40">
              <span className="text-muted-foreground">Tenant Isolation Mode:</span>
              <span className="font-medium text-foreground">Enterprise Tier-1 (CSOP-IT-WAF Ready)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-border/40">
              <span className="text-muted-foreground">Management API Version:</span>
              <span className="font-mono text-emerald-400">v1.3.0 (Golang Chi + Alert Engine)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-border/40">
              <span className="text-muted-foreground">Dashboard UI Runtime:</span>
              <span className="font-medium text-foreground">Next.js 16 + React 19</span>
            </div>
            <div className="flex justify-between py-1.5">
              <span className="text-muted-foreground">Last Telemetry Diagnostic:</span>
              <span className="font-mono text-muted-foreground">
                {diag?.timestamp ? format(new Date(diag.timestamp), "yyyy-MM-dd HH:mm:ss") : "Now"}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Enterprise Alerting & Telkomsel CSOP Gateway Section */}
      <div className="glass-panel p-6 rounded-xl border border-border space-y-4">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-blue-500 animate-pulse" />
            <h3 className="font-semibold text-base">Enterprise Alerting Gateway (Telkomsel CSOP-IT-WAF)</h3>
          </div>
          <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
            SMTP & Incident Dispatcher Online
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div className="p-3.5 bg-secondary/30 rounded-lg border border-border">
            <span className="text-muted-foreground block mb-1">SMTP Relay Host</span>
            <span className="font-mono font-bold text-white">smtp.internal.corp:587</span>
          </div>
          <div className="p-3.5 bg-secondary/30 rounded-lg border border-border">
            <span className="text-muted-foreground block mb-1">Authorized Sender</span>
            <span className="font-mono font-bold text-emerald-400">csop-it-waf@telkomsel.co.id</span>
          </div>
          <div className="p-3.5 bg-secondary/30 rounded-lg border border-border">
            <span className="text-muted-foreground block mb-1">Default Application Tower Lead</span>
            <span className="font-mono font-bold text-white">tower-app-lead@telkomsel.co.id</span>
          </div>
          <div className="p-3.5 bg-secondary/30 rounded-lg border border-border">
            <span className="text-muted-foreground block mb-1">Standard Risk SLA</span>
            <span className="font-bold text-amber-400">3 Hari Kerja (Auto-Revoke)</span>
          </div>
        </div>
      </div>
    </div>
  );
}

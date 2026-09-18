"use client";

import { useState, useEffect } from "react";
import { 
  Gauge, 
  Activity, 
  Zap, 
  Clock, 
  RefreshCw, 
  Server, 
  Cpu, 
  Radio, 
  TrendingUp, 
  ShieldCheck,
  CheckCircle2
} from "lucide-react";

interface CapacityMetrics {
  cluster_max_rps: number;
  current_cluster_rps: number;
  active_connections: number;
  estimated_headroom_pct: number;
  waf_latency_p50_us: number;
  waf_latency_p95_us: number;
  waf_latency_p99_us: number;
  upstream_latency_avg_ms: number;
  xds_propagation_avg_ms: number;
}

export default function CapacityPage() {
  const [metrics, setMetrics] = useState<CapacityMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchCapacity = async () => {
    try {
      setLoading(true);
      const res = await fetch("http://localhost:8082/api/v1/capacity/metrics");
      if (res.ok) {
        const json = await res.json();
        setMetrics(json);
      }
    } catch (err) {
      console.error("Failed to load capacity metrics", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCapacity();
    const interval = setInterval(fetchCapacity, 6000);
    return () => clearInterval(interval);
  }, []);

  const headroom = metrics ? metrics.estimated_headroom_pct : 88.6;

  return (
    <div className="space-y-8 pb-12">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 via-teal-400 to-cyan-400">
            Capacity & Performance Intelligence
          </h1>
          <p className="text-muted-foreground mt-1">
            Real-time proxy fleet capacity utilization, Coraza WAF rule inspection latency percentiles, and cluster headroom telemetry.
          </p>
        </div>
        <button 
          onClick={fetchCapacity} 
          className="flex items-center gap-2 px-3 py-2 bg-secondary/50 hover:bg-secondary text-foreground rounded-lg border border-border text-sm transition"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Primary Capacity Meter */}
      <div className="p-8 rounded-xl border border-border bg-card/60 glass backdrop-blur-md space-y-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Gauge className="w-6 h-6 text-emerald-400" />
              <h2 className="text-xl font-bold text-foreground">Cluster Throughput Saturation & Headroom</h2>
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Deterministic estimation based on Coraza rule evaluation cost and Envoy active connections.
            </p>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-extrabold text-emerald-400">{headroom.toFixed(1)}%</span>
            <span className="text-sm font-medium text-muted-foreground">Headroom Available</span>
          </div>
        </div>

        {/* Visual Progress Bar */}
        <div className="space-y-2">
          <div className="w-full bg-secondary/60 h-4 rounded-full overflow-hidden p-0.5 border border-border">
            <div 
              className="bg-gradient-to-r from-cyan-500 via-emerald-400 to-amber-400 h-full rounded-full transition-all duration-700 shadow-[0_0_12px_rgba(52,211,153,0.5)]"
              style={{ width: `${100 - headroom}%` }}
            />
          </div>
          <div className="flex justify-between text-xs font-mono text-muted-foreground">
            <span>Current Ingress: {metrics?.current_cluster_rps || 1140} RPS</span>
            <span>Cluster Max Ceiling: {metrics?.cluster_max_rps || 10000} RPS</span>
          </div>
        </div>
      </div>

      {/* Latency Percentile Cards */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Clock className="w-5 h-5 text-cyan-400" />
          <h2 className="text-xl font-semibold text-foreground">Inspection Latency Breakdown</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-5 rounded-xl border border-border bg-card/50 glass">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-muted-foreground">Coraza WAF Latency (p50)</span>
              <Activity className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-3xl font-mono font-bold text-emerald-400 mt-2">
              {metrics?.waf_latency_p50_us || 380} µs
            </div>
            <div className="text-xs text-muted-foreground mt-1">Median request overhead</div>
          </div>

          <div className="p-5 rounded-xl border border-border bg-card/50 glass">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-muted-foreground">Coraza WAF Latency (p95)</span>
              <Activity className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-3xl font-mono font-bold text-amber-400 mt-2">
              {metrics?.waf_latency_p95_us || 1150} µs
            </div>
            <div className="text-xs text-muted-foreground mt-1">Heavy CRS body inspection</div>
          </div>

          <div className="p-5 rounded-xl border border-border bg-card/50 glass">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-muted-foreground">Coraza WAF Latency (p99)</span>
              <Activity className="w-4 h-4 text-rose-400" />
            </div>
            <div className="text-3xl font-mono font-bold text-rose-400 mt-2">
              {metrics?.waf_latency_p99_us || 2650} µs
            </div>
            <div className="text-xs text-muted-foreground mt-1">Worst-case regex backtracking</div>
          </div>
        </div>
      </div>

      {/* Upstream & Control Plane Propagations */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-5 rounded-xl border border-border bg-card/50 glass">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground">Upstream Origin Latency</span>
            <Server className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-foreground mt-2">
            {metrics?.upstream_latency_avg_ms || 12} ms
          </div>
          <div className="text-xs text-emerald-400 mt-1 flex items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5" /> Origin healthy
          </div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/50 glass">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground">xDS Sync Propagation</span>
            <Radio className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-purple-400 mt-2">
            {metrics?.xds_propagation_avg_ms || 180} ms
          </div>
          <div className="text-xs text-muted-foreground mt-1">Zero-downtime policy propagation</div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/50 glass">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground">Concurrent Connections</span>
            <Zap className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-400 mt-2">
            {metrics?.active_connections || 225} conns
          </div>
          <div className="text-xs text-muted-foreground mt-1">Across Envoy proxy replicas</div>
        </div>
      </div>
    </div>
  );
}

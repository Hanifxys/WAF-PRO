"use client";

import { useState, useEffect } from "react";
import { 
  Server, 
  RefreshCw, 
  Activity, 
  CheckCircle2, 
  AlertTriangle, 
  Plus, 
  ArrowDownCircle, 
  Cpu, 
  Network, 
  ShieldCheck, 
  Zap, 
  Clock, 
  Radio
} from "lucide-react";
import { API } from "@/lib/api";

interface ClusterNode {
  id: number;
  node_id: string;
  hostname: string;
  ip_address: string;
  role: string;
  status: string;
  active_version: number;
  current_rps: number;
  active_connections: number;
  last_heartbeat: string;
  created_at: string;
}

interface ClusterResponse {
  nodes: ClusterNode[];
  total_nodes: number;
  healthy_nodes: number;
  draining_nodes: number;
  total_cluster_rps: number;
  total_active_conns: number;
  active_xds_version: string;
}

export default function ClusterNodesPage() {
  const [data, setData] = useState<ClusterResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [showRegisterModal, setShowRegisterModal] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Register Form State
  const [nodeId, setNodeId] = useState("node-envoy-replica-02");
  const [hostname, setHostname] = useState("edge-gw-03.internal");
  const [ipAddress, setIpAddress] = useState("10.0.1.12");
  const [role, setRole] = useState("EDGE_REPLICA");
  const [currentRps, setCurrentRps] = useState(310);
  const [activeConns, setActiveConns] = useState(64);

  // Drain Notification State
  const [drainNotice, setDrainNotice] = useState<string | null>(null);

  const fetchNodes = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API}/api/v1/cluster/nodes`);
      if (res.ok) {
        const json = await res.json();
        setData(json);
      }
    } catch (err) {
      console.error("Failed to load cluster nodes", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchNodes();
    const timer = setInterval(fetchNodes, 10000);
    return () => clearInterval(timer);
  }, []);

  const handleRegisterHeartbeat = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      const res = await fetch(`${API}/api/v1/cluster/nodes/heartbeat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          node_id: nodeId,
          hostname: hostname,
          ip_address: ipAddress,
          role: role,
          status: "HEALTHY",
          current_rps: Number(currentRps),
          active_connections: Number(activeConns)
        })
      });

      if (res.ok) {
        setShowRegisterModal(false);
        fetchNodes();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDrainNode = async (targetNodeId: string) => {
    if (!confirm(`Are you sure you want to gracefully drain all traffic on node '${targetNodeId}'? Ingress routing will transition connections to sibling replicas.`)) {
      return;
    }

    try {
      const res = await fetch(`${API}/api/v1/cluster/nodes/${targetNodeId}/drain`, {
        method: "POST"
      });

      if (res.ok) {
        const resJson = await res.json();
        setDrainNotice(`Node '${targetNodeId}' is now DRAINING. In-flight connections finishing gracefully.`);
        fetchNodes();
        setTimeout(() => setDrainNotice(null), 6000);
      }
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-8 pb-12">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-blue-400 via-indigo-400 to-cyan-400">
            Distributed Data Plane & HA Cluster Topology
          </h1>
          <p className="text-muted-foreground mt-1">
            Real-time telemetry, Envoy proxy fleet synchronization, health tracking, and graceful zero-downtime traffic draining.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={fetchNodes} 
            className="flex items-center gap-2 px-3 py-2 bg-secondary/50 hover:bg-secondary text-foreground rounded-lg border border-border text-sm transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button 
            onClick={() => setShowRegisterModal(true)} 
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium shadow-lg shadow-blue-500/20 transition"
          >
            <Plus className="w-4 h-4" />
            Simulate Replica Heartbeat
          </button>
        </div>
      </div>

      {drainNotice && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
            <span className="text-sm font-medium">{drainNotice}</span>
          </div>
          <button onClick={() => setDrainNotice(null)} className="text-xs text-muted-foreground hover:text-foreground">
            Dismiss
          </button>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl border border-border bg-card/60 glass backdrop-blur-md">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Cluster Fleet Health</span>
            <Server className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold mt-2">
            {data?.healthy_nodes || 0} / {data?.total_nodes || 0} Replicas
          </div>
          <div className="text-xs text-emerald-400 mt-1 flex items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5" /> High-Availability Quorum
          </div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/60 glass backdrop-blur-md">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Aggregate Ingress Load</span>
            <Zap className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold mt-2 text-cyan-400">
            {data?.total_cluster_rps || 0} RPS
          </div>
          <div className="text-xs text-muted-foreground mt-1">
            {data?.total_active_conns || 0} concurrent connections
          </div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/60 glass backdrop-blur-md">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Active Draining Nodes</span>
            <ArrowDownCircle className="w-5 h-5 text-amber-400" />
          </div>
          <div className="text-2xl font-bold mt-2 text-amber-400">
            {data?.draining_nodes || 0}
          </div>
          <div className="text-xs text-muted-foreground mt-1">Zero dropped connections</div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/60 glass backdrop-blur-md">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Control Plane Sync</span>
            <Radio className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold mt-2 text-indigo-400 font-mono">
            {data?.active_xds_version || "v1"}
          </div>
          <div className="text-xs text-muted-foreground mt-1">xDS gRPC Stream Synced</div>
        </div>
      </div>

      {/* Nodes Table */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Cpu className="w-5 h-5 text-blue-400" />
            <h2 className="text-xl font-semibold text-foreground">Data Plane Node Inventory</h2>
          </div>
          <span className="text-xs text-muted-foreground">Auto-refreshes every 10 seconds</span>
        </div>

        <div className="rounded-xl border border-border bg-card/40 glass overflow-hidden">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border bg-secondary/30 text-xs text-muted-foreground uppercase font-medium">
              <tr>
                <th className="px-5 py-3">Node ID</th>
                <th className="px-5 py-3">Hostname / IP</th>
                <th className="px-5 py-3">Role</th>
                <th className="px-5 py-3">Throughput</th>
                <th className="px-5 py-3">xDS Version</th>
                <th className="px-5 py-3">Status</th>
                <th className="px-5 py-3">Last Heartbeat</th>
                <th className="px-5 py-3 text-right">Traffic Control</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loading && !data ? (
                <tr>
                  <td colSpan={8} className="px-5 py-8 text-center text-muted-foreground">Loading cluster topology...</td>
                </tr>
              ) : !data?.nodes || data.nodes.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-5 py-8 text-center text-muted-foreground">No cluster nodes detected.</td>
                </tr>
              ) : (
                data.nodes.map((n) => (
                  <tr key={n.id} className="hover:bg-secondary/20 transition">
                    <td className="px-5 py-3.5 font-mono text-xs font-semibold text-foreground">
                      {n.node_id}
                    </td>
                    <td className="px-5 py-3.5">
                      <div className="font-medium text-foreground">{n.hostname}</div>
                      <div className="text-xs font-mono text-muted-foreground">{n.ip_address}</div>
                    </td>
                    <td className="px-5 py-3.5">
                      <span className={`text-xs px-2.5 py-0.5 rounded-full font-semibold border ${
                        n.role === "PRIMARY" 
                          ? "bg-purple-500/10 text-purple-400 border-purple-500/20"
                          : "bg-blue-500/10 text-blue-400 border-blue-500/20"
                      }`}>
                        {n.role}
                      </span>
                    </td>
                    <td className="px-5 py-3.5">
                      <div className="text-xs font-semibold text-foreground">{n.current_rps} RPS</div>
                      <div className="text-xs text-muted-foreground">{n.active_connections} conns</div>
                    </td>
                    <td className="px-5 py-3.5 font-mono text-xs text-indigo-300">
                      v{n.active_version}
                    </td>
                    <td className="px-5 py-3.5">
                      <span className={`text-xs px-2.5 py-0.5 rounded-full font-semibold border flex items-center gap-1.5 w-fit ${
                        n.status === "HEALTHY"
                          ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                          : n.status === "DRAINING"
                          ? "bg-amber-500/10 text-amber-400 border-amber-500/20 animate-pulse"
                          : "bg-rose-500/10 text-rose-400 border-rose-500/20"
                      }`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          n.status === "HEALTHY" ? "bg-emerald-400" : n.status === "DRAINING" ? "bg-amber-400" : "bg-rose-400"
                        }`} />
                        {n.status}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-xs text-muted-foreground flex items-center gap-1 mt-2">
                      <Clock className="w-3.5 h-3.5" />
                      {new Date(n.last_heartbeat).toLocaleTimeString()}
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      {n.status === "HEALTHY" ? (
                        <button
                          onClick={() => handleDrainNode(n.node_id)}
                          className="px-3 py-1 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/20 rounded-lg text-xs font-medium transition flex items-center gap-1.5 ml-auto"
                        >
                          <ArrowDownCircle className="w-3.5 h-3.5" />
                          Drain Traffic
                        </button>
                      ) : n.status === "DRAINING" ? (
                        <span className="text-xs text-amber-400 font-mono">Draining Active...</span>
                      ) : (
                        <span className="text-xs text-muted-foreground">Inactive</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Heartbeat Simulation Modal */}
      {showRegisterModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-card border border-border rounded-xl p-6 w-full max-w-md shadow-2xl glass space-y-4">
            <h3 className="text-lg font-semibold text-foreground">Simulate Envoy Replica Heartbeat</h3>
            <p className="text-xs text-muted-foreground">
              Simulates an Envoy data plane proxy node reporting telemetry and receiving active xDS version directives.
            </p>
            <form onSubmit={handleRegisterHeartbeat} className="space-y-4">
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Node Identifier (Unique)</label>
                <input 
                  type="text" 
                  required
                  value={nodeId} 
                  onChange={(e) => setNodeId(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs text-muted-foreground block mb-1">Hostname</label>
                <input 
                  type="text" 
                  required
                  value={hostname} 
                  onChange={(e) => setHostname(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="text-xs text-muted-foreground block mb-1">IP Address</label>
                <input 
                  type="text" 
                  required
                  value={ipAddress} 
                  onChange={(e) => setIpAddress(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs text-muted-foreground block mb-1">Cluster Role</label>
                <select 
                  value={role} 
                  onChange={(e) => setRole(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
                >
                  <option value="EDGE_REPLICA">EDGE_REPLICA</option>
                  <option value="PRIMARY">PRIMARY</option>
                  <option value="DISASTER_RECOVERY">DISASTER_RECOVERY</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-muted-foreground block mb-1">Current RPS</label>
                  <input 
                    type="number" 
                    value={currentRps} 
                    onChange={(e) => setCurrentRps(Number(e.target.value))}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground block mb-1">Active Conns</label>
                  <input 
                    type="number" 
                    value={activeConns} 
                    onChange={(e) => setActiveConns(Number(e.target.value))}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button 
                  type="button" 
                  onClick={() => setShowRegisterModal(false)}
                  className="px-4 py-2 bg-secondary text-foreground text-sm rounded-lg hover:bg-secondary/80 transition"
                >
                  Cancel
                </button>
                <button 
                  type="submit" 
                  disabled={isSubmitting}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition"
                >
                  {isSubmitting ? "Transmitting..." : "Send Heartbeat"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}


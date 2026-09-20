"use client";

import { useState, useEffect } from "react";
import { 
  Radio, 
  Binary, 
  Layers, 
  Shield, 
  CheckCircle2, 
  RefreshCw, 
  AlertTriangle, 
  Save, 
  Sliders
} from "lucide-react";
import { API } from "@/lib/api";

interface ProtocolShield {
  id: number;
  app_id: number;
  protocol: string;
  policy_config: Record<string, any>;
  action: string;
  is_enabled: boolean;
  created_at: string;
}

export default function ModernProtocolsPage() {
  const [shields, setShields] = useState<Record<string, ProtocolShield>>({});
  const [loading, setLoading] = useState(true);
  const [savingProtocol, setSavingProtocol] = useState<string | null>(null);

  // GraphQL Form
  const [gqlMaxDepth, setGqlMaxDepth] = useState(8);
  const [gqlMaxComplexity, setGqlMaxComplexity] = useState(500);
  const [gqlMaxAliases, setGqlMaxAliases] = useState(20);
  const [gqlDisableIntrospection, setGqlDisableIntrospection] = useState(true);
  const [gqlAction, setGqlAction] = useState("BLOCK");

  // WebSocket Form
  const [wsAllowedOrigins, setWsAllowedOrigins] = useState("*.telkomsel.co.id");
  const [wsMaxConcurrent, setWsMaxConcurrent] = useState(50);
  const [wsMaxMsgSize, setWsMaxMsgSize] = useState(1024);
  const [wsIdleTimeout, setWsIdleTimeout] = useState(300);
  const [wsAction, setWsAction] = useState("BLOCK");

  // gRPC Form
  const [grpcAllowedPackages, setGrpcAllowedPackages] = useState("telkomsel.services.*");
  const [grpcRestrictedMethods, setGrpcRestrictedMethods] = useState("DeleteUser, PurgeDatabase");
  const [grpcMaxMsgSizeMB, setGrpcMaxMsgSizeMB] = useState(4);
  const [grpcAction, setGrpcAction] = useState("BLOCK");

  const fetchShields = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API}/api/v1/protocol-shields/all`);
      if (res.ok) {
        const list: ProtocolShield[] = await res.json();
        const map: Record<string, ProtocolShield> = {};
        list.forEach((s) => {
          map[s.protocol.toLowerCase()] = s;
        });
        setShields(map);

        if (map["graphql"]?.policy_config) {
          const cfg = map["graphql"].policy_config;
          if (cfg.max_depth) setGqlMaxDepth(cfg.max_depth);
          if (cfg.max_complexity) setGqlMaxComplexity(cfg.max_complexity);
          if (cfg.max_aliases) setGqlMaxAliases(cfg.max_aliases);
          if (cfg.disable_introspection !== undefined) setGqlDisableIntrospection(cfg.disable_introspection);
          if (map["graphql"].action) setGqlAction(map["graphql"].action);
        }

        if (map["websocket"]?.policy_config) {
          const cfg = map["websocket"].policy_config;
          if (cfg.allowed_origins) setWsAllowedOrigins(cfg.allowed_origins);
          if (cfg.max_concurrent_connections) setWsMaxConcurrent(cfg.max_concurrent_connections);
          if (cfg.max_message_size_kb) setWsMaxMsgSize(cfg.max_message_size_kb);
          if (cfg.idle_timeout_sec) setWsIdleTimeout(cfg.idle_timeout_sec);
          if (map["websocket"].action) setWsAction(map["websocket"].action);
        }

        if (map["grpc"]?.policy_config) {
          const cfg = map["grpc"].policy_config;
          if (cfg.allowed_packages) setGrpcAllowedPackages(cfg.allowed_packages);
          if (cfg.restricted_methods) setGrpcRestrictedMethods(cfg.restricted_methods);
          if (cfg.max_message_size_mb) setGrpcMaxMsgSizeMB(cfg.max_message_size_mb);
          if (map["grpc"].action) setGrpcAction(map["grpc"].action);
        }
      }
    } catch (err) {
      console.error("Failed to load protocol shields", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchShields();
  }, []);

  const saveShield = async (protocol: string, config: any, action: string) => {
    try {
      setSavingProtocol(protocol);
      const res = await fetch(`${API}/api/v1/protocol-shields/${protocol}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          app_id: 1,
          policy_config: config,
          action,
          is_enabled: true,
        }),
      });
      if (res.ok) {
        await fetchShields();
      }
    } catch (err) {
      console.error("Failed to save shield", err);
    } finally {
      setSavingProtocol(null);
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-cyan-400 flex items-center gap-2">
            <Radio className="w-6 h-6 text-emerald-400" />
            Pillar 3: Modern Protocol Protection (Phases 35, 36, 37)
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Deep packet inspection and policy enforcement for non-traditional protocols: GraphQL, WebSocket connections, and gRPC remote procedure calls.
          </p>
        </div>

        <button
          onClick={fetchShields}
          disabled={loading}
          className="p-2.5 rounded-lg border border-border bg-card/50 text-foreground hover:bg-card hover:text-emerald-400 transition-colors"
          title="Refresh"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
        </button>
      </div>

      {/* 3 Protocol Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Card 1: GraphQL Shield */}
        <div className="glass rounded-xl border border-border p-6 flex flex-col justify-between space-y-6">
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-2">
                <Binary className="w-5 h-5 text-fuchsia-400" />
                <h3 className="font-bold text-foreground">GraphQL Shield (Phase 35)</h3>
              </div>
              <span className="px-2 py-0.5 rounded text-xs font-semibold bg-fuchsia-500/10 text-fuchsia-400 border border-fuchsia-500/20">
                ACTIVE
              </span>
            </div>

            <p className="text-xs text-muted-foreground">
              Mitigate introspection data exposure, deeply nested denial-of-service queries, and alias batching attacks.
            </p>

            <div className="space-y-3 pt-2">
              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Max Query Depth</label>
                <input
                  type="number"
                  value={gqlMaxDepth}
                  onChange={(e) => setGqlMaxDepth(Number(e.target.value))}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-fuchsia-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Max Complexity Score</label>
                <input
                  type="number"
                  value={gqlMaxComplexity}
                  onChange={(e) => setGqlMaxComplexity(Number(e.target.value))}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-fuchsia-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Max Aliases Limit</label>
                <input
                  type="number"
                  value={gqlMaxAliases}
                  onChange={(e) => setGqlMaxAliases(Number(e.target.value))}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-fuchsia-500 font-mono"
                />
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="gql_introspection"
                  checked={gqlDisableIntrospection}
                  onChange={(e) => setGqlDisableIntrospection(e.target.checked)}
                  className="rounded border-border bg-secondary text-fuchsia-500 focus:ring-fuchsia-500"
                />
                <label htmlFor="gql_introspection" className="text-xs text-muted-foreground font-medium">
                  Block Production Schema Introspection
                </label>
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Violation Action</label>
                <select
                  value={gqlAction}
                  onChange={(e) => setGqlAction(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-fuchsia-500"
                >
                  <option value="BLOCK">BLOCK (400 Bad Request)</option>
                  <option value="ALERT">ALERT ONLY</option>
                </select>
              </div>
            </div>
          </div>

          <button
            onClick={() => saveShield("graphql", {
              max_depth: gqlMaxDepth,
              max_complexity: gqlMaxComplexity,
              max_aliases: gqlMaxAliases,
              disable_introspection: gqlDisableIntrospection,
            }, gqlAction)}
            disabled={savingProtocol === "graphql"}
            className="w-full py-2 rounded-lg bg-fuchsia-500 hover:bg-fuchsia-600 text-white font-semibold text-sm transition-all flex items-center justify-center gap-2 shadow-lg shadow-fuchsia-500/20"
          >
            <Save className="w-4 h-4" />
            {savingProtocol === "graphql" ? "Applying..." : "Update GraphQL Shield"}
          </button>
        </div>

        {/* Card 2: WebSocket Shield */}
        <div className="glass rounded-xl border border-border p-6 flex flex-col justify-between space-y-6">
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-2">
                <Radio className="w-5 h-5 text-cyan-400" />
                <h3 className="font-bold text-foreground">WebSocket Shield (Phase 36)</h3>
              </div>
              <span className="px-2 py-0.5 rounded text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                ACTIVE
              </span>
            </div>

            <p className="text-xs text-muted-foreground">
              Secure HTTP Upgrade handshakes, enforce Origin validation, cap per-IP concurrency, and inspect frame message limits.
            </p>

            <div className="space-y-3 pt-2">
              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Allowed Origins</label>
                <input
                  type="text"
                  value={wsAllowedOrigins}
                  onChange={(e) => setWsAllowedOrigins(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Max Concurrent Connections / IP</label>
                <input
                  type="number"
                  value={wsMaxConcurrent}
                  onChange={(e) => setWsMaxConcurrent(Number(e.target.value))}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Max Message Frame Size (KB)</label>
                <input
                  type="number"
                  value={wsMaxMsgSize}
                  onChange={(e) => setWsMaxMsgSize(Number(e.target.value))}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Idle Timeout (seconds)</label>
                <input
                  type="number"
                  value={wsIdleTimeout}
                  onChange={(e) => setWsIdleTimeout(Number(e.target.value))}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Violation Action</label>
                <select
                  value={wsAction}
                  onChange={(e) => setWsAction(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-cyan-500"
                >
                  <option value="BLOCK">BLOCK (Close Handshake 403)</option>
                  <option value="RATE_LIMIT">RATE_LIMIT</option>
                </select>
              </div>
            </div>
          </div>

          <button
            onClick={() => saveShield("websocket", {
              allowed_origins: wsAllowedOrigins,
              max_concurrent_connections: wsMaxConcurrent,
              max_message_size_kb: wsMaxMsgSize,
              idle_timeout_sec: wsIdleTimeout,
            }, wsAction)}
            disabled={savingProtocol === "websocket"}
            className="w-full py-2 rounded-lg bg-cyan-500 hover:bg-cyan-600 text-black font-semibold text-sm transition-all flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20"
          >
            <Save className="w-4 h-4" />
            {savingProtocol === "websocket" ? "Applying..." : "Update WebSocket Shield"}
          </button>
        </div>

        {/* Card 3: gRPC Shield */}
        <div className="glass rounded-xl border border-border p-6 flex flex-col justify-between space-y-6">
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-2">
                <Layers className="w-5 h-5 text-indigo-400" />
                <h3 className="font-bold text-foreground">gRPC Shield (Phase 37)</h3>
              </div>
              <span className="px-2 py-0.5 rounded text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                ACTIVE
              </span>
            </div>

            <p className="text-xs text-muted-foreground">
              Enforce method allowlisting, payload size controls, and authentication metadata checks for HTTP/2 Protobuf services.
            </p>

            <div className="space-y-3 pt-2">
              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Allowed Service Packages</label>
                <input
                  type="text"
                  value={grpcAllowedPackages}
                  onChange={(e) => setGrpcAllowedPackages(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-indigo-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Restricted Methods (Denylist)</label>
                <input
                  type="text"
                  value={grpcRestrictedMethods}
                  onChange={(e) => setGrpcRestrictedMethods(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-indigo-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Max Message Size (MB)</label>
                <input
                  type="number"
                  value={grpcMaxMsgSizeMB}
                  onChange={(e) => setGrpcMaxMsgSizeMB(Number(e.target.value))}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-indigo-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Violation Action</label>
                <select
                  value={grpcAction}
                  onChange={(e) => setGrpcAction(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-indigo-500"
                >
                  <option value="BLOCK">BLOCK (gRPC Status PERMISSION_DENIED)</option>
                  <option value="ALERT">ALERT ONLY</option>
                </select>
              </div>
            </div>
          </div>

          <button
            onClick={() => saveShield("grpc", {
              allowed_packages: grpcAllowedPackages,
              restricted_methods: grpcRestrictedMethods,
              max_message_size_mb: grpcMaxMsgSizeMB,
            }, grpcAction)}
            disabled={savingProtocol === "grpc"}
            className="w-full py-2 rounded-lg bg-indigo-500 hover:bg-indigo-600 text-white font-semibold text-sm transition-all flex items-center justify-center gap-2 shadow-lg shadow-indigo-500/20"
          >
            <Save className="w-4 h-4" />
            {savingProtocol === "grpc" ? "Applying..." : "Update gRPC Shield"}
          </button>
        </div>
      </div>
    </div>
  );
}


"use client";

import { useState, useEffect } from "react";
import { 
  Search, 
  Plus, 
  RefreshCw, 
  CheckCircle2, 
  AlertTriangle, 
  Lock, 
  Unlock, 
  Globe, 
  Radio, 
  Binary, 
  KeyRound, 
  ShieldAlert,
  Layers,
  Upload
} from "lucide-react";
import { API } from "@/lib/api";

interface DiscoveredAsset {
  id: number;
  app_id: number;
  asset_type: string;
  path_pattern: string;
  method: string;
  is_sensitive: boolean;
  observed_clients_count: number;
  last_observed_at: string;
}

export default function AssetDiscoveryPage() {
  const [assets, setAssets] = useState<DiscoveredAsset[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState("ALL");
  const [showModal, setShowModal] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // New Asset Form
  const [pathPattern, setPathPattern] = useState("");
  const [method, setMethod] = useState("GET");
  const [assetType, setAssetType] = useState("");
  const [isSensitive, setIsSensitive] = useState(false);

  const fetchAssets = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API}/api/v1/assets`);
      if (res.ok) {
        const data = await res.json();
        setAssets(data || []);
      }
    } catch (err) {
      console.error("Failed to load assets", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, []);

  const handleClassify = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setIsSubmitting(true);
      const res = await fetch(`${API}/api/v1/assets/classify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          app_id: 1,
          path_pattern: pathPattern,
          method,
          asset_type: assetType || undefined,
          is_sensitive: isSensitive,
        }),
      });
      if (res.ok) {
        setShowModal(false);
        setPathPattern("");
        setAssetType("");
        setIsSensitive(false);
        await fetchAssets();
      }
    } catch (err) {
      console.error("Failed to classify asset", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const toggleSensitivity = async (id: number, current: boolean) => {
    try {
      const res = await fetch(`${API}/api/v1/assets/${id}/tag-sensitive`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ is_sensitive: !current }),
      });
      if (res.ok) {
        setAssets(assets.map(a => a.id === id ? { ...a, is_sensitive: !current } : a));
      }
    } catch (err) {
      console.error("Failed to toggle sensitivity", err);
    }
  };

  const filteredAssets = filterType === "ALL" 
    ? assets 
    : assets.filter(a => a.asset_type === filterType);

  const sensitiveCount = assets.filter(a => a.is_sensitive).length;
  const webCount = assets.filter(a => a.asset_type === "WEB" || a.asset_type === "REST").length;
  const modernProtocolCount = assets.filter(a => ["GRAPHQL", "WEBSOCKET", "GRPC"].includes(a.asset_type)).length;

  const getTypeBadge = (type: string) => {
    switch (type) {
      case "AUTH":
        return <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20"><KeyRound className="w-3 h-3" /> AUTH</span>;
      case "ADMIN":
        return <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20"><ShieldAlert className="w-3 h-3" /> ADMIN</span>;
      case "GRAPHQL":
        return <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-fuchsia-500/10 text-fuchsia-400 border border-fuchsia-500/20"><Binary className="w-3 h-3" /> GRAPHQL</span>;
      case "WEBSOCKET":
        return <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"><Radio className="w-3 h-3" /> WEBSOCKET</span>;
      case "GRPC":
        return <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20"><Layers className="w-3 h-3" /> GRPC</span>;
      case "UPLOAD":
        return <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/20"><Upload className="w-3 h-3" /> UPLOAD</span>;
      case "REST":
        return <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"><Globe className="w-3 h-3" /> REST API</span>;
      default:
        return <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20"><Globe className="w-3 h-3" /> WEB</span>;
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-cyan-400 flex items-center gap-2">
            <Search className="w-6 h-6 text-emerald-400" />
            Pillar 1: Advanced Application Discovery (Phase 31)
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Real-time automatic discovery of exposed web applications, REST APIs, GraphQL, WebSockets, gRPC services, and sensitive endpoints.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchAssets}
            disabled={loading}
            className="p-2.5 rounded-lg border border-border bg-card/50 text-foreground hover:bg-card hover:text-emerald-400 transition-colors"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-black font-semibold text-sm shadow-lg shadow-emerald-500/20 transition-all"
          >
            <Plus className="w-4 h-4" />
            Register / Classify Asset
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass p-5 rounded-xl border border-border">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Discovered Assets</span>
            <Search className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-foreground mt-2">{assets.length}</div>
          <div className="text-xs text-emerald-400 mt-1">Automated inventory sync</div>
        </div>

        <div className="glass p-5 rounded-xl border border-border">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Sensitive Endpoints</span>
            <Lock className="w-5 h-5 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400 mt-2">{sensitiveCount}</div>
          <div className="text-xs text-muted-foreground mt-1">Auth, Admin, Upload & PII</div>
        </div>

        <div className="glass p-5 rounded-xl border border-border">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Modern Protocols</span>
            <Radio className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-400 mt-2">{modernProtocolCount}</div>
          <div className="text-xs text-muted-foreground mt-1">GraphQL, WebSocket & gRPC</div>
        </div>

        <div className="glass p-5 rounded-xl border border-border">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Web & REST APIs</span>
            <Globe className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-foreground mt-2">{webCount}</div>
          <div className="text-xs text-muted-foreground mt-1">HTTP 1.1 / HTTP 2 Traffic</div>
        </div>
      </div>

      {/* Filters & Table */}
      <div className="glass rounded-xl border border-border overflow-hidden">
        <div className="p-4 border-b border-border flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            {["ALL", "REST", "WEB", "GRAPHQL", "WEBSOCKET", "GRPC", "AUTH", "ADMIN", "UPLOAD"].map((type) => (
              <button
                key={type}
                onClick={() => setFilterType(type)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  filterType === type 
                    ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" 
                    : "text-muted-foreground hover:bg-secondary hover:text-foreground"
                }`}
              >
                {type}
              </button>
            ))}
          </div>
          <span className="text-xs text-muted-foreground">Showing {filteredAssets.length} of {assets.length} items</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20 text-xs font-semibold uppercase text-muted-foreground">
                <th className="p-4">Type</th>
                <th className="p-4">Path Pattern</th>
                <th className="p-4">HTTP Method</th>
                <th className="p-4">Classification</th>
                <th className="p-4">Observed Clients</th>
                <th className="p-4">Last Observed</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loading ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-muted-foreground">
                    <RefreshCw className="w-6 h-6 animate-spin mx-auto text-emerald-400 mb-2" />
                    Scanning discovered application topology...
                  </td>
                </tr>
              ) : filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-muted-foreground">
                    No discovered assets match the current filter.
                  </td>
                </tr>
              ) : (
                filteredAssets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-muted/10 transition-colors">
                    <td className="p-4">{getTypeBadge(asset.asset_type)}</td>
                    <td className="p-4 font-mono font-medium text-foreground">{asset.path_pattern}</td>
                    <td className="p-4">
                      <span className="px-2 py-0.5 rounded text-xs font-mono bg-secondary text-foreground font-semibold">
                        {asset.method}
                      </span>
                    </td>
                    <td className="p-4">
                      {asset.is_sensitive ? (
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/20">
                          <Lock className="w-3 h-3" /> Sensitive
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground">Standard</span>
                      )}
                    </td>
                    <td className="p-4 font-mono text-muted-foreground">{asset.observed_clients_count}</td>
                    <td className="p-4 text-xs text-muted-foreground">
                      {new Date(asset.last_observed_at).toLocaleString()}
                    </td>
                    <td className="p-4 text-right">
                      <button
                        onClick={() => toggleSensitivity(asset.id, asset.is_sensitive)}
                        className={`p-1.5 rounded-lg border text-xs font-medium transition-colors ${
                          asset.is_sensitive
                            ? "border-rose-500/20 text-rose-400 hover:bg-rose-500/10"
                            : "border-border text-muted-foreground hover:bg-card hover:text-foreground"
                        }`}
                        title={asset.is_sensitive ? "Untag sensitive" : "Tag as sensitive"}
                      >
                        {asset.is_sensitive ? <Unlock className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal: Classify Asset */}
      {showModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass border border-border rounded-xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-foreground">Register or Classify Asset</h3>
            <p className="text-xs text-muted-foreground">
              Provide the endpoint pattern. The WAF will automatically classify the protocol type if left blank.
            </p>

            <form onSubmit={handleClassify} className="space-y-4 pt-2">
              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Path Pattern</label>
                <input
                  type="text"
                  required
                  placeholder="/api/v1/orders or /ws/chat"
                  value={pathPattern}
                  onChange={(e) => setPathPattern(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-semibold text-muted-foreground block mb-1">HTTP Method</label>
                  <select
                    value={method}
                    onChange={(e) => setMethod(e.target.value)}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-emerald-500"
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
                  <label className="text-xs font-semibold text-muted-foreground block mb-1">Protocol / Asset Type</label>
                  <select
                    value={assetType}
                    onChange={(e) => setAssetType(e.target.value)}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-emerald-500"
                  >
                    <option value="">Auto-Detect (Heuristic)</option>
                    <option value="REST">REST API</option>
                    <option value="WEB">Web App</option>
                    <option value="GRAPHQL">GraphQL</option>
                    <option value="WEBSOCKET">WebSocket</option>
                    <option value="GRPC">gRPC</option>
                    <option value="AUTH">Authentication</option>
                    <option value="ADMIN">Admin Endpoint</option>
                    <option value="UPLOAD">File Upload</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center gap-2 pt-2">
                <input
                  type="checkbox"
                  id="is_sensitive"
                  checked={isSensitive}
                  onChange={(e) => setIsSensitive(e.target.checked)}
                  className="rounded border-border bg-secondary text-emerald-500 focus:ring-emerald-500"
                />
                <label htmlFor="is_sensitive" className="text-xs text-muted-foreground font-medium">
                  Mark as Sensitive Endpoint (enforce stricter CRS PL3 & DLP masking)
                </label>
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-border">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 rounded-lg text-sm text-muted-foreground hover:bg-secondary transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-black font-semibold text-sm transition-all"
                >
                  {isSubmitting ? "Classifying..." : "Save Asset"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}


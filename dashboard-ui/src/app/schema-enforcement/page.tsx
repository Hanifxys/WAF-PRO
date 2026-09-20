"use client";

import { useState, useEffect } from "react";
import { 
  FileCheck, 
  Upload, 
  RefreshCw, 
  CheckCircle2, 
  AlertTriangle, 
  Shield, 
  FileCode, 
  Eye, 
  Settings,
  Layers
} from "lucide-react";
import { API } from "@/lib/api";

interface APISchema {
  id: number;
  app_id: number;
  spec_version: string;
  title: string;
  raw_openapi_json: string;
  enforcement_mode: string;
  endpoints_count: number;
  created_at: string;
}

export default function SchemaEnforcementPage() {
  const [schemas, setSchemas] = useState<APISchema[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [selectedSchema, setSelectedSchema] = useState<APISchema | null>(null);

  // Form
  const [title, setTitle] = useState("");
  const [specVersion, setSpecVersion] = useState("3.0.0");
  const [enforcementMode, setEnforcementMode] = useState("MONITOR");
  const [rawJson, setRawJson] = useState(`{
  "openapi": "3.0.0",
  "info": {
    "title": "Telkomsel Digital Banking & Core API",
    "version": "1.0.0"
  },
  "paths": {
    "/api/v1/users": {
      "get": { "summary": "List users", "responses": { "200": { "description": "Success" } } }
    },
    "/api/v1/payments": {
      "post": { "summary": "Process transaction", "responses": { "201": { "description": "Created" } } }
    },
    "/api/v1/accounts/{id}": {
      "get": { "summary": "Get balance", "responses": { "200": { "description": "Success" } } }
    }
  }
}`);

  const fetchSchemas = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API}/api/v1/schemas/1`);
      if (res.ok) {
        const data = await res.json();
        setSchemas(data || []);
      }
    } catch (err) {
      console.error("Failed to load schemas", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSchemas();
  }, []);

  const handleImport = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setIsSubmitting(true);
      const res = await fetch(`${API}/api/v1/schemas/import`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          app_id: 1,
          title: title || "Telkomsel OpenAPI Spec",
          spec_version: specVersion,
          raw_openapi_json: rawJson,
          enforcement_mode: enforcementMode,
        }),
      });
      if (res.ok) {
        setShowModal(false);
        setTitle("");
        await fetchSchemas();
      }
    } catch (err) {
      console.error("Failed to import schema", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleModeChange = async (id: number, newMode: string) => {
    try {
      const res = await fetch(`${API}/api/v1/schemas/${id}/mode`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enforcement_mode: newMode }),
      });
      if (res.ok) {
        setSchemas(schemas.map(s => s.id === id ? { ...s, enforcement_mode: newMode } : s));
      }
    } catch (err) {
      console.error("Failed to update schema mode", err);
    }
  };

  const totalEndpoints = schemas.reduce((acc, s) => acc + s.endpoints_count, 0);
  const enforcedCount = schemas.filter(s => s.enforcement_mode === "BLOCK").length;

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-cyan-400 flex items-center gap-2">
            <FileCheck className="w-6 h-6 text-emerald-400" />
            Pillar 1: API Schema Enforcement (Phase 32)
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Enforce OpenAPI/JSON schemas strictly against live API traffic to block parameter tampering, unauthorized methods, and unknown endpoints.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchSchemas}
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
            <Upload className="w-4 h-4" />
            Import OpenAPI Spec
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <div className="glass p-5 rounded-xl border border-border">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Imported Specs</span>
            <FileCode className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-foreground mt-2">{schemas.length}</div>
          <div className="text-xs text-muted-foreground mt-1">OpenAPI 3.0 / Swagger 2.0</div>
        </div>

        <div className="glass p-5 rounded-xl border border-border">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Enforced Endpoints</span>
            <Layers className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-400 mt-2">{totalEndpoints}</div>
          <div className="text-xs text-muted-foreground mt-1">Strict method & param checks</div>
        </div>

        <div className="glass p-5 rounded-xl border border-border">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Active Enforcement</span>
            <Shield className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-indigo-400 mt-2">{enforcedCount} Specs Blocking</div>
          <div className="text-xs text-emerald-400 mt-1">Zero schema drift allowed</div>
        </div>
      </div>

      {/* Schema List */}
      <div className="glass rounded-xl border border-border overflow-hidden">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <h2 className="text-sm font-semibold text-foreground">API Contracts & Enforcement Profiles</h2>
          <span className="text-xs text-muted-foreground">Live synchronization with Coraza WASM</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20 text-xs font-semibold uppercase text-muted-foreground">
                <th className="p-4">Schema Title</th>
                <th className="p-4">Spec Version</th>
                <th className="p-4">Declared Endpoints</th>
                <th className="p-4">Enforcement Mode</th>
                <th className="p-4">Imported At</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loading ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-muted-foreground">
                    <RefreshCw className="w-6 h-6 animate-spin mx-auto text-emerald-400 mb-2" />
                    Loading OpenAPI schemas...
                  </td>
                </tr>
              ) : schemas.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-muted-foreground">
                    No OpenAPI specifications imported yet. Click &quot;Import OpenAPI Spec&quot; above to begin contract enforcement.
                  </td>
                </tr>
              ) : (
                schemas.map((s) => (
                  <tr key={s.id} className="hover:bg-muted/10 transition-colors">
                    <td className="p-4 font-medium text-foreground flex items-center gap-2">
                      <FileCheck className="w-4 h-4 text-emerald-400" />
                      {s.title}
                    </td>
                    <td className="p-4 font-mono text-xs text-muted-foreground">OpenAPI {s.spec_version}</td>
                    <td className="p-4 font-mono text-foreground font-semibold">{s.endpoints_count} paths</td>
                    <td className="p-4">
                      <select
                        value={s.enforcement_mode}
                        onChange={(e) => handleModeChange(s.id, e.target.value)}
                        className={`text-xs font-semibold rounded-lg px-2.5 py-1 border transition-colors ${
                          s.enforcement_mode === "BLOCK"
                            ? "bg-rose-500/10 text-rose-400 border-rose-500/20"
                            : s.enforcement_mode === "MONITOR"
                            ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                            : "bg-secondary text-muted-foreground border-border"
                        }`}
                      >
                        <option value="MONITOR">MONITOR (Alert on drift)</option>
                        <option value="BLOCK">BLOCK (Strict 403 on drift)</option>
                        <option value="DISABLED">DISABLED</option>
                      </select>
                    </td>
                    <td className="p-4 text-xs text-muted-foreground">{new Date(s.created_at).toLocaleString()}</td>
                    <td className="p-4 text-right">
                      <button
                        onClick={() => setSelectedSchema(s)}
                        className="p-1.5 rounded-lg border border-border text-xs text-muted-foreground hover:bg-card hover:text-foreground transition-colors"
                        title="View Raw OpenAPI"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal: Import OpenAPI */}
      {showModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass border border-border rounded-xl max-w-xl w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-foreground">Import OpenAPI Specification</h3>
            <p className="text-xs text-muted-foreground">
              Paste your OpenAPI JSON spec. The system extracts declared paths, required params, and HTTP methods for real-time traffic validation.
            </p>

            <form onSubmit={handleImport} className="space-y-4 pt-2">
              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">Specification Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. MyTelkomsel Payments V2 API"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-semibold text-muted-foreground block mb-1">Spec Version</label>
                  <select
                    value={specVersion}
                    onChange={(e) => setSpecVersion(e.target.value)}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-emerald-500"
                  >
                    <option value="3.0.0">OpenAPI 3.0.0</option>
                    <option value="3.1.0">OpenAPI 3.1.0</option>
                    <option value="2.0">Swagger 2.0</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs font-semibold text-muted-foreground block mb-1">Initial Enforcement Mode</label>
                  <select
                    value={enforcementMode}
                    onChange={(e) => setEnforcementMode(e.target.value)}
                    className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-emerald-500"
                  >
                    <option value="MONITOR">MONITOR (Alert on drift)</option>
                    <option value="BLOCK">BLOCK (Block 403 on violation)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-xs font-semibold text-muted-foreground block mb-1">OpenAPI Document (JSON)</label>
                <textarea
                  rows={8}
                  required
                  value={rawJson}
                  onChange={(e) => setRawJson(e.target.value)}
                  className="w-full bg-secondary/50 border border-border rounded-lg p-3 text-xs font-mono text-foreground focus:outline-none focus:border-emerald-500 resize-none"
                />
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
                  {isSubmitting ? "Importing..." : "Parse & Enforce Schema"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: View Schema Details */}
      {selectedSchema && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass border border-border rounded-xl max-w-2xl w-full p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-bold text-foreground">{selectedSchema.title}</h3>
              <span className="text-xs font-mono bg-secondary px-2 py-1 rounded">OpenAPI {selectedSchema.spec_version}</span>
            </div>

            <pre className="p-4 bg-black/50 border border-border rounded-lg text-xs font-mono overflow-auto max-h-96 text-emerald-400">
              {(() => {
                try {
                  return JSON.stringify(JSON.parse(selectedSchema.raw_openapi_json), null, 2);
                } catch {
                  return selectedSchema.raw_openapi_json;
                }
              })()}
            </pre>

            <div className="flex justify-end pt-2 border-t border-border">
              <button
                onClick={() => setSelectedSchema(null)}
                className="px-4 py-2 rounded-lg bg-secondary text-sm text-foreground hover:bg-card transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


"use client";

import { useState, useEffect } from "react";
import { 
  ScrollText, 
  Download, 
  Upload, 
  RefreshCw, 
  ShieldCheck, 
  Clock, 
  UserCheck, 
  FileText, 
  CheckCircle2, 
  AlertCircle,
  Database,
  Hash
} from "lucide-react";
import { API } from "@/lib/api";

interface AuditLog {
  id: number;
  actor_username: string;
  action: string;
  resource_type: string;
  resource_id: string;
  details: string;
  client_ip: string;
  created_at: string;
}

export default function AuditTrailPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionFilter, setActionFilter] = useState("ALL");
  const [downloading, setDownloading] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [restoreJSON, setRestoreJSON] = useState("");
  const [showRestoreModal, setShowRestoreModal] = useState(false);
  const [notification, setNotification] = useState<{ type: "success" | "error" | null; message: string }>({ type: null, message: "" });

  const fetchLogs = async () => {
    try {
      setLoading(true);
      let url = `${API}/api/v1/audit-logs`;
      if (actionFilter !== "ALL") {
        url += `?action=${actionFilter}`;
      }
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setLogs(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      console.error("Failed to load audit logs", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [actionFilter]);

  const handleExportBackup = async () => {
    try {
      setDownloading(true);
      const res = await fetch(`${API}/api/v1/system/backup`);
      if (res.ok) {
        const bundle = await res.json();
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(bundle, null, 2));
        const downloadAnchor = document.createElement("a");
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", `waf_pro_cluster_backup_${new Date().toISOString().slice(0,10)}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
        setNotification({
          type: "success",
          message: `Disaster recovery backup exported successfully! SHA-256: ${bundle.sha256_checksum?.slice(0, 16)}...`
        });
        fetchLogs();
      }
    } catch (err) {
      setNotification({ type: "error", message: "Failed to download backup bundle" });
    } finally {
      setDownloading(false);
    }
  };

  const handleRestoreBackup = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setRestoring(true);
      const parsed = JSON.parse(restoreJSON);
      const res = await fetch(`${API}/api/v1/system/restore`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(parsed)
      });
      if (res.ok) {
        const data = await res.json();
        setShowRestoreModal(false);
        setRestoreJSON("");
        setNotification({
          type: "success",
          message: `Cluster configuration restored successfully! Tables restored: ${data.restored_tables?.join(", ")}`
        });
        fetchLogs();
      } else {
        setNotification({ type: "error", message: "Restore failed: Invalid bundle or transaction error." });
      }
    } catch (err) {
      setNotification({ type: "error", message: "Invalid JSON format in backup payload." });
    } finally {
      setRestoring(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-5">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <ScrollText className="w-7 h-7 text-emerald-400" />
            Compliance Audit Trail &amp; Disaster Recovery
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Immutable administrative change log, cryptographic configuration snapshots, and full cluster disaster recovery.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchLogs}
            className="p-2.5 rounded-lg border border-border bg-secondary/50 hover:bg-secondary text-foreground transition-colors"
            title="Refresh Audit Logs"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin text-emerald-400" : ""}`} />
          </button>
          <button
            onClick={handleExportBackup}
            disabled={downloading}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 font-semibold text-xs transition-colors"
          >
            <Download className="w-4 h-4" />
            {downloading ? "Exporting..." : "Export DR Backup"}
          </button>
          <button
            onClick={() => setShowRestoreModal(true)}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-bold text-xs transition-colors shadow-lg shadow-emerald-500/20"
          >
            <Upload className="w-4 h-4 stroke-[3]" />
            Restore Cluster
          </button>
        </div>
      </div>

      {notification.type && (
        <div className={`p-4 rounded-lg flex items-start gap-3 border text-sm ${
          notification.type === "success" ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400" : "bg-red-500/10 border-red-500/20 text-red-400"
        }`}>
          {notification.type === "success" ? <CheckCircle2 className="w-5 h-5 shrink-0" /> : <AlertCircle className="w-5 h-5 shrink-0" />}
          <p>{notification.message}</p>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl border border-border bg-card/60 backdrop-blur-sm">
          <div className="flex justify-between items-start">
            <div className="space-y-1">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Audit Records</span>
              <h2 className="text-3xl font-bold text-foreground">{logs.length}</h2>
            </div>
            <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <FileText className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-muted-foreground flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> Immutable audit trail
          </div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/60 backdrop-blur-sm">
          <div className="flex justify-between items-start">
            <div className="space-y-1">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Admin Actors</span>
              <h2 className="text-3xl font-bold text-cyan-400">SOC Lead</h2>
            </div>
            <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <UserCheck className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-muted-foreground flex items-center gap-1.5">
            RBAC session tracking
          </div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/60 backdrop-blur-sm">
          <div className="flex justify-between items-start">
            <div className="space-y-1">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">DR Integrity</span>
              <h2 className="text-3xl font-bold text-emerald-400">SHA-256</h2>
            </div>
            <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Hash className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-muted-foreground flex items-center gap-1.5">
            Cryptographic bundle checksum
          </div>
        </div>

        <div className="p-5 rounded-xl border border-border bg-card/60 backdrop-blur-sm">
          <div className="flex justify-between items-start">
            <div className="space-y-1">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">DR Status</span>
              <h2 className="text-3xl font-bold text-foreground">HOT_SYNCED</h2>
            </div>
            <div className="p-2.5 rounded-lg bg-secondary text-muted-foreground border border-border">
              <Database className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-muted-foreground flex items-center gap-1.5">
            100% Config rollback ready
          </div>
        </div>
      </div>

      {/* Filter Chips */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1">
        {["ALL", "INITIALIZE_CLUSTER", "CREATE_DDOS_POLICY", "EXPORT_SYSTEM_BACKUP", "RESTORE_SYSTEM_BACKUP"].map((act) => (
          <button
            key={act}
            onClick={() => setActionFilter(act)}
            className={`px-3 py-1 rounded-full text-xs font-mono font-medium border transition-colors ${
              actionFilter === act
                ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
                : "bg-secondary/40 text-muted-foreground border-border hover:text-foreground"
            }`}
          >
            {act}
          </button>
        ))}
      </div>

      {/* Audit Logs Table */}
      <div className="rounded-xl border border-border bg-card/40 backdrop-blur-sm overflow-hidden">
        <div className="p-4 border-b border-border/60 flex items-center justify-between bg-card/60">
          <div className="flex items-center gap-2">
            <ScrollText className="w-4 h-4 text-emerald-400" />
            <h3 className="font-semibold text-sm text-foreground">Control Plane Action Log</h3>
          </div>
          <span className="text-xs text-muted-foreground font-mono">SOC Compliance Stream</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-secondary/40 text-muted-foreground uppercase font-mono text-[11px] tracking-wider border-b border-border/40">
              <tr>
                <th className="py-3 px-4 font-semibold">Timestamp</th>
                <th className="py-3 px-4 font-semibold">Actor</th>
                <th className="py-3 px-4 font-semibold">Action</th>
                <th className="py-3 px-4 font-semibold">Resource</th>
                <th className="py-3 px-4 font-semibold">Details / Change Summary</th>
                <th className="py-3 px-4 font-semibold text-right">Client IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/30 font-sans">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-muted-foreground">
                    <RefreshCw className="w-6 h-6 animate-spin text-emerald-400 mx-auto mb-2" />
                    Loading governance audit logs...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-muted-foreground">
                    No audit records match the current filter.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="hover:bg-secondary/20 transition-colors">
                    <td className="py-3 px-4 font-mono text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 font-semibold text-foreground text-xs">
                      {log.actor_username}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        {log.action}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-cyan-300">
                      {log.resource_type} [{log.resource_id}]
                    </td>
                    <td className="py-3 px-4 text-xs text-muted-foreground max-w-md truncate">
                      {log.details}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-muted-foreground text-right">
                      {log.client_ip}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal: Restore Cluster */}
      {showRestoreModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm">
          <div className="w-full max-w-2xl rounded-2xl border border-border bg-card p-6 shadow-2xl relative animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between pb-4 border-b border-border/60">
              <div className="flex items-center gap-2 text-foreground font-bold text-lg">
                <Upload className="w-5 h-5 text-emerald-400" />
                Restore Cluster Configuration from Backup
              </div>
              <button 
                onClick={() => setShowRestoreModal(false)}
                className="text-muted-foreground hover:text-foreground p-1 rounded-lg"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleRestoreBackup} className="space-y-4 pt-4">
              <div>
                <label className="block text-xs font-bold text-foreground uppercase tracking-wider mb-1.5">
                  Paste Disaster Recovery JSON Bundle
                </label>
                <textarea
                  rows={8}
                  required
                  value={restoreJSON}
                  onChange={(e) => setRestoreJSON(e.target.value)}
                  placeholder='{"backup_version": "1.0.0", "applications": [...], "custom_rules": [...] }'
                  className="w-full rounded-lg border border-border bg-black/40 p-3 text-xs font-mono text-emerald-300 focus:outline-none focus:ring-1 focus:ring-emerald-400"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-border/60">
                <button
                  type="button"
                  onClick={() => setShowRestoreModal(false)}
                  className="px-4 py-2 rounded-lg border border-border hover:bg-secondary text-sm font-medium transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={restoring}
                  className="px-5 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-bold text-sm transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50"
                >
                  {restoring ? "Restoring..." : "Execute DR Restore & Sync xDS"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}


"use client";

import React, { useState, useEffect } from "react";
import { format } from "date-fns";
import { 
  Flame, 
  RefreshCw, 
  ShieldAlert, 
  CheckCircle2, 
  AlertCircle, 
  Search, 
  Filter, 
  Ban, 
  Clock, 
  ArrowRight, 
  X, 
  Shield, 
  Activity,
  Layers
} from "lucide-react";

interface Incident {
  id: number;
  inc_number: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  status: "INVESTIGATING" | "ACKNOWLEDGED" | "MITIGATED" | "RESOLVED";
  source_ip: string;
  target_app: string;
  event_count: number;
  mitigation_action: string;
  first_seen: string;
  last_seen: string;
}

interface SecurityEvent {
  id: number;
  request_id: string;
  timestamp: string;
  rule_id: string;
  severity: string;
  action: string;
  client_ip: string;
  path: string;
}

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [filterQuery, setFilterQuery] = useState("");
  const [filterStatus, setFilterStatus] = useState("ALL");
  const [notification, setNotification] = useState<{ type: "success" | "error" | null; message: string }>({ type: null, message: "" });

  // Timeline Drawer
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [timelineEvents, setTimelineEvents] = useState<SecurityEvent[]>([]);
  const [timelineLoading, setTimelineLoading] = useState(false);

  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8082";

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/incidents`);
      if (res.ok) {
        const data = await res.json();
        setIncidents(data || []);
      }
    } catch (err) {
      console.error("Failed to fetch incidents:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const handleUpdateStatus = async (id: number, nextStatus: string) => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/incidents/${id}/status`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: nextStatus }),
      });
      if (res.ok) {
        setNotification({
          type: "success",
          message: `Incident status moved to ${nextStatus}.`,
        });
        fetchIncidents();
      }
    } catch (err) {
      setNotification({ type: "error", message: "Failed to update incident status." });
    } finally {
      setActionLoading(false);
    }
  };

  const handleBlockIP = async (ip: string, incNumber: string) => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/ip-block`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ip_address: ip,
          reason: `Auto-mitigation from Incident ${incNumber}`,
        }),
      });
      if (res.ok) {
        setNotification({
          type: "success",
          message: `Attacker IP ${ip} successfully blocked at Envoy edge via xDS!`,
        });
        fetchIncidents();
      }
    } catch (err) {
      setNotification({ type: "error", message: "Failed to block attacker IP." });
    } finally {
      setActionLoading(false);
    }
  };

  const openTimeline = async (inc: Incident) => {
    setSelectedIncident(inc);
    setTimelineLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/incidents/${inc.id}/timeline`);
      if (res.ok) {
        const events = await res.json();
        setTimelineEvents(events || []);
      }
    } catch (err) {
      console.error("Failed to fetch incident timeline:", err);
    } finally {
      setTimelineLoading(false);
    }
  };

  const filteredIncidents = incidents.filter((inc) => {
    const matchesQuery =
      inc.inc_number.toLowerCase().includes(filterQuery.toLowerCase()) ||
      inc.title.toLowerCase().includes(filterQuery.toLowerCase()) ||
      inc.source_ip.toLowerCase().includes(filterQuery.toLowerCase());
    const matchesStatus = filterStatus === "ALL" || inc.status === filterStatus;
    return matchesQuery && matchesStatus;
  });

  const activeCount = incidents.filter((i) => i.status === "INVESTIGATING" || i.status === "ACKNOWLEDGED").length;
  const criticalCount = incidents.filter((i) => i.severity === "CRITICAL" || i.severity === "HIGH").length;
  const mitigatedCount = incidents.filter((i) => i.status === "MITIGATED" || i.status === "RESOLVED").length;
  const totalEventsCorrelated = incidents.reduce((acc, i) => acc + (i.event_count || 0), 0);

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case "CRITICAL":
        return "bg-rose-500/10 text-rose-400 border-rose-500/20";
      case "HIGH":
        return "bg-red-500/10 text-red-400 border-red-500/20";
      case "MEDIUM":
        return "bg-amber-500/10 text-amber-400 border-amber-500/20";
      default:
        return "bg-blue-500/10 text-blue-400 border-blue-500/20";
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "INVESTIGATING":
        return "bg-red-500/10 text-red-400 border-red-500/20 animate-pulse";
      case "ACKNOWLEDGED":
        return "bg-amber-500/10 text-amber-400 border-amber-500/20";
      case "MITIGATED":
        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/20";
      case "RESOLVED":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
      default:
        return "bg-secondary text-muted-foreground border-border";
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Flame className="w-8 h-8 text-rose-500" />
            <h1 className="text-3xl font-bold tracking-tight">SOC Incident Management</h1>
          </div>
          <p className="text-muted-foreground mt-1">
            Correlate isolated WAF security events into multi-vector attack campaigns and execute instant SOC response.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={fetchIncidents}
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
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="glass-panel p-4 rounded-xl border border-border flex items-center gap-4">
          <div className="p-3 bg-rose-500/10 rounded-lg text-rose-400">
            <Flame className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-muted-foreground uppercase font-semibold">Active Incidents</div>
            <div className="text-2xl font-bold text-rose-400">{activeCount}</div>
          </div>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-border flex items-center gap-4">
          <div className="p-3 bg-red-500/10 rounded-lg text-red-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-muted-foreground uppercase font-semibold">High / Critical</div>
            <div className="text-2xl font-bold text-red-400">{criticalCount}</div>
          </div>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-border flex items-center gap-4">
          <div className="p-3 bg-emerald-500/10 rounded-lg text-emerald-400">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-muted-foreground uppercase font-semibold">Mitigated / Resolved</div>
            <div className="text-2xl font-bold text-emerald-400">{mitigatedCount}</div>
          </div>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-border flex items-center gap-4">
          <div className="p-3 bg-cyan-500/10 rounded-lg text-cyan-400">
            <Layers className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-muted-foreground uppercase font-semibold">Correlated Events</div>
            <div className="text-2xl font-bold text-cyan-400">{totalEventsCorrelated.toLocaleString()}</div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="glass-panel p-4 rounded-xl border border-border flex flex-col sm:flex-row gap-4 justify-between items-center">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by INC ID, IP, or title..."
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
            className="w-full bg-secondary/40 border border-border rounded-lg pl-9 pr-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-rose-500"
          />
        </div>
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-4 h-4 text-muted-foreground" />
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="bg-secondary/40 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-rose-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="ACKNOWLEDGED">Acknowledged</option>
            <option value="MITIGATED">Mitigated</option>
            <option value="RESOLVED">Resolved</option>
          </select>
        </div>
      </div>

      {/* Incidents Table */}
      <div className="glass-panel rounded-xl overflow-hidden border border-border">
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-muted-foreground uppercase bg-secondary/50 border-b border-border">
              <tr>
                <th className="px-6 py-4 font-semibold tracking-wider">Incident ID</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Severity</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Campaign Title & Pattern</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Attacker IP</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Events</th>
                <th className="px-6 py-4 font-semibold tracking-wider">SOC Status</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Last Activity</th>
                <th className="px-6 py-4 font-semibold tracking-wider text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50">
              {loading && incidents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-6 py-12 text-center text-muted-foreground">
                    Correlating security events into incident campaigns...
                  </td>
                </tr>
              ) : filteredIncidents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-6 py-12 text-center text-muted-foreground">
                    No matching incidents found. System is quiet and protected.
                  </td>
                </tr>
              ) : (
                filteredIncidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-secondary/40 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap font-mono font-bold text-xs text-rose-400">
                      {inc.inc_number}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded-md text-xs font-semibold border ${getSeverityBadge(inc.severity)}`}>
                        {inc.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="font-medium text-foreground">{inc.title}</div>
                      <div className="text-xs text-muted-foreground mt-0.5">{inc.target_app}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap font-mono text-xs">
                      <div className="flex items-center gap-2">
                        <span className="text-foreground">{inc.source_ip}</span>
                        <button
                          onClick={() => handleBlockIP(inc.source_ip, inc.inc_number)}
                          disabled={actionLoading}
                          title="Instantly block IP at Envoy xDS edge"
                          className="px-2 py-0.5 text-xs bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20 rounded transition-colors"
                        >
                          <Ban className="w-3 h-3 inline mr-1" />
                          Block
                        </button>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap font-mono text-xs font-semibold text-rose-400">
                      {inc.event_count} attacks
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <select
                        value={inc.status}
                        onChange={(e) => handleUpdateStatus(inc.id, e.target.value)}
                        className={`text-xs font-semibold rounded-full px-2.5 py-1 border bg-secondary/80 focus:outline-none ${getStatusBadge(inc.status)}`}
                      >
                        <option value="INVESTIGATING">INVESTIGATING</option>
                        <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
                        <option value="MITIGATED">MITIGATED</option>
                        <option value="RESOLVED">RESOLVED</option>
                      </select>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-xs text-muted-foreground">
                      {format(new Date(inc.last_seen), "MMM dd, HH:mm:ss")}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      <button
                        onClick={() => openTimeline(inc)}
                        className="px-3 py-1.5 rounded-lg text-xs font-medium bg-secondary text-foreground hover:bg-secondary/70 border border-border transition-colors inline-flex items-center gap-1.5"
                      >
                        <Clock className="w-3.5 h-3.5 text-cyan-400" />
                        Timeline
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Timeline Drawer */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 bg-black/70 flex justify-end">
          <div className="bg-card border-l border-border w-full max-w-xl h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-300">
            {/* Drawer Header */}
            <div className="p-6 border-b border-border flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold text-rose-400">{selectedIncident.inc_number}</span>
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${getSeverityBadge(selectedIncident.severity)}`}>
                    {selectedIncident.severity}
                  </span>
                </div>
                <h3 className="text-lg font-bold mt-1">{selectedIncident.title}</h3>
                <div className="text-xs text-muted-foreground mt-1">
                  Source: <span className="font-mono text-foreground">{selectedIncident.source_ip}</span> • Total events: {selectedIncident.event_count}
                </div>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="p-2 rounded-lg hover:bg-secondary text-muted-foreground hover:text-foreground"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Timeline Stream */}
            <div className="flex-1 overflow-y-auto p-6 space-y-4">
              <h4 className="text-xs uppercase font-semibold text-muted-foreground tracking-wider flex items-center gap-1.5">
                <Activity className="w-4 h-4 text-rose-400" />
                Attacker Event Stream
              </h4>

              {timelineLoading ? (
                <div className="py-12 text-center text-muted-foreground">Loading attack telemetry...</div>
              ) : timelineEvents.length === 0 ? (
                <div className="py-12 text-center text-muted-foreground">No granular event logs available for this source IP.</div>
              ) : (
                <div className="relative border-l-2 border-border/80 ml-3 space-y-6">
                  {timelineEvents.map((ev, idx) => (
                    <div key={ev.id || idx} className="relative pl-6">
                      <div className="absolute -left-1.5 top-1 w-3 h-3 rounded-full bg-rose-500 ring-4 ring-background" />
                      <div className="glass-panel p-3 rounded-lg border border-border space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-mono text-cyan-400">{ev.path}</span>
                          <span className="text-muted-foreground">
                            {format(new Date(ev.timestamp), "HH:mm:ss.SSS")}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 text-xs">
                          <span className="font-semibold text-foreground">Rule: {ev.rule_id}</span>
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/20">
                            {ev.action}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Drawer Footer Actions */}
            <div className="p-4 border-t border-border bg-secondary/20 flex items-center justify-between">
              <button
                onClick={() => handleBlockIP(selectedIncident.source_ip, selectedIncident.inc_number)}
                disabled={actionLoading}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold"
              >
                <Ban className="w-4 h-4" />
                Block Attacker IP ({selectedIncident.source_ip})
              </button>
              <button
                onClick={() => handleUpdateStatus(selectedIncident.id, "RESOLVED")}
                disabled={actionLoading}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold"
              >
                <CheckCircle2 className="w-4 h-4" />
                Resolve Incident
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

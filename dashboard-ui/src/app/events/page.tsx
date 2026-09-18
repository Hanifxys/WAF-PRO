"use client";

import React, { useState, useEffect } from "react";
import { format } from "date-fns";
import { ShieldAlert, Eye, Server, Activity, Search, Ban, X, CheckCircle2, AlertCircle, Mail, Send, ChevronDown, Check, FileText, CheckCheck, Sliders } from "lucide-react";

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

interface EventDetail extends SecurityEvent {
  raw_log?: any;
}

export default function EventsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedEvent, setSelectedEvent] = useState<EventDetail | null>(null);
  const [modalLoading, setModalLoading] = useState(false);
  const [blockingIP, setBlockingIP] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ type: "success" | "error" | null; message: string }>({ type: null, message: "" });
  
  // Phase 11: F5 ASM & Telkomsel Risk Acceptance State
  const [viewMode, setViewMode] = useState<"basic" | "all">("basic");
  const [showRiskModal, setShowRiskModal] = useState(false);
  const [sendingEmail, setSendingEmail] = useState(false);

  // Usability Pack: 1-Click Rule Exception Wizard State
  const [showExceptionWizard, setShowExceptionWizard] = useState(false);
  const [exceptionScope, setExceptionScope] = useState<"PATH_ONLY" | "TARGET" | "GLOBAL">("PATH_ONLY");
  const [exceptionTTL, setExceptionTTL] = useState<number>(86400); // 24h default
  const [creatingException, setCreatingException] = useState(false);
  const [riskForm, setRiskForm] = useState({
    crq_number: "CRQ000000858920",
    rlm_number: "RLM000000413504",
    app_name: "RMS AJAKTEMAN",
    policy_name: "WAF_RMS_AJAKTEMAN",
    recipient: "tower-app-lead@telkomsel.co.id",
    cc: "CSOP-L, CSOP-IT-WAF-L, MO ITSecOps Network <mo_itsecops_network@metrocom.co.id>, NetSecPlat-L",
    reason: "Activity Enable Full Blocking RMS AJAKTEMAN",
  });

  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8082";

  const fetchEvents = async () => {
    try {
      const res = await fetch(`${API}/api/v1/events`);
      if (res.ok) {
        const data = await res.json();
        setEvents(data || []);
      }
    } catch (err) {
      console.error("Failed to fetch events:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
    const interval = setInterval(fetchEvents, 5000);
    return () => clearInterval(interval);
  }, []);

  const openEventDetail = async (id: number) => {
    setModalLoading(true);
    setViewMode("basic");
    setShowRiskModal(false);
    try {
      const res = await fetch(`${API}/api/v1/events/${id}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedEvent(data);
      }
    } catch (err) {
      console.error("Failed to fetch event detail:", err);
    } finally {
      setModalLoading(false);
    }
  };

  const handleQuickBlock = async (ip: string) => {
    if (!confirm(`Block IP ${ip} immediately across Envoy data-plane?`)) return;

    setBlockingIP(ip);
    setNotification({ type: null, message: "" });
    try {
      const res = await fetch(`${API}/api/v1/ip-block`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ip_address: ip,
          reason: `L2 SOC manual block from Security Events Feed (Auto-block)`,
        }),
      });

      if (res.ok) {
        setNotification({ type: "success", message: `IP ${ip} blocked instantly and updated in Envoy xDS!` });
      } else {
        setNotification({ type: "error", message: `Failed to block IP ${ip}.` });
      }
    } catch (err) {
      setNotification({ type: "error", message: "Network error occurred." });
    } finally {
      setBlockingIP(null);
    }
  };

  const handleSendRiskAcceptanceEmail = async () => {
    if (!selectedEvent) return;
    setSendingEmail(true);
    try {
      const res = await fetch(`${API}/api/v1/alerts/risk-acceptance`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          event_id: selectedEvent.id.toString(),
          crq_number: riskForm.crq_number,
          rlm_number: riskForm.rlm_number,
          app_name: riskForm.app_name,
          policy_name: riskForm.policy_name,
          recipient: riskForm.recipient,
          cc: riskForm.cc,
          reason: riskForm.reason,
          send_email: true,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setNotification({
          type: "success",
          message: `Email Risk Acceptance (Telkomsel CSOP-IT-WAF) dispatched successfully! Delivery Mode: ${data.delivery_mode}`,
        });
        setShowRiskModal(false);
      } else {
        setNotification({ type: "error", message: "Failed to dispatch Risk Acceptance email." });
      }
    } catch (err) {
      setNotification({ type: "error", message: "Network error during email dispatch." });
    } finally {
      setSendingEmail(false);
    }
  };

  const handleAutoGenerateException = async () => {
    if (!selectedEvent) return;
    setCreatingException(true);
    setNotification({ type: null, message: "" });
    try {
      const res = await fetch(`${API}/api/v1/exceptions/auto-generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          event_id: selectedEvent.id,
          scope: exceptionScope,
          ttl_seconds: exceptionTTL,
          reason: `Auto-generated 1-click exception from Event #${selectedEvent.id} (${selectedEvent.path})`,
          ticket_ref: riskForm.crq_number || `CRQ-AUTO-${selectedEvent.id}`,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setNotification({
          type: "success",
          message: `Rule exception active! Target Rule #${selectedEvent.rule_id} whitelisted on ${data.applied_scope} with TTL ${exceptionTTL > 0 ? exceptionTTL / 3600 + "h" : "Permanent"}. xDS updated in Envoy!`,
        });
        setShowExceptionWizard(false);
        setSelectedEvent(null);
      } else {
        setNotification({ type: "error", message: "Failed to generate rule exception." });
      }
    } catch (err) {
      setNotification({ type: "error", message: "Network error during exception creation." });
    } finally {
      setCreatingException(false);
    }
  };

  // Helper to deduce detection cause from Coraza logs
  const getDetectionCause = (event: EventDetail) => {
    if (event.raw_log?.messages?.[0]?.message) {
      return event.raw_log.messages[0].message;
    }
    if (event.rule_id?.startsWith("942")) return "SQL Injection Attack Signature";
    if (event.rule_id?.startsWith("941")) return "XSS Attack Signature";
    if (event.rule_id?.startsWith("930")) return "Directory Traversal Attack Signature";
    if (event.rule_id?.startsWith("932")) return "Unix/Linux Command Execution attempt";
    if (event.rule_id?.startsWith("920")) return "Illegal URL / Protocol Violation";
    return "OWASP CRS Security Policy Violation";
  };

  const filteredEvents = events.filter((e) => {
    const q = searchQuery.toLowerCase();
    return (
      e.client_ip.toLowerCase().includes(q) ||
      e.path.toLowerCase().includes(q) ||
      e.rule_id.toLowerCase().includes(q) ||
      e.action.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div className="flex flex-col gap-1">
          <h1 className="text-3xl font-bold tracking-tight">Security Events & Incident Console</h1>
          <p className="text-muted-foreground">
            Enterprise WAF real-time violation monitoring, F5 ASM incident inspector, and Telkomsel CSOP alerting.
          </p>
        </div>
        
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input 
              type="text" 
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by IP, Rule, Path..." 
              className="bg-secondary/30 border border-border rounded-lg pl-9 pr-4 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-emerald-500 w-full sm:w-64"
            />
          </div>
        </div>
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

      <div className="glass-panel rounded-xl overflow-hidden border border-border">
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-muted-foreground uppercase bg-secondary/50 border-b border-border">
              <tr>
                <th className="px-6 py-4 font-semibold tracking-wider">Time</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Action</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Rule ID</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Client IP</th>
                <th className="px-6 py-4 font-semibold tracking-wider">Path</th>
                <th className="px-6 py-4 font-semibold tracking-wider text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50">
              {loading && events.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-muted-foreground">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <Activity className="w-6 h-6 animate-pulse text-emerald-500" />
                      <span>Loading events...</span>
                    </div>
                  </td>
                </tr>
              ) : filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-muted-foreground">
                    No security events matching filter.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((event) => (
                  <tr key={event.id} className="hover:bg-secondary/40 transition-colors group">
                    <td className="px-6 py-4 whitespace-nowrap text-muted-foreground">
                      {format(new Date(event.timestamp), "MMM dd, HH:mm:ss")}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${
                        event.action === 'BLOCKED' 
                          ? 'bg-red-500/10 text-red-400 border-red-500/20' 
                          : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      }`}>
                        {event.action}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap font-mono text-xs">
                      {event.rule_id}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <Server className="w-3.5 h-3.5 text-muted-foreground" />
                        <span className="font-mono text-xs">{event.client_ip}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-muted-foreground truncate max-w-[200px]" title={event.path}>
                      {event.path}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right flex items-center justify-end gap-2">
                      <button
                        onClick={() => handleQuickBlock(event.client_ip)}
                        disabled={blockingIP === event.client_ip}
                        title="Quick Block IP"
                        className="p-1.5 rounded-md hover:bg-red-500/20 text-muted-foreground hover:text-red-400 transition-colors"
                      >
                        <Ban className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => openEventDetail(event.id)}
                        title="View F5 ASM Violation Details"
                        className="p-1.5 rounded-md hover:bg-emerald-500/20 text-muted-foreground hover:text-emerald-400 transition-colors"
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

      {/* F5 BIG-IP ASM Style Event Violation Inspector Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#10141d] border border-blue-500/30 rounded-xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden shadow-2xl animate-in zoom-in-95 duration-200">
            {/* F5 Top Header Bar */}
            <div className="p-4 border-b border-border/70 flex items-center justify-between bg-[#151b28]">
              <div className="flex items-center gap-3">
                <div className="w-3 h-3 rounded-full bg-red-500 animate-pulse" />
                <h3 className="font-bold text-sm tracking-wide text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-red-400" />
                  F5 ASM Violation Inspector — Event #{selectedEvent.id}
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <div className="flex bg-secondary/80 rounded-md p-0.5 border border-border">
                  <button
                    onClick={() => setViewMode("basic")}
                    className={`px-3 py-1 text-xs font-semibold rounded ${viewMode === 'basic' ? 'bg-blue-600 text-white shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
                  >
                    Basic
                  </button>
                  <button
                    onClick={() => setViewMode("all")}
                    className={`px-3 py-1 text-xs font-semibold rounded ${viewMode === 'all' ? 'bg-blue-600 text-white shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
                  >
                    All Details
                  </button>
                </div>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="p-1.5 rounded-md hover:bg-secondary text-muted-foreground hover:text-foreground ml-2"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-5 text-sm">
              {/* F5 Triggered Violation Box */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-blue-400 font-bold text-base">
                    <ChevronDown className="w-5 h-5 text-blue-400" />
                    <span>1 Triggered Violation</span>
                    <div className="flex items-center gap-1 ml-2">
                      <span className="text-xs text-muted-foreground font-mono">3</span>
                      <span className="w-2.5 h-3 bg-amber-400 rounded-xs inline-block"></span>
                      <span className="w-2.5 h-3 bg-amber-400 rounded-xs inline-block"></span>
                      <span className="w-2.5 h-3 bg-amber-400 rounded-xs inline-block"></span>
                      <span className="w-2.5 h-3 bg-gray-600 rounded-xs inline-block"></span>
                    </div>
                  </div>
                  <span className="text-xs text-blue-400 font-medium cursor-pointer hover:underline flex items-center gap-1">
                    1 Occurrence <ChevronDown className="w-3 h-3" />
                  </span>
                </div>

                {/* Sub-card Popover Style */}
                <div className="p-4 rounded-lg bg-[#182030] border border-blue-500/20 space-y-2">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                    <div>
                      <span className="text-muted-foreground block font-semibold mb-0.5">Requested URL</span>
                      <span className="font-mono text-emerald-400 break-all">[HTTP] GET {selectedEvent.path}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground block font-semibold mb-0.5">Detection Cause</span>
                      <span className="font-semibold text-amber-300">{getDetectionCause(selectedEvent)}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground block font-semibold mb-0.5">Applied Blocking Settings</span>
                      <div className="flex items-center gap-3 font-semibold text-xs text-white">
                        <span className="flex items-center gap-1 text-red-400"><Check className="w-3.5 h-3.5" /> Block</span>
                        <span className="flex items-center gap-1 text-amber-400"><Check className="w-3.5 h-3.5" /> Alarm</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {viewMode === "basic" ? (
                /* F5 2-Column Details Table */
                <div className="space-y-3">
                  <h4 className="text-xs font-bold text-muted-foreground uppercase tracking-wider flex items-center gap-2">
                    <ChevronDown className="w-4 h-4 text-blue-400" />
                    Request Details
                  </h4>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6 p-4 rounded-lg bg-[#151b28]/60 border border-border text-xs">
                    {/* Left Column */}
                    <div className="divide-y divide-border/40">
                      <div className="py-2.5 flex justify-between items-center">
                        <span className="text-muted-foreground font-semibold">Requested URL</span>
                        <span className="font-mono text-white text-right max-w-xs truncate" title={selectedEvent.path}>
                          {selectedEvent.path}
                        </span>
                      </div>
                      <div className="py-2.5 flex justify-between items-center">
                        <span className="text-muted-foreground font-semibold">Host</span>
                        <span className="font-mono text-white">api.rms-ajakteman.telkomsel.co.id</span>
                      </div>
                      <div className="py-2.5 flex justify-between items-center">
                        <span className="text-muted-foreground font-semibold">Time</span>
                        <span className="font-mono text-white">
                          {format(new Date(selectedEvent.timestamp), "yyyy-MM-dd HH:mm:ss")}
                        </span>
                      </div>
                      <div className="py-2.5 flex justify-between items-center">
                        <span className="text-muted-foreground font-semibold">Geolocation</span>
                        <span className="font-semibold text-white flex items-center gap-1.5">
                          <span className="text-base">🇮🇩</span> Indonesia
                        </span>
                      </div>
                      <div className="py-2.5 flex justify-between items-center">
                        <span className="text-muted-foreground font-semibold">Source IP Address</span>
                        <span className="font-mono text-emerald-400 font-bold">{selectedEvent.client_ip}:5381</span>
                      </div>
                    </div>

                    {/* Right Column */}
                    <div className="divide-y divide-border/40">
                      <div className="py-2.5 flex justify-between items-center">
                        <span className="text-muted-foreground font-semibold">Request Status</span>
                        <span className="flex items-center gap-1.5 font-bold text-red-400">
                          <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block"></span>
                          {selectedEvent.action === 'BLOCKED' ? 'Blocked' : 'Allowed'}
                        </span>
                      </div>
                      <div className="py-2.5 flex justify-between items-center">
                        <span className="text-muted-foreground font-semibold">Enforcement Action</span>
                        <span className="font-semibold text-white">Block</span>
                      </div>
                      <div className="py-2.5 flex justify-between items-center">
                        <span className="text-muted-foreground font-semibold">Virtual Server</span>
                        <span className="font-mono text-blue-400 font-semibold cursor-pointer hover:underline">VS_RMS_AJAKTEMAN</span>
                      </div>
                      <div className="py-2.5 flex justify-between items-center">
                        <span className="text-muted-foreground font-semibold">Security Policy</span>
                        <span className="font-mono text-blue-400 font-semibold cursor-pointer hover:underline">WAF_RMS_AJAKTEMAN</span>
                      </div>
                      <div className="py-2.5 flex justify-between items-center">
                        <span className="text-muted-foreground font-semibold">Microservice</span>
                        <span className="font-mono text-muted-foreground">N/A</span>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                /* All Details View (Raw Audit Log) */
                <div className="space-y-2">
                  <div className="flex justify-between items-center">
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider block">
                      Raw Coraza WASM Transaction JSON
                    </label>
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                      RFC-ModSec Compatible
                    </span>
                  </div>
                  <pre className="p-4 bg-background/90 rounded-lg font-mono text-xs border border-border overflow-x-auto text-emerald-300 max-h-72">
                    {JSON.stringify(selectedEvent.raw_log, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            {/* Modal Footer Actions */}
            <div className="p-4 border-t border-border flex items-center justify-between bg-[#151b28]">
              <div className="flex items-center gap-2 flex-wrap">
                {/* Telkomsel CSOP Risk Acceptance Trigger Button */}
                <button
                  onClick={() => setShowRiskModal(true)}
                  className="flex items-center gap-2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs font-semibold py-2 px-3.5 rounded-lg shadow-md transition-all"
                >
                  <Mail className="w-4 h-4 text-blue-200" />
                  Kirim Risk Acceptance Email (Telkomsel CSOP)
                </button>

                <button
                  onClick={() => handleQuickBlock(selectedEvent.client_ip)}
                  className="flex items-center gap-2 bg-red-600/80 hover:bg-red-600 text-white text-xs font-semibold py-2 px-3 rounded-lg transition-colors"
                >
                  <Ban className="w-3.5 h-3.5" />
                  Block IP {selectedEvent.client_ip}
                </button>

                {selectedEvent.rule_id && selectedEvent.rule_id !== "0" && (
                  <button
                    onClick={() => setShowExceptionWizard(true)}
                    className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 text-black text-xs font-bold py-2 px-3.5 rounded-lg shadow-md transition-all"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5 text-black" />
                    1-Click Exception Wizard
                  </button>
                )}

                {selectedEvent.rule_id && selectedEvent.rule_id !== "0" && (
                  <button
                    onClick={() => {
                      // Open Granular Exception Wizard with pre-filled context
                      const params = new URLSearchParams({
                        rule_id: selectedEvent.rule_id,
                        path: selectedEvent.path || "/",
                        method: "ANY",
                      });
                      setSelectedEvent(null);
                      window.location.href = `/tuning?${params.toString()}`;
                    }}
                    className="flex items-center gap-1.5 bg-amber-600/80 hover:bg-amber-600 text-white text-xs font-semibold py-2 px-3 rounded-lg transition-colors"
                  >
                    <Sliders className="w-3.5 h-3.5" />
                    Tune FP — Rule #{selectedEvent.rule_id}
                  </button>
                )}
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-2 text-xs font-medium bg-secondary hover:bg-secondary/80 rounded-lg text-foreground border border-border"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 1-Click Rule Exception Wizard Modal */}
      {showExceptionWizard && selectedEvent && (
        <div className="fixed inset-0 z-60 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-[#121722] border border-emerald-500/40 rounded-xl w-full max-w-2xl overflow-hidden shadow-2xl animate-in zoom-in-95 duration-200">
            <div className="p-4 border-b border-border/70 flex items-center justify-between bg-[#151e2e]">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                <div>
                  <h3 className="font-bold text-sm text-white">1-Click Rule Exception Generator</h3>
                  <p className="text-[11px] text-muted-foreground">Automatically extract offending signature, path, and parameter to generate xDS bypass</p>
                </div>
              </div>
              <button
                onClick={() => setShowExceptionWizard(false)}
                className="p-1 rounded-md hover:bg-secondary text-muted-foreground hover:text-foreground text-sm"
              >
                ✕
              </button>
            </div>

            <div className="p-6 space-y-4 text-xs">
              <div className="p-3 bg-secondary/40 border border-border rounded-lg space-y-2 font-mono">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Target Rule ID:</span>
                  <span className="text-emerald-400 font-bold">CRS #{selectedEvent.rule_id}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Evaluation Path:</span>
                  <span className="text-foreground">{selectedEvent.path}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Offending Client:</span>
                  <span className="text-cyan-400">{selectedEvent.client_ip}</span>
                </div>
              </div>

              {/* Scope Selection */}
              <div>
                <label className="text-xs font-semibold text-foreground block mb-1.5">Bypass Scope</label>
                <div className="grid grid-cols-3 gap-2">
                  {[
                    { id: "PATH_ONLY", title: "Path Only", desc: "Whitelists rule for all queries on this path" },
                    { id: "TARGET", title: "Parameter Only", desc: "Whitelists rule only on specific parameter (ARGS:q)" },
                    { id: "GLOBAL", title: "Global Bypass", desc: "Completely disables rule across application" },
                  ].map((s) => (
                    <button
                      key={s.id}
                      type="button"
                      onClick={() => setExceptionScope(s.id as any)}
                      className={`p-3 rounded-lg border text-left transition-all ${
                        exceptionScope === s.id
                          ? "bg-emerald-500/10 border-emerald-500/50 text-emerald-300"
                          : "bg-secondary/30 border-border text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      <div className="font-bold text-xs">{s.title}</div>
                      <div className="text-[10px] mt-1 opacity-80">{s.desc}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* TTL Selection */}
              <div>
                <label className="text-xs font-semibold text-foreground block mb-1.5">Time-To-Live (Auto-Expiry)</label>
                <div className="grid grid-cols-3 gap-2 font-mono text-xs">
                  {[
                    { sec: 86400, label: "24 Hours (Temp)" },
                    { sec: 604800, label: "7 Days (Sprint)" },
                    { sec: 0, label: "Permanent" },
                  ].map((t) => (
                    <button
                      key={t.sec}
                      type="button"
                      onClick={() => setExceptionTTL(t.sec)}
                      className={`py-2 rounded-lg border text-center transition-all ${
                        exceptionTTL === t.sec
                          ? "bg-cyan-500/10 border-cyan-500/50 text-cyan-300 font-bold"
                          : "bg-secondary/30 border-border text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      {t.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-emerald-300 text-[11px]">
                Upon confirmation, an xDS config snapshot will be compiled and distributed to all Envoy workers without proxy reload or traffic interruption.
              </div>
            </div>

            <div className="p-4 border-t border-border flex items-center justify-end gap-2 bg-[#151e2e]">
              <button
                onClick={() => setShowExceptionWizard(false)}
                className="px-4 py-2 text-xs font-medium bg-secondary hover:bg-secondary/80 rounded-lg text-foreground border border-border"
              >
                Cancel
              </button>
              <button
                onClick={handleAutoGenerateException}
                disabled={creatingException}
                className="flex items-center gap-1.5 bg-emerald-500 hover:bg-emerald-600 text-black text-xs font-bold py-2 px-4 rounded-lg shadow-md transition-colors"
              >
                <CheckCircle2 className="w-4 h-4" />
                {creatingException ? "Compiling xDS..." : "Generate Exception & Deploy"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Telkomsel CSOP-IT-WAF Risk Acceptance Email Modal */}
      {showRiskModal && selectedEvent && (
        <div className="fixed inset-0 z-60 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-[#121722] border border-blue-500/40 rounded-xl w-full max-w-3xl max-h-[90vh] flex flex-col overflow-hidden shadow-2xl animate-in zoom-in-95 duration-200">
            <div className="p-4 border-b border-border/70 flex items-center justify-between bg-[#182133]">
              <div className="flex items-center gap-2">
                <Mail className="w-5 h-5 text-blue-400" />
                <div>
                  <h3 className="font-bold text-sm text-white">Telkomsel CSOP-IT-WAF — Form Risk Acceptance Email</h3>
                  <p className="text-[11px] text-muted-foreground">Standardized incident dispatch workflow (CRQ tracking & 3-day SLA policy)</p>
                </div>
              </div>
              <button
                onClick={() => setShowRiskModal(false)}
                className="p-1 rounded-md hover:bg-secondary text-muted-foreground hover:text-foreground"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-4 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-muted-foreground font-semibold block mb-1">CRQ Reference Number</label>
                  <input
                    type="text"
                    value={riskForm.crq_number}
                    onChange={(e) => setRiskForm({ ...riskForm, crq_number: e.target.value })}
                    className="w-full bg-[#182030] border border-border rounded-lg px-3 py-2 font-mono text-xs text-white"
                  />
                </div>
                <div>
                  <label className="text-muted-foreground font-semibold block mb-1">RLM Ticket Number</label>
                  <input
                    type="text"
                    value={riskForm.rlm_number}
                    onChange={(e) => setRiskForm({ ...riskForm, rlm_number: e.target.value })}
                    className="w-full bg-[#182030] border border-border rounded-lg px-3 py-2 font-mono text-xs text-white"
                  />
                </div>
                <div>
                  <label className="text-muted-foreground font-semibold block mb-1">Recipient (Tower Application Lead)</label>
                  <input
                    type="email"
                    value={riskForm.recipient}
                    onChange={(e) => setRiskForm({ ...riskForm, recipient: e.target.value })}
                    className="w-full bg-[#182030] border border-border rounded-lg px-3 py-2 font-mono text-xs text-white"
                  />
                </div>
                <div>
                  <label className="text-muted-foreground font-semibold block mb-1">CC Recipients</label>
                  <input
                    type="text"
                    value={riskForm.cc}
                    onChange={(e) => setRiskForm({ ...riskForm, cc: e.target.value })}
                    className="w-full bg-[#182030] border border-border rounded-lg px-3 py-2 font-mono text-xs text-white"
                  />
                </div>
              </div>

              {/* Exact Telkomsel Email Preview Window */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-blue-400 uppercase tracking-wider flex items-center gap-1.5">
                  <FileText className="w-3.5 h-3.5" /> Pratinjau Email Resmi Telkomsel CSOP-IT-WAF:
                </label>
                <div className="p-4 bg-[#0a0d14] rounded-lg border border-border/80 font-mono text-[11px] leading-relaxed text-gray-200 whitespace-pre-wrap select-all">
{`Subject: Risk Acceptance Allow Specific Attack Signature in Specific Parameter Apps ${riskForm.app_name}

Berdasarkan Activity Enable Full Blocking ${riskForm.app_name} (${riskForm.crq_number} - ${riskForm.rlm_number}), dibutuhkan allow attack signature dengan detail:

Policy: ${riskForm.policy_name}
URI: ${selectedEvent.path}
Parameter: body
Attack Signature: ${getDetectionCause(selectedEvent)}
Sig ID: ${selectedEvent.rule_id}
Attack Type: Command Execution / Injection
Severity: High
Risk Description: Possible unauthorized administrative access to the server or application can result

Action: Allow Specific Attack Signature in Specific Parameter in URL

Jika tetap akan dilanjutkan untuk allow attack signature pada URL/Parameter tersebut, silahkan accept risk email ini beserta reason & justifikasi, dan segala risiko serangan yang berhubungan dengan fitur proteksi ini akan ditanggung sepenuhnya oleh tim Tower Aplikasi.

Jika email Risk Acceptance tidak di-accept dalam kurun waktu 3 hari kerja, maka attack signature akan kami enable kembali. Terima kasih.

Thank you.`}
                </div>
              </div>
            </div>

            <div className="p-4 border-t border-border flex items-center justify-between bg-[#182133]">
              <span className="text-[11px] text-muted-foreground">
                Dispatcher: <span className="text-blue-400 font-mono">csop-it-waf@telkomsel.co.id</span>
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowRiskModal(false)}
                  className="px-4 py-2 text-xs font-medium bg-secondary hover:bg-secondary/80 rounded-lg text-foreground border border-border"
                >
                  Batal
                </button>
                <button
                  onClick={handleSendRiskAcceptanceEmail}
                  disabled={sendingEmail}
                  className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold py-2 px-4 rounded-lg shadow-md transition-colors"
                >
                  <Send className={`w-3.5 h-3.5 ${sendingEmail ? 'animate-pulse' : ''}`} />
                  {sendingEmail ? "Mengirim..." : "Kirim Email Sekarang"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

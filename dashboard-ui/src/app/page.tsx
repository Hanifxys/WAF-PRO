"use client";

import { useEffect, useState } from "react";
import { Shield, ShieldAlert, Activity, ArrowUpRight, FileCode2, Clock, Ban, Zap, AlertTriangle } from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8082";

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

interface AnalyticsData {
  total_events: number;
  blocked_requests: number;
  allowed_requests: number;
  block_rate: number;
  top_attacking_ips: { ip: string; count: number }[];
  top_rules: { rule_id: string; count: number }[];
  attack_types: Record<string, number>;
  severity_split: Record<string, number>;
}

function timeAgo(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.floor(m / 60)}h ago`;
}

export default function Dashboard() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const [eventsRes, analyticsRes] = await Promise.all([
        fetch(`${API}/api/v1/events`),
        fetch(`${API}/api/v1/analytics/summary`),
      ]);
      if (eventsRes.ok) {
        const eventsData = await eventsRes.json();
        setEvents(eventsData || []);
      }
      if (analyticsRes.ok) {
        const analyticsData = await analyticsRes.json();
        setAnalytics(analyticsData);
      }
    } catch (err) {
      console.error("Failed to fetch dashboard data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const totalEvents = analytics?.total_events ?? events.length;
  const blockedEvents = analytics?.blocked_requests ?? events.filter((e) => e.action === "BLOCKED").length;
  const allowedEvents = analytics?.allowed_requests ?? (totalEvents - blockedEvents);
  const blockRate = analytics?.block_rate ?? (totalEvents > 0 ? (blockedEvents / totalEvents) * 100 : 0);

  const topRules = analytics?.top_rules || [];
  const topIPs = analytics?.top_attacking_ips || [];
  const attackTypes = Object.entries(analytics?.attack_types || {});
  const recentEvents = events.slice(0, 8);

  const handleQuickBlock = async (ip: string) => {
    if (!confirm(`Quick Block IP ${ip}?`)) return;
    try {
      await fetch(`${API}/api/v1/ip-block`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip_address: ip, reason: "Quick block from Overview" }),
      });
      fetchData();
    } catch (err) {
      console.error("Error blocking IP:", err);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight">Overview</h1>
        <p className="text-muted-foreground">
          Real-time enterprise WAF security posture and threat intelligence analytics.
        </p>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="glass-panel p-6 rounded-xl flex flex-col gap-4 relative overflow-hidden group hover:border-emerald-500/50 transition-colors">
          <div className="absolute -right-4 -top-4 w-24 h-24 bg-emerald-500/10 rounded-full blur-2xl group-hover:bg-emerald-500/20 transition-all" />
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Total Ingested Events</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex flex-col">
            <span className="text-3xl font-bold">{loading ? "—" : totalEvents.toLocaleString()}</span>
            <div className="flex items-center text-xs text-emerald-400 mt-1 font-medium">
              <ArrowUpRight className="w-3 h-3 mr-1" />
              <span>Vector Stream to PostgreSQL</span>
            </div>
          </div>
        </div>

        <div className="glass-panel p-6 rounded-xl flex flex-col gap-4 relative overflow-hidden group hover:border-red-500/50 transition-colors">
          <div className="absolute -right-4 -top-4 w-24 h-24 bg-red-500/10 rounded-full blur-2xl group-hover:bg-red-500/20 transition-all" />
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Threats Blocked</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="flex flex-col">
            <span className="text-3xl font-bold text-red-400">{loading ? "—" : blockedEvents.toLocaleString()}</span>
            <div className="flex items-center text-xs text-muted-foreground mt-1 font-medium">
              <span>{blockRate.toFixed(1)}% enforcement rate</span>
            </div>
          </div>
        </div>

        <div className="glass-panel p-6 rounded-xl flex flex-col gap-4 relative overflow-hidden group hover:border-blue-500/50 transition-colors">
          <div className="absolute -right-4 -top-4 w-24 h-24 bg-blue-500/10 rounded-full blur-2xl group-hover:bg-blue-500/20 transition-all" />
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Requests Passed</span>
            <Shield className="w-4 h-4 text-blue-400" />
          </div>
          <div className="flex flex-col">
            <span className="text-3xl font-bold text-blue-400">{loading ? "—" : allowedEvents.toLocaleString()}</span>
            <div className="flex items-center text-xs text-muted-foreground mt-1 font-medium">
              <span>OWASP CRS v4.0 Active</span>
            </div>
          </div>
        </div>
      </div>

      {/* Middle Row: Attack Category Distribution & Top Attacking IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Attack Categories */}
        <div className="glass-panel rounded-xl p-6 flex flex-col gap-4">
          <div className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-amber-400" />
            <h3 className="font-semibold text-lg">Attack Category Breakdown</h3>
          </div>
          {loading ? (
            <div className="flex items-center justify-center h-40 text-muted-foreground text-sm">
              Loading attack distribution...
            </div>
          ) : attackTypes.length === 0 ? (
            <div className="flex items-center justify-center h-40 border border-dashed border-border rounded-lg text-sm text-muted-foreground">
              No attack signatures classified yet.
            </div>
          ) : (
            <div className="space-y-3 mt-1">
              {attackTypes.map(([type, count]) => (
                <div key={type} className="flex items-center justify-between p-2.5 rounded-lg bg-secondary/30 border border-border/50 text-sm">
                  <span className="font-medium">{type}</span>
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                    {count} attacks
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top Attacking IPs */}
        <div className="glass-panel rounded-xl p-6 flex flex-col gap-4">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <h3 className="font-semibold text-lg">Top Attacking IP Addresses</h3>
          </div>
          {loading ? (
            <div className="flex items-center justify-center h-40 text-muted-foreground text-sm">
              Loading source IPs...
            </div>
          ) : topIPs.length === 0 ? (
            <div className="flex items-center justify-center h-40 border border-dashed border-border rounded-lg text-sm text-muted-foreground">
              No attacker IPs recorded yet.
            </div>
          ) : (
            <div className="space-y-3 mt-1">
              {topIPs.map((item) => (
                <div key={item.ip} className="flex items-center justify-between p-2.5 rounded-lg bg-secondary/30 border border-border/50 text-sm">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-medium text-red-400">{item.ip}</span>
                    <span className="text-xs text-muted-foreground">({item.count} events)</span>
                  </div>
                  <button
                    onClick={() => handleQuickBlock(item.ip)}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-red-600/80 hover:bg-red-600 text-white text-xs font-medium transition-colors"
                  >
                    <Ban className="w-3.5 h-3.5" />
                    Block
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Bottom panels */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Rules */}
        <div className="glass-panel rounded-xl p-6 flex flex-col gap-4">
          <div className="flex items-center gap-2">
            <FileCode2 className="w-5 h-5 text-emerald-400" />
            <h3 className="font-semibold text-lg">Top Triggered Rules</h3>
          </div>
          {loading ? (
            <div className="flex items-center justify-center h-32 text-muted-foreground text-sm">
              <Activity className="w-4 h-4 animate-pulse mr-2 text-emerald-500" />
              Loading...
            </div>
          ) : topRules.length === 0 ? (
            <div className="flex items-center justify-center h-32 border border-dashed border-border rounded-lg text-sm text-muted-foreground">
              No rule hits yet.
            </div>
          ) : (
            <div className="space-y-4 mt-1">
              {topRules.map((item, i) => {
                const colors = ["bg-red-500", "bg-orange-500", "bg-amber-500", "bg-yellow-500", "bg-blue-500"];
                const maxCount = topRules[0].count || 1;
                return (
                  <div key={item.rule_id} className="flex flex-col gap-1.5">
                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${colors[i % colors.length]}`} />
                        <span className="font-mono text-xs text-muted-foreground">Rule #{item.rule_id}</span>
                      </div>
                      <span className="font-mono font-medium">{item.count}</span>
                    </div>
                    <div className="w-full bg-secondary/50 rounded-full h-1.5">
                      <div
                        className={`${colors[i % colors.length]} h-1.5 rounded-full transition-all duration-500`}
                        style={{ width: `${(item.count / maxCount) * 100}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Recent Events */}
        <div className="glass-panel rounded-xl p-6 flex flex-col gap-4">
          <div className="flex items-center gap-2">
            <Clock className="w-5 h-5 text-emerald-400" />
            <h3 className="font-semibold text-lg">Recent Security Events</h3>
          </div>
          {loading ? (
            <div className="flex items-center justify-center h-32 text-muted-foreground text-sm">
              <Activity className="w-4 h-4 animate-pulse mr-2 text-emerald-500" />
              Loading...
            </div>
          ) : recentEvents.length === 0 ? (
            <div className="flex items-center justify-center h-32 border border-dashed border-border rounded-lg text-sm text-muted-foreground">
              No events yet.
            </div>
          ) : (
            <div className="space-y-2">
              {recentEvents.map((event) => (
                <div
                  key={event.id}
                  className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-secondary/40 transition-colors"
                >
                  <div className={`w-2 h-2 rounded-full shrink-0 ${event.action === "BLOCKED" ? "bg-red-500" : "bg-emerald-500"}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span
                        className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                          event.action === "BLOCKED"
                            ? "bg-red-500/15 text-red-400"
                            : "bg-emerald-500/15 text-emerald-400"
                        }`}
                      >
                        {event.action}
                      </span>
                      <span className="text-xs text-muted-foreground font-mono truncate">{event.path}</span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      {event.client_ip} · Rule #{event.rule_id}
                    </p>
                  </div>
                  <span className="text-[11px] text-muted-foreground shrink-0">{timeAgo(event.timestamp)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


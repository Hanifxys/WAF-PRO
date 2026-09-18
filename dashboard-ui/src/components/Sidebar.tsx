"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { LayoutDashboard, ShieldAlert, Settings, Activity, FileCode2, Ban, Globe, Sliders, Gauge, ShieldCheck, Lock, Network, Flame, Bot, FlaskConical, Bell, History, Radar, KeyRound, Share2, BadgeCheck, Waves, ScrollText, Binary, Server, Sparkles, Building2, TrendingUp } from "lucide-react";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const navItems = [
  { name: "Dashboard", href: "/", icon: LayoutDashboard },
  { name: "App Wizard", href: "/onboarding", icon: Sparkles },
  { name: "Applications", href: "/applications", icon: Globe },
  { name: "Tenants", href: "/tenants", icon: Building2 },
  { name: "Capacity", href: "/capacity", icon: TrendingUp },
  { name: "API Security", href: "/api-security", icon: Network },
  { name: "Incidents", href: "/incidents", icon: Flame },
  { name: "Threat Intel", href: "/threat-intel", icon: Radar },
  { name: "Bot Shield", href: "/bot-management", icon: Bot },
  { name: "Simulator", href: "/simulator", icon: FlaskConical },
  { name: "Events", href: "/events", icon: ShieldAlert },
  { name: "Blocked IPs", href: "/blocked-ips", icon: Ban },
  { name: "Rule Tuning", href: "/tuning", icon: Sliders },
  { name: "Rate Limits", href: "/rate-limits", icon: Gauge },
  { name: "DDoS Shield", href: "/ddos-protection", icon: Waves },
  { name: "Protocol Shield", href: "/protocol-shield", icon: Binary },
  { name: "Cluster Nodes", href: "/cluster-nodes", icon: Server },
  { name: "Policy Studio", href: "/policy-studio", icon: ShieldCheck },
  { name: "DLP Protection", href: "/dlp", icon: Lock },
  { name: "Rules", href: "/rules", icon: FileCode2 },
  { name: "Alert Rules", href: "/alerts", icon: Bell },
  { name: "Config History", href: "/config-history", icon: History },
  { name: "Access Control", href: "/access-control", icon: KeyRound },
  { name: "Certificates", href: "/certificates", icon: BadgeCheck },
  { name: "SIEM Stream", href: "/siem", icon: Share2 },
  { name: "Audit Trail", href: "/audit-trail", icon: ScrollText },
  { name: "Settings", href: "/settings", icon: Settings },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 h-screen fixed left-0 top-0 border-r border-border glass flex flex-col z-40">
      <div className="h-16 flex items-center px-6 border-b border-border">
        <Activity className="w-6 h-6 text-emerald-400 mr-2" />
        <span className="font-bold text-lg tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-cyan-400">
          WAF Pro
        </span>
      </div>

      <div className="flex-1 overflow-y-auto py-6 px-4 space-y-2">
        <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-4 px-2">
          Overview
        </div>
        
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group relative",
                isActive
                  ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                  : "text-muted-foreground hover:bg-secondary hover:text-foreground border border-transparent"
              )}
            >
              {isActive && (
                <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-emerald-400 rounded-r-md shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
              )}
              <item.icon className={cn("w-5 h-5", isActive ? "text-emerald-400" : "text-muted-foreground group-hover:text-foreground")} />
              {item.name}
            </Link>
          );
        })}
      </div>

      <div className="p-4 border-t border-border">
        <div className="flex items-center gap-3 px-2">
          <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-emerald-500 to-cyan-500 flex items-center justify-center text-sm font-bold shadow-lg">
            AD
          </div>
          <div>
            <div className="text-sm font-medium">Admin User</div>
            <div className="text-xs text-muted-foreground">admin@waf.local</div>
          </div>
        </div>
      </div>
    </aside>
  );
}

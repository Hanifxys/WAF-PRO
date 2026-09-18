"use client";

import { Bell, Search, Menu } from "lucide-react";

export default function Topbar() {
  return (
    <header className="h-16 border-b border-border glass flex items-center justify-between px-6 sticky top-0 z-30">
      <div className="flex items-center gap-4">
        <button className="p-2 -ml-2 rounded-md hover:bg-secondary text-muted-foreground hover:text-foreground md:hidden transition-colors">
          <Menu className="w-5 h-5" />
        </button>
        <div className="relative hidden md:flex items-center">
          <Search className="w-4 h-4 absolute left-3 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search events or rules..."
            className="bg-secondary/50 border border-border rounded-full pl-10 pr-4 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-emerald-500/50 focus:bg-secondary transition-all w-64 placeholder:text-muted-foreground"
          />
        </div>
      </div>

      <div className="flex items-center gap-4">
        <button className="relative p-2 rounded-full hover:bg-secondary text-muted-foreground hover:text-foreground transition-colors">
          <Bell className="w-5 h-5" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
        </button>
      </div>
    </header>
  );
}

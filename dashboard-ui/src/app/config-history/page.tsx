"use client";
import React, { useState, useEffect, useCallback } from "react";
import { History, RotateCcw, Eye, GitCompare, RefreshCw, ChevronDown, ChevronUp, Shield, Clock, FileText } from "lucide-react";
const API = "http://localhost:8082/api/v1";

interface Snapshot {
  id: number;
  version: number;
  snapshot_label: string;
  seclang_content?: string;
  changed_by: string;
  change_reason: string;
  created_at: string;
  content_size: number;
}

interface DiffResult {
  from_id: string;
  to_id: string;
  lines_added: number;
  lines_removed: number;
  added: string[];
  removed: string[];
}

export default function ConfigHistoryPage() {
  const [snapshots, setSnapshots] = useState<Snapshot[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [detail, setDetail] = useState<Snapshot | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [diffFrom, setDiffFrom] = useState<string>("");
  const [diffTo, setDiffTo] = useState<string>("");
  const [diffResult, setDiffResult] = useState<DiffResult | null>(null);
  const [toast, setToast] = useState<{ msg: string; type: string } | null>(null);
  const showToast = (msg: string, type="ok") => { setToast({msg,type}); setTimeout(()=>setToast(null),3500); };
  const fetchSnapshots = useCallback(async () => {
    setLoading(true);
    try { const res = await fetch(`${API}/config-snapshots`); const data = await res.json(); setSnapshots(Array.isArray(data)?data:[]); }
    catch { setSnapshots([]); } finally { setLoading(false); }
  }, []);
  useEffect(()=>{fetchSnapshots();},[fetchSnapshots]);
  const expandDetail = async (id: number) => {
    if (expandedId===id) { setExpandedId(null); setDetail(null); return; }
    setExpandedId(id); setDetailLoading(true);
    try { const res = await fetch(`${API}/config-snapshots/${id}`); setDetail(await res.json()); }
    catch { setDetail(null); } finally { setDetailLoading(false); }
  };
  const handleRollback = async (id: number, label: string) => {
    if (!confirm(`Rollback to ${label}? This will immediately push this config to Envoy.`)) return;
    try {
      const res = await fetch(`${API}/config-snapshots/${id}/rollback`,{method:"POST"});
      if(!res.ok) throw new Error(await res.text());
      showToast(`Rolled back to snapshot #${id}`);
      setTimeout(()=>fetchSnapshots(),1000);
    } catch(e: any) { showToast(`Rollback failed: ${e.message}`,"err"); }
  };
  const handleDiff = async () => {
    if(!diffFrom||!diffTo) { showToast("Select both snapshots to compare","err"); return; }
    try {
      const res = await fetch(`${API}/config-snapshots/diff?from=${diffFrom}&to=${diffTo}`);
      setDiffResult(await res.json());
    } catch(e: any) { showToast(`Diff failed: ${e.message}`,"err"); }
  };
  const fmtSize = (b: number) => b>1024?`${(b/1024).toFixed(1)}KB`:`${b}B`;
  return (
    <div className="flex-1 p-6 space-y-6">
      {toast&&<div className={`fixed top-4 right-4 z-50 px-4 py-3 rounded-lg text-sm font-medium shadow-xl border ${toast.type==="ok"?"bg-emerald-500/20 border-emerald-500/40 text-emerald-300":"bg-red-500/20 border-red-500/40 text-red-300"}`}>{toast.msg}</div>}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-indigo-500/10 border border-indigo-500/20"><History className="w-6 h-6 text-indigo-400"/></div>
          <div><h1 className="text-xl font-bold text-foreground">Config History & Rollback</h1><p className="text-sm text-muted-foreground">Versioned WAF SecLang policy snapshots — auto-saved on every xDS push</p></div>
        </div>
        <button onClick={fetchSnapshots} className="p-2 rounded-lg border border-border text-muted-foreground hover:text-foreground"><RefreshCw className="w-4 h-4"/></button>
      </div>
      <div className="grid grid-cols-3 gap-4">
        {[
          {label:"Total Snapshots",value:snapshots.length,Icon:History,color:"text-indigo-400",bg:"bg-indigo-500/10"},
          {label:"Latest Version",value:snapshots.length>0?`v${snapshots[0]?.version}`:"—",Icon:Shield,color:"text-emerald-400",bg:"bg-emerald-500/10"},
          {label:"Avg Policy Size",value:snapshots.length>0?fmtSize(Math.round(snapshots.reduce((s,x)=>s+(x.content_size||0),0)/snapshots.length)):"—",Icon:FileText,color:"text-amber-400",bg:"bg-amber-500/10"},
        ].map(s=>(
          <div key={s.label} className="flex items-center gap-4 p-4 rounded-xl border border-border bg-card">
            <div className={`p-2.5 rounded-lg ${s.bg}`}><s.Icon className={`w-5 h-5 ${s.color}`}/></div>
            <div><div className={`text-2xl font-bold ${s.color}`}>{s.value}</div><div className="text-xs text-muted-foreground">{s.label}</div></div>
          </div>
        ))}
      </div>
      <div className="p-4 rounded-xl border border-indigo-500/20 bg-indigo-500/5 space-y-3">
        <div className="flex items-center gap-2"><GitCompare className="w-4 h-4 text-indigo-400"/><span className="font-semibold text-sm text-indigo-300">Diff Viewer — Compare Two Snapshots</span></div>
        <div className="flex gap-3 flex-wrap">
          <select value={diffFrom||""} onChange={e=>setDiffFrom(e.target.value)} className="px-3 py-2 rounded-lg bg-slate-800 border border-border text-sm text-foreground focus:outline-none focus:border-indigo-500 flex-1 min-w-[160px]">
            <option value="">Select base snapshot</option>
            {snapshots.map(s=><option key={s.id} value={s.id}>{s.snapshot_label}</option>)}
          </select>
          <select value={diffTo||""} onChange={e=>setDiffTo(e.target.value)} className="px-3 py-2 rounded-lg bg-slate-800 border border-border text-sm text-foreground focus:outline-none focus:border-indigo-500 flex-1 min-w-[160px]">
            <option value="">Select compare snapshot</option>
            {snapshots.map(s=><option key={s.id} value={s.id}>{s.snapshot_label}</option>)}
          </select>
          <button onClick={handleDiff} className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm bg-indigo-600 text-white font-semibold hover:bg-indigo-500 transition-all"><GitCompare className="w-4 h-4"/>Compare</button>
        </div>
        {diffResult&&(
          <div className="grid grid-cols-2 gap-4 mt-2">
            <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
              <p className="text-xs font-semibold text-emerald-400 mb-2">+ {diffResult.lines_added} lines added</p>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {(diffResult.added||[]).map((l,i)=><p key={i} className="text-[10px] font-mono text-emerald-300 truncate">+ {l}</p>)}
              </div>
            </div>
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
              <p className="text-xs font-semibold text-red-400 mb-2">- {diffResult.lines_removed} lines removed</p>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {(diffResult.removed||[]).map((l,i)=><p key={i} className="text-[10px] font-mono text-red-300 truncate">- {l}</p>)}
              </div>
            </div>
          </div>
        )}
      </div>
      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="p-4 border-b border-border flex items-center gap-2">
          <History className="w-4 h-4 text-indigo-400"/><span className="font-semibold text-sm">Snapshot History</span>
          <span className="ml-auto text-xs text-muted-foreground">Most recent first — max 50 retained</span>
        </div>
        {loading?(<div className="py-12 text-center text-muted-foreground text-sm">Loading...</div>):snapshots.length===0?(
          <div className="flex flex-col items-center py-16 gap-3"><History className="w-10 h-10 text-muted-foreground/30"/><p className="text-muted-foreground text-sm">No snapshots yet. Snapshots are created automatically when WAF rules change.</p></div>
        ):(
          <div className="divide-y divide-border">
            {snapshots.map((snap,idx)=>(
              <div key={snap.id}>
                <div className="p-4 hover:bg-muted/20 cursor-pointer" onClick={()=>expandDetail(snap.id)}>
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                      <div className={`px-2.5 py-0.5 rounded-md text-xs font-bold font-mono ${idx===0?"bg-emerald-500/20 text-emerald-400 border border-emerald-500/40":"bg-slate-700 text-slate-300 border border-slate-600"}`}>
                        v{snap.version}
                      </div>
                      <div>
                        <p className="text-sm font-medium text-foreground">{snap.snapshot_label}</p>
                        <div className="flex items-center gap-3 mt-0.5 text-xs text-muted-foreground">
                          <span className="flex items-center gap-1"><Clock className="w-3 h-3"/>{new Date(snap.created_at).toLocaleString()}</span>
                          <span className="flex items-center gap-1"><FileText className="w-3 h-3"/>{fmtSize(snap.content_size||0)}</span>
                          <span>by {snap.changed_by}</span>
                        </div>
                        {snap.change_reason&&<p className="text-[10px] text-muted-foreground/60 mt-0.5">{snap.change_reason}</p>}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {idx!==0&&(
                        <button onClick={e=>{e.stopPropagation();handleRollback(snap.id,snap.snapshot_label);}} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-amber-500/10 border border-amber-500/30 text-amber-400 hover:bg-amber-500/20 font-medium transition-all">
                          <RotateCcw className="w-3 h-3"/>Rollback
                        </button>
                      )}
                      {idx===0&&<span className="text-xs text-emerald-400 font-semibold border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 rounded-lg">Current</span>}
                      {expandedId===snap.id?<ChevronUp className="w-4 h-4 text-muted-foreground"/>:<ChevronDown className="w-4 h-4 text-muted-foreground"/>}
                    </div>
                  </div>
                </div>
                {expandedId===snap.id&&(
                  <div className="border-t border-border bg-slate-950/60 p-4">
                    {detailLoading?(<div className="text-xs text-muted-foreground">Loading...</div>):detail?(
                      <div>
                        <p className="text-xs font-semibold text-muted-foreground uppercase mb-2 flex items-center gap-1"><Eye className="w-3 h-3"/>SecLang Policy Content</p>
                        <pre className="text-[10px] font-mono text-slate-300 bg-slate-900 rounded-lg p-3 overflow-x-auto max-h-80 leading-relaxed whitespace-pre-wrap">{detail.seclang_content}</pre>
                      </div>
                    ):(<div className="text-xs text-red-400">Failed to load snapshot detail</div>)}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
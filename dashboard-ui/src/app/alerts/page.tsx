"use client";
import React, { useState, useEffect, useCallback } from "react";
import { Bell, Plus, Trash2, ToggleLeft, ToggleRight, Edit2, CheckCircle2, Zap, Activity, ShieldAlert, RefreshCw, Save, Clock } from "lucide-react";
const API = "http://localhost:8082/api/v1";

interface AlertRuleItem {
  id: number;
  name: string;
  description: string;
  metric: string;
  operator: string;
  threshold: number;
  window_seconds: number;
  attack_type: string;
  action_create_incident: boolean;
  action_send_email: boolean;
  action_block_ip: boolean;
  email_recipient: string;
  cooldown_seconds: number;
  is_enabled: boolean;
  trigger_count: number;
  last_triggered_at?: string;
}

export default function AlertRulesPage() {
  const [rules, setRules] = useState<AlertRuleItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState<{ msg: string; type: string } | null>(null);
  const [form, setForm] = useState<Record<string, any>>({ name:"", description:"", metric:"event_count", operator:"gte", threshold:100, window_seconds:300, attack_type:"", action_create_incident:true, action_send_email:false, action_block_ip:false, email_recipient:"", cooldown_seconds:300 });
  const showToast = (msg: string, type="ok") => { setToast({msg,type}); setTimeout(()=>setToast(null),3000); };
  const fetchRules = useCallback(async () => {
    setLoading(true);
    try { const res = await fetch(`${API}/alert-rules`); const data = await res.json(); setRules(Array.isArray(data)?data:[]); }
    catch { setRules([]); } finally { setLoading(false); }
  }, []);
  useEffect(()=>{fetchRules();},[fetchRules]);
  const resetForm = () => ({ name:"",description:"",metric:"event_count",operator:"gte",threshold:100,window_seconds:300,attack_type:"",action_create_incident:true,action_send_email:false,action_block_ip:false,email_recipient:"",cooldown_seconds:300 });
  const openCreate = () => { setEditingId(null); setForm(resetForm()); setShowForm(true); };
  const openEdit = (rule: AlertRuleItem) => { setEditingId(rule.id); setForm({...rule}); setShowForm(true); };
  const handleSave = async () => {
    if (!form.name?.trim()) { showToast("Name required","err"); return; }
    setSaving(true);
    try {
      const method = editingId?"PUT":"POST";
      const url = editingId?`${API}/alert-rules/${editingId}`:`${API}/alert-rules`;
      const res = await fetch(url,{method,headers:{"Content-Type":"application/json"},body:JSON.stringify(form)});
      if(!res.ok) throw new Error(await res.text());
      showToast(editingId?"Updated":"Created"); setShowForm(false); fetchRules();
    } catch(e: any) { showToast(`Failed: ${e.message}`,"err"); } finally { setSaving(false); }
  };
  const handleToggle = async (id: number) => { await fetch(`${API}/alert-rules/${id}/toggle`,{method:"PUT"}); fetchRules(); };
  const handleDelete = async (id: number) => { if(!confirm("Delete?")) return; await fetch(`${API}/alert-rules/${id}`,{method:"DELETE"}); showToast("Deleted"); fetchRules(); };
  const WMAP: Record<number, string> = {60:"1m",300:"5m",600:"10m",1800:"30m",3600:"1h"};
  const wl = (s: number) => WMAP[s]||`${s}s`;
  return (
    <div className="flex-1 p-6 space-y-6">
      {toast && <div className={`fixed top-4 right-4 z-50 px-4 py-3 rounded-lg text-sm font-medium shadow-xl border ${toast.type==="ok"?"bg-emerald-500/20 border-emerald-500/40 text-emerald-300":"bg-red-500/20 border-red-500/40 text-red-300"}`}>{toast.msg}</div>}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/20"><Bell className="w-6 h-6 text-amber-400" /></div>
          <div><h1 className="text-xl font-bold text-foreground">Alert Rules Engine</h1><p className="text-sm text-muted-foreground">Automated threshold triggers — evaluates every 60 seconds</p></div>
        </div>
        <div className="flex gap-2">
          <button onClick={fetchRules} className="p-2 rounded-lg border border-border text-muted-foreground hover:text-foreground"><RefreshCw className="w-4 h-4" /></button>
          <button onClick={openCreate} className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm bg-amber-500 text-black font-semibold hover:bg-amber-400"><Plus className="w-4 h-4" />New Rule</button>
        </div>
      </div>
      <div className="grid grid-cols-3 gap-4">
        {[{label:"Total Rules",value:rules.length,color:"text-amber-400",bg:"bg-amber-500/10",Icon:Bell},{label:"Active",value:rules.filter(r=>r.is_enabled).length,color:"text-emerald-400",bg:"bg-emerald-500/10",Icon:CheckCircle2},{label:"Total Triggers",value:rules.reduce((s,r)=>s+(r.trigger_count||0),0),color:"text-red-400",bg:"bg-red-500/10",Icon:Zap}].map(s=>(
          <div key={s.label} className="flex items-center gap-4 p-4 rounded-xl border border-border bg-card">
            <div className={`p-2.5 rounded-lg ${s.bg}`}><s.Icon className={`w-5 h-5 ${s.color}`} /></div>
            <div><div className={`text-2xl font-bold ${s.color}`}>{s.value}</div><div className="text-xs text-muted-foreground">{s.label}</div></div>
          </div>
        ))}
      </div>
      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="p-4 border-b border-border flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-amber-400" /><span className="font-semibold text-sm">Alert Rules</span>
          <span className="ml-auto text-xs text-muted-foreground">Background evaluator running</span>
        </div>
        {loading?(<div className="py-12 text-center text-muted-foreground text-sm">Loading...</div>):rules.length===0?(
          <div className="flex flex-col items-center py-16 gap-3"><Bell className="w-10 h-10 text-muted-foreground/30" /><p className="text-muted-foreground text-sm">No alert rules configured.</p></div>
        ):(
          <div className="divide-y divide-border">
            {rules.map(rule=>(
              <div key={rule.id} className="p-4 hover:bg-muted/20">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-sm">{rule.name}</span>
                      <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold border ${rule.is_enabled?"bg-emerald-500/15 text-emerald-400 border-emerald-500/30":"bg-slate-500/15 text-slate-400 border-slate-500/30"}`}>{rule.is_enabled?"ACTIVE":"DISABLED"}</span>
                      {rule.trigger_count>0&&<span className="text-[10px] px-2 py-0.5 rounded-full bg-red-500/15 text-red-400 border border-red-500/30 font-bold">fired {rule.trigger_count}x</span>}
                    </div>
                    {rule.description&&<p className="text-xs text-muted-foreground mt-0.5">{rule.description}</p>}
                    <div className="flex flex-wrap gap-3 mt-1.5 text-xs text-muted-foreground">
                      <span className="flex items-center gap-1"><Activity className="w-3 h-3" />{rule.metric==="event_count"?"Events":"Attack"} {rule.operator} <strong className="text-foreground ml-1">{rule.threshold}</strong>{rule.attack_type&&<span className="text-amber-400 ml-1">({rule.attack_type})</span>}</span>
                      <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{wl(rule.window_seconds)}</span>
                      {rule.action_create_incident&&<span className="text-amber-400">Incident</span>}
                      {rule.action_send_email&&<span className="text-blue-400">Email</span>}
                      {rule.action_block_ip&&<span className="text-red-400">Block IP</span>}
                    </div>
                    {rule.last_triggered_at&&<p className="text-[10px] text-muted-foreground/50 mt-1">Last: {new Date(rule.last_triggered_at).toLocaleString()}</p>}
                  </div>
                  <div className="flex items-center gap-1">
                    <button onClick={()=>handleToggle(rule.id)} className="p-1.5 rounded hover:bg-muted/50">{rule.is_enabled?<ToggleRight className="w-5 h-5 text-emerald-400"/>:<ToggleLeft className="w-5 h-5 text-muted-foreground"/>}</button>
                    <button onClick={()=>openEdit(rule)} className="p-1.5 rounded hover:bg-muted/50 text-muted-foreground hover:text-foreground"><Edit2 className="w-4 h-4"/></button>
                    <button onClick={()=>handleDelete(rule.id)} className="p-1.5 rounded hover:bg-red-500/10 text-muted-foreground hover:text-red-400"><Trash2 className="w-4 h-4"/></button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      {showForm&&(
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-border rounded-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto shadow-2xl">
            <div className="p-5 border-b border-border flex items-center justify-between">
              <h2 className="font-bold">{editingId?"Edit Alert Rule":"New Alert Rule"}</h2>
              <button onClick={()=>setShowForm(false)} className="text-muted-foreground hover:text-foreground text-2xl">&times;</button>
            </div>
            <div className="p-5 space-y-4">
              <div><label className="text-xs font-medium text-muted-foreground uppercase">Name *</label><input value={form.name} onChange={e=>setForm(p=>({...p,name:e.target.value}))} className="mt-1 w-full px-3 py-2 rounded-lg bg-slate-800 border border-border text-sm text-foreground focus:outline-none focus:border-amber-500" placeholder="High SQLi Volume Alert"/></div>
              <div><label className="text-xs font-medium text-muted-foreground uppercase">Description</label><input value={form.description} onChange={e=>setForm(p=>({...p,description:e.target.value}))} className="mt-1 w-full px-3 py-2 rounded-lg bg-slate-800 border border-border text-sm text-foreground focus:outline-none focus:border-amber-500"/></div>
              <div className="p-3 rounded-lg bg-amber-500/5 border border-amber-500/20 space-y-3">
                <p className="text-xs font-semibold text-amber-400 uppercase">Trigger Condition</p>
                <div className="grid grid-cols-2 gap-3">
                  <div><label className="text-xs text-muted-foreground">Metric</label><select value={form.metric} onChange={e=>setForm(p=>({...p,metric:e.target.value}))} className="mt-1 w-full px-3 py-2 rounded-lg bg-slate-800 border border-border text-sm text-foreground focus:outline-none"><option value="event_count">Total Events</option><option value="attack_type_count">Attack Type</option></select></div>
                  <div><label className="text-xs text-muted-foreground">Operator</label><select value={form.operator} onChange={e=>setForm(p=>({...p,operator:e.target.value}))} className="mt-1 w-full px-3 py-2 rounded-lg bg-slate-800 border border-border text-sm text-foreground focus:outline-none"><option value="gte">&gt;= gte</option><option value="gt">&gt; gt</option><option value="lte">&lt;= lte</option><option value="lt">&lt; lt</option></select></div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div><label className="text-xs text-muted-foreground">Threshold</label><input type="number" value={form.threshold} onChange={e=>setForm(p=>({...p,threshold:+e.target.value}))} className="mt-1 w-full px-3 py-2 rounded-lg bg-slate-800 border border-border text-sm text-foreground focus:outline-none"/></div>
                  <div><label className="text-xs text-muted-foreground">Window</label><select value={form.window_seconds} onChange={e=>setForm(p=>({...p,window_seconds:+e.target.value}))} className="mt-1 w-full px-3 py-2 rounded-lg bg-slate-800 border border-border text-sm text-foreground focus:outline-none"><option value={60}>1 minute</option><option value={300}>5 minutes</option><option value={600}>10 minutes</option><option value={1800}>30 minutes</option><option value={3600}>1 hour</option></select></div>
                </div>
                <div><label className="text-xs text-muted-foreground">Filter Attack Type</label><select value={form.attack_type} onChange={e=>setForm(p=>({...p,attack_type:e.target.value}))} className="mt-1 w-full px-3 py-2 rounded-lg bg-slate-800 border border-border text-sm text-foreground focus:outline-none"><option value="">All types</option>{["SQLi","XSS","Path Traversal","Command Injection","Scanner","Bot","DDoS","Brute Force"].map(t=><option key={t} value={t}>{t}</option>)}</select></div>
              </div>
              <div className="p-3 rounded-lg bg-blue-500/5 border border-blue-500/20 space-y-2">
                <p className="text-xs font-semibold text-blue-400 uppercase">Actions</p>
                {[{k:"action_create_incident",label:"Auto-create Incident"},{k:"action_send_email",label:"Send email alert"},{k:"action_block_ip",label:"Auto-block source IP"}].map(a=>(
                  <label key={a.k} className="flex items-center gap-3 cursor-pointer"><input type="checkbox" checked={!!form[a.k]} onChange={e=>setForm(p=>({...p,[a.k]:e.target.checked}))} className="w-4 h-4 accent-amber-500"/><span className="text-sm text-foreground">{a.label}</span></label>
                ))}
                {form.action_send_email&&<input value={form.email_recipient} onChange={e=>setForm(p=>({...p,email_recipient:e.target.value}))} className="mt-1 w-full px-3 py-2 rounded-lg bg-slate-800 border border-border text-sm text-foreground focus:outline-none focus:border-blue-500" placeholder="Email recipient"/>}
              </div>
              <div><label className="text-xs font-medium text-muted-foreground uppercase">Cooldown</label><select value={form.cooldown_seconds} onChange={e=>setForm(p=>({...p,cooldown_seconds:+e.target.value}))} className="mt-1 w-full px-3 py-2 rounded-lg bg-slate-800 border border-border text-sm text-foreground focus:outline-none"><option value={60}>1 minute</option><option value={300}>5 minutes</option><option value={900}>15 minutes</option><option value={1800}>30 minutes</option><option value={3600}>1 hour</option></select></div>
            </div>
            <div className="p-5 border-t border-border flex justify-end gap-3">
              <button onClick={()=>setShowForm(false)} className="px-4 py-2 rounded-lg text-sm border border-border text-muted-foreground hover:text-foreground">Cancel</button>
              <button onClick={handleSave} disabled={saving} className="flex items-center gap-2 px-5 py-2 rounded-lg text-sm bg-amber-500 text-black font-semibold hover:bg-amber-400 disabled:opacity-50"><Save className="w-4 h-4"/>{saving?"Saving...":editingId?"Update":"Create"}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
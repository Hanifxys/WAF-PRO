"use client";

import React, { useState, useEffect } from "react";
import { FlaskConical, Play, CheckCircle2, XCircle, RefreshCw, Terminal, Activity, ShieldAlert, ShieldCheck, Layers } from "lucide-react";
import { API } from "@/lib/api";

interface SingleTestResult {
  rule_id: number;
  is_matched: boolean;
  decision: "BLOCK" | "ALLOW";
  matched_variable?: string;
  matched_value?: string;
  execution_latency_ms: number;
  evaluated_at: string;
}

interface BatchTestResult {
  rule_id: number;
  total_tested: number;
  passed: number;
  blocked: number;
  false_positives: number;
  false_negatives: number;
  accuracy_percent: number;
  details_sample: {
    payload: string;
    is_attack_expected: boolean;
    actual_blocked: boolean;
    is_correct: boolean;
    classification: string;
  }[];
}

interface RegressionSuiteResult {
  total_rules_tested: number;
  total_cases_run: number;
  passed_cases: number;
  failed_cases: number;
  deployment_allowed: boolean;
  gate_message: string;
  failures?: string[];
  evaluated_at: string;
}

interface RegressionTestCase {
  id: number;
  rule_id: number;
  test_name: string;
  payload: string;
  is_attack_expected: boolean;
  target_variable: string;
}

export default function RuleLabPage() {
  const [activeTab, setActiveTab] = useState<"single" | "batch" | "regression">("single");

  // Single Test State
  const [singleRuleID, setSingleRuleID] = useState(942100);
  const [singleMethod, setSingleMethod] = useState("POST");
  const [singlePath, setSinglePath] = useState("/api/customer");
  const [singleBody, setSingleBody] = useState("customerName=admin' UNION SELECT 1,password FROM users --");
  const [singleLoading, setSingleLoading] = useState(false);
  const [singleResult, setSingleResult] = useState<SingleTestResult | null>(null);

  // Batch Test State
  const [batchRuleID, setBatchRuleID] = useState(942100);
  const [batchText, setBatchText] = useState(
    `admin' OR 1=1 -- | ATTACK\nUNION SELECT * FROM accounts | ATTACK\n'; DROP TABLE users; -- | ATTACK\nO'Connor | LEGITIMATE\nD'Angelo | LEGITIMATE\nJohn Doe | LEGITIMATE\n1234 Elm Street | LEGITIMATE`
  );
  const [batchLoading, setBatchLoading] = useState(false);
  const [batchResult, setBatchResult] = useState<BatchTestResult | null>(null);

  // Regression Suite State
  const [regTests, setRegTests] = useState<RegressionTestCase[]>([]);
  const [regLoading, setRegLoading] = useState(false);
  const [regRunResult, setRegRunResult] = useState<RegressionSuiteResult | null>(null);

  const fetchRegressionTests = async () => {
    try {
      const res = await fetch(`${API}/api/v1/rule-lab/regression-tests`);
      if (res.ok) {
        setRegTests(await res.json());
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      void fetchRegressionTests();
    }, 0);
    return () => clearTimeout(timer);
  }, []);

  const handleRunSingleTest = async () => {
    setSingleLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/rule-lab/test-single`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rule_id: Number(singleRuleID),
          method: singleMethod,
          path: singlePath,
          body: singleBody,
        }),
      });
      if (res.ok) {
        setSingleResult(await res.json());
      }
    } catch (e) {
      console.error(e);
    } finally {
      setSingleLoading(false);
    }
  };

  const handleRunBatchTest = async () => {
    setBatchLoading(true);
    try {
      const lines = batchText.split("\n").filter((l) => l.trim().length > 0);
      const payloads = lines.map((line) => {
        const parts = line.split("|");
        const payload = parts[0]?.trim() || "";
        const isAttack = (parts[1]?.trim().toUpperCase() || "") === "ATTACK";
        return { payload, is_attack_expected: isAttack };
      });

      const res = await fetch(`${API}/api/v1/rule-lab/test-batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rule_id: Number(batchRuleID),
          payloads,
        }),
      });
      if (res.ok) {
        setBatchResult(await res.json());
      }
    } catch (e) {
      console.error(e);
    } finally {
      setBatchLoading(false);
    }
  };

  const handleRunRegression = async () => {
    setRegLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/rule-lab/run-regression`, {
        method: "POST",
      });
      const data = await res.json();
      setRegRunResult(data);
    } catch (e) {
      console.error(e);
    } finally {
      setRegLoading(false);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-border/60 pb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="p-2.5 rounded-xl bg-gradient-to-tr from-cyan-500/20 to-blue-500/20 border border-cyan-500/30 text-cyan-400">
              <FlaskConical className="w-6 h-6" />
            </div>
            <h1 className="text-3xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-200 to-slate-400">
              WAF Rule Testing Lab
            </h1>
          </div>
          <p className="text-muted-foreground text-sm">
            Roadmap Pillars 26 & 27: Interactive regex testing, batch FP classification, and automated regression deployment gates.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-1 bg-secondary/50 p-1.5 rounded-xl border border-border">
          <button
            onClick={() => setActiveTab("single")}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
              activeTab === "single"
                ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            Single Payload
          </button>
          <button
            onClick={() => setActiveTab("batch")}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
              activeTab === "batch"
                ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            Batch Evaluator
          </button>
          <button
            onClick={() => setActiveTab("regression")}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
              activeTab === "regression"
                ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            Regression Pack
          </button>
        </div>
      </div>

      {/* Tab 1: Single Payload Test */}
      {activeTab === "single" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Request Form */}
          <div className="glass p-6 rounded-2xl border border-border space-y-4">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <Terminal className="w-5 h-5 text-cyan-400" />
              Craft Test Request
            </h2>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-muted-foreground font-medium mb-1 block">Rule ID</label>
                <select
                  value={singleRuleID}
                  onChange={(e) => setSingleRuleID(Number(e.target.value))}
                  className="w-full bg-secondary/60 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-400"
                >
                  <option value={942100}>942100 - SQL Injection (CRS)</option>
                  <option value={941100}>941100 - XSS Cross-Site Scripting</option>
                  <option value={950001}>950001 - Cloud Metadata SSRF</option>
                </select>
              </div>
              <div>
                <label className="text-xs text-muted-foreground font-medium mb-1 block">HTTP Method</label>
                <select
                  value={singleMethod}
                  onChange={(e) => setSingleMethod(e.target.value)}
                  className="w-full bg-secondary/60 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-400"
                >
                  <option value="POST">POST</option>
                  <option value="GET">GET</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                </select>
              </div>
            </div>

            <div>
              <label className="text-xs text-muted-foreground font-medium mb-1 block">Request Path</label>
              <input
                type="text"
                value={singlePath}
                onChange={(e) => setSinglePath(e.target.value)}
                className="w-full bg-secondary/60 border border-border rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-cyan-400"
              />
            </div>

            <div>
              <label className="text-xs text-muted-foreground font-medium mb-1 block">Request Body / Payload</label>
              <textarea
                rows={4}
                value={singleBody}
                onChange={(e) => setSingleBody(e.target.value)}
                className="w-full bg-secondary/60 border border-border rounded-lg p-3 text-sm font-mono focus:outline-none focus:border-cyan-400"
              />
            </div>

            <button
              onClick={handleRunSingleTest}
              disabled={singleLoading}
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-medium flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-50"
            >
              {singleLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-white" />}
              Execute Rule Evaluation
            </button>
          </div>

          {/* Test Verdict */}
          <div className="glass p-6 rounded-2xl border border-border flex flex-col justify-between">
            <div>
              <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Activity className="w-5 h-5 text-emerald-400" />
                Evaluation Verdict
              </h2>

              {singleResult ? (
                <div className="space-y-4">
                  <div
                    className={`p-4 rounded-xl border flex items-center justify-between ${
                      singleResult.decision === "BLOCK"
                        ? "bg-rose-500/10 border-rose-500/30 text-rose-400"
                        : "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      {singleResult.decision === "BLOCK" ? (
                        <ShieldAlert className="w-8 h-8 text-rose-400" />
                      ) : (
                        <ShieldCheck className="w-8 h-8 text-emerald-400" />
                      )}
                      <div>
                        <div className="text-xl font-bold">{singleResult.decision}</div>
                        <div className="text-xs opacity-80">
                          {singleResult.decision === "BLOCK"
                            ? `Matched signature trigger on Rule ${singleResult.rule_id}`
                            : `Clean request passed all heuristics`}
                        </div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-xs text-muted-foreground">Latency</div>
                      <div className="text-sm font-mono font-bold text-foreground">
                        {singleResult.execution_latency_ms.toFixed(2)} ms
                      </div>
                    </div>
                  </div>

                  {singleResult.matched_variable && (
                    <div className="p-3 bg-secondary/40 rounded-xl border border-border space-y-1 text-xs font-mono">
                      <div className="text-muted-foreground">Matched Variable:</div>
                      <div className="text-cyan-400 font-semibold">{singleResult.matched_variable}</div>
                    </div>
                  )}

                  {singleResult.matched_value && (
                    <div className="p-3 bg-secondary/40 rounded-xl border border-border space-y-1 text-xs font-mono">
                      <div className="text-muted-foreground">Evidence Snippet:</div>
                      <div className="text-rose-400 font-semibold bg-rose-500/10 p-2 rounded border border-rose-500/20">
                        {singleResult.matched_value}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="h-48 flex flex-col items-center justify-center text-center text-muted-foreground">
                  <FlaskConical className="w-10 h-10 mb-2 opacity-30" />
                  <p className="text-sm">Submit a payload to see real-time rule match results & regex latency.</p>
                </div>
              )}
            </div>

            <div className="pt-4 border-t border-border/60 text-xs text-muted-foreground flex justify-between">
              <span>Engine: Coraza WASM Regex Engine</span>
              <span>ReDoS Protected: Yes</span>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Batch Payload Evaluator */}
      {activeTab === "batch" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Input */}
            <div className="lg:col-span-1 glass p-6 rounded-2xl border border-border space-y-4">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <Layers className="w-5 h-5 text-cyan-400" />
                Batch Dataset
              </h2>
              <div>
                <label className="text-xs text-muted-foreground font-medium mb-1 block">Target Rule</label>
                <select
                  value={batchRuleID}
                  onChange={(e) => setBatchRuleID(Number(e.target.value))}
                  className="w-full bg-secondary/60 border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-400"
                >
                  <option value={942100}>942100 - SQLi Common DB Injections</option>
                  <option value={941100}>941100 - XSS Cross-Site Scripting</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-muted-foreground font-medium mb-1 block">
                  Format: &lt;payload&gt; | ATTACK / LEGITIMATE
                </label>
                <textarea
                  rows={10}
                  value={batchText}
                  onChange={(e) => setBatchText(e.target.value)}
                  className="w-full bg-secondary/60 border border-border rounded-lg p-3 text-xs font-mono focus:outline-none focus:border-cyan-400"
                />
              </div>

              <button
                onClick={handleRunBatchTest}
                disabled={batchLoading}
                className="w-full py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold flex items-center justify-center gap-2 transition-all disabled:opacity-50 shadow-lg shadow-cyan-500/20"
              >
                {batchLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-slate-950" />}
                Evaluate All Payloads
              </button>
            </div>

            {/* Scorecard & Details */}
            <div className="lg:col-span-2 glass p-6 rounded-2xl border border-border space-y-6">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <Activity className="w-5 h-5 text-emerald-400" />
                Accuracy & Classification Scorecard
              </h2>

              {batchResult ? (
                <>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                    <div className="p-4 bg-secondary/40 rounded-xl border border-border text-center">
                      <div className="text-2xl font-bold text-cyan-400">{batchResult.total_tested}</div>
                      <div className="text-xs text-muted-foreground">Total Tested</div>
                    </div>
                    <div className="p-4 bg-secondary/40 rounded-xl border border-border text-center">
                      <div className="text-2xl font-bold text-emerald-400">{batchResult.accuracy_percent}%</div>
                      <div className="text-xs text-muted-foreground">Accuracy</div>
                    </div>
                    <div className="p-4 bg-secondary/40 rounded-xl border border-border text-center">
                      <div className="text-2xl font-bold text-amber-400">{batchResult.false_positives}</div>
                      <div className="text-xs text-muted-foreground">False Positives</div>
                    </div>
                    <div className="p-4 bg-secondary/40 rounded-xl border border-border text-center">
                      <div className="text-2xl font-bold text-rose-400">{batchResult.false_negatives}</div>
                      <div className="text-xs text-muted-foreground">False Negatives</div>
                    </div>
                  </div>

                  <div className="overflow-x-auto rounded-xl border border-border">
                    <table className="w-full text-xs text-left">
                      <thead className="bg-secondary/60 text-muted-foreground border-b border-border">
                        <tr>
                          <th className="p-3">Payload</th>
                          <th className="p-3">Expected</th>
                          <th className="p-3">WAF Decision</th>
                          <th className="p-3">Classification</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {batchResult.details_sample.map((item, idx) => (
                          <tr key={idx} className="hover:bg-secondary/30">
                            <td className="p-3 font-mono text-foreground font-medium">{item.payload}</td>
                            <td className="p-3">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  item.is_attack_expected ? "bg-rose-500/20 text-rose-400" : "bg-emerald-500/20 text-emerald-400"
                                }`}
                              >
                                {item.is_attack_expected ? "ATTACK" : "LEGITIMATE"}
                              </span>
                            </td>
                            <td className="p-3">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  item.actual_blocked ? "bg-rose-500/20 text-rose-400" : "bg-emerald-500/20 text-emerald-400"
                                }`}
                              >
                                {item.actual_blocked ? "BLOCKED" : "ALLOWED"}
                              </span>
                            </td>
                            <td className="p-3 font-bold text-[11px]">
                              {item.classification === "TRUE_POSITIVE" && <span className="text-emerald-400">✓ True Positive</span>}
                              {item.classification === "TRUE_NEGATIVE" && <span className="text-emerald-400">✓ True Negative</span>}
                              {item.classification === "FALSE_POSITIVE" && <span className="text-amber-400">⚠ False Positive</span>}
                              {item.classification === "FALSE_NEGATIVE" && <span className="text-rose-400">✗ False Negative</span>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              ) : (
                <div className="h-48 flex flex-col items-center justify-center text-center text-muted-foreground">
                  <Layers className="w-10 h-10 mb-2 opacity-30" />
                  <p className="text-sm">Click &apos;Evaluate All Payloads&apos; to classify the dataset into TP, TN, FP, and FN.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Regression Pack & Deployment Gate */}
      {activeTab === "regression" && (
        <div className="space-y-6">
          {/* Gate Status Card */}
          <div className="glass p-6 rounded-2xl border border-border flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-bold">Rule Regression Deployment Gate</h2>
                {regRunResult && (
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-bold flex items-center gap-1 ${
                      regRunResult.deployment_allowed
                        ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                        : "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                    }`}
                  >
                    {regRunResult.deployment_allowed ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                    {regRunResult.deployment_allowed ? "GATE: APPROVED" : "GATE: BLOCKED"}
                  </span>
                )}
              </div>
              <p className="text-sm text-muted-foreground">
                Automated quality assurance ensures newly created rules or regex modifications do not break legitimate traffic.
              </p>
            </div>

            <button
              onClick={handleRunRegression}
              disabled={regLoading}
              className="px-6 py-3 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 font-bold flex items-center gap-2 shadow-lg shadow-emerald-500/20 transition-all disabled:opacity-50"
            >
              {regLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-slate-950" />}
              Run Regression Suite
            </button>
          </div>

          {regRunResult && (
            <div
              className={`p-4 rounded-xl border ${
                regRunResult.deployment_allowed
                  ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                  : "bg-rose-500/10 border-rose-500/20 text-rose-400"
              }`}
            >
              <div className="font-semibold text-sm">{regRunResult.gate_message}</div>
              <div className="text-xs opacity-80 mt-1">
                Evaluated {regRunResult.total_cases_run} test cases across {regRunResult.total_rules_tested} rules ({regRunResult.passed_cases} passed, {regRunResult.failed_cases} failed).
              </div>
            </div>
          )}

          {/* Test Case Table */}
          <div className="glass rounded-2xl border border-border overflow-hidden">
            <div className="p-4 border-b border-border flex items-center justify-between bg-secondary/30">
              <h3 className="font-semibold text-sm">Active Invariant Test Cases ({regTests.length})</h3>
              <span className="text-xs text-muted-foreground">Pre-deployment Verification Suite</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="bg-secondary/50 text-muted-foreground border-b border-border">
                  <tr>
                    <th className="p-3">ID</th>
                    <th className="p-3">Target Rule</th>
                    <th className="p-3">Scenario Name</th>
                    <th className="p-3">Payload Snippet</th>
                    <th className="p-3">Expected Outcome</th>
                    <th className="p-3">Target Location</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {regTests.map((t) => (
                    <tr key={t.id} className="hover:bg-secondary/20">
                      <td className="p-3 font-mono text-muted-foreground">#{t.id}</td>
                      <td className="p-3 font-mono font-bold text-cyan-400">Rule {t.rule_id}</td>
                      <td className="p-3 font-medium text-foreground">{t.test_name}</td>
                      <td className="p-3 font-mono text-foreground">{t.payload}</td>
                      <td className="p-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            t.is_attack_expected ? "bg-rose-500/20 text-rose-400" : "bg-emerald-500/20 text-emerald-400"
                          }`}
                        >
                          {t.is_attack_expected ? "EXPECT BLOCK" : "EXPECT ALLOW"}
                        </span>
                      </td>
                      <td className="p-3 font-mono text-muted-foreground">{t.target_variable}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


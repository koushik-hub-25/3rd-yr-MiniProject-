import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import {
  User, Cpu, Database, Radio, Shield, Bell, Key, RefreshCw, CheckCircle2,
  AlertTriangle, Server, Lock, ExternalLink, HardDrive, Info
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent, Badge, cn } from "../components/ui";

export default function Settings() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<"profile" | "ai" | "sources" | "alerts" | "system">("profile");
  const [dataSources, setDataSources] = useState<any[]>([]);
  const [config, setConfig] = useState<any>(null);
  const [resetting, setResetting] = useState(false);
  const [resetMessage, setResetMessage] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/config")
      .then(res => res.json())
      .then(data => setConfig(data))
      .catch(() => {});

    fetch("/api/datasources/status")
      .then(res => res.json())
      .then(data => setDataSources(data.sources || []))
      .catch(() => {});
  }, []);

  const handleResetData = async () => {
    setResetting(true);
    setResetMessage(null);
    try {
      const res = await fetch("/api/reset-data", { method: "POST" });
      const data = await res.json();
      if (data.success) {
        setResetMessage("Successfully reset CTI database to verified synthetic baseline.");
      } else {
        setResetMessage("Failed to reset: " + data.error);
      }
    } catch (e: any) {
      setResetMessage("Error resetting dataset: " + e.message);
    } finally {
      setResetting(false);
    }
  };

  const tabs = [
    { id: "profile", label: "Analyst Profile", icon: User },
    { id: "ai", label: "AI Engine Configuration", icon: Cpu },
    { id: "sources", label: "Data Source Integrations", icon: Database },
    { id: "alerts", label: "Alerting & Notifications", icon: Bell },
    { id: "system", label: "System Integrity & Baseline", icon: Server }
  ];

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="pb-2 border-b border-slate-800/80">
        <h1 className="text-xl font-extrabold text-white tracking-tight">Platform Configuration & Settings</h1>
        <p className="text-xs text-slate-400 mt-1">
          Manage analyst credentials, AI engine parameters, threat feed integrations, and academic prototype controls.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1.5 border-b border-slate-800/80 pb-2 overflow-x-auto">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={cn(
                "flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold whitespace-nowrap transition-all border",
                isActive
                  ? "bg-cyan-950/80 text-cyan-300 border-cyan-500/40 shadow-sm shadow-cyan-950"
                  : "bg-slate-900/50 text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/50"
              )}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab Contents */}
      {activeTab === "profile" && (
        <Card>
          <CardHeader>
            <CardTitle><User className="w-4 h-4 text-cyan-400" /> Analyst Identity & Role</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-4 p-4 rounded-xl bg-[#070B14] border border-slate-800">
              <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-600 to-blue-700 flex items-center justify-center text-white font-extrabold text-lg shadow-lg shadow-cyan-950/50">
                {user?.avatarInitials || "AM"}
              </div>
              <div>
                <h3 className="text-sm font-bold text-white">{user?.name || "Alex Morgan"}</h3>
                <p className="text-xs text-cyan-400 font-mono">{user?.email || "alex.morgan@shieldzen.sec"}</p>
                <div className="flex items-center gap-2 mt-1.5">
                  <Badge variant="cyan">{user?.role || "Senior Security Analyst"}</Badge>
                  <span className="text-[11px] text-slate-400 font-mono">{user?.clearance || "SOC Tier-2"}</span>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-3.5 rounded-xl bg-[#070B14] border border-slate-800 space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-500 font-mono">Platform Identity ID</span>
                <p className="text-xs font-mono text-slate-200">{user?.id || "usr-alex-morgan"}</p>
              </div>
              <div className="p-3.5 rounded-xl bg-[#070B14] border border-slate-800 space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-500 font-mono">Authentication Status</span>
                <p className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Active Enterprise Session
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === "ai" && (
        <Card>
          <CardHeader>
            <CardTitle><Cpu className="w-4 h-4 text-purple-400" /> AI Intelligence Engine Configuration</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="p-4 rounded-xl bg-gradient-to-r from-purple-950/40 to-indigo-950/30 border border-purple-500/30 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    {config?.aiEngine || "Gemini 3.7 Flash / Demo AI Mode"}
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    {config?.hasApiKey
                      ? "Direct server-side Google GenAI SDK integration with Gemini 3.7 Flash."
                      : "Operating in high-precision Deterministic CTI Mode (Demo AI Mode) for offline/academic resilience."}
                  </p>
                </div>
                <Badge variant={config?.hasApiKey ? "success" : "cyan"}>
                  {config?.hasApiKey ? "ONLINE (API KEY PRESENT)" : "DEMO AI MODE ACTIVE"}
                </Badge>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
                <div className="p-2.5 rounded-lg bg-[#070B14] border border-slate-800">
                  <span className="text-[10px] text-slate-500 font-mono uppercase block">Model Family</span>
                  <span className="text-xs font-bold text-slate-200">Gemini 3.7 Flash</span>
                </div>
                <div className="p-2.5 rounded-lg bg-[#070B14] border border-slate-800">
                  <span className="text-[10px] text-slate-500 font-mono uppercase block">Temperature</span>
                  <span className="text-xs font-bold text-slate-200">0.2 (High Precision CTI)</span>
                </div>
                <div className="p-2.5 rounded-lg bg-[#070B14] border border-slate-800">
                  <span className="text-[10px] text-slate-500 font-mono uppercase block">Fallback Mechanism</span>
                  <span className="text-xs font-bold text-slate-200">Automatic Deterministic</span>
                </div>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-[#070B14] border border-slate-800 space-y-2">
              <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                System Instruction & Safety Grounding
              </h4>
              <p className="text-xs text-slate-300 leading-relaxed font-mono bg-black/40 p-3 rounded-lg border border-slate-800">
                You are ShieldZen AI Analyst, an authoritative SOC intelligence advisor. Strictly provide defensive cybersecurity analysis, threat summaries, risk reasoning, and defensive recommendations.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === "sources" && (
        <Card>
          <CardHeader>
            <CardTitle><Database className="w-4 h-4 text-cyan-400" /> Integrated Data Sources & Feeds</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {dataSources.map((source) => (
              <div key={source.id} className="p-3.5 rounded-xl bg-[#070B14] border border-slate-800 flex items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <h4 className="text-xs font-bold text-white">{source.name}</h4>
                    <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-1.5 py-0.2 rounded border border-cyan-500/20">
                      {source.category}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">{source.description}</p>
                </div>

                <div className="flex items-center gap-3 flex-shrink-0">
                  <div className="text-right font-mono text-[10px]">
                    <span className="text-slate-500 block">LATENCY</span>
                    <span className="text-slate-300">{source.latency}</span>
                  </div>
                  <span className="px-2.5 py-1 rounded-lg text-xs font-mono font-bold bg-emerald-950/70 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    {source.status}
                  </span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {activeTab === "alerts" && (
        <Card>
          <CardHeader>
            <CardTitle><Bell className="w-4 h-4 text-amber-400" /> Alert Thresholds & Notification Policies</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between p-3 rounded-xl bg-[#070B14] border border-slate-800">
                <div>
                  <h4 className="text-xs font-bold text-white">Critical Severity Instant Alerting</h4>
                  <p className="text-[11px] text-slate-400">Trigger immediate high-priority notification when threat risk score exceeds 85/100.</p>
                </div>
                <input type="checkbox" defaultChecked className="w-4 h-4 accent-cyan-500 cursor-pointer" />
              </div>

              <div className="flex items-center justify-between p-3 rounded-xl bg-[#070B14] border border-slate-800">
                <div>
                  <h4 className="text-xs font-bold text-white">CISA KEV Match Detection Alert</h4>
                  <p className="text-[11px] text-slate-400">Notify SOC immediately when an ingested CVE is confirmed on the federal KEV catalog.</p>
                </div>
                <input type="checkbox" defaultChecked className="w-4 h-4 accent-cyan-500 cursor-pointer" />
              </div>

              <div className="flex items-center justify-between p-3 rounded-xl bg-[#070B14] border border-slate-800">
                <div>
                  <h4 className="text-xs font-bold text-white">Emerging Attack Surge Warnings</h4>
                  <p className="text-[11px] text-slate-400">Alert on time-series acceleration over 40% in ransomware or credential access vectors.</p>
                </div>
                <input type="checkbox" defaultChecked className="w-4 h-4 accent-cyan-500 cursor-pointer" />
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === "system" && (
        <Card>
          <CardHeader>
            <CardTitle><Server className="w-4 h-4 text-cyan-400" /> Academic Sandbox & Database Baseline</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="p-4 rounded-xl bg-[#070B14] border border-slate-800 space-y-3">
              <div className="flex items-start gap-3">
                <Info className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-xs font-bold text-white">Sandboxed Threat Intelligence Prototype</h4>
                  <p className="text-xs text-slate-400 leading-relaxed mt-1">
                    ShieldZen operates as a defensive research platform. All simulated scenarios, vulnerability catalogs, and threat mappings are isolated within this sandbox environment.
                  </p>
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-xs font-bold text-slate-200">Re-seed Baseline CTI Scenarios</span>
                  <p className="text-[11px] text-slate-400">Restores all threats, reports, IOCs, incidents, and predictions to the verified baseline.</p>
                </div>
                <button
                  onClick={handleResetData}
                  disabled={resetting}
                  className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/30 rounded-xl text-xs font-bold transition-colors flex items-center gap-2"
                >
                  <RefreshCw className={cn("w-3.5 h-3.5", resetting && "animate-spin")} />
                  <span>{resetting ? "Resetting..." : "Reset to Baseline"}</span>
                </button>
              </div>

              {resetMessage && (
                <div className="p-3 rounded-lg bg-cyan-950/40 border border-cyan-500/40 text-cyan-300 text-xs font-mono">
                  {resetMessage}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

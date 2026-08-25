import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import {
  User, Cpu, Database, Radio, Shield, Bell, Key, RefreshCw, CheckCircle2,
  AlertTriangle, Server, Lock, ExternalLink, HardDrive, Info, Globe, Clock,
  ArrowDownCircle, Search, Filter, Flame, Layers, ShieldCheck, Zap
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent, Badge, cn } from "../components/ui";
import { IntelligenceSourceInfo, IntelligenceFeedItem } from "../types";

export default function Settings() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<"profile" | "ai" | "sources" | "feed" | "alerts" | "audit" | "system">("sources");
  const [dataSources, setDataSources] = useState<IntelligenceSourceInfo[]>([]);
  const [lastSystemSync, setLastSystemSync] = useState<string>("");
  const [config, setConfig] = useState<any>(null);
  const [resetting, setResetting] = useState(false);
  const [resetMessage, setResetMessage] = useState<string | null>(null);
  const [auditLogsList, setAuditLogsList] = useState<any[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);

  // Syncing state per source
  const [syncingSource, setSyncingSource] = useState<string | null>(null);
  const [syncNotification, setSyncNotification] = useState<{ source: string; message: string; isError?: boolean } | null>(null);

  // Feed Explorer State
  const [feedItems, setFeedItems] = useState<IntelligenceFeedItem[]>([]);
  const [feedLoading, setFeedLoading] = useState(false);
  const [feedSearch, setFeedSearch] = useState("");
  const [feedSourceFilter, setFeedSourceFilter] = useState("ALL");
  const [feedKevOnly, setFeedKevOnly] = useState(false);
  const [selectedFeedItem, setSelectedFeedItem] = useState<IntelligenceFeedItem | null>(null);

  const fetchSourceStatus = () => {
    fetch("/api/datasources/status")
      .then(res => res.json())
      .then(data => {
        if (data.sources) {
          setDataSources(data.sources);
          setLastSystemSync(data.lastSync || new Date().toISOString());
        }
      })
      .catch(() => {});
  };

  const fetchFeed = () => {
    setFeedLoading(true);
    const params = new URLSearchParams();
    if (feedSourceFilter !== "ALL") params.append("source", feedSourceFilter);
    if (feedKevOnly) params.append("isKevOnly", "true");
    if (feedSearch.trim()) params.append("search", feedSearch.trim());
    params.append("limit", "40");

    fetch(`/api/datasources/feed?${params.toString()}`)
      .then(res => res.json())
      .then(data => {
        setFeedItems(Array.isArray(data) ? data : []);
      })
      .catch(err => console.error("Error loading feed:", err))
      .finally(() => setFeedLoading(false));
  };

  useEffect(() => {
    fetch("/api/config")
      .then(res => res.json())
      .then(data => setConfig(data))
      .catch(() => {});

    fetchSourceStatus();
  }, []);

  useEffect(() => {
    if (activeTab === "feed") {
      fetchFeed();
    }
    if (activeTab === "audit") {
      setAuditLoading(true);
      fetch("/api/auth/audit-logs")
        .then(res => res.json())
        .then(data => setAuditLogsList(Array.isArray(data) ? data : []))
        .catch(err => console.error("Error fetching audit logs:", err))
        .finally(() => setAuditLoading(false));
    }
  }, [activeTab, feedSourceFilter, feedKevOnly]);

  const handleSyncSource = async (sourceId: string) => {
    setSyncingSource(sourceId);
    setSyncNotification(null);
    try {
      const res = await fetch(`/api/datasources/${sourceId}/sync`, { method: "POST" });
      const data = await res.json();
      if (res.ok) {
        setSyncNotification({
          source: sourceId,
          message: data.message || `Successfully synced ${sourceId.toUpperCase()}`
        });
        fetchSourceStatus();
        if (activeTab === "feed") fetchFeed();
      } else {
        setSyncNotification({
          source: sourceId,
          message: data.error || `Sync failed for ${sourceId}`,
          isError: true
        });
      }
    } catch (e: any) {
      setSyncNotification({
        source: sourceId,
        message: `Network error during sync: ${e.message}`,
        isError: true
      });
    } finally {
      setSyncingSource(null);
    }
  };

  const handleResetData = async () => {
    setResetting(true);
    setResetMessage(null);
    try {
      const res = await fetch("/api/reset-data", { method: "POST" });
      const data = await res.json();
      if (data.success) {
        setResetMessage("Successfully reset CTI database to verified synthetic baseline.");
        fetchSourceStatus();
      } else {
        setResetMessage("Failed to reset: " + data.error);
      }
    } catch (e: any) {
      setResetMessage("Error resetting dataset: " + e.message);
    } finally {
      setResetting(false);
    }
  };

  const getFreshnessBadge = (label: string) => {
    switch (label) {
      case "LIVE":
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />LIVE</span>;
      case "RECENT":
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30">RECENT CACHE</span>;
      case "STALE":
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">STALE</span>;
      case "OUTDATED":
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">OUTDATED</span>;
      case "SYNTHETIC":
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/10 text-purple-400 border border-purple-500/30">SYNTHETIC</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-500/10 text-slate-400 border border-slate-500/30">{label}</span>;
    }
  };

  const tabs = [
    { id: "sources", label: "Data Sources & Provenance", icon: Database },
    { id: "feed", label: "Live Threat Feeds (NVD & KEV)", icon: Globe },
    { id: "ai", label: "AI Engine Configuration", icon: Cpu },
    { id: "profile", label: "Analyst Profile", icon: User },
    { id: "audit", label: "Security & Audit Trail", icon: Lock },
    { id: "alerts", label: "Alerting & Policies", icon: Bell },
    { id: "system", label: "System Baseline & Recovery", icon: Server }
  ];

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="pb-3 border-b border-slate-800/80 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-xl font-extrabold text-white tracking-tight flex items-center gap-2.5">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            Intelligence Architecture & Provenance Settings
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Hybrid CTI feed orchestration, live NIST NVD & CISA KEV synchronization, and deterministic risk data provenance.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              fetchSourceStatus();
              if (activeTab === "feed") fetchFeed();
            }}
            className="px-3 py-1.5 bg-slate-900/80 hover:bg-slate-800 text-cyan-400 border border-slate-700 rounded-xl text-xs font-mono font-semibold transition-all flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh Telemetry
          </button>
        </div>
      </div>

      {/* Sync Notification Banner */}
      {syncNotification && (
        <div className={cn(
          "p-3.5 rounded-xl border flex items-center justify-between gap-3 text-xs font-mono animate-in fade-in slide-in-from-top-1",
          syncNotification.isError
            ? "bg-rose-950/40 border-rose-500/40 text-rose-300"
            : "bg-emerald-950/40 border-emerald-500/40 text-emerald-300"
        )}>
          <div className="flex items-center gap-2">
            {syncNotification.isError ? <AlertTriangle className="w-4 h-4 text-rose-400" /> : <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
            <span>{syncNotification.message}</span>
          </div>
          <button
            onClick={() => setSyncNotification(null)}
            className="text-slate-400 hover:text-white text-xs px-2"
          >
            Dismiss
          </button>
        </div>
      )}

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

      {/* Tab: Data Sources & Provenance */}
      {activeTab === "sources" && (
        <div className="space-y-6">
          {/* Hybrid Architecture Overview Banner */}
          <div className="p-4 rounded-2xl bg-gradient-to-r from-cyan-950/40 via-blue-950/30 to-slate-950/60 border border-cyan-500/30">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-500/30">
                    Hybrid CTI Architecture
                  </span>
                  <span className="text-xs text-slate-400">• Last Global Check: {new Date(lastSystemSync).toLocaleTimeString()}</span>
                </div>
                <h3 className="text-sm font-bold text-white">Dual Live-API & Cached Fallback Engine</h3>
                <p className="text-xs text-slate-300 max-w-3xl leading-relaxed">
                  ShieldZen implements a resilient threat intelligence pipeline: live CVE lookups from NIST NVD and real-time active exploitation tracking via CISA KEV, coupled with deterministic offline catalogs and synthetic telemetry for sandboxed academic analysis.
                </p>
              </div>

              <div className="flex items-center gap-2 flex-shrink-0">
                <button
                  onClick={() => handleSyncSource("nvd")}
                  disabled={syncingSource === "nvd"}
                  className="px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-bold transition-all shadow-md shadow-cyan-950 flex items-center gap-2 disabled:opacity-50"
                >
                  <RefreshCw className={cn("w-3.5 h-3.5", syncingSource === "nvd" && "animate-spin")} />
                  <span>{syncingSource === "nvd" ? "Syncing NVD..." : "Sync NIST NVD"}</span>
                </button>
                <button
                  onClick={() => handleSyncSource("cisa_kev")}
                  disabled={syncingSource === "cisa_kev"}
                  className="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-bold transition-all shadow-md shadow-blue-950 flex items-center gap-2 disabled:opacity-50"
                >
                  <RefreshCw className={cn("w-3.5 h-3.5", syncingSource === "cisa_kev" && "animate-spin")} />
                  <span>{syncingSource === "cisa_kev" ? "Syncing KEV..." : "Sync CISA KEV"}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Sources Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {dataSources.map((source) => {
              const isSyncing = syncingSource === source.id;
              const canManualSync = source.id === "nvd" || source.id === "cisa_kev";

              return (
                <div
                  key={source.id}
                  className="p-4 rounded-2xl bg-[#070B14] border border-slate-800/80 hover:border-slate-700 transition-all flex flex-col justify-between space-y-4"
                >
                  <div>
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div>
                        <div className="flex items-center gap-2">
                          <h4 className="text-sm font-bold text-white tracking-tight">{source.name}</h4>
                        </div>
                        <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/20 mt-1 inline-block">
                          {source.sourceType.replace("_", " ")}
                        </span>
                      </div>
                      <div className="flex flex-col items-end gap-1">
                        {getFreshnessBadge(source.freshnessLabel)}
                        <span className="text-[10px] font-mono text-slate-400">
                          {source.syncDurationMs}ms latency
                        </span>
                      </div>
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed mb-3">
                      {source.description}
                    </p>

                    {/* Metadata Specs */}
                    <div className="grid grid-cols-2 gap-2 p-2.5 rounded-xl bg-slate-900/50 border border-slate-800 text-[11px] font-mono">
                      <div>
                        <span className="text-slate-500 block text-[10px] uppercase">Catalog Volume</span>
                        <span className="text-slate-200 font-bold">{source.recordCount.toLocaleString()} Entries</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px] uppercase">Sync Cadence</span>
                        <span className="text-slate-200">Every {source.syncIntervalMinutes}m</span>
                      </div>
                      <div className="col-span-2 pt-1 border-t border-slate-800/60">
                        <span className="text-slate-500 block text-[10px] uppercase">Last Synchronization</span>
                        <span className="text-cyan-400">
                          {source.lastSuccessfulSync ? new Date(source.lastSuccessfulSync).toLocaleString() : "Initialization Cached"}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between">
                    <span className="text-[10px] font-mono text-slate-500">
                      {source.isSynthetic ? "Synthetic CTI" : "Verified Feed"}
                    </span>

                    {canManualSync ? (
                      <button
                        onClick={() => handleSyncSource(source.id)}
                        disabled={isSyncing}
                        className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/30 rounded-lg text-xs font-mono font-bold transition-all flex items-center gap-1.5 disabled:opacity-50"
                      >
                        <RefreshCw className={cn("w-3 h-3", isSyncing && "animate-spin")} />
                        <span>{isSyncing ? "Syncing..." : "Manual Sync"}</span>
                      </button>
                    ) : (
                      <span className="text-[10px] font-mono text-emerald-400/80 bg-emerald-950/30 px-2 py-0.5 rounded border border-emerald-500/20">
                        Always Available
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Tab: Threat Feeds Explorer */}
      {activeTab === "feed" && (
        <div className="space-y-4">
          <div className="p-4 rounded-2xl bg-[#070B14] border border-slate-800 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Globe className="w-4 h-4 text-cyan-400" />
                  Unified External Threat Intelligence Feed
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Search live and cached CVE records from NIST NVD and actively exploited vulnerabilities from CISA KEV.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={fetchFeed}
                  disabled={feedLoading}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded-xl text-xs font-mono font-bold border border-cyan-500/30 flex items-center gap-1.5"
                >
                  <RefreshCw className={cn("w-3 h-3", feedLoading && "animate-spin")} />
                  <span>Reload Feed</span>
                </button>
              </div>
            </div>

            {/* Filter Bar */}
            <div className="grid grid-cols-1 sm:grid-cols-12 gap-2.5 pt-2">
              <div className="sm:col-span-6 relative">
                <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search CVE ID (e.g. CVE-2023-38606), vendor, product, or keyword..."
                  value={feedSearch}
                  onChange={(e) => setFeedSearch(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && fetchFeed()}
                  className="w-full pl-9 pr-3 py-2 bg-slate-900/80 border border-slate-700 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="sm:col-span-3">
                <select
                  value={feedSourceFilter}
                  onChange={(e) => setFeedSourceFilter(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900/80 border border-slate-700 rounded-xl text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="ALL">All Catalogs (NVD & KEV)</option>
                  <option value="NVD">NIST NVD Only</option>
                  <option value="CISA_KEV">CISA KEV Only</option>
                </select>
              </div>

              <div className="sm:col-span-3 flex items-center">
                <label className="flex items-center gap-2 px-3 py-2 bg-slate-900/80 border border-slate-700 rounded-xl text-xs text-slate-300 w-full cursor-pointer hover:bg-slate-800/80">
                  <input
                    type="checkbox"
                    checked={feedKevOnly}
                    onChange={(e) => setFeedKevOnly(e.target.checked)}
                    className="w-4 h-4 accent-cyan-500"
                  />
                  <span className="font-bold text-red-400">CISA KEV Only</span>
                </label>
              </div>
            </div>
          </div>

          {/* Feed Records Table */}
          <div className="rounded-2xl border border-slate-800 bg-[#070B14] overflow-hidden">
            <div className="p-3 border-b border-slate-800 bg-slate-900/30 flex items-center justify-between text-xs font-mono text-slate-400">
              <span>Showing {feedItems.length} Intelligence Items</span>
              <span>Sorted by Freshness & Criticality</span>
            </div>

            {feedLoading ? (
              <div className="p-12 text-center text-slate-400 space-y-2 font-mono text-xs">
                <RefreshCw className="w-5 h-5 animate-spin mx-auto text-cyan-400" />
                <p>Loading threat intelligence feed from NVD & CISA KEV...</p>
              </div>
            ) : feedItems.length === 0 ? (
              <div className="p-12 text-center text-slate-400 space-y-2">
                <AlertTriangle className="w-6 h-6 mx-auto text-amber-400" />
                <p className="text-xs">No intelligence records match the specified search or filter criteria.</p>
              </div>
            ) : (
              <div className="divide-y divide-slate-800/60 max-h-[600px] overflow-y-auto">
                {feedItems.map((item) => {
                  const isCritical = item.cvssScore >= 9.0;
                  const isHigh = item.cvssScore >= 7.0 && item.cvssScore < 9.0;

                  return (
                    <div
                      key={item.id}
                      onClick={() => setSelectedFeedItem(item)}
                      className="p-4 hover:bg-slate-900/40 transition-colors cursor-pointer space-y-2"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2.5 flex-wrap">
                          <span className="text-xs font-extrabold font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/30">
                            {item.cveId}
                          </span>

                          <span className={cn(
                            "text-[10px] font-mono font-bold px-2 py-0.5 rounded border",
                            isCritical
                              ? "bg-red-500/10 text-red-400 border-red-500/30"
                              : isHigh
                              ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                              : "bg-blue-500/10 text-blue-400 border-blue-500/30"
                          )}>
                            CVSS {item.cvssScore.toFixed(1)} {item.cvssSeverity}
                          </span>

                          {item.isCisaKev && (
                            <span className="text-[10px] font-mono font-extrabold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 flex items-center gap-1">
                              <Flame className="w-3 h-3 text-rose-400" /> CISA KEV
                            </span>
                          )}

                          {item.knownRansomwareUse === "Known" && (
                            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-purple-500/15 text-purple-300 border border-purple-500/30">
                              Ransomware
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono text-slate-400">
                            {item.sourceName}
                          </span>
                          {getFreshnessBadge(item.freshnessLabel)}
                        </div>
                      </div>

                      <p className="text-xs text-slate-300 leading-relaxed line-clamp-2">
                        {item.description}
                      </p>

                      <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1">
                        <div className="flex items-center gap-2">
                          <span>Products: {item.affectedProducts.slice(0, 3).join(", ") || "General"}</span>
                        </div>
                        <span>Synced: {new Date(item.lastSyncedAt).toLocaleDateString()}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab: AI Engine */}
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

      {/* Tab: Profile */}
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

      {/* Tab: Audit Logs */}
      {activeTab === "audit" && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle><Lock className="w-4 h-4 text-cyan-400" /> Security Audit Trail & Access Logs</CardTitle>
              <button
                onClick={() => {
                  setAuditLoading(true);
                  fetch("/api/auth/audit-logs")
                    .then(res => res.json())
                    .then(data => setAuditLogsList(Array.isArray(data) ? data : []))
                    .finally(() => setAuditLoading(false));
                }}
                className="px-2.5 py-1 text-[11px] font-mono text-cyan-400 hover:text-cyan-300 bg-cyan-950/60 border border-cyan-500/30 rounded-lg flex items-center gap-1.5"
              >
                <RefreshCw className={cn("w-3 h-3", auditLoading && "animate-spin")} />
                <span>Refresh Log</span>
              </button>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-xs text-slate-400 leading-relaxed">
              Real-time audit log of all security lifecycle events including registrations, email verifications, logins, password resets, and intelligence ingestion operations.
            </p>

            <div className="rounded-xl border border-slate-800 bg-[#070B14] overflow-hidden">
              <div className="max-h-96 overflow-y-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900/90 text-[10px] font-mono uppercase text-slate-400 sticky top-0 border-b border-slate-800">
                    <tr>
                      <th className="p-2.5">Timestamp</th>
                      <th className="p-2.5">Action</th>
                      <th className="p-2.5">User / Target</th>
                      <th className="p-2.5">Resource</th>
                      <th className="p-2.5">IP Address</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                    {auditLogsList.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="p-4 text-center text-slate-500">
                          {auditLoading ? "Loading audit trail..." : "No audit entries found."}
                        </td>
                      </tr>
                    ) : (
                      auditLogsList.map((log) => (
                        <tr key={log.id} className="hover:bg-slate-900/50">
                          <td className="p-2.5 text-slate-400 whitespace-nowrap">
                            {new Date(log.timestamp).toLocaleString()}
                          </td>
                          <td className="p-2.5">
                            <span className={cn(
                              "px-2 py-0.5 rounded text-[10px] font-bold",
                              log.action.includes("FAIL") || log.action.includes("BLOCKED") || log.action.includes("EXPIRED")
                                ? "bg-red-950 text-red-300 border border-red-800/60"
                                : log.action.includes("SUCCESS") || log.action.includes("VERIFIED")
                                ? "bg-emerald-950 text-emerald-300 border border-emerald-800/60"
                                : "bg-cyan-950 text-cyan-300 border border-cyan-800/60"
                            )}>
                              {log.action}
                            </span>
                          </td>
                          <td className="p-2.5 text-slate-200">{log.userEmail || "System"}</td>
                          <td className="p-2.5 text-slate-400">
                            {log.resourceType ? `${log.resourceType}: ${log.resourceId || "-"}` : "-"}
                          </td>
                          <td className="p-2.5 text-slate-500">{log.ipAddress || "local"}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tab: Alerts */}
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

      {/* Tab: System Baseline */}
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

            {user?.role === "admin" && (
              <div className="p-4 rounded-xl bg-[#070B14] border border-slate-800 space-y-3">
                <div className="pt-3 flex items-center justify-between">
                  <div>
                    <span className="text-xs font-bold text-slate-200">Database Explorer (Admin Only)</span>
                    <p className="text-[11px] text-slate-400">View actual SQLite database records in a secure, read-only environment.</p>
                  </div>
                  <Link
                    to="/database-explorer"
                    className="px-3.5 py-2 bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/30 rounded-xl text-xs font-bold transition-colors flex items-center gap-2"
                  >
                    <Database className="w-3.5 h-3.5" />
                    <span>Open Explorer</span>
                  </Link>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Modal Detail for Selected Feed Item */}
      {selectedFeedItem && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#070B14] border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-4 shadow-2xl max-h-[85vh] overflow-y-auto">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-xs font-mono text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-500/30">
                  {selectedFeedItem.sourceName} • {selectedFeedItem.provider}
                </span>
                <h3 className="text-base font-bold text-white mt-1.5">{selectedFeedItem.cveId}</h3>
              </div>
              <button
                onClick={() => setSelectedFeedItem(null)}
                className="text-slate-400 hover:text-white text-xs px-2 py-1 bg-slate-900 rounded-lg border border-slate-800 font-mono"
              >
                Close (ESC)
              </button>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-bold font-mono px-2.5 py-1 rounded bg-purple-500/10 text-purple-400 border border-purple-500/30">
                CVSS {selectedFeedItem.cvssScore.toFixed(1)} {selectedFeedItem.cvssSeverity}
              </span>
              {selectedFeedItem.isCisaKev && (
                <span className="text-xs font-bold font-mono px-2.5 py-1 rounded bg-red-500/15 text-red-400 border border-red-500/30 flex items-center gap-1">
                  <Flame className="w-3.5 h-3.5" /> Confirmed CISA KEV Exploitation
                </span>
              )}
              {getFreshnessBadge(selectedFeedItem.freshnessLabel)}
            </div>

            <div className="space-y-2">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">Vulnerability Description</h4>
              <p className="text-xs text-slate-300 leading-relaxed bg-slate-900/60 p-3 rounded-xl border border-slate-800">
                {selectedFeedItem.description}
              </p>
            </div>

            {selectedFeedItem.isCisaKev && (
              <div className="p-3.5 rounded-xl bg-rose-950/30 border border-rose-500/30 space-y-2 text-xs font-mono">
                <span className="text-rose-400 font-bold uppercase block">CISA Directive & Remediation</span>
                <p className="text-slate-300">{selectedFeedItem.cisaRequiredAction || "Apply vendor patch immediately according to BOD 22-01."}</p>
                <div className="flex items-center gap-4 text-slate-400 pt-1">
                  <span>Date Added: {selectedFeedItem.cisaDateAdded || "Recent"}</span>
                  <span>Due Date: {selectedFeedItem.cisaDueDate || "Immediate"}</span>
                </div>
              </div>
            )}

            <div className="space-y-1 text-xs font-mono">
              <span className="text-slate-400 uppercase text-[10px]">Affected Products</span>
              <p className="text-slate-300 bg-slate-900/40 p-2 rounded-lg border border-slate-800/80">
                {selectedFeedItem.affectedProducts.join(", ") || "General enterprise network components"}
              </p>
            </div>

            <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
              <span className="text-[10px] font-mono text-slate-500">
                Synchronized at {new Date(selectedFeedItem.lastSyncedAt).toLocaleString()}
              </span>
              <button
                onClick={() => setSelectedFeedItem(null)}
                className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-bold font-mono transition-all"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

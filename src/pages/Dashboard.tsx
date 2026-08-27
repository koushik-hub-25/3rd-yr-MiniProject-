import React, { useEffect, useState, useRef } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
  Badge,
  SeverityBadge,
  ConfidenceMeter,
  SourceBadge,
  cn
} from "../components/ui";
import { useRealtimeEvent } from "../context/RealtimeContext";
import {
  ShieldAlert,
  FileText,
  Activity,
  TrendingUp,
  AlertTriangle,
  UploadCloud,
  CheckCircle2,
  Database,
  ArrowRight,
  ExternalLink,
  Cpu,
  RefreshCw,
  Search,
  Sparkles,
  Layers,
  Radio,
  Clock,
  ShieldCheck,
  Bot,
  MapPin,
  Globe,
  Check,
  AlertCircle,
  BarChart3,
  Server,
  Zap,
  Lock,
  Network,
  Share2,
  ChevronRight,
  Terminal,
  Shield
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar
} from "recharts";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import type { Threat, Incident, Prediction } from "../types";
import { SourceFilterBar, SourceFilterType } from "../components/SourceFilterBar";
import { useAuth } from "../context/AuthContext";
import { AIAnalystDrawer } from "../components/AIAnalystDrawer";

export default function Dashboard() {
  const { user } = useAuth();
  const navigate = useNavigate();

  // State
  const [stats, setStats] = useState<any>({
    totalReports: 0,
    totalThreats: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    totalIocs: 0,
    totalIncidents: 0,
    emergingThreats: 0,
    activeThreats: 0
  });
  const [threats, setThreats] = useState<Threat[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [predictions, setPredictions] = useState<Prediction[]>([]);
  const [heatmapPoints, setHeatmapPoints] = useState<any[]>([]);
  const [analytics, setAnalytics] = useState<any>(null);
  const [config, setConfig] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  // Filters & Controls
  const [activityTimeframe, setActivityTimeframe] = useState<"7D" | "30D" | "90D">("30D");
  const [activitySource, setActivitySource] = useState<"ALL" | "NVD" | "CISA_KEV" | "REPORTS" | "SYNTHETIC">("ALL");
  const [prioritySourceFilter, setPrioritySourceFilter] = useState<SourceFilterType>("ALL");
  const [mapRiskFilter, setMapRiskFilter] = useState<"ALL" | "CRITICAL" | "HIGH" | "MEDIUM">("ALL");

  // AI Drawer
  const [aiDrawerOpen, setAiDrawerOpen] = useState(false);
  const [aiDrawerPrompt, setAiDrawerPrompt] = useState<string | undefined>(undefined);
  const [lastUpdated, setLastUpdated] = useState<string>(
    new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  );

  // Remediation Action Checklist
  const [completedActions, setCompletedActions] = useState<Record<string, boolean>>({
    action_1: true,
    action_2: false,
    action_3: false,
    action_4: false
  });

  const toggleAction = (key: string) => {
    setCompletedActions((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const [sRes, tRes, iRes, pRes, hRes, aRes, cRes] = await Promise.all([
        fetch("/api/stats").then((r) => r.json()).catch(() => ({})),
        fetch("/api/threats").then((r) => r.json()).catch(() => []),
        fetch("/api/incidents").then((r) => r.json()).catch(() => []),
        fetch("/api/predictions").then((r) => r.json()).catch(() => []),
        fetch("/api/heatmap").then((r) => r.json()).catch(() => []),
        fetch("/api/analytics").then((r) => r.json()).catch(() => null),
        fetch("/api/config").then((r) => r.json()).catch(() => null)
      ]);

      setStats(
        sRes && !sRes.error
          ? sRes
          : {
              totalReports: 0,
              totalThreats: 0,
              critical: 0,
              high: 0,
              medium: 0,
              low: 0,
              totalIocs: 0,
              totalIncidents: 0,
              emergingThreats: 0,
              activeThreats: 0
            }
      );
      setThreats(Array.isArray(tRes) ? tRes : []);
      setIncidents(Array.isArray(iRes) ? iRes : []);
      setPredictions(Array.isArray(pRes) ? pRes : []);
      setHeatmapPoints(Array.isArray(hRes) ? hRes : []);
      setAnalytics(aRes && !aRes.error ? aRes : null);
      setConfig(cRes && !cRes.error ? cRes : null);
      setLastUpdated(new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
    } catch (e) {
      console.error("Dashboard fetch error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  // Real-Time SSE Targeted Refreshes
  useRealtimeEvent("intelligence.synced", () => {
    fetchDashboardData(true);
  });
  useRealtimeEvent("report.correlated", () => {
    fetchDashboardData(true);
  });
  useRealtimeEvent("vulnerability.updated", () => {
    fetchDashboardData(true);
  });
  useRealtimeEvent("threatmap.updated", () => {
    fetchDashboardData(true);
  });

  const handleMarkReviewed = async (threatId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await fetch(`/api/threats/${threatId}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: "reviewed" })
      });
      setThreats((prev) =>
        prev.map((t) => (t.id === threatId ? { ...t, status: "reviewed" } : t))
      );
    } catch (err) {
      console.error("Failed to mark reviewed", err);
    }
  };

  // Filtered threats for Priority Threats section
  const filteredPriorityThreats = threats.filter((t) => {
    if (prioritySourceFilter === "ALL") return true;
    const txt = `${t.title} ${t.description} ${t.source || ""}`.toUpperCase();
    if (prioritySourceFilter === "NVD") return txt.includes("CVE");
    if (prioritySourceFilter === "CISA_KEV") return t.severity === "CRITICAL" || txt.includes("EXPLOIT");
    if (prioritySourceFilter === "MITRE") return Boolean(t.mitreTechniques);
    if (prioritySourceFilter === "REPORTS") return (t.source || "").toUpperCase().includes("REPORT");
    if (prioritySourceFilter === "AI") return (t.source || "").toUpperCase().includes("AI");
    return true;
  });

  // Filtered heatmap points
  const filteredMapPoints = heatmapPoints.filter((p) => {
    const w = p.weight ?? (p.severity === "CRITICAL" ? 9 : p.severity === "HIGH" ? 7 : p.severity === "MEDIUM" ? 5 : 3);
    if (mapRiskFilter === "CRITICAL") return w >= 8;
    if (mapRiskFilter === "HIGH") return w >= 6 && w < 8;
    if (mapRiskFilter === "MEDIUM") return w >= 4 && w < 6;
    return true;
  });

  // Donut chart data
  const pieData = [
    { name: "Critical", value: stats.critical || 0, color: "#ef4444" },
    { name: "High", value: stats.high || 0, color: "#f97316" },
    { name: "Medium", value: stats.medium || 0, color: "#eab308" },
    { name: "Low", value: stats.low || 0, color: "#10b981" }
  ].filter((d) => d.value > 0);

  // Timeframe-adapted chart series
  const rawTrend = analytics?.monthlyTrend || [
    { month: "Sep", critical: 8, high: 14, medium: 22 },
    { month: "Oct", critical: 11, high: 19, medium: 28 },
    { month: "Nov", critical: 15, high: 24, medium: 34 },
    { month: "Dec", critical: 18, high: 29, medium: 41 },
    { month: "Jan", critical: 22, high: 36, medium: 48 },
    { month: "Feb", critical: 27, high: 42, medium: 55 }
  ];

  const displayTrend =
    activityTimeframe === "7D"
      ? [
          { month: "Day 1", critical: 4, high: 7, medium: 10 },
          { month: "Day 2", critical: 5, high: 6, medium: 12 },
          { month: "Day 3", critical: 7, high: 9, medium: 11 },
          { month: "Day 4", critical: 6, high: 8, medium: 14 },
          { month: "Day 5", critical: 9, high: 11, medium: 15 },
          { month: "Day 6", critical: 8, high: 12, medium: 13 },
          { month: "Today", critical: 10, high: 14, medium: 16 }
        ]
      : activityTimeframe === "90D"
      ? [
          { month: "Month -3", critical: 12, high: 18, medium: 28 },
          { month: "Month -2", critical: 19, high: 26, medium: 38 },
          { month: "Month -1", critical: 24, high: 35, medium: 46 },
          { month: "Current", critical: 29, high: 44, medium: 58 }
        ]
      : rawTrend;

  // Emerging threats default fallback
  const displayPredictions =
    predictions.length > 0
      ? predictions.slice(0, 3)
      : [
          {
            id: "pred-1",
            threatType: "Edge Gateway & VPN Zero-Day Exploitation",
            predictedDate: "Next 14 Days",
            confidence: 88,
            indicators: ["CVE-2024-3400", "PAN-OS GlobalProtect", "Command Injection"],
            reasoning: "Surge in automated scanning targeting edge appliances and perimeter firewalls.",
            trendDirection: "Increasing",
            growthRate: "+42%",
            supportingIncidentsCount: 8
          },
          {
            id: "pred-2",
            threatType: "Ransomware-as-a-Service Double Extortion",
            predictedDate: "Next 30 Days",
            confidence: 82,
            indicators: ["LockBit 3.0", "BlackCat/ALPHV", "Living-off-the-Land (LotL)"],
            reasoning: "Lateral movement observed via compromised privileged service accounts.",
            trendDirection: "Increasing",
            growthRate: "+28%",
            supportingIncidentsCount: 14
          },
          {
            id: "pred-3",
            threatType: "Supply Chain Dependency Compromise",
            predictedDate: "Next 45 Days",
            confidence: 76,
            indicators: ["XZ Utils Backdoor", "NPM Typosquatting", "PyPI Injection"],
            reasoning: "Adversary infiltration into upstream open-source package repositories.",
            trendDirection: "Accelerating",
            growthRate: "+35%",
            supportingIncidentsCount: 6
          }
        ];

  return (
    <div className="w-full bg-[#070B14] text-[#E0E6ED] flex flex-col">
      {/* =========================================================================
          SECTION 1: HERO SECTION
          ========================================================================= */}
      <section id="section-hero" className="relative w-full border-b border-slate-800/80 bg-gradient-to-b from-[#080D1A] via-[#070B14] to-[#070B14] py-20 sm:py-28 overflow-hidden">
        {/* Subtle Cyber Grid & Ambient Glowing Orbs */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b10_1px,transparent_1px),linear-gradient(to_bottom,#1e293b10_1px,transparent_1px)] bg-[size:48px_48px] pointer-events-none" />
        <div className="absolute top-10 left-1/2 -translate-x-1/2 w-[700px] h-[350px] bg-cyan-600/10 rounded-full blur-[120px] pointer-events-none" />
        <div className="absolute top-40 right-10 w-[400px] h-[300px] bg-indigo-600/10 rounded-full blur-[100px] pointer-events-none" />

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10 text-center flex flex-col items-center space-y-6">
          {/* Small Label Pill */}
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-cyan-950/70 border border-cyan-500/30 text-[11px] font-mono font-bold text-cyan-300 tracking-wider uppercase shadow-inner">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            SHIELDZEN INTELLIGENCE PLATFORM
          </div>

          {/* Main Headline */}
          <h1 className="text-4xl sm:text-6xl lg:text-7xl font-extrabold text-white tracking-tight max-w-4xl leading-[1.1]">
            See Beyond the <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-300 to-indigo-400">Noise.</span>
          </h1>

          {/* Supporting Headline */}
          <p className="text-base sm:text-lg lg:text-xl text-slate-300 max-w-2xl font-normal leading-relaxed">
            AI-powered cybersecurity intelligence that turns fragmented signals into prioritized, explainable risk.
          </p>

          {/* Call to Actions */}
          <div className="flex items-center justify-center gap-3.5 pt-2 flex-wrap w-full sm:w-auto">
            <Link
              to="/threat-intelligence"
              id="hero-btn-explore"
              className="px-6 py-3 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs sm:text-sm font-bold flex items-center gap-2 shadow-lg shadow-cyan-950/60 transition-all border border-cyan-400/30 group cursor-pointer"
            >
              <span>Explore Intelligence</span>
              <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
            </Link>

            <Link
              to="/upload"
              id="hero-btn-upload"
              className="px-6 py-3 bg-slate-900/90 hover:bg-slate-800 text-slate-200 hover:text-white rounded-xl text-xs sm:text-sm font-bold flex items-center gap-2 border border-slate-700/80 shadow-md transition-all cursor-pointer"
            >
              <UploadCloud className="w-4 h-4 text-cyan-400" />
              <span>Upload Report</span>
            </Link>

            <button
              id="hero-btn-ai-brief"
              onClick={() => {
                setAiDrawerPrompt(
                  "Provide an executive summary of current critical cyber threats, active exploitation vectors across NVD and CISA KEV, and prioritized SOC analyst recommendations."
                );
                setAiDrawerOpen(true);
              }}
              className="px-5 py-3 bg-indigo-950/60 hover:bg-indigo-900/80 border border-indigo-500/40 text-indigo-200 hover:text-white rounded-xl text-xs sm:text-sm font-bold flex items-center gap-2 transition-all cursor-pointer"
            >
              <Bot className="w-4 h-4 text-indigo-400" />
              <span>AI Executive Brief</span>
            </button>
          </div>

          {/* Subtle Live Status Indicators */}
          <div className="pt-6 flex items-center justify-center gap-4 sm:gap-8 text-[11px] font-mono text-slate-400 flex-wrap">
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> NIST NVD Synced
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-red-400" /> CISA KEV Active
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" /> MITRE Matrix v15
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" /> Gemini AI Online
            </span>
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 2: THREAT OVERVIEW (MINIMALIST STAT BLOCKS)
          ========================================================================= */}
      <section id="section-threat-overview" className="w-full border-b border-slate-800/80 py-16 sm:py-20 bg-[#080D1A]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-10">
          <div className="text-center sm:text-left space-y-1">
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Threat Intelligence at a Glance
            </h2>
            <p className="text-xs sm:text-sm text-slate-400">
              Aggregated visibility across vulnerabilities, exploits, and unstructured threat advisories.
            </p>
          </div>

          {/* 6 Minimalist Stat Blocks with large typography and subtle separators */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 divide-y lg:divide-y-0 lg:divide-x divide-slate-800/80 border-y border-slate-800/80 py-6">
            {/* 1. Total Threats */}
            <div className="p-4 sm:p-6 text-center sm:text-left flex flex-col justify-between space-y-2">
              <div className="text-[11px] font-mono font-bold uppercase tracking-wider text-slate-400">
                Total Threats
              </div>
              <div className="text-3xl sm:text-4xl font-extrabold text-white font-mono tracking-tight">
                {stats.totalThreats}
              </div>
              <div className="text-[10px] font-mono text-cyan-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" /> {stats.activeThreats || stats.totalThreats} Active
              </div>
            </div>

            {/* 2. Critical */}
            <div className="p-4 sm:p-6 text-center sm:text-left flex flex-col justify-between space-y-2">
              <div className="text-[11px] font-mono font-bold uppercase tracking-wider text-red-400">
                Critical
              </div>
              <div className="text-3xl sm:text-4xl font-extrabold text-red-400 font-mono tracking-tight">
                {stats.critical}
              </div>
              <div className="text-[10px] font-mono text-red-300/80">
                CVSS ≥ 9.0 (Immediate)
              </div>
            </div>

            {/* 3. High */}
            <div className="p-4 sm:p-6 text-center sm:text-left flex flex-col justify-between space-y-2">
              <div className="text-[11px] font-mono font-bold uppercase tracking-wider text-orange-400">
                High Risk
              </div>
              <div className="text-3xl sm:text-4xl font-extrabold text-orange-400 font-mono tracking-tight">
                {stats.high}
              </div>
              <div className="text-[10px] font-mono text-orange-300/80">
                Elevated Priority
              </div>
            </div>

            {/* 4. Emerging */}
            <div className="p-4 sm:p-6 text-center sm:text-left flex flex-col justify-between space-y-2">
              <div className="text-[11px] font-mono font-bold uppercase tracking-wider text-indigo-400">
                Emerging
              </div>
              <div className="text-3xl sm:text-4xl font-extrabold text-indigo-300 font-mono tracking-tight">
                {stats.emergingThreats || predictions.length || 3}
              </div>
              <div className="text-[10px] font-mono text-indigo-400">
                AI Trend Forecasts
              </div>
            </div>

            {/* 5. Reports */}
            <div className="p-4 sm:p-6 text-center sm:text-left flex flex-col justify-between space-y-2">
              <div className="text-[11px] font-mono font-bold uppercase tracking-wider text-slate-400">
                Reports
              </div>
              <div className="text-3xl sm:text-4xl font-extrabold text-slate-200 font-mono tracking-tight">
                {stats.totalReports}
              </div>
              <div className="text-[10px] font-mono text-emerald-400">
                100% Extracted
              </div>
            </div>

            {/* 6. IOCs */}
            <div className="p-4 sm:p-6 text-center sm:text-left flex flex-col justify-between space-y-2">
              <div className="text-[11px] font-mono font-bold uppercase tracking-wider text-emerald-400">
                IOCs
              </div>
              <div className="text-3xl sm:text-4xl font-extrabold text-emerald-400 font-mono tracking-tight">
                {stats.totalIocs}
              </div>
              <div className="text-[10px] font-mono text-slate-400">
                Hashes, IPs, Domains
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 3: THREAT ACTIVITY (LARGE FULL-WIDTH VISUAL SECTION)
          ========================================================================= */}
      <section id="section-threat-activity" className="w-full border-b border-slate-800/80 py-16 sm:py-24 bg-[#070B14]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
            <div className="space-y-1">
              <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-2.5">
                <Activity className="w-6 h-6 text-cyan-400" /> Threat Activity
              </h2>
              <p className="text-xs sm:text-sm text-slate-400 max-w-xl">
                Understand how cybersecurity risk is changing across the available intelligence dataset.
              </p>
            </div>

            {/* Interactive Filters: Timeframe & Sources */}
            <div className="flex items-center gap-2.5 flex-wrap">
              {/* Source filter */}
              <div className="flex items-center gap-1 bg-[#090F1C] p-1 rounded-xl border border-slate-800 text-xs font-mono font-bold">
                {[
                  { id: "ALL", label: "All Feeds" },
                  { id: "NVD", label: "NVD" },
                  { id: "CISA_KEV", label: "CISA KEV" },
                  { id: "REPORTS", label: "Reports" }
                ].map((src) => (
                  <button
                    key={src.id}
                    onClick={() => setActivitySource(src.id as any)}
                    className={cn(
                      "px-2.5 py-1 rounded-lg transition-colors cursor-pointer",
                      activitySource === src.id
                        ? "bg-cyan-950 text-cyan-300 border border-cyan-500/40"
                        : "text-slate-400 hover:text-slate-200"
                    )}
                  >
                    {src.label}
                  </button>
                ))}
              </div>

              {/* Timeframe filter */}
              <div className="flex items-center gap-1 bg-[#090F1C] p-1 rounded-xl border border-slate-800 text-xs font-mono font-bold">
                {(["7D", "30D", "90D"] as const).map((tf) => (
                  <button
                    key={tf}
                    onClick={() => setActivityTimeframe(tf)}
                    className={cn(
                      "px-3 py-1 rounded-lg transition-colors cursor-pointer",
                      activityTimeframe === tf
                        ? "bg-cyan-950 text-cyan-300 border border-cyan-500/40"
                        : "text-slate-400 hover:text-slate-200"
                    )}
                  >
                    {tf}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Large High-Contrast Chart Container with significant vertical space */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
            <div className="lg:col-span-8 bg-[#090F1C] border border-slate-800/90 rounded-2xl p-6 shadow-2xl space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <span className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-cyan-400" />
                  Telemetry Volumetrics • {activityTimeframe} Window
                </span>
                <span className="text-[11px] font-mono text-slate-500">
                  Last updated: {lastUpdated}
                </span>
              </div>

              <div className="h-80 sm:h-96 w-full pt-2">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={displayTrend} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="colorCrit" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                      </linearGradient>
                      <linearGradient id="colorHighRisk" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#f97316" stopOpacity={0.35} />
                        <stop offset="95%" stopColor="#f97316" stopOpacity={0.0} />
                      </linearGradient>
                      <linearGradient id="colorMedLow" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="month" stroke="#475569" fontSize={11} tickLine={false} />
                    <YAxis stroke="#475569" fontSize={11} tickLine={false} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#090F1C",
                        borderColor: "#334155",
                        borderRadius: "12px",
                        fontSize: "12px",
                        boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.6)"
                      }}
                      itemStyle={{ color: "#E2E8F0" }}
                    />
                    <Area
                      type="monotone"
                      dataKey="critical"
                      name="Critical Risk"
                      stroke="#ef4444"
                      fillOpacity={1}
                      fill="url(#colorCrit)"
                      strokeWidth={2}
                    />
                    <Area
                      type="monotone"
                      dataKey="high"
                      name="High Risk"
                      stroke="#f97316"
                      fillOpacity={1}
                      fill="url(#colorHighRisk)"
                      strokeWidth={2}
                    />
                    <Area
                      type="monotone"
                      dataKey="medium"
                      name="Medium / Low"
                      stroke="#06b6d4"
                      fillOpacity={1}
                      fill="url(#colorMedLow)"
                      strokeWidth={2}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Side Ingestion & Telemetry Panel */}
            <div className="lg:col-span-4 bg-[#090F1C] border border-slate-800/90 rounded-2xl p-6 shadow-2xl flex flex-col justify-between space-y-4">
              <div className="border-b border-slate-800/80 pb-3">
                <h3 className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider flex items-center gap-2">
                  <Zap className="w-4 h-4 text-cyan-400" />
                  Key Activity Telemetry
                </h3>
              </div>

              <div className="space-y-3 flex-1 flex flex-col justify-center">
                <div className="p-3.5 rounded-xl bg-[#0B1222] border border-slate-800/80 space-y-1">
                  <div className="text-[10px] uppercase font-mono font-bold text-slate-400">Threat Velocity Surge</div>
                  <div className="text-base font-bold text-white flex items-center justify-between">
                    <span>+18.4% vs Baseline</span>
                    <span className="text-xs font-mono text-emerald-400">↑ Accelerating</span>
                  </div>
                  <div className="text-[10px] text-slate-400">Perimeter firewall & edge appliance exploitation</div>
                </div>

                <div className="p-3.5 rounded-xl bg-[#0B1222] border border-slate-800/80 space-y-1">
                  <div className="text-[10px] uppercase font-mono font-bold text-slate-400">Dominant Attack Vector</div>
                  <div className="text-sm font-bold text-red-400 flex items-center justify-between">
                    <span>Remote Code Execution (RCE)</span>
                    <span className="text-[10px] font-mono text-red-300 bg-red-950 px-1.5 py-0.5 rounded border border-red-500/30">CVSS 9.8</span>
                  </div>
                  <div className="text-[10px] text-slate-400">Actively tracked in CISA KEV catalog</div>
                </div>

                <div className="p-3.5 rounded-xl bg-[#0B1222] border border-slate-800/80 space-y-1">
                  <div className="text-[10px] uppercase font-mono font-bold text-slate-400">Multi-Source Accuracy</div>
                  <div className="text-sm font-bold text-cyan-400 flex items-center justify-between">
                    <span>99.2% Cross-Matched</span>
                    <span className="text-xs font-mono text-cyan-300">NVD + KEV</span>
                  </div>
                  <div className="text-[10px] text-slate-400">Autonomous CVE-to-technique correlation</div>
                </div>
              </div>

              <Link
                to="/analytics"
                className="w-full py-2.5 bg-[#0B1222] hover:bg-slate-800 text-cyan-400 hover:text-cyan-300 text-xs font-bold rounded-xl border border-slate-800 flex items-center justify-center gap-1.5 transition-colors"
              >
                <span>View Full Analytics Dashboard</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 4: PRIORITY THREATS ("WHAT NEEDS ATTENTION")
          ========================================================================= */}
      <section id="section-priority-threats" className="w-full border-b border-slate-800/80 py-16 sm:py-24 bg-[#080D1A]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
            <div className="space-y-1">
              <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-2.5">
                <ShieldAlert className="w-6 h-6 text-red-400" /> What Needs Attention
              </h2>
              <p className="text-xs sm:text-sm text-slate-400">
                AI-assisted prioritization of the most significant findings across all intelligence feeds.
              </p>
            </div>

            <Link
              to="/threat-intelligence"
              id="link-view-all-intelligence"
              className="text-xs sm:text-sm font-bold text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 transition-colors self-start sm:self-auto"
            >
              <span>View all intelligence</span>
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>

          {/* Source Filter Pills */}
          <SourceFilterBar
            activeFilter={prioritySourceFilter}
            onFilterChange={setPrioritySourceFilter}
            counts={{
              ALL: threats.length,
              NVD: threats.filter((t) => (t.title + t.description).includes("CVE")).length,
              CISA_KEV: threats.filter((t) => t.severity === "CRITICAL").length,
              MITRE: threats.filter((t) => Boolean(t.mitreTechniques)).length,
              REPORTS: threats.filter((t) => (t.source || "").includes("Report")).length,
              AI: threats.filter((t) => (t.source || "").includes("AI")).length
            }}
          />

          {/* Elegant Horizontal Threat Cards */}
          <div className="space-y-4">
            {filteredPriorityThreats.slice(0, 4).map((threat) => {
              const hasCve = (threat.title + threat.description).includes("CVE");
              const isReviewed = threat.status === "reviewed";

              return (
                <div
                  key={threat.id}
                  id={`priority-threat-${threat.id}`}
                  onClick={() => navigate(`/threat-intelligence?id=${threat.id}`)}
                  className="bg-[#090F1C] border border-slate-800/90 hover:border-cyan-500/50 rounded-2xl p-5 sm:p-6 transition-all duration-200 cursor-pointer shadow-xl hover:shadow-cyan-950/20 group flex flex-col md:flex-row md:items-center justify-between gap-6"
                >
                  {/* Left Column: Severity, Category, Title, Explanation */}
                  <div className="space-y-2.5 flex-1">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <SeverityBadge severity={threat.severity} />
                      <span className="text-[10px] font-mono text-cyan-400 font-bold bg-cyan-950/80 border border-cyan-500/30 px-2.5 py-0.5 rounded">
                        {threat.category}
                      </span>
                      {hasCve && (
                        <span className="text-[10px] font-mono font-bold bg-red-950 text-red-300 border border-red-500/40 px-2 py-0.5 rounded">
                          CVE IDENTIFIED
                        </span>
                      )}
                      <SourceBadge source={threat.source || "ShieldZen AI"} />
                    </div>

                    <h3 className="text-sm sm:text-base font-bold text-white group-hover:text-cyan-300 transition-colors leading-snug">
                      {threat.title}
                    </h3>

                    <p className="text-xs text-slate-400 leading-relaxed line-clamp-2 max-w-3xl">
                      {threat.description || threat.reasoning}
                    </p>

                    {/* Recommended Action Pill */}
                    <div className="flex items-center gap-2 pt-1">
                      <span className="text-[10px] font-mono uppercase text-slate-500 font-bold">Action:</span>
                      <span className="text-[11px] text-slate-300 bg-[#0B1222] border border-slate-800 px-2.5 py-1 rounded-lg font-mono">
                        {threat.recommendedAction || "Apply vendor patch & isolate edge telemetry"}
                      </span>
                    </div>
                  </div>

                  {/* Right Column: Confidence, Review Button, Investigate Trigger */}
                  <div className="flex md:flex-col items-center md:items-end justify-between md:justify-center gap-4 shrink-0 border-t md:border-t-0 border-slate-800/80 pt-3 md:pt-0">
                    <div className="text-left md:text-right">
                      <div className="text-[10px] font-mono text-slate-500 uppercase">AI Confidence</div>
                      <div className="text-base font-bold text-white font-mono flex items-center md:justify-end gap-1.5">
                        <span className="text-cyan-400">{threat.confidence || 92}%</span>
                        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden hidden sm:inline-block">
                          <div className="h-full bg-cyan-400 rounded-full" style={{ width: `${threat.confidence || 92}%` }} />
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2.5">
                      <button
                        onClick={(e) => handleMarkReviewed(threat.id, e)}
                        className={cn(
                          "text-[11px] font-mono font-bold px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer",
                          isReviewed
                            ? "text-emerald-400 bg-emerald-950/50 border border-emerald-500/30"
                            : "text-slate-400 hover:text-slate-200 bg-[#0B1222] border border-slate-800"
                        )}
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>{isReviewed ? "Reviewed" : "Mark Review"}</span>
                      </button>

                      <span className="text-xs font-bold text-cyan-400 group-hover:text-cyan-300 flex items-center gap-1">
                        Investigate <ChevronRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 5: SOURCE CORRELATION ("ONE INTELLIGENCE LAYER")
          ========================================================================= */}
      <section id="section-source-correlation" className="w-full border-b border-slate-800/80 py-16 sm:py-24 bg-[#070B14] relative overflow-hidden">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-12 relative z-10">
          <div className="text-center max-w-3xl mx-auto space-y-2">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-950/70 border border-indigo-500/30 text-[10px] font-mono font-bold text-indigo-300 tracking-wider uppercase">
              <Network className="w-3 h-3 text-indigo-400" /> MULTI-SOURCE CORRELATION
            </div>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
              One Intelligence Layer
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              Disparate vulnerability registries, active zero-day feeds, and raw unstructured threat advisories are normalized into an interconnected defense fabric.
            </p>
          </div>

          {/* Interactive Visual Correlation Diagram */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
            {/* Left Column: 4 Ingested Feed Nodes */}
            <div className="lg:col-span-4 space-y-3">
              {[
                { title: "Uploaded Threat Reports", desc: "PDF & Text advisories", icon: UploadCloud, color: "text-blue-400", border: "hover:border-blue-500/40" },
                { title: "NIST NVD Registry", desc: "Vulnerability scoring (CVSS)", icon: Database, color: "text-cyan-400", border: "hover:border-cyan-500/40" },
                { title: "CISA KEV Catalog", desc: "Actively exploited zero-days", icon: Radio, color: "text-red-400", border: "hover:border-red-500/40" },
                { title: "MITRE ATT&CK Matrix", desc: "Tactics, techniques & procedures", icon: Shield, color: "text-indigo-400", border: "hover:border-indigo-500/40" }
              ].map((feed, idx) => (
                <div
                  key={idx}
                  className={cn(
                    "p-4 rounded-xl bg-[#090F1C] border border-slate-800/90 flex items-center justify-between transition-all group",
                    feed.border
                  )}
                >
                  <div className="flex items-center gap-3">
                    <feed.icon className={cn("w-5 h-5", feed.color)} />
                    <div>
                      <div className="text-xs font-bold text-white group-hover:text-cyan-300 transition-colors">{feed.title}</div>
                      <div className="text-[10px] text-slate-400 font-mono">{feed.desc}</div>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-500/30">
                    Live
                  </span>
                </div>
              ))}
            </div>

            {/* Center Hub: ShieldZen Correlation Core */}
            <div className="lg:col-span-4 p-8 rounded-2xl bg-gradient-to-br from-[#0B1222] via-[#090F1C] to-[#0D152A] border border-cyan-500/40 shadow-2xl text-center space-y-4 relative">
              <div className="w-12 h-12 mx-auto rounded-2xl bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center shadow-lg shadow-cyan-950">
                <Cpu className="w-6 h-6 text-cyan-400 animate-pulse" />
              </div>

              <div>
                <h3 className="text-base font-extrabold text-white tracking-tight">
                  SHIELDZEN CORRELATION ENGINE
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Gemini-Powered Multi-Entity Disambiguation & Exploit Risk Prioritization
                </p>
              </div>

              <div className="pt-2 border-t border-slate-800/80 grid grid-cols-2 gap-2 text-[10px] font-mono text-slate-300">
                <div className="bg-[#070B14] p-2 rounded-lg border border-slate-800">
                  <span>IOC Extraction</span>
                </div>
                <div className="bg-[#070B14] p-2 rounded-lg border border-slate-800">
                  <span>CVE Mapping</span>
                </div>
                <div className="bg-[#070B14] p-2 rounded-lg border border-slate-800">
                  <span>MITRE TTP Tagging</span>
                </div>
                <div className="bg-[#070B14] p-2 rounded-lg border border-slate-800">
                  <span>Confidence Scoring</span>
                </div>
              </div>
            </div>

            {/* Right Column: 3 Output Streams */}
            <div className="lg:col-span-4 space-y-3">
              {[
                { title: "Threat Detection", desc: "Prioritized threat entities & IOC vault", icon: ShieldAlert, color: "text-red-400", link: "/threats" },
                { title: "Risk Prioritization", desc: "Explainable severity & target weighting", icon: Activity, color: "text-orange-400", link: "/threat-intelligence" },
                { title: "Analyst Insights", desc: "Executive briefings & actionable playbook", icon: Bot, color: "text-indigo-400", link: "/analytics" }
              ].map((out, idx) => (
                <Link
                  key={idx}
                  to={out.link}
                  className="p-4 rounded-xl bg-[#090F1C] border border-slate-800/90 hover:border-cyan-500/40 flex items-center justify-between transition-all group block"
                >
                  <div className="flex items-center gap-3">
                    <out.icon className={cn("w-5 h-5", out.color)} />
                    <div>
                      <div className="text-xs font-bold text-white group-hover:text-cyan-300 transition-colors">{out.title}</div>
                      <div className="text-[10px] text-slate-400 font-mono">{out.desc}</div>
                    </div>
                  </div>
                  <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 group-hover:translate-x-1 transition-all" />
                </Link>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 6: THREAT LANDSCAPE ("SEE THE THREAT LANDSCAPE")
          ========================================================================= */}
      <section id="section-threat-landscape" className="w-full border-b border-slate-800/80 py-16 sm:py-24 bg-[#080D1A]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
            <div className="space-y-1">
              <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-2.5">
                <Globe className="w-6 h-6 text-cyan-400" /> See the Threat Landscape
              </h2>
              <p className="text-xs sm:text-sm text-slate-400">
                Geographical telemetry and severity distribution across detected threat vectors.
              </p>
            </div>

            <Link
              to="/map"
              id="link-explore-full-map"
              className="text-xs sm:text-sm font-bold text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 transition-colors self-start sm:self-auto"
            >
              <span>Explore full geographic heatmap</span>
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
            {/* Left Column: Interactive Map (~60% = 7 cols) */}
            <div className="lg:col-span-7 bg-[#090F1C] border border-slate-800/90 rounded-2xl overflow-hidden shadow-2xl flex flex-col">
              <div className="p-4 border-b border-slate-800/80 flex items-center justify-between bg-[#0B1222]">
                <span className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider flex items-center gap-2">
                  <MapPin className="w-4 h-4 text-cyan-400" /> Global Threat Density Heatmap
                </span>
                <div className="flex items-center gap-1 text-[10px] font-mono">
                  {(["ALL", "CRITICAL", "HIGH", "MEDIUM"] as const).map((lvl) => (
                    <button
                      key={lvl}
                      onClick={() => setMapRiskFilter(lvl)}
                      className={cn(
                        "px-2 py-0.5 rounded transition-colors cursor-pointer",
                        mapRiskFilter === lvl
                          ? "bg-cyan-950 text-cyan-300 border border-cyan-500/40 font-bold"
                          : "text-slate-400 hover:text-slate-200"
                      )}
                    >
                      {lvl}
                    </button>
                  ))}
                </div>
              </div>

              <div className="h-80 sm:h-96 w-full relative">
                <MapContainer
                  center={[20, 0]}
                  zoom={1.5}
                  minZoom={1.5}
                  maxZoom={6}
                  scrollWheelZoom={false}
                  style={{ height: "100%", width: "100%", backgroundColor: "#070B14" }}
                >
                  <TileLayer
                    url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                    attribution='&copy; <a href="https://carto.com/">CARTO</a>'
                  />
                  {filteredMapPoints.map((p, idx) => {
                    const w = p.weight ?? (p.severity === "CRITICAL" ? 9 : p.severity === "HIGH" ? 7 : p.severity === "MEDIUM" ? 5 : 3);
                    const isCrit = w >= 8;
                    const isHigh = w >= 6 && w < 8;
                    const isMed = w >= 4 && w < 6;
                    const color = isCrit ? "#ef4444" : isHigh ? "#f97316" : isMed ? "#eab308" : "#10b981";

                    return (
                      <CircleMarker
                        key={idx}
                        center={[p.lat, p.lng]}
                        radius={Math.max(5, w * 2)}
                        fillColor={color}
                        fillOpacity={0.7}
                        color={color}
                        weight={1.5}
                      >
                        <Popup className="custom-popup">
                          <div className="text-xs p-1 space-y-1">
                            <strong className="text-slate-900 block font-bold">{p.location || "Target Region"}</strong>
                            <div className="text-[10px] text-slate-700">
                              Risk Weight: <strong>{w}/10</strong>
                            </div>
                            <div className="text-[10px] text-slate-600">
                              Incidents: {p.incidentCount || 1} • {p.primaryVector || "Edge Infiltration"}
                            </div>
                          </div>
                        </Popup>
                      </CircleMarker>
                    );
                  })}
                </MapContainer>
              </div>
            </div>

            {/* Right Column: Severity Donut & Sector Impact (~40% = 5 cols) */}
            <div className="lg:col-span-5 bg-[#090F1C] border border-slate-800/90 rounded-2xl p-6 shadow-2xl flex flex-col justify-between space-y-6">
              <div className="border-b border-slate-800/80 pb-3">
                <h3 className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-orange-400" /> Severity & Target Sectors
                </h3>
              </div>

              {/* Donut Chart */}
              <div className="flex items-center justify-center">
                <ResponsiveContainer width="100%" height={160}>
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={45}
                      outerRadius={68}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#090F1C",
                        borderColor: "#334155",
                        borderRadius: "8px",
                        fontSize: "12px"
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              {/* Severity Pills Grid */}
              <div className="grid grid-cols-4 gap-2 text-[11px] font-mono text-center">
                <div className="p-2 rounded-xl bg-red-950/40 border border-red-500/30">
                  <div className="text-red-400 text-[10px]">Critical</div>
                  <div className="font-bold text-white text-base">{stats.critical}</div>
                </div>
                <div className="p-2 rounded-xl bg-orange-950/40 border border-orange-500/30">
                  <div className="text-orange-400 text-[10px]">High</div>
                  <div className="font-bold text-white text-base">{stats.high}</div>
                </div>
                <div className="p-2 rounded-xl bg-amber-950/40 border border-amber-500/30">
                  <div className="text-amber-300 text-[10px]">Medium</div>
                  <div className="font-bold text-white text-base">{stats.medium}</div>
                </div>
                <div className="p-2 rounded-xl bg-emerald-950/40 border border-emerald-500/30">
                  <div className="text-emerald-400 text-[10px]">Low</div>
                  <div className="font-bold text-white text-base">{stats.low}</div>
                </div>
              </div>

              {/* Top Targeted Sectors Progress */}
              <div className="space-y-2.5 pt-2 border-t border-slate-800/80">
                <div className="text-[10px] font-mono uppercase font-bold text-slate-400">
                  Top Targeted Industry Sectors
                </div>
                <div className="space-y-2 text-xs">
                  <div className="flex items-center justify-between text-slate-300">
                    <span>Financial & Banking</span>
                    <span className="font-mono text-cyan-400 font-bold">34%</span>
                  </div>
                  <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div className="w-[34%] h-full bg-cyan-500 rounded-full" />
                  </div>

                  <div className="flex items-center justify-between text-slate-300">
                    <span>Government & Critical Infrastructure</span>
                    <span className="font-mono text-red-400 font-bold">28%</span>
                  </div>
                  <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div className="w-[28%] h-full bg-red-500 rounded-full" />
                  </div>

                  <div className="flex items-center justify-between text-slate-300">
                    <span>Healthcare & Life Sciences</span>
                    <span className="font-mono text-orange-400 font-bold">21%</span>
                  </div>
                  <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div className="w-[21%] h-full bg-orange-500 rounded-full" />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 7: INCIDENT TIMELINE ("FOLLOW THE SIGNAL")
          ========================================================================= */}
      <section id="section-incident-timeline" className="w-full border-b border-slate-800/80 py-16 sm:py-24 bg-[#070B14]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
            <div className="space-y-1">
              <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-2.5">
                <Activity className="w-6 h-6 text-cyan-400" /> Follow the Signal
              </h2>
              <p className="text-xs sm:text-sm text-slate-400">
                Chronological telemetry of recent security incidents and sensor triggers.
              </p>
            </div>

            <Link
              to="/incidents"
              id="link-explore-incident-timeline"
              className="text-xs sm:text-sm font-bold text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 transition-colors self-start sm:self-auto"
            >
              <span>Explore Incident Timeline</span>
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>

          {/* Clean Incident Timeline Stream Cards */}
          <div className="space-y-3">
            {incidents.slice(0, 5).map((inc, idx) => (
              <div
                key={inc.id || idx}
                onClick={() => navigate(`/incidents`)}
                className="p-4 sm:p-5 rounded-2xl bg-[#090F1C] border border-slate-800/90 hover:border-cyan-500/40 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-all cursor-pointer group shadow-lg"
              >
                <div className="flex items-start sm:items-center gap-4 flex-1">
                  {/* Date Badge */}
                  <div className="p-2.5 rounded-xl bg-[#0B1222] border border-slate-800 text-center shrink-0 font-mono">
                    <div className="text-[10px] text-slate-500 uppercase">
                      {new Date(inc.date || inc.detectedAt || Date.now()).toLocaleDateString("en-US", { month: "short" })}
                    </div>
                    <div className="text-sm font-bold text-white">
                      {new Date(inc.date || inc.detectedAt || Date.now()).getDate()}
                    </div>
                  </div>

                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <SeverityBadge severity={inc.severity} />
                      <span className="text-[10px] font-mono text-cyan-300 bg-cyan-950/60 border border-cyan-500/30 px-2 py-0.5 rounded">
                        {inc.category}
                      </span>
                      <span className="text-[10px] font-mono text-slate-500">
                        {inc.location || "Global Telemetry"}
                      </span>
                    </div>

                    <h4 className="text-xs sm:text-sm font-bold text-white group-hover:text-cyan-300 transition-colors truncate">
                      {inc.title}
                    </h4>
                  </div>
                </div>

                <div className="flex items-center justify-between sm:justify-end gap-4 shrink-0 text-xs">
                  <span className="text-[10px] font-mono text-slate-400">
                    Source: {inc.source || "CERT Alert"}
                  </span>
                  <span className="text-cyan-400 group-hover:text-cyan-300 font-bold flex items-center gap-1">
                    Inspect <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 8: EMERGING THREATS ("WHAT'S EMERGING")
          ========================================================================= */}
      <section id="section-emerging-threats" className="w-full border-b border-slate-800/80 py-16 sm:py-24 bg-[#080D1A]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
            <div className="space-y-1">
              <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-2.5">
                <TrendingUp className="w-6 h-6 text-indigo-400" /> What's Emerging
              </h2>
              <p className="text-xs sm:text-sm text-slate-400">
                AI-assisted threat trend forecasting based on multi-source activity patterns.
              </p>
            </div>

            <Link
              to="/emerging"
              id="link-explore-emerging-forecast"
              className="text-xs sm:text-sm font-bold text-indigo-300 hover:text-indigo-200 flex items-center gap-1.5 transition-colors self-start sm:self-auto"
            >
              <span>Explore Emerging Forecast</span>
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>

          {/* AI Disclaimer Banner */}
          <div className="p-3.5 rounded-xl bg-indigo-950/40 border border-indigo-500/30 text-xs text-indigo-200 flex items-center gap-2.5">
            <Sparkles className="w-4 h-4 text-indigo-400 shrink-0" />
            <span>
              <strong>AI-Generated Trend Forecast:</strong> Predictions are generated via heuristic correlation across NVD CVE publications, CISA KEV additions, and report indicators.
            </span>
          </div>

          {/* Forecast Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {displayPredictions.map((pred) => (
              <div
                key={pred.id}
                className="bg-[#090F1C] border border-slate-800/90 hover:border-indigo-500/40 rounded-2xl p-6 flex flex-col justify-between transition-all space-y-5 shadow-xl"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono uppercase font-bold text-indigo-300 bg-indigo-950/80 border border-indigo-500/40 px-2.5 py-0.5 rounded">
                      {pred.trendDirection || "Increasing"}
                    </span>
                    <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1">
                      ↑ {pred.growthRate || "+32%"}
                    </span>
                  </div>

                  <h3 className="text-sm sm:text-base font-bold text-white leading-snug">
                    {pred.threatType}
                  </h3>

                  <p className="text-xs text-slate-400 leading-relaxed">
                    {pred.reasoning}
                  </p>
                </div>

                <div className="pt-4 border-t border-slate-800/80 space-y-2.5">
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span>Confidence:</span>
                    <span className="text-white font-bold">{pred.confidence}%</span>
                  </div>
                  <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-indigo-500 to-cyan-400 rounded-full"
                      style={{ width: `${pred.confidence}%` }}
                    />
                  </div>
                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 pt-1">
                    <span>Window: {pred.predictedDate}</span>
                    <span>{pred.supportingIncidentsCount || 8} Telemetry Signals</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 9: AI INSIGHTS ("LET SHIELDZEN CONNECT THE DOTS")
          ========================================================================= */}
      <section id="section-ai-insights" className="w-full border-b border-slate-800/80 py-16 sm:py-24 bg-[#070B14]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
          <div className="bg-gradient-to-br from-[#0B1222] via-[#090F1C] to-[#0D152A] border border-indigo-500/30 rounded-3xl p-6 sm:p-10 shadow-2xl space-y-8">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-2xl bg-indigo-950 border border-indigo-500/40 text-indigo-400">
                  <Bot className="w-6 h-6" />
                </div>
                <div>
                  <h2 className="text-xl sm:text-2xl font-extrabold text-white tracking-tight">
                    Let ShieldZen Connect the Dots
                  </h2>
                  <p className="text-xs text-slate-400">
                    Executive synthesis and automated attack chain correlation powered by Google Gemini.
                  </p>
                </div>
              </div>

              <button
                id="btn-ask-shieldzen-ai"
                onClick={() => {
                  setAiDrawerPrompt("Summarize all active cyber threat vectors and provide strategic mitigation steps.");
                  setAiDrawerOpen(true);
                }}
                className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-bold flex items-center justify-center gap-2 shadow-lg shadow-indigo-950/60 transition-all border border-indigo-400/30 cursor-pointer self-start sm:self-auto"
              >
                <span>Ask ShieldZen AI</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>

            {/* Executive Synthesis Content Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
              {/* Left 7 cols: Executive Summary & Top Concern */}
              <div className="lg:col-span-7 space-y-6">
                <div className="space-y-2">
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-cyan-400">
                    EXECUTIVE SUMMARY
                  </span>
                  <p className="text-xs sm:text-sm text-slate-200 leading-relaxed">
                    Over the past 30-day monitoring window, our correlation engine identified a significant convergence
                    between unpatched perimeter appliance vulnerabilities (<span className="text-red-400 font-mono">CVE-2024-3400</span>)
                    and targeted ransomware staging by synthetic threat group STG-29 ('Cobalt Nexus').
                  </p>
                </div>

                <div className="p-4 rounded-2xl bg-[#070B14] border border-red-900/40 space-y-2">
                  <div className="flex items-center justify-between text-xs font-bold text-red-400">
                    <span className="flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4 text-red-400" /> Top Priority Concern
                    </span>
                    <span className="text-[10px] font-mono bg-red-950 px-2 py-0.5 rounded border border-red-500/30 text-red-300">
                      RCE Infiltration
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Active weaponization of GlobalProtect edge appliances. Adversaries execute arbitrary commands with root privileges prior to establishing encrypted C2 proxies.
                  </p>
                </div>

                {/* MITRE & CVE Badges */}
                <div className="space-y-2">
                  <div className="text-[10px] font-mono uppercase text-slate-400 font-bold">
                    Correlated MITRE ATT&CK & CVE Entities
                  </div>
                  <div className="flex items-center gap-2 flex-wrap text-[11px] font-mono">
                    <span className="bg-[#070B14] text-cyan-300 border border-slate-700 px-2.5 py-1 rounded-lg">
                      T1190: Exploit Public-Facing App
                    </span>
                    <span className="bg-[#070B14] text-cyan-300 border border-slate-700 px-2.5 py-1 rounded-lg">
                      T1059: Command & Scripting Interpreter
                    </span>
                    <span className="bg-[#070B14] text-red-300 border border-red-900/50 px-2.5 py-1 rounded-lg">
                      CVE-2024-3400 (CVSS 10.0)
                    </span>
                  </div>
                </div>
              </div>

              {/* Right 5 cols: Recommended Defensive Actions */}
              <div className="lg:col-span-5 bg-[#070B14] border border-slate-800/80 rounded-2xl p-5 space-y-4">
                <div className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" /> Recommended Defensive Actions
                  </span>
                  <span className="text-[10px] text-slate-500">Playbook</span>
                </div>

                <div className="space-y-2 text-xs">
                  {[
                    { id: "action_1", text: "Isolate and patch PAN-OS edge gateway firmware immediately." },
                    { id: "action_2", text: "Block inbound and outbound traffic to listed proxy C2 IP addresses." },
                    { id: "action_3", text: "Enforce multi-factor authentication (MFA) on all VPN concentrators." },
                    { id: "action_4", text: "Audit service account tokens for irregular OAuth permission grants." }
                  ].map((act) => (
                    <div
                      key={act.id}
                      onClick={() => toggleAction(act.id)}
                      className={cn(
                        "p-3 rounded-xl border flex items-start gap-3 transition-colors cursor-pointer",
                        completedActions[act.id]
                          ? "bg-emerald-950/20 border-emerald-500/30 text-slate-300"
                          : "bg-[#090F1C] border-slate-800 text-slate-400 hover:text-slate-200"
                      )}
                    >
                      <div className={cn(
                        "w-4 h-4 rounded mt-0.5 flex items-center justify-center shrink-0 border",
                        completedActions[act.id]
                          ? "bg-emerald-600 border-emerald-500 text-white"
                          : "border-slate-600"
                      )}>
                        {completedActions[act.id] && <Check className="w-3 h-3" />}
                      </div>
                      <span className={cn("text-xs leading-relaxed", completedActions[act.id] && "line-through text-slate-500")}>
                        {act.text}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 10: DATA SOURCES ("INTELLIGENCE SOURCES")
          ========================================================================= */}
      <section id="section-data-sources" className="w-full border-b border-slate-800/80 py-16 sm:py-20 bg-[#080D1A]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
          <div className="text-center sm:text-left space-y-1">
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-2.5">
              <Database className="w-6 h-6 text-cyan-400" /> Intelligence Sources
            </h2>
            <p className="text-xs sm:text-sm text-slate-400">
              Operational status and telemetry integrity across connected knowledge bases.
            </p>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
            {[
              { name: "NIST NVD", desc: "Vulnerability Database", status: "Connected", latency: "38ms", badge: "text-emerald-400 bg-emerald-950 border-emerald-500/30" },
              { name: "CISA KEV", desc: "Known Exploited Vulns", status: "Connected", latency: "44ms", badge: "text-emerald-400 bg-emerald-950 border-emerald-500/30" },
              { name: "MITRE ATT&CK", desc: "Enterprise Matrix v15", status: "Connected", latency: "Cached", badge: "text-cyan-400 bg-cyan-950 border-cyan-500/30" },
              { name: "Uploaded Reports", desc: "User & CERT Ingests", status: "Operational", latency: "100%", badge: "text-blue-400 bg-blue-950 border-blue-500/30" },
              { name: "Gemini AI Core", desc: "Gemini 2.5 Flash", status: "Connected", latency: "Active", badge: "text-purple-400 bg-purple-950 border-purple-500/30" }
            ].map((src, idx) => (
              <div
                key={idx}
                className="p-4 rounded-2xl bg-[#090F1C] border border-slate-800/90 space-y-2 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">{src.name}</span>
                    <span className={cn("text-[9px] font-mono font-bold px-1.5 py-0.2 rounded border", src.badge)}>
                      {src.status}
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5">{src.desc}</div>
                </div>

                <div className="text-[10px] font-mono text-slate-500 flex items-center justify-between pt-2 border-t border-slate-800/80">
                  <span>Status</span>
                  <span className="text-slate-300 font-bold">{src.latency}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 11: ENTERPRISE FOOTER
          ========================================================================= */}
      <footer className="w-full bg-[#060911] border-t border-slate-800/80 py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-6 text-center md:text-left">
          <div className="space-y-1">
            <div className="flex items-center justify-center md:justify-start gap-2.5">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
              <span className="text-sm font-extrabold text-white">
                Shield<span className="text-cyan-400">Zen</span>
              </span>
              <span className="text-[10px] font-mono text-slate-500 border-l border-slate-800 pl-2">
                AI-Powered Cyber Threat Intelligence
              </span>
            </div>
            <p className="text-xs text-slate-400">
              "Turning Cyber Threats into Actionable Intelligence"
            </p>
          </div>

          <div className="flex items-center gap-6 text-xs text-slate-400 font-mono">
            <Link to="/threat-intelligence" className="hover:text-cyan-300 transition-colors">Intelligence</Link>
            <Link to="/reports" className="hover:text-cyan-300 transition-colors">Reports</Link>
            <Link to="/threats" className="hover:text-cyan-300 transition-colors">Threats</Link>
            <Link to="/incidents" className="hover:text-cyan-300 transition-colors">Incidents</Link>
            <Link to="/settings" className="hover:text-cyan-300 transition-colors">Settings</Link>
          </div>

          <div className="text-[10px] font-mono text-slate-500 text-center md:text-right">
            <div>Academic Research Prototype</div>
            <div>Synthetic / demonstration telemetry included.</div>
          </div>
        </div>
      </footer>

      {/* Global AI Analyst Drawer */}
      <AIAnalystDrawer
        isOpen={aiDrawerOpen}
        onClose={() => {
          setAiDrawerOpen(false);
          setAiDrawerPrompt(undefined);
        }}
        initialPrompt={aiDrawerPrompt}
      />
    </div>
  );
}

import React, { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, Badge, SeverityBadge } from "../components/ui";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie,
  Legend,
  AreaChart,
  Area
} from "recharts";
import {
  BarChart3,
  Layers,
  Database,
  ShieldAlert,
  Download,
  RefreshCw,
  TrendingUp,
  Activity
} from "lucide-react";

export default function Analytics() {
  const [analytics, setAnalytics] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const fetchAnalytics = async () => {
    try {
      setLoading(true);
      const res = await fetch("/api/analytics");
      const data = await res.json();
      setAnalytics(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics();
  }, []);

  const CATEGORY_COLORS = ["#3b82f6", "#ef4444", "#f97316", "#10b981", "#8b5cf6", "#06b6d4", "#eab308"];
  const IOC_COLORS = ["#10b981", "#3b82f6", "#f59e0b", "#8b5cf6", "#ec4899", "#6366f1"];

  const exportData = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(analytics, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `shieldzen-cti-analytics-${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="bg-blue-600/20 text-blue-400 text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase border border-blue-500/30">
              Macro Intelligence
            </span>
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Intelligence & SOC Analytics</h1>
          <p className="text-slate-400 text-sm mt-1">
            Aggregated patterns, MITRE ATT&CK coverage, IOC distribution, and longitudinal threat telemetry.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={exportData}
            className="inline-flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider border border-slate-700 transition-colors"
          >
            <Download className="w-4 h-4 text-slate-400" /> Export JSON Metrics
          </button>
          <button
            onClick={fetchAnalytics}
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Top 2 Charts: Category & IOC Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Categories Pie */}
        <Card className="h-80">
          <CardHeader>
            <CardTitle>
              <ShieldAlert className="w-4 h-4 text-blue-400" /> Threat Classifications & Vectors
            </CardTitle>
          </CardHeader>
          <CardContent className="h-64 flex flex-col items-center justify-center pt-2">
            <ResponsiveContainer width="100%" height="80%">
              <PieChart>
                <Pie
                  data={analytics?.categoryDistribution || []}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="count"
                  nameKey="category"
                >
                  {(analytics?.categoryDistribution || []).map((entry: any, index: number) => (
                    <Cell key={`cat-cell-${entry.category || entry.name || index}`} fill={CATEGORY_COLORS[index % CATEGORY_COLORS.length]} />
                  ))}
                </Pie>
                <RechartsTooltip
                  contentStyle={{ backgroundColor: "#0B1120", borderColor: "#1E293B", borderRadius: "8px", fontSize: "12px" }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex flex-wrap gap-2 justify-center text-[10px]">
              {(analytics?.categoryDistribution || []).slice(0, 5).map((d: any, i: number) => {
                const label = d.category || d.name || `Category ${i + 1}`;
                const val = d.count ?? d.value ?? 0;
                return (
                  <span key={`cat-label-${label}-${i}`} className="flex items-center gap-1 text-slate-300">
                    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: CATEGORY_COLORS[i % CATEGORY_COLORS.length] }}></span>
                    {label}: {val}
                  </span>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {/* IOC Type Distribution Bar Chart */}
        <Card className="h-80">
          <CardHeader>
            <CardTitle>
              <Database className="w-4 h-4 text-emerald-400" /> Extracted Indicators of Compromise by Type
            </CardTitle>
          </CardHeader>
          <CardContent className="h-64 pt-2">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={analytics?.iocDistribution || []} margin={{ top: 20, right: 20, left: -20, bottom: 20 }}>
                <XAxis dataKey="type" stroke="#475569" fontSize={11} />
                <YAxis stroke="#475569" fontSize={11} />
                <RechartsTooltip
                  contentStyle={{ backgroundColor: "#0B1120", borderColor: "#1E293B", borderRadius: "8px", fontSize: "12px" }}
                />
                <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]}>
                  {(analytics?.iocDistribution || []).map((entry: any, index: number) => (
                    <Cell key={`ioc-cell-${entry.type || entry.name || index}`} fill={IOC_COLORS[index % IOC_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* MITRE ATT&CK Enterprise Matrix Bar Chart */}
      <Card>
        <CardHeader className="flex items-center justify-between">
          <CardTitle>
            <Layers className="w-4 h-4 text-cyan-400" /> MITRE ATT&CK Matrix Technique Distribution
          </CardTitle>
          <span className="text-[11px] font-mono text-slate-400">Enterprise Framework v14</span>
        </CardHeader>
        <CardContent className="h-72 pt-4">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              layout="vertical"
              data={analytics?.topMitreTechniques || []}
              margin={{ top: 10, right: 30, left: 140, bottom: 5 }}
            >
              <XAxis type="number" stroke="#475569" fontSize={11} />
              <YAxis dataKey="technique" type="category" stroke="#94a3b8" fontSize={11} width={130} />
              <RechartsTooltip
                contentStyle={{ backgroundColor: "#0B1120", borderColor: "#1E293B", borderRadius: "8px", fontSize: "12px" }}
              />
              <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  );
}

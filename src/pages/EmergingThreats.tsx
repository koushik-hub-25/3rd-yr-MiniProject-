import React, { useEffect, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent, Badge, ConfidenceMeter } from "../components/ui";
import {
  TrendingUp,
  Activity,
  ArrowUpRight,
  ShieldAlert,
  AlertTriangle,
  Zap,
  Layers,
  Sparkles,
  Calendar,
  RefreshCw,
  Clock
} from "lucide-react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine
} from "recharts";
import type { Prediction } from "../types";

export default function EmergingThreats() {
  const [predictions, setPredictions] = useState<Prediction[]>([]);
  const [loading, setLoading] = useState(true);
  const [timeframe, setTimeframe] = useState<"7d" | "30d" | "90d">("30d");

  const fetchPredictions = async () => {
    try {
      setLoading(true);
      const res = await fetch("/api/predictions");
      const data = await res.json();
      setPredictions(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error(e);
      setPredictions([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPredictions();
  }, []);

  const forecastChartData = [
    { month: "Nov", historical: 28, predicted: null },
    { month: "Dec", historical: 35, predicted: null },
    { month: "Jan", historical: 42, predicted: null },
    { month: "Feb", historical: 51, predicted: 51 },
    { month: "Mar (Pred)", historical: null, predicted: 68 },
    { month: "Apr (Pred)", historical: null, predicted: 84 },
    { month: "May (Pred)", historical: null, predicted: 102 }
  ];

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="bg-cyan-600/20 text-cyan-400 text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase border border-cyan-500/30">
              Predictive AI Forecasting
            </span>
            <span className="text-slate-400 text-xs font-mono">
              [TIME-SERIES VECTOR ANALYSIS]
            </span>
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Emerging Cyber Threat Vectors</h1>
          <p className="text-slate-400 text-sm mt-1">
            Early-warning forecasting of evolving adversary campaigns, zero-day exploit velocity, and critical infrastructure risk.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchPredictions}
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Forecast Trend Chart */}
      <Card>
        <CardHeader className="flex items-center justify-between">
          <div>
            <CardTitle>
              <TrendingUp className="w-4 h-4 text-cyan-400" /> Historical Incidents vs. Projected Threat Velocity
            </CardTitle>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Bayesian trend extrapolation correlated with active adversary reconnaissance telemetry
            </p>
          </div>
          <div className="flex items-center gap-4 text-xs font-mono">
            <span className="flex items-center gap-1.5 text-blue-400">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-500"></span> Confirmed Historical
            </span>
            <span className="flex items-center gap-1.5 text-cyan-400">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400"></span> AI Projected (+48% YoY)
            </span>
          </div>
        </CardHeader>
        <CardContent className="h-64 pt-4">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={forecastChartData} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
              <XAxis dataKey="month" stroke="#475569" fontSize={11} />
              <YAxis stroke="#475569" fontSize={11} />
              <Tooltip
                contentStyle={{ backgroundColor: "#0B1120", borderColor: "#1E293B", borderRadius: "8px", fontSize: "12px" }}
              />
              <ReferenceLine x="Feb" stroke="#64748b" strokeDasharray="3 3" label={{ value: 'Forecast Horizon', fill: '#94a3b8', fontSize: 10 }} />
              <Line type="monotone" dataKey="historical" stroke="#3b82f6" strokeWidth={2.5} dot={{ r: 4, fill: "#3b82f6" }} />
              <Line type="monotone" dataKey="predicted" stroke="#06b6d4" strokeWidth={2.5} strokeDasharray="4 4" dot={{ r: 4, fill: "#06b6d4" }} />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Emerging Threat Forecast Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {predictions.map((p) => {
          const isHighRisk = p.riskScore >= 85;

          return (
            <Card
              key={p.id}
              className="border-slate-800 hover:border-cyan-500/40 transition-all shadow-xl flex flex-col justify-between"
            >
              <div>
                <CardHeader className="bg-gradient-to-r from-slate-950 to-slate-900 border-b border-slate-800">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 text-[10px] font-mono px-2 py-0.5 rounded uppercase font-bold">
                        {p.category}
                      </span>
                      <span className="text-[11px] font-mono text-slate-400">
                        Target Sector: {p.location}
                      </span>
                    </div>
                    <h3 className="text-base font-bold text-white tracking-tight pt-1">
                      Projected Escalation: {p.category}
                    </h3>
                  </div>

                  <div className="flex flex-col items-end gap-1 shrink-0">
                    <span className="text-[10px] font-bold uppercase text-slate-400">Risk Score</span>
                    <span className={`text-base font-mono font-bold px-2 py-0.5 rounded border ${
                      isHighRisk
                        ? "bg-red-950 text-red-400 border-red-500/30"
                        : "bg-orange-950 text-orange-400 border-orange-500/30"
                    }`}>
                      {p.riskScore} / 100
                    </span>
                  </div>
                </CardHeader>

                <CardContent className="space-y-4 pt-4">
                  <div className="space-y-1.5">
                    <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                      Predictive Correlation Model
                    </div>
                    <p className="text-xs text-slate-200 leading-relaxed bg-slate-950 p-3.5 rounded-lg border border-slate-800">
                      {p.explanation}
                    </p>
                  </div>
                </CardContent>
              </div>

              <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400 text-[11px]">AI Confidence:</span>
                  <ConfidenceMeter confidence={p.confidence} />
                </div>

                <span className="text-[11px] font-mono text-cyan-400 flex items-center gap-1">
                  <Sparkles className="w-3 h-3" /> Predictive Forecast
                </span>
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

import React, { useEffect, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent, Badge, SeverityBadge, ConfidenceMeter } from "../components/ui";
import { Link } from "react-router-dom";
import {
  ShieldAlert,
  Search,
  Filter,
  ExternalLink,
  Layers,
  CheckCircle2,
  AlertTriangle,
  Server,
  ArrowRight,
  RefreshCw
} from "lucide-react";
import type { Threat } from "../types";

export default function Threats() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [categoryFilter, setCategoryFilter] = useState("ALL");
  const [loading, setLoading] = useState(true);

  const fetchThreats = async () => {
    try {
      setLoading(true);
      const res = await fetch("/api/threats");
      const data = await res.json();
      setThreats(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error(e);
      setThreats([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
  }, []);

  const categories = Array.from(new Set(threats.map(t => t.category))).filter(Boolean);

  const filtered = threats.filter(t => {
    const matchesSearch =
      t.title.toLowerCase().includes(search.toLowerCase()) ||
      t.description.toLowerCase().includes(search.toLowerCase()) ||
      t.category.toLowerCase().includes(search.toLowerCase()) ||
      (t.affectedSystems && t.affectedSystems.toLowerCase().includes(search.toLowerCase()));
    const matchesSev = severityFilter === "ALL" || t.severity === severityFilter;
    const matchesStatus = statusFilter === "ALL" || t.status === statusFilter;
    const matchesCat = categoryFilter === "ALL" || t.category === categoryFilter;
    return matchesSearch && matchesSev && matchesStatus && matchesCat;
  });

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="bg-red-600/20 text-red-400 text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase border border-red-500/30">
              Active Triage Queue
            </span>
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Threat Intelligence Feed</h1>
          <p className="text-slate-400 text-sm mt-1">
            Prioritized repository of AI-identified threats, MITRE ATT&CK techniques, and containment vectors.
          </p>
        </div>

        <button
          onClick={fetchThreats}
          className="inline-flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white px-4 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider border border-slate-700 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh Feed
        </button>
      </div>

      {/* Filter Bar */}
      <Card>
        <CardContent className="p-4 flex flex-col md:flex-row items-center gap-4">
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search threat indicators, systems, keywords..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:ring-1 focus:ring-blue-500 outline-none"
            />
          </div>

          <div className="flex items-center gap-3 flex-wrap w-full md:w-auto">
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:ring-1 focus:ring-blue-500 outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:ring-1 focus:ring-blue-500 outline-none"
            >
              <option value="ALL">All Statuses</option>
              <option value="active">Active Triage</option>
              <option value="reviewed">Reviewed</option>
              <option value="escalated">Escalated L3</option>
              <option value="confirmed_incident">Confirmed Incident</option>
            </select>

            <select
              value={categoryFilter}
              onChange={e => setCategoryFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:ring-1 focus:ring-blue-500 outline-none"
            >
              <option value="ALL">All Categories</option>
              {categories.map(c => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </div>
        </CardContent>
      </Card>

      {/* Threats Grid & Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filtered.map(t => {
          let mitreList: string[] = [];
          if (t.mitreTechniques) {
            try {
              mitreList = JSON.parse(t.mitreTechniques);
            } catch {
              mitreList = [t.mitreTechniques];
            }
          }

          return (
            <Card key={t.id} className="hover:border-slate-700 transition-all shadow-md group flex flex-col justify-between">
              <div>
                <CardHeader className="flex items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <SeverityBadge severity={t.severity} />
                      <span className="bg-slate-900 text-slate-300 px-2 py-0.5 rounded border border-slate-800 text-[10px] font-bold uppercase">
                        {t.category}
                      </span>
                      {t.analystSeverityOverride && (
                        <span className="bg-purple-950/60 text-purple-400 border border-purple-500/30 text-[9px] font-mono px-1.5 py-0.5 rounded uppercase">
                          Analyst Override
                        </span>
                      )}
                    </div>
                    <Link
                      to={`/threats/${t.id}`}
                      className="text-base font-bold text-white group-hover:text-blue-400 transition-colors block pt-1"
                    >
                      {t.title}
                    </Link>
                  </div>

                  <div className="shrink-0">
                    {t.status === "escalated" ? (
                      <Badge variant="critical">Escalated</Badge>
                    ) : t.status === "reviewed" ? (
                      <Badge variant="success">Reviewed</Badge>
                    ) : t.status === "confirmed_incident" ? (
                      <Badge variant="critical">Incident</Badge>
                    ) : (
                      <Badge variant="info">Active</Badge>
                    )}
                  </div>
                </CardHeader>

                <CardContent className="space-y-4 pt-4">
                  <p className="text-xs text-slate-300 line-clamp-2 leading-relaxed">
                    {t.description}
                  </p>

                  {/* AI Explainability Excerpt */}
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
                    <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                      Explainability Rationale
                    </div>
                    <p className="text-[11px] text-slate-400 italic line-clamp-2">
                      "{t.reasoning}"
                    </p>
                  </div>

                  {/* MITRE ATT&CK & Affected Systems */}
                  <div className="space-y-2">
                    {mitreList.length > 0 && (
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <Layers className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                        {mitreList.slice(0, 2).map((m, i) => (
                          <span key={i} className="text-[10px] font-mono bg-cyan-950/40 text-cyan-300 border border-cyan-500/20 px-1.5 py-0.5 rounded">
                            {m}
                          </span>
                        ))}
                        {mitreList.length > 2 && (
                          <span className="text-[10px] text-slate-400 font-mono">+{mitreList.length - 2} more</span>
                        )}
                      </div>
                    )}

                    {t.affectedSystems && (
                      <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
                        <Server className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                        <span className="truncate">{t.affectedSystems}</span>
                      </div>
                    )}
                  </div>
                </CardContent>
              </div>

              {/* Card Footer with Confidence & CTA */}
              <div className="px-5 py-3 border-t border-slate-800/80 bg-[#090E1A] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-slate-400">Confidence:</span>
                  <ConfidenceMeter confidence={t.confidence} />
                </div>

                <Link
                  to={`/threats/${t.id}`}
                  className="inline-flex items-center gap-1 text-xs font-semibold text-blue-400 hover:text-blue-300 transition-colors"
                >
                  Analyze Dossier <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            </Card>
          );
        })}
      </div>

      {filtered.length === 0 && (
        <div className="p-12 text-center bg-slate-900/30 rounded-xl border border-slate-800 text-slate-400 text-xs">
          No threat indicators match the current filters.
        </div>
      )}
    </div>
  );
}

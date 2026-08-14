import React, { useEffect, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent, Badge, SeverityBadge } from "../components/ui";
import {
  Clock,
  MapPin,
  Tag,
  ShieldAlert,
  Search,
  Filter,
  Calendar,
  Layers,
  Database,
  Terminal,
  Activity,
  ArrowRight
} from "lucide-react";
import type { Incident } from "../types";
import { Link } from "react-router-dom";

export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [categoryFilter, setCategoryFilter] = useState("ALL");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/incidents")
      .then(r => r.json())
      .then(data => {
        setIncidents(Array.isArray(data) ? data : []);
        setLoading(false);
      })
      .catch(e => {
        console.error(e);
        setIncidents([]);
        setLoading(false);
      });
  }, []);

  const categories = Array.from(new Set(incidents.map(i => i.category))).filter(Boolean);

  const filtered = incidents.filter(i => {
    const matchesSearch =
      i.title.toLowerCase().includes(search.toLowerCase()) ||
      i.description.toLowerCase().includes(search.toLowerCase()) ||
      i.location.toLowerCase().includes(search.toLowerCase()) ||
      (i.malware && i.malware.toLowerCase().includes(search.toLowerCase())) ||
      (i.threatActor && i.threatActor.toLowerCase().includes(search.toLowerCase()));
    const matchesSev = severityFilter === "ALL" || i.severity === severityFilter;
    const matchesCat = categoryFilter === "ALL" || i.category === categoryFilter;
    return matchesSearch && matchesSev && matchesCat;
  });

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-8">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="bg-blue-600/20 text-blue-400 text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase border border-blue-500/30">
            Chronological Timeline
          </span>
        </div>
        <h1 className="text-3xl font-bold text-white tracking-tight">Cyber Incident Timeline</h1>
        <p className="text-slate-400 text-sm mt-1">
          Chronological ledger of confirmed sensor triggers, anomalous activities, and prioritized incidents.
        </p>
      </div>

      {/* Filter Bar */}
      <Card>
        <CardContent className="p-4 flex flex-col md:flex-row items-center gap-4">
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search incidents by location, actor, malware, title..."
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

      {/* Timeline Stream */}
      <div className="relative border-l-2 border-slate-800 ml-4 space-y-8 pb-8">
        {filtered.map((inc) => {
          let dotColor = "bg-blue-500";
          if (inc.severity === "CRITICAL") dotColor = "bg-red-500 shadow-red-500/50 shadow-md";
          else if (inc.severity === "HIGH") dotColor = "bg-orange-500";
          else if (inc.severity === "MEDIUM") dotColor = "bg-amber-500";

          return (
            <div key={inc.id} className="relative pl-8 group">
              <div className={`absolute w-4 h-4 rounded-full -left-[9px] top-1.5 border-4 border-[#05070A] ${dotColor} transition-transform group-hover:scale-125`}></div>
              
              <Card className="hover:border-slate-700 transition-all shadow-md">
                <div className="p-5 space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <SeverityBadge severity={inc.severity} />
                      <span className="bg-slate-900 text-slate-300 px-2 py-0.5 rounded border border-slate-800 text-[10px] font-bold uppercase">
                        {inc.category}
                      </span>
                      {inc.malware && (
                        <span className="bg-purple-950/60 text-purple-300 border border-purple-500/30 text-[10px] font-mono px-2 py-0.5 rounded">
                          Malware: {inc.malware}
                        </span>
                      )}
                      {inc.threatActor && (
                        <span className="bg-indigo-950/60 text-indigo-300 border border-indigo-500/30 text-[10px] font-mono px-2 py-0.5 rounded">
                          Actor: {inc.threatActor}
                        </span>
                      )}
                    </div>

                    <div className="text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-slate-400" />
                      {new Date(inc.date).toLocaleString()}
                    </div>
                  </div>

                  <div>
                    <h3 className="text-base font-bold text-white tracking-tight">
                      {inc.title}
                    </h3>
                    <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                      {inc.description}
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/70 text-xs text-slate-400">
                    <div className="flex items-center gap-4 flex-wrap">
                      <div className="flex items-center gap-1.5 font-medium text-slate-300">
                        <MapPin className="w-3.5 h-3.5 text-red-400" /> {inc.location}
                      </div>
                      {inc.coordinates && (
                        <span className="text-[10px] font-mono text-slate-500">
                          [{inc.coordinates}]
                        </span>
                      )}
                    </div>

                    {inc.threatId && (
                      <Link
                        to={`/threats/${inc.threatId}`}
                        className="text-blue-400 hover:text-blue-300 font-semibold flex items-center gap-1 transition-colors text-xs"
                      >
                        Correlated Threat Dossier <ArrowRight className="w-3 h-3" />
                      </Link>
                    )}
                  </div>
                </div>
              </Card>
            </div>
          );
        })}

        {filtered.length === 0 && !loading && (
          <div className="pl-8 text-slate-500 text-xs py-6">
            No incident events match the selected criteria.
          </div>
        )}
      </div>
    </div>
  );
}

import React, { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Skull,
  Search,
  Filter,
  Plus,
  ShieldAlert,
  Globe,
  Crosshair,
  TrendingUp,
  Activity,
  Layers,
  Database,
  ExternalLink,
  ChevronRight,
  AlertTriangle,
  Flame,
  Radio,
  FileText,
  Clock,
  Sparkles,
  Server,
  Zap,
  Edit2,
  Trash2,
  CheckCircle2,
  Target
} from "lucide-react";
import { ThreatActorListItem, ThreatActor } from "../types";
import { Card, CardContent, CardHeader, CardTitle, Badge, SeverityBadge, ConfidenceMeter, Modal } from "../components/ui";

export default function ThreatActors() {
  const navigate = useNavigate();
  const [actors, setActors] = useState<ThreatActorListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [originFilter, setOriginFilter] = useState("ALL");
  const [motivationFilter, setMotivationFilter] = useState("ALL");
  const [sophisticationFilter, setSophisticationFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [viewMode, setViewMode] = useState<"cards" | "table">("cards");

  // Create Modal
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [formData, setFormData] = useState({
    name: "",
    aliases: "",
    description: "",
    origin: "Eastern Europe",
    motivation: "Financial Gain / Ransomware",
    sophistication: "Advanced",
    confidence: 90,
    status: "Active",
    notes: ""
  });
  const [formError, setFormError] = useState("");

  const fetchThreatActors = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (search) params.append("search", search);
      if (originFilter !== "ALL") params.append("origin", originFilter);
      if (motivationFilter !== "ALL") params.append("motivation", motivationFilter);
      if (sophisticationFilter !== "ALL") params.append("sophistication", sophisticationFilter);
      if (statusFilter !== "ALL") params.append("status", statusFilter);

      const res = await fetch(`/api/threat-actors?${params.toString()}`);
      if (!res.ok) throw new Error("Failed to load threat actors");
      const data = await res.json();
      setActors(data);
    } catch (err: any) {
      console.error("Error fetching threat actors:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreatActors();
  }, [search, originFilter, motivationFilter, sophisticationFilter, statusFilter]);

  const handleCreateActor = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError("");

    if (!formData.name.trim()) {
      setFormError("Actor designation / name is required.");
      return;
    }
    if (!formData.description.trim()) {
      setFormError("Actor profile description is required.");
      return;
    }

    try {
      setCreating(true);
      const res = await fetch("/api/threat-actors", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: formData.name,
          aliases: formData.aliases.split(",").map((s) => s.trim()).filter(Boolean),
          description: formData.description,
          origin: formData.origin,
          motivation: formData.motivation,
          sophistication: formData.sophistication,
          confidence: Number(formData.confidence),
          status: formData.status,
          notes: formData.notes
        })
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "Failed to create threat actor");
      }

      const created = await res.json();
      setCreateModalOpen(false);
      setFormData({
        name: "",
        aliases: "",
        description: "",
        origin: "Eastern Europe",
        motivation: "Financial Gain / Ransomware",
        sophistication: "Advanced",
        confidence: 90,
        status: "Active",
        notes: ""
      });
      fetchThreatActors();
      if (created?.actor?.id) {
        navigate(`/threat-actors/${created.actor.id}`);
      }
    } catch (err: any) {
      setFormError(err.message);
    } finally {
      setCreating(false);
    }
  };

  // KPI Calculations
  const totalCount = actors.length;
  const activeCount = actors.filter((a) => a.status === "Active").length;
  const advancedCount = actors.filter((a) => a.sophistication === "Advanced" || a.sophistication === "High").length;
  const totalCampaignsTracked = actors.reduce((acc, a) => acc + (a.campaignCount || 0), 0);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6 animate-in fade-in duration-300">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-950/80 text-red-400 border border-red-500/40 uppercase tracking-widest">
              Adversary Tracking & Attribution
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-900 border border-slate-800">
              MITRE ATT&CK Group Mapping
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight mt-1 flex items-center gap-3">
            <Skull className="w-8 h-8 text-red-500" />
            Threat Actors Intelligence
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-3xl">
            Structured adversary profiles, state-sponsored APT tracking, tactical motivations, mapped campaigns, and multi-source correlation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/campaigns"
            className="px-3.5 py-2 rounded-xl bg-[#0F172A] hover:bg-slate-800 border border-slate-700/80 text-slate-200 text-xs font-bold transition-colors flex items-center gap-2"
          >
            <Flame className="w-4 h-4 text-amber-400" />
            View Active Campaigns
          </Link>
          <button
            onClick={() => setCreateModalOpen(true)}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white text-xs font-bold shadow-lg shadow-red-950/50 transition-all flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Register Threat Actor
          </button>
        </div>
      </div>

      {/* KPI Metrics Banner */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-[#090F1E] border-slate-800/80">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Tracked Adversaries</p>
              <p className="text-2xl font-black text-white font-mono mt-0.5">{totalCount}</p>
              <p className="text-[10px] text-slate-500 mt-0.5">Nation-state & eCrime syndicates</p>
            </div>
            <div className="w-10 h-10 rounded-xl bg-red-950/40 border border-red-500/30 flex items-center justify-center text-red-400">
              <Skull className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-[#090F1E] border-slate-800/80">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Active Operations</p>
              <p className="text-2xl font-black text-red-400 font-mono mt-0.5">{activeCount}</p>
              <p className="text-[10px] text-emerald-400/80 mt-0.5">Currently weaponized</p>
            </div>
            <div className="w-10 h-10 rounded-xl bg-amber-950/40 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <Flame className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-[#090F1E] border-slate-800/80">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Advanced Sophistication</p>
              <p className="text-2xl font-black text-indigo-400 font-mono mt-0.5">{advancedCount}</p>
              <p className="text-[10px] text-slate-500 mt-0.5">Custom zero-days & rootkits</p>
            </div>
            <div className="w-10 h-10 rounded-xl bg-indigo-950/40 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              <Zap className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-[#090F1E] border-slate-800/80">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Attributed Campaigns</p>
              <p className="text-2xl font-black text-cyan-400 font-mono mt-0.5">{totalCampaignsTracked}</p>
              <p className="text-[10px] text-cyan-400/80 mt-0.5">Cross-correlated incidents</p>
            </div>
            <div className="w-10 h-10 rounded-xl bg-cyan-950/40 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Crosshair className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Search & Filter Toolbar */}
      <Card className="bg-[#080D1A] border-slate-800/90">
        <CardContent className="p-4 space-y-4">
          <div className="flex flex-col lg:flex-row items-center justify-between gap-3">
            {/* Search Input */}
            <div className="relative w-full lg:w-96">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search adversary name, aliases, origins, or motivations..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-[#050811] border border-slate-700/80 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-red-500 transition-colors"
              />
            </div>

            {/* View Mode & Reset Filter */}
            <div className="flex items-center gap-2 w-full lg:w-auto justify-end">
              <div className="bg-[#050811] p-1 rounded-xl border border-slate-800 flex items-center gap-1">
                <button
                  onClick={() => setViewMode("cards")}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                    viewMode === "cards" ? "bg-slate-800 text-white shadow" : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  Cards
                </button>
                <button
                  onClick={() => setViewMode("table")}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                    viewMode === "table" ? "bg-slate-800 text-white shadow" : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  Matrix View
                </button>
              </div>

              {(originFilter !== "ALL" || motivationFilter !== "ALL" || sophisticationFilter !== "ALL" || statusFilter !== "ALL" || search) && (
                <button
                  onClick={() => {
                    setSearch("");
                    setOriginFilter("ALL");
                    setMotivationFilter("ALL");
                    setSophisticationFilter("ALL");
                    setStatusFilter("ALL");
                  }}
                  className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors"
                >
                  Reset Filters
                </button>
              )}
            </div>
          </div>

          {/* Filter Dropdowns Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 border-t border-slate-800/80">
            <div>
              <label className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block mb-1">Origin / State</label>
              <select
                value={originFilter}
                onChange={(e) => setOriginFilter(e.target.value)}
                className="w-full bg-[#050811] border border-slate-700/70 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-red-500"
              >
                <option value="ALL">All Geographies</option>
                <option value="Russia">Russia (APT28, Sandworm, Cozy Bear)</option>
                <option value="China">China (Volt Typhoon, APT41)</option>
                <option value="North Korea">North Korea (Lazarus, Kimsuky)</option>
                <option value="Iran">Iran (Charming Kitten, MuddyWater)</option>
                <option value="Eastern Europe">Eastern Europe / CIS</option>
                <option value="Global">Global / Decentralized</option>
                <option value="Unknown">Unknown Attribution</option>
              </select>
            </div>

            <div>
              <label className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block mb-1">Primary Motivation</label>
              <select
                value={motivationFilter}
                onChange={(e) => setMotivationFilter(e.target.value)}
                className="w-full bg-[#050811] border border-slate-700/70 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-red-500"
              >
                <option value="ALL">All Motivations</option>
                <option value="Espionage">Espionage & IP Theft</option>
                <option value="Financial">Financial Gain / Ransomware</option>
                <option value="Infrastructure">Critical Infrastructure Disruption</option>
                <option value="Warfare">Cyber Warfare / Destructive</option>
                <option value="Influence">Information Operations</option>
              </select>
            </div>

            <div>
              <label className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block mb-1">Sophistication Level</label>
              <select
                value={sophisticationFilter}
                onChange={(e) => setSophisticationFilter(e.target.value)}
                className="w-full bg-[#050811] border border-slate-700/70 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-red-500"
              >
                <option value="ALL">All Sophistication</option>
                <option value="Advanced">Advanced (Nation-State Tier 1)</option>
                <option value="High">High (Organized Syndicate)</option>
                <option value="Medium">Medium (Tool Consumers)</option>
                <option value="Low">Low (Script Kiddies)</option>
              </select>
            </div>

            <div>
              <label className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block mb-1">Operational Status</label>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="w-full bg-[#050811] border border-slate-700/70 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-red-500"
              >
                <option value="ALL">All Operational States</option>
                <option value="Active">Active Operations</option>
                <option value="Monitored">Monitored / High Alert</option>
                <option value="Dormant">Dormant</option>
                <option value="Disrupted">Disrupted / Indicted</option>
              </select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Content Rendering */}
      {loading ? (
        <div className="py-20 text-center space-y-3">
          <div className="w-10 h-10 border-2 border-red-500 border-t-transparent rounded-full animate-spin mx-auto" />
          <p className="text-xs font-mono text-slate-400 tracking-wider uppercase">Loading Adversary Intelligence Dossiers...</p>
        </div>
      ) : actors.length === 0 ? (
        <div className="py-16 text-center bg-[#080D1A] rounded-2xl border border-slate-800 p-8 space-y-4">
          <Skull className="w-12 h-12 text-slate-600 mx-auto" />
          <div>
            <h3 className="text-base font-bold text-white">No Threat Actors Found</h3>
            <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
              No adversaries match your active search and filter criteria. Reset the filters or register a new intelligence profile.
            </p>
          </div>
          <button
            onClick={() => setCreateModalOpen(true)}
            className="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-bold inline-flex items-center gap-2"
          >
            <Plus className="w-4 h-4" /> Register Threat Actor
          </button>
        </div>
      ) : viewMode === "cards" ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {actors.map((actor) => (
            <Card
              key={actor.id}
              className="bg-[#090F1E] border-slate-800 hover:border-red-500/50 hover:shadow-red-950/20 transition-all group flex flex-col justify-between"
            >
              <CardContent className="p-5 space-y-4">
                {/* Header & Badges */}
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400 uppercase font-bold">
                        {actor.origin}
                      </span>
                      {actor.isSynthetic === 1 && (
                        <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-500/30 font-bold">
                          SYNTHETIC INTEL
                        </span>
                      )}
                    </div>
                    <Link
                      to={`/threat-actors/${actor.id}`}
                      className="text-base font-bold text-white group-hover:text-red-400 transition-colors mt-1.5 block tracking-tight"
                    >
                      {actor.name}
                    </Link>
                  </div>

                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider border ${
                      actor.status === "Active"
                        ? "bg-red-950/80 text-red-300 border-red-500/50"
                        : actor.status === "Monitored"
                        ? "bg-amber-950/80 text-amber-300 border-amber-500/50"
                        : "bg-slate-900 text-slate-400 border-slate-800"
                    }`}
                  >
                    ● {actor.status}
                  </span>
                </div>

                {/* Aliases Tags */}
                {actor.aliases && actor.aliases.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {actor.aliases.slice(0, 3).map((alias, idx) => (
                      <span
                        key={idx}
                        className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900/80 text-slate-300 border border-slate-800"
                      >
                        aka: {alias}
                      </span>
                    ))}
                    {actor.aliases.length > 3 && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-500">
                        +{actor.aliases.length - 3} more
                      </span>
                    )}
                  </div>
                )}

                {/* Description */}
                <p className="text-xs text-slate-400 line-clamp-3 leading-relaxed">
                  {actor.description}
                </p>

                {/* Key Attributes Grid */}
                <div className="grid grid-cols-2 gap-2 pt-3 border-t border-slate-800/80 text-[11px]">
                  <div>
                    <span className="text-slate-500 block text-[9px] font-mono uppercase">Motivation</span>
                    <span className="text-slate-300 font-medium truncate block">{actor.motivation}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[9px] font-mono uppercase">Sophistication</span>
                    <span className="text-indigo-300 font-bold block">{actor.sophistication}</span>
                  </div>
                </div>

                {/* Attribution Confidence */}
                <div className="space-y-1">
                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                    <span>Attribution Confidence</span>
                    <span className="text-white font-bold">{actor.confidence}%</span>
                  </div>
                  <ConfidenceMeter confidence={actor.confidence} />
                </div>

                {/* Mapped Entity Counters */}
                <div className="grid grid-cols-4 gap-1.5 pt-3 border-t border-slate-800/80 text-center">
                  <div className="bg-[#050811] p-1.5 rounded-lg border border-slate-800/60">
                    <span className="block text-[9px] font-mono text-slate-500 uppercase">Campaigns</span>
                    <span className="text-xs font-black font-mono text-amber-400">{actor.campaignCount}</span>
                  </div>
                  <div className="bg-[#050811] p-1.5 rounded-lg border border-slate-800/60">
                    <span className="block text-[9px] font-mono text-slate-500 uppercase">Threats</span>
                    <span className="text-xs font-black font-mono text-red-400">{actor.threatCount}</span>
                  </div>
                  <div className="bg-[#050811] p-1.5 rounded-lg border border-slate-800/60">
                    <span className="block text-[9px] font-mono text-slate-500 uppercase">IOCs</span>
                    <span className="text-xs font-black font-mono text-cyan-400">{actor.iocCount}</span>
                  </div>
                  <div className="bg-[#050811] p-1.5 rounded-lg border border-slate-800/60">
                    <span className="block text-[9px] font-mono text-slate-500 uppercase">Incidents</span>
                    <span className="text-xs font-black font-mono text-indigo-400">{actor.incidentCount}</span>
                  </div>
                </div>

                {/* Footer Action */}
                <div className="pt-2">
                  <Link
                    to={`/threat-actors/${actor.id}`}
                    className="w-full py-2 px-3 rounded-xl bg-slate-800/80 hover:bg-red-950/60 hover:text-red-300 hover:border-red-500/40 border border-slate-700/70 text-slate-200 text-xs font-bold transition-all flex items-center justify-center gap-2"
                  >
                    Open Intelligence Dossier
                    <ChevronRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        /* Matrix Table View */
        <Card className="bg-[#090F1E] border-slate-800 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0D1527] border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                <tr>
                  <th className="py-3.5 px-4 font-bold">Threat Actor</th>
                  <th className="py-3.5 px-4 font-bold">Origin</th>
                  <th className="py-3.5 px-4 font-bold">Motivation</th>
                  <th className="py-3.5 px-4 font-bold">Sophistication</th>
                  <th className="py-3.5 px-4 font-bold">Status</th>
                  <th className="py-3.5 px-4 font-bold">Attribution</th>
                  <th className="py-3.5 px-4 font-bold text-center">Correlations</th>
                  <th className="py-3.5 px-4 font-bold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {actors.map((actor) => (
                  <tr key={actor.id} className="hover:bg-slate-800/30 transition-colors group">
                    <td className="py-3.5 px-4 font-semibold text-white">
                      <Link
                        to={`/threat-actors/${actor.id}`}
                        className="group-hover:text-red-400 transition-colors flex items-center gap-2"
                      >
                        <Skull className="w-4 h-4 text-red-400 shrink-0" />
                        <div>
                          <span className="font-bold">{actor.name}</span>
                          {actor.aliases && actor.aliases.length > 0 && (
                            <span className="text-[10px] text-slate-400 font-mono block">
                              {actor.aliases.join(", ")}
                            </span>
                          )}
                        </div>
                      </Link>
                    </td>
                    <td className="py-3.5 px-4 text-slate-300 font-mono text-[11px]">{actor.origin}</td>
                    <td className="py-3.5 px-4 text-slate-400 text-[11px]">{actor.motivation}</td>
                    <td className="py-3.5 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-950/60 text-indigo-300 border border-indigo-500/30">
                        {actor.sophistication}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                          actor.status === "Active"
                            ? "bg-red-950/70 text-red-400 border border-red-500/30"
                            : "bg-slate-900 text-slate-400 border border-slate-800"
                        }`}
                      >
                        {actor.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="w-24">
                        <ConfidenceMeter confidence={actor.confidence} />
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex items-center justify-center gap-2 font-mono text-[11px]">
                        <span className="text-amber-400 font-bold" title="Campaigns">{actor.campaignCount} C</span>
                        <span className="text-slate-600">|</span>
                        <span className="text-red-400 font-bold" title="Threats">{actor.threatCount} T</span>
                        <span className="text-slate-600">|</span>
                        <span className="text-cyan-400 font-bold" title="IOCs">{actor.iocCount} I</span>
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <Link
                        to={`/threat-actors/${actor.id}`}
                        className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-red-600 text-white text-xs font-bold transition-colors inline-flex items-center gap-1.5"
                      >
                        Dossier
                        <ChevronRight className="w-3 h-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Register Threat Actor Modal */}
      <Modal
        isOpen={createModalOpen}
        onClose={() => setCreateModalOpen(false)}
        title="Register New Threat Actor Profile"
        maxWidth="max-w-2xl"
      >
        <form onSubmit={handleCreateActor} className="space-y-4 text-xs">
          {formError && (
            <div className="p-3 bg-red-950/80 border border-red-500/50 rounded-xl text-red-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{formError}</span>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Adversary Name / Designation *
              </label>
              <input
                type="text"
                required
                placeholder="e.g. Cobalt Spider, APT44, Volt Typhoon"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-red-500"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Known Aliases (comma separated)
              </label>
              <input
                type="text"
                placeholder="e.g. UNC3886, Bronze Union, LuckyMouse"
                value={formData.aliases}
                onChange={(e) => setFormData({ ...formData, aliases: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-red-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
              Adversary Profile & Executive Summary *
            </label>
            <textarea
              required
              rows={4}
              placeholder="Describe background, historical targets, known TTPs, tradecraft, and victimology..."
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full bg-[#050811] border border-slate-700 rounded-xl p-3 text-white placeholder-slate-500 focus:outline-none focus:border-red-500"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Origin / Affiliation
              </label>
              <select
                value={formData.origin}
                onChange={(e) => setFormData({ ...formData, origin: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-red-500"
              >
                <option value="Russia">Russia</option>
                <option value="China">China</option>
                <option value="North Korea">North Korea</option>
                <option value="Iran">Iran</option>
                <option value="Eastern Europe">Eastern Europe</option>
                <option value="Middle East">Middle East</option>
                <option value="Global">Global / Decentralized</option>
                <option value="Unknown">Unknown</option>
              </select>
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Strategic Motivation
              </label>
              <select
                value={formData.motivation}
                onChange={(e) => setFormData({ ...formData, motivation: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-red-500"
              >
                <option value="Espionage & IP Theft">Espionage & IP Theft</option>
                <option value="Financial Gain / Ransomware">Financial Gain / Ransomware</option>
                <option value="Critical Infrastructure Disruption">Critical Infrastructure Disruption</option>
                <option value="Cyber Warfare">Cyber Warfare / Destructive</option>
                <option value="Hacktivism / Influence">Hacktivism / Influence</option>
              </select>
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Sophistication Tier
              </label>
              <select
                value={formData.sophistication}
                onChange={(e) => setFormData({ ...formData, sophistication: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-red-500"
              >
                <option value="Advanced">Advanced (Tier 1 APT)</option>
                <option value="High">High (Organized Syndicate)</option>
                <option value="Medium">Medium (Skilled Operators)</option>
                <option value="Low">Low (Commodity)</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Attribution Confidence ({formData.confidence}%)
              </label>
              <input
                type="range"
                min={10}
                max={100}
                value={formData.confidence}
                onChange={(e) => setFormData({ ...formData, confidence: parseInt(e.target.value, 10) })}
                className="w-full accent-red-500"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Operational Status
              </label>
              <select
                value={formData.status}
                onChange={(e) => setFormData({ ...formData, status: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-red-500"
              >
                <option value="Active">Active Operations</option>
                <option value="Monitored">Monitored / High Alert</option>
                <option value="Dormant">Dormant</option>
                <option value="Disrupted">Disrupted / Indicted</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
              Internal Analyst Notes & Caveats
            </label>
            <input
              type="text"
              placeholder="e.g. Under investigation by CISA; observed targeting European energy sector in Q1."
              value={formData.notes}
              onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
              className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-red-500"
            />
          </div>

          <div className="pt-4 border-t border-slate-800 flex justify-end gap-3">
            <button
              type="button"
              onClick={() => setCreateModalOpen(false)}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={creating}
              className="px-5 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-bold transition-all shadow-lg shadow-red-950/50 flex items-center gap-2"
            >
              {creating ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Saving Intelligence...
                </>
              ) : (
                <>
                  <CheckCircle2 className="w-4 h-4" />
                  Save Threat Actor
                </>
              )}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

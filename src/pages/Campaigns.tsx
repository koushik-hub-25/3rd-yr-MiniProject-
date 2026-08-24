import React, { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Flame,
  Search,
  Filter,
  Plus,
  Crosshair,
  Globe,
  ShieldAlert,
  Target,
  Skull,
  TrendingUp,
  ChevronRight,
  Database,
  Server,
  Layers,
  AlertTriangle,
  Radio,
  Calendar,
  Clock,
  CheckCircle2,
  Zap,
  Activity
} from "lucide-react";
import { CampaignListItem, ThreatActorListItem } from "../types";
import { Card, CardContent, CardHeader, CardTitle, Badge, SeverityBadge, ConfidenceMeter, Modal } from "../components/ui";

export default function Campaigns() {
  const navigate = useNavigate();
  const [campaigns, setCampaigns] = useState<CampaignListItem[]>([]);
  const [threatActors, setThreatActors] = useState<ThreatActorListItem[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [sectorFilter, setSectorFilter] = useState("ALL");
  const [regionFilter, setRegionFilter] = useState("ALL");
  const [actorFilter, setActorFilter] = useState("ALL");
  const [viewMode, setViewMode] = useState<"cards" | "table">("cards");

  // Create Campaign Modal
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [formData, setFormData] = useState({
    name: "",
    description: "",
    threatActorId: "",
    targetSectors: "Financial Services, Critical Infrastructure",
    targetRegions: "North America, Western Europe",
    objectives: "Data Exfiltration, Ransom Demands, Disruption",
    status: "Active",
    confidence: 90,
    notes: ""
  });
  const [formError, setFormError] = useState("");

  const fetchCampaigns = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (search) params.append("search", search);
      if (statusFilter !== "ALL") params.append("status", statusFilter);
      if (sectorFilter !== "ALL") params.append("sector", sectorFilter);
      if (regionFilter !== "ALL") params.append("region", regionFilter);
      if (actorFilter !== "ALL") params.append("threatActorId", actorFilter);

      const res = await fetch(`/api/campaigns?${params.toString()}`);
      if (!res.ok) throw new Error("Failed to load campaigns");
      const data = await res.json();
      setCampaigns(data);
    } catch (err: any) {
      console.error("Error fetching campaigns:", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchThreatActorsList = async () => {
    try {
      const res = await fetch("/api/threat-actors");
      if (res.ok) {
        setThreatActors(await res.json());
      }
    } catch (e) {
      console.warn("Could not fetch threat actors list:", e);
    }
  };

  useEffect(() => {
    fetchThreatActorsList();
  }, []);

  useEffect(() => {
    fetchCampaigns();
  }, [search, statusFilter, sectorFilter, regionFilter, actorFilter]);

  const handleCreateCampaign = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError("");

    if (!formData.name.trim()) {
      setFormError("Campaign codename / title is required.");
      return;
    }
    if (!formData.description.trim()) {
      setFormError("Campaign operational description is required.");
      return;
    }

    try {
      setCreating(true);
      const res = await fetch("/api/campaigns", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: formData.name,
          description: formData.description,
          threatActorId: formData.threatActorId || null,
          targetSectors: formData.targetSectors.split(",").map((s) => s.trim()).filter(Boolean),
          targetRegions: formData.targetRegions.split(",").map((s) => s.trim()).filter(Boolean),
          objectives: formData.objectives,
          status: formData.status,
          confidence: Number(formData.confidence),
          notes: formData.notes
        })
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "Failed to create campaign");
      }

      const created = await res.json();
      setCreateModalOpen(false);
      setFormData({
        name: "",
        description: "",
        threatActorId: "",
        targetSectors: "Financial Services, Critical Infrastructure",
        targetRegions: "North America, Western Europe",
        objectives: "Data Exfiltration, Ransom Demands, Disruption",
        status: "Active",
        confidence: 90,
        notes: ""
      });
      fetchCampaigns();
      if (created?.campaign?.id) {
        navigate(`/campaigns/${created.campaign.id}`);
      }
    } catch (err: any) {
      setFormError(err.message);
    } finally {
      setCreating(false);
    }
  };

  const totalCount = campaigns.length;
  const activeCount = campaigns.filter((c) => c.status === "Active").length;
  const monitoredCount = campaigns.filter((c) => c.status === "Monitored").length;
  const highConfidenceCount = campaigns.filter((c) => c.confidence >= 85).length;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6 animate-in fade-in duration-300">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/80 text-amber-400 border border-amber-500/40 uppercase tracking-widest">
              Adversary Operations Tracking
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-900 border border-slate-800">
              Correlated Multi-Stage Campaigns
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight mt-1 flex items-center gap-3">
            <Flame className="w-8 h-8 text-amber-500" />
            Threat Campaigns Intelligence
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-3xl">
            Track coordinated adversary operations spanning multiple attacks, victim sectors, geographic theaters, weaponized exploits, and MITRE execution tactics.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/threat-actors"
            className="px-3.5 py-2 rounded-xl bg-[#0F172A] hover:bg-slate-800 border border-slate-700/80 text-slate-200 text-xs font-bold transition-colors flex items-center gap-2"
          >
            <Skull className="w-4 h-4 text-red-400" />
            Adversary Profiles
          </Link>
          <button
            onClick={() => setCreateModalOpen(true)}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-white text-xs font-bold shadow-lg shadow-amber-950/50 transition-all flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Launch Campaign Record
          </button>
        </div>
      </div>

      {/* KPI Metrics */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-[#090F1E] border-slate-800/80">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Total Tracked Campaigns</p>
              <p className="text-2xl font-black text-white font-mono mt-0.5">{totalCount}</p>
              <p className="text-[10px] text-slate-500 mt-0.5">Coordinated offensive operations</p>
            </div>
            <div className="w-10 h-10 rounded-xl bg-amber-950/40 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <Flame className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-[#090F1E] border-slate-800/80">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Active Weaponization</p>
              <p className="text-2xl font-black text-red-400 font-mono mt-0.5">{activeCount}</p>
              <p className="text-[10px] text-red-400/80 mt-0.5">Active attacks observed in the wild</p>
            </div>
            <div className="w-10 h-10 rounded-xl bg-red-950/40 border border-red-500/30 flex items-center justify-center text-red-400">
              <Radio className="w-5 h-5 animate-pulse" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-[#090F1E] border-slate-800/80">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Monitored Inactivity</p>
              <p className="text-2xl font-black text-indigo-400 font-mono mt-0.5">{monitoredCount}</p>
              <p className="text-[10px] text-slate-500 mt-0.5">Low-level staging or reconnaissance</p>
            </div>
            <div className="w-10 h-10 rounded-xl bg-indigo-950/40 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              <Target className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-[#090F1E] border-slate-800/80">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">High-Confidence Attribution</p>
              <p className="text-2xl font-black text-emerald-400 font-mono mt-0.5">{highConfidenceCount}</p>
              <p className="text-[10px] text-emerald-400/80 mt-0.5">&ge;85% correlation certainty</p>
            </div>
            <div className="w-10 h-10 rounded-xl bg-emerald-950/40 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <CheckCircle2 className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Toolbar & Filters */}
      <Card className="bg-[#080D1A] border-slate-800/90">
        <CardContent className="p-4 space-y-4">
          <div className="flex flex-col lg:flex-row items-center justify-between gap-3">
            {/* Search Input */}
            <div className="relative w-full lg:w-96">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search campaign name, objectives, sectors, or regions..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-[#050811] border border-slate-700/80 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-amber-500 transition-colors"
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

              {(statusFilter !== "ALL" || sectorFilter !== "ALL" || regionFilter !== "ALL" || actorFilter !== "ALL" || search) && (
                <button
                  onClick={() => {
                    setSearch("");
                    setStatusFilter("ALL");
                    setSectorFilter("ALL");
                    setRegionFilter("ALL");
                    setActorFilter("ALL");
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
              <label className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block mb-1">Operational Status</label>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="w-full bg-[#050811] border border-slate-700/70 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
              >
                <option value="ALL">All Statuses</option>
                <option value="Active">Active Attack Campaign</option>
                <option value="Monitored">Monitored Threat</option>
                <option value="Disrupted">Disrupted Operation</option>
                <option value="Completed">Completed / Historic</option>
              </select>
            </div>

            <div>
              <label className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block mb-1">Target Sector</label>
              <select
                value={sectorFilter}
                onChange={(e) => setSectorFilter(e.target.value)}
                className="w-full bg-[#050811] border border-slate-700/70 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
              >
                <option value="ALL">All Critical Sectors</option>
                <option value="Financial">Financial Services & Banking</option>
                <option value="Energy">Energy & Utilities</option>
                <option value="Critical Infrastructure">Critical Infrastructure</option>
                <option value="Healthcare">Healthcare & Biotech</option>
                <option value="Defense">Defense & Government</option>
                <option value="Technology">Technology & Cloud Infrastructure</option>
                <option value="Telecommunications">Telecommunications</option>
              </select>
            </div>

            <div>
              <label className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block mb-1">Target Region</label>
              <select
                value={regionFilter}
                onChange={(e) => setRegionFilter(e.target.value)}
                className="w-full bg-[#050811] border border-slate-700/70 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
              >
                <option value="ALL">All Global Regions</option>
                <option value="North America">North America</option>
                <option value="Europe">Western & Eastern Europe</option>
                <option value="Asia">Asia-Pacific</option>
                <option value="Middle East">Middle East</option>
                <option value="Global">Global Operations</option>
              </select>
            </div>

            <div>
              <label className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block mb-1">Attributed Actor</label>
              <select
                value={actorFilter}
                onChange={(e) => setActorFilter(e.target.value)}
                className="w-full bg-[#050811] border border-slate-700/70 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
              >
                <option value="ALL">All Threat Actors</option>
                {threatActors.map((actor) => (
                  <option key={actor.id} value={actor.id}>{actor.name} ({actor.origin})</option>
                ))}
              </select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Content Rendering */}
      {loading ? (
        <div className="py-20 text-center space-y-3">
          <div className="w-10 h-10 border-2 border-amber-500 border-t-transparent rounded-full animate-spin mx-auto" />
          <p className="text-xs font-mono text-slate-400 tracking-wider uppercase">Loading Cyber Campaign Intelligence...</p>
        </div>
      ) : campaigns.length === 0 ? (
        <div className="py-16 text-center bg-[#080D1A] rounded-2xl border border-slate-800 p-8 space-y-4">
          <Flame className="w-12 h-12 text-slate-600 mx-auto" />
          <div>
            <h3 className="text-base font-bold text-white">No Threat Campaigns Found</h3>
            <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
              No active campaigns match your selected search and filter criteria.
            </p>
          </div>
          <button
            onClick={() => setCreateModalOpen(true)}
            className="px-4 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold inline-flex items-center gap-2"
          >
            <Plus className="w-4 h-4" /> Launch Campaign Record
          </button>
        </div>
      ) : viewMode === "cards" ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {campaigns.map((campaign) => (
            <Card
              key={campaign.id}
              className="bg-[#090F1E] border-slate-800 hover:border-amber-500/50 hover:shadow-amber-950/20 transition-all group flex flex-col justify-between"
            >
              <CardContent className="p-5 space-y-4">
                {/* Header */}
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <span
                      className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase tracking-wider border ${
                        campaign.status === "Active"
                          ? "bg-red-950/80 text-red-300 border-red-500/50"
                          : campaign.status === "Monitored"
                          ? "bg-amber-950/80 text-amber-300 border-amber-500/50"
                          : "bg-slate-900 text-slate-400 border-slate-800"
                      }`}
                    >
                      ● {campaign.status}
                    </span>
                    <Link
                      to={`/campaigns/${campaign.id}`}
                      className="text-base font-bold text-white group-hover:text-amber-400 transition-colors mt-2 block tracking-tight"
                    >
                      {campaign.name}
                    </Link>
                  </div>

                  <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                    {campaign.confidence}% Conf.
                  </span>
                </div>

                {/* Attributed Threat Actor Link */}
                {campaign.threatActor && (
                  <div className="p-2 bg-[#050811] rounded-lg border border-slate-800/80 flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1.5 text-slate-400 font-mono text-[11px]">
                      <Skull className="w-3.5 h-3.5 text-red-400" />
                      <span>Attributed Actor:</span>
                    </div>
                    <Link
                      to={`/threat-actors/${campaign.threatActor.id}`}
                      className="font-bold text-red-400 hover:underline flex items-center gap-1"
                    >
                      {campaign.threatActor.name}
                      <span className="text-[10px] text-slate-500 font-normal">({campaign.threatActor.origin})</span>
                    </Link>
                  </div>
                )}

                {/* Description */}
                <p className="text-xs text-slate-400 line-clamp-3 leading-relaxed">
                  {campaign.description}
                </p>

                {/* Target Sectors & Regions Badges */}
                <div className="space-y-2 pt-2 border-t border-slate-800/80 text-[11px]">
                  {campaign.targetSectors && campaign.targetSectors.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1">
                      <span className="text-slate-500 font-mono text-[9px] uppercase">Sectors:</span>
                      {campaign.targetSectors.slice(0, 3).map((sec, idx) => (
                        <span
                          key={idx}
                          className="px-1.5 py-0.2 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-500/30 font-mono text-[10px]"
                        >
                          {sec}
                        </span>
                      ))}
                    </div>
                  )}

                  {campaign.targetRegions && campaign.targetRegions.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1">
                      <span className="text-slate-500 font-mono text-[9px] uppercase">Theaters:</span>
                      {campaign.targetRegions.slice(0, 2).map((reg, idx) => (
                        <span
                          key={idx}
                          className="px-1.5 py-0.2 rounded bg-slate-900 text-slate-300 font-mono text-[10px]"
                        >
                          {reg}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Entity Counters */}
                <div className="grid grid-cols-4 gap-1.5 pt-3 border-t border-slate-800/80 text-center">
                  <div className="bg-[#050811] p-1.5 rounded-lg border border-slate-800/60">
                    <span className="block text-[9px] font-mono text-slate-500 uppercase">Threats</span>
                    <span className="text-xs font-black font-mono text-red-400">{campaign.threatCount}</span>
                  </div>
                  <div className="bg-[#050811] p-1.5 rounded-lg border border-slate-800/60">
                    <span className="block text-[9px] font-mono text-slate-500 uppercase">IOCs</span>
                    <span className="text-xs font-black font-mono text-cyan-400">{campaign.iocCount}</span>
                  </div>
                  <div className="bg-[#050811] p-1.5 rounded-lg border border-slate-800/60">
                    <span className="block text-[9px] font-mono text-slate-500 uppercase">Incidents</span>
                    <span className="text-xs font-black font-mono text-indigo-400">{campaign.incidentCount}</span>
                  </div>
                  <div className="bg-[#050811] p-1.5 rounded-lg border border-slate-800/60">
                    <span className="block text-[9px] font-mono text-slate-500 uppercase">TTPs</span>
                    <span className="text-xs font-black font-mono text-amber-400">{campaign.techniqueCount}</span>
                  </div>
                </div>

                {/* Footer Link */}
                <div className="pt-2">
                  <Link
                    to={`/campaigns/${campaign.id}`}
                    className="w-full py-2 px-3 rounded-xl bg-slate-800/80 hover:bg-amber-950/60 hover:text-amber-300 hover:border-amber-500/40 border border-slate-700/70 text-slate-200 text-xs font-bold transition-all flex items-center justify-center gap-2"
                  >
                    Open Campaign Dossier
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
                  <th className="py-3.5 px-4 font-bold">Campaign Name</th>
                  <th className="py-3.5 px-4 font-bold">Attributed Actor</th>
                  <th className="py-3.5 px-4 font-bold">Status</th>
                  <th className="py-3.5 px-4 font-bold">Target Sectors</th>
                  <th className="py-3.5 px-4 font-bold">Theaters</th>
                  <th className="py-3.5 px-4 font-bold text-center">Telemetry Links</th>
                  <th className="py-3.5 px-4 font-bold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {campaigns.map((c) => (
                  <tr key={c.id} className="hover:bg-slate-800/30 transition-colors group">
                    <td className="py-3.5 px-4 font-semibold text-white">
                      <Link to={`/campaigns/${c.id}`} className="group-hover:text-amber-400 transition-colors font-bold block">
                        {c.name}
                      </Link>
                      <span className="text-[10px] text-slate-400 font-mono line-clamp-1">
                        {c.objectives || "Multi-stage cyber operation"}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      {c.threatActor ? (
                        <Link to={`/threat-actors/${c.threatActor.id}`} className="text-red-400 font-bold hover:underline">
                          {c.threatActor.name}
                        </Link>
                      ) : (
                        <span className="text-slate-500 font-mono">Unattributed APT</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                          c.status === "Active"
                            ? "bg-red-950/70 text-red-400 border border-red-500/30"
                            : "bg-slate-900 text-slate-400 border border-slate-800"
                        }`}
                      >
                        {c.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-300 font-mono text-[11px]">
                      {(c.targetSectors || []).slice(0, 2).join(", ")}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                      {(c.targetRegions || []).slice(0, 2).join(", ")}
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex items-center justify-center gap-2 font-mono text-[11px]">
                        <span className="text-red-400 font-bold" title="Threats">{c.threatCount} T</span>
                        <span className="text-slate-600">|</span>
                        <span className="text-cyan-400 font-bold" title="IOCs">{c.iocCount} I</span>
                        <span className="text-slate-600">|</span>
                        <span className="text-amber-400 font-bold" title="TTPs">{c.techniqueCount} TTP</span>
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <Link
                        to={`/campaigns/${c.id}`}
                        className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-amber-600 text-white text-xs font-bold transition-colors inline-flex items-center gap-1.5"
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

      {/* Launch Campaign Modal */}
      <Modal
        isOpen={createModalOpen}
        onClose={() => setCreateModalOpen(false)}
        title="Launch New Cyber Threat Campaign Record"
        maxWidth="max-w-2xl"
      >
        <form onSubmit={handleCreateCampaign} className="space-y-4 text-xs">
          {formError && (
            <div className="p-3 bg-red-950/80 border border-red-500/50 rounded-xl text-red-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{formError}</span>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Campaign Codename / Title *
              </label>
              <input
                type="text"
                required
                placeholder="e.g. Operation Voltage Ghost, DarkSide Revival"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Attributed Threat Actor
              </label>
              <select
                value={formData.threatActorId}
                onChange={(e) => setFormData({ ...formData, threatActorId: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-amber-500"
              >
                <option value="">-- Select Attributed Threat Actor (Optional) --</option>
                {threatActors.map((a) => (
                  <option key={a.id} value={a.id}>{a.name} ({a.origin})</option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
              Campaign Operational Description *
            </label>
            <textarea
              required
              rows={4}
              placeholder="Describe campaign vector, staging methodology, target profile, malware families, and tactical objectives..."
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full bg-[#050811] border border-slate-700 rounded-xl p-3 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Target Sectors (comma-separated)
              </label>
              <input
                type="text"
                placeholder="Financial Services, Energy, Healthcare"
                value={formData.targetSectors}
                onChange={(e) => setFormData({ ...formData, targetSectors: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Target Theaters / Regions (comma-separated)
              </label>
              <input
                type="text"
                placeholder="North America, Western Europe, APAC"
                value={formData.targetRegions}
                onChange={(e) => setFormData({ ...formData, targetRegions: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
              Primary Strategic Objectives
            </label>
            <input
              type="text"
              placeholder="e.g. Intellectual Property Theft, Pre-positioning in ICS grids, Ransom Extortion"
              value={formData.objectives}
              onChange={(e) => setFormData({ ...formData, objectives: e.target.value })}
              className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
            />
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
                className="w-full accent-amber-500"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Operational Status
              </label>
              <select
                value={formData.status}
                onChange={(e) => setFormData({ ...formData, status: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-amber-500"
              >
                <option value="Active">Active Attack Campaign</option>
                <option value="Monitored">Monitored Threat</option>
                <option value="Disrupted">Disrupted Operation</option>
                <option value="Completed">Completed / Historic</option>
              </select>
            </div>
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
              className="px-5 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold transition-all shadow-lg shadow-amber-950/50 flex items-center gap-2"
            >
              {creating ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Registering Campaign...
                </>
              ) : (
                <>
                  <CheckCircle2 className="w-4 h-4" />
                  Save Campaign
                </>
              )}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

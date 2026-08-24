import React, { useState, useEffect } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import {
  Skull,
  ArrowLeft,
  Flame,
  ShieldAlert,
  Crosshair,
  Database,
  Layers,
  Activity,
  AlertTriangle,
  Globe,
  Clock,
  Calendar,
  ExternalLink,
  Plus,
  Edit2,
  Trash2,
  CheckCircle2,
  Server,
  Zap,
  Tag,
  Search,
  Sparkles,
  ChevronRight,
  Radio,
  FileText,
  Filter,
  X,
  Target
} from "lucide-react";
import { ThreatActorDossier, ThreatActor } from "../types";
import { Card, CardContent, CardHeader, CardTitle, Badge, SeverityBadge, ConfidenceMeter, Modal } from "../components/ui";
import IocInvestigationModal from "../components/IocInvestigationModal";

export default function ThreatActorDetails() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [dossier, setDossier] = useState<ThreatActorDossier | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<"overview" | "campaigns" | "threats" | "iocs" | "incidents" | "mitre" | "assets" | "timeline">("overview");

  // Edit Modal State
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [editFormData, setEditFormData] = useState({
    name: "",
    aliases: "",
    description: "",
    origin: "",
    motivation: "",
    sophistication: "",
    confidence: 90,
    status: "",
    notes: ""
  });

  // Relationship Modal State
  const [relModalOpen, setRelModalOpen] = useState(false);
  const [addingRel, setAddingRel] = useState(false);
  const [relFormData, setRelFormData] = useState({
    type: "THREAT",
    targetId: "",
    confidence: "confirmed",
    attributionType: "Primary Operator",
    context: ""
  });
  const [relError, setRelError] = useState("");

  // Selectable options for relationship linking
  const [availableThreats, setAvailableThreats] = useState<any[]>([]);
  const [availableIocs, setAvailableIocs] = useState<any[]>([]);
  const [availableIncidents, setAvailableIncidents] = useState<any[]>([]);
  const [availableCampaigns, setAvailableCampaigns] = useState<any[]>([]);

  // IOC Investigation Modal State
  const [investigationDossier, setInvestigationDossier] = useState<any | null>(null);
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [investigatingLoading, setInvestigatingLoading] = useState(false);

  const handleInvestigateIoc = async (iocValue: string) => {
    try {
      setInvestigatingLoading(true);
      const res = await fetch("/api/iocs/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ioc: iocValue })
      });
      if (res.ok) {
        const data = await res.json();
        setInvestigationDossier(data);
        setIsInvestigating(true);
      }
    } catch (err) {
      console.error("IOC investigation failed:", err);
    } finally {
      setInvestigatingLoading(false);
    }
  };

  const fetchDossier = async () => {
    if (!id) return;
    try {
      setLoading(true);
      setError("");
      const res = await fetch(`/api/threat-actors/${id}`);
      if (!res.ok) {
        if (res.status === 404) throw new Error("Threat Actor profile not found.");
        throw new Error("Failed to fetch Threat Actor dossier.");
      }
      const data: ThreatActorDossier = await res.json();
      setDossier(data);
      setEditFormData({
        name: data.actor.name,
        aliases: Array.isArray(data.actor.aliases)
          ? data.actor.aliases.join(", ")
          : typeof data.actor.aliases === "string"
          ? data.actor.aliases
          : "",
        description: data.actor.description,
        origin: data.actor.origin,
        motivation: data.actor.motivation,
        sophistication: data.actor.sophistication,
        confidence: data.actor.confidence,
        status: data.actor.status,
        notes: data.actor.notes || ""
      });
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchAvailableEntities = async () => {
    try {
      const [tRes, iRes, incRes, cRes] = await Promise.all([
        fetch("/api/threats"),
        fetch("/api/iocs"),
        fetch("/api/incidents"),
        fetch("/api/campaigns")
      ]);
      if (tRes.ok) setAvailableThreats(await tRes.json());
      if (iRes.ok) setAvailableIocs(await iRes.json());
      if (incRes.ok) setAvailableIncidents(await incRes.json());
      if (cRes.ok) setAvailableCampaigns(await cRes.json());
    } catch (e) {
      console.warn("Could not fetch lookup entities for relationship modal:", e);
    }
  };

  useEffect(() => {
    fetchDossier();
  }, [id]);

  const handleUpdateActor = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!id) return;

    try {
      setUpdating(true);
      const res = await fetch(`/api/threat-actors/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: editFormData.name,
          aliases: editFormData.aliases.split(",").map((s) => s.trim()).filter(Boolean),
          description: editFormData.description,
          origin: editFormData.origin,
          motivation: editFormData.motivation,
          sophistication: editFormData.sophistication,
          confidence: Number(editFormData.confidence),
          status: editFormData.status,
          notes: editFormData.notes
        })
      });

      if (!res.ok) throw new Error("Failed to update Threat Actor profile.");
      const updated = await res.json();
      setDossier(updated);
      setEditModalOpen(false);
    } catch (err: any) {
      alert("Update failed: " + err.message);
    } finally {
      setUpdating(false);
    }
  };

  const handleDeleteActor = async () => {
    if (!id || !dossier) return;
    const confirmDelete = window.confirm(`Are you sure you want to delete intelligence dossier for "${dossier.actor.name}"? This action cannot be undone.`);
    if (!confirmDelete) return;

    try {
      const res = await fetch(`/api/threat-actors/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to delete Threat Actor.");
      navigate("/threat-actors");
    } catch (err: any) {
      alert("Deletion failed: " + err.message);
    }
  };

  const handleAddRelationship = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!id) return;
    setRelError("");

    if (!relFormData.targetId) {
      setRelError("Please select a target entity to correlate.");
      return;
    }

    try {
      setAddingRel(true);
      const res = await fetch(`/api/threat-actors/${id}/relationships`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: relFormData.type,
          targetId: relFormData.targetId,
          confidence: relFormData.confidence,
          attributionType: relFormData.attributionType,
          context: relFormData.context
        })
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to add relationship link.");
      }

      const updated = await res.json();
      setDossier(updated);
      setRelModalOpen(false);
      setRelFormData({
        type: "THREAT",
        targetId: "",
        confidence: "confirmed",
        attributionType: "Primary Operator",
        context: ""
      });
    } catch (err: any) {
      setRelError(err.message);
    } finally {
      setAddingRel(false);
    }
  };

  const handleRemoveRelationship = async (type: string, targetId: string) => {
    if (!id) return;
    const confirmRemove = window.confirm(`Remove association with ${type} artifact ${targetId}?`);
    if (!confirmRemove) return;

    try {
      const res = await fetch(`/api/threat-actors/${id}/relationships`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type, targetId })
      });
      if (!res.ok) throw new Error("Failed to remove relationship");
      const updated = await res.json();
      setDossier(updated);
    } catch (err: any) {
      alert("Error removing relationship: " + err.message);
    }
  };

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-24 text-center space-y-4 animate-in fade-in duration-200">
        <div className="w-12 h-12 border-2 border-red-500 border-t-transparent rounded-full animate-spin mx-auto" />
        <p className="text-xs font-mono uppercase tracking-wider text-slate-400">Loading Adversary Dossier & Cross-Correlations...</p>
      </div>
    );
  }

  if (error || !dossier) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-16 text-center space-y-4">
        <AlertTriangle className="w-12 h-12 text-red-500 mx-auto" />
        <h2 className="text-lg font-bold text-white">Adversary Dossier Not Found</h2>
        <p className="text-xs text-slate-400">{error || "The requested threat actor does not exist."}</p>
        <Link
          to="/threat-actors"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Threat Actors
        </Link>
      </div>
    );
  }

  const { actor, campaigns, threats, iocs, incidents, mitreTechniques, correlatedAssets, timeline } = dossier;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6 animate-in fade-in duration-300">
      {/* Navigation Breadcrumbs */}
      <div className="flex items-center justify-between text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <Link to="/threat-intelligence" className="hover:text-cyan-400 transition-colors">Intelligence</Link>
          <span>/</span>
          <Link to="/threat-actors" className="hover:text-cyan-400 transition-colors">Threat Actors</Link>
          <span>/</span>
          <span className="text-slate-200 font-bold">{actor.name}</span>
        </div>

        <Link
          to="/threat-actors"
          className="inline-flex items-center gap-1.5 text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to List
        </Link>
      </div>

      {/* Synthetic Intelligence Notice Banner */}
      {actor.isSynthetic === 1 && (
        <div className="p-3 bg-cyan-950/40 border border-cyan-500/40 rounded-2xl flex items-center justify-between gap-4 text-xs text-cyan-300">
          <div className="flex items-center gap-2.5">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping shrink-0" />
            <span>
              <strong>Synthetic Intelligence Dataset:</strong> This threat actor profile contains realistic structured emulation data correlated with live NVD CVE feeds and real-world MITRE ATT&CK frameworks.
            </span>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-900/60 border border-cyan-500/30 text-cyan-200 whitespace-nowrap">
            SEC-SANDBOX-EMULATION
          </span>
        </div>
      )}

      {/* Executive Dossier Header Card */}
      <Card className="bg-[#090F1E] border-slate-800">
        <CardContent className="p-6 space-y-6">
          <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6">
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-red-950/90 text-red-300 border border-red-500/50 uppercase tracking-widest flex items-center gap-1.5">
                  <Skull className="w-3.5 h-3.5 text-red-400" />
                  THREAT ACTOR DOSSIER
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-900 border border-slate-800 text-slate-300 uppercase">
                  {actor.origin}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-950/70 text-indigo-300 border border-indigo-500/40 uppercase">
                  {actor.sophistication} SOPHISTICATION
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                    actor.status === "Active"
                      ? "bg-red-950 text-red-300 border border-red-500/40"
                      : "bg-slate-900 text-slate-400 border border-slate-800"
                  }`}
                >
                  ● {actor.status}
                </span>
              </div>

              <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight flex items-center gap-3">
                {actor.name}
              </h1>

              {/* Aliases Tags */}
              {(() => {
                const aliasList = Array.isArray(actor.aliases)
                  ? actor.aliases
                  : typeof actor.aliases === "string"
                  ? (actor.aliases as string).split(",").map((s) => s.trim()).filter(Boolean)
                  : [];
                if (aliasList.length === 0) return null;
                return (
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span className="text-slate-500 font-mono text-[10px] uppercase">Known Aliases:</span>
                    {aliasList.map((alias, i) => (
                      <span
                        key={i}
                        className="px-2 py-0.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 font-mono text-[11px]"
                      >
                        {alias}
                      </span>
                    ))}
                  </div>
                );
              })()}

              <p className="text-xs sm:text-sm text-slate-300 leading-relaxed max-w-4xl pt-1">
                {actor.description}
              </p>
            </div>

            {/* Right Action Bar & Attribution Meter */}
            <div className="flex flex-col items-start lg:items-end gap-4 shrink-0">
              <div className="bg-[#050811] p-3.5 rounded-2xl border border-slate-800 space-y-2 w-full sm:w-64">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-400">Attribution Confidence</span>
                  <span className="text-white font-bold">{actor.confidence}%</span>
                </div>
                <ConfidenceMeter confidence={actor.confidence} />
                <p className="text-[10px] text-slate-500">Based on telemetry, IOC overlap & TTP matching</p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => {
                    fetchAvailableEntities();
                    setRelModalOpen(true);
                  }}
                  className="px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold transition-all shadow-md shadow-cyan-950/50 flex items-center gap-1.5"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Correlate Artifact
                </button>
                <button
                  onClick={() => setEditModalOpen(true)}
                  className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold transition-colors flex items-center gap-1.5"
                >
                  <Edit2 className="w-3.5 h-3.5" />
                  Edit
                </button>
                <button
                  onClick={handleDeleteActor}
                  className="p-2 rounded-xl bg-red-950/40 hover:bg-red-900/60 border border-red-500/30 text-red-400 transition-colors"
                  title="Delete Threat Actor"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>

          {/* Dossier Quick Key Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 pt-4 border-t border-slate-800/80 text-center">
            <div className="bg-[#050811] p-2.5 rounded-xl border border-slate-800/70">
              <span className="block text-[9px] font-mono text-slate-500 uppercase">Origin Country</span>
              <span className="text-xs font-bold text-white mt-0.5 truncate block">{actor.origin}</span>
            </div>
            <div className="bg-[#050811] p-2.5 rounded-xl border border-slate-800/70">
              <span className="block text-[9px] font-mono text-slate-500 uppercase">Motivation</span>
              <span className="text-xs font-bold text-amber-400 mt-0.5 truncate block">{actor.motivation}</span>
            </div>
            <div className="bg-[#050811] p-2.5 rounded-xl border border-slate-800/70">
              <span className="block text-[9px] font-mono text-slate-500 uppercase">Active Campaigns</span>
              <span className="text-xs font-black font-mono text-amber-400 mt-0.5">{campaigns.length}</span>
            </div>
            <div className="bg-[#050811] p-2.5 rounded-xl border border-slate-800/70">
              <span className="block text-[9px] font-mono text-slate-500 uppercase">Threat Reports</span>
              <span className="text-xs font-black font-mono text-red-400 mt-0.5">{threats.length}</span>
            </div>
            <div className="bg-[#050811] p-2.5 rounded-xl border border-slate-800/70">
              <span className="block text-[9px] font-mono text-slate-500 uppercase">Weaponized IOCs</span>
              <span className="text-xs font-black font-mono text-cyan-400 mt-0.5">{iocs.length}</span>
            </div>
            <div className="bg-[#050811] p-2.5 rounded-xl border border-slate-800/70">
              <span className="block text-[9px] font-mono text-slate-500 uppercase">MITRE TTPs</span>
              <span className="text-xs font-black font-mono text-indigo-400 mt-0.5">{mitreTechniques.length}</span>
            </div>
            <div className="bg-[#050811] p-2.5 rounded-xl border border-slate-800/70">
              <span className="block text-[9px] font-mono text-slate-500 uppercase">Target Assets</span>
              <span className="text-xs font-black font-mono text-emerald-400 mt-0.5">{correlatedAssets.length}</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Tabbed Intelligence Sections Navigation */}
      <div className="border-b border-slate-800 flex items-center gap-1 overflow-x-auto pb-px">
        {[
          { id: "overview", label: "Executive Overview", icon: Activity, count: null },
          { id: "campaigns", label: "Operations & Campaigns", icon: Flame, count: campaigns.length },
          { id: "threats", label: "Attributed Threats", icon: ShieldAlert, count: threats.length },
          { id: "iocs", label: "Threat Artifacts & IOCs", icon: Database, count: iocs.length },
          { id: "incidents", label: "Security Incidents", icon: Crosshair, count: incidents.length },
          { id: "mitre", label: "MITRE ATT&CK Matrix", icon: Target, count: mitreTechniques.length },
          { id: "assets", label: "Target Assets at Risk", icon: Server, count: correlatedAssets.length },
          { id: "timeline", label: "Chronological Timeline", icon: Clock, count: timeline.length },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`px-4 py-3 text-xs font-bold whitespace-nowrap transition-all border-b-2 flex items-center gap-2 ${
              activeTab === tab.id
                ? "border-red-500 text-red-400 bg-red-950/20"
                : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40"
            }`}
          >
            <tab.icon className="w-3.5 h-3.5" />
            <span>{tab.label}</span>
            {tab.count !== null && (
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-slate-800 text-slate-300">
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab Content Display */}

      {/* TAB 1: EXECUTIVE OVERVIEW */}
      {activeTab === "overview" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            {/* Analyst Tactical Profile */}
            <Card className="bg-[#090F1E] border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <FileText className="w-4 h-4 text-red-400" />
                  Tactical Profile & Operational Methodology
                </CardTitle>
              </CardHeader>
              <CardContent className="p-5 space-y-4 text-xs leading-relaxed text-slate-300">
                <p>{actor.description}</p>
                {actor.notes && (
                  <div className="p-4 bg-[#050811] rounded-xl border border-slate-800 space-y-1">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 font-bold block">
                      Analyst Investigation Notes:
                    </span>
                    <p className="text-slate-300">{actor.notes}</p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Campaign Summary in Overview */}
            <Card className="bg-[#090F1E] border-slate-800">
              <CardHeader>
                <div className="flex items-center justify-between w-full">
                  <CardTitle className="text-white flex items-center gap-2">
                    <Flame className="w-4 h-4 text-amber-400" />
                    Major Attributed Campaigns ({campaigns.length})
                  </CardTitle>
                  <button
                    onClick={() => setActiveTab("campaigns")}
                    className="text-xs text-cyan-400 hover:underline"
                  >
                    View All
                  </button>
                </div>
              </CardHeader>
              <CardContent className="p-5 space-y-3">
                {campaigns.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">No active campaigns currently linked.</p>
                ) : (
                  campaigns.map((c) => (
                    <div
                      key={c.id}
                      className="p-3.5 bg-[#050811] rounded-xl border border-slate-800 hover:border-amber-500/40 transition-colors flex items-center justify-between gap-4"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <Link to={`/campaigns/${c.id}`} className="font-bold text-white hover:text-amber-400 transition-colors text-xs">
                            {c.name}
                          </Link>
                          <span className={`px-2 py-0.2 rounded text-[9px] font-mono uppercase ${
                            c.status === "Active" ? "bg-red-950 text-red-300 border border-red-500/30" : "bg-slate-900 text-slate-400"
                          }`}>
                            {c.status}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 line-clamp-1">{c.description}</p>
                      </div>
                      <Link
                        to={`/campaigns/${c.id}`}
                        className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-amber-600 text-white text-[11px] font-bold transition-colors shrink-0 flex items-center gap-1"
                      >
                        Campaign Details <ChevronRight className="w-3 h-3" />
                      </Link>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>
          </div>

          {/* Sidebar Info & Risk Signals */}
          <div className="space-y-6">
            <Card className="bg-[#090F1E] border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-red-400" />
                  Adversary Intel Attributes
                </CardTitle>
              </CardHeader>
              <CardContent className="p-5 space-y-3.5 text-xs">
                <div className="flex justify-between items-center py-1.5 border-b border-slate-800/80">
                  <span className="text-slate-400">Designation ID</span>
                  <span className="font-mono text-cyan-400 font-bold">{actor.id}</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-slate-800/80">
                  <span className="text-slate-400">Geographic Origin</span>
                  <span className="text-white font-medium">{actor.origin}</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-slate-800/80">
                  <span className="text-slate-400">Primary Motivation</span>
                  <span className="text-amber-300 font-medium">{actor.motivation}</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-slate-800/80">
                  <span className="text-slate-400">Sophistication Level</span>
                  <span className="text-indigo-300 font-bold">{actor.sophistication}</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-slate-800/80">
                  <span className="text-slate-400">Attribution Confidence</span>
                  <span className="text-emerald-400 font-mono font-bold">{actor.confidence}%</span>
                </div>
                <div className="flex justify-between items-center py-1.5">
                  <span className="text-slate-400">First Observed</span>
                  <span className="text-slate-300 font-mono text-[11px]">
                    {actor.firstObserved ? new Date(actor.firstObserved).toLocaleDateString() : "Historical"}
                  </span>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-[#090F1E] border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Target className="w-4 h-4 text-cyan-400" />
                  Top Observed MITRE Tactics
                </CardTitle>
              </CardHeader>
              <CardContent className="p-5 space-y-2">
                {mitreTechniques.slice(0, 5).map((mt) => (
                  <div key={mt.id} className="p-2 bg-[#050811] rounded-lg border border-slate-800 flex items-center justify-between text-xs">
                    <span className="font-mono text-cyan-400 font-bold">{mt.techniqueId}</span>
                    <span className="text-slate-300 truncate max-w-[150px]">{mt.name}</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">{mt.tactic}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </div>
      )}

      {/* TAB 2: CAMPAIGNS */}
      {activeTab === "campaigns" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Attributed Operations & Campaigns ({campaigns.length})
            </h3>
            <Link
              to="/campaigns"
              className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold transition-colors flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" /> Launch New Campaign
            </Link>
          </div>

          {campaigns.length === 0 ? (
            <Card className="bg-[#090F1E] border-slate-800 p-8 text-center text-slate-400 text-xs">
              No operational campaigns linked to this threat actor.
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {campaigns.map((c) => (
                <Card key={c.id} className="bg-[#090F1E] border-slate-800 hover:border-amber-500/50 transition-all">
                  <CardContent className="p-5 space-y-3">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <span className={`px-2 py-0.5 rounded text-[9px] font-mono uppercase font-bold ${
                          c.status === "Active" ? "bg-red-950 text-red-300 border border-red-500/40" : "bg-slate-900 text-slate-400"
                        }`}>
                          ● {c.status}
                        </span>
                        <Link
                          to={`/campaigns/${c.id}`}
                          className="text-base font-bold text-white hover:text-amber-400 transition-colors mt-1 block"
                        >
                          {c.name}
                        </Link>
                      </div>
                      <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-1 rounded border border-slate-800">
                        {c.confidence}% Conf.
                      </span>
                    </div>

                    <p className="text-xs text-slate-400 leading-relaxed line-clamp-2">
                      {c.description}
                    </p>

                    {/* Sectors and Regions */}
                    <div className="space-y-2 pt-2 border-t border-slate-800/80 text-[11px]">
                      {c.targetSectors && c.targetSectors.length > 0 && (
                        <div className="flex flex-wrap items-center gap-1">
                          <span className="text-slate-500 font-mono text-[9px] uppercase">Sectors:</span>
                          {c.targetSectors.map((sec, i) => (
                            <span key={i} className="px-1.5 py-0.2 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-500/30 font-mono text-[10px]">
                              {sec}
                            </span>
                          ))}
                        </div>
                      )}
                      {c.targetRegions && c.targetRegions.length > 0 && (
                        <div className="flex flex-wrap items-center gap-1">
                          <span className="text-slate-500 font-mono text-[9px] uppercase">Regions:</span>
                          {c.targetRegions.map((reg, i) => (
                            <span key={i} className="px-1.5 py-0.2 rounded bg-slate-900 text-slate-300 font-mono text-[10px]">
                              {reg}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>

                    <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between">
                      <span className="text-[10px] font-mono text-slate-500">
                        Observed: {new Date(c.firstObserved).toLocaleDateString()}
                      </span>
                      <Link
                        to={`/campaigns/${c.id}`}
                        className="text-xs font-bold text-amber-400 hover:text-amber-300 flex items-center gap-1"
                      >
                        Campaign Dossier <ChevronRight className="w-3.5 h-3.5" />
                      </Link>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: ATTRIBUTED THREATS */}
      {activeTab === "threats" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Attributed Threat Intelligence Records ({threats.length})
            </h3>
            <button
              onClick={() => {
                fetchAvailableEntities();
                setRelFormData({ ...relFormData, type: "THREAT" });
                setRelModalOpen(true);
              }}
              className="px-3 py-1.5 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-bold transition-colors flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" /> Link Threat
            </button>
          </div>

          <Card className="bg-[#090F1E] border-slate-800 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#0D1527] border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                  <tr>
                    <th className="py-3.5 px-4 font-bold">Severity</th>
                    <th className="py-3.5 px-4 font-bold">Threat Title</th>
                    <th className="py-3.5 px-4 font-bold">Attribution Type</th>
                    <th className="py-3.5 px-4 font-bold">Relationship Confidence</th>
                    <th className="py-3.5 px-4 font-bold">Threat Status</th>
                    <th className="py-3.5 px-4 font-bold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {threats.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-500 italic">
                        No threat records directly attributed.
                      </td>
                    </tr>
                  ) : (
                    threats.map((t) => (
                      <tr key={t.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-3.5 px-4">
                          <SeverityBadge severity={t.severity} />
                        </td>
                        <td className="py-3.5 px-4 font-medium text-white">
                          <Link to={`/threats/${t.id}`} className="hover:text-red-400 transition-colors font-bold block">
                            {t.title}
                          </Link>
                          <span className="text-[10px] text-slate-400 font-mono block">
                            Category: {t.category}
                          </span>
                        </td>
                        <td className="py-3.5 px-4">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-950/70 text-indigo-300 border border-indigo-500/40">
                            {t.attributionType || "Primary Operator"}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 font-mono text-[11px] text-slate-300 uppercase">
                          {t.relationshipConfidence || "confirmed"}
                        </td>
                        <td className="py-3.5 px-4">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-900 text-slate-400 border border-slate-800">
                            {t.status}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <Link
                              to={`/threats/${t.id}`}
                              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold transition-colors"
                            >
                              View Threat
                            </Link>
                            <button
                              onClick={() => handleRemoveRelationship("THREAT", t.id)}
                              className="p-1 rounded text-slate-500 hover:text-red-400 transition-colors"
                              title="Unlink"
                            >
                              <X className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}

      {/* TAB 4: IOCs */}
      {activeTab === "iocs" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Attributed Indicators of Compromise ({iocs.length})
            </h3>
            <button
              onClick={() => {
                fetchAvailableEntities();
                setRelFormData({ ...relFormData, type: "IOC" });
                setRelModalOpen(true);
              }}
              className="px-3 py-1.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold transition-colors flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" /> Link Indicator
            </button>
          </div>

          <Card className="bg-[#090F1E] border-slate-800 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#0D1527] border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                  <tr>
                    <th className="py-3.5 px-4 font-bold">Type</th>
                    <th className="py-3.5 px-4 font-bold">Indicator Value</th>
                    <th className="py-3.5 px-4 font-bold">Confidence</th>
                    <th className="py-3.5 px-4 font-bold">Adversary Context</th>
                    <th className="py-3.5 px-4 font-bold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {iocs.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-slate-500 italic">
                        No weaponized indicators directly attributed.
                      </td>
                    </tr>
                  ) : (
                    iocs.map((ioc) => (
                      <tr key={ioc.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-3.5 px-4">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-500/40 uppercase">
                            {ioc.type}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 font-mono font-bold text-slate-200">
                          {ioc.value}
                        </td>
                        <td className="py-3.5 px-4">
                          <div className="w-24">
                            <ConfidenceMeter confidence={ioc.confidence || 90} />
                          </div>
                        </td>
                        <td className="py-3.5 px-4 text-slate-400">
                          {ioc.context || ioc.actorContext || "Associated Adversary Infrastructure"}
                        </td>
                        <td className="py-3.5 px-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={() => handleInvestigateIoc(ioc.value)}
                              className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 text-xs font-bold transition-colors flex items-center gap-1"
                            >
                              <Search className="w-3 h-3" />
                              Investigate
                            </button>
                            <button
                              onClick={() => handleRemoveRelationship("IOC", ioc.id)}
                              className="p-1 rounded text-slate-500 hover:text-red-400 transition-colors"
                              title="Unlink"
                            >
                              <X className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}

      {/* TAB 5: INCIDENTS */}
      {activeTab === "incidents" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Attributed Security Incidents ({incidents.length})
            </h3>
            <button
              onClick={() => {
                fetchAvailableEntities();
                setRelFormData({ ...relFormData, type: "INCIDENT" });
                setRelModalOpen(true);
              }}
              className="px-3 py-1.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold transition-colors flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" /> Link Incident
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {incidents.length === 0 ? (
              <Card className="bg-[#090F1E] border-slate-800 p-8 text-center text-slate-400 text-xs col-span-2">
                No active security incidents attributed to this threat actor.
              </Card>
            ) : (
              incidents.map((inc) => (
                <Card key={inc.id} className="bg-[#090F1E] border-slate-800">
                  <CardContent className="p-5 space-y-3">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <SeverityBadge severity={inc.severity} />
                        <h4 className="text-sm font-bold text-white mt-1.5">{inc.title}</h4>
                      </div>
                      <span className="text-[10px] font-mono text-slate-400">
                        {new Date(inc.date).toLocaleDateString()}
                      </span>
                    </div>

                    <p className="text-xs text-slate-400 leading-relaxed">{inc.impact}</p>

                    <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[11px]">
                      <span className="text-slate-400 font-mono">
                        Target: <strong className="text-white">{inc.affectedEntity}</strong>
                      </span>
                      <button
                        onClick={() => handleRemoveRelationship("INCIDENT", inc.id)}
                        className="text-slate-500 hover:text-red-400 text-xs font-bold"
                      >
                        Unlink
                      </button>
                    </div>
                  </CardContent>
                </Card>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 6: MITRE ATT&CK TECHNIQUES */}
      {activeTab === "mitre" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Mapped MITRE ATT&CK Matrix Tactics & Techniques ({mitreTechniques.length})
            </h3>
          </div>

          <Card className="bg-[#090F1E] border-slate-800 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#0D1527] border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                  <tr>
                    <th className="py-3.5 px-4 font-bold">Technique ID</th>
                    <th className="py-3.5 px-4 font-bold">Technique Name</th>
                    <th className="py-3.5 px-4 font-bold">Tactic Stage</th>
                    <th className="py-3.5 px-4 font-bold">Description & Scope</th>
                    <th className="py-3.5 px-4 font-bold text-right">Reference</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {mitreTechniques.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-slate-500 italic">
                        No MITRE ATT&CK techniques mapped for this actor.
                      </td>
                    </tr>
                  ) : (
                    mitreTechniques.map((mt) => (
                      <tr key={mt.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-3.5 px-4 font-mono font-bold text-cyan-400">
                          {mt.techniqueId}
                        </td>
                        <td className="py-3.5 px-4 font-bold text-white">
                          {mt.name}
                        </td>
                        <td className="py-3.5 px-4">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-900 text-slate-300 border border-slate-800">
                            {mt.tactic}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 text-slate-400 max-w-md truncate">
                          {mt.description}
                        </td>
                        <td className="py-3.5 px-4 text-right">
                          <a
                            href={mt.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-mono font-bold transition-colors inline-flex items-center gap-1"
                          >
                            MITRE Matrix <ExternalLink className="w-3 h-3" />
                          </a>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}

      {/* TAB 7: TARGET ASSETS AT RISK */}
      {activeTab === "assets" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Correlated Organization Assets in Targeting Range ({correlatedAssets.length})
            </h3>
            <Link
              to="/assets"
              className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold transition-colors flex items-center gap-1.5"
            >
              <Server className="w-3.5 h-3.5" /> Full Asset Inventory
            </Link>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {correlatedAssets.length === 0 ? (
              <Card className="bg-[#090F1E] border-slate-800 p-8 text-center text-slate-400 text-xs col-span-3">
                No high-criticality assets identified in immediate targeting range.
              </Card>
            ) : (
              correlatedAssets.map((asset) => (
                <Card key={asset.id} className="bg-[#090F1E] border-slate-800">
                  <CardContent className="p-4 space-y-2.5">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <span className="text-[10px] font-mono text-slate-500 uppercase">{asset.type}</span>
                        <h4 className="text-sm font-bold text-white">{asset.name}</h4>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                        asset.criticality === "CRITICAL"
                          ? "bg-red-950 text-red-300 border border-red-500/40"
                          : "bg-orange-950 text-orange-300 border border-orange-500/40"
                      }`}>
                        {asset.criticality}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-[11px] font-mono pt-2 border-t border-slate-800/80">
                      <div>
                        <span className="text-slate-500 block text-[9px]">IP / FQDN</span>
                        <span className="text-slate-300">{asset.ipAddress || asset.fqdn || "Internal"}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[9px]">Exposure</span>
                        <span className="text-cyan-400">{asset.exposure}</span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 8: CHRONOLOGICAL ACTIVITY TIMELINE */}
      {activeTab === "timeline" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Chronological Adversary Sightings & Operational History ({timeline.length})
            </h3>
          </div>

          <Card className="bg-[#090F1E] border-slate-800 p-6">
            <div className="space-y-6 relative before:absolute before:left-4 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
              {timeline.length === 0 ? (
                <p className="text-xs text-slate-500 italic">No timeline entries available.</p>
              ) : (
                timeline.map((item, idx) => (
                  <div key={idx} className="flex items-start gap-4 relative pl-8">
                    <div className={`w-8 h-8 rounded-full border flex items-center justify-center absolute -left-0 top-0 shadow-lg ${
                      item.type === "INCIDENT"
                        ? "bg-red-950 border-red-500/50 text-red-400"
                        : item.type === "CAMPAIGN"
                        ? "bg-amber-950 border-amber-500/50 text-amber-400"
                        : "bg-cyan-950 border-cyan-500/50 text-cyan-400"
                    }`}>
                      {item.type === "INCIDENT" ? <Crosshair className="w-3.5 h-3.5" /> : item.type === "CAMPAIGN" ? <Flame className="w-3.5 h-3.5" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                    </div>

                    <div className="p-4 rounded-xl bg-[#050811] border border-slate-800/80 flex-1 space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-bold text-white text-xs">{item.title}</span>
                        <span className="text-[10px] font-mono text-slate-400">
                          {new Date(item.date).toLocaleDateString()}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400">{item.description}</p>
                    </div>
                  </div>
                ))
              )}
            </div>
          </Card>
        </div>
      )}

      {/* Correlate Relationship Modal */}
      <Modal
        isOpen={relModalOpen}
        onClose={() => setRelModalOpen(false)}
        title={`Correlate Artifact with ${actor.name}`}
        maxWidth="max-w-xl"
      >
        <form onSubmit={handleAddRelationship} className="space-y-4 text-xs">
          {relError && (
            <div className="p-3 bg-red-950/80 border border-red-500/50 rounded-xl text-red-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{relError}</span>
            </div>
          )}

          <div>
            <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
              Select Entity Type to Correlate
            </label>
            <select
              value={relFormData.type}
              onChange={(e) => setRelFormData({ ...relFormData, type: e.target.value, targetId: "" })}
              className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="THREAT">Threat Intelligence Record</option>
              <option value="IOC">Indicator of Compromise (IOC)</option>
              <option value="INCIDENT">Security Incident</option>
              <option value="CAMPAIGN">Operational Campaign</option>
            </select>
          </div>

          <div>
            <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
              Select Target Item *
            </label>
            <select
              required
              value={relFormData.targetId}
              onChange={(e) => setRelFormData({ ...relFormData, targetId: e.target.value })}
              className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">-- Choose target entity from database --</option>
              {relFormData.type === "THREAT" && availableThreats.map((t) => (
                <option key={t.id} value={t.id}>{t.title} ({t.severity})</option>
              ))}
              {relFormData.type === "IOC" && availableIocs.map((i) => (
                <option key={i.id} value={i.id}>{i.type}: {i.value}</option>
              ))}
              {relFormData.type === "INCIDENT" && availableIncidents.map((inc) => (
                <option key={inc.id} value={inc.id}>{inc.title} - {inc.affectedEntity}</option>
              ))}
              {relFormData.type === "CAMPAIGN" && availableCampaigns.map((c) => (
                <option key={c.id} value={c.id}>{c.name} ({c.status})</option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Attribution Type / Role
              </label>
              <input
                type="text"
                placeholder="e.g. Primary Operator, Infrastructure Provider"
                value={relFormData.attributionType}
                onChange={(e) => setRelFormData({ ...relFormData, attributionType: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Attribution Confidence
              </label>
              <select
                value={relFormData.confidence}
                onChange={(e) => setRelFormData({ ...relFormData, confidence: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="confirmed">Confirmed (90%+)</option>
                <option value="high">High Probability (75-89%)</option>
                <option value="suspected">Suspected / Moderate (50-74%)</option>
                <option value="low">Low Confidence (&lt;50%)</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
              Relationship Context & Evidence
            </label>
            <input
              type="text"
              placeholder="e.g. Shared C2 staging server, certificate fingerprint overlap"
              value={relFormData.context}
              onChange={(e) => setRelFormData({ ...relFormData, context: e.target.value })}
              className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="pt-4 border-t border-slate-800 flex justify-end gap-3">
            <button
              type="button"
              onClick={() => setRelModalOpen(false)}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={addingRel}
              className="px-5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold transition-all shadow-md shadow-cyan-950/50 flex items-center gap-2"
            >
              {addingRel ? "Linking..." : "Establish Link"}
            </button>
          </div>
        </form>
      </Modal>

      {/* Edit Threat Actor Modal */}
      <Modal
        isOpen={editModalOpen}
        onClose={() => setEditModalOpen(false)}
        title={`Edit Threat Actor: ${actor.name}`}
        maxWidth="max-w-2xl"
      >
        <form onSubmit={handleUpdateActor} className="space-y-4 text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Adversary Name / Designation *
              </label>
              <input
                type="text"
                required
                value={editFormData.name}
                onChange={(e) => setEditFormData({ ...editFormData, name: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-red-500"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Known Aliases (comma separated)
              </label>
              <input
                type="text"
                value={editFormData.aliases}
                onChange={(e) => setEditFormData({ ...editFormData, aliases: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-red-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
              Adversary Description & Profile *
            </label>
            <textarea
              required
              rows={4}
              value={editFormData.description}
              onChange={(e) => setEditFormData({ ...editFormData, description: e.target.value })}
              className="w-full bg-[#050811] border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-red-500"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Origin / Affiliation
              </label>
              <input
                type="text"
                value={editFormData.origin}
                onChange={(e) => setEditFormData({ ...editFormData, origin: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-red-500"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Strategic Motivation
              </label>
              <input
                type="text"
                value={editFormData.motivation}
                onChange={(e) => setEditFormData({ ...editFormData, motivation: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-red-500"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Sophistication
              </label>
              <select
                value={editFormData.sophistication}
                onChange={(e) => setEditFormData({ ...editFormData, sophistication: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-red-500"
              >
                <option value="Advanced">Advanced (Tier 1)</option>
                <option value="High">High (Syndicate)</option>
                <option value="Medium">Medium (Tool User)</option>
                <option value="Low">Low (Commodity)</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Attribution Confidence ({editFormData.confidence}%)
              </label>
              <input
                type="range"
                min={10}
                max={100}
                value={editFormData.confidence}
                onChange={(e) => setEditFormData({ ...editFormData, confidence: parseInt(e.target.value, 10) })}
                className="w-full accent-red-500"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Operational Status
              </label>
              <select
                value={editFormData.status}
                onChange={(e) => setEditFormData({ ...editFormData, status: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-red-500"
              >
                <option value="Active">Active Operations</option>
                <option value="Monitored">Monitored / High Alert</option>
                <option value="Dormant">Dormant</option>
                <option value="Disrupted">Disrupted</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
              Analyst Notes
            </label>
            <input
              type="text"
              value={editFormData.notes}
              onChange={(e) => setEditFormData({ ...editFormData, notes: e.target.value })}
              className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-red-500"
            />
          </div>

          <div className="pt-4 border-t border-slate-800 flex justify-end gap-3">
            <button
              type="button"
              onClick={() => setEditModalOpen(false)}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={updating}
              className="px-5 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-bold transition-all shadow-md shadow-red-950/50 flex items-center gap-2"
            >
              {updating ? "Saving Changes..." : "Save Dossier"}
            </button>
          </div>
        </form>
      </Modal>

      {/* Deep IOC Investigation Modal */}
      {isInvestigating && (
        <IocInvestigationModal
          isOpen={isInvestigating}
          onClose={() => {
            setIsInvestigating(false);
            setInvestigationDossier(null);
          }}
          dossier={investigationDossier}
        />
      )}
    </div>
  );
}

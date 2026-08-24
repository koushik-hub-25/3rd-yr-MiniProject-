import React, { useState, useEffect } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import {
  Flame,
  ArrowLeft,
  Skull,
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
  Target,
  ShieldCheck,
  TrendingUp
} from "lucide-react";
import { CampaignDossier, Campaign } from "../types";
import { Card, CardContent, CardHeader, CardTitle, Badge, SeverityBadge, ConfidenceMeter, Modal } from "../components/ui";
import IocInvestigationModal from "../components/IocInvestigationModal";

export default function CampaignDetails() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [dossier, setDossier] = useState<CampaignDossier | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<"overview" | "threats" | "iocs" | "incidents" | "mitre" | "assets" | "timeline">("overview");

  // Edit Modal State
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [editFormData, setEditFormData] = useState({
    name: "",
    description: "",
    threatActorId: "",
    targetSectors: "",
    targetRegions: "",
    objectives: "",
    status: "Active",
    confidence: 90,
    notes: ""
  });

  // Relationship Modal State
  const [relModalOpen, setRelModalOpen] = useState(false);
  const [addingRel, setAddingRel] = useState(false);
  const [relFormData, setRelFormData] = useState({
    type: "THREAT",
    targetId: "",
    confidence: "confirmed",
    techniqueName: "",
    tactic: "Execution"
  });
  const [relError, setRelError] = useState("");

  // Selectable options
  const [availableThreats, setAvailableThreats] = useState<any[]>([]);
  const [availableIocs, setAvailableIocs] = useState<any[]>([]);
  const [availableIncidents, setAvailableIncidents] = useState<any[]>([]);
  const [availableThreatActors, setAvailableThreatActors] = useState<any[]>([]);

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
      const res = await fetch(`/api/campaigns/${id}`);
      if (!res.ok) {
        if (res.status === 404) throw new Error("Campaign record not found.");
        throw new Error("Failed to fetch Campaign dossier.");
      }
      const data: CampaignDossier = await res.json();
      setDossier(data);
      setEditFormData({
        name: data.campaign.name,
        description: data.campaign.description,
        threatActorId: data.campaign.threatActorId || "",
        targetSectors: Array.isArray(data.campaign.targetSectors)
          ? data.campaign.targetSectors.join(", ")
          : typeof data.campaign.targetSectors === "string"
          ? data.campaign.targetSectors
          : "",
        targetRegions: Array.isArray(data.campaign.targetRegions)
          ? data.campaign.targetRegions.join(", ")
          : typeof data.campaign.targetRegions === "string"
          ? data.campaign.targetRegions
          : "",
        objectives: data.campaign.objectives || "",
        status: data.campaign.status,
        confidence: data.campaign.confidence,
        notes: data.campaign.notes || ""
      });
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchAvailableEntities = async () => {
    try {
      const [tRes, iRes, incRes, taRes] = await Promise.all([
        fetch("/api/threats"),
        fetch("/api/iocs"),
        fetch("/api/incidents"),
        fetch("/api/threat-actors")
      ]);
      if (tRes.ok) setAvailableThreats(await tRes.json());
      if (iRes.ok) setAvailableIocs(await iRes.json());
      if (incRes.ok) setAvailableIncidents(await incRes.json());
      if (taRes.ok) setAvailableThreatActors(await taRes.json());
    } catch (e) {
      console.warn("Could not fetch entities for relationship linking:", e);
    }
  };

  useEffect(() => {
    fetchDossier();
  }, [id]);

  const handleUpdateCampaign = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!id) return;

    try {
      setUpdating(true);
      const res = await fetch(`/api/campaigns/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: editFormData.name,
          description: editFormData.description,
          threatActorId: editFormData.threatActorId || null,
          targetSectors: editFormData.targetSectors.split(",").map((s) => s.trim()).filter(Boolean),
          targetRegions: editFormData.targetRegions.split(",").map((s) => s.trim()).filter(Boolean),
          objectives: editFormData.objectives,
          status: editFormData.status,
          confidence: Number(editFormData.confidence),
          notes: editFormData.notes
        })
      });

      if (!res.ok) throw new Error("Failed to update Campaign profile.");
      const updated = await res.json();
      setDossier(updated);
      setEditModalOpen(false);
    } catch (err: any) {
      alert("Update failed: " + err.message);
    } finally {
      setUpdating(false);
    }
  };

  const handleDeleteCampaign = async () => {
    if (!id || !dossier) return;
    const confirmDelete = window.confirm(`Are you sure you want to delete campaign "${dossier.campaign.name}"?`);
    if (!confirmDelete) return;

    try {
      const res = await fetch(`/api/campaigns/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to delete Campaign.");
      navigate("/campaigns");
    } catch (err: any) {
      alert("Deletion failed: " + err.message);
    }
  };

  const handleAddRelationship = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!id) return;
    setRelError("");

    if (!relFormData.targetId) {
      setRelError("Please select a target entity or specify technique ID.");
      return;
    }

    try {
      setAddingRel(true);
      const res = await fetch(`/api/campaigns/${id}/relationships`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: relFormData.type,
          targetId: relFormData.targetId,
          confidence: relFormData.confidence,
          techniqueName: relFormData.techniqueName,
          tactic: relFormData.tactic
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
        techniqueName: "",
        tactic: "Execution"
      });
    } catch (err: any) {
      setRelError(err.message);
    } finally {
      setAddingRel(false);
    }
  };

  const handleRemoveRelationship = async (type: string, targetId: string) => {
    if (!id) return;
    const confirmRemove = window.confirm(`Remove correlation with ${type} artifact ${targetId}?`);
    if (!confirmRemove) return;

    try {
      const res = await fetch(`/api/campaigns/${id}/relationships`, {
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
        <div className="w-12 h-12 border-2 border-amber-500 border-t-transparent rounded-full animate-spin mx-auto" />
        <p className="text-xs font-mono uppercase tracking-wider text-slate-400">Compiling Multi-Stage Campaign Dossier & Risk Signals...</p>
      </div>
    );
  }

  if (error || !dossier) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-16 text-center space-y-4">
        <AlertTriangle className="w-12 h-12 text-red-500 mx-auto" />
        <h2 className="text-lg font-bold text-white">Campaign Record Not Found</h2>
        <p className="text-xs text-slate-400">{error || "The requested campaign does not exist."}</p>
        <Link
          to="/campaigns"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Campaigns
        </Link>
      </div>
    );
  }

  const { campaign, threatActor, threats, iocs, incidents, mitreTechniques, correlatedAssets, timeline, riskSummary } = dossier;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6 animate-in fade-in duration-300">
      {/* Navigation Breadcrumbs */}
      <div className="flex items-center justify-between text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <Link to="/threat-intelligence" className="hover:text-cyan-400 transition-colors">Intelligence</Link>
          <span>/</span>
          <Link to="/campaigns" className="hover:text-amber-400 transition-colors">Campaigns</Link>
          <span>/</span>
          <span className="text-slate-200 font-bold">{campaign.name}</span>
        </div>

        <Link
          to="/campaigns"
          className="inline-flex items-center gap-1.5 text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to List
        </Link>
      </div>

      {/* Executive Campaign Dossier Header */}
      <Card className="bg-[#090F1E] border-slate-800">
        <CardContent className="p-6 space-y-6">
          <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6">
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/90 text-amber-300 border border-amber-500/50 uppercase tracking-widest flex items-center gap-1.5">
                  <Flame className="w-3.5 h-3.5 text-amber-400" />
                  CAMPAIGN DOSSIER
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                    campaign.status === "Active"
                      ? "bg-red-950 text-red-300 border border-red-500/40"
                      : "bg-slate-900 text-slate-400 border border-slate-800"
                  }`}
                >
                  ● {campaign.status}
                </span>
                {threatActor && (
                  <Link
                    to={`/threat-actors/${threatActor.id}`}
                    className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-950/70 text-red-300 border border-red-500/40 uppercase hover:bg-red-900 transition-colors flex items-center gap-1"
                  >
                    <Skull className="w-3 h-3 text-red-400" />
                    ACTOR: {threatActor.name} ({threatActor.origin})
                  </Link>
                )}
              </div>

              <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight flex items-center gap-3">
                {campaign.name}
              </h1>

              <p className="text-xs sm:text-sm text-slate-300 leading-relaxed max-w-4xl pt-1">
                {campaign.description}
              </p>
            </div>

            {/* Right Action Bar */}
            <div className="flex flex-col items-start lg:items-end gap-4 shrink-0">
              <div className="bg-[#050811] p-3.5 rounded-2xl border border-slate-800 space-y-2 w-full sm:w-64">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-400">Campaign Confidence</span>
                  <span className="text-white font-bold">{campaign.confidence}%</span>
                </div>
                <ConfidenceMeter confidence={campaign.confidence} />
                <p className="text-[10px] text-slate-500">Cross-verified telemetry & MITRE overlap</p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => {
                    fetchAvailableEntities();
                    setRelModalOpen(true);
                  }}
                  className="px-3.5 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold transition-all shadow-md shadow-amber-950/50 flex items-center gap-1.5"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Correlate Artifact
                </button>
                <button
                  onClick={() => {
                    fetchAvailableEntities();
                    setEditModalOpen(true);
                  }}
                  className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold transition-colors flex items-center gap-1.5"
                >
                  <Edit2 className="w-3.5 h-3.5" />
                  Edit
                </button>
                <button
                  onClick={handleDeleteCampaign}
                  className="p-2 rounded-xl bg-red-950/40 hover:bg-red-900/60 border border-red-500/30 text-red-400 transition-colors"
                  title="Delete Campaign"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>

          {/* Key Metrics Row */}
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 pt-4 border-t border-slate-800/80 text-center">
            <div className="bg-[#050811] p-2.5 rounded-xl border border-slate-800/70">
              <span className="block text-[9px] font-mono text-slate-500 uppercase">Operational State</span>
              <span className="text-xs font-bold text-amber-400 mt-0.5 truncate block">{campaign.status}</span>
            </div>
            <div className="bg-[#050811] p-2.5 rounded-xl border border-slate-800/70">
              <span className="block text-[9px] font-mono text-slate-500 uppercase">Weaponized Threats</span>
              <span className="text-xs font-black font-mono text-red-400 mt-0.5">{threats.length}</span>
            </div>
            <div className="bg-[#050811] p-2.5 rounded-xl border border-slate-800/70">
              <span className="block text-[9px] font-mono text-slate-500 uppercase">Weaponized IOCs</span>
              <span className="text-xs font-black font-mono text-cyan-400 mt-0.5">{iocs.length}</span>
            </div>
            <div className="bg-[#050811] p-2.5 rounded-xl border border-slate-800/70">
              <span className="block text-[9px] font-mono text-slate-500 uppercase">Target Incidents</span>
              <span className="text-xs font-black font-mono text-indigo-400 mt-0.5">{incidents.length}</span>
            </div>
            <div className="bg-[#050811] p-2.5 rounded-xl border border-slate-800/70">
              <span className="block text-[9px] font-mono text-slate-500 uppercase">Observed TTPs</span>
              <span className="text-xs font-black font-mono text-amber-400 mt-0.5">{mitreTechniques.length}</span>
            </div>
            <div className="bg-[#050811] p-2.5 rounded-xl border border-slate-800/70">
              <span className="block text-[9px] font-mono text-slate-500 uppercase">At-Risk Assets</span>
              <span className="text-xs font-black font-mono text-emerald-400 mt-0.5">{correlatedAssets.length}</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* FEATURE 2 RISK ENGINE INTEGRATION: EXPLAINABLE CAMPAIGN RISK SUMMARY */}
      {riskSummary && (
        <Card className="bg-gradient-to-r from-[#090F1E] via-[#0E172E] to-[#090F1E] border border-red-500/30 shadow-xl shadow-black/40">
          <CardContent className="p-5 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-xl bg-red-950/70 border border-red-500/50 flex items-center justify-center font-mono font-black text-xl text-red-400 shadow-lg shadow-red-950/50">
                  {riskSummary.highestScore}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                      Deterministic Campaign Risk Evaluation
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-950 text-red-400 border border-red-500/40">
                      {riskSummary.riskLevel} SEVERITY
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Evaluated by ShieldZen Explainable Risk Scoring Engine across {riskSummary.threatCount} linked threats and {correlatedAssets.length} target assets.
                  </p>
                </div>
              </div>

              <Link
                to="/risk-engine"
                className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-bold transition-colors inline-flex items-center gap-1.5 shrink-0"
              >
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                Open Risk Engine Studio
              </Link>
            </div>

            {/* Risk Factor Breakdown Badges */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-800/80 text-xs">
              <div className="bg-[#050811] p-2 rounded-lg border border-slate-800/60">
                <span className="text-[9px] font-mono text-slate-500 uppercase block">Average Threat Risk</span>
                <span className="text-white font-bold font-mono text-xs">{riskSummary.averageScore}/100</span>
              </div>
              <div className="bg-[#050811] p-2 rounded-lg border border-slate-800/60">
                <span className="text-[9px] font-mono text-slate-500 uppercase block">Dominant Vector</span>
                <span className="text-amber-400 font-medium truncate block">{riskSummary.dominantVector}</span>
              </div>
              <div className="bg-[#050811] p-2 rounded-lg border border-slate-800/60">
                <span className="text-[9px] font-mono text-slate-500 uppercase block">Assigned Threat Actor</span>
                <span className="text-red-400 font-bold truncate block">{threatActor?.name || "Unattributed APT"}</span>
              </div>
              <div className="bg-[#050811] p-2 rounded-lg border border-slate-800/60">
                <span className="text-[9px] font-mono text-slate-500 uppercase block">Asset Exposure Blast</span>
                <span className="text-emerald-400 font-bold font-mono text-xs">{correlatedAssets.length} Endpoints</span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tabbed Intelligence Navigation */}
      <div className="border-b border-slate-800 flex items-center gap-1 overflow-x-auto pb-px">
        {[
          { id: "overview", label: "Strategic Overview", icon: Activity, count: null },
          { id: "threats", label: "Weaponized Threats", icon: ShieldAlert, count: threats.length },
          { id: "iocs", label: "Threat Artifacts & IOCs", icon: Database, count: iocs.length },
          { id: "incidents", label: "Security Incidents", icon: Crosshair, count: incidents.length },
          { id: "mitre", label: "MITRE ATT&CK Matrix", icon: Target, count: mitreTechniques.length },
          { id: "assets", label: "Correlated Target Assets", icon: Server, count: correlatedAssets.length },
          { id: "timeline", label: "Campaign Timeline", icon: Clock, count: timeline.length },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`px-4 py-3 text-xs font-bold whitespace-nowrap transition-all border-b-2 flex items-center gap-2 ${
              activeTab === tab.id
                ? "border-amber-500 text-amber-400 bg-amber-950/20"
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

      {/* TAB 1: STRATEGIC OVERVIEW */}
      {activeTab === "overview" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            {/* Operational Objectives & Vectors */}
            <Card className="bg-[#090F1E] border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Target className="w-4 h-4 text-amber-400" />
                  Strategic Objectives & Mission Scope
                </CardTitle>
              </CardHeader>
              <CardContent className="p-5 space-y-4 text-xs leading-relaxed text-slate-300">
                <div>
                  <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 font-bold block mb-1">
                    Primary Offensive Objectives:
                  </span>
                  <p className="text-white font-medium bg-[#050811] p-3 rounded-xl border border-slate-800">
                    {campaign.objectives || "Pre-positioning in critical infrastructure networks, intellectual property theft, lateral movement, and data extortion."}
                  </p>
                </div>

                <div>
                  <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 font-bold block mb-1">
                    Detailed Methodology:
                  </span>
                  <p className="text-slate-300">{campaign.description}</p>
                </div>

                {campaign.notes && (
                  <div className="p-4 bg-[#050811] rounded-xl border border-slate-800 space-y-1">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-amber-400 font-bold block">
                      Analyst Operational Notes:
                    </span>
                    <p className="text-slate-300">{campaign.notes}</p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Target Sectors & Theaters */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card className="bg-[#090F1E] border-slate-800">
                <CardHeader>
                  <CardTitle className="text-white text-xs">Targeted Critical Sectors</CardTitle>
                </CardHeader>
                <CardContent className="p-4 space-y-2">
                  {campaign.targetSectors && campaign.targetSectors.length > 0 ? (
                    campaign.targetSectors.map((sector, i) => (
                      <div key={i} className="p-2 bg-[#050811] rounded-lg border border-slate-800 flex items-center gap-2 text-xs font-mono text-cyan-300">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                        <span>{sector}</span>
                      </div>
                    ))
                  ) : (
                    <p className="text-xs text-slate-500 italic">Sector targeting broad or unspecified.</p>
                  )}
                </CardContent>
              </Card>

              <Card className="bg-[#090F1E] border-slate-800">
                <CardHeader>
                  <CardTitle className="text-white text-xs">Target Geographic Theaters</CardTitle>
                </CardHeader>
                <CardContent className="p-4 space-y-2">
                  {campaign.targetRegions && campaign.targetRegions.length > 0 ? (
                    campaign.targetRegions.map((region, i) => (
                      <div key={i} className="p-2 bg-[#050811] rounded-lg border border-slate-800 flex items-center gap-2 text-xs font-mono text-amber-300">
                        <Globe className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                        <span>{region}</span>
                      </div>
                    ))
                  ) : (
                    <p className="text-xs text-slate-500 italic">Regional focus global.</p>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>

          {/* Attributed Threat Actor Sidebar Profile */}
          <div className="space-y-6">
            {threatActor ? (
              <Card className="bg-[#090F1E] border-slate-800 border-t-2 border-t-red-500">
                <CardHeader>
                  <CardTitle className="text-white flex items-center gap-2">
                    <Skull className="w-4 h-4 text-red-400" />
                    Attributed Adversary Profile
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-5 space-y-3.5 text-xs">
                  <div>
                    <span className="text-[10px] font-mono text-slate-500 uppercase">Operator Designation</span>
                    <Link
                      to={`/threat-actors/${threatActor.id}`}
                      className="text-base font-bold text-white hover:text-red-400 transition-colors block mt-0.5"
                    >
                      {threatActor.name}
                    </Link>
                  </div>

                  <div className="flex justify-between items-center py-1.5 border-b border-slate-800/80">
                    <span className="text-slate-400">Origin / Affiliation</span>
                    <span className="font-bold text-white font-mono">{threatActor.origin}</span>
                  </div>

                  <div className="flex justify-between items-center py-1.5 border-b border-slate-800/80">
                    <span className="text-slate-400">Strategic Motivation</span>
                    <span className="text-amber-300">{threatActor.motivation}</span>
                  </div>

                  <div className="flex justify-between items-center py-1.5 border-b border-slate-800/80">
                    <span className="text-slate-400">Sophistication Tier</span>
                    <span className="text-indigo-300 font-bold">{threatActor.sophistication}</span>
                  </div>

                  <div className="flex justify-between items-center py-1.5">
                    <span className="text-slate-400">Actor Attribution</span>
                    <span className="text-emerald-400 font-mono font-bold">{threatActor.confidence}%</span>
                  </div>

                  <Link
                    to={`/threat-actors/${threatActor.id}`}
                    className="w-full py-2 px-3 rounded-xl bg-slate-800 hover:bg-red-950/60 hover:text-red-300 border border-slate-700/70 text-slate-200 text-xs font-bold transition-all flex items-center justify-center gap-1.5 mt-2"
                  >
                    Open Adversary Dossier <ChevronRight className="w-3.5 h-3.5" />
                  </Link>
                </CardContent>
              </Card>
            ) : (
              <Card className="bg-[#090F1E] border-slate-800 p-5 text-center space-y-3">
                <Skull className="w-8 h-8 text-slate-600 mx-auto" />
                <div>
                  <h4 className="text-xs font-bold text-white">Unattributed Campaign</h4>
                  <p className="text-[11px] text-slate-400 mt-1">No adversary profile explicitly bound to this campaign yet.</p>
                </div>
                <button
                  onClick={() => {
                    fetchAvailableEntities();
                    setEditModalOpen(true);
                  }}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold"
                >
                  Assign Threat Actor
                </button>
              </Card>
            )}

            <Card className="bg-[#090F1E] border-slate-800">
              <CardHeader>
                <CardTitle className="text-white text-xs">Observed Intelligence Window</CardTitle>
              </CardHeader>
              <CardContent className="p-4 space-y-2 text-xs">
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">First Sighting</span>
                  <span className="text-white font-mono">{new Date(campaign.firstObserved).toLocaleDateString()}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Latest Sighting</span>
                  <span className="text-amber-400 font-mono font-bold">{new Date(campaign.lastObserved).toLocaleDateString()}</span>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      )}

      {/* TAB 2: WEAPONIZED THREATS */}
      {activeTab === "threats" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Weaponized Threat Intelligence Records ({threats.length})
            </h3>
            <button
              onClick={() => {
                fetchAvailableEntities();
                setRelFormData({ ...relFormData, type: "THREAT" });
                setRelModalOpen(true);
              }}
              className="px-3 py-1.5 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold transition-colors flex items-center gap-1.5"
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
                    <th className="py-3.5 px-4 font-bold">Category</th>
                    <th className="py-3.5 px-4 font-bold">Confidence</th>
                    <th className="py-3.5 px-4 font-bold">Status</th>
                    <th className="py-3.5 px-4 font-bold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {threats.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-500 italic">
                        No threat records associated with this campaign.
                      </td>
                    </tr>
                  ) : (
                    threats.map((t) => (
                      <tr key={t.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-3.5 px-4">
                          <SeverityBadge severity={t.severity} />
                        </td>
                        <td className="py-3.5 px-4 font-medium text-white">
                          <Link to={`/threats/${t.id}`} className="hover:text-amber-400 transition-colors font-bold block">
                            {t.title}
                          </Link>
                          {t.cveId && (
                            <span className="text-[10px] text-cyan-400 font-mono block">
                              CVE: {t.cveId}
                            </span>
                          )}
                        </td>
                        <td className="py-3.5 px-4 text-slate-300 font-mono text-[11px]">{t.category}</td>
                        <td className="py-3.5 px-4 font-mono text-emerald-400 font-bold">{t.confidence}%</td>
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

      {/* TAB 3: IOCs */}
      {activeTab === "iocs" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Campaign Indicators of Compromise ({iocs.length})
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
                    <th className="py-3.5 px-4 font-bold">Indicator Artifact Value</th>
                    <th className="py-3.5 px-4 font-bold">Confidence</th>
                    <th className="py-3.5 px-4 font-bold">Operational Context</th>
                    <th className="py-3.5 px-4 font-bold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {iocs.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-slate-500 italic">
                        No weaponized indicators linked to this campaign.
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
                        <td className="py-3.5 px-4 font-mono text-emerald-400 font-bold">
                          {ioc.confidence || 90}%
                        </td>
                        <td className="py-3.5 px-4 text-slate-400">
                          {ioc.context || "Associated Campaign Staging Infrastructure"}
                        </td>
                        <td className="py-3.5 px-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={() => handleInvestigateIoc(ioc.value)}
                              className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 text-xs font-bold transition-colors flex items-center gap-1"
                            >
                              <Search className="w-3 h-3" /> Investigate
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

      {/* TAB 4: INCIDENTS */}
      {activeTab === "incidents" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Campaign Security Incidents ({incidents.length})
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
                No active security incidents associated with this campaign.
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
                        Target System: <strong className="text-white">{inc.affectedEntity}</strong>
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

      {/* TAB 5: MITRE ATT&CK TECHNIQUES */}
      {activeTab === "mitre" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Campaign MITRE ATT&CK Tactics & Techniques ({mitreTechniques.length})
            </h3>
            <button
              onClick={() => {
                setRelFormData({ ...relFormData, type: "TECHNIQUE", targetId: "T1059.001", techniqueName: "PowerShell", tactic: "Execution" });
                setRelModalOpen(true);
              }}
              className="px-3 py-1.5 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold transition-colors flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" /> Link MITRE Technique
            </button>
          </div>

          <Card className="bg-[#090F1E] border-slate-800 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#0D1527] border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                  <tr>
                    <th className="py-3.5 px-4 font-bold">Technique ID</th>
                    <th className="py-3.5 px-4 font-bold">Technique Name</th>
                    <th className="py-3.5 px-4 font-bold">Tactic Stage</th>
                    <th className="py-3.5 px-4 font-bold">Attribution Confidence</th>
                    <th className="py-3.5 px-4 font-bold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {mitreTechniques.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-slate-500 italic">
                        No MITRE techniques linked.
                      </td>
                    </tr>
                  ) : (
                    mitreTechniques.map((mt) => (
                      <tr key={mt.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-3.5 px-4 font-mono font-bold text-cyan-400">
                          {mt.techniqueId}
                        </td>
                        <td className="py-3.5 px-4 font-bold text-white">
                          {mt.techniqueName}
                        </td>
                        <td className="py-3.5 px-4">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-900 text-slate-300 border border-slate-800">
                            {mt.tactic}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 font-mono text-emerald-400 font-bold">
                          {mt.confidence}%
                        </td>
                        <td className="py-3.5 px-4 text-right">
                          <button
                            onClick={() => handleRemoveRelationship("TECHNIQUE", mt.techniqueId)}
                            className="p-1 rounded text-slate-500 hover:text-red-400 transition-colors"
                            title="Unlink"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
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

      {/* TAB 6: CORRELATED TARGET ASSETS */}
      {activeTab === "assets" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Correlated Assets in Threat Range ({correlatedAssets.length})
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
                No high-criticality assets identified in target sector.
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

      {/* TAB 7: CAMPAIGN TIMELINE */}
      {activeTab === "timeline" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Campaign Execution & Sightings Timeline ({timeline.length})
            </h3>
          </div>

          <Card className="bg-[#090F1E] border-slate-800 p-6">
            <div className="space-y-6 relative before:absolute before:left-4 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
              {timeline.length === 0 ? (
                <p className="text-xs text-slate-500 italic">No timeline entries recorded for this campaign.</p>
              ) : (
                timeline.map((item, idx) => (
                  <div key={idx} className="flex items-start gap-4 relative pl-8">
                    <div className={`w-8 h-8 rounded-full border flex items-center justify-center absolute -left-0 top-0 shadow-lg ${
                      item.type === "INCIDENT"
                        ? "bg-red-950 border-red-500/50 text-red-400"
                        : "bg-amber-950 border-amber-500/50 text-amber-400"
                    }`}>
                      {item.type === "INCIDENT" ? <Crosshair className="w-3.5 h-3.5" /> : <Flame className="w-3.5 h-3.5" />}
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
        title={`Correlate Artifact with ${campaign.name}`}
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
              className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-amber-500"
            >
              <option value="THREAT">Threat Intelligence Record</option>
              <option value="IOC">Indicator of Compromise (IOC)</option>
              <option value="INCIDENT">Security Incident</option>
              <option value="TECHNIQUE">MITRE ATT&CK Technique</option>
            </select>
          </div>

          {relFormData.type !== "TECHNIQUE" ? (
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Select Target Item *
              </label>
              <select
                required
                value={relFormData.targetId}
                onChange={(e) => setRelFormData({ ...relFormData, targetId: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-amber-500"
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
              </select>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                    MITRE Technique ID *
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. T1059.001"
                    value={relFormData.targetId}
                    onChange={(e) => setRelFormData({ ...relFormData, targetId: e.target.value })}
                    className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
                  />
                </div>
                <div>
                  <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                    Technique Name
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. PowerShell"
                    value={relFormData.techniqueName}
                    onChange={(e) => setRelFormData({ ...relFormData, techniqueName: e.target.value })}
                    className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                  MITRE Tactic Phase
                </label>
                <select
                  value={relFormData.tactic}
                  onChange={(e) => setRelFormData({ ...relFormData, tactic: e.target.value })}
                  className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-amber-500"
                >
                  <option value="Initial Access">Initial Access</option>
                  <option value="Execution">Execution</option>
                  <option value="Persistence">Persistence</option>
                  <option value="Privilege Escalation">Privilege Escalation</option>
                  <option value="Defense Evasion">Defense Evasion</option>
                  <option value="Credential Access">Credential Access</option>
                  <option value="Discovery">Discovery</option>
                  <option value="Lateral Movement">Lateral Movement</option>
                  <option value="Collection">Collection</option>
                  <option value="Command and Control">Command and Control</option>
                  <option value="Exfiltration">Exfiltration</option>
                  <option value="Impact">Impact</option>
                </select>
              </div>
            </div>
          )}

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
              className="px-5 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold transition-all shadow-md shadow-amber-950/50 flex items-center gap-2"
            >
              {addingRel ? "Correlating..." : "Establish Correlation"}
            </button>
          </div>
        </form>
      </Modal>

      {/* Edit Campaign Modal */}
      <Modal
        isOpen={editModalOpen}
        onClose={() => setEditModalOpen(false)}
        title={`Edit Campaign: ${campaign.name}`}
        maxWidth="max-w-2xl"
      >
        <form onSubmit={handleUpdateCampaign} className="space-y-4 text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Campaign Name *
              </label>
              <input
                type="text"
                required
                value={editFormData.name}
                onChange={(e) => setEditFormData({ ...editFormData, name: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-amber-500"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Attributed Threat Actor
              </label>
              <select
                value={editFormData.threatActorId}
                onChange={(e) => setEditFormData({ ...editFormData, threatActorId: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-amber-500"
              >
                <option value="">-- None (Unattributed) --</option>
                {availableThreatActors.map((a) => (
                  <option key={a.id} value={a.id}>{a.name} ({a.origin})</option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
              Campaign Description *
            </label>
            <textarea
              required
              rows={4}
              value={editFormData.description}
              onChange={(e) => setEditFormData({ ...editFormData, description: e.target.value })}
              className="w-full bg-[#050811] border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-amber-500"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Target Sectors (comma-separated)
              </label>
              <input
                type="text"
                value={editFormData.targetSectors}
                onChange={(e) => setEditFormData({ ...editFormData, targetSectors: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-amber-500"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Target Theaters (comma-separated)
              </label>
              <input
                type="text"
                value={editFormData.targetRegions}
                onChange={(e) => setEditFormData({ ...editFormData, targetRegions: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-amber-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
              Strategic Objectives
            </label>
            <input
              type="text"
              value={editFormData.objectives}
              onChange={(e) => setEditFormData({ ...editFormData, objectives: e.target.value })}
              className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-amber-500"
            />
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
                className="w-full accent-amber-500"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Operational Status
              </label>
              <select
                value={editFormData.status}
                onChange={(e) => setEditFormData({ ...editFormData, status: e.target.value })}
                className="w-full bg-[#050811] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-amber-500"
              >
                <option value="Active">Active Attack Campaign</option>
                <option value="Monitored">Monitored Threat</option>
                <option value="Disrupted">Disrupted</option>
                <option value="Completed">Completed</option>
              </select>
            </div>
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
              className="px-5 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold transition-all shadow-md shadow-amber-950/50 flex items-center gap-2"
            >
              {updating ? "Saving Changes..." : "Save Campaign"}
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

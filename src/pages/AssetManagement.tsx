import React, { useEffect, useState } from "react";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
  Badge,
  SeverityBadge,
  cn
} from "../components/ui";
import {
  Server,
  Database,
  Globe,
  Lock,
  Shield,
  ShieldAlert,
  AlertTriangle,
  Search,
  Filter,
  Plus,
  Trash2,
  Edit3,
  Eye,
  RefreshCw,
  Download,
  Copy,
  Check,
  X,
  Laptop,
  Cloud,
  Cpu,
  Layers,
  Terminal,
  Clock,
  User,
  Building,
  MapPin,
  Tag,
  FileText,
  Activity,
  CheckCircle2,
  HardDrive
} from "lucide-react";
import type { Asset, AssetType, AssetEnvironment, AssetCriticality, AssetExposure, AssetStatus, ExplainableRiskAssessment } from "../types";
import { ExplainableRiskScoreCard } from "../components/ExplainableRiskScoreCard";

export default function AssetManagement() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [criticalityFilter, setCriticalityFilter] = useState("ALL");
  const [exposureFilter, setExposureFilter] = useState("ALL");
  const [environmentFilter, setEnvironmentFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");

  // Selection & Modals
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [detailModalOpen, setDetailModalOpen] = useState(false);
  const [formModalOpen, setFormModalOpen] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [assetToDelete, setAssetToDelete] = useState<Asset | null>(null);
  const [assetRiskAssessment, setAssetRiskAssessment] = useState<ExplainableRiskAssessment | null>(null);
  const [loadingAssetRisk, setLoadingAssetRisk] = useState(false);

  // Form State
  const [formData, setFormData] = useState({
    id: "",
    name: "",
    hostname: "",
    ipAddress: "",
    assetType: "SERVER" as AssetType,
    operatingSystem: "",
    software: "",
    environment: "Production" as AssetEnvironment,
    criticality: "MEDIUM" as AssetCriticality,
    exposure: "INTERNAL" as AssetExposure,
    owner: "",
    department: "",
    location: "",
    description: "",
    tags: "",
    status: "ACTIVE" as AssetStatus
  });
  const [formErrors, setFormErrors] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);
  const [copiedIp, setCopiedIp] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3000);
  };

  const fetchAssets = async () => {
    try {
      setLoading(true);
      const res = await fetch("/api/assets");
      const data = await res.json();
      setAssets(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error("Failed to fetch assets:", e);
      setAssets([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, []);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIp(id);
    setTimeout(() => setCopiedIp(null), 2000);
  };

  // Filtered Assets
  const filteredAssets = assets.filter((a) => {
    const q = search.toLowerCase().trim();
    const matchesSearch =
      !q ||
      a.name.toLowerCase().includes(q) ||
      (a.hostname && a.hostname.toLowerCase().includes(q)) ||
      (a.ipAddress && a.ipAddress.toLowerCase().includes(q)) ||
      (a.owner && a.owner.toLowerCase().includes(q)) ||
      (a.department && a.department.toLowerCase().includes(q)) ||
      (a.software && a.software.toLowerCase().includes(q)) ||
      (a.operatingSystem && a.operatingSystem.toLowerCase().includes(q)) ||
      (a.tags && a.tags.toLowerCase().includes(q)) ||
      (a.description && a.description.toLowerCase().includes(q));

    const matchesType = typeFilter === "ALL" || a.assetType?.toUpperCase() === typeFilter.toUpperCase();
    const matchesCriticality = criticalityFilter === "ALL" || a.criticality?.toUpperCase() === criticalityFilter.toUpperCase();
    const matchesExposure = exposureFilter === "ALL" || a.exposure?.toUpperCase() === exposureFilter.toUpperCase();
    const matchesEnvironment = environmentFilter === "ALL" || a.environment?.toUpperCase() === environmentFilter.toUpperCase();
    const matchesStatus = statusFilter === "ALL" || a.status?.toUpperCase() === statusFilter.toUpperCase();

    return matchesSearch && matchesType && matchesCriticality && matchesExposure && matchesEnvironment && matchesStatus;
  });

  // Calculate Metrics
  const totalAssetsCount = assets.length;
  const criticalCount = assets.filter((a) => a.criticality === "CRITICAL").length;
  const internetExposedCount = assets.filter((a) => a.exposure === "INTERNET").length;
  const productionCount = assets.filter((a) => a.environment === "Production" && a.status === "ACTIVE").length;

  const typeCounts: Record<string, number> = {};
  assets.forEach((a) => {
    const t = a.assetType || "OTHER";
    typeCounts[t] = (typeCounts[t] || 0) + 1;
  });

  // Open Create Form
  const openCreateModal = () => {
    setIsEditing(false);
    setFormData({
      id: "",
      name: "",
      hostname: "",
      ipAddress: "",
      assetType: "SERVER",
      operatingSystem: "",
      software: "",
      environment: "Production",
      criticality: "MEDIUM",
      exposure: "INTERNAL",
      owner: "",
      department: "",
      location: "",
      description: "",
      tags: "",
      status: "ACTIVE"
    });
    setFormErrors({});
    setFormModalOpen(true);
  };

  // Open Edit Form
  const openEditModal = (asset: Asset) => {
    setIsEditing(true);
    setFormData({
      id: asset.id,
      name: asset.name || "",
      hostname: asset.hostname || "",
      ipAddress: asset.ipAddress || "",
      assetType: (asset.assetType as AssetType) || "SERVER",
      operatingSystem: asset.operatingSystem || "",
      software: asset.software || "",
      environment: (asset.environment as AssetEnvironment) || "Production",
      criticality: (asset.criticality as AssetCriticality) || "MEDIUM",
      exposure: (asset.exposure as AssetExposure) || "INTERNAL",
      owner: asset.owner || "",
      department: asset.department || "",
      location: asset.location || "",
      description: asset.description || "",
      tags: asset.tags || "",
      status: (asset.status as AssetStatus) || "ACTIVE"
    });
    setFormErrors({});
    setFormModalOpen(true);
  };

  // Open Detail Modal
  const openDetailModal = async (asset: Asset) => {
    setSelectedAsset(asset);
    setDetailModalOpen(true);
    setAssetRiskAssessment(null);
    try {
      setLoadingAssetRisk(true);
      const res = await fetch(`/api/risk/asset/${asset.id}`);
      if (res.ok) {
        const data = await res.json();
        setAssetRiskAssessment(data);
      }
    } catch (e) {
      console.error("Asset risk assessment fetch failed", e);
    } finally {
      setLoadingAssetRisk(false);
    }
  };

  // Open Delete Modal
  const openDeleteModal = (asset: Asset) => {
    setAssetToDelete(asset);
    setDeleteModalOpen(true);
  };

  // Validate & Submit Form
  const handleSubmitForm = async (e: React.FormEvent) => {
    e.preventDefault();
    const errors: Record<string, string> = {};

    if (!formData.name.trim()) {
      errors.name = "Asset name is required";
    }
    if (!formData.assetType) {
      errors.assetType = "Asset type is required";
    }

    if (Object.keys(errors).length > 0) {
      setFormErrors(errors);
      return;
    }

    try {
      setSubmitting(true);
      if (isEditing && formData.id) {
        const res = await fetch(`/api/assets/${formData.id}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(formData)
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.error || "Failed to update asset");
        }
        const updated = await res.json();
        setAssets((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
        if (selectedAsset && selectedAsset.id === updated.id) {
          setSelectedAsset(updated);
        }
        showToast("Asset updated successfully");
      } else {
        const res = await fetch("/api/assets", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(formData)
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.error || "Failed to create asset");
        }
        const created = await res.json();
        setAssets((prev) => [created, ...prev]);
        showToast("Asset created successfully");
      }
      setFormModalOpen(false);
    } catch (err: any) {
      setFormErrors({ submit: err.message });
    } finally {
      setSubmitting(false);
    }
  };

  // Confirm Delete
  const handleConfirmDelete = async () => {
    if (!assetToDelete) return;
    try {
      setSubmitting(true);
      const res = await fetch(`/api/assets/${assetToDelete.id}`, {
        method: "DELETE"
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Failed to delete asset");
      }
      setAssets((prev) => prev.filter((a) => a.id !== assetToDelete.id));
      if (selectedAsset && selectedAsset.id === assetToDelete.id) {
        setDetailModalOpen(false);
        setSelectedAsset(null);
      }
      setDeleteModalOpen(false);
      setAssetToDelete(null);
      showToast("Asset removed from inventory");
    } catch (err: any) {
      alert("Error deleting asset: " + err.message);
    } finally {
      setSubmitting(false);
    }
  };

  // Export CSV
  const exportCSV = () => {
    const headers = [
      "ID",
      "Name",
      "Hostname",
      "IP Address",
      "Asset Type",
      "OS",
      "Software",
      "Environment",
      "Criticality",
      "Exposure",
      "Owner",
      "Department",
      "Location",
      "Tags",
      "Status",
      "Created At",
      "Updated At"
    ];

    const rows = filteredAssets.map((a) => [
      `"${a.id}"`,
      `"${a.name.replace(/"/g, '""')}"`,
      `"${(a.hostname || "").replace(/"/g, '""')}"`,
      `"${(a.ipAddress || "").replace(/"/g, '""')}"`,
      `"${a.assetType}"`,
      `"${(a.operatingSystem || "").replace(/"/g, '""')}"`,
      `"${(a.software || "").replace(/"/g, '""')}"`,
      `"${a.environment}"`,
      `"${a.criticality}"`,
      `"${a.exposure}"`,
      `"${(a.owner || "").replace(/"/g, '""')}"`,
      `"${(a.department || "").replace(/"/g, '""')}"`,
      `"${(a.location || "").replace(/"/g, '""')}"`,
      `"${(a.tags || "").replace(/"/g, '""')}"`,
      `"${a.status}"`,
      `"${new Date(a.createdAt).toISOString()}"`,
      `"${new Date(a.updatedAt).toISOString()}"`
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `shieldzen-assets-${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  // Asset Type Icon Helper
  const getAssetTypeIcon = (type: string) => {
    switch (type?.toUpperCase()) {
      case "SERVER":
        return <Server className="w-4 h-4 text-blue-400" />;
      case "DATABASE":
        return <Database className="w-4 h-4 text-purple-400" />;
      case "WORKSTATION":
        return <Laptop className="w-4 h-4 text-emerald-400" />;
      case "NETWORK_DEVICE":
        return <HardDrive className="w-4 h-4 text-amber-400" />;
      case "CLOUD":
        return <Cloud className="w-4 h-4 text-cyan-400" />;
      case "APPLICATION":
        return <Cpu className="w-4 h-4 text-pink-400" />;
      default:
        return <Layers className="w-4 h-4 text-slate-400" />;
    }
  };

  // Exposure Badge Helper
  const renderExposureBadge = (exposure: string) => {
    switch (exposure?.toUpperCase()) {
      case "INTERNET":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-950/80 text-red-300 border border-red-500/40">
            <Globe className="w-3 h-3 text-red-400 animate-pulse" />
            INTERNET
          </span>
        );
      case "RESTRICTED":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-950/80 text-purple-300 border border-purple-500/40">
            <Shield className="w-3 h-3 text-purple-400" />
            RESTRICTED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-500/30">
            <Lock className="w-3 h-3 text-cyan-400" />
            INTERNAL
          </span>
        );
    }
  };

  // Criticality Badge Helper
  const renderCriticalityBadge = (crit: string) => {
    switch (crit?.toUpperCase()) {
      case "CRITICAL":
        return <SeverityBadge severity="CRITICAL" />;
      case "HIGH":
        return <SeverityBadge severity="HIGH" />;
      case "MEDIUM":
        return <SeverityBadge severity="MEDIUM" />;
      default:
        return <SeverityBadge severity="LOW" />;
    }
  };

  // Status Badge Helper
  const renderStatusBadge = (status: string) => {
    switch (status?.toUpperCase()) {
      case "ACTIVE":
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono text-emerald-400 font-semibold">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            ACTIVE
          </span>
        );
      case "MAINTENANCE":
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono text-amber-400 font-semibold">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
            MAINTENANCE
          </span>
        );
      case "INACTIVE":
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono text-slate-400 font-semibold">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
            INACTIVE
          </span>
        );
      case "DECOMMISSIONED":
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono text-red-400 line-through font-semibold">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
            DECOMMISSIONED
          </span>
        );
      default:
        return <span className="text-[10px] font-mono text-slate-400">{status}</span>;
    }
  };

  const hasActiveFilters =
    search ||
    typeFilter !== "ALL" ||
    criticalityFilter !== "ALL" ||
    exposureFilter !== "ALL" ||
    environmentFilter !== "ALL" ||
    statusFilter !== "ALL";

  const clearAllFilters = () => {
    setSearch("");
    setTypeFilter("ALL");
    setCriticalityFilter("ALL");
    setExposureFilter("ALL");
    setEnvironmentFilter("ALL");
    setStatusFilter("ALL");
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Toast notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#0c1a2f] border border-cyan-500/50 text-cyan-200 px-4 py-2.5 rounded-xl shadow-2xl flex items-center gap-2 text-xs font-semibold animate-in fade-in slide-in-from-bottom-2 duration-200">
          <CheckCircle2 className="w-4 h-4 text-cyan-400" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Page Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono uppercase tracking-widest text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-500/30">
              SOC Asset Inventory
            </span>
            <span className="text-[10px] font-mono text-slate-400">
              ● {totalAssetsCount} Tracked Entities
            </span>
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight mt-1">
            Enterprise Asset Management
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Centralized visibility of infrastructure endpoints, hostnames, IP allocations, software stacks, network exposure levels, and asset criticality tiers.
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          <button
            id="btn-refresh-assets"
            onClick={fetchAssets}
            disabled={loading}
            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold flex items-center gap-1.5 border border-slate-700 transition-colors cursor-pointer"
            title="Refresh asset inventory"
          >
            <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin text-cyan-400")} />
            <span>Refresh</span>
          </button>

          <button
            id="btn-export-assets-csv"
            onClick={exportCSV}
            disabled={filteredAssets.length === 0}
            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold flex items-center gap-1.5 border border-slate-700 transition-colors cursor-pointer disabled:opacity-50"
            title="Export filtered assets as CSV"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export CSV</span>
          </button>

          <button
            id="btn-add-new-asset"
            onClick={openCreateModal}
            className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold flex items-center gap-1.5 shadow-md shadow-cyan-950/60 transition-all cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>New Asset</span>
          </button>
        </div>
      </div>

      {/* Top Asset Summary Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Assets */}
        <Card id="card-metric-total-assets" className="border-slate-800/80 bg-[#0B1222]">
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                Total Assets
              </div>
              <div className="text-2xl font-extrabold text-white mt-1">
                {totalAssetsCount}
              </div>
              <div className="text-[10px] text-slate-400 mt-1 flex items-center gap-1">
                <span>{typeCounts["SERVER"] || 0} Servers</span>
                <span>•</span>
                <span>{typeCounts["DATABASE"] || 0} DBs</span>
                <span>•</span>
                <span>{typeCounts["CLOUD"] || 0} Cloud</span>
              </div>
            </div>
            <div className="w-11 h-11 rounded-xl bg-blue-950/60 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Server className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        {/* Critical Infrastructure */}
        <Card id="card-metric-critical-assets" className="border-red-900/40 bg-gradient-to-br from-[#0B1222] to-red-950/20">
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <div className="text-[11px] font-mono text-red-400 uppercase tracking-wider flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-red-400 animate-ping" />
                Critical Assets
              </div>
              <div className="text-2xl font-extrabold text-red-400 mt-1">
                {criticalCount}
              </div>
              <div className="text-[10px] text-red-300/80 mt-1">
                Tier-1 mission critical systems
              </div>
            </div>
            <div className="w-11 h-11 rounded-xl bg-red-950/80 border border-red-500/40 flex items-center justify-center text-red-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        {/* Internet Exposed */}
        <Card id="card-metric-exposed-assets" className="border-amber-900/40 bg-gradient-to-br from-[#0B1222] to-amber-950/20">
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <div className="text-[11px] font-mono text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5" />
                Internet Exposed
              </div>
              <div className="text-2xl font-extrabold text-amber-400 mt-1">
                {internetExposedCount}
              </div>
              <div className="text-[10px] text-amber-300/80 mt-1">
                Direct external attack surface
              </div>
            </div>
            <div className="w-11 h-11 rounded-xl bg-amber-950/80 border border-amber-500/40 flex items-center justify-center text-amber-400">
              <Globe className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        {/* Production Active */}
        <Card id="card-metric-prod-active-assets" className="border-emerald-900/40 bg-gradient-to-br from-[#0B1222] to-emerald-950/20">
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <div className="text-[11px] font-mono text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Production Live
              </div>
              <div className="text-2xl font-extrabold text-emerald-400 mt-1">
                {productionCount}
              </div>
              <div className="text-[10px] text-emerald-300/80 mt-1">
                Active live environment nodes
              </div>
            </div>
            <div className="w-11 h-11 rounded-xl bg-emerald-950/80 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
              <Activity className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filter and Search Bar */}
      <Card className="border-slate-800 bg-[#090F1C]">
        <CardContent className="p-4 space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-center">
            {/* Search */}
            <div className="md:col-span-4 relative">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                id="input-asset-search"
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search name, hostname, IP, software, owner..."
                className="w-full bg-[#070B14] border border-slate-700/80 text-white placeholder-slate-500 text-xs pl-9 pr-8 py-2 rounded-xl focus:outline-none focus:border-cyan-500/80 focus:ring-1 focus:ring-cyan-500/30 font-sans"
              />
              {search && (
                <button
                  onClick={() => setSearch("")}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Type Filter */}
            <div className="md:col-span-2">
              <select
                id="select-asset-type"
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="w-full bg-[#070B14] border border-slate-700/80 text-slate-200 text-xs px-3 py-2 rounded-xl focus:outline-none focus:border-cyan-500 font-sans"
              >
                <option value="ALL">All Asset Types</option>
                <option value="SERVER">Server</option>
                <option value="DATABASE">Database</option>
                <option value="WORKSTATION">Workstation</option>
                <option value="NETWORK_DEVICE">Network Device</option>
                <option value="CLOUD">Cloud Node</option>
                <option value="APPLICATION">Application</option>
                <option value="ENDPOINT">Endpoint</option>
                <option value="OTHER">Other</option>
              </select>
            </div>

            {/* Criticality Filter */}
            <div className="md:col-span-2">
              <select
                id="select-asset-criticality"
                value={criticalityFilter}
                onChange={(e) => setCriticalityFilter(e.target.value)}
                className="w-full bg-[#070B14] border border-slate-700/80 text-slate-200 text-xs px-3 py-2 rounded-xl focus:outline-none focus:border-cyan-500 font-sans"
              >
                <option value="ALL">All Criticality</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            {/* Exposure Filter */}
            <div className="md:col-span-2">
              <select
                id="select-asset-exposure"
                value={exposureFilter}
                onChange={(e) => setExposureFilter(e.target.value)}
                className="w-full bg-[#070B14] border border-slate-700/80 text-slate-200 text-xs px-3 py-2 rounded-xl focus:outline-none focus:border-cyan-500 font-sans"
              >
                <option value="ALL">All Exposure</option>
                <option value="INTERNET">Internet Facing</option>
                <option value="INTERNAL">Internal Network</option>
                <option value="RESTRICTED">Restricted Enclave</option>
              </select>
            </div>

            {/* Environment Filter */}
            <div className="md:col-span-2">
              <select
                id="select-asset-environment"
                value={environmentFilter}
                onChange={(e) => setEnvironmentFilter(e.target.value)}
                className="w-full bg-[#070B14] border border-slate-700/80 text-slate-200 text-xs px-3 py-2 rounded-xl focus:outline-none focus:border-cyan-500 font-sans"
              >
                <option value="ALL">All Environments</option>
                <option value="Production">Production</option>
                <option value="Staging">Staging</option>
                <option value="Testing">Testing</option>
                <option value="Development">Development</option>
              </select>
            </div>
          </div>

          {/* Active Filter Tags */}
          {hasActiveFilters && (
            <div className="flex items-center gap-2 pt-2 border-t border-slate-800/80 text-xs flex-wrap">
              <span className="text-[10px] font-mono text-slate-400 uppercase">Filtered by:</span>
              {search && (
                <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded text-[11px] flex items-center gap-1">
                  Search: "{search}"
                  <X className="w-3 h-3 cursor-pointer" onClick={() => setSearch("")} />
                </span>
              )}
              {typeFilter !== "ALL" && (
                <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded text-[11px] flex items-center gap-1">
                  Type: {typeFilter}
                  <X className="w-3 h-3 cursor-pointer" onClick={() => setTypeFilter("ALL")} />
                </span>
              )}
              {criticalityFilter !== "ALL" && (
                <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded text-[11px] flex items-center gap-1">
                  Criticality: {criticalityFilter}
                  <X className="w-3 h-3 cursor-pointer" onClick={() => setCriticalityFilter("ALL")} />
                </span>
              )}
              {exposureFilter !== "ALL" && (
                <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded text-[11px] flex items-center gap-1">
                  Exposure: {exposureFilter}
                  <X className="w-3 h-3 cursor-pointer" onClick={() => setExposureFilter("ALL")} />
                </span>
              )}
              {environmentFilter !== "ALL" && (
                <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded text-[11px] flex items-center gap-1">
                  Env: {environmentFilter}
                  <X className="w-3 h-3 cursor-pointer" onClick={() => setEnvironmentFilter("ALL")} />
                </span>
              )}
              <button
                onClick={clearAllFilters}
                className="text-[11px] text-cyan-400 hover:text-cyan-300 underline ml-auto font-medium"
              >
                Clear all filters
              </button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Main Asset Table */}
      <Card className="border-slate-800 overflow-hidden">
        <CardHeader className="flex-row items-center justify-between py-3.5">
          <CardTitle>
            <Server className="w-4 h-4 text-cyan-400" />
            <span>Infrastructure Inventory ({filteredAssets.length})</span>
          </CardTitle>
          <div className="text-xs text-slate-400 font-mono">
            Showing {filteredAssets.length} of {totalAssetsCount} items
          </div>
        </CardHeader>

        <CardContent className="p-0">
          {loading ? (
            <div className="p-12 text-center text-slate-400 flex flex-col items-center justify-center gap-3">
              <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
              <p className="text-xs">Loading enterprise asset records...</p>
            </div>
          ) : filteredAssets.length === 0 ? (
            <div className="p-12 text-center text-slate-400 space-y-3">
              <div className="w-12 h-12 rounded-2xl bg-slate-800/80 border border-slate-700 flex items-center justify-center mx-auto text-slate-500">
                <Server className="w-6 h-6" />
              </div>
              <p className="text-sm font-semibold text-slate-300">No assets match your search criteria</p>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                Try adjusting your search queries or clearing active filters to view all recorded enterprise endpoints.
              </p>
              {hasActiveFilters && (
                <button
                  onClick={clearAllFilters}
                  className="mt-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-400 rounded-lg text-xs font-semibold transition-colors"
                >
                  Reset Filters
                </button>
              )}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 bg-[#080D1A] text-[11px] font-mono uppercase tracking-wider text-slate-400">
                    <th className="py-3 px-4 font-semibold">Asset Details</th>
                    <th className="py-3 px-4 font-semibold">Network & Host</th>
                    <th className="py-3 px-4 font-semibold">Type / OS</th>
                    <th className="py-3 px-4 font-semibold">Environment</th>
                    <th className="py-3 px-4 font-semibold">Criticality</th>
                    <th className="py-3 px-4 font-semibold">Exposure</th>
                    <th className="py-3 px-4 font-semibold">Owner / Dept</th>
                    <th className="py-3 px-4 font-semibold">Status</th>
                    <th className="py-3 px-4 text-right font-semibold">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-xs">
                  {filteredAssets.map((asset) => (
                    <tr
                      key={asset.id}
                      id={`asset-row-${asset.id}`}
                      className="hover:bg-slate-800/30 transition-colors group"
                    >
                      {/* Asset Details */}
                      <td className="py-3.5 px-4">
                        <div className="flex items-start gap-2.5">
                          <div className="p-2 rounded-lg bg-slate-800/80 border border-slate-700/60 mt-0.5 shrink-0">
                            {getAssetTypeIcon(asset.assetType)}
                          </div>
                          <div>
                            <button
                              onClick={() => openDetailModal(asset)}
                              className="font-bold text-white hover:text-cyan-300 transition-colors text-left text-xs leading-snug"
                            >
                              {asset.name}
                            </button>
                            <div className="flex items-center gap-2 mt-1">
                              <span className="text-[10px] font-mono text-slate-500">
                                {asset.id}
                              </span>
                              {asset.location && (
                                <span className="text-[10px] text-slate-400 flex items-center gap-0.5">
                                  <MapPin className="w-2.5 h-2.5 text-slate-500" />
                                  {asset.location}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      </td>

                      {/* Network & Host */}
                      <td className="py-3.5 px-4 font-mono">
                        {asset.ipAddress ? (
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-200 font-semibold">{asset.ipAddress}</span>
                            <button
                              onClick={() => copyToClipboard(asset.ipAddress!, asset.id)}
                              className="text-slate-500 hover:text-cyan-300 p-0.5 transition-colors"
                              title="Copy IP Address"
                            >
                              {copiedIp === asset.id ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                        ) : (
                          <span className="text-slate-600 text-[11px]">No IP assigned</span>
                        )}
                        {asset.hostname && (
                          <div className="text-[11px] text-slate-400 truncate max-w-[180px]" title={asset.hostname}>
                            {asset.hostname}
                          </div>
                        )}
                      </td>

                      {/* Type / OS */}
                      <td className="py-3.5 px-4">
                        <span className="inline-block px-1.5 py-0.5 bg-slate-800 text-slate-300 rounded text-[10px] font-mono font-medium border border-slate-700/60 mb-0.5">
                          {asset.assetType}
                        </span>
                        {asset.operatingSystem && (
                          <div className="text-[11px] text-slate-400 truncate max-w-[160px]" title={asset.operatingSystem}>
                            {asset.operatingSystem}
                          </div>
                        )}
                      </td>

                      {/* Environment */}
                      <td className="py-3.5 px-4">
                        <span
                          className={cn(
                            "px-2 py-0.5 rounded text-[10px] font-mono font-bold border",
                            asset.environment === "Production"
                              ? "bg-emerald-950/60 text-emerald-300 border-emerald-500/30"
                              : asset.environment === "Staging"
                              ? "bg-amber-950/60 text-amber-300 border-amber-500/30"
                              : "bg-blue-950/60 text-blue-300 border-blue-500/30"
                          )}
                        >
                          {asset.environment}
                        </span>
                      </td>

                      {/* Criticality */}
                      <td className="py-3.5 px-4">
                        {renderCriticalityBadge(asset.criticality)}
                      </td>

                      {/* Exposure */}
                      <td className="py-3.5 px-4">
                        {renderExposureBadge(asset.exposure)}
                      </td>

                      {/* Owner / Dept */}
                      <td className="py-3.5 px-4">
                        <div className="text-slate-300 font-medium text-xs truncate max-w-[140px]" title={asset.owner || "Unassigned"}>
                          {asset.owner || <span className="text-slate-600">Unassigned</span>}
                        </div>
                        {asset.department && (
                          <div className="text-[10px] text-slate-500 truncate max-w-[140px]">
                            {asset.department}
                          </div>
                        )}
                      </td>

                      {/* Status */}
                      <td className="py-3.5 px-4">
                        {renderStatusBadge(asset.status)}
                      </td>

                      {/* Actions */}
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5 opacity-80 group-hover:opacity-100 transition-opacity">
                          <button
                            id={`btn-view-asset-${asset.id}`}
                            onClick={() => openDetailModal(asset)}
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-300 border border-slate-700 transition-colors cursor-pointer"
                            title="View Asset Details"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          <button
                            id={`btn-edit-asset-${asset.id}`}
                            onClick={() => openEditModal(asset)}
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition-colors cursor-pointer"
                            title="Edit Asset"
                          >
                            <Edit3 className="w-3.5 h-3.5" />
                          </button>
                          <button
                            id={`btn-delete-asset-${asset.id}`}
                            onClick={() => openDeleteModal(asset)}
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-red-950/80 text-slate-400 hover:text-red-400 border border-slate-700 hover:border-red-500/40 transition-colors cursor-pointer"
                            title="Delete Asset"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Asset Detail Modal / Drawer */}
      {detailModalOpen && selectedAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="w-full max-w-2xl bg-[#090F1C] border border-slate-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-[#080D1A]">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-slate-800 border border-slate-700 text-cyan-400">
                  {getAssetTypeIcon(selectedAsset.assetType)}
                </div>
                <div>
                  <h3 className="text-base font-extrabold text-white">
                    {selectedAsset.name}
                  </h3>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950 px-1.5 py-0.2 rounded border border-cyan-500/30">
                      {selectedAsset.id}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400">
                      {selectedAsset.assetType}
                    </span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    setDetailModalOpen(false);
                    openEditModal(selectedAsset);
                  }}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold flex items-center gap-1 border border-slate-700 transition-colors"
                >
                  <Edit3 className="w-3.5 h-3.5" />
                  <span>Edit</span>
                </button>
                <button
                  onClick={() => setDetailModalOpen(false)}
                  className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-6 text-xs">
              {/* Top Pill Badges */}
              <div className="flex items-center gap-3 flex-wrap p-3 rounded-xl bg-[#070B14] border border-slate-800">
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-mono uppercase text-slate-500">Criticality:</span>
                  {renderCriticalityBadge(selectedAsset.criticality)}
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-mono uppercase text-slate-500">Exposure:</span>
                  {renderExposureBadge(selectedAsset.exposure)}
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-mono uppercase text-slate-500">Environment:</span>
                  <span className="font-mono font-bold text-slate-300">{selectedAsset.environment}</span>
                </div>
                <div className="flex items-center gap-1.5 ml-auto">
                  <span className="text-[10px] font-mono uppercase text-slate-500">Status:</span>
                  {renderStatusBadge(selectedAsset.status)}
                </div>
              </div>

              {/* Explainable Risk Assessment Card */}
              <ExplainableRiskScoreCard
                assessment={assetRiskAssessment}
                loading={loadingAssetRisk}
                title={`Deterministic Risk Assessment: ${selectedAsset.name}`}
              />

              {/* Description */}
              {selectedAsset.description && (
                <div className="space-y-1.5">
                  <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <FileText className="w-3.5 h-3.5 text-cyan-400" />
                    Operational Overview
                  </div>
                  <p className="text-slate-300 leading-relaxed bg-[#070B14] p-3.5 rounded-xl border border-slate-800/80">
                    {selectedAsset.description}
                  </p>
                </div>
              )}

              {/* Grid Attributes */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Network & Infrastructure */}
                <div className="bg-[#070B14] p-4 rounded-xl border border-slate-800/80 space-y-3">
                  <div className="text-[11px] font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center gap-1.5 border-b border-slate-800 pb-2">
                    <Terminal className="w-3.5 h-3.5" />
                    Network & Host Identity
                  </div>
                  <div className="space-y-2 font-mono text-[11px]">
                    <div>
                      <span className="text-slate-500 block text-[10px]">Hostname:</span>
                      <span className="text-slate-200 font-semibold">{selectedAsset.hostname || "None specified"}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">IP Address:</span>
                      <span className="text-cyan-300 font-semibold">{selectedAsset.ipAddress || "Unallocated"}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">Operating System:</span>
                      <span className="text-slate-200">{selectedAsset.operatingSystem || "Not specified"}</span>
                    </div>
                  </div>
                </div>

                {/* Organization & Location */}
                <div className="bg-[#070B14] p-4 rounded-xl border border-slate-800/80 space-y-3">
                  <div className="text-[11px] font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center gap-1.5 border-b border-slate-800 pb-2">
                    <Building className="w-3.5 h-3.5" />
                    Ownership & Placement
                  </div>
                  <div className="space-y-2 text-[11px]">
                    <div>
                      <span className="text-slate-500 block font-mono text-[10px]">Owner / Lead:</span>
                      <span className="text-slate-200 font-semibold">{selectedAsset.owner || "Unassigned"}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block font-mono text-[10px]">Department:</span>
                      <span className="text-slate-200">{selectedAsset.department || "General IT / Ops"}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block font-mono text-[10px]">Physical / Cloud Location:</span>
                      <span className="text-slate-200">{selectedAsset.location || "Global Perimeter"}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Software & Installed Stack */}
              {selectedAsset.software && (
                <div className="space-y-1.5">
                  <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                    Installed Software & Dependencies
                  </div>
                  <div className="bg-[#070B14] p-3.5 rounded-xl border border-slate-800/80 text-slate-300 font-mono text-[11px] leading-relaxed">
                    {selectedAsset.software}
                  </div>
                </div>
              )}

              {/* Tags */}
              {selectedAsset.tags && (
                <div className="space-y-1.5">
                  <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Tag className="w-3.5 h-3.5 text-cyan-400" />
                    Security & Classification Tags
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedAsset.tags.split(",").map((t, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 bg-slate-800 text-cyan-300 rounded text-[10px] font-mono border border-slate-700"
                      >
                        #{t.trim()}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Timestamps */}
              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-500">
                <div>Created: {new Date(selectedAsset.createdAt).toLocaleString()}</div>
                <div>Last Audited: {new Date(selectedAsset.updatedAt).toLocaleString()}</div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-3.5 border-t border-slate-800 bg-[#080D1A] flex justify-between items-center">
              <button
                onClick={() => {
                  setDetailModalOpen(false);
                  openDeleteModal(selectedAsset);
                }}
                className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Delete Asset</span>
              </button>

              <button
                onClick={() => setDetailModalOpen(false)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-xs font-bold transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Asset Create / Edit Modal */}
      {formModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="w-full max-w-2xl bg-[#090F1C] border border-slate-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-[#080D1A]">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  {isEditing ? "Edit Enterprise Asset" : "Register New Asset"}
                </h3>
              </div>
              <button
                onClick={() => setFormModalOpen(false)}
                className="p-1 text-slate-400 hover:text-white rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmitForm} className="flex flex-col flex-1 overflow-hidden">
              <div className="p-6 overflow-y-auto space-y-4 text-xs">
                {formErrors.submit && (
                  <div className="p-3 bg-red-950/80 border border-red-500/50 text-red-300 rounded-xl text-xs flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                    <span>{formErrors.submit}</span>
                  </div>
                )}

                {/* Name & Asset Type */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                      Asset Name <span className="text-red-400">*</span>
                    </label>
                    <input
                      id="input-form-asset-name"
                      type="text"
                      required
                      placeholder="e.g. Primary Edge API Gateway"
                      value={formData.name}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      className={cn(
                        "w-full bg-[#070B14] border text-white text-xs px-3 py-2 rounded-xl focus:outline-none focus:ring-1 focus:ring-cyan-500",
                        formErrors.name ? "border-red-500" : "border-slate-700/80"
                      )}
                    />
                    {formErrors.name && (
                      <p className="text-[10px] text-red-400 mt-0.5">{formErrors.name}</p>
                    )}
                  </div>

                  <div>
                    <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                      Asset Type <span className="text-red-400">*</span>
                    </label>
                    <select
                      id="select-form-asset-type"
                      value={formData.assetType}
                      onChange={(e) => setFormData({ ...formData, assetType: e.target.value as AssetType })}
                      className="w-full bg-[#070B14] border border-slate-700/80 text-slate-200 text-xs px-3 py-2 rounded-xl focus:outline-none focus:border-cyan-500"
                    >
                      <option value="SERVER">SERVER (Physical / Virtual Host)</option>
                      <option value="DATABASE">DATABASE (SQL / NoSQL Cluster)</option>
                      <option value="WORKSTATION">WORKSTATION (Endpoint / Analyst PC)</option>
                      <option value="NETWORK_DEVICE">NETWORK_DEVICE (Firewall / Switch / Router)</option>
                      <option value="CLOUD">CLOUD (Kubernetes Pod / Lambda / Instance)</option>
                      <option value="APPLICATION">APPLICATION (Web / API / Service)</option>
                      <option value="ENDPOINT">ENDPOINT (Mobile / IoT / Embedded)</option>
                      <option value="OTHER">OTHER</option>
                    </select>
                  </div>
                </div>

                {/* Hostname & IP Address */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                      Hostname / FQDN
                    </label>
                    <input
                      id="input-form-hostname"
                      type="text"
                      placeholder="e.g. gw-edge-01.prod.shieldzen.net"
                      value={formData.hostname}
                      onChange={(e) => setFormData({ ...formData, hostname: e.target.value })}
                      className="w-full bg-[#070B14] border border-slate-700/80 text-white text-xs px-3 py-2 rounded-xl focus:outline-none focus:border-cyan-500 font-mono"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                      IP Address
                    </label>
                    <input
                      id="input-form-ip-address"
                      type="text"
                      placeholder="e.g. 52.14.88.192 or 10.100.4.15"
                      value={formData.ipAddress}
                      onChange={(e) => setFormData({ ...formData, ipAddress: e.target.value })}
                      className="w-full bg-[#070B14] border border-slate-700/80 text-white text-xs px-3 py-2 rounded-xl focus:outline-none focus:border-cyan-500 font-mono"
                    />
                  </div>
                </div>

                {/* Criticality, Exposure, Environment, Status */}
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 bg-[#070B14] p-3.5 rounded-xl border border-slate-800">
                  <div>
                    <label className="block text-[10px] font-mono uppercase text-slate-400 mb-1">
                      Criticality
                    </label>
                    <select
                      id="select-form-criticality"
                      value={formData.criticality}
                      onChange={(e) => setFormData({ ...formData, criticality: e.target.value as AssetCriticality })}
                      className="w-full bg-[#090F1C] border border-slate-700/80 text-slate-200 text-xs px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-cyan-500"
                    >
                      <option value="CRITICAL">CRITICAL (Tier-1)</option>
                      <option value="HIGH">HIGH (Tier-2)</option>
                      <option value="MEDIUM">MEDIUM (Tier-3)</option>
                      <option value="LOW">LOW (Tier-4)</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-[10px] font-mono uppercase text-slate-400 mb-1">
                      Exposure Level
                    </label>
                    <select
                      id="select-form-exposure"
                      value={formData.exposure}
                      onChange={(e) => setFormData({ ...formData, exposure: e.target.value as AssetExposure })}
                      className="w-full bg-[#090F1C] border border-slate-700/80 text-slate-200 text-xs px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-cyan-500"
                    >
                      <option value="INTERNAL">INTERNAL (VPC / LAN)</option>
                      <option value="INTERNET">INTERNET (Public)</option>
                      <option value="RESTRICTED">RESTRICTED (Air-gapped)</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-[10px] font-mono uppercase text-slate-400 mb-1">
                      Environment
                    </label>
                    <select
                      id="select-form-environment"
                      value={formData.environment}
                      onChange={(e) => setFormData({ ...formData, environment: e.target.value as AssetEnvironment })}
                      className="w-full bg-[#090F1C] border border-slate-700/80 text-slate-200 text-xs px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-cyan-500"
                    >
                      <option value="Production">Production</option>
                      <option value="Staging">Staging</option>
                      <option value="Testing">Testing</option>
                      <option value="Development">Development</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-[10px] font-mono uppercase text-slate-400 mb-1">
                      Lifecycle Status
                    </label>
                    <select
                      id="select-form-status"
                      value={formData.status}
                      onChange={(e) => setFormData({ ...formData, status: e.target.value as AssetStatus })}
                      className="w-full bg-[#090F1C] border border-slate-700/80 text-slate-200 text-xs px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-cyan-500"
                    >
                      <option value="ACTIVE">ACTIVE</option>
                      <option value="MAINTENANCE">MAINTENANCE</option>
                      <option value="INACTIVE">INACTIVE</option>
                      <option value="DECOMMISSIONED">DECOMMISSIONED</option>
                    </select>
                  </div>
                </div>

                {/* OS & Software */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                      Operating System
                    </label>
                    <input
                      id="input-form-os"
                      type="text"
                      placeholder="e.g. Ubuntu 22.04 LTS / Windows Server 2022"
                      value={formData.operatingSystem}
                      onChange={(e) => setFormData({ ...formData, operatingSystem: e.target.value })}
                      className="w-full bg-[#070B14] border border-slate-700/80 text-white text-xs px-3 py-2 rounded-xl focus:outline-none focus:border-cyan-500"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                      Installed Software / Stack
                    </label>
                    <input
                      id="input-form-software"
                      type="text"
                      placeholder="e.g. NGINX 1.25, OpenSSL 3.0, CrowdStrike Sensor"
                      value={formData.software}
                      onChange={(e) => setFormData({ ...formData, software: e.target.value })}
                      className="w-full bg-[#070B14] border border-slate-700/80 text-white text-xs px-3 py-2 rounded-xl focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>

                {/* Owner, Department, Location */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div>
                    <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                      Owner / Point of Contact
                    </label>
                    <input
                      id="input-form-owner"
                      type="text"
                      placeholder="e.g. DevOps Lead"
                      value={formData.owner}
                      onChange={(e) => setFormData({ ...formData, owner: e.target.value })}
                      className="w-full bg-[#070B14] border border-slate-700/80 text-white text-xs px-3 py-2 rounded-xl focus:outline-none focus:border-cyan-500"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                      Department
                    </label>
                    <input
                      id="input-form-department"
                      type="text"
                      placeholder="e.g. Platform Engineering"
                      value={formData.department}
                      onChange={(e) => setFormData({ ...formData, department: e.target.value })}
                      className="w-full bg-[#070B14] border border-slate-700/80 text-white text-xs px-3 py-2 rounded-xl focus:outline-none focus:border-cyan-500"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                      Location / Region
                    </label>
                    <input
                      id="input-form-location"
                      type="text"
                      placeholder="e.g. US-East (N. Virginia)"
                      value={formData.location}
                      onChange={(e) => setFormData({ ...formData, location: e.target.value })}
                      className="w-full bg-[#070B14] border border-slate-700/80 text-white text-xs px-3 py-2 rounded-xl focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>

                {/* Tags & Description */}
                <div>
                  <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                    Tags (comma-separated)
                  </label>
                  <input
                    id="input-form-tags"
                    type="text"
                    placeholder="e.g. edge, api-gateway, pci-dss, tier-1"
                    value={formData.tags}
                    onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
                    className="w-full bg-[#070B14] border border-slate-700/80 text-white text-xs px-3 py-2 rounded-xl focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                    Operational Description & Notes
                  </label>
                  <textarea
                    id="input-form-description"
                    rows={3}
                    placeholder="Describe role, function, backup frequency, security controls..."
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    className="w-full bg-[#070B14] border border-slate-700/80 text-white text-xs p-3 rounded-xl focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              {/* Modal Footer */}
              <div className="px-6 py-3.5 border-t border-slate-800 bg-[#080D1A] flex justify-end gap-2.5">
                <button
                  type="button"
                  onClick={() => setFormModalOpen(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold transition-colors"
                >
                  Cancel
                </button>
                <button
                  id="btn-submit-asset-form"
                  type="submit"
                  disabled={submitting}
                  className="px-5 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold transition-all flex items-center gap-1.5 shadow-md shadow-cyan-950/50 disabled:opacity-50 cursor-pointer"
                >
                  {submitting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>{isEditing ? "Save Changes" : "Create Asset"}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteModalOpen && assetToDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="w-full max-w-md bg-[#090F1C] border border-red-900/50 rounded-2xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center gap-3 text-red-400">
              <div className="p-2.5 rounded-xl bg-red-950/80 border border-red-500/40">
                <Trash2 className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  Confirm Asset Deletion
                </h3>
                <span className="text-[10px] text-red-300 font-mono">Irreversible Operation</span>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Are you sure you want to remove <strong className="text-white">"{assetToDelete.name}"</strong> (<span className="font-mono text-cyan-400">{assetToDelete.id}</span>) from the active enterprise asset inventory?
            </p>

            <div className="p-3 bg-[#070B14] rounded-xl border border-slate-800 text-[11px] font-mono text-slate-400 space-y-1">
              <div>Type: <span className="text-slate-200">{assetToDelete.assetType}</span></div>
              <div>IP: <span className="text-slate-200">{assetToDelete.ipAddress || "N/A"}</span></div>
              <div>Criticality: <span className="text-red-400 font-bold">{assetToDelete.criticality}</span></div>
            </div>

            <div className="flex justify-end gap-2.5 pt-2">
              <button
                type="button"
                onClick={() => {
                  setDeleteModalOpen(false);
                  setAssetToDelete(null);
                }}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold transition-colors"
              >
                Cancel
              </button>
              <button
                id="btn-confirm-delete-asset"
                type="button"
                onClick={handleConfirmDelete}
                disabled={submitting}
                className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-xl text-xs font-bold transition-colors flex items-center gap-1.5"
              >
                {submitting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                <span>Delete Asset</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

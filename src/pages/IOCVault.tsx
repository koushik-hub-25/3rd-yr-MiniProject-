import React, { useEffect, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent, Badge } from "../components/ui";
import {
  Database,
  Search,
  Filter,
  Copy,
  Check,
  Download,
  ShieldAlert,
  FileText,
  RefreshCw,
  ExternalLink,
  Code,
  FileSpreadsheet,
  Plus,
  Crosshair,
  Server,
  Zap,
  Trash2,
  Lock,
  Globe,
  Hash,
  AlertTriangle,
  ArrowRight
} from "lucide-react";
import type { IOC, IocDetailResponse } from "../types";
import { Link } from "react-router-dom";
import IocInvestigationModal from "../components/IocInvestigationModal";
import AddIocModal from "../components/AddIocModal";

export default function IOCVault() {
  const [iocsList, setIocsList] = useState<IOC[]>([]);
  const [search, setSearch] = useState("");
  const [selectedType, setSelectedType] = useState("ALL");
  const [selectedSeverity, setSelectedSeverity] = useState("ALL");
  const [minConfidence, setMinConfidence] = useState<number>(0);
  const [useDefanged, setUseDefanged] = useState<boolean>(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Live Analyst Triage Input
  const [triageInput, setTriageInput] = useState("");
  const [triageLoading, setTriageLoading] = useState(false);
  const [detectedType, setDetectedType] = useState<string | null>(null);

  // Modals
  const [investigationDossier, setInvestigationDossier] = useState<IocDetailResponse | null>(null);
  const [isInvestigationOpen, setIsInvestigationOpen] = useState(false);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);

  const fetchIOCs = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (search.trim()) params.set("search", search.trim());
      if (selectedType !== "ALL") params.set("type", selectedType);
      if (selectedSeverity !== "ALL") params.set("severity", selectedSeverity);
      if (minConfidence > 0) params.set("minConfidence", minConfidence.toString());

      const res = await fetch(`/api/iocs?${params.toString()}`);
      const data = await res.json();
      setIocsList(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error(e);
      setIocsList([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIOCs();
  }, [selectedType, selectedSeverity, minConfidence]);

  // Debounced search
  useEffect(() => {
    const timer = setTimeout(() => {
      fetchIOCs();
    }, 250);
    return () => clearTimeout(timer);
  }, [search]);

  // Live Triage Type Auto-detection
  useEffect(() => {
    if (!triageInput.trim()) {
      setDetectedType(null);
      return;
    }
    const clean = triageInput.replace(/\[\.\]/g, ".").replace(/\[@\]/g, "@").trim();
    if (/^CVE-\d{4}-\d{4,8}$/i.test(clean)) setDetectedType("CVE");
    else if (/^[a-fA-F0-9]{64}$/.test(clean)) setDetectedType("SHA256");
    else if (/^[a-fA-F0-9]{40}$/.test(clean)) setDetectedType("SHA1");
    else if (/^[a-fA-F0-9]{32}$/.test(clean)) setDetectedType("MD5");
    else if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(clean)) setDetectedType("IPv4");
    else if (/:/.test(clean) && /^[a-fA-F0-9:]+$/.test(clean)) setDetectedType("IPv6");
    else if (/^https?:\/\//i.test(clean)) setDetectedType("URL");
    else if (/@/.test(clean) && /\.[a-z]{2,}$/i.test(clean)) setDetectedType("Email");
    else if (/^HKLM|^HKCU/i.test(clean)) setDetectedType("Registry");
    else if (/\.(exe|dll|sys|jsp|bin|elf|sh|ps1)$/i.test(clean)) setDetectedType("Filename");
    else if (/\.[a-z]{2,}$/i.test(clean)) setDetectedType("Domain");
    else setDetectedType("Artifact");
  }, [triageInput]);

  const runLiveTriage = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!triageInput.trim()) return;

    try {
      setTriageLoading(true);
      const res = await fetch("/api/iocs/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ioc: triageInput.trim() })
      });
      if (!res.ok) throw new Error("Lookup failed");
      const dossier = await res.json();
      setInvestigationDossier(dossier);
      setIsInvestigationOpen(true);
    } catch (err) {
      console.error("Live triage error:", err);
    } finally {
      setTriageLoading(false);
    }
  };

  const openInvestigation = async (iocId: string) => {
    try {
      const res = await fetch(`/api/iocs/${iocId}`);
      if (!res.ok) throw new Error("Failed to load IOC dossier");
      const data = await res.json();
      setInvestigationDossier(data);
      setIsInvestigationOpen(true);
    } catch (err) {
      console.error(err);
    }
  };

  const deleteIOC = async (id: string) => {
    if (!confirm("Remove this indicator from the intelligence repository?")) return;
    try {
      const res = await fetch(`/api/iocs/${id}`, { method: "DELETE" });
      if (res.ok) {
        setIocsList(prev => prev.filter(i => i.id !== id));
      }
    } catch (e) {
      console.error("Delete failed", e);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const exportCSV = () => {
    const headers = ["Type", "Value", "Severity", "Confidence", "ReputationScore", "Context", "Tags", "ThreatID", "ReportID"];
    const rows = iocsList.map(i => [
      `"${i.type}"`,
      `"${i.value}"`,
      `"${i.severity || "HIGH"}"`,
      i.confidence,
      i.reputationScore || 85,
      `"${(i.context || "").replace(/"/g, '""')}"`,
      `"${(i.tags || "").toString()}"`,
      `"${i.threatId || ""}"`,
      `"${i.reportId || ""}"`
    ]);
    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `shieldzen-iocs-${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  const exportSTIX = () => {
    const stixBundle = {
      type: "bundle",
      id: `bundle--${Math.random().toString(36).substring(2, 10)}`,
      spec_version: "2.1",
      objects: iocsList.map(i => ({
        type: "indicator",
        spec_version: "2.1",
        id: `indicator--${i.id}`,
        created: new Date().toISOString(),
        modified: new Date().toISOString(),
        name: `${i.type} Indicator: ${i.value}`,
        description: i.context || "Identified cyber threat indicator extracted by ShieldZen",
        indicator_types: [i.type.toLowerCase()],
        pattern: `[${i.type.toLowerCase()}:value = '${i.value}']`,
        pattern_type: "stix",
        confidence: i.confidence
      }))
    };

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(stixBundle, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `shieldzen-stix2.1-bundle-${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Stats
  const criticalCount = iocsList.filter(i => i.severity === "CRITICAL").length;
  const highCount = iocsList.filter(i => i.severity === "HIGH").length;
  const threatLinkedCount = iocsList.filter(i => i.threatId).length;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="bg-emerald-600/20 text-emerald-400 text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase border border-emerald-500/30">
              Analyst Investigation Workspace
            </span>
            <span className="bg-blue-600/20 text-blue-400 text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase border border-blue-500/30">
              STIX 2.1 Compatible
            </span>
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Indicators of Compromise & Investigation</h1>
          <p className="text-slate-400 text-sm mt-1">
            Centralized intelligence index covering 11 artifact types with multi-source enrichment, blast radius correlation, and detection rule synthesis.
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          <button
            onClick={() => setIsAddModalOpen(true)}
            className="inline-flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white px-3.5 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider transition-colors shadow-md shadow-blue-600/30"
          >
            <Plus className="w-3.5 h-3.5" /> Add Indicator
          </button>
          <button
            onClick={exportCSV}
            className="inline-flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 px-3.5 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider border border-slate-700 transition-colors"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" /> Export CSV
          </button>
          <button
            onClick={exportSTIX}
            className="inline-flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 px-3.5 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider border border-slate-700 transition-colors"
          >
            <Code className="w-3.5 h-3.5 text-blue-400" /> Export STIX 2.1
          </button>
          <button
            onClick={fetchIOCs}
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 transition-colors"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Summary KPI Stats Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-[#090e1a]/80 border-slate-800">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <span className="text-slate-500 text-[10px] uppercase font-mono font-bold block">Tracked Indicators</span>
              <span className="text-2xl font-bold text-white font-mono">{iocsList.length}</span>
            </div>
            <div className="p-2.5 bg-blue-950/60 rounded-lg border border-blue-500/30">
              <Database className="w-5 h-5 text-blue-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-[#090e1a]/80 border-slate-800">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <span className="text-slate-500 text-[10px] uppercase font-mono font-bold block">Critical Severity</span>
              <span className="text-2xl font-bold text-red-400 font-mono">{criticalCount}</span>
            </div>
            <div className="p-2.5 bg-red-950/60 rounded-lg border border-red-500/30">
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-[#090e1a]/80 border-slate-800">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <span className="text-slate-500 text-[10px] uppercase font-mono font-bold block">High Severity</span>
              <span className="text-2xl font-bold text-orange-400 font-mono">{highCount}</span>
            </div>
            <div className="p-2.5 bg-orange-950/60 rounded-lg border border-orange-500/30">
              <ShieldAlert className="w-5 h-5 text-orange-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-[#090e1a]/80 border-slate-800">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <span className="text-slate-500 text-[10px] uppercase font-mono font-bold block">Threat Linked</span>
              <span className="text-2xl font-bold text-purple-400 font-mono">{threatLinkedCount}</span>
            </div>
            <div className="p-2.5 bg-purple-950/60 rounded-lg border border-purple-500/30">
              <Crosshair className="w-5 h-5 text-purple-400" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Live Analyst On-Demand Triage Box */}
      <Card className="border-blue-500/40 bg-gradient-to-r from-blue-950/30 via-slate-900/60 to-purple-950/20 shadow-lg">
        <CardContent className="p-5">
          <form onSubmit={runLiveTriage} className="flex flex-col md:flex-row items-center gap-3">
            <div className="flex items-center gap-2 text-blue-400 font-mono font-bold text-xs shrink-0">
              <Zap className="w-4 h-4 animate-pulse" />
              <span>LIVE ARTIFACT TRIAGE:</span>
            </div>

            <div className="relative flex-1 w-full">
              <input
                type="text"
                placeholder="Paste any IP, C2 domain, SHA256/MD5 hash, URL, CVE, or Windows registry key..."
                value={triageInput}
                onChange={e => setTriageInput(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-3 pr-24 py-2.5 text-xs text-white placeholder-slate-500 focus:ring-2 focus:ring-blue-500 outline-none font-mono"
              />
              {detectedType && (
                <div className="absolute right-2.5 top-1/2 -translate-y-1/2">
                  <span className="px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-500/40 text-[10px] font-mono font-bold">
                    {detectedType}
                  </span>
                </div>
              )}
            </div>

            <button
              type="submit"
              disabled={triageLoading || !triageInput.trim()}
              className="w-full md:w-auto inline-flex items-center justify-center gap-2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 disabled:opacity-50 text-white px-5 py-2.5 rounded-lg text-xs font-bold uppercase tracking-wider font-mono transition-all shadow-md shrink-0"
            >
              {triageLoading ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Enriching...</span>
                </>
              ) : (
                <>
                  <Crosshair className="w-3.5 h-3.5" />
                  <span>Investigate Indicator</span>
                </>
              )}
            </button>
          </form>
        </CardContent>
      </Card>

      {/* Filter Toolbar */}
      <Card>
        <CardContent className="p-4 flex flex-col md:flex-row items-center gap-4">
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search indicators, tags, threat context, or hash prefix..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:ring-1 focus:ring-blue-500 outline-none font-mono"
            />
          </div>

          <div className="flex items-center gap-3 w-full md:w-auto flex-wrap">
            <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
              <Filter className="w-3.5 h-3.5" />
              <span>Type:</span>
            </div>
            <select
              value={selectedType}
              onChange={e => setSelectedType(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:ring-1 focus:ring-blue-500 outline-none font-mono"
            >
              <option value="ALL">All 11 Types</option>
              <option value="IPv4">IPv4</option>
              <option value="IPv6">IPv6</option>
              <option value="Domain">Domain</option>
              <option value="URL">URL</option>
              <option value="SHA256">SHA256</option>
              <option value="SHA1">SHA1</option>
              <option value="MD5">MD5</option>
              <option value="CVE">CVE</option>
              <option value="Filename">Filename</option>
              <option value="Registry">Registry</option>
              <option value="Email">Email</option>
            </select>

            <select
              value={selectedSeverity}
              onChange={e => setSelectedSeverity(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:ring-1 focus:ring-blue-500 outline-none font-mono"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            <button
              onClick={() => setUseDefanged(!useDefanged)}
              className={`px-3 py-2 rounded-lg text-xs font-mono border transition-colors flex items-center gap-1.5 ${
                useDefanged
                  ? "bg-amber-950/60 text-amber-300 border-amber-500/40"
                  : "bg-slate-950 text-slate-400 border-slate-800 hover:text-white"
              }`}
              title="Toggle [.] defanging for safe rendering and copying"
            >
              <Lock className="w-3 h-3" />
              <span>{useDefanged ? "Defanged [.]" : "Raw Mode"}</span>
            </button>
          </div>
        </CardContent>
      </Card>

      {/* IOCs Table */}
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse font-mono">
            <thead>
              <tr className="bg-[#090E1A] border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
                <th className="p-4 font-sans">Type & Severity</th>
                <th className="p-4 font-sans">Artifact Value</th>
                <th className="p-4 font-sans">Threat Role & Context</th>
                <th className="p-4 font-sans">Correlations</th>
                <th className="p-4 font-sans">Confidence</th>
                <th className="p-4 font-sans text-right">Analyst Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {iocsList.map(ioc => {
                // Type badge coloring
                let typeBadge = "bg-blue-950 text-blue-400 border-blue-500/30";
                if (ioc.type === "IPv4" || ioc.type === "IPv6") typeBadge = "bg-emerald-950 text-emerald-400 border-emerald-500/30";
                else if (ioc.type === "SHA256" || ioc.type === "SHA1" || ioc.type === "MD5") typeBadge = "bg-purple-950 text-purple-400 border-purple-500/30";
                else if (ioc.type === "CVE") typeBadge = "bg-red-950 text-red-400 border-red-500/30";
                else if (ioc.type === "Domain" || ioc.type === "URL") typeBadge = "bg-cyan-950 text-cyan-400 border-cyan-500/30";
                else if (ioc.type === "Registry") typeBadge = "bg-amber-950 text-amber-400 border-amber-500/30";

                const severity = ioc.severity || "HIGH";
                let sevBadge = "bg-slate-800 text-slate-300 border-slate-700";
                if (severity === "CRITICAL") sevBadge = "bg-red-950/80 text-red-400 border-red-500/40";
                else if (severity === "HIGH") sevBadge = "bg-orange-950/80 text-orange-400 border-orange-500/40";
                else if (severity === "MEDIUM") sevBadge = "bg-amber-950/80 text-amber-400 border-amber-500/40";

                const displayVal = useDefanged && (ioc as any).defangedValue ? (ioc as any).defangedValue : ioc.value;

                return (
                  <tr key={ioc.id} className="hover:bg-slate-900/50 transition-colors group">
                    <td className="p-4 whitespace-nowrap">
                      <div className="flex flex-col gap-1 items-start">
                        <span className={`px-2 py-0.5 rounded border text-[10px] font-bold uppercase ${typeBadge}`}>
                          {ioc.type}
                        </span>
                        <span className={`px-1.5 py-0.5 rounded border text-[9px] font-bold uppercase ${sevBadge}`}>
                          {severity}
                        </span>
                      </div>
                    </td>

                    <td className="p-4">
                      <div className="flex items-center gap-2">
                        <span className="text-white font-semibold select-all break-all text-xs">
                          {displayVal}
                        </span>
                      </div>
                      {ioc.tags && (
                        <div className="text-[10px] text-slate-500 mt-1 flex items-center gap-1">
                          <span>Tags:</span>
                          <span className="text-slate-400">{ioc.tags.toString()}</span>
                        </div>
                      )}
                    </td>

                    <td className="p-4 text-slate-300 font-sans text-xs max-w-xs">
                      <div className="line-clamp-2">{ioc.context || "Observed Incident Artifact"}</div>
                    </td>

                    <td className="p-4 whitespace-nowrap">
                      <div className="flex flex-col gap-1 text-[11px]">
                        {ioc.threatTitle && (
                          <Link
                            to={`/threats/${ioc.threatId}`}
                            className="text-blue-400 hover:underline flex items-center gap-1 truncate max-w-[180px]"
                            title={ioc.threatTitle}
                          >
                            <Crosshair className="w-3 h-3 shrink-0" />
                            <span className="truncate">{ioc.threatTitle}</span>
                          </Link>
                        )}
                        {ioc.reportTitle && (
                          <Link
                            to={`/reports/${ioc.reportId}`}
                            className="text-purple-400 hover:underline flex items-center gap-1 truncate max-w-[180px]"
                            title={ioc.reportTitle}
                          >
                            <FileText className="w-3 h-3 shrink-0" />
                            <span className="truncate">{ioc.reportTitle}</span>
                          </Link>
                        )}
                        {!ioc.threatTitle && !ioc.reportTitle && (
                          <span className="text-slate-500">Telemetry Feed</span>
                        )}
                      </div>
                    </td>

                    <td className="p-4 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className="text-emerald-400 font-bold">{ioc.confidence}%</span>
                      </div>
                      <div className="text-[10px] text-slate-500">Rep: {ioc.reputationScore || 85}/100</div>
                    </td>

                    <td className="p-4 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => openInvestigation(ioc.id)}
                          className="inline-flex items-center gap-1 bg-blue-600/20 hover:bg-blue-600 text-blue-400 hover:text-white px-2.5 py-1 rounded text-[11px] font-sans border border-blue-500/30 transition-all font-semibold"
                          title="Open Analyst Investigation Workbench"
                        >
                          <Crosshair className="w-3 h-3" />
                          <span>Investigate</span>
                        </button>

                        <button
                          onClick={() => copyToClipboard(displayVal, ioc.id)}
                          className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded text-[11px] font-sans border border-slate-700 transition-colors"
                          title="Copy Artifact Value"
                        >
                          {copiedId === ioc.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        </button>

                        <button
                          onClick={() => deleteIOC(ioc.id)}
                          className="p-1.5 bg-slate-800 hover:bg-red-900/60 text-slate-400 hover:text-red-300 rounded border border-slate-700 transition-colors"
                          title="Delete Indicator"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}

              {iocsList.length === 0 && !loading && (
                <tr>
                  <td colSpan={6} className="p-12 text-center text-slate-500 font-sans text-xs">
                    No Indicators of Compromise matched your filter criteria.
                  </td>
                </tr>
              )}

              {loading && (
                <tr>
                  <td colSpan={6} className="p-12 text-center text-slate-400 font-sans text-xs">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-blue-500" />
                    Loading intelligence indicators...
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Investigation Dossier Modal */}
      <IocInvestigationModal
        dossier={investigationDossier}
        isOpen={isInvestigationOpen}
        onClose={() => {
          setIsInvestigationOpen(false);
          setInvestigationDossier(null);
        }}
        onUpdateIoc={() => fetchIOCs()}
      />

      {/* Manual Indicator Registration Modal */}
      <AddIocModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onSuccess={() => fetchIOCs()}
      />
    </div>
  );
}

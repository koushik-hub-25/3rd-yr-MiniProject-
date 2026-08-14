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
  FileSpreadsheet
} from "lucide-react";
import type { IOC } from "../types";
import { Link } from "react-router-dom";

export default function IOCVault() {
  const [iocsList, setIocsList] = useState<IOC[]>([]);
  const [search, setSearch] = useState("");
  const [selectedType, setSelectedType] = useState("ALL");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedAll, setCopiedAll] = useState(false);
  const [loading, setLoading] = useState(true);

  const fetchIOCs = async () => {
    try {
      setLoading(true);
      const res = await fetch("/api/iocs");
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
  }, []);

  const copyToClipboard = (text: string, id?: string) => {
    navigator.clipboard.writeText(text);
    if (id) {
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } else {
      setCopiedAll(true);
      setTimeout(() => setCopiedAll(false), 2000);
    }
  };

  const types = Array.from(new Set(iocsList.map(i => i.type))).filter(Boolean);

  const filtered = iocsList.filter(i => {
    const matchesSearch =
      i.value.toLowerCase().includes(search.toLowerCase()) ||
      i.type.toLowerCase().includes(search.toLowerCase()) ||
      (i.context && i.context.toLowerCase().includes(search.toLowerCase()));
    const matchesType = selectedType === "ALL" || i.type === selectedType;
    return matchesSearch && matchesType;
  });

  const exportCSV = () => {
    const headers = ["Type", "Value", "Context", "Confidence", "ThreatID", "ReportID"];
    const rows = filtered.map(i => [
      `"${i.type}"`,
      `"${i.value}"`,
      `"${i.context || ""}"`,
      i.confidence,
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
      objects: filtered.map(i => ({
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

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="bg-emerald-600/20 text-emerald-400 text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase border border-emerald-500/30">
              Indicator Repository
            </span>
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Indicators of Compromise (IOC Vault)</h1>
          <p className="text-slate-400 text-sm mt-1">
            Centralized index of machine-readable threat artifacts extracted by AI: IPs, C2 Domains, SHA256 Hashes, CVEs & URLs.
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          <button
            onClick={exportCSV}
            className="inline-flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 px-3.5 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider border border-slate-700 transition-colors"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" /> Export CSV
          </button>
          <button
            onClick={exportSTIX}
            className="inline-flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white px-3.5 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider transition-colors shadow-md shadow-blue-600/30"
          >
            <Code className="w-3.5 h-3.5" /> Export STIX 2.1
          </button>
          <button
            onClick={fetchIOCs}
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <Card>
        <CardContent className="p-4 flex flex-col md:flex-row items-center gap-4">
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search IOC value, IP address, SHA256, CVE ID, domain..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:ring-1 focus:ring-blue-500 outline-none font-mono"
            />
          </div>

          <div className="flex items-center gap-3 w-full md:w-auto">
            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <Filter className="w-3.5 h-3.5" />
              <span>Type:</span>
            </div>
            <select
              value={selectedType}
              onChange={e => setSelectedType(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:ring-1 focus:ring-blue-500 outline-none font-mono"
            >
              <option value="ALL">All Types ({iocsList.length})</option>
              {types.map(t => (
                <option key={t} value={t}>
                  {t} ({iocsList.filter(i => i.type === t).length})
                </option>
              ))}
            </select>
          </div>
        </CardContent>
      </Card>

      {/* IOCs Table */}
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse font-mono">
            <thead>
              <tr className="bg-[#090E1A] border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
                <th className="p-4 font-sans">Indicator Type</th>
                <th className="p-4 font-sans">Artifact Value</th>
                <th className="p-4 font-sans">Threat Role / Context</th>
                <th className="p-4 font-sans">AI Confidence</th>
                <th className="p-4 font-sans text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filtered.map(ioc => {
                let typeBadge = "bg-blue-950 text-blue-400 border-blue-500/30";
                if (ioc.type === "IPv4" || ioc.type === "IPv6") typeBadge = "bg-emerald-950 text-emerald-400 border-emerald-500/30";
                else if (ioc.type === "SHA256" || ioc.type === "MD5") typeBadge = "bg-purple-950 text-purple-400 border-purple-500/30";
                else if (ioc.type === "CVE") typeBadge = "bg-red-950 text-red-400 border-red-500/30";
                else if (ioc.type === "Domain") typeBadge = "bg-cyan-950 text-cyan-400 border-cyan-500/30";

                return (
                  <tr key={ioc.id} className="hover:bg-slate-900/50 transition-colors">
                    <td className="p-4 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded border text-[10px] font-bold uppercase ${typeBadge}`}>
                        {ioc.type}
                      </span>
                    </td>
                    <td className="p-4">
                      <div className="text-white font-semibold select-all break-all">{ioc.value}</div>
                    </td>
                    <td className="p-4 text-slate-300 font-sans text-xs">
                      {ioc.context || "Observed Incident Artifact"}
                    </td>
                    <td className="p-4 whitespace-nowrap">
                      <span className="text-emerald-400 font-bold">{ioc.confidence}%</span>
                    </td>
                    <td className="p-4 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => copyToClipboard(ioc.value, ioc.id)}
                          className="inline-flex items-center gap-1 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white px-2.5 py-1 rounded text-[11px] font-sans border border-slate-700 transition-colors"
                        >
                          {copiedId === ioc.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedId === ioc.id ? "Copied" : "Copy"}</span>
                        </button>
                        {ioc.threatId && (
                          <Link
                            to={`/threats/${ioc.threatId}`}
                            title="View Related Threat Dossier"
                            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-blue-400 hover:text-white rounded border border-slate-700 transition-colors"
                          >
                            <ExternalLink className="w-3 h-3" />
                          </Link>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-500 font-sans text-xs">
                    No Indicators of Compromise match the query.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

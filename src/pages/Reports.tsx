import React, { useEffect, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent, Badge, SeverityBadge, ConfidenceMeter, Modal } from "../components/ui";
import {
  FileText,
  Search,
  RefreshCw,
  Trash2,
  Eye,
  Sparkles,
  ExternalLink,
  Calendar,
  Layers,
  Database,
  Filter,
  CheckCircle2
} from "lucide-react";
import type { Report } from "../types";
import { Link } from "react-router-dom";

export default function Reports() {
  const [reports, setReports] = useState<Report[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState("ALL");
  const [selectedCategory, setSelectedCategory] = useState("ALL");
  const [selectedReport, setSelectedReport] = useState<any>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [reanalyzingId, setReanalyzingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchReports = async () => {
    try {
      setLoading(true);
      const res = await fetch("/api/reports");
      const data = await res.json();
      setReports(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error(e);
      setReports([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const openReportModal = async (id: string) => {
    try {
      const res = await fetch(`/api/reports/${id}`);
      const data = await res.json();
      setSelectedReport(data);
      setIsModalOpen(true);
    } catch (e) {
      console.error(e);
    }
  };

  const deleteReport = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm("Are you sure you want to delete this intelligence report and related records?")) return;
    try {
      await fetch(`/api/reports/${id}`, { method: "DELETE" });
      setReports(reports.filter(r => r.id !== id));
      if (selectedReport?.id === id) setIsModalOpen(false);
    } catch (err) {
      console.error(err);
    }
  };

  const reanalyzeReport = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      setReanalyzingId(id);
      await fetch(`/api/reports/${id}/reanalyze`, { method: "POST" });
      await fetchReports();
      if (selectedReport?.id === id) {
        const updated = await fetch(`/api/reports/${id}`).then(r => r.json());
        setSelectedReport(updated);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setReanalyzingId(null);
    }
  };

  const categories = Array.from(new Set(reports.map(r => r.category))).filter(Boolean);

  const filteredReports = reports.filter(r => {
    const matchesSearch =
      r.filename.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (r.summary && r.summary.toLowerCase().includes(searchQuery.toLowerCase())) ||
      r.category.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = selectedSeverity === "ALL" || r.severity === selectedSeverity;
    const matchesCategory = selectedCategory === "ALL" || r.category === selectedCategory;
    return matchesSearch && matchesSeverity && matchesCategory;
  });

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="bg-blue-600/20 text-blue-400 text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase border border-blue-500/30">
              Intelligence Catalog
            </span>
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Intelligence Reports</h1>
          <p className="text-slate-400 text-sm mt-1">
            Browse, inspect, and re-analyze ingested threat reports, vulnerability disclosures, and incident flashes.
          </p>
        </div>

        <Link
          to="/upload"
          className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white px-4 py-2.5 rounded-lg text-xs font-bold uppercase tracking-wider transition-colors shadow-md shadow-blue-600/30 self-start sm:self-auto"
        >
          <FileText className="w-4 h-4" /> Upload New Report
        </Link>
      </div>

      {/* Filter & Search Bar */}
      <Card>
        <CardContent className="p-4 flex flex-col md:flex-row items-center gap-4">
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search reports by title, keyword, summary..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:ring-1 focus:ring-blue-500 outline-none"
            />
          </div>

          <div className="flex items-center gap-3 w-full md:w-auto">
            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <Filter className="w-3.5 h-3.5" />
              <span>Severity:</span>
            </div>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:ring-1 focus:ring-blue-500 outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:ring-1 focus:ring-blue-500 outline-none"
            >
              <option value="ALL">All Categories</option>
              {categories.map(c => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>

            <button
              onClick={fetchReports}
              title="Refresh"
              className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 transition-colors"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            </button>
          </div>
        </CardContent>
      </Card>

      {/* Reports Table */}
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-[#090E1A] border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
                <th className="p-4">Report Details</th>
                <th className="p-4">Category</th>
                <th className="p-4">Severity</th>
                <th className="p-4">Extracted IOCs</th>
                <th className="p-4">Threats</th>
                <th className="p-4">AI Confidence</th>
                <th className="p-4">Ingested At</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredReports.map((r) => (
                <tr
                  key={r.id}
                  onClick={() => openReportModal(r.id)}
                  className="hover:bg-slate-900/60 cursor-pointer transition-colors"
                >
                  <td className="p-4">
                    <div className="flex items-start gap-3">
                      <div className="p-2 bg-slate-900 rounded border border-slate-800 text-blue-400 shrink-0 mt-0.5">
                        <FileText className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="font-semibold text-white text-sm hover:text-blue-300 transition-colors">
                          {r.filename}
                        </div>
                        <div className="text-[11px] text-slate-400 line-clamp-1 mt-0.5 max-w-md">
                          {r.summary || "Pending analysis summary..."}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="p-4 whitespace-nowrap">
                    <span className="bg-slate-800/80 text-slate-300 px-2 py-0.5 rounded border border-slate-700 font-medium">
                      {r.category}
                    </span>
                  </td>
                  <td className="p-4 whitespace-nowrap">
                    <SeverityBadge severity={r.severity || "HIGH"} />
                  </td>
                  <td className="p-4 whitespace-nowrap font-mono text-emerald-400 font-bold">
                    {r.iocCount || 0} IOCs
                  </td>
                  <td className="p-4 whitespace-nowrap font-mono text-indigo-300 font-bold">
                    {r.threatCount || 0} Threats
                  </td>
                  <td className="p-4 whitespace-nowrap">
                    <ConfidenceMeter confidence={r.aiConfidence || 88} />
                  </td>
                  <td className="p-4 whitespace-nowrap text-slate-400 font-mono text-[11px]">
                    {new Date(r.uploadDate).toLocaleDateString()}
                  </td>
                  <td className="p-4 text-right whitespace-nowrap">
                    <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => openReportModal(r.id)}
                        title="View Full Report"
                        className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded border border-slate-700 transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={(e) => reanalyzeReport(r.id, e)}
                        title="Re-run AI Analysis Pipeline"
                        disabled={reanalyzingId === r.id}
                        className="p-1.5 bg-slate-800 hover:bg-blue-900/40 text-blue-400 hover:text-blue-300 rounded border border-slate-700 transition-colors"
                      >
                        <Sparkles className={`w-3.5 h-3.5 ${reanalyzingId === r.id ? "animate-spin" : ""}`} />
                      </button>
                      <button
                        onClick={(e) => deleteReport(r.id, e)}
                        title="Delete Report"
                        className="p-1.5 bg-slate-800 hover:bg-red-900/40 text-red-400 hover:text-red-300 rounded border border-slate-700 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {filteredReports.length === 0 && (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-slate-400 text-xs">
                    No intelligence reports match the selected filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Report Details Drawer / Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title={selectedReport?.filename || "Intelligence Report Profile"}
        maxWidth="max-w-4xl"
      >
        {selectedReport && (
          <div className="space-y-6">
            {/* Top Metadata */}
            <div className="flex flex-wrap items-center justify-between gap-4 p-4 bg-slate-950 rounded-lg border border-slate-800">
              <div className="flex items-center gap-3">
                <SeverityBadge severity={selectedReport.severity || "HIGH"} />
                <span className="text-xs font-semibold text-slate-300 bg-slate-900 px-2.5 py-1 rounded border border-slate-800">
                  {selectedReport.category}
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  Origin: {selectedReport.sourceOrigin || "OSINT Feed"}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-400">AI Confidence:</span>
                <ConfidenceMeter confidence={selectedReport.aiConfidence || 90} />
              </div>
            </div>

            {/* Executive Summary */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-blue-400" /> Executive Intelligence Summary
              </h4>
              <p className="text-xs text-slate-200 bg-slate-950 p-4 rounded-lg border border-slate-800 leading-relaxed italic">
                "{selectedReport.summary}"
              </p>
            </div>

            {/* Key Findings */}
            {selectedReport.keyFindings && (
              <div className="space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Key High-Impact Findings
                </h4>
                <ul className="space-y-2 bg-slate-950 p-4 rounded-lg border border-slate-800 text-xs text-slate-300">
                  {(() => {
                    try {
                      const list = JSON.parse(selectedReport.keyFindings);
                      return Array.isArray(list) ? (
                        list.map((finding: string, i: number) => (
                          <li key={i} className="flex items-start gap-2">
                            <span className="text-emerald-400 mt-0.5">•</span>
                            <span>{finding}</span>
                          </li>
                        ))
                      ) : (
                        <li>{selectedReport.keyFindings}</li>
                      );
                    } catch {
                      return <li>{selectedReport.keyFindings}</li>;
                    }
                  })()}
                </ul>
              </div>
            )}

            {/* Extracted IOCs */}
            {selectedReport.iocs && selectedReport.iocs.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <Database className="w-4 h-4 text-emerald-400" /> Extracted Indicators of Compromise ({selectedReport.iocs.length})
                </h4>
                <div className="overflow-x-auto bg-slate-950 rounded-lg border border-slate-800">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="p-3">Type</th>
                        <th className="p-3">Indicator Value</th>
                        <th className="p-3">Context / Role</th>
                        <th className="p-3">Confidence</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {selectedReport.iocs.map((ioc: any) => (
                        <tr key={ioc.id}>
                          <td className="p-3 font-mono font-bold text-blue-400">{ioc.type}</td>
                          <td className="p-3 font-mono text-slate-200">{ioc.value}</td>
                          <td className="p-3 text-slate-400">{ioc.context || "Identified Artifact"}</td>
                          <td className="p-3 font-mono text-emerald-400">{ioc.confidence}%</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Raw Report Document View */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <FileText className="w-4 h-4 text-slate-400" /> Ingested Raw Text Document
              </h4>
              <pre className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono text-slate-300 whitespace-pre-wrap max-h-60 overflow-y-auto">
                {selectedReport.rawText}
              </pre>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

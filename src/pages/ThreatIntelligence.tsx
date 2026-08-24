import React, { useState, useEffect } from "react";
import { useSearchParams, Link } from "react-router-dom";
import {
  Shield, AlertTriangle, AlertCircle, Database, Radio, Cpu, Search, Filter,
  ExternalLink, Copy, Check, Sparkles, CheckCircle2, ChevronRight, Layers,
  Terminal, ShieldCheck, Clock, RefreshCw, Bot, ArrowUpRight
} from "lucide-react";
import { Threat, NvdVulnerability, CisaKevEntry, MitreTechnique, CorrelatedThreatIntel } from "../types";
import { Card, CardHeader, CardTitle, CardContent, Badge, SeverityBadge, ConfidenceMeter, SourceBadge, DataOriginLabel, cn } from "../components/ui";
import { SourceFilterBar, SourceFilterType } from "../components/SourceFilterBar";
import { AIAnalystDrawer } from "../components/AIAnalystDrawer";
import { ExplainableRiskScoreCard } from "../components/ExplainableRiskScoreCard";

export default function ThreatIntelligence() {
  const [searchParams] = useSearchParams();
  const [threats, setThreats] = useState<Threat[]>([]);
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("ALL");
  const [selectedSource, setSelectedSource] = useState<SourceFilterType>("ALL");
  const [minConfidence, setMinConfidence] = useState<number>(0);
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);
  const [correlationData, setCorrelationData] = useState<CorrelatedThreatIntel | null>(null);
  const [correlating, setCorrelating] = useState(false);
  const [aiDrawerOpen, setAiDrawerOpen] = useState(false);

  // Fetch threats
  const fetchThreats = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/threats");
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) {
          setThreats(data);
          const initialId = searchParams.get("id");
          if (initialId) {
            const found = data.find(t => t.id === initialId);
            if (found) setSelectedThreat(found);
            else if (data.length > 0) setSelectedThreat(data[0]);
          } else if (data.length > 0) {
            setSelectedThreat(data[0]);
          }
        }
      }
    } catch (e) {
      console.error("Failed to load threats", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
  }, []);

  // Whenever selected threat changes, perform multi-source correlation (NVD + CISA KEV + MITRE)
  useEffect(() => {
    if (!selectedThreat) return;

    let isMounted = true;
    setCorrelating(true);

    const cveCandidates: string[] = [];
    const textToScan = `${selectedThreat.title} ${selectedThreat.description} ${selectedThreat.evidence || ""}`;
    const cveMatches = textToScan.match(/CVE-\d{4}-\d{4,7}/gi) || [];
    cveMatches.forEach(c => {
      if (!cveCandidates.includes(c.toUpperCase())) cveCandidates.push(c.toUpperCase());
    });

    const mitreCandidates: string[] = [];
    if (selectedThreat.mitreTechniques) {
      const parsed = typeof selectedThreat.mitreTechniques === "string"
        ? selectedThreat.mitreTechniques.split(",")
        : selectedThreat.mitreTechniques;
      parsed.forEach((m: string) => mitreCandidates.push(m.trim()));
    }

    fetch("/api/correlate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: textToScan,
        cveCandidates,
        mitreCandidates,
        initialSeverity: selectedThreat.severity,
        threatTitle: selectedThreat.title
      })
    })
      .then(res => res.json())
      .then(data => {
        if (isMounted) {
          setCorrelationData(data);
          setCorrelating(false);
        }
      })
      .catch(() => {
        if (isMounted) setCorrelating(false);
      });

    return () => {
      isMounted = false;
    };
  }, [selectedThreat]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIoc(text);
    setTimeout(() => setCopiedIoc(null), 2000);
  };

  // Filtered threats list
  const filteredThreats = threats.filter(t => {
    if (selectedSeverity !== "ALL" && t.severity !== selectedSeverity) return false;
    if (t.confidence < minConfidence) return false;

    if (selectedSource !== "ALL") {
      const src = (t.source || "").toUpperCase();
      const txt = `${t.title} ${t.description}`.toUpperCase();
      if (selectedSource === "NVD" && !txt.includes("CVE")) return false;
      if (selectedSource === "CISA_KEV" && !txt.includes("EXPLOIT") && !txt.includes("CVE")) return false;
      if (selectedSource === "MITRE" && !t.mitreTechniques) return false;
      if (selectedSource === "REPORTS" && !src.includes("REPORT")) return false;
      if (selectedSource === "AI" && !src.includes("AI")) return false;
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = t.title.toLowerCase().includes(q);
      const matchDesc = (t.description || "").toLowerCase().includes(q);
      const matchCat = (t.category || "").toLowerCase().includes(q);
      const matchReason = (t.reasoning || "").toLowerCase().includes(q);
      return matchTitle || matchDesc || matchCat || matchReason;
    }
    return true;
  });

  return (
    <div className="p-6 sm:p-8 max-w-7xl mx-auto space-y-8">
      {/* Page Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-extrabold text-white tracking-tight">Threat Intelligence Center</h1>
            <span className="text-[11px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded">
              Analyst Workbench
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Deep multi-source correlation across NVD CVEs, CISA KEV catalog, MITRE ATT&CK Matrix, and ShieldZen AI reasoning.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            id="btn-open-analyst-copilot"
            onClick={() => setAiDrawerOpen(true)}
            className="px-3.5 py-2 bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-500 hover:to-indigo-600 text-white rounded-xl text-xs font-bold flex items-center gap-2 shadow-lg shadow-indigo-950/50 transition-all"
          >
            <Bot className="w-4 h-4 text-indigo-200" />
            <span>Ask AI Analyst</span>
          </button>

          <button
            onClick={fetchThreats}
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl transition-colors border border-slate-700"
            title="Refresh Intelligence Data"
          >
            <RefreshCw className={cn("w-4 h-4", loading && "animate-spin text-cyan-400")} />
          </button>
        </div>
      </div>

      {/* Reusable Source Filter Bar */}
      <SourceFilterBar
        activeFilter={selectedSource}
        onFilterChange={setSelectedSource}
        counts={{
          ALL: threats.length,
          NVD: threats.filter(t => (t.title + t.description).includes("CVE")).length,
          CISA_KEV: threats.filter(t => t.severity === "CRITICAL").length,
          MITRE: threats.filter(t => Boolean(t.mitreTechniques)).length,
          REPORTS: threats.filter(t => (t.source || "").includes("Report")).length,
          AI: threats.filter(t => (t.source || "").includes("AI")).length
        }}
      />

      {/* Main 2-Column Analyst Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Filterable Feed (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <Card>
            <CardHeader className="py-3">
              <div className="flex items-center justify-between w-full">
                <CardTitle>
                  <Filter className="w-3.5 h-3.5 text-cyan-400" /> Intelligence Feed ({filteredThreats.length})
                </CardTitle>
                <span className="text-[10px] text-slate-400 font-mono">Correlated CTI Feed</span>
              </div>
            </CardHeader>

            <div className="p-3 border-b border-slate-800/80 bg-[#070B14]/60 space-y-2.5">
              {/* Search */}
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search CVEs, malware, actors, IOCs..."
                  className="w-full bg-[#0B1222] border border-slate-700/70 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-sans"
                />
              </div>

              {/* Severity & Confidence Controls */}
              <div className="flex items-center justify-between gap-2 pt-1 text-[11px]">
                <div className="flex items-center gap-1">
                  {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                    <button
                      key={sev}
                      onClick={() => setSelectedSeverity(sev)}
                      className={cn(
                        "px-2 py-0.5 rounded text-[10px] font-mono font-bold transition-colors",
                        selectedSeverity === sev
                          ? "bg-slate-700 text-white"
                          : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
                      )}
                    >
                      {sev}
                    </button>
                  ))}
                </div>

                <div className="flex items-center gap-1.5 text-slate-400 font-mono text-[10px]">
                  <span>Conf &gt; {minConfidence}%</span>
                  <input
                    type="range"
                    min="0"
                    max="90"
                    step="10"
                    value={minConfidence}
                    onChange={(e) => setMinConfidence(Number(e.target.value))}
                    className="w-14 accent-cyan-400 h-1 bg-slate-800 rounded-lg cursor-pointer"
                  />
                </div>
              </div>
            </div>

            {/* List items */}
            <div className="divide-y divide-slate-800/60 max-h-[620px] overflow-y-auto">
              {loading ? (
                <div className="p-8 text-center text-xs text-slate-500">
                  <RefreshCw className="w-5 h-5 animate-spin text-cyan-400 mx-auto mb-2" />
                  Ingesting threat intelligence feed...
                </div>
              ) : filteredThreats.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-500">
                  No threats match the specified filter criteria.
                </div>
              ) : (
                filteredThreats.map((threat) => {
                  const isSelected = selectedThreat?.id === threat.id;
                  const hasCve = (threat.title + threat.description).includes("CVE");

                  return (
                    <div
                      key={threat.id}
                      onClick={() => setSelectedThreat(threat)}
                      className={cn(
                        "p-4 cursor-pointer transition-all flex flex-col gap-2 relative border-l-2",
                        isSelected
                          ? "bg-slate-800/40 border-l-cyan-400 shadow-inner"
                          : "hover:bg-slate-800/20 border-l-transparent"
                      )}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-[10px] font-mono text-cyan-400 font-bold bg-cyan-950/60 border border-cyan-500/20 px-1.5 py-0.2 rounded">
                              {threat.category}
                            </span>
                            {hasCve && (
                              <span className="text-[9px] font-mono font-bold bg-red-950/80 text-red-300 border border-red-500/30 px-1 py-0.2 rounded">
                                CVE MATCH
                              </span>
                            )}
                          </div>
                          <h4 className={cn("text-xs font-bold truncate", isSelected ? "text-cyan-300" : "text-slate-200")}>
                            {threat.title}
                          </h4>
                        </div>
                        <SeverityBadge severity={threat.severity} />
                      </div>

                      <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                        {threat.description || threat.reasoning}
                      </p>

                      <div className="flex items-center justify-between pt-1 text-[10px] text-slate-500 font-mono">
                        <ConfidenceMeter confidence={threat.confidence} />
                        <SourceBadge source={threat.source || "ShieldZen AI"} />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </Card>
        </div>

        {/* Right Column: Deep Threat Dossier (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {selectedThreat ? (
            <>
              {/* Main Threat Overview Card */}
              <Card className="border-slate-700/80">
                <CardHeader className="bg-[#0D1527] py-4">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 w-full">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <DataOriginLabel origin={selectedThreat.source?.includes("Report") ? "PUBLIC" : "AI"} />
                        <span className="text-[10px] font-mono text-slate-400">ID: {selectedThreat.id}</span>
                      </div>
                      <h2 className="text-base font-extrabold text-white tracking-tight">
                        {selectedThreat.title}
                      </h2>
                    </div>

                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={selectedThreat.severity} />
                      <button
                        onClick={() => setAiDrawerOpen(true)}
                        className="px-2.5 py-1 bg-indigo-950 text-indigo-300 border border-indigo-500/40 rounded-lg text-xs font-bold flex items-center gap-1.5 hover:bg-indigo-900 transition-colors"
                        title="Open AI Analyst for this specific threat"
                      >
                        <Bot className="w-3.5 h-3.5 text-indigo-400" />
                        <span>AI Triage</span>
                      </button>
                    </div>
                  </div>
                </CardHeader>

                <CardContent className="space-y-5">
                  {/* Summary & Reasoning */}
                  <div className="space-y-3">
                    <div>
                      <h4 className="text-[11px] font-bold font-mono uppercase text-slate-400 tracking-wider mb-1">
                        Executive Summary & Threat Description
                      </h4>
                      <p className="text-xs text-slate-200 leading-relaxed bg-[#070B14]/60 p-3 rounded-xl border border-slate-800">
                        {selectedThreat.description || "No description provided."}
                      </p>
                    </div>

                    <div>
                      <h4 className="text-[11px] font-bold font-mono uppercase text-slate-400 tracking-wider mb-1 flex items-center gap-1.5">
                        <Sparkles className="w-3.5 h-3.5 text-cyan-400" /> AI Risk Prioritization & Explainability
                      </h4>
                      <div className="bg-gradient-to-br from-[#0c182c] to-[#091120] border border-cyan-500/30 p-3.5 rounded-xl text-xs text-slate-200 space-y-2">
                        <p className="leading-relaxed">{selectedThreat.reasoning || "Standard threat heuristic scoring."}</p>
                        {selectedThreat.evidence && (
                          <div className="pt-2 border-t border-slate-800 flex items-start gap-2 text-[11px] text-cyan-300 font-mono">
                            <Terminal className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-cyan-400" />
                            <span>Evidence: "{selectedThreat.evidence}"</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Multi-Source Correlation Section */}
                  <div className="pt-2 border-t border-slate-800 space-y-3">
                    <div className="flex items-center justify-between">
                      <h4 className="text-[11px] font-bold font-mono uppercase text-slate-400 tracking-wider flex items-center gap-2">
                        <Layers className="w-3.5 h-3.5 text-cyan-400" /> Multi-Source Intelligence Correlation & Risk Assessment
                      </h4>
                      {correlating && (
                        <span className="text-[10px] text-cyan-400 font-mono flex items-center gap-1">
                          <RefreshCw className="w-3 h-3 animate-spin" /> Correlating feeds...
                        </span>
                      )}
                    </div>

                    {/* Deterministic Explainable Risk Score Card */}
                    {correlationData?.explainableRiskAssessment && (
                      <ExplainableRiskScoreCard
                        assessment={correlationData.explainableRiskAssessment}
                        loading={correlating}
                        showRawFormula={false}
                      />
                    )}

                    {/* NVD Card */}
                    {correlationData?.nvdData && (
                      <div className="p-3.5 rounded-xl bg-[#070F1E] border border-cyan-500/40 space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Database className="w-4 h-4 text-cyan-400" />
                            <span className="text-xs font-bold text-white font-mono">{correlationData.nvdData.cveId}</span>
                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/30 font-mono font-bold">
                              NVD CVSS {correlationData.nvdData.cvssScore}
                            </span>
                          </div>
                          <SeverityBadge severity={correlationData.nvdData.cvssSeverity} />
                        </div>
                        <p className="text-[11px] text-slate-300">{correlationData.nvdData.description}</p>
                        {correlationData.nvdData.affectedProducts?.length > 0 && (
                          <div className="text-[10px] text-slate-400 font-mono flex items-center gap-1 flex-wrap">
                            <span className="text-slate-500 font-bold">Affected:</span>
                            {correlationData.nvdData.affectedProducts.map((p, idx) => (
                              <span key={idx} className="bg-slate-900 border border-slate-800 px-1.5 py-0.5 rounded text-slate-300">
                                {p}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    {/* CISA KEV Card */}
                    {correlationData?.cisaKevData?.isKnownExploited && (
                      <div className="p-3.5 rounded-xl bg-red-950/30 border border-red-500/50 space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Radio className="w-4 h-4 text-red-400 animate-pulse" />
                            <span className="text-xs font-bold text-red-300 font-mono">
                              CISA KNOWN EXPLOITED VULNERABILITY (KEV)
                            </span>
                          </div>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-500/40 font-mono font-bold">
                            WEAPONIZED EXPLOIT
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-300">
                          {correlationData.cisaKevData.entry?.shortDescription}
                        </p>
                        <div className="pt-2 border-t border-red-900/40 flex flex-wrap items-center justify-between gap-2 text-[10px] font-mono">
                          <span className="text-red-400">
                            Required Action Due: <strong>{correlationData.cisaKevData.entry?.dueDate || "Immediate"}</strong>
                          </span>
                          <span className="text-slate-400">
                            Ransomware Link: <strong className="text-red-300">{correlationData.cisaKevData.entry?.knownRansomwareCampaignUse}</strong>
                          </span>
                        </div>
                      </div>
                    )}

                    {/* MITRE ATT&CK Mapping */}
                    {correlationData?.mitreMapping && correlationData.mitreMapping.length > 0 && (
                      <div className="space-y-2">
                        <h5 className="text-[10px] font-mono font-bold uppercase text-slate-400">
                          MITRE ATT&CK Enterprise Matrix Alignment
                        </h5>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          {correlationData.mitreMapping.map(tech => (
                            <div key={tech.id} className="p-2.5 rounded-lg bg-[#070B14] border border-slate-800 space-y-1">
                              <div className="flex items-center justify-between">
                                <span className="text-xs font-bold text-cyan-400 font-mono">{tech.id}</span>
                                <span className="text-[9px] font-mono bg-indigo-950 text-indigo-300 border border-indigo-500/30 px-1 py-0.2 rounded">
                                  {tech.tactic}
                                </span>
                              </div>
                              <div className="text-[11px] font-medium text-slate-200">{tech.name}</div>
                              <p className="text-[10px] text-slate-400 leading-snug line-clamp-2">{tech.detection}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* IOCs Pillbox */}
                  {selectedThreat.iocs && (
                    <div className="pt-2 border-t border-slate-800 space-y-2">
                      <h4 className="text-[11px] font-bold font-mono uppercase text-slate-400 tracking-wider">
                        Extracted Indicators of Compromise (IOCs)
                      </h4>
                      <div className="flex flex-wrap gap-2">
                        {(typeof selectedThreat.iocs === "string" ? JSON.parse(selectedThreat.iocs || "[]") : selectedThreat.iocs).map((ioc: any, idx: number) => {
                          const val = typeof ioc === "string" ? ioc : ioc.value;
                          const typ = typeof ioc === "string" ? "IOC" : ioc.type;

                          return (
                            <div
                              key={idx}
                              className="flex items-center gap-1.5 bg-[#070B14] border border-slate-800 rounded-lg px-2.5 py-1 text-xs font-mono text-slate-300 hover:border-slate-700"
                            >
                              <span className="text-[10px] text-cyan-400 font-bold uppercase">{typ}:</span>
                              <span className="truncate max-w-[200px]">{val}</span>
                              <button
                                onClick={() => copyToClipboard(val)}
                                className="text-slate-500 hover:text-white p-0.5"
                                title="Copy IOC"
                              >
                                {copiedIoc === val ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              </button>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Defensive Action Checklist */}
                  <div className="pt-2 border-t border-slate-800 space-y-2">
                    <h4 className="text-[11px] font-bold font-mono uppercase text-slate-400 tracking-wider flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> SOC Defensive Containment Protocol
                    </h4>
                    <div className="space-y-1.5">
                      {(correlationData?.recommendationMatrix || [
                        "Isolate affected endpoint hosts from production subnets.",
                        "Block correlated hashes and external C2 IP addresses in firewall / proxy.",
                        "Enforce credential rotation for all authenticated identities involved in this attack vector."
                      ]).map((action, idx) => (
                        <div key={idx} className="flex items-start gap-2 text-xs text-slate-300 bg-[#070B14]/40 p-2 rounded-lg border border-slate-800/80">
                          <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0 mt-0.5" />
                          <span>{action}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </>
          ) : (
            <Card className="p-12 text-center text-slate-500">
              Select a threat from the feed on the left to inspect detailed intelligence dossiers.
            </Card>
          )}
        </div>
      </div>

      {/* Global AI Analyst Drawer */}
      <AIAnalystDrawer
        isOpen={aiDrawerOpen}
        onClose={() => setAiDrawerOpen(false)}
        focusedThreatId={selectedThreat?.id}
        initialPrompt={selectedThreat ? `Explain the risk factors and mitigation strategy for "${selectedThreat.title}"` : undefined}
      />
    </div>
  );
}

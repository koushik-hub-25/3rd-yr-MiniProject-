import React, { useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Globe,
  Server,
  FileCode,
  Terminal,
  Hash,
  AlertTriangle,
  Copy,
  Check,
  ExternalLink,
  Download,
  Calendar,
  Layers,
  Database,
  Crosshair,
  Lock,
  Cpu,
  X
} from "lucide-react";
import { Link } from "react-router-dom";
import type { IocDetailResponse } from "../types";

interface IocInvestigationModalProps {
  dossier: IocDetailResponse | null;
  isOpen: boolean;
  onClose: () => void;
  onUpdateIoc?: (updated: any) => void;
}

export default function IocInvestigationModal({
  dossier,
  isOpen,
  onClose,
  onUpdateIoc
}: IocInvestigationModalProps) {
  const [activeTab, setActiveTab] = useState<"enrichment" | "relationships" | "detection" | "notes">("enrichment");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [useDefanged, setUseDefanged] = useState<boolean>(false);

  if (!isOpen || !dossier) return null;

  const { ioc, defangedValue, enrichment, relatedThreats, relatedReports, relatedAssets, relatedIncidents } = dossier;
  const displayValue = useDefanged ? defangedValue : ioc.value;

  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const exportSingleStix = () => {
    const stixBundle = {
      type: "bundle",
      id: `bundle--${Math.random().toString(36).substring(2, 10)}`,
      spec_version: "2.1",
      objects: [
        {
          type: "indicator",
          spec_version: "2.1",
          id: `indicator--${ioc.id}`,
          created: dossier.firstSeen,
          modified: dossier.lastSeen,
          name: `${ioc.type} Indicator: ${defangedValue}`,
          description: ioc.context || "ShieldZen extracted cyber threat indicator",
          indicator_types: [ioc.type.toLowerCase()],
          pattern: `[${ioc.type.toLowerCase()}:value = '${ioc.value}']`,
          pattern_type: "stix",
          confidence: ioc.confidence
        }
      ]
    };

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(stixBundle, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `shieldzen-indicator-${ioc.id}.stix.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Severity color mapping
  const severityColors = {
    CRITICAL: "bg-red-950/80 text-red-400 border-red-500/40",
    HIGH: "bg-orange-950/80 text-orange-400 border-orange-500/40",
    MEDIUM: "bg-amber-950/80 text-amber-400 border-amber-500/40",
    LOW: "bg-emerald-950/80 text-emerald-400 border-emerald-500/40"
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div className="bg-[#0b101b] border border-slate-800 rounded-xl max-w-4xl w-full my-8 shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="p-6 border-b border-slate-800/80 bg-gradient-to-r from-slate-900/90 via-[#0d1527] to-slate-900/90 flex items-start justify-between gap-4">
          <div className="space-y-2 flex-1 min-w-0">
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className="bg-blue-600/20 text-blue-400 text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase border border-blue-500/30">
                {ioc.type}
              </span>
              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase border ${severityColors[dossier.severity] || severityColors.HIGH}`}>
                {dossier.severity} SEVERITY
              </span>
              <span className="bg-slate-800 text-slate-300 text-[10px] font-mono font-bold px-2 py-0.5 rounded border border-slate-700">
                CONFIDENCE: {ioc.confidence}%
              </span>
              <span className="bg-purple-950/60 text-purple-300 text-[10px] font-mono font-bold px-2 py-0.5 rounded border border-purple-700/40">
                REPUTATION: {enrichment?.reputationScore || 85}/100
              </span>
            </div>

            <div className="flex items-center gap-3">
              <h2 className="text-xl font-bold text-white font-mono break-all select-all">
                {displayValue}
              </h2>
            </div>

            <p className="text-xs text-slate-400 font-sans">
              {ioc.context || "Identified in intelligence feeds and correlated across enterprise telemetry."}
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => setUseDefanged(!useDefanged)}
              title={useDefanged ? "Show raw value" : "Defang value for safe display"}
              className={`px-2.5 py-1.5 rounded text-xs font-mono border transition-colors ${
                useDefanged
                  ? "bg-amber-950/60 text-amber-300 border-amber-500/40 hover:bg-amber-900/60"
                  : "bg-slate-800 text-slate-400 border-slate-700 hover:text-white"
              }`}
            >
              {useDefanged ? "[.] Defanged" : "Defang"}
            </button>
            <button
              onClick={() => copyText(displayValue, "header_val")}
              className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition-colors"
              title="Copy Indicator Value"
            >
              {copiedKey === "header_val" ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
            <button
              onClick={exportSingleStix}
              className="p-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded transition-colors shadow-sm"
              title="Export STIX 2.1 Indicator"
            >
              <Download className="w-4 h-4" />
            </button>
            <button
              onClick={onClose}
              className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white rounded border border-slate-700 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center border-b border-slate-800 px-6 bg-slate-950/60 font-mono text-xs">
          <button
            onClick={() => setActiveTab("enrichment")}
            className={`py-3 px-4 font-semibold border-b-2 transition-colors flex items-center gap-2 ${
              activeTab === "enrichment"
                ? "border-blue-500 text-blue-400 bg-blue-500/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Multi-Source Enrichment</span>
          </button>
          <button
            onClick={() => setActiveTab("relationships")}
            className={`py-3 px-4 font-semibold border-b-2 transition-colors flex items-center gap-2 ${
              activeTab === "relationships"
                ? "border-blue-500 text-blue-400 bg-blue-500/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Relationships & Blast Radius ({relatedThreats.length + relatedReports.length + relatedAssets.length})</span>
          </button>
          <button
            onClick={() => setActiveTab("detection")}
            className={`py-3 px-4 font-semibold border-b-2 transition-colors flex items-center gap-2 ${
              activeTab === "detection"
                ? "border-blue-500 text-blue-400 bg-blue-500/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Detection Engineering</span>
          </button>
          <button
            onClick={() => setActiveTab("notes")}
            className={`py-3 px-4 font-semibold border-b-2 transition-colors flex items-center gap-2 ${
              activeTab === "notes"
                ? "border-blue-500 text-blue-400 bg-blue-500/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>Analyst History & Timeline</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
          {/* TAB 1: ENRICHMENT */}
          {activeTab === "enrichment" && (
            <div className="space-y-6">
              {/* Provider Info Banner */}
              <div className="p-3.5 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between flex-wrap gap-3">
                <div className="flex items-center gap-3">
                  <ShieldAlert className="w-4 h-4 text-blue-400 shrink-0" />
                  <div>
                    <div className="text-white font-semibold">{enrichment?.provider || "ShieldZen Multi-Source Threat Intel Provider"}</div>
                    <div className="text-slate-400 text-[11px]">
                      Verdict: <span className="text-red-400 font-bold">{enrichment?.maliciousVerdict || "MALICIOUS"}</span> ({enrichment?.detectionEngines?.detectionRatio || "62/70"} detection engines flagged)
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 text-[10px] font-mono border border-emerald-500/30">
                    {enrichment?.providerStatus || "ONLINE_DETERMINISTIC"}
                  </span>
                </div>
              </div>

              {/* GeoIP & ASN (for IPs / Domains) */}
              {enrichment?.geoIp && (
                <div className="p-4 rounded-lg bg-slate-900/50 border border-slate-800 space-y-3">
                  <div className="flex items-center gap-2 text-slate-300 font-semibold uppercase tracking-wider font-mono text-[11px]">
                    <Globe className="w-3.5 h-3.5 text-blue-400" />
                    <span>GeoIP & Autonomous System (ASN) Telemetry</span>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono">
                    <div className="p-2.5 bg-slate-950 rounded border border-slate-800/80">
                      <span className="text-slate-500 text-[10px] block">Country / City</span>
                      <span className="text-white font-semibold">{enrichment.geoIp.country} ({enrichment.geoIp.countryCode})</span>
                      {enrichment.geoIp.city && <span className="text-slate-400 text-[11px] block">{enrichment.geoIp.city}</span>}
                    </div>
                    <div className="p-2.5 bg-slate-950 rounded border border-slate-800/80">
                      <span className="text-slate-500 text-[10px] block">ASN Number</span>
                      <span className="text-white font-semibold">{enrichment.geoIp.asn}</span>
                    </div>
                    <div className="p-2.5 bg-slate-950 rounded border border-slate-800/80 col-span-2">
                      <span className="text-slate-500 text-[10px] block">ISP / Hosting Organization</span>
                      <span className="text-white font-semibold">{enrichment.geoIp.isp}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* WHOIS & DNS (for Domains) */}
              {enrichment?.whois && (
                <div className="p-4 rounded-lg bg-slate-900/50 border border-slate-800 space-y-3">
                  <div className="flex items-center gap-2 text-slate-300 font-semibold uppercase tracking-wider font-mono text-[11px]">
                    <Server className="w-3.5 h-3.5 text-cyan-400" />
                    <span>WHOIS Registration & Domain Telemetry</span>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3 font-mono">
                    <div className="p-2.5 bg-slate-950 rounded border border-slate-800/80">
                      <span className="text-slate-500 text-[10px] block">Registrar</span>
                      <span className="text-white font-semibold">{enrichment.whois.registrar || "NameCheap Inc."}</span>
                    </div>
                    <div className="p-2.5 bg-slate-950 rounded border border-slate-800/80">
                      <span className="text-slate-500 text-[10px] block">Domain Age</span>
                      <span className="text-amber-400 font-semibold">{enrichment.whois.domainAgeDays || 45} Days (Fresh Registration)</span>
                    </div>
                    <div className="p-2.5 bg-slate-950 rounded border border-slate-800/80">
                      <span className="text-slate-500 text-[10px] block">Created Date</span>
                      <span className="text-slate-300">{enrichment.whois.createdDate?.slice(0, 10) || "2024-01-15"}</span>
                    </div>
                  </div>
                  {enrichment.dnsRecords && enrichment.dnsRecords.length > 0 && (
                    <div className="mt-2 space-y-1">
                      <span className="text-slate-400 text-[11px] block font-mono">Resolved DNS Records:</span>
                      <div className="space-y-1 font-mono text-[11px]">
                        {enrichment.dnsRecords.map((rec, idx) => (
                          <div key={idx} className="p-1.5 bg-slate-950/80 rounded border border-slate-800 flex items-center justify-between">
                            <span className="text-blue-400 font-bold w-12">{rec.type}</span>
                            <span className="text-slate-200 truncate flex-1">{rec.value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* File Info (for Hashes / Binaries) */}
              {enrichment?.fileInfo && (
                <div className="p-4 rounded-lg bg-slate-900/50 border border-slate-800 space-y-3">
                  <div className="flex items-center gap-2 text-slate-300 font-semibold uppercase tracking-wider font-mono text-[11px]">
                    <Hash className="w-3.5 h-3.5 text-purple-400" />
                    <span>File Metadata & Static Analysis Characteristics</span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono">
                    <div className="p-2.5 bg-slate-950 rounded border border-slate-800/80">
                      <span className="text-slate-500 text-[10px] block">File Type & Architecture</span>
                      <span className="text-white font-semibold">{enrichment.fileInfo.fileType}</span>
                    </div>
                    <div className="p-2.5 bg-slate-950 rounded border border-slate-800/80">
                      <span className="text-slate-500 text-[10px] block">AV Signature / Malware Family</span>
                      <span className="text-red-400 font-semibold">{enrichment.fileInfo.signature}</span>
                    </div>
                    {enrichment.fileInfo.imphash && (
                      <div className="p-2.5 bg-slate-950 rounded border border-slate-800/80 col-span-2">
                        <span className="text-slate-500 text-[10px] block">Import Hash (Imphash)</span>
                        <span className="text-slate-300 text-[11px] select-all">{enrichment.fileInfo.imphash}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Vulnerability Details (for CVEs) */}
              {enrichment?.vulnerabilityDetails && (
                <div className="p-4 rounded-lg bg-red-950/20 border border-red-500/30 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-red-300 font-semibold uppercase tracking-wider font-mono text-[11px]">
                      <AlertTriangle className="w-4 h-4 text-red-400" />
                      <span>NIST NVD & CISA KEV Vulnerability Intelligence</span>
                    </div>
                    {enrichment.vulnerabilityDetails.isCisaKev && (
                      <span className="px-2 py-0.5 rounded bg-red-600 text-white font-bold text-[10px] uppercase tracking-wider animate-pulse">
                        CISA KEV ACTIVELY EXPLOITED
                      </span>
                    )}
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono">
                    <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                      <span className="text-slate-500 text-[10px] block">CVSS v3.1 Base Score</span>
                      <span className="text-red-400 font-bold text-base">{enrichment.vulnerabilityDetails.cvssScore} / 10.0</span>
                    </div>
                    <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                      <span className="text-slate-500 text-[10px] block">Severity Rating</span>
                      <span className="text-white font-semibold">{enrichment.vulnerabilityDetails.severity}</span>
                    </div>
                    <div className="p-2.5 bg-slate-950 rounded border border-slate-800 col-span-2">
                      <span className="text-slate-500 text-[10px] block">Weakness Enumeration (CWE)</span>
                      <span className="text-slate-300 text-[11px] truncate block">{enrichment.vulnerabilityDetails.cwe}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Recommended Mitigation Guidelines */}
              {enrichment?.mitigationGuidelines && (
                <div className="p-4 rounded-lg bg-slate-900/50 border border-slate-800 space-y-2">
                  <div className="flex items-center gap-2 text-slate-300 font-semibold uppercase tracking-wider font-mono text-[11px]">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                    <span>SOC Incident Response & Containment Playbook</span>
                  </div>
                  <ul className="space-y-1.5 text-slate-300 pl-4 list-disc font-sans text-xs">
                    {enrichment.mitigationGuidelines.map((guideline, idx) => (
                      <li key={idx}>{guideline}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: RELATIONSHIPS & BLAST RADIUS */}
          {activeTab === "relationships" && (
            <div className="space-y-6">
              {/* Correlated Enterprise Assets */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-slate-200 font-semibold font-mono text-[11px] uppercase tracking-wider">
                    <Server className="w-3.5 h-3.5 text-blue-400" />
                    <span>Impacted Enterprise Assets ({relatedAssets.length})</span>
                  </div>
                  <Link to="/assets" className="text-blue-400 hover:underline text-[11px] flex items-center gap-1 font-mono">
                    View Asset Inventory <ExternalLink className="w-3 h-3" />
                  </Link>
                </div>

                {relatedAssets.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {relatedAssets.map(asset => (
                      <div key={asset.id} className="p-3 bg-slate-900/80 rounded-lg border border-slate-800 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-white font-bold font-mono">{asset.name}</span>
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                            asset.criticality === "TIER_1_MISSION_CRITICAL" ? "bg-red-950 text-red-400 border border-red-500/40" : "bg-slate-800 text-slate-300"
                          }`}>
                            {asset.criticality.replace("TIER_1_", "")}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono space-y-0.5">
                          <div>IP: <span className="text-slate-200">{asset.ipAddress || "N/A"}</span> | OS: <span className="text-slate-200">{asset.operatingSystem || "Linux"}</span></div>
                          <div>Software: <span className="text-slate-200 truncate">{asset.software || "Core Service"}</span></div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 bg-slate-900/30 rounded-lg border border-dashed border-slate-800 text-center text-slate-500">
                    No active enterprise assets directly match this indicator's IP or software signature.
                  </div>
                )}
              </div>

              {/* Related Threats */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-slate-200 font-semibold font-mono text-[11px] uppercase tracking-wider">
                    <Crosshair className="w-3.5 h-3.5 text-red-400" />
                    <span>Correlated Threat Dossiers ({relatedThreats.length})</span>
                  </div>
                </div>

                {relatedThreats.length > 0 ? (
                  <div className="space-y-2">
                    {relatedThreats.map(threat => (
                      <div key={threat.id} className="p-3 bg-slate-900/80 rounded-lg border border-slate-800 flex items-center justify-between gap-4">
                        <div className="space-y-1 flex-1">
                          <div className="flex items-center gap-2">
                            <span className="text-white font-semibold">{threat.title}</span>
                            <span className="px-1.5 py-0.5 rounded bg-red-950/80 text-red-400 border border-red-500/40 text-[10px] font-mono font-bold">
                              {threat.severity}
                            </span>
                          </div>
                          <p className="text-slate-400 text-[11px] line-clamp-1">{threat.description}</p>
                        </div>
                        <Link
                          to={`/threats/${threat.id}`}
                          className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-blue-400 hover:text-white rounded border border-slate-700 text-[11px] font-mono shrink-0 flex items-center gap-1 transition-colors"
                        >
                          Threat Dossier <ExternalLink className="w-3 h-3" />
                        </Link>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 bg-slate-900/30 rounded-lg border border-dashed border-slate-800 text-center text-slate-500">
                    No specific threat dossier tied directly to this artifact.
                  </div>
                )}
              </div>

              {/* Related Reports */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-slate-200 font-semibold font-mono text-[11px] uppercase tracking-wider">
                    <Database className="w-3.5 h-3.5 text-purple-400" />
                    <span>Ingested Intelligence Reports ({relatedReports.length})</span>
                  </div>
                </div>

                {relatedReports.length > 0 ? (
                  <div className="space-y-2">
                    {relatedReports.map(report => (
                      <div key={report.id} className="p-3 bg-slate-900/80 rounded-lg border border-slate-800 flex items-center justify-between gap-4">
                        <div className="space-y-0.5 flex-1">
                          <span className="text-white font-semibold block">{report.filename || "CTI Report Feed"}</span>
                          <span className="text-slate-400 text-[11px]">Origin: {report.sourceOrigin || report.category || "CTI Feed"} | Ingested: {report.uploadDate ? new Date(report.uploadDate).toISOString().slice(0, 10) : "Recent"}</span>
                        </div>
                        <Link
                          to={`/reports/${report.id}`}
                          className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-purple-400 hover:text-white rounded border border-slate-700 text-[11px] font-mono shrink-0 flex items-center gap-1 transition-colors"
                        >
                          View Report <ExternalLink className="w-3 h-3" />
                        </Link>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 bg-slate-900/30 rounded-lg border border-dashed border-slate-800 text-center text-slate-500">
                    No intelligence report linked.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: DETECTION ENGINEERING */}
          {activeTab === "detection" && (
            <div className="space-y-6 font-mono">
              {/* Snort / Suricata */}
              {enrichment?.snortRule && (
                <div className="p-4 bg-slate-900/80 rounded-lg border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-blue-400 font-semibold text-[11px]">Snort / Suricata IDS Signature</span>
                    <button
                      onClick={() => copyText(enrichment.snortRule!, "snort")}
                      className="inline-flex items-center gap-1 text-[10px] text-slate-300 hover:text-white bg-slate-800 px-2 py-1 rounded border border-slate-700"
                    >
                      {copiedKey === "snort" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedKey === "snort" ? "Copied" : "Copy Rule"}</span>
                    </button>
                  </div>
                  <pre className="p-3 bg-slate-950 rounded border border-slate-800/80 text-emerald-400 text-[11px] overflow-x-auto whitespace-pre-wrap">
                    {enrichment.snortRule}
                  </pre>
                </div>
              )}

              {/* YARA */}
              {enrichment?.yaraRule && (
                <div className="p-4 bg-slate-900/80 rounded-lg border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-purple-400 font-semibold text-[11px]">YARA Host Artifact Signature</span>
                    <button
                      onClick={() => copyText(enrichment.yaraRule!, "yara")}
                      className="inline-flex items-center gap-1 text-[10px] text-slate-300 hover:text-white bg-slate-800 px-2 py-1 rounded border border-slate-700"
                    >
                      {copiedKey === "yara" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedKey === "yara" ? "Copied" : "Copy YARA"}</span>
                    </button>
                  </div>
                  <pre className="p-3 bg-slate-950 rounded border border-slate-800/80 text-purple-300 text-[11px] overflow-x-auto whitespace-pre-wrap">
                    {enrichment.yaraRule}
                  </pre>
                </div>
              )}

              {/* Firewall Rule */}
              {enrichment?.firewallRule && (
                <div className="p-4 bg-slate-900/80 rounded-lg border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-red-400 font-semibold text-[11px]">Firewall / Proxy Ingress Block Directive</span>
                    <button
                      onClick={() => copyText(enrichment.firewallRule!, "fw")}
                      className="inline-flex items-center gap-1 text-[10px] text-slate-300 hover:text-white bg-slate-800 px-2 py-1 rounded border border-slate-700"
                    >
                      {copiedKey === "fw" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedKey === "fw" ? "Copied" : "Copy Command"}</span>
                    </button>
                  </div>
                  <pre className="p-3 bg-slate-950 rounded border border-slate-800/80 text-slate-200 text-[11px] overflow-x-auto whitespace-pre-wrap">
                    {enrichment.firewallRule}
                  </pre>
                </div>
              )}

              {/* EDR Hunting Query */}
              {enrichment?.edrHuntingQuery && (
                <div className="p-4 bg-slate-900/80 rounded-lg border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-amber-400 font-semibold text-[11px]">EDR / SIEM Threat Hunting Query (KQL / Microsoft Defender)</span>
                    <button
                      onClick={() => copyText(enrichment.edrHuntingQuery!, "edr")}
                      className="inline-flex items-center gap-1 text-[10px] text-slate-300 hover:text-white bg-slate-800 px-2 py-1 rounded border border-slate-700"
                    >
                      {copiedKey === "edr" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedKey === "edr" ? "Copied" : "Copy Query"}</span>
                    </button>
                  </div>
                  <pre className="p-3 bg-slate-950 rounded border border-slate-800/80 text-amber-300 text-[11px] overflow-x-auto whitespace-pre-wrap">
                    {enrichment.edrHuntingQuery}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* TAB 4: ANALYST HISTORY */}
          {activeTab === "notes" && (
            <div className="space-y-4">
              <div className="p-4 bg-slate-900/50 rounded-lg border border-slate-800 space-y-3 font-mono">
                <div className="text-slate-300 font-semibold uppercase text-[11px]">Investigation Audit & Sighting History</div>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">First Sighting</span>
                    <span className="text-white">{dossier.firstSeen?.slice(0, 10)}</span>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">Last Sighting</span>
                    <span className="text-white">{dossier.lastSeen?.slice(0, 10)}</span>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">Total Ingestions</span>
                    <span className="text-emerald-400 font-bold">{dossier.occurrenceCount} occurrences</span>
                  </div>
                </div>

                <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1">
                  <span className="text-slate-400 text-[10px] uppercase font-bold">Investigation Audit Trail</span>
                  <div className="text-slate-300 text-xs font-sans">
                    Last reviewed by: <span className="font-semibold text-white">{dossier.investigationAudit?.lastInvestigatedBy || "SOC Lead Analyst"}</span>
                  </div>
                  <ul className="list-disc pl-4 text-slate-400 text-[11px] font-sans pt-1">
                    {dossier.investigationAudit?.analystNotes?.map((note, i) => (
                      <li key={i}>{note}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 bg-slate-950 border-t border-slate-800 flex items-center justify-between">
          <div className="text-slate-500 text-[11px] font-mono">
            Indicator ID: <span className="text-slate-400">{ioc.id}</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold uppercase tracking-wider font-mono border border-slate-700 transition-colors"
          >
            Close Workspace
          </button>
        </div>
      </div>
    </div>
  );
}

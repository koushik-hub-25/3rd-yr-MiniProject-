import React, { useEffect, useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { Card, CardHeader, CardTitle, CardContent, Badge, SeverityBadge, ConfidenceMeter } from "../components/ui";
import {
  ArrowLeft,
  ShieldAlert,
  Cpu,
  CheckCircle,
  Target,
  FileText,
  Copy,
  Check,
  Layers,
  Server,
  UserCheck,
  MessageSquare,
  AlertTriangle,
  Send,
  Database,
  ExternalLink,
  Lock,
  Clock,
  Sparkles
} from "lucide-react";
import type { Threat, Recommendation, IOC, Entity, Incident, AnalystNote } from "../types";

export default function ThreatDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [threat, setThreat] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);
  const [copiedAll, setCopiedAll] = useState(false);

  // Analyst Control State
  const [overrideSeverity, setOverrideSeverity] = useState("");
  const [overrideReason, setOverrideReason] = useState("");
  const [newStatus, setNewStatus] = useState("");
  const [newNote, setNewNote] = useState("");
  const [authorName, setAuthorName] = useState("Jordan Chen (L2 SOC Analyst)");
  const [savingAction, setSavingAction] = useState(false);

  const fetchThreatDetails = async () => {
    try {
      setLoading(true);
      const res = await fetch(`/api/threats/${id}`);
      const data = await res.json();
      setThreat(data);
      if (data) {
        setOverrideSeverity(data.analystSeverityOverride || data.severity);
        setNewStatus(data.status);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreatDetails();
  }, [id]);

  const copyToClipboard = (text: string, iocId?: string) => {
    navigator.clipboard.writeText(text);
    if (iocId) {
      setCopiedIoc(iocId);
      setTimeout(() => setCopiedIoc(null), 2000);
    } else {
      setCopiedAll(true);
      setTimeout(() => setCopiedAll(false), 2000);
    }
  };

  const copyAllIocs = () => {
    if (!threat?.iocs) return;
    const text = threat.iocs.map((i: IOC) => `${i.type}: ${i.value} (${i.context || ""})`).join("\n");
    copyToClipboard(text);
  };

  const handleUpdateStatusAndSeverity = async () => {
    try {
      setSavingAction(true);
      await fetch(`/api/threats/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status: newStatus,
          severity: overrideSeverity !== threat.severity ? overrideSeverity : threat.severity,
          analystSeverityOverride: overrideSeverity !== threat.severity ? overrideSeverity : null,
          overrideReason: overrideReason || undefined,
          analystNote: overrideReason ? `[Severity Override to ${overrideSeverity}]: ${overrideReason}` : undefined,
          author: authorName
        })
      });
      await fetchThreatDetails();
    } catch (e) {
      console.error(e);
    } finally {
      setSavingAction(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    try {
      await fetch(`/api/threats/${id}/notes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          note: newNote,
          author: authorName
        })
      });
      setNewNote("");
      await fetchThreatDetails();
    } catch (e) {
      console.error(e);
    }
  };

  const toggleRecommendation = async (recId: string, currentStatus: number = 0) => {
    try {
      await fetch(`/api/recommendations/${recId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ completed: currentStatus ? 0 : 1 })
      });
      await fetchThreatDetails();
    } catch (e) {
      console.error(e);
    }
  };

  if (loading) {
    return <div className="p-12 text-slate-400 text-center text-xs">Loading threat dossier...</div>;
  }

  if (!threat) {
    return (
      <div className="p-12 text-center space-y-4">
        <p className="text-slate-400 text-sm">Threat record not found.</p>
        <button onClick={() => navigate(-1)} className="text-blue-400 hover:underline text-xs">
          Return to Threat Feed
        </button>
      </div>
    );
  }

  let mitreList: string[] = [];
  if (threat.mitreTechniques) {
    try {
      mitreList = JSON.parse(threat.mitreTechniques);
    } catch {
      mitreList = [threat.mitreTechniques];
    }
  }

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-8">
      {/* Back Navigation */}
      <button
        onClick={() => navigate(-1)}
        className="text-slate-400 hover:text-white flex items-center gap-2 text-xs font-semibold uppercase tracking-wider transition-colors"
      >
        <ArrowLeft className="w-4 h-4" /> Back to Threat Queue
      </button>

      {/* Main Threat Header */}
      <div className="flex flex-col md:flex-row md:items-start justify-between gap-6 p-6 bg-[#0B1120] border border-slate-800 rounded-xl shadow-xl">
        <div className="space-y-2">
          <div className="flex items-center gap-3 flex-wrap">
            <SeverityBadge severity={threat.severity} />
            <span className="bg-slate-900 text-slate-300 text-xs font-semibold px-2.5 py-1 rounded border border-slate-800">
              {threat.category}
            </span>
            {threat.analystSeverityOverride && (
              <Badge variant="info">
                Analyst Override: {threat.analystSeverityOverride}
              </Badge>
            )}
            {threat.status === "escalated" ? (
              <Badge variant="critical">Escalated to Tier-3</Badge>
            ) : threat.status === "reviewed" ? (
              <Badge variant="success">Reviewed by SOC</Badge>
            ) : threat.status === "confirmed_incident" ? (
              <Badge variant="critical">Confirmed Active Incident</Badge>
            ) : (
              <Badge variant="info">Active Triage</Badge>
            )}
          </div>

          <h1 className="text-2xl md:text-3xl font-bold text-white tracking-tight">
            {threat.title}
          </h1>

          <div className="flex items-center gap-4 text-xs text-slate-400 pt-1 flex-wrap">
            <span className="flex items-center gap-1.5 font-mono">
              <Clock className="w-3.5 h-3.5 text-slate-400" />
              Detected: {new Date(threat.detectedAt).toLocaleString()}
            </span>
            {threat.affectedSystems && (
              <span className="flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-slate-400" />
                {threat.affectedSystems}
              </span>
            )}
          </div>
        </div>

        <div className="flex flex-col items-start md:items-end gap-2 shrink-0">
          <div className="text-xs text-slate-400">AI Confidence Score:</div>
          <ConfidenceMeter confidence={threat.confidence} />
        </div>
      </div>

      {/* Grid: Main Analysis Left, Controls Right */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left 2 Cols: AI Explainability, Evidence, IOCs, Recommendations */}
        <div className="lg:col-span-2 space-y-6">
          {/* AI Explainability & Reasoning */}
          <Card>
            <CardHeader className="bg-blue-950/20 border-b border-blue-500/20">
              <CardTitle className="text-blue-400">
                <Cpu className="w-4 h-4" /> AI Threat Rationale & Explainability
              </CardTitle>
              <span className="text-[10px] font-mono bg-blue-900/40 text-blue-300 px-2 py-0.5 rounded border border-blue-500/30">
                Decision Support Output
              </span>
            </CardHeader>
            <CardContent className="space-y-4 pt-5">
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-1">
                  Threat Description
                </h4>
                <p className="text-xs text-slate-200 leading-relaxed">
                  {threat.description}
                </p>
              </div>

              <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <Sparkles className="w-3.5 h-3.5 text-amber-400" /> Why was {threat.severity} Severity Assigned?
                </h4>
                <p className="text-xs text-slate-300 italic leading-relaxed">
                  "{threat.reasoning}"
                </p>
              </div>

              {threat.evidence && (
                <div className="space-y-1.5">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                    Direct Evidence Excerpt
                  </h4>
                  <blockquote className="p-3 bg-slate-950/70 border-l-2 border-blue-500 rounded-r text-xs text-slate-300 font-mono italic">
                    {threat.evidence}
                  </blockquote>
                </div>
              )}

              {/* MITRE ATT&CK Matrix Tags */}
              {mitreList.length > 0 && (
                <div className="space-y-2 pt-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-cyan-400" /> Mapped MITRE ATT&CK Techniques
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {mitreList.map((tech, idx) => (
                      <span
                        key={idx}
                        className="bg-cyan-950/60 text-cyan-300 border border-cyan-500/30 text-xs font-mono px-2.5 py-1 rounded shadow-sm"
                      >
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Extracted IOCs */}
          <Card>
            <CardHeader className="flex items-center justify-between">
              <CardTitle>
                <Database className="w-4 h-4 text-emerald-400" /> Extracted Indicators of Compromise (IOCs)
              </CardTitle>
              {threat.iocs && threat.iocs.length > 0 && (
                <button
                  onClick={copyAllIocs}
                  className="text-xs text-emerald-400 hover:text-emerald-300 font-semibold flex items-center gap-1.5 transition-colors"
                >
                  {copiedAll ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedAll ? "Copied All IOCs!" : "Copy All IOCs"}
                </button>
              )}
            </CardHeader>
            <CardContent className="pt-2">
              {threat.iocs && threat.iocs.length > 0 ? (
                <div className="overflow-x-auto bg-slate-950 rounded-lg border border-slate-800">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
                        <th className="p-3">Type</th>
                        <th className="p-3">Indicator Value</th>
                        <th className="p-3">Role / Context</th>
                        <th className="p-3 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {threat.iocs.map((ioc: IOC) => (
                        <tr key={ioc.id} className="hover:bg-slate-900/40">
                          <td className="p-3 font-mono font-bold text-blue-400">{ioc.type}</td>
                          <td className="p-3 font-mono text-slate-200">{ioc.value}</td>
                          <td className="p-3 text-slate-400 text-[11px]">{ioc.context || "Identified Artifact"}</td>
                          <td className="p-3 text-right">
                            <button
                              onClick={() => copyToClipboard(ioc.value, ioc.id)}
                              title="Copy to clipboard"
                              className="p-1 text-slate-400 hover:text-white hover:bg-slate-800 rounded transition-colors inline-flex items-center gap-1"
                            >
                              {copiedIoc === ioc.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                              <span className="text-[10px]">{copiedIoc === ioc.id ? "Copied" : "Copy"}</span>
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-slate-500 text-xs p-4">No specific IOC indicators tied directly to this threat sub-vector.</p>
              )}
            </CardContent>
          </Card>

          {/* Safe Defensive Actions Checklist */}
          <Card>
            <CardHeader>
              <CardTitle>
                <Target className="w-4 h-4 text-orange-400" /> Recommended Containment & Defensive Actions
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 pt-3">
              {threat.recommendations && threat.recommendations.length > 0 ? (
                threat.recommendations.map((rec: Recommendation) => (
                  <div
                    key={rec.id}
                    onClick={() => toggleRecommendation(rec.id, rec.completed)}
                    className={`flex items-start gap-3 p-3.5 rounded-lg border cursor-pointer transition-all ${
                      rec.completed
                        ? "bg-slate-950/40 border-slate-800/60 opacity-60 line-through"
                        : "bg-slate-950 border-slate-800 hover:border-slate-700"
                    }`}
                  >
                    <div className="mt-0.5 shrink-0">
                      <input
                        type="checkbox"
                        checked={Boolean(rec.completed)}
                        onChange={() => {}}
                        className="rounded border-slate-700 text-blue-600 focus:ring-0 cursor-pointer"
                      />
                    </div>
                    <div className="space-y-1 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-slate-200">{rec.recommendation}</span>
                        {rec.priority && (
                          <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded font-bold uppercase ${
                            rec.priority === "Critical" ? "bg-red-900/50 text-red-400" : "bg-orange-900/50 text-orange-400"
                          }`}>
                            {rec.priority}
                          </span>
                        )}
                        {rec.actionType && (
                          <span className="text-[9px] font-mono bg-slate-900 text-slate-400 px-1.5 py-0.2 rounded border border-slate-800">
                            {rec.actionType}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-slate-500 text-xs">Standard perimeter logging and network isolation recommended.</p>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Right Col: Human-in-the-Loop Analyst Override & Audit */}
        <div className="space-y-6">
          {/* Analyst Control Box */}
          <Card className="border-blue-500/30">
            <CardHeader className="bg-blue-950/30">
              <CardTitle className="text-white flex items-center gap-2">
                <UserCheck className="w-4 h-4 text-blue-400" /> Human-in-the-Loop Controls
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 pt-4">
              <div>
                <label className="block text-[11px] font-bold uppercase text-slate-400 mb-1.5">
                  Update Triage Status
                </label>
                <select
                  value={newStatus}
                  onChange={e => setNewStatus(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:ring-1 focus:ring-blue-500 outline-none"
                >
                  <option value="active">Active Triage</option>
                  <option value="reviewed">Mark as Reviewed</option>
                  <option value="escalated">Escalate to Tier-3 Incident Response</option>
                  <option value="confirmed_incident">Confirm as Active Breach/Incident</option>
                  <option value="false_positive">Mark as False Positive</option>
                </select>
              </div>

              <div>
                <label className="block text-[11px] font-bold uppercase text-slate-400 mb-1.5">
                  Analyst Severity Override
                </label>
                <select
                  value={overrideSeverity}
                  onChange={e => setOverrideSeverity(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:ring-1 focus:ring-blue-500 outline-none"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              {overrideSeverity !== threat.severity && (
                <div>
                  <label className="block text-[11px] font-bold uppercase text-amber-400 mb-1.5">
                    Override Justification (Required for Audit)
                  </label>
                  <textarea
                    rows={2}
                    placeholder="State reason for overriding AI severity..."
                    value={overrideReason}
                    onChange={e => setOverrideReason(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:ring-1 focus:ring-blue-500 outline-none"
                  />
                </div>
              )}

              <button
                onClick={handleUpdateStatusAndSeverity}
                disabled={savingAction}
                className="w-full bg-blue-600 hover:bg-blue-500 text-white py-2 rounded-lg text-xs font-bold uppercase tracking-wider transition-colors shadow-md shadow-blue-600/30"
              >
                {savingAction ? "Saving changes..." : "Save Analyst Decisions"}
              </button>
            </CardContent>
          </Card>

          {/* Source Intelligence Report Link */}
          <Card>
            <CardHeader>
              <CardTitle>
                <FileText className="w-4 h-4 text-slate-400" /> Source Intelligence
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 pt-3">
              {threat.report ? (
                <div>
                  <div className="font-semibold text-xs text-slate-200">{threat.report.filename}</div>
                  <div className="text-[10px] text-slate-400 mt-0.5">
                    Uploaded {new Date(threat.report.uploadDate).toLocaleString()}
                  </div>
                  <Link
                    to="/reports"
                    className="mt-3 block w-full text-center bg-slate-950 hover:bg-slate-800 text-slate-300 py-2 rounded border border-slate-800 transition-colors text-xs font-semibold"
                  >
                    View Source Report
                  </Link>
                </div>
              ) : (
                <p className="text-slate-500 text-xs">Direct Sensor Alert or Synthesized Stream</p>
              )}
            </CardContent>
          </Card>

          {/* Related Entities */}
          {threat.entities && threat.entities.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Related Entities</CardTitle>
              </CardHeader>
              <CardContent className="pt-3">
                <div className="flex flex-wrap gap-2">
                  {threat.entities.map((ent: Entity) => (
                    <span
                      key={ent.id}
                      className="bg-slate-950 text-slate-300 border border-slate-800 text-[11px] px-2.5 py-1 rounded"
                    >
                      <strong className="text-blue-400 font-mono text-[9px] uppercase mr-1">{ent.type}:</strong>
                      {ent.name}
                    </span>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Analyst Notes Trail */}
          <Card>
            <CardHeader>
              <CardTitle>
                <MessageSquare className="w-4 h-4 text-slate-400" /> SOC Analyst Audit Notes
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 pt-3">
              <div className="space-y-3 max-h-48 overflow-y-auto pr-1">
                {threat.analystNotes && threat.analystNotes.length > 0 ? (
                  threat.analystNotes.map((n: AnalystNote) => (
                    <div key={n.id} className="p-2.5 bg-slate-950 rounded border border-slate-800 space-y-1">
                      <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono">
                        <span className="font-bold text-slate-300">{n.author}</span>
                        <span>{new Date(n.timestamp).toLocaleTimeString()}</span>
                      </div>
                      <p className="text-xs text-slate-200">{n.note}</p>
                    </div>
                  ))
                ) : (
                  <p className="text-slate-500 text-xs">No analyst notes recorded yet.</p>
                )}
              </div>

              <form onSubmit={handleAddNote} className="space-y-2 pt-2 border-t border-slate-800">
                <input
                  type="text"
                  placeholder="Add SOC investigation note..."
                  value={newNote}
                  onChange={e => setNewNote(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white focus:ring-1 focus:ring-blue-500 outline-none"
                />
                <button
                  type="submit"
                  className="w-full bg-slate-800 hover:bg-slate-700 text-slate-200 py-1.5 rounded text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors border border-slate-700"
                >
                  <Send className="w-3 h-3" /> Post Note
                </button>
              </form>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

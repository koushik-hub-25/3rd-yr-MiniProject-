import React, { useState, useEffect } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Flame,
  AlertTriangle,
  Info,
  Layers,
  Server,
  Radio,
  Sliders,
  RefreshCw,
  Sparkles,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  Database,
  Search,
  Download,
  Terminal,
  Activity,
  Play,
  RotateCcw
} from "lucide-react";
import {
  ExplainableRiskAssessment,
  BenchmarkScenario,
  Asset,
  Threat,
  RiskLevel
} from "../types";
import { Card, CardHeader, CardTitle, CardContent, Badge, SeverityBadge, ConfidenceMeter, cn } from "../components/ui";
import { ExplainableRiskScoreCard } from "../components/ExplainableRiskScoreCard";

export default function RiskScoringEngine() {
  const [scenarios, setScenarios] = useState<BenchmarkScenario[]>([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>("scenario-critical");
  const [assessment, setAssessment] = useState<ExplainableRiskAssessment | null>(null);
  const [loading, setLoading] = useState(false);
  const [inventoryMatrix, setInventoryMatrix] = useState<ExplainableRiskAssessment[]>([]);
  const [loadingMatrix, setLoadingMatrix] = useState(false);
  const [activeTab, setActiveTab] = useState<"simulator" | "benchmarks" | "inventory">("benchmarks");

  // Interactive Simulator Form State
  const [simParams, setSimParams] = useState({
    assetName: "prod-payment-gateway-01",
    assetCriticality: "CRITICAL",
    assetExposure: "INTERNET",
    assetEnvironment: "Production",
    assetIp: "198.51.100.42",
    cveId: "CVE-2024-38077",
    cvssScore: 9.8,
    isCisaKev: true,
    exploitAvailability: "WEAPONIZED",
    threatTitle: "Active Pre-Auth Remote Code Execution in RDS Licensing",
    threatSeverity: "CRITICAL",
    threatConfidence: 98,
    intelligenceRecencyDays: 2
  });

  // Assets list for dropdown
  const [availableAssets, setAvailableAssets] = useState<Asset[]>([]);

  // Fetch benchmark scenarios
  const fetchScenarios = async () => {
    try {
      setLoading(true);
      const res = await fetch("/api/risk/scenarios");
      if (res.ok) {
        const data = await res.json();
        setScenarios(data);
        const initial = data.find((s: BenchmarkScenario) => s.id === selectedScenarioId) || data[0];
        if (initial && initial.result) {
          setAssessment(initial.result);
          if (initial.params) {
            setSimParams({ ...initial.params });
          }
        }
      }
    } catch (e) {
      console.error("Failed to load risk scenarios", e);
    } finally {
      setLoading(false);
    }
  };

  // Fetch registered assets
  const fetchAssets = async () => {
    try {
      const res = await fetch("/api/assets");
      if (res.ok) {
        const data = await res.json();
        setAvailableAssets(data);
      }
    } catch (e) {
      console.error("Failed to load assets", e);
    }
  };

  // Fetch inventory cross matrix
  const fetchMatrix = async () => {
    try {
      setLoadingMatrix(true);
      const res = await fetch("/api/risk/matrix");
      if (res.ok) {
        const data = await res.json();
        setInventoryMatrix(data);
      }
    } catch (e) {
      console.error("Failed to load risk matrix", e);
    } finally {
      setLoadingMatrix(false);
    }
  };

  useEffect(() => {
    fetchScenarios();
    fetchAssets();
    fetchMatrix();
  }, []);

  // Recalculate deterministic risk score
  const evaluateCustomRisk = async (paramsToEvaluate = simParams) => {
    try {
      setLoading(true);
      const res = await fetch("/api/risk/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(paramsToEvaluate)
      });
      if (res.ok) {
        const data = await res.json();
        setAssessment(data);
      }
    } catch (e) {
      console.error("Failed to evaluate risk score", e);
    } finally {
      setLoading(false);
    }
  };

  // Switch benchmark scenario
  const handleSelectScenario = (scenario: BenchmarkScenario) => {
    setSelectedScenarioId(scenario.id);
    if (scenario.result) {
      setAssessment(scenario.result);
    }
    if (scenario.params) {
      setSimParams({ ...scenario.params });
    }
  };

  // Handle asset selection in simulator
  const handleSelectRegisteredAsset = (assetId: string) => {
    const found = availableAssets.find(a => a.id === assetId);
    if (found) {
      const updated = {
        ...simParams,
        assetName: found.name,
        assetCriticality: found.criticality,
        assetExposure: found.exposure,
        assetEnvironment: found.environment,
        assetIp: found.ipAddress || ""
      };
      setSimParams(updated);
      evaluateCustomRisk(updated);
    }
  };

  // Quick lookup CVE
  const handleCveLookup = async (cve: string) => {
    if (!cve || !cve.startsWith("CVE-")) return;
    try {
      const res = await fetch(`/api/nvd/${cve}`);
      if (res.ok) {
        const nvd = await res.json();
        const kevRes = await fetch(`/api/cisa-kev/${cve}`);
        const kev = kevRes.ok ? await kevRes.json() : null;

        const updated = {
          ...simParams,
          cveId: cve,
          cvssScore: nvd.cvssScore || simParams.cvssScore,
          isCisaKev: Boolean(kev?.isKnownExploited),
          exploitAvailability: kev?.isKnownExploited ? "WEAPONIZED" : nvd.cvssScore >= 7.5 ? "PUBLIC_POC" : "THEORETICAL"
        };
        setSimParams(updated);
        evaluateCustomRisk(updated);
      }
    } catch (e) {
      console.error("CVE lookup failed", e);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-border/60 pb-5">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-primary/10 border border-primary/20 text-primary">
              <Activity className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-foreground">
                Explainable Risk Scoring Engine
              </h1>
              <p className="text-sm text-muted-foreground">
                Deterministic 0–100 risk scoring framework with mathematical factor attribution and NVD/CISA KEV integration.
              </p>
            </div>
          </div>
        </div>

        {/* View Tabs */}
        <div className="flex items-center space-x-2 bg-secondary/50 p-1 rounded-xl border border-border/60">
          <button
            id="tab-benchmarks"
            onClick={() => setActiveTab("benchmarks")}
            className={cn(
              "px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center space-x-1.5",
              activeTab === "benchmarks"
                ? "bg-background text-foreground shadow-sm border border-border/60"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Benchmark Scenarios</span>
          </button>
          <button
            id="tab-simulator"
            onClick={() => setActiveTab("simulator")}
            className={cn(
              "px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center space-x-1.5",
              activeTab === "simulator"
                ? "bg-background text-foreground shadow-sm border border-border/60"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>Interactive Simulator</span>
          </button>
          <button
            id="tab-inventory"
            onClick={() => setActiveTab("inventory")}
            className={cn(
              "px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center space-x-1.5",
              activeTab === "inventory"
                ? "bg-background text-foreground shadow-sm border border-border/60"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Inventory Matrix ({inventoryMatrix.length})</span>
          </button>
        </div>
      </div>

      {/* Main Grid: Visualizer & Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Interactive Controls / Benchmark Selector */}
        <div className="lg:col-span-5 space-y-6">
          {activeTab === "benchmarks" && (
            <Card className="border-border/80">
              <CardHeader className="pb-3 border-b border-border/60">
                <CardTitle className="text-sm font-semibold flex items-center space-x-2">
                  <ShieldAlert className="w-4 h-4 text-primary" />
                  <span>Standard Benchmark Scenarios</span>
                </CardTitle>
                <p className="text-xs text-muted-foreground">
                  Pre-calibrated test cases across all four mandatory risk levels.
                </p>
              </CardHeader>

              <CardContent className="p-4 space-y-3">
                {scenarios.map((scen) => {
                  const isSelected = scen.id === selectedScenarioId;
                  const lvl = scen.result?.level || "LOW";
                  const badgeColor =
                    lvl === "CRITICAL"
                      ? "bg-red-500/10 text-red-400 border-red-500/30"
                      : lvl === "HIGH"
                      ? "bg-orange-500/10 text-orange-400 border-orange-500/30"
                      : lvl === "MEDIUM"
                      ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                      : "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";

                  return (
                    <div
                      key={scen.id}
                      id={scen.id}
                      onClick={() => handleSelectScenario(scen)}
                      className={cn(
                        "p-4 rounded-xl border transition-all cursor-pointer",
                        isSelected
                          ? "bg-primary/5 border-primary shadow-sm"
                          : "bg-background/60 border-border/60 hover:bg-secondary/40"
                      )}
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-xs font-bold text-foreground">
                          {scen.name}
                        </span>
                        <div className="flex items-center space-x-2">
                          <span className={cn("text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold", badgeColor)}>
                            {lvl} • {scen.result?.score}/100
                          </span>
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground leading-relaxed">
                        {scen.description}
                      </p>
                      <div className="flex flex-wrap items-center gap-1.5 mt-2.5 pt-2 border-t border-border/40 text-[10px] text-muted-foreground font-mono">
                        <span className="bg-secondary px-1.5 py-0.5 rounded">Asset: {scen.params.assetCriticality}</span>
                        <span className="bg-secondary px-1.5 py-0.5 rounded">CVSS: {scen.params.cvssScore}</span>
                        {scen.params.isCisaKev && (
                          <span className="bg-red-500/10 text-red-400 border border-red-500/20 px-1.5 py-0.5 rounded font-bold">KEV</span>
                        )}
                        <span className="bg-secondary px-1.5 py-0.5 rounded">{scen.params.exploitAvailability}</span>
                      </div>
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          )}

          {activeTab === "simulator" && (
            <Card className="border-border/80">
              <CardHeader className="pb-3 border-b border-border/60 flex flex-row items-center justify-between">
                <div>
                  <CardTitle className="text-sm font-semibold flex items-center space-x-2">
                    <Sliders className="w-4 h-4 text-primary" />
                    <span>Real-Time Parameter Simulator</span>
                  </CardTitle>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Adjust factors below to observe deterministic recalculation.
                  </p>
                </div>
                <button
                  onClick={() => evaluateCustomRisk()}
                  className="p-1.5 rounded-lg bg-secondary hover:bg-secondary/80 text-foreground transition-colors"
                  title="Recalculate Score"
                >
                  <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
                </button>
              </CardHeader>

              <CardContent className="p-4 space-y-4 max-h-[600px] overflow-y-auto">
                {/* Registered Asset Quick Select */}
                <div>
                  <label className="text-xs font-semibold text-foreground block mb-1">
                    Select Target Asset
                  </label>
                  <select
                    className="w-full bg-background border border-border/70 rounded-lg px-3 py-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                    onChange={(e) => handleSelectRegisteredAsset(e.target.value)}
                    value={availableAssets.find(a => a.name === simParams.assetName)?.id || ""}
                  >
                    <option value="">-- Choose Registered Asset or Custom --</option>
                    {availableAssets.map(a => (
                      <option key={a.id} value={a.id}>
                        {a.name} ({a.criticality} • {a.exposure} • {a.environment})
                      </option>
                    ))}
                  </select>
                </div>

                {/* Asset Custom Fields */}
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-[11px] font-medium text-muted-foreground block mb-1">
                      Asset Criticality (Max 15 pt)
                    </label>
                    <select
                      className="w-full bg-background border border-border/70 rounded-lg px-2.5 py-1.5 text-xs text-foreground"
                      value={simParams.assetCriticality}
                      onChange={(e) => {
                        const val = e.target.value;
                        setSimParams(prev => {
                          const next = { ...prev, assetCriticality: val };
                          evaluateCustomRisk(next);
                          return next;
                        });
                      }}
                    >
                      <option value="CRITICAL">CRITICAL (Tier 1: 15 pt)</option>
                      <option value="HIGH">HIGH (Important: 10 pt)</option>
                      <option value="MEDIUM">MEDIUM (Standard: 5 pt)</option>
                      <option value="LOW">LOW (Testing: 2 pt)</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[11px] font-medium text-muted-foreground block mb-1">
                      Asset Exposure (Max 10 pt)
                    </label>
                    <select
                      className="w-full bg-background border border-border/70 rounded-lg px-2.5 py-1.5 text-xs text-foreground"
                      value={simParams.assetExposure}
                      onChange={(e) => {
                        const val = e.target.value;
                        setSimParams(prev => {
                          const next = { ...prev, assetExposure: val };
                          evaluateCustomRisk(next);
                          return next;
                        });
                      }}
                    >
                      <option value="INTERNET">INTERNET (Public: 10 pt)</option>
                      <option value="INTERNAL">INTERNAL (Corp LAN: 5 pt)</option>
                      <option value="RESTRICTED">RESTRICTED (Air-gapped: 1 pt)</option>
                    </select>
                  </div>
                </div>

                {/* Vulnerability & CVSS Inputs */}
                <div className="pt-2 border-t border-border/40 space-y-3">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-semibold text-foreground">
                      Vulnerability & NVD Metrics
                    </label>
                    <span className="text-[10px] font-mono text-muted-foreground">Max 25 pt</span>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-[11px] font-medium text-muted-foreground block mb-1">
                        CVE Identifier
                      </label>
                      <input
                        type="text"
                        placeholder="CVE-2024-38077"
                        className="w-full bg-background border border-border/70 rounded-lg px-2.5 py-1.5 text-xs font-mono text-foreground"
                        value={simParams.cveId}
                        onChange={(e) => setSimParams({ ...simParams, cveId: e.target.value })}
                        onBlur={(e) => handleCveLookup(e.target.value)}
                      />
                    </div>
                    <div>
                      <div className="flex justify-between items-center mb-1">
                        <label className="text-[11px] font-medium text-muted-foreground">
                          CVSS Base Score: <span className="text-foreground font-mono font-bold">{simParams.cvssScore}</span>
                        </label>
                      </div>
                      <input
                        type="range"
                        min="0"
                        max="10"
                        step="0.1"
                        className="w-full accent-primary"
                        value={simParams.cvssScore}
                        onChange={(e) => {
                          const val = parseFloat(e.target.value);
                          setSimParams(prev => {
                            const next = { ...prev, cvssScore: val };
                            evaluateCustomRisk(next);
                            return next;
                          });
                        }}
                      />
                    </div>
                  </div>

                  {/* CISA KEV Toggle & Exploit Availability */}
                  <div className="grid grid-cols-2 gap-3 items-center">
                    <div className="flex items-center space-x-2 bg-background p-2 rounded-lg border border-border/60">
                      <input
                        type="checkbox"
                        id="kevCheckbox"
                        checked={simParams.isCisaKev}
                        onChange={(e) => {
                          const val = e.target.checked;
                          setSimParams(prev => {
                            const next = { ...prev, isCisaKev: val };
                            evaluateCustomRisk(next);
                            return next;
                          });
                        }}
                        className="rounded border-border text-red-500 focus:ring-red-500"
                      />
                      <label htmlFor="kevCheckbox" className="text-xs font-semibold text-foreground cursor-pointer">
                        CISA KEV Listed (+20 pt)
                      </label>
                    </div>

                    <div>
                      <select
                        className="w-full bg-background border border-border/70 rounded-lg px-2.5 py-2 text-xs text-foreground"
                        value={simParams.exploitAvailability}
                        onChange={(e) => {
                          const val = e.target.value;
                          setSimParams(prev => {
                            const next = { ...prev, exploitAvailability: val };
                            evaluateCustomRisk(next);
                            return next;
                          });
                        }}
                      >
                        <option value="WEAPONIZED">Weaponized (15 pt)</option>
                        <option value="PUBLIC_POC">Public Exploit (10 pt)</option>
                        <option value="THEORETICAL">Theoretical PoC (5 pt)</option>
                        <option value="NONE">No Exploit (0 pt)</option>
                      </select>
                    </div>
                  </div>
                </div>

                {/* Threat Telemetry Inputs */}
                <div className="pt-2 border-t border-border/40 space-y-3">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-semibold text-foreground">
                      Threat Intel & Confidence
                    </label>
                    <span className="text-[10px] font-mono text-muted-foreground">Max 20 pt</span>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-[11px] font-medium text-muted-foreground block mb-1">
                        Threat Severity (Max 10 pt)
                      </label>
                      <select
                        className="w-full bg-background border border-border/70 rounded-lg px-2.5 py-1.5 text-xs text-foreground"
                        value={simParams.threatSeverity}
                        onChange={(e) => {
                          const val = e.target.value;
                          setSimParams(prev => {
                            const next = { ...prev, threatSeverity: val };
                            evaluateCustomRisk(next);
                            return next;
                          });
                        }}
                      >
                        <option value="CRITICAL">CRITICAL (10 pt)</option>
                        <option value="HIGH">HIGH (7 pt)</option>
                        <option value="MEDIUM">MEDIUM (4 pt)</option>
                        <option value="LOW">LOW (1 pt)</option>
                      </select>
                    </div>

                    <div>
                      <label className="text-[11px] font-medium text-muted-foreground block mb-1">
                        Recency Window (Max 5 pt)
                      </label>
                      <select
                        className="w-full bg-background border border-border/70 rounded-lg px-2.5 py-1.5 text-xs text-foreground"
                        value={simParams.intelligenceRecencyDays}
                        onChange={(e) => {
                          const val = parseInt(e.target.value);
                          setSimParams(prev => {
                            const next = { ...prev, intelligenceRecencyDays: val };
                            evaluateCustomRisk(next);
                            return next;
                          });
                        }}
                      >
                        <option value={2}>Active Outbreak (&lt;=7d: 5 pt)</option>
                        <option value={15}>Recent Campaign (&lt;=30d: 3 pt)</option>
                        <option value={60}>Active Quarter (&lt;=90d: 2 pt)</option>
                        <option value={120}>Historical (&gt;90d: 1 pt)</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <label className="text-[11px] font-medium text-muted-foreground">
                        Threat Confidence: <span className="text-foreground font-mono font-bold">{simParams.threatConfidence}%</span>
                      </label>
                      <span className="text-[10px] text-muted-foreground font-mono">
                        {Math.round((simParams.threatConfidence / 100) * 5)} / 5 pt
                      </span>
                    </div>
                    <input
                      type="range"
                      min="20"
                      max="100"
                      step="5"
                      className="w-full accent-primary"
                      value={simParams.threatConfidence}
                      onChange={(e) => {
                        const val = parseInt(e.target.value);
                        setSimParams(prev => {
                          const next = { ...prev, threatConfidence: val };
                          evaluateCustomRisk(next);
                          return next;
                        });
                      }}
                    />
                  </div>
                </div>

                <button
                  onClick={() => evaluateCustomRisk()}
                  className="w-full py-2.5 rounded-lg bg-primary text-primary-foreground font-semibold text-xs flex items-center justify-center space-x-2 shadow-sm hover:bg-primary/90 transition-colors"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Execute Deterministic Evaluation</span>
                </button>
              </CardContent>
            </Card>
          )}

          {activeTab === "inventory" && (
            <Card className="border-border/80">
              <CardHeader className="pb-3 border-b border-border/60">
                <CardTitle className="text-sm font-semibold flex items-center space-x-2">
                  <Database className="w-4 h-4 text-primary" />
                  <span>Cross-Inventory Risk Ranking</span>
                </CardTitle>
                <p className="text-xs text-muted-foreground">
                  Live risk prioritization across active corporate assets.
                </p>
              </CardHeader>
              <CardContent className="p-3 space-y-2 max-h-[600px] overflow-y-auto">
                {loadingMatrix ? (
                  <div className="py-8 text-center text-muted-foreground animate-pulse">
                    Computing multi-asset risk matrix...
                  </div>
                ) : inventoryMatrix.length === 0 ? (
                  <div className="py-8 text-center text-muted-foreground text-xs">
                    No active assets found in inventory.
                  </div>
                ) : (
                  inventoryMatrix.map((item, idx) => (
                    <div
                      key={idx}
                      onClick={() => setAssessment(item)}
                      className={cn(
                        "p-3 rounded-lg border transition-all cursor-pointer flex items-center justify-between",
                        assessment?.targetAsset?.name === item.targetAsset?.name
                          ? "bg-primary/10 border-primary"
                          : "bg-background/60 border-border/50 hover:bg-secondary/40"
                      )}
                    >
                      <div className="space-y-0.5">
                        <div className="text-xs font-semibold text-foreground flex items-center space-x-1.5">
                          <Server className="w-3 h-3 text-muted-foreground" />
                          <span>{item.targetAsset?.name || "Asset"}</span>
                        </div>
                        <p className="text-[11px] text-muted-foreground truncate max-w-[200px]">
                          {item.vulnerability?.cveId || item.threat?.title || "Security Posture"}
                        </p>
                      </div>

                      <div className="flex items-center space-x-2">
                        <span className={cn(
                          "text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold",
                          item.level === "CRITICAL"
                            ? "bg-red-500/10 text-red-400 border-red-500/30"
                            : item.level === "HIGH"
                            ? "bg-orange-500/10 text-orange-400 border-orange-500/30"
                            : item.level === "MEDIUM"
                            ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                            : "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                        )}>
                          {item.score}/100
                        </span>
                        <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />
                      </div>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>
          )}
        </div>

        {/* Right Column: Explainable Risk Score Card Display */}
        <div className="lg:col-span-7 space-y-6">
          <ExplainableRiskScoreCard
            assessment={assessment}
            loading={loading}
            onRefresh={() => evaluateCustomRisk()}
          />
        </div>
      </div>
    </div>
  );
}

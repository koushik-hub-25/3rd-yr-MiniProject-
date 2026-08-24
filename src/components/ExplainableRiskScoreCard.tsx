import React, { useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  Server,
  Layers,
  Flame,
  CheckCircle2,
  Lock,
  Globe,
  Radio,
  Clock,
  Sparkles,
  HelpCircle,
  ChevronDown,
  ChevronUp,
  Cpu,
  ArrowUpRight
} from "lucide-react";
import { ExplainableRiskAssessment, RiskFactor, RiskLevel } from "../types";
import { Card, CardHeader, CardTitle, CardContent, Badge, SeverityBadge, cn } from "./ui";

interface ExplainableRiskScoreCardProps {
  assessment: ExplainableRiskAssessment | null;
  loading?: boolean;
  onRefresh?: () => void;
  compact?: boolean;
  className?: string;
  showRawFormula?: boolean;
  title?: string;
}

export function ExplainableRiskScoreCard({
  assessment,
  loading = false,
  onRefresh,
  compact = false,
  className = "",
  showRawFormula = true,
  title
}: ExplainableRiskScoreCardProps) {
  const [expandedFactors, setExpandedFactors] = useState(false);

  if (loading) {
    return (
      <Card className={cn("border-border/70 animate-pulse", className)}>
        <CardContent className="p-6">
          <div className="flex items-center space-x-4 mb-4">
            <div className="w-16 h-16 rounded-full bg-secondary/80"></div>
            <div className="flex-1 space-y-2">
              <div className="h-5 bg-secondary/80 rounded w-1/3"></div>
              <div className="h-4 bg-secondary/60 rounded w-1/2"></div>
            </div>
          </div>
          <div className="h-20 bg-secondary/50 rounded-lg"></div>
        </CardContent>
      </Card>
    );
  }

  if (!assessment) {
    return (
      <Card className={cn("border-border/70", className)}>
        <CardContent className="p-8 text-center text-muted-foreground">
          <ShieldAlert className="w-10 h-10 mx-auto mb-2 text-muted-foreground/50" />
          <p className="text-sm font-medium">No risk score assessment available</p>
          <p className="text-xs text-muted-foreground mt-1">Select an asset or threat to compute an explainable score.</p>
        </CardContent>
      </Card>
    );
  }

  const { score, level, factors, explanation, targetAsset, vulnerability, threat, formula } = assessment;

  // Level visual styles
  const getLevelColor = (lvl: RiskLevel) => {
    switch (lvl) {
      case "CRITICAL":
        return {
          bg: "bg-red-500/10 text-red-400 border-red-500/30",
          ring: "text-red-500 stroke-red-500",
          bar: "bg-red-500",
          glow: "shadow-[0_0_20px_rgba(239,68,68,0.2)]",
          icon: Flame
        };
      case "HIGH":
        return {
          bg: "bg-orange-500/10 text-orange-400 border-orange-500/30",
          ring: "text-orange-500 stroke-orange-500",
          bar: "bg-orange-500",
          glow: "shadow-[0_0_15px_rgba(249,115,22,0.15)]",
          icon: AlertTriangle
        };
      case "MEDIUM":
        return {
          bg: "bg-amber-500/10 text-amber-400 border-amber-500/30",
          ring: "text-amber-500 stroke-amber-500",
          bar: "bg-amber-500",
          glow: "shadow-[0_0_10px_rgba(245,158,11,0.1)]",
          icon: Info
        };
      case "LOW":
      default:
        return {
          bg: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
          ring: "text-emerald-500 stroke-emerald-500",
          bar: "bg-emerald-500",
          glow: "shadow-[0_0_10px_rgba(16,185,129,0.1)]",
          icon: ShieldCheck
        };
    }
  };

  const levelStyle = getLevelColor(level);
  const LevelIcon = levelStyle.icon;

  // Category badge colors
  const getCategoryColor = (cat: string) => {
    switch (cat) {
      case "VULNERABILITY":
        return "bg-purple-500/10 text-purple-400 border-purple-500/30";
      case "EXPLOITATION":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30";
      case "ASSET_IMPACT":
        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";
      case "THREAT_INTEL":
      default:
        return "bg-blue-500/10 text-blue-400 border-blue-500/30";
    }
  };

  // SVG Gauge calculations
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (Math.min(score, 100) / 100) * circumference;

  return (
    <Card id={`risk-assessment-${score}`} className={cn("border-border/80 overflow-hidden bg-card/90", levelStyle.glow, className)}>
      {/* Header Banner */}
      <div className="p-5 border-b border-border/60 bg-secondary/30 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className={cn("w-10 h-10 rounded-lg flex items-center justify-center border", levelStyle.bg)}>
            <LevelIcon className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h3 className="text-base font-semibold text-foreground tracking-tight">
                {title || "Deterministic Risk Scoring Engine"}
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">
                0-100 CALIBRATED
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              Explainable multi-factor scoring • Pure mathematical aggregation
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <span className={cn("text-xs font-bold px-3 py-1 rounded-full border uppercase tracking-wider", levelStyle.bg)}>
            {level} RISK
          </span>
        </div>
      </div>

      <CardContent className="p-6 space-y-6">
        {/* Top Summary: Score Gauge + Top Drivers */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
          {/* Circular Score Meter */}
          <div className="md:col-span-4 flex flex-col items-center justify-center p-4 rounded-xl bg-background/50 border border-border/60">
            <div className="relative w-32 h-32 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                <circle
                  cx="50"
                  cy="50"
                  r={radius}
                  className="stroke-secondary"
                  strokeWidth="8"
                  fill="transparent"
                />
                <circle
                  cx="50"
                  cy="50"
                  r={radius}
                  className={levelStyle.ring}
                  strokeWidth="8"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                  fill="transparent"
                  style={{ transition: "stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1)" }}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-3xl font-extrabold text-foreground tracking-tighter">
                  {score}
                </span>
                <span className="text-[10px] font-mono text-muted-foreground uppercase">
                  / 100 Points
                </span>
              </div>
            </div>

            <div className="text-center mt-3">
              <span className={cn("text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded border", levelStyle.bg)}>
                {level} SEVERITY
              </span>
              <p className="text-[11px] text-muted-foreground mt-1.5 font-mono">
                Formula contribution: {factors.reduce((acc, f) => acc + f.contribution, 0)} raw pts
              </p>
            </div>
          </div>

          {/* Natural Language Deterministic Explanation */}
          <div className="md:col-span-8 flex flex-col justify-between space-y-3 bg-secondary/20 p-4 rounded-xl border border-border/50">
            <div>
              <div className="flex items-center space-x-2 text-xs font-semibold text-foreground uppercase tracking-wider mb-2">
                <Sparkles className="w-3.5 h-3.5 text-primary" />
                <span>Explainable Assessment Summary</span>
              </div>
              <p className="text-sm text-foreground/90 leading-relaxed bg-background/60 p-3 rounded-lg border border-border/40 font-normal">
                {explanation}
              </p>
            </div>

            {/* Context Entity Badges */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2 border-t border-border/40">
              {/* Affected Asset */}
              <div className="bg-background/40 p-2.5 rounded-lg border border-border/30">
                <div className="flex items-center space-x-1.5 text-[11px] text-muted-foreground font-medium mb-1">
                  <Server className="w-3 h-3 text-cyan-400" />
                  <span>Affected Asset</span>
                </div>
                <div className="text-xs font-semibold text-foreground truncate" title={targetAsset?.name || "Unassigned"}>
                  {targetAsset?.name || "Corporate Perimeter"}
                </div>
                <div className="flex items-center space-x-1 mt-1">
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                    {targetAsset?.criticality || "HIGH"}
                  </span>
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-secondary text-muted-foreground border border-border/40">
                    {targetAsset?.exposure || "INTERNET"}
                  </span>
                </div>
              </div>

              {/* Vulnerability / CVE */}
              <div className="bg-background/40 p-2.5 rounded-lg border border-border/30">
                <div className="flex items-center space-x-1.5 text-[11px] text-muted-foreground font-medium mb-1">
                  <Flame className="w-3 h-3 text-purple-400" />
                  <span>Vulnerability</span>
                </div>
                <div className="text-xs font-semibold text-foreground font-mono truncate" title={vulnerability?.cveId || "N/A"}>
                  {vulnerability?.cveId || "General CVE Exposure"}
                </div>
                <div className="flex items-center space-x-1 mt-1">
                  {vulnerability?.cvssScore ? (
                    <span className="text-[9px] px-1.5 py-0.2 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 font-mono">
                      CVSS {vulnerability.cvssScore.toFixed(1)}
                    </span>
                  ) : null}
                  {vulnerability?.isCisaKev ? (
                    <span className="text-[9px] px-1.5 py-0.2 rounded bg-red-500/15 text-red-400 border border-red-500/30 font-bold">
                      CISA KEV
                    </span>
                  ) : null}
                </div>
              </div>

              {/* Threat Signature */}
              <div className="bg-background/40 p-2.5 rounded-lg border border-border/30">
                <div className="flex items-center space-x-1.5 text-[11px] text-muted-foreground font-medium mb-1">
                  <Radio className="w-3 h-3 text-blue-400" />
                  <span>Threat Intelligence</span>
                </div>
                <div className="text-xs font-semibold text-foreground truncate" title={threat?.title || "Active Threat Feed"}>
                  {threat?.title || "Active Threat Feed"}
                </div>
                <div className="flex items-center space-x-1 mt-1">
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                    {threat?.severity || "HIGH"}
                  </span>
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-secondary text-muted-foreground font-mono">
                    {threat?.confidence || 85}% Conf
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Transparent Factor Breakdown Table */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold text-foreground uppercase tracking-wider flex items-center space-x-2">
              <Layers className="w-3.5 h-3.5 text-primary" />
              <span>Transparent Factor Contributions ({factors.length} Drivers)</span>
            </h4>
            <button
              onClick={() => setExpandedFactors(!expandedFactors)}
              className="text-xs text-primary hover:text-primary/80 font-medium flex items-center space-x-1"
            >
              <span>{expandedFactors ? "Collapse details" : "View full factor details"}</span>
              {expandedFactors ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>
          </div>

          <div className="border border-border/60 rounded-xl overflow-hidden bg-background/40">
            <div className="divide-y divide-border/40">
              {factors.map((factor, index) => {
                const percentage = Math.round((factor.contribution / factor.maxPossible) * 100) || 0;
                const isTopContributor = factor.contribution >= 15;

                return (
                  <div
                    key={factor.name + index}
                    className={cn(
                      "p-3.5 transition-colors hover:bg-secondary/20",
                      isTopContributor && "bg-primary/[0.02]"
                    )}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center space-x-2.5">
                        <span className={cn("text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-medium", getCategoryColor(factor.category))}>
                          {factor.category.replace("_", " ")}
                        </span>
                        <div>
                          <span className="text-xs font-semibold text-foreground">
                            {factor.name}
                          </span>
                          <span className="text-xs text-muted-foreground ml-2 font-mono">
                            = {String(factor.value)}
                          </span>
                        </div>
                      </div>

                      {/* Contribution Indicator */}
                      <div className="flex items-center space-x-3 self-end sm:self-auto">
                        <div className="w-24 sm:w-32 bg-secondary/80 h-2 rounded-full overflow-hidden border border-border/40">
                          <div
                            className={cn(
                              "h-full rounded-full transition-all duration-500",
                              factor.contribution === factor.maxPossible
                                ? "bg-red-500"
                                : factor.contribution > 0
                                ? "bg-primary"
                                : "bg-muted"
                            )}
                            style={{ width: `${percentage}%` }}
                          />
                        </div>
                        <div className="w-20 text-right font-mono">
                          <span className={cn(
                            "text-xs font-bold",
                            factor.contribution > 0 ? "text-foreground" : "text-muted-foreground"
                          )}>
                            +{factor.contribution}
                          </span>
                          <span className="text-[10px] text-muted-foreground"> / {factor.maxPossible} pt</span>
                        </div>
                      </div>
                    </div>

                    {(expandedFactors || isTopContributor) && (
                      <p className="text-xs text-muted-foreground mt-1.5 pl-1 leading-normal font-normal">
                        {factor.description}
                      </p>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Mathematical Formula Footer */}
        {showRawFormula && (
          <div className="p-3 bg-secondary/30 rounded-lg border border-border/50 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] text-muted-foreground font-mono">
            <div className="flex items-center space-x-2">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>Deterministic Formula: Score = CVSS(25) + KEV(20) + Exploit(15) + Criticality(15) + Exposure(10) + Severity(10) + Confidence(5) + Recency(5)</span>
            </div>
            <span className="text-emerald-400 font-semibold uppercase">Verified Deterministic</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

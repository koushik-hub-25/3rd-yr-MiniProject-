import { fetchNvdCve } from "./nvdService";
import { checkCisaKev } from "./cisaKevService";
import { lookupMitreTechnique } from "./mitreService";

export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface RiskFactor {
  name: string;
  value: string | number | boolean;
  score: number; // 0 - 100
  contribution: number; // Weighted contribution towards final score
  maxPossible: number;
  weightPercentage: number;
  category: "SEVERITY" | "RECENCY" | "IOC" | "KEV" | "CVSS" | "MITRE" | "ASSET_IMPACT";
  description: string;
  source?: string;
  provenanceStatus?: "LIVE" | "CACHED" | "SYNTHETIC" | "ANALYST_VERIFIED";
  isSynthetic?: boolean;
}

export interface ExplainableRiskAssessment {
  score: number; // 0 - 100
  level: RiskLevel;
  factors: RiskFactor[];
  explanation: string;
  components: {
    severity: { raw: string; score: number; weight: number; contribution: number };
    recency: { ageHours: number; score: number; weight: number; contribution: number };
    ioc: { count: number; avgConfidence: number; score: number; weight: number; contribution: number };
    kev: { isCisaKev: boolean; ransomwareUse: string; score: number; weight: number; contribution: number };
    cvss: { rawCvss: number | null; score: number; weight: number; contribution: number };
    mitre: { techniqueCount: number; score: number; weight: number; contribution: number };
  };
  targetAsset?: {
    id?: string;
    name: string;
    criticality: string;
    exposure: string;
    environment?: string;
    ipAddress?: string | null;
  } | null;
  vulnerability?: {
    cveId: string;
    cvssScore: number;
    cvssSeverity: string;
    isCisaKev: boolean;
    description?: string;
    source?: string;
    provenanceStatus?: "LIVE" | "CACHED" | "SYNTHETIC";
  } | null;
  threat?: {
    id?: string;
    title: string;
    severity: string;
    confidence: number;
    detectedAt?: string | Date;
    isSynthetic?: boolean;
  } | null;
  dataProvenance?: {
    sources: {
      name: string;
      category: string;
      status: "LIVE" | "CACHED" | "SYNTHETIC" | "ANALYST_VERIFIED";
      isLive: boolean;
      isSynthetic: boolean;
    }[];
  };
  evaluatedAt: string;
  formula: string;
  decayFormula: string;
}

export interface RiskEvaluationParams {
  // Severity (0-100)
  severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN" | string;
  threatSeverity?: string;

  // Recency
  detectedAt?: string | Date;
  ageHours?: number;
  intelligenceRecencyDays?: number;

  // IOCs
  iocCount?: number;
  avgIocConfidence?: number;

  // Vulnerability & CISA KEV
  cveId?: string;
  cvssScore?: number;
  isCisaKev?: boolean;
  knownRansomwareUse?: boolean | string;
  vulnerabilitySourceStatus?: "LIVE" | "CACHED" | "SYNTHETIC";

  // MITRE ATT&CK
  mitreTechniqueCount?: number;
  mitreTechniques?: string[];

  // Exploit Availability
  exploitAvailability?: "WEAPONIZED" | "PUBLIC_POC" | "THEORETICAL" | "NONE" | string;

  // Asset Context
  assetId?: string;
  assetName?: string;
  assetCriticality?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string;
  assetExposure?: "INTERNET" | "INTERNAL" | "RESTRICTED" | string;
  assetEnvironment?: string;
  assetIp?: string;

  // Threat Info
  threatId?: string;
  threatTitle?: string;
  threatConfidence?: number;
  isSynthetic?: boolean;
}

/**
 * Deterministic multi-factor risk calculation:
 * Risk = 0.30×Severity + 0.20×Recency + 0.15×IOC + 0.15×KEV + 0.10×CVSS + 0.10×MITRE
 * Recency = 100 × exp(-ageHours / 720)
 */
export function calculateDeterministicRiskScore(params: RiskEvaluationParams): ExplainableRiskAssessment {
  const factors: RiskFactor[] = [];
  const isSynth = Boolean(params.isSynthetic);
  const vulnStatus = params.vulnerabilitySourceStatus || (isSynth ? "SYNTHETIC" : "CACHED");

  // -------------------------------------------------------------
  // 1. Severity Factor (Weight: 30%, Max contribution: 30 pts)
  // -------------------------------------------------------------
  const rawSev = (params.severity || params.threatSeverity || "MEDIUM").toUpperCase();
  let severityScore = 50;
  if (rawSev === "CRITICAL") severityScore = 100;
  else if (rawSev === "HIGH") severityScore = 75;
  else if (rawSev === "MEDIUM") severityScore = 50;
  else if (rawSev === "LOW" || rawSev === "INFORMATIONAL") severityScore = 25;
  else severityScore = 40;

  const severityContribution = Math.round(severityScore * 0.30 * 10) / 10;
  factors.push({
    name: "Threat Severity",
    value: rawSev,
    score: severityScore,
    contribution: severityContribution,
    maxPossible: 30,
    weightPercentage: 30,
    category: "SEVERITY",
    source: "Adversary Severity Classification",
    provenanceStatus: isSynth ? "SYNTHETIC" : "LIVE",
    isSynthetic: isSynth,
    description: `Threat severity classified as '${rawSev}' (${severityScore}/100 normalized) contributing ${severityContribution} points (30% weight).`
  });

  // -------------------------------------------------------------
  // 2. Recency Factor with 30-Day Half-Life Exponential Time Decay (Weight: 20%, Max: 20 pts)
  // Decay = 2^(-ageHours / 720) -> Exact 30-day (720 hours) half-life
  // -------------------------------------------------------------
  let ageHours = 0;
  if (typeof params.ageHours === "number" && !isNaN(params.ageHours) && params.ageHours >= 0) {
    ageHours = params.ageHours;
  } else if (params.detectedAt) {
    const d = new Date(params.detectedAt).getTime();
    if (!isNaN(d)) {
      ageHours = Math.max(0, (Date.now() - d) / (1000 * 60 * 60));
    }
  } else if (typeof params.intelligenceRecencyDays === "number") {
    ageHours = Math.max(0, params.intelligenceRecencyDays * 24);
  }

  // Pure mathematical exponential decay with 720-hour (30 days) half-life: 2^(-ageHours / 720)
  const decayMultiplier = Math.pow(2, -ageHours / 720);
  const recencyScore = Math.max(0, Math.min(100, Math.round(100 * decayMultiplier)));
  const recencyContribution = Math.round(recencyScore * 0.20 * 10) / 10;

  factors.push({
    name: "Intelligence Recency",
    value: `${ageHours < 24 ? ageHours.toFixed(1) + "h" : (ageHours / 24).toFixed(1) + "d"} ago`,
    score: recencyScore,
    contribution: recencyContribution,
    maxPossible: 20,
    weightPercentage: 20,
    category: "RECENCY",
    source: "Threat Telemetry Timestamp",
    provenanceStatus: isSynth ? "SYNTHETIC" : "LIVE",
    isSynthetic: isSynth,
    description: `Observation age of ${ageHours.toFixed(1)} hours (30-day half-life decay multiplier ${decayMultiplier.toFixed(3)}) yields recency score ${recencyScore}/100 (+${recencyContribution} points).`
  });

  // -------------------------------------------------------------
  // 3. IOC Indicator Factor (Weight: 15%, Max: 15 pts)
  // -------------------------------------------------------------
  const iocCount = Math.max(0, params.iocCount || 0);
  const avgConfidence = Math.max(0, Math.min(100, params.avgIocConfidence || 90));
  let iocScore = 0;
  if (iocCount > 0) {
    iocScore = Math.min(100, Math.round((iocCount * 20) * (avgConfidence / 100)));
  }

  const iocContribution = Math.round(iocScore * 0.15 * 10) / 10;
  factors.push({
    name: "IOC Evidence",
    value: `${iocCount} indicator(s)`,
    score: iocScore,
    contribution: iocContribution,
    maxPossible: 15,
    weightPercentage: 15,
    category: "IOC",
    source: "ShieldZen IOC Vault",
    provenanceStatus: isSynth ? "SYNTHETIC" : "ANALYST_VERIFIED",
    isSynthetic: isSynth,
    description: iocCount > 0
      ? `${iocCount} technical indicator(s) identified at ${avgConfidence}% confidence yields ${iocScore}/100 (+${iocContribution} points).`
      : "No associated indicators of compromise linked (0 points)."
  });

  // -------------------------------------------------------------
  // 4. CISA KEV Factor (Weight: 15%, Max: 15 pts)
  // -------------------------------------------------------------
  const isKev = Boolean(params.isCisaKev);
  const ransomwareStr = String(params.knownRansomwareUse || "").toLowerCase();
  const hasRansomware = ransomwareStr.includes("known") || ransomwareStr === "true";

  let kevScore = 0;
  if (isKev) {
    kevScore = hasRansomware ? 100 : 85;
  }

  const kevContribution = Math.round(kevScore * 0.15 * 10) / 10;
  factors.push({
    name: "CISA KEV Exploitation",
    value: isKev ? (hasRansomware ? "Active KEV + Ransomware" : "Active KEV") : "Not Listed",
    score: kevScore,
    contribution: kevContribution,
    maxPossible: 15,
    weightPercentage: 15,
    category: "KEV",
    source: "CISA Known Exploited Vulnerabilities Catalog",
    provenanceStatus: isSynth ? "SYNTHETIC" : vulnStatus,
    isSynthetic: isSynth,
    description: isKev
      ? `Confirmed active weaponized exploitation listed in CISA KEV${hasRansomware ? " with known ransomware campaigns" : ""} (${kevScore}/100 -> +${kevContribution} points).`
      : "No active exploitation cataloged in CISA KEV (0 points)."
  });

  // -------------------------------------------------------------
  // 5. CVSS Vulnerability Factor (Weight: 10%, Max: 10 pts)
  // -------------------------------------------------------------
  let rawCvss: number | null = null;
  let cvssScore = 50; // Neutral baseline default if missing

  if (typeof params.cvssScore === "number" && !isNaN(params.cvssScore) && params.cvssScore > 0) {
    rawCvss = Math.max(0, Math.min(10, params.cvssScore));
    cvssScore = Math.min(100, Math.max(0, Math.round(rawCvss * 10)));
  }

  const cvssContribution = Math.round(cvssScore * 0.10 * 10) / 10;
  factors.push({
    name: "CVSS Base Metric",
    value: rawCvss !== null ? rawCvss.toFixed(1) : "Unavailable (Default 5.0)",
    score: cvssScore,
    contribution: cvssContribution,
    maxPossible: 10,
    weightPercentage: 10,
    category: "CVSS",
    source: "NIST National Vulnerability Database (NVD)",
    provenanceStatus: isSynth ? "SYNTHETIC" : vulnStatus,
    isSynthetic: isSynth,
    description: rawCvss !== null
      ? `CVSS score of ${rawCvss.toFixed(1)}/10.0 scaled to ${cvssScore}/100 (+${cvssContribution} points).`
      : `CVSS metric unavailable; neutral default of 50/100 applied (+${cvssContribution} points).`
  });

  // -------------------------------------------------------------
  // 6. MITRE ATT&CK Factor (Weight: 10%, Max: 10 pts)
  // -------------------------------------------------------------
  const techCount = params.mitreTechniqueCount || (params.mitreTechniques ? params.mitreTechniques.length : 0);
  const mitreScore = Math.min(100, techCount * 25);
  const mitreContribution = Math.round(mitreScore * 0.10 * 10) / 10;

  factors.push({
    name: "MITRE ATT&CK Techniques",
    value: `${techCount} technique(s)`,
    score: mitreScore,
    contribution: mitreContribution,
    maxPossible: 10,
    weightPercentage: 10,
    category: "MITRE",
    source: "MITRE ATT&CK Enterprise Matrix",
    provenanceStatus: isSynth ? "SYNTHETIC" : "LIVE",
    isSynthetic: isSynth,
    description: techCount > 0
      ? `${techCount} mapped MITRE ATT&CK technique(s) yield ${mitreScore}/100 (+${mitreContribution} points).`
      : "No mapped adversary techniques linked (0 points)."
  });

  // -------------------------------------------------------------
  // 7. Aggregate Total & Strict Bounding [0, 100]
  // -------------------------------------------------------------
  const rawSum = severityContribution + recencyContribution + iocContribution + kevContribution + cvssContribution + mitreContribution;
  const finalScore = Math.min(100, Math.max(0, Math.round(rawSum)));

  // Risk Categories:
  // CRITICAL: 85 - 100
  // HIGH: 70 - 84
  // MEDIUM: 45 - 69
  // LOW: 0 - 44
  let level: RiskLevel = "LOW";
  if (finalScore >= 85) level = "CRITICAL";
  else if (finalScore >= 70) level = "HIGH";
  else if (finalScore >= 45) level = "MEDIUM";
  else level = "LOW";

  // Deterministic Explainability String
  const explanation = `Assessed as ${level} risk with an aggregate score of ${finalScore}/100. Formula: 0.30×Severity(${severityScore}) + 0.20×Recency(${recencyScore}) + 0.15×IOC(${iocScore}) + 0.15×KEV(${kevScore}) + 0.10×CVSS(${cvssScore}) + 0.10×MITRE(${mitreScore}). Primary contributors are: ${
    factors.sort((a, b) => b.contribution - a.contribution).slice(0, 3).map(f => `${f.name} (+${f.contribution} pts)`).join(", ")
  }.`;

  return {
    score: finalScore,
    level,
    factors,
    explanation,
    components: {
      severity: { raw: rawSev, score: severityScore, weight: 0.30, contribution: severityContribution },
      recency: { ageHours, score: recencyScore, weight: 0.20, contribution: recencyContribution },
      ioc: { count: iocCount, avgConfidence, score: iocScore, weight: 0.15, contribution: iocContribution },
      kev: { isCisaKev: isKev, ransomwareUse: hasRansomware ? "Known" : "Unknown", score: kevScore, weight: 0.15, contribution: kevContribution },
      cvss: { rawCvss, score: cvssScore, weight: 0.10, contribution: cvssContribution },
      mitre: { techniqueCount: techCount, score: mitreScore, weight: 0.10, contribution: mitreContribution }
    },
    targetAsset: params.assetName ? {
      id: params.assetId,
      name: params.assetName,
      criticality: params.assetCriticality || "MEDIUM",
      exposure: params.assetExposure || "INTERNAL",
      environment: params.assetEnvironment,
      ipAddress: params.assetIp || null
    } : null,
    vulnerability: params.cveId ? {
      cveId: params.cveId,
      cvssScore: rawCvss || (cvssScore / 10),
      cvssSeverity: cvssScore >= 90 ? "CRITICAL" : cvssScore >= 70 ? "HIGH" : cvssScore >= 40 ? "MEDIUM" : "LOW",
      isCisaKev: isKev,
      source: isKev ? "CISA KEV / NIST NVD" : "NIST NVD",
      provenanceStatus: isSynth ? "SYNTHETIC" : vulnStatus
    } : null,
    threat: params.threatTitle ? {
      id: params.threatId,
      title: params.threatTitle,
      severity: rawSev,
      confidence: params.threatConfidence || 85,
      detectedAt: params.detectedAt,
      isSynthetic: isSynth
    } : null,
    dataProvenance: {
      sources: [
        {
          name: "NIST National Vulnerability Database",
          category: "Vulnerability Catalog",
          status: isSynth ? "SYNTHETIC" : vulnStatus,
          isLive: vulnStatus === "LIVE",
          isSynthetic: isSynth
        },
        {
          name: "CISA Known Exploited Vulnerabilities",
          category: "Active Exploitation Catalog",
          status: isSynth ? "SYNTHETIC" : (isKev ? vulnStatus : "CACHED"),
          isLive: vulnStatus === "LIVE",
          isSynthetic: isSynth
        },
        {
          name: "MITRE ATT&CK Enterprise",
          category: "Adversary TTP Matrix",
          status: "LIVE",
          isLive: true,
          isSynthetic: isSynth
        }
      ]
    },
    evaluatedAt: new Date().toISOString(),
    formula: "Risk = 0.30×Severity + 0.20×Recency + 0.15×IOC + 0.15×KEV + 0.10×CVSS + 0.10×MITRE",
    decayFormula: "Recency = 100 × 2^(-ageHours / 720)"
  };
}

/**
 * Async helper to evaluate risk with live and local CTI datasets.
 */
export async function evaluateRiskWithLiveIntel(params: RiskEvaluationParams): Promise<ExplainableRiskAssessment> {
  let resolvedCvss = params.cvssScore;
  let resolvedKev = params.isCisaKev;
  let resolvedRansomware = params.knownRansomwareUse;
  let resolvedSourceStatus = params.vulnerabilitySourceStatus || "CACHED";

  if (params.cveId) {
    const cveNorm = params.cveId.toUpperCase().trim();
    if (resolvedCvss === undefined) {
      const nvd = await fetchNvdCve(cveNorm);
      if (nvd && typeof nvd.cvssScore === "number") {
        resolvedCvss = nvd.cvssScore;
        if (nvd.sourceStatus === "LIVE") {
          resolvedSourceStatus = "LIVE";
        }
      }
    }

    if (resolvedKev === undefined) {
      const kev = await checkCisaKev(cveNorm);
      if (kev && kev.isKnownExploited) {
        resolvedKev = true;
        if (kev.entry?.knownRansomwareCampaignUse) {
          resolvedRansomware = kev.entry.knownRansomwareCampaignUse;
        }
      }
    }
  }

  return calculateDeterministicRiskScore({
    ...params,
    cvssScore: resolvedCvss,
    isCisaKev: resolvedKev,
    knownRansomwareUse: resolvedRansomware,
    vulnerabilitySourceStatus: resolvedSourceStatus
  });
}

/**
 * Pre-defined benchmark scenarios covering all required risk tiers.
 */
export const BENCHMARK_RISK_SCENARIOS = {
  CRITICAL: {
    id: "scenario-critical",
    name: "Critical Risk Scenario",
    description: "Active CISA KEV weaponized zero-day RCE with known ransomware campaigns and 5 confirmed C2 IOCs.",
    params: {
      cveId: "CVE-2024-38077",
      cvssScore: 9.8,
      isCisaKev: true,
      knownRansomwareUse: "Known",
      severity: "CRITICAL",
      ageHours: 2,
      iocCount: 5,
      avgIocConfidence: 95,
      mitreTechniqueCount: 4,
      assetName: "prod-payment-gateway-01",
      assetCriticality: "CRITICAL",
      assetExposure: "INTERNET"
    }
  },
  HIGH: {
    id: "scenario-high",
    name: "High Risk Scenario",
    description: "High-severity CISA KEV exploitation advisory observed 4 days ago with 3 IOCs and MITRE techniques.",
    params: {
      cveId: "CVE-2023-34362",
      cvssScore: 8.8,
      isCisaKev: true,
      knownRansomwareUse: "Unknown",
      severity: "HIGH",
      ageHours: 96,
      iocCount: 3,
      avgIocConfidence: 90,
      mitreTechniqueCount: 2,
      assetName: "dmz-web-app-02",
      assetCriticality: "HIGH",
      assetExposure: "INTERNET"
    }
  },
  MEDIUM: {
    id: "scenario-medium",
    name: "Medium Risk Scenario",
    description: "Medium-severity internal threat with 2 IOCs and MITRE T1059 observed 10 days ago (no active KEV).",
    params: {
      cveId: "CVE-2023-23397",
      cvssScore: 6.5,
      isCisaKev: false,
      severity: "MEDIUM",
      ageHours: 240, // 10 days
      iocCount: 2,
      avgIocConfidence: 85,
      mitreTechniqueCount: 2,
      assetName: "corp-internal-db-04",
      assetCriticality: "MEDIUM",
      assetExposure: "INTERNAL"
    }
  },
  LOW: {
    id: "scenario-low",
    name: "Low Risk Scenario",
    description: "Informational low-severity event observed 45 days ago with no active exploits or IOCs.",
    params: {
      severity: "LOW",
      ageHours: 1080, // 45 days
      iocCount: 0,
      isCisaKev: false,
      cvssScore: 3.2,
      mitreTechniqueCount: 0,
      assetName: "dev-test-sandbox-09",
      assetCriticality: "LOW",
      assetExposure: "RESTRICTED"
    }
  }
};

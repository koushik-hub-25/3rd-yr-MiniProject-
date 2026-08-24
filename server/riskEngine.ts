import { fetchNvdCve, NvdVulnerability } from "./nvdService";
import { checkCisaKev, CisaKevEntry } from "./cisaKevService";

export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface RiskFactor {
  name: string;
  value: string | number | boolean;
  contribution: number;
  maxPossible: number;
  weightPercentage: number;
  category: "VULNERABILITY" | "EXPLOITATION" | "ASSET_IMPACT" | "THREAT_INTEL";
  description: string;
}

export interface ExplainableRiskAssessment {
  score: number; // 0 - 100
  level: RiskLevel;
  factors: RiskFactor[];
  explanation: string;
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
  } | null;
  threat?: {
    id?: string;
    title: string;
    severity: string;
    confidence: number;
    detectedAt?: string | Date;
  } | null;
  evaluatedAt: string;
  formula: string;
}

export interface RiskEvaluationParams {
  // Vulnerability inputs
  cveId?: string;
  cvssScore?: number;
  isCisaKev?: boolean;

  // Exploit Availability
  exploitAvailability?: "WEAPONIZED" | "PUBLIC_POC" | "THEORETICAL" | "NONE" | string;

  // Asset inputs
  assetId?: string;
  assetName?: string;
  assetCriticality?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string;
  assetExposure?: "INTERNET" | "INTERNAL" | "RESTRICTED" | string;
  assetEnvironment?: string;
  assetIp?: string;

  // Threat Intel inputs
  threatId?: string;
  threatTitle?: string;
  threatSeverity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL" | string;
  threatConfidence?: number; // 0 - 100
  intelligenceRecencyDays?: number; // e.g. 3 days ago
  detectedAt?: string | Date;
}

/**
 * Deterministic calculation of risk score (0-100) and transparent factor breakdown.
 * Pure mathematical logic: AI does NOT decide the numerical score.
 */
export function calculateDeterministicRiskScore(params: RiskEvaluationParams): ExplainableRiskAssessment {
  const factors: RiskFactor[] = [];
  let rawSum = 0;

  // 1. CVSS Base Score Factor (Max 25 pts)
  // Scale: 0.0 - 10.0 => 0 - 25 points
  const rawCvss = typeof params.cvssScore === "number" ? Math.max(0, Math.min(10, params.cvssScore)) : 0;
  const cvssContribution = Math.min(25, Math.max(0, Math.round((rawCvss / 10.0) * 25)));
  rawSum += cvssContribution;
  factors.push({
    name: "CVSS",
    value: rawCvss,
    contribution: cvssContribution,
    maxPossible: 25,
    weightPercentage: 25,
    category: "VULNERABILITY",
    description: rawCvss > 0
      ? `Base CVSS score of ${rawCvss.toFixed(1)}/10.0 contributes ${cvssContribution} points (normalized to 25% max weight).`
      : "No direct CVSS base metric available (0 points)."
  });

  // 2. CISA KEV Status Factor (Max 20 pts)
  // Listed in KEV means confirmed active weaponized exploitation in the wild
  const isKev = Boolean(params.isCisaKev);
  const kevContribution = isKev ? 20 : 0;
  rawSum += kevContribution;
  factors.push({
    name: "CISA KEV",
    value: isKev,
    contribution: kevContribution,
    maxPossible: 20,
    weightPercentage: 20,
    category: "EXPLOITATION",
    description: isKev
      ? "Confirmed active weaponized in-the-wild exploitation cataloged in CISA KEV (+20 points)."
      : "Not listed in CISA Known Exploited Vulnerabilities catalog (0 points)."
  });

  // 3. Exploit Availability Factor (Max 15 pts)
  const exploit = (params.exploitAvailability || "NONE").toUpperCase();
  let exploitContribution = 0;
  let exploitLabel = "None / Unproven";

  if (exploit.includes("WEAPON") || exploit.includes("ACTIVE") || (isKev && exploit === "NONE")) {
    exploitContribution = 15;
    exploitLabel = "Weaponized / Active";
  } else if (exploit.includes("PUBLIC") || exploit.includes("POC") || exploit.includes("FUNCTIONAL")) {
    exploitContribution = 10;
    exploitLabel = "Public Exploit / PoC";
  } else if (exploit.includes("THEORETICAL") || exploit.includes("PROOF")) {
    exploitContribution = 5;
    exploitLabel = "Theoretical PoC";
  } else {
    exploitContribution = 0;
    exploitLabel = "None / Unproven";
  }
  rawSum += exploitContribution;
  factors.push({
    name: "Exploit Availability",
    value: exploitLabel,
    contribution: exploitContribution,
    maxPossible: 15,
    weightPercentage: 15,
    category: "EXPLOITATION",
    description: `Exploit maturity level assessed as '${exploitLabel}' (${exploitContribution} points).`
  });

  // 4. Asset Criticality Factor (Max 15 pts)
  const crit = (params.assetCriticality || "MEDIUM").toUpperCase();
  let critContribution = 5;
  if (crit === "CRITICAL") critContribution = 15;
  else if (crit === "HIGH") critContribution = 10;
  else if (crit === "MEDIUM") critContribution = 5;
  else if (crit === "LOW") critContribution = 2;

  rawSum += critContribution;
  factors.push({
    name: "Asset Criticality",
    value: crit,
    contribution: critContribution,
    maxPossible: 15,
    weightPercentage: 15,
    category: "ASSET_IMPACT",
    description: `Target asset criticality classified as ${crit} (+${critContribution} points).`
  });

  // 5. Asset Exposure Factor (Max 10 pts)
  const exposure = (params.assetExposure || "INTERNAL").toUpperCase();
  let exposureContribution = 5;
  if (exposure === "INTERNET") exposureContribution = 10;
  else if (exposure === "INTERNAL") exposureContribution = 5;
  else if (exposure === "RESTRICTED") exposureContribution = 1;

  rawSum += exposureContribution;
  factors.push({
    name: "Asset Exposure",
    value: exposure,
    contribution: exposureContribution,
    maxPossible: 10,
    weightPercentage: 10,
    category: "ASSET_IMPACT",
    description: exposure === "INTERNET"
      ? "Internet-facing asset with direct external perimeter attack surface (+10 points)."
      : exposure === "INTERNAL"
      ? "Internal enterprise network asset with indirect lateral exposure (+5 points)."
      : "Restricted air-gapped or isolated security enclave (+1 point)."
  });

  // 6. Threat Severity Factor (Max 10 pts)
  const sev = (params.threatSeverity || "MEDIUM").toUpperCase();
  let sevContribution = 4;
  if (sev === "CRITICAL") sevContribution = 10;
  else if (sev === "HIGH") sevContribution = 7;
  else if (sev === "MEDIUM") sevContribution = 4;
  else if (sev === "LOW") sevContribution = 1;
  else if (sev === "INFORMATIONAL") sevContribution = 0;

  rawSum += sevContribution;
  factors.push({
    name: "Threat Severity",
    value: sev,
    contribution: sevContribution,
    maxPossible: 10,
    weightPercentage: 10,
    category: "THREAT_INTEL",
    description: `Observed threat indicator severity assessed as ${sev} (+${sevContribution} points).`
  });

  // 7. Threat Confidence Factor (Max 5 pts)
  const conf = typeof params.threatConfidence === "number" ? Math.max(0, Math.min(100, params.threatConfidence)) : 75;
  const confContribution = Math.min(5, Math.max(0, Math.round((conf / 100.0) * 5)));
  rawSum += confContribution;
  factors.push({
    name: "Threat Confidence",
    value: `${conf}%`,
    contribution: confContribution,
    maxPossible: 5,
    weightPercentage: 5,
    category: "THREAT_INTEL",
    description: `Telemetry and attribution confidence at ${conf}% contributes ${confContribution} points.`
  });

  // 8. Intelligence Recency Factor (Max 5 pts)
  let recencyDays = 14;
  if (typeof params.intelligenceRecencyDays === "number") {
    recencyDays = params.intelligenceRecencyDays;
  } else if (params.detectedAt) {
    const diffMs = Date.now() - new Date(params.detectedAt).getTime();
    recencyDays = Math.max(0, Math.floor(diffMs / (1000 * 60 * 60 * 24)));
  }

  let recencyContribution = 1;
  let recencyLabel = `${recencyDays} days ago`;
  if (recencyDays <= 7) {
    recencyContribution = 5;
    recencyLabel = `Active outbreak (<=7d, ${recencyDays}d)`;
  } else if (recencyDays <= 30) {
    recencyContribution = 3;
    recencyLabel = `Recent campaign (<=30d, ${recencyDays}d)`;
  } else if (recencyDays <= 90) {
    recencyContribution = 2;
    recencyLabel = `Active quarter (<=90d, ${recencyDays}d)`;
  } else {
    recencyContribution = 1;
    recencyLabel = `Historical (>90d, ${recencyDays}d)`;
  }

  rawSum += recencyContribution;
  factors.push({
    name: "Intelligence Recency",
    value: recencyLabel,
    contribution: recencyContribution,
    maxPossible: 5,
    weightPercentage: 5,
    category: "THREAT_INTEL",
    description: `Intelligence recency window '${recencyLabel}' contributes ${recencyContribution} points.`
  });

  // Strict 0 - 100 Bounding
  const finalScore = Math.min(100, Math.max(0, rawSum));

  // Determine Risk Level Tier
  let level: RiskLevel = "LOW";
  if (finalScore >= 80) level = "CRITICAL";
  else if (finalScore >= 60) level = "HIGH";
  else if (finalScore >= 30) level = "MEDIUM";
  else level = "LOW";

  // Generate Transparent, Deterministic Explanation
  const topDrivers = [...factors]
    .sort((a, b) => b.contribution - a.contribution)
    .filter(f => f.contribution > 0)
    .slice(0, 3)
    .map(f => `${f.name} (+${f.contribution} pts)`);

  const assetDetails = params.assetName
    ? `targeting '${params.assetName}' (${crit} criticality, ${exposure.toLowerCase()} exposure)`
    : `assessed under ${crit} asset criticality (${exposure.toLowerCase()} exposure)`;

  const vulnDetails = params.cveId
    ? `vulnerability ${params.cveId} (CVSS: ${rawCvss > 0 ? rawCvss.toFixed(1) : "N/A"}${isKev ? ", CISA KEV active" : ""})`
    : `threat signature ${params.threatTitle || "Generic Threat"}`;

  const explanation = `Assessed as ${level} risk with an aggregate score of ${finalScore}/100. Primary risk drivers are ${topDrivers.join(", ")}. This reflects ${vulnDetails} ${assetDetails} with '${exploitLabel}' exploit availability and ${conf}% intelligence confidence.`;

  return {
    score: finalScore,
    level,
    factors,
    explanation,
    targetAsset: params.assetName ? {
      id: params.assetId,
      name: params.assetName,
      criticality: crit,
      exposure,
      environment: params.assetEnvironment,
      ipAddress: params.assetIp || null
    } : null,
    vulnerability: params.cveId ? {
      cveId: params.cveId,
      cvssScore: rawCvss,
      cvssSeverity: rawCvss >= 9.0 ? "CRITICAL" : rawCvss >= 7.0 ? "HIGH" : rawCvss >= 4.0 ? "MEDIUM" : "LOW",
      isCisaKev: isKev
    } : null,
    threat: params.threatTitle ? {
      id: params.threatId,
      title: params.threatTitle,
      severity: sev,
      confidence: conf,
      detectedAt: params.detectedAt
    } : null,
    evaluatedAt: new Date().toISOString(),
    formula: "Score = CVSS(25) + CISA_KEV(20) + Exploit(15) + Criticality(15) + Exposure(10) + Severity(10) + Confidence(5) + Recency(5) [Capped at 100]"
  };
}

/**
 * Async helper to evaluate risk with live or cached NVD and CISA KEV data integration.
 */
export async function evaluateRiskWithLiveIntel(params: RiskEvaluationParams): Promise<ExplainableRiskAssessment> {
  let resolvedCvss = params.cvssScore;
  let resolvedKev = params.isCisaKev;
  let resolvedExploit = params.exploitAvailability;

  if (params.cveId) {
    const cveNorm = params.cveId.toUpperCase().trim();
    if (resolvedCvss === undefined) {
      const nvd = await fetchNvdCve(cveNorm);
      if (nvd && typeof nvd.cvssScore === "number") {
        resolvedCvss = nvd.cvssScore;
      }
    }

    if (resolvedKev === undefined) {
      const kev = await checkCisaKev(cveNorm);
      if (kev && kev.isKnownExploited) {
        resolvedKev = true;
        if (!resolvedExploit || resolvedExploit === "NONE") {
          resolvedExploit = "WEAPONIZED";
        }
      }
    }
  }

  return calculateDeterministicRiskScore({
    ...params,
    cvssScore: resolvedCvss,
    isCisaKev: resolvedKev,
    exploitAvailability: resolvedExploit
  });
}

/**
 * Pre-defined benchmark scenarios covering all required risk tiers:
 * - Critical Risk
 * - High Risk
 * - Medium Risk
 * - Low Risk
 */
export const BENCHMARK_RISK_SCENARIOS = {
  CRITICAL: {
    id: "scenario-critical",
    name: "Critical Risk Scenario",
    description: "Active CISA KEV zero-day remote code execution weaponized against an internet-facing core payment gateway.",
    params: {
      cveId: "CVE-2024-38077",
      cvssScore: 9.8,
      isCisaKev: true,
      exploitAvailability: "WEAPONIZED",
      assetName: "prod-payment-gateway-01",
      assetCriticality: "CRITICAL",
      assetExposure: "INTERNET",
      assetEnvironment: "Production",
      assetIp: "198.51.100.42",
      threatTitle: "Active Pre-Auth Remote Code Execution in RDS Licensing",
      threatSeverity: "CRITICAL",
      threatConfidence: 98,
      intelligenceRecencyDays: 2
    }
  },
  HIGH: {
    id: "scenario-high",
    name: "High Risk Scenario",
    description: "High CVSS command injection with public exploit code targeting an internet-facing customer portal node.",
    params: {
      cveId: "CVE-2024-21887",
      cvssScore: 8.2,
      isCisaKev: false,
      exploitAvailability: "PUBLIC_POC",
      assetName: "api-edge-proxy-us-east",
      assetCriticality: "HIGH",
      assetExposure: "INTERNET",
      assetEnvironment: "Production",
      assetIp: "203.0.113.15",
      threatTitle: "Ivanti Gateway Command Injection Probe",
      threatSeverity: "HIGH",
      threatConfidence: 85,
      intelligenceRecencyDays: 14
    }
  },
  MEDIUM: {
    id: "scenario-medium",
    name: "Medium Risk Scenario",
    description: "Medium CVSS theoretical denial of service vulnerability targeting an internal staging database cluster.",
    params: {
      cveId: "CVE-2023-44487",
      cvssScore: 5.3,
      isCisaKev: false,
      exploitAvailability: "THEORETICAL",
      assetName: "db-replica-cluster-02",
      assetCriticality: "MEDIUM",
      assetExposure: "INTERNAL",
      assetEnvironment: "Staging",
      assetIp: "10.240.12.88",
      threatTitle: "HTTP/2 Rapid Reset Flow Disruption",
      threatSeverity: "MEDIUM",
      threatConfidence: 70,
      intelligenceRecencyDays: 45
    }
  },
  LOW: {
    id: "scenario-low",
    name: "Low Risk Scenario",
    description: "Low CVSS informational flaw with no exploit code located on an isolated, air-gapped development machine.",
    params: {
      cveId: "CVE-2023-23397",
      cvssScore: 2.5,
      isCisaKev: false,
      exploitAvailability: "NONE",
      assetName: "dev-sandbox-node-04",
      assetCriticality: "LOW",
      assetExposure: "RESTRICTED",
      assetEnvironment: "Development",
      assetIp: "172.16.99.14",
      threatTitle: "Legacy Protocol Information Disclosure",
      threatSeverity: "LOW",
      threatConfidence: 50,
      intelligenceRecencyDays: 120
    }
  }
};

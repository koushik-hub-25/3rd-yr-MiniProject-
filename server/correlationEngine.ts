import { fetchNvdCve, NvdVulnerability } from "./nvdService";
import { checkCisaKev, CisaKevEntry } from "./cisaKevService";
import { lookupMitreTechnique, MitreTechnique } from "./mitreService";
import { calculateDeterministicRiskScore, ExplainableRiskAssessment } from "./riskEngine";

export interface CorrelatedThreatIntel {
  cveId?: string;
  nvdData?: NvdVulnerability | null;
  cisaKevData?: { isKnownExploited: boolean; entry?: CisaKevEntry; source: string } | null;
  mitreMapping?: MitreTechnique[];
  riskPriority: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  priorityScore: number; // 0 - 100
  confidence: number;
  reasoningPoints: string[];
  sourceAttribution: string[];
  recommendationMatrix: string[];
  explainableRiskAssessment?: ExplainableRiskAssessment | null;
}

/**
 * Correlates threat indicators (CVEs, MITRE techniques, malware names) against
 * NVD, CISA KEV, and MITRE ATT&CK datasets to generate explainable risk prioritization.
 */
export async function correlateThreatIndicators(params: {
  text?: string;
  cveCandidates?: string[];
  mitreCandidates?: string[];
  initialSeverity?: string;
  threatTitle?: string;
}): Promise<CorrelatedThreatIntel> {
  const { text = "", cveCandidates = [], mitreCandidates = [], initialSeverity = "HIGH", threatTitle = "" } = params;

  // Extract any CVEs mentioned in text if not explicitly provided
  const combinedCveList = [...cveCandidates];
  const cveRegex = /CVE-\d{4}-\d{4,7}/gi;
  const matches = (text + " " + threatTitle).match(cveRegex) || [];
  for (const m of matches) {
    const norm = m.toUpperCase();
    if (!combinedCveList.includes(norm)) {
      combinedCveList.push(norm);
    }
  }

  let primaryNvd: NvdVulnerability | null = null;
  let primaryKev: { isKnownExploited: boolean; entry?: CisaKevEntry; source: string } | null = null;
  const reasoningPoints: string[] = [];
  const sourceAttribution: string[] = ["ShieldZen AI Correlation Engine"];
  let baseScore = 65;

  if (initialSeverity === "CRITICAL") baseScore = 85;
  else if (initialSeverity === "HIGH") baseScore = 75;
  else if (initialSeverity === "MEDIUM") baseScore = 55;
  else if (initialSeverity === "LOW") baseScore = 35;

  // 1. Correlate with NVD & CISA KEV if CVE present
  if (combinedCveList.length > 0) {
    const primaryCve = combinedCveList[0];
    primaryNvd = await fetchNvdCve(primaryCve);
    primaryKev = await checkCisaKev(primaryCve);

    if (primaryNvd) {
      sourceAttribution.push("National Vulnerability Database (NIST)");
      reasoningPoints.push(`NVD CVSS v3.1 base score assessed at ${primaryNvd.cvssScore} (${primaryNvd.cvssSeverity}).`);
      if (primaryNvd.cvssScore >= 9.0) baseScore += 15;
      else if (primaryNvd.cvssScore >= 7.5) baseScore += 8;
    }

    if (primaryKev?.isKnownExploited) {
      sourceAttribution.push("CISA Known Exploited Vulnerabilities (KEV) Catalog");
      reasoningPoints.push(`Listed on the CISA KEV Catalog with confirmed active in-the-wild weaponization (Action Due: ${primaryKev.entry?.dueDate || "Immediate"}).`);
      baseScore += 20;
      if (primaryKev.entry?.knownRansomwareCampaignUse === "Known") {
        reasoningPoints.push("CISA flags confirmed association with active Ransomware campaign distribution.");
        baseScore += 10;
      }
    } else {
      reasoningPoints.push("No active CISA KEV in-the-wild exploitation catalog listing detected for this vulnerability.");
    }
  } else {
    reasoningPoints.push("Identified behavioral attack heuristics without specific CVE binding.");
  }

  // 2. Correlate with MITRE ATT&CK Matrix
  const mitreMapping: MitreTechnique[] = [];
  const allMitreSources = [...mitreCandidates];
  // Auto-scan text for MITRE keywords
  const possibleTechs = ["T1566", "T1190", "T1059", "T1078", "T1486", "T1027", "T1071", "T1003", "T1567"];
  for (const tId of possibleTechs) {
    if ((text + " " + threatTitle).toUpperCase().includes(tId) && !allMitreSources.includes(tId)) {
      allMitreSources.push(tId);
    }
  }

  for (const item of allMitreSources) {
    const tech = lookupMitreTechnique(item);
    if (tech && !mitreMapping.some(m => m.id === tech.id)) {
      mitreMapping.push(tech);
      if (!sourceAttribution.includes("MITRE ATT&CK Framework")) {
        sourceAttribution.push("MITRE ATT&CK Framework");
      }
    }
  }

  if (mitreMapping.length > 0) {
    reasoningPoints.push(`Correlated to ${mitreMapping.length} MITRE ATT&CK technique(s): ${mitreMapping.map(m => `${m.id} (${m.name})`).join(", ")}.`);
  }

  // Calculate final priority
  const cappedScore = Math.min(Math.max(baseScore, 20), 99);
  let riskPriority: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" = "MEDIUM";
  if (cappedScore >= 85 || primaryKev?.isKnownExploited) {
    riskPriority = "CRITICAL";
  } else if (cappedScore >= 70) {
    riskPriority = "HIGH";
  } else if (cappedScore >= 45) {
    riskPriority = "MEDIUM";
  } else {
    riskPriority = "LOW";
  }

  const recommendationMatrix: string[] = [];
  if (primaryKev?.isKnownExploited) {
    recommendationMatrix.push(`[CISA KEV Mandate] ${primaryKev.entry?.requiredAction || "Isolate affected assets and patch immediately."}`);
  }
  if (primaryNvd?.affectedProducts?.length) {
    recommendationMatrix.push(`Audit perimeter exposure for affected software: ${primaryNvd.affectedProducts.join(", ")}.`);
  }
  if (mitreMapping.some(m => m.id === "T1486")) {
    recommendationMatrix.push("Deploy immutable offline backup verification and block suspicious Volume Shadow Copy deletions.");
  }
  if (mitreMapping.some(m => m.id === "T1566")) {
    recommendationMatrix.push("Implement strict email quarantine rules for high-risk inbound attachments and spoofed domains.");
  }

  // Calculate deterministic explainable risk assessment
  const explainableAssessment = calculateDeterministicRiskScore({
    cveId: combinedCveList[0],
    cvssScore: primaryNvd?.cvssScore,
    isCisaKev: primaryKev?.isKnownExploited,
    exploitAvailability: primaryKev?.isKnownExploited ? "WEAPONIZED" : primaryNvd?.cvssScore ? "PUBLIC_POC" : "THEORETICAL",
    threatTitle: params.threatTitle || (combinedCveList[0] ? `Threat targeting ${combinedCveList[0]}` : "Correlated Threat Pattern"),
    threatSeverity: params.initialSeverity || riskPriority,
    threatConfidence: 88 + (mitreMapping.length > 0 ? 4 : 0) + (primaryKev?.isKnownExploited ? 5 : 0),
    assetCriticality: "HIGH",
    assetExposure: "INTERNET"
  });

  return {
    cveId: combinedCveList[0],
    nvdData: primaryNvd,
    cisaKevData: primaryKev,
    mitreMapping,
    riskPriority,
    priorityScore: cappedScore,
    confidence: 88 + (mitreMapping.length > 0 ? 4 : 0) + (primaryKev?.isKnownExploited ? 5 : 0),
    reasoningPoints,
    sourceAttribution,
    recommendationMatrix: recommendationMatrix.length > 0 ? recommendationMatrix : ["Monitor egress telemetry for anomalous connections."],
    explainableRiskAssessment: explainableAssessment
  };
}

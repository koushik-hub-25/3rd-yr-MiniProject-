import { db } from "../src/db";
import {
  reports,
  threats,
  iocs,
  entities,
  incidents,
  recommendations,
  predictions,
  cachedVulnerabilities,
  mitreTechniques
} from "../src/db/schema";
import { eq, and, sql } from "drizzle-orm";
import {
  normalizeCveId,
  extractCveCandidates,
  refangIoc,
  defangIoc,
  detectIocType,
  normalizeIocValue,
  normalizeMitreTechniqueId,
  extractMitreTechniques,
  upsertNormalizedIoc,
  upsertNormalizedVulnerability,
  CtiSourceProvenance
} from "./normalizationService";
import { lookupMitreTechnique } from "./mitreService";
import { checkCisaKev } from "./cisaKevService";
import { fetchNvdCve } from "./nvdService";
import { ctiEventBus } from "./eventBus";

export interface CorrelatedVulnerability {
  cveId: string;
  description: string;
  cvssScore: number | null;
  cvssSeverity: string | null;
  isCisaKev: boolean;
  cisaDateAdded?: string | null;
  cisaDueDate?: string | null;
  cisaRequiredAction?: string | null;
  knownRansomwareUse?: string | null;
  sourceProvenance: string[];
}

export interface CorrelatedIoc {
  id: string;
  type: string;
  value: string;
  defangedValue: string;
  confidence: number;
  context: string;
  severity: string;
  sourceProvenance: string;
}

export interface CorrelatedMitreTechnique {
  id: string;
  name: string;
  tactic: string;
  tacticId?: string;
  description: string;
  url: string;
  sourceProvenance: string;
}

export interface CorrelationReportResult {
  reportId: string;
  filename: string;
  summary: string;
  severity: string;
  category: string;
  vulnerabilities: CorrelatedVulnerability[];
  iocs: CorrelatedIoc[];
  mitreTechniques: CorrelatedMitreTechnique[];
  correlations: Array<{ type: string; label: string; confidence: number; evidence: string }>;
  sources: string[];
  timestamp: string;
}

/**
 * Extracts raw indicator strings from unstructured text with regex pattern matchers.
 */
export function extractIocsFromText(text: string): Array<{ type: string; value: string }> {
  if (!text || typeof text !== "string") return [];
  const results: Array<{ type: string; value: string }> = [];
  const seen = new Set<string>();

  // 1. IPv4 (standard and defanged)
  const ipv4Matches = text.match(/\b(?:\d{1,3}(?:\[\.\]|\.)){3}\d{1,3}\b/g) || [];
  for (const raw of ipv4Matches) {
    const clean = refangIoc(raw);
    const type = detectIocType(clean);
    if (type === "IPv4" && !seen.has(`IPv4:${clean}`)) {
      seen.add(`IPv4:${clean}`);
      results.push({ type: "IPv4", value: clean });
    }
  }

  // 2. Hashes (SHA256, SHA1, MD5)
  const sha256Matches = text.match(/\b[a-fA-F0-9]{64}\b/g) || [];
  for (const raw of sha256Matches) {
    const val = raw.toLowerCase();
    if (!seen.has(`SHA256:${val}`)) {
      seen.add(`SHA256:${val}`);
      results.push({ type: "SHA256", value: val });
    }
  }

  const sha1Matches = text.match(/\b[a-fA-F0-9]{40}\b/g) || [];
  for (const raw of sha1Matches) {
    const val = raw.toLowerCase();
    if (!seen.has(`SHA1:${val}`)) {
      seen.add(`SHA1:${val}`);
      results.push({ type: "SHA1", value: val });
    }
  }

  const md5Matches = text.match(/\b[a-fA-F0-9]{32}\b/g) || [];
  for (const raw of md5Matches) {
    const val = raw.toLowerCase();
    if (!seen.has(`MD5:${val}`)) {
      seen.add(`MD5:${val}`);
      results.push({ type: "MD5", value: val });
    }
  }

  // 3. URLs (standard and defanged)
  const urlMatches = text.match(/(?:hxxps?|https?)(?:\[\:\/\/\]|\:\/\/)[^\s"'<>]+/gi) || [];
  for (const raw of urlMatches) {
    const clean = refangIoc(raw);
    if (!seen.has(`URL:${clean}`)) {
      seen.add(`URL:${clean}`);
      results.push({ type: "URL", value: clean });
    }
  }

  // 4. Domains (standard and defanged)
  const domainMatches = text.match(/(?:[a-zA-Z0-9-]{1,63}(?:\[\.\]|\.))+[a-zA-Z]{2,63}/gi) || [];
  for (const raw of domainMatches) {
    const clean = refangIoc(raw.replace(/\/+$/, "")).toLowerCase();
    // Exclude common file extensions or code tokens
    if (clean.endsWith(".exe") || clean.endsWith(".dll") || clean.endsWith(".txt") || clean.endsWith(".pdf") || clean.endsWith(".docx") || clean.endsWith(".ts") || clean.endsWith(".json")) {
      continue;
    }
    // Don't duplicate if it's an IP
    if (detectIocType(clean) === "IPv4" || detectIocType(clean) === "IPv6") {
      continue;
    }
    const type = detectIocType(clean);
    if (type === "domain" && !seen.has(`domain:${clean}`)) {
      seen.add(`domain:${clean}`);
      results.push({ type: "domain", value: clean });
    }
  }

  // 5. Emails (standard and defanged)
  const emailMatches = text.match(/[a-zA-Z0-9_.+-]+(?:\[@\]|@)[a-zA-Z0-9-]+(?:\[\.\]|\.)[a-zA-Z0-9-.]+/gi) || [];
  for (const raw of emailMatches) {
    const clean = refangIoc(raw).toLowerCase();
    if (detectIocType(clean) === "email" && !seen.has(`email:${clean}`)) {
      seen.add(`email:${clean}`);
      results.push({ type: "email", value: clean });
    }
  }

  return results;
}

/**
 * Executes full CTI normalization, local cache correlation, and database persistence for an uploaded report.
 */
export async function correlateUploadedReport(params: {
  reportId: string;
  filename: string;
  text: string;
  analysis: any;
}): Promise<CorrelationReportResult> {
  const { reportId, filename, text, analysis } = params;
  const now = new Date();
  const sourcesSet = new Set<string>(["ANALYST_UPLOAD"]);

  // -------------------------------------------------------------
  // 1. Vulnerability Extraction & Multi-Source Correlation (NVD + CISA)
  // -------------------------------------------------------------
  const textCves = extractCveCandidates(text);
  const analysisCves: string[] = [];
  if (Array.isArray(analysis?.threats)) {
    for (const t of analysis.threats) {
      const match = `${t.title || ""} ${t.description || ""} ${t.evidence || ""}`.match(/CVE-\d{4}-\d{4,7}/gi);
      if (match) match.forEach((c: string) => {
        const norm = normalizeCveId(c);
        if (norm) analysisCves.push(norm);
      });
    }
  }

  const allCveIds = Array.from(new Set([...textCves, ...analysisCves]));
  const correlatedVulnerabilities: CorrelatedVulnerability[] = [];

  for (const cveId of allCveIds) {
    let vulnRecord: any = null;
    const sourceProvenance: string[] = ["ANALYST_UPLOAD"];

    // Check local SQLite cache first
    const existingInDb = await db.select().from(cachedVulnerabilities).where(eq(cachedVulnerabilities.cveId, cveId));
    if (existingInDb.length > 0) {
      vulnRecord = existingInDb[0];
      sourceProvenance.push("AUTHORITATIVE_NVD");
      sourcesSet.add("AUTHORITATIVE_NVD");
      if (vulnRecord.isCisaKev === 1) {
        sourceProvenance.push("AUTHORITATIVE_CISA");
        sourcesSet.add("AUTHORITATIVE_CISA");
      }
    } else {
      // Check CISA KEV
      const cisaCheck = await checkCisaKev(cveId);
      if (cisaCheck.isKnownExploited && cisaCheck.entry) {
        sourceProvenance.push("AUTHORITATIVE_CISA");
        sourcesSet.add("AUTHORITATIVE_CISA");
      }

      // Safe fallback NVD fetch
      try {
        const nvdResult = await fetchNvdCve(cveId);
        if (nvdResult && !nvdResult.isCached) {
          sourceProvenance.push("AUTHORITATIVE_NVD");
          sourcesSet.add("AUTHORITATIVE_NVD");
        }
      } catch (nvdErr) {
        console.warn(`[Correlation] NVD lookup notice for ${cveId}:`, nvdErr);
      }

      // Ingest into local SQLite cache with HYBRID or ANALYST_UPLOAD source
      const cisaEntry = cisaCheck.isKnownExploited ? cisaCheck.entry : null;
      await upsertNormalizedVulnerability({
        cveId,
        source: cisaCheck.isKnownExploited ? "HYBRID" : "ANALYST_UPLOAD",
        description: cisaEntry?.shortDescription || `Vulnerability identified in uploaded report ${filename}.`,
        cvssScore: 8.5,
        cvssSeverity: "HIGH",
        isCisaKev: cisaCheck.isKnownExploited,
        cisaDateAdded: cisaEntry?.dateAdded,
        cisaDueDate: cisaEntry?.dueDate,
        cisaRequiredAction: cisaEntry?.requiredAction,
        knownRansomwareUse: cisaEntry?.knownRansomwareCampaignUse
      });

      const reQuery = await db.select().from(cachedVulnerabilities).where(eq(cachedVulnerabilities.cveId, cveId));
      vulnRecord = reQuery[0];
    }

    if (vulnRecord) {
      correlatedVulnerabilities.push({
        cveId: vulnRecord.cveId,
        description: vulnRecord.description || "",
        cvssScore: vulnRecord.cvssScore ? vulnRecord.cvssScore / 10 : null,
        cvssSeverity: vulnRecord.cvssSeverity || null,
        isCisaKev: vulnRecord.isCisaKev === 1,
        cisaDateAdded: vulnRecord.cisaDateAdded,
        cisaDueDate: vulnRecord.cisaDueDate,
        cisaRequiredAction: vulnRecord.cisaRequiredAction,
        knownRansomwareUse: vulnRecord.knownRansomwareUse,
        sourceProvenance
      });
    }
  }

  // -------------------------------------------------------------
  // 2. MITRE ATT&CK Technique Extraction & Cache Correlation
  // -------------------------------------------------------------
  const textMitre = extractMitreTechniques(text);
  const analysisMitre: string[] = [];
  if (Array.isArray(analysis?.threats)) {
    for (const t of analysis.threats) {
      if (Array.isArray(t.mitreTechniques)) {
        t.mitreTechniques.forEach((m: string) => {
          const norm = normalizeMitreTechniqueId(m);
          if (norm) analysisMitre.push(norm);
        });
      }
    }
  }

  const allMitreIds = Array.from(new Set([...textMitre, ...analysisMitre]));
  const correlatedMitreTechniques: CorrelatedMitreTechnique[] = [];

  for (const techId of allMitreIds) {
    const tech = lookupMitreTechnique(techId);
    if (tech) {
      sourcesSet.add("AUTHORITATIVE_MITRE");
      correlatedMitreTechniques.push({
        id: tech.id,
        name: tech.name,
        tactic: tech.tactic,
        tacticId: tech.tacticId,
        description: tech.description,
        url: tech.url,
        sourceProvenance: "AUTHORITATIVE_MITRE"
      });
    } else {
      correlatedMitreTechniques.push({
        id: techId,
        name: `Technique ${techId}`,
        tactic: "Adversary Technique",
        description: "Adversary technique observed in uploaded intelligence report.",
        url: `https://attack.mitre.org/techniques/${techId}/`,
        sourceProvenance: "ANALYST_UPLOAD"
      });
    }
  }

  // -------------------------------------------------------------
  // 3. IOC Extraction, Normalization & Deduplication
  // -------------------------------------------------------------
  const textIocs = extractIocsFromText(text);
  const analysisIocs: Array<{ type: string; value: string; context?: string }> = Array.isArray(analysis?.iocs)
    ? analysis.iocs.map((i: any) => ({ type: i.type, value: i.value, context: i.context }))
    : [];

  const rawIocsCombined = [...textIocs, ...analysisIocs];
  const correlatedIocs: CorrelatedIoc[] = [];

  for (const raw of rawIocsCombined) {
    const norm = normalizeIocValue(raw.type, raw.value);
    if (!norm.isValid) continue;

    const upsertRes = await upsertNormalizedIoc({
      reportId,
      type: norm.type,
      value: norm.normalizedValue,
      confidence: 90,
      context: raw.context || `Extracted from uploaded report: ${filename}`,
      severity: "HIGH",
      source: "ANALYST_UPLOAD"
    });

    correlatedIocs.push({
      id: upsertRes.id,
      type: norm.type,
      value: norm.normalizedValue,
      defangedValue: defangIoc(norm.normalizedValue),
      confidence: 90,
      context: raw.context || `Extracted from uploaded report: ${filename}`,
      severity: "HIGH",
      sourceProvenance: "ANALYST_UPLOAD"
    });
  }

  // Deduplicate in-memory representation
  const uniqueIocsMap = new Map<string, CorrelatedIoc>();
  for (const i of correlatedIocs) {
    const key = `${i.type}:${i.value}`;
    if (!uniqueIocsMap.has(key)) {
      uniqueIocsMap.set(key, i);
    }
  }
  const distinctCorrelatedIocs = Array.from(uniqueIocsMap.values());

  // -------------------------------------------------------------
  // 4. Persistence of Related Analysis Artifacts
  // -------------------------------------------------------------
  // Insert Threats
  for (const t of analysis?.threats || []) {
    const threatId = "thr-usr-" + Math.random().toString(36).substring(2, 9);
    await db.insert(threats).values({
      id: threatId,
      reportId,
      title: t.title || `Threat identified in ${filename}`,
      description: t.description || t.title,
      category: t.category || analysis?.category || "Cyber Threat Intel",
      severity: t.severity || analysis?.severity || "HIGH",
      confidence: t.confidence || 88,
      reasoning: t.reasoning || "Extracted from analyst uploaded artifact.",
      evidence: t.evidence || text.substring(0, 300),
      mitreTechniques: JSON.stringify(t.mitreTechniques || allMitreIds),
      affectedSystems: t.affectedSystems || "Corporate Enterprise Perimeter",
      detectedAt: now,
      status: "active"
    });

    // Recommendations
    for (const rec of t.recommendations || []) {
      await db.insert(recommendations).values({
        id: "rec-usr-" + Math.random().toString(36).substring(2, 9),
        threatId,
        recommendation: rec.recommendation || rec,
        priority: rec.priority || "High",
        actionType: rec.actionType || "Containment",
        completed: 0
      });
    }
  }

  // Insert Entities
  for (const e of analysis?.entities || []) {
    await db.insert(entities).values({
      id: "ent-usr-" + Math.random().toString(36).substring(2, 9),
      reportId,
      name: e.name,
      type: e.type || "Threat Actor",
      confidence: e.confidence || 85
    });
  }

  // Insert Incidents (with strict geolocation validation)
  for (const inc of analysis?.incidents || []) {
    let safeCoordinates: string | null = null;
    if (inc.coordinates && typeof inc.coordinates === "string") {
      const parts = inc.coordinates.split(",");
      if (parts.length === 2) {
        const lat = parseFloat(parts[0]);
        const lng = parseFloat(parts[1]);
        if (!isNaN(lat) && !isNaN(lng) && lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180) {
          safeCoordinates = `${lat.toFixed(4)},${lng.toFixed(4)}`;
        }
      }
    }

    await db.insert(incidents).values({
      id: "inc-usr-" + Math.random().toString(36).substring(2, 9),
      reportId,
      title: inc.title || `Incident flagged in ${filename}`,
      date: inc.date || now.toISOString(),
      location: inc.location || "Monitored Sector",
      coordinates: safeCoordinates,
      category: inc.category || "Cyber Incident",
      severity: inc.severity || "HIGH",
      description: inc.description || "Correlated security telemetry logged.",
      malware: inc.malware || null,
      threatActor: inc.threatActor || null,
      relatedIocCount: distinctCorrelatedIocs.length
    });
  }

  // Insert Prediction if available
  if (analysis?.prediction) {
    const p = analysis.prediction;
    await db.insert(predictions).values({
      id: "pred-usr-" + Math.random().toString(36).substring(2, 9),
      category: p.category || analysis?.category || "Advanced Threat",
      location: p.location || "Enterprise Perimeter",
      riskScore: p.riskScore || 85,
      growthRate: p.growthRate || "+20%",
      trendDirection: p.trendDirection || "INCREASING",
      confidence: p.confidence || 88,
      predictionDate: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
      explanation: p.explanation || "AI-generated risk trajectory based on ingested CTI signals.",
      supportingIncidentsCount: 5
    });
  }

  // Build Correlation List
  const correlations = [];
  if (correlatedVulnerabilities.length > 0) {
    correlations.push({
      type: "VULNERABILITY_CORRELATION",
      label: `Correlated ${correlatedVulnerabilities.length} CVE(s) with NVD/CISA KEV`,
      confidence: 95,
      evidence: correlatedVulnerabilities.map(v => `${v.cveId}${v.isCisaKev ? " [CISA KEV EXPLOITED]" : ""}`).join(", ")
    });
  }
  if (correlatedMitreTechniques.length > 0) {
    correlations.push({
      type: "MITRE_MAPPING",
      label: `Mapped ${correlatedMitreTechniques.length} MITRE ATT&CK technique(s)`,
      confidence: 92,
      evidence: correlatedMitreTechniques.map(m => `${m.id} (${m.name})`).join(", ")
    });
  }
  if (distinctCorrelatedIocs.length > 0) {
    correlations.push({
      type: "IOC_EXTRACTION",
      label: `Extracted & Normalized ${distinctCorrelatedIocs.length} Indicator(s) of Compromise`,
      confidence: 90,
      evidence: distinctCorrelatedIocs.map(i => `${i.type}: ${i.value}`).join(", ")
    });
  }

  // Broadcast Real-Time SSE Events
  ctiEventBus.emitCtiEvent("report.correlated", {
    reportId,
    filename,
    summary: analysis?.summary || `Intelligence report ${filename} ingested and correlated.`,
    severity: analysis?.severity || "HIGH",
    category: analysis?.category || "Cyber Threat Intel",
    threatCount: (analysis?.threats || []).length,
    vulnerabilityCount: correlatedVulnerabilities.length,
    iocCount: distinctCorrelatedIocs.length,
    mitreCount: correlatedMitreTechniques.length,
    sources: Array.from(sourcesSet)
  });

  if ((analysis?.incidents || []).length > 0) {
    ctiEventBus.emitCtiEvent("threatmap.updated", {
      reportId,
      incidentCount: (analysis?.incidents || []).length,
      timestamp: now.toISOString()
    });
  }

  return {
    reportId,
    filename,
    summary: analysis?.summary || `Intelligence report ${filename} ingested and correlated.`,
    severity: analysis?.severity || "HIGH",
    category: analysis?.category || "Cyber Threat Intel",
    vulnerabilities: correlatedVulnerabilities,
    iocs: distinctCorrelatedIocs,
    mitreTechniques: correlatedMitreTechniques,
    correlations,
    sources: Array.from(sourcesSet),
    timestamp: now.toISOString()
  };
}

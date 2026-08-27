import { db } from "../src/db";
import { cachedVulnerabilities, iocs, mitreTechniques } from "../src/db/schema";
import { eq, and, sql } from "drizzle-orm";
import { lookupMitreTechnique } from "./mitreService";

export type CtiSourceProvenance = "NVD" | "CISA_KEV" | "HYBRID" | "MITRE_ATT&CK" | "ANALYST_UPLOAD" | "AI_DERIVED";

export interface NormalizedIocResult {
  normalizedValue: string;
  originalValue: string;
  type: "IPv4" | "IPv6" | "domain" | "URL" | "SHA256" | "SHA1" | "MD5" | "email" | "Unknown";
  isValid: boolean;
}

/**
 * Normalizes CVE identifiers to strict canonical standard: CVE-YYYY-NNNN+
 */
export function normalizeCveId(raw: string): string | null {
  if (!raw || typeof raw !== "string") return null;
  const match = raw.trim().toUpperCase().match(/CVE-\d{4}-\d{4,7}/i);
  return match ? match[0].toUpperCase() : null;
}

/**
 * Scans free-form text or documents and extracts all unique normalized CVE identifiers.
 */
export function extractCveCandidates(text: string): string[] {
  if (!text) return [];
  const regex = /CVE-\d{4}-\d{4,7}/gi;
  const matches = text.match(regex) || [];
  const unique = new Set<string>();
  for (const m of matches) {
    const norm = normalizeCveId(m);
    if (norm) unique.add(norm);
  }
  return Array.from(unique);
}

/**
 * Converts defanged indicators (e.g. hxxp[://], 192[.]168[.]1[.]1, example[.]com) to standard format.
 */
export function refangIoc(raw: string): string {
  if (!raw || typeof raw !== "string") return "";
  let clean = raw.trim();
  clean = clean.replace(/\[\.\]/g, ".");
  clean = clean.replace(/\(\.\)/g, ".");
  clean = clean.replace(/\[dot\]/gi, ".");
  clean = clean.replace(/\[\:\/\/\]/g, "://");
  clean = clean.replace(/hxxps?:\/\//gi, (m) => m.toLowerCase().startsWith("hxxps") ? "https://" : "http://");
  clean = clean.replace(/\[@\]/g, "@");
  clean = clean.replace(/\[at\]/gi, "@");
  return clean;
}

/**
 * Defangs standard indicator for safe display in UI or logs.
 */
export function defangIoc(raw: string): string {
  if (!raw || typeof raw !== "string") return "";
  let clean = refangIoc(raw);
  clean = clean.replace(/https?:\/\//gi, (m) => m.toLowerCase().startsWith("https") ? "hxxps://" : "hxxp://");
  clean = clean.replace(/\./g, "[.]");
  clean = clean.replace(/@/g, "[@]");
  return clean;
}

/**
 * Detects and classifies the technical IOC type.
 */
export function detectIocType(value: string): "IPv4" | "IPv6" | "domain" | "URL" | "SHA256" | "SHA1" | "MD5" | "email" | "Unknown" {
  const clean = refangIoc(value).trim();

  // IPv4
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
  if (ipv4Regex.test(clean)) return "IPv4";

  // IPv6
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;
  if (ipv6Regex.test(clean)) return "IPv6";

  // Hash values (hex)
  if (/^[a-f0-9]{64}$/i.test(clean)) return "SHA256";
  if (/^[a-f0-9]{40}$/i.test(clean)) return "SHA1";
  if (/^[a-f0-9]{32}$/i.test(clean)) return "MD5";

  // Email
  if (/^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/.test(clean)) return "email";

  // URL
  if (/^https?:\/\/[^\s/$.?#].[^\s]*$/i.test(clean)) return "URL";

  // Domain
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(clean)) return "domain";

  return "Unknown";
}

/**
 * Normalizes an IOC value based on its type without destroying its original form.
 */
export function normalizeIocValue(type: string, rawValue: string): NormalizedIocResult {
  const originalValue = String(rawValue || "").trim();
  const refanged = refangIoc(originalValue);
  const detectedType = detectIocType(refanged);
  const finalType = type && type !== "Unknown" ? (type as any) : detectedType;

  let normalized = refanged;

  switch (finalType) {
    case "IPv4":
    case "IPv6":
      normalized = refanged.toLowerCase().trim();
      break;
    case "domain":
    case "email":
      normalized = refanged.toLowerCase().trim().replace(/\/+$/, "");
      break;
    case "SHA256":
    case "SHA1":
    case "MD5":
      normalized = refanged.toLowerCase().trim();
      break;
    case "URL":
      try {
        const u = new URL(refanged);
        normalized = `${u.protocol.toLowerCase()}//${u.hostname.toLowerCase()}${u.port ? ":" + u.port : ""}${u.pathname}${u.search}`;
      } catch {
        normalized = refanged.trim();
      }
      break;
    default:
      normalized = refanged.trim();
  }

  return {
    normalizedValue: normalized,
    originalValue,
    type: finalType,
    isValid: finalType !== "Unknown"
  };
}

/**
 * Normalizes MITRE technique identifier (e.g. "t1566", "T1566.001 - Spearphishing" -> "T1566.001").
 */
export function normalizeMitreTechniqueId(raw: string): string | null {
  if (!raw || typeof raw !== "string") return null;
  const match = raw.trim().toUpperCase().match(/T\d{4}(?:\.\d{3})?/);
  return match ? match[0] : null;
}

/**
 * Scans text and extracts all unique normalized MITRE ATT&CK technique IDs.
 */
export function extractMitreTechniques(text: string): string[] {
  if (!text) return [];
  const regex = /T\d{4}(?:\.\d{3})?/gi;
  const matches = text.match(regex) || [];
  const unique = new Set<string>();
  for (const m of matches) {
    const norm = normalizeMitreTechniqueId(m);
    if (norm) unique.add(norm);
  }
  return Array.from(unique);
}

/**
 * Upserts an IOC into SQLite with strict deduplication on (type + normalized value).
 */
export async function upsertNormalizedIoc(params: {
  reportId?: string | null;
  threatId?: string | null;
  type: string;
  value: string;
  confidence?: number;
  context?: string;
  severity?: string;
  source?: CtiSourceProvenance;
}): Promise<{ id: string; isNew: boolean; normalizedValue: string }> {
  const norm = normalizeIocValue(params.type, params.value);
  const valToStore = norm.normalizedValue || params.value.trim();
  const typeToStore = norm.type !== "Unknown" ? norm.type : (params.type || "domain");
  const now = new Date();

  // Deduplicate by type and normalized value
  const existing = await db.select().from(iocs).where(
    and(
      eq(iocs.type, typeToStore),
      sql`LOWER(TRIM(${iocs.value})) = ${valToStore.toLowerCase()}`
    )
  );

  if (existing.length > 0) {
    const current = existing[0];
    await db.update(iocs).set({
      lastSeen: now,
      confidence: Math.max(current.confidence || 85, params.confidence || 85),
      context: params.context ? `${current.context || ""} | ${params.context}`.trim().slice(0, 500) : current.context
    }).where(eq(iocs.id, current.id));

    return { id: current.id, isNew: false, normalizedValue: valToStore };
  }

  const newId = "ioc-" + Math.random().toString(36).substring(2, 9);
  await db.insert(iocs).values({
    id: newId,
    reportId: params.reportId || null,
    threatId: params.threatId || null,
    type: typeToStore,
    value: valToStore,
    confidence: params.confidence || 90,
    context: params.context || "Normalized Threat Indicator",
    severity: params.severity || "HIGH",
    firstSeen: now,
    lastSeen: now,
    reputationScore: 85
  });

  return { id: newId, isNew: true, normalizedValue: valToStore };
}

/**
 * Upserts a vulnerability record into SQLite with deduplication and source correlation.
 */
export async function upsertNormalizedVulnerability(params: {
  cveId: string;
  source: CtiSourceProvenance;
  description?: string;
  cvssScore?: number;
  cvssSeverity?: string;
  cvssVector?: string;
  cwe?: string;
  isCisaKev?: boolean;
  cisaDateAdded?: string;
  cisaDueDate?: string;
  cisaRequiredAction?: string;
  knownRansomwareUse?: string;
  affectedProducts?: string[];
  references?: string[];
}): Promise<{ cveId: string; isNew: boolean; sourceAssigned: string }> {
  const normCve = normalizeCveId(params.cveId);
  if (!normCve) throw new Error(`Invalid CVE ID format: ${params.cveId}`);

  const now = new Date();
  const existing = await db.select().from(cachedVulnerabilities).where(eq(cachedVulnerabilities.cveId, normCve));

  if (existing.length > 0) {
    const current = existing[0];
    const isHybrid = (current.source !== params.source) || current.source === "HYBRID";
    const finalSource = isHybrid ? "HYBRID" : current.source;
    const finalKev = (params.isCisaKev || current.isCisaKev === 1) ? 1 : 0;

    await db.update(cachedVulnerabilities).set({
      source: finalSource,
      isCisaKev: finalKev,
      cisaDateAdded: params.cisaDateAdded || current.cisaDateAdded,
      cisaDueDate: params.cisaDueDate || current.cisaDueDate,
      cisaRequiredAction: params.cisaRequiredAction || current.cisaRequiredAction,
      knownRansomwareUse: params.knownRansomwareUse || current.knownRansomwareUse,
      description: (params.description && params.description.length > 30) ? params.description : current.description,
      cvssScore: typeof params.cvssScore === "number" ? Math.round(params.cvssScore * 10) : current.cvssScore,
      cvssSeverity: (params.cvssSeverity as any) || current.cvssSeverity,
      lastSyncedAt: now
    }).where(eq(cachedVulnerabilities.cveId, normCve));

    return { cveId: normCve, isNew: false, sourceAssigned: finalSource };
  }

  // Insert new
  await db.insert(cachedVulnerabilities).values({
    cveId: normCve,
    source: params.source,
    description: params.description || `Security vulnerability tracked under ${normCve}.`,
    cvssScore: typeof params.cvssScore === "number" ? Math.round(params.cvssScore * 10) : 75,
    cvssSeverity: (params.cvssSeverity as any) || "HIGH",
    cvssVector: params.cvssVector || null,
    cwe: params.cwe || null,
    publishedDate: params.cisaDateAdded || now.toISOString(),
    lastModifiedDate: now.toISOString(),
    isCisaKev: params.isCisaKev ? 1 : 0,
    cisaDateAdded: params.cisaDateAdded || null,
    cisaDueDate: params.cisaDueDate || null,
    cisaRequiredAction: params.cisaRequiredAction || null,
    knownRansomwareUse: params.knownRansomwareUse || "Unknown",
    affectedProducts: JSON.stringify(params.affectedProducts || ["Enterprise Systems"]),
    references: JSON.stringify(params.references || [`https://nvd.nist.gov/vuln/detail/${normCve}`]),
    sourceStatus: "LIVE",
    lastSyncedAt: now
  });

  return { cveId: normCve, isNew: true, sourceAssigned: params.source };
}

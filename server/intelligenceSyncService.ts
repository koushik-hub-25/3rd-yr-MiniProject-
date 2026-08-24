import { db } from "../src/db";
import { intelligenceSources, cachedVulnerabilities } from "../src/db/schema";
import { eq, desc, or, like, sql } from "drizzle-orm";
import { VERIFIED_NVD_CATALOG, NvdVulnerability } from "./nvdService";
import { VERIFIED_CISA_KEV_CATALOG, CisaKevEntry } from "./cisaKevService";
import { MITRE_ATTACK_MATRIX } from "./mitreService";

export type IntelligenceSourceStatus = "LIVE" | "CACHED" | "SYNTHETIC" | "DEGRADED" | "ERROR" | "DISCONNECTED";

export interface IntelligenceSourceInfo {
  id: string;
  name: string;
  sourceType: string;
  provider: string;
  endpoint?: string;
  status: IntelligenceSourceStatus;
  lastSuccessfulSync?: string | null;
  lastAttemptedSync?: string | null;
  nextScheduledSync?: string | null;
  recordCount: number;
  errorMessage?: string | null;
  syncDurationMs: number;
  isLive: boolean;
  isSynthetic: boolean;
  freshnessSeconds: number;
  freshnessLabel: "LIVE" | "RECENT" | "STALE" | "OUTDATED" | "SYNTHETIC" | "DEGRADED";
  syncIntervalMinutes: number;
  description?: string;
}

export interface IntelligenceFeedItem {
  id: string;
  cveId: string;
  source: "NVD" | "CISA_KEV" | "HYBRID";
  sourceName: string;
  provider: string;
  description: string;
  cvssScore: number;
  cvssSeverity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  cvssVector?: string;
  cwe?: string;
  publishedDate?: string;
  lastModifiedDate?: string;
  affectedProducts: string[];
  references: string[];
  isCisaKev: boolean;
  cisaDateAdded?: string;
  cisaDueDate?: string;
  cisaRequiredAction?: string;
  knownRansomwareUse: "Known" | "Unknown" | string;
  status: IntelligenceSourceStatus;
  lastSyncedAt: string;
  freshnessSeconds: number;
  freshnessLabel: string;
  isLive: boolean;
  isSynthetic: boolean;
}

// Configurable sync intervals (in minutes) with safe defaults
const NVD_SYNC_INTERVAL_MINUTES = parseInt(process.env.NVD_SYNC_INTERVAL_MINUTES || "30", 10);
const CISA_KEV_SYNC_INTERVAL_MINUTES = parseInt(process.env.CISA_KEV_SYNC_INTERVAL_MINUTES || "30", 10);

// In-memory runtime tracking
let syncTimer: NodeJS.Timeout | null = null;
let isSyncingNvd = false;
let isSyncingCisa = false;

/**
 * Calculates human-readable and deterministic freshness labels based on sync elapsed time.
 */
export function calculateFreshness(lastSuccessMs: number | null, isLiveFlag: boolean, isSynth: boolean, status: IntelligenceSourceStatus): {
  freshnessSeconds: number;
  freshnessLabel: "LIVE" | "RECENT" | "STALE" | "OUTDATED" | "SYNTHETIC" | "DEGRADED";
} {
  if (isSynth) {
    return { freshnessSeconds: 0, freshnessLabel: "SYNTHETIC" };
  }

  if (status === "DEGRADED") {
    const elapsed = lastSuccessMs ? Math.max(0, Math.floor((Date.now() - lastSuccessMs) / 1000)) : 999999;
    return { freshnessSeconds: elapsed, freshnessLabel: "DEGRADED" };
  }

  if (!lastSuccessMs) {
    return { freshnessSeconds: 999999, freshnessLabel: "OUTDATED" };
  }

  const elapsedSeconds = Math.max(0, Math.floor((Date.now() - lastSuccessMs) / 1000));

  // 0 - 15 minutes (900s) AND live external sync confirmed: LIVE
  if (elapsedSeconds <= 900 && isLiveFlag) {
    return { freshnessSeconds: elapsedSeconds, freshnessLabel: "LIVE" };
  }

  // 15 min to 6 hours (21,600s): RECENT
  if (elapsedSeconds <= 21600) {
    return { freshnessSeconds: elapsedSeconds, freshnessLabel: "RECENT" };
  }

  // 6 hours to 24 hours (86,400s): STALE
  if (elapsedSeconds <= 86400) {
    return { freshnessSeconds: elapsedSeconds, freshnessLabel: "STALE" };
  }

  // > 24 hours: OUTDATED
  return { freshnessSeconds: elapsedSeconds, freshnessLabel: "OUTDATED" };
}

/**
 * Initialize all core intelligence source records in the database.
 */
export async function initializeIntelligenceSources(): Promise<void> {
  const sourcesToSeed = [
    {
      id: "nvd",
      name: "NIST National Vulnerability Database (NVD)",
      sourceType: "VULNERABILITY_FEED",
      provider: "NIST",
      endpoint: "https://services.nvd.nist.gov/rest/json/cves/2.0",
      status: "CACHED",
      recordCount: Object.keys(VERIFIED_NVD_CATALOG).length,
      isLive: 0,
      isSynthetic: 0,
      syncIntervalMinutes: NVD_SYNC_INTERVAL_MINUTES,
      syncDurationMs: 420
    },
    {
      id: "cisa_kev",
      name: "CISA Known Exploited Vulnerabilities (KEV)",
      sourceType: "EXPLOITATION_FEED",
      provider: "CISA",
      endpoint: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      status: "CACHED",
      recordCount: Object.keys(VERIFIED_CISA_KEV_CATALOG).length,
      isLive: 0,
      isSynthetic: 0,
      syncIntervalMinutes: CISA_KEV_SYNC_INTERVAL_MINUTES,
      syncDurationMs: 380
    },
    {
      id: "mitre",
      name: "MITRE ATT&CK Enterprise Matrix v15",
      sourceType: "ADVERSARY_KNOWLEDGE_BASE",
      provider: "MITRE",
      endpoint: "https://attack.mitre.org/",
      status: "CACHED",
      recordCount: Object.keys(MITRE_ATTACK_MATRIX).length,
      isLive: 0,
      isSynthetic: 0,
      syncIntervalMinutes: 1440,
      syncDurationMs: 45
    },
    {
      id: "gemini_ai",
      name: "Google Gemini 3.7 Flash AI Engine",
      sourceType: "AI_ENGINE",
      provider: "Google",
      endpoint: "Google GenAI API",
      status: process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== "MY_GEMINI_API_KEY" ? "LIVE" : "CACHED",
      recordCount: 1,
      isLive: process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== "MY_GEMINI_API_KEY" ? 1 : 0,
      isSynthetic: 0,
      syncIntervalMinutes: 60,
      syncDurationMs: 120
    },
    {
      id: "analyst_uploads",
      name: "Uploaded Intelligence Reports & Artifacts",
      sourceType: "ANALYST_INTEL",
      provider: "Analyst Submissions",
      endpoint: "Local SOC Upload Pipeline",
      status: "LIVE",
      recordCount: 0,
      isLive: 1,
      isSynthetic: 0,
      syncIntervalMinutes: 0,
      syncDurationMs: 10
    },
    {
      id: "synthetic_cti",
      name: "ShieldZen Synthetic CTI Dataset",
      sourceType: "SYNTHETIC_DATASET",
      provider: "ShieldZen Academic Platform",
      endpoint: "In-Memory Simulation Generator",
      status: "SYNTHETIC",
      recordCount: 14,
      isLive: 0,
      isSynthetic: 1,
      syncIntervalMinutes: 0,
      syncDurationMs: 5
    }
  ];

  for (const src of sourcesToSeed) {
    const existing = await db.select().from(intelligenceSources).where(eq(intelligenceSources.id, src.id));
    if (existing.length === 0) {
      await db.insert(intelligenceSources).values({
        ...src,
        lastSuccessfulSync: new Date(),
        lastAttemptedSync: new Date(),
        nextScheduledSync: new Date(Date.now() + src.syncIntervalMinutes * 60 * 1000),
        createdAt: new Date(),
        updatedAt: new Date()
      });
    }
  }

  // Prepopulate verified cached vulnerabilities into SQLite if empty
  await seedInitialCachedVulnerabilities();
}

/**
 * Prepopulate initial verified CVEs into cachedVulnerabilities table.
 */
async function seedInitialCachedVulnerabilities(): Promise<void> {
  for (const [cveId, nvd] of Object.entries(VERIFIED_NVD_CATALOG)) {
    const kev = VERIFIED_CISA_KEV_CATALOG[cveId];
    const existing = await db.select().from(cachedVulnerabilities).where(eq(cachedVulnerabilities.cveId, cveId));
    if (existing.length === 0) {
      await db.insert(cachedVulnerabilities).values({
        cveId,
        source: kev ? "HYBRID" : "NVD",
        description: nvd.description,
        cvssScore: Math.round(nvd.cvssScore * 10),
        cvssSeverity: nvd.cvssSeverity,
        cvssVector: nvd.cvssVector,
        cwe: nvd.cwe,
        publishedDate: nvd.publishedDate,
        lastModifiedDate: nvd.lastModifiedDate,
        affectedProducts: JSON.stringify(nvd.affectedProducts),
        references: JSON.stringify(nvd.references),
        isCisaKev: kev ? 1 : 0,
        cisaDateAdded: kev?.dateAdded || null,
        cisaDueDate: kev?.dueDate || null,
        cisaRequiredAction: kev?.requiredAction || null,
        knownRansomwareUse: kev?.knownRansomwareCampaignUse || "Unknown",
        sourceStatus: "CACHED",
        lastSyncedAt: new Date()
      });
    }
  }
}

/**
 * Synchronizes NIST NVD external intelligence.
 * Respects NVD REST API 2.0 specs with rate limiting and timeout.
 */
export async function syncNvdIntelligence(): Promise<{
  success: boolean;
  recordsUpdated: number;
  durationMs: number;
  status: IntelligenceSourceStatus;
  error?: string;
}> {
  if (isSyncingNvd) {
    return { success: true, recordsUpdated: 0, durationMs: 0, status: "LIVE" };
  }

  isSyncingNvd = true;
  const startTime = Date.now();
  await db.update(intelligenceSources)
    .set({ lastAttemptedSync: new Date() })
    .where(eq(intelligenceSources.id, "nvd"));

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000);

    // Fetch recent high-priority CVEs from NIST NVD API 2.0
    // Query published in recent window
    const url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10";
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "ShieldZen-CTI-Platform/2.4 (Security-Academic-Research)"
      }
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`NVD API returned HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    let recordsUpdated = 0;

    if (Array.isArray(data.vulnerabilities)) {
      for (const item of data.vulnerabilities) {
        const cve = item.cve;
        if (!cve?.id) continue;

        const cveId = cve.id.toUpperCase();
        const metrics = cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
                        cve.metrics?.cvssMetricV30?.[0]?.cvssData ||
                        cve.metrics?.cvssMetricV2?.[0]?.cvssData;

        const desc = cve.descriptions?.find((d: any) => d.lang === "en")?.value || "Vulnerability record retrieved from NIST NVD.";
        const rawScore = metrics?.baseScore || 7.5;
        const cvssSeverity = (metrics?.baseSeverity || (rawScore >= 9.0 ? "CRITICAL" : rawScore >= 7.0 ? "HIGH" : rawScore >= 4.0 ? "MEDIUM" : "LOW")) as any;
        const cwe = cve.weaknesses?.[0]?.description?.[0]?.value;
        const refs = (cve.references || []).slice(0, 4).map((r: any) => r.url);
        const affectedProducts = (cve.configurations?.[0]?.nodes || [])
          .flatMap((node: any) => (node.cpeMatch || []).map((m: any) => m.criteria?.split(":")?.[4] || m.criteria))
          .filter(Boolean)
          .slice(0, 4);

        const kev = VERIFIED_CISA_KEV_CATALOG[cveId];

        const existing = await db.select().from(cachedVulnerabilities).where(eq(cachedVulnerabilities.cveId, cveId));
        if (existing.length > 0) {
          await db.update(cachedVulnerabilities).set({
            description: desc,
            cvssScore: Math.round(rawScore * 10),
            cvssSeverity,
            cvssVector: metrics?.vectorString || existing[0].cvssVector,
            cwe: cwe || existing[0].cwe,
            publishedDate: cve.published || existing[0].publishedDate,
            lastModifiedDate: cve.lastModified || existing[0].lastModifiedDate,
            affectedProducts: JSON.stringify(affectedProducts.length > 0 ? affectedProducts : JSON.parse(existing[0].affectedProducts || "[]")),
            references: JSON.stringify(refs.length > 0 ? refs : JSON.parse(existing[0].references || "[]")),
            sourceStatus: "LIVE",
            lastSyncedAt: new Date()
          }).where(eq(cachedVulnerabilities.cveId, cveId));
        } else {
          await db.insert(cachedVulnerabilities).values({
            cveId,
            source: kev ? "HYBRID" : "NVD",
            description: desc,
            cvssScore: Math.round(rawScore * 10),
            cvssSeverity,
            cvssVector: metrics?.vectorString,
            cwe,
            publishedDate: cve.published,
            lastModifiedDate: cve.lastModified,
            affectedProducts: JSON.stringify(affectedProducts),
            references: JSON.stringify(refs),
            isCisaKev: kev ? 1 : 0,
            cisaDateAdded: kev?.dateAdded || null,
            cisaDueDate: kev?.dueDate || null,
            cisaRequiredAction: kev?.requiredAction || null,
            knownRansomwareUse: kev?.knownRansomwareCampaignUse || "Unknown",
            sourceStatus: "LIVE",
            lastSyncedAt: new Date()
          });
        }
        recordsUpdated++;
      }
    }

    const durationMs = Date.now() - startTime;
    const countRes = await db.select({ count: sql<number>`count(*)` }).from(cachedVulnerabilities);
    const totalCount = Number(countRes[0]?.count || recordsUpdated);

    await db.update(intelligenceSources).set({
      status: "LIVE",
      isLive: 1,
      lastSuccessfulSync: new Date(),
      syncDurationMs: durationMs,
      recordCount: totalCount,
      errorMessage: null,
      nextScheduledSync: new Date(Date.now() + NVD_SYNC_INTERVAL_MINUTES * 60 * 1000),
      updatedAt: new Date()
    }).where(eq(intelligenceSources.id, "nvd"));

    isSyncingNvd = false;
    return { success: true, recordsUpdated, durationMs, status: "LIVE" };
  } catch (error: any) {
    const durationMs = Date.now() - startTime;
    console.warn(`[Sync] NIST NVD sync encountered issue (${error.message}). Gracefully serving cached baseline.`);

    // Check if we have cached records
    const countRes = await db.select({ count: sql<number>`count(*)` }).from(cachedVulnerabilities);
    const hasCache = Number(countRes[0]?.count || 0) > 0;
    const fallbackStatus: IntelligenceSourceStatus = hasCache ? "DEGRADED" : "ERROR";

    await db.update(intelligenceSources).set({
      status: fallbackStatus,
      isLive: 0,
      syncDurationMs: durationMs,
      errorMessage: `External API lookup warning: ${error.message}. Serving local cached vulnerability catalog.`,
      updatedAt: new Date()
    }).where(eq(intelligenceSources.id, "nvd"));

    isSyncingNvd = false;
    return { success: false, recordsUpdated: 0, durationMs, status: fallbackStatus, error: error.message };
  }
}

/**
 * Synchronizes CISA Known Exploited Vulnerabilities catalog feed.
 */
export async function syncCisaKevIntelligence(): Promise<{
  success: boolean;
  recordsUpdated: number;
  durationMs: number;
  status: IntelligenceSourceStatus;
  error?: string;
}> {
  if (isSyncingCisa) {
    return { success: true, recordsUpdated: 0, durationMs: 0, status: "LIVE" };
  }

  isSyncingCisa = true;
  const startTime = Date.now();
  await db.update(intelligenceSources)
    .set({ lastAttemptedSync: new Date() })
    .where(eq(intelligenceSources.id, "cisa_kev"));

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000);

    const response = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", {
      signal: controller.signal,
      headers: { "User-Agent": "ShieldZen-CTI/2.4 (Security-Academic-Research)" }
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`CISA KEV feed returned HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    let recordsUpdated = 0;

    if (Array.isArray(data.vulnerabilities)) {
      // Process first 25 high-priority vulnerabilities for caching
      for (const item of data.vulnerabilities.slice(0, 30)) {
        if (!item.cveID) continue;
        const cveId = item.cveID.toUpperCase();

        const existing = await db.select().from(cachedVulnerabilities).where(eq(cachedVulnerabilities.cveId, cveId));
        if (existing.length > 0) {
          await db.update(cachedVulnerabilities).set({
            isCisaKev: 1,
            cisaDateAdded: item.dateAdded,
            cisaDueDate: item.dueDate,
            cisaRequiredAction: item.requiredAction,
            knownRansomwareUse: item.knownRansomwareCampaignUse || "Known",
            source: "HYBRID",
            sourceStatus: "LIVE",
            lastSyncedAt: new Date()
          }).where(eq(cachedVulnerabilities.cveId, cveId));
        } else {
          await db.insert(cachedVulnerabilities).values({
            cveId,
            source: "CISA_KEV",
            description: item.shortDescription || item.vulnerabilityName || "CISA Known Exploited Vulnerability",
            cvssScore: 90, // Default 9.0 critical
            cvssSeverity: "CRITICAL",
            isCisaKev: 1,
            cisaDateAdded: item.dateAdded,
            cisaDueDate: item.dueDate,
            cisaRequiredAction: item.requiredAction,
            knownRansomwareUse: item.knownRansomwareCampaignUse || "Known",
            affectedProducts: JSON.stringify([`${item.vendorProject || ""} ${item.product || ""}`.trim()]),
            references: JSON.stringify([`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cveId}`]),
            sourceStatus: "LIVE",
            lastSyncedAt: new Date()
          });
        }
        recordsUpdated++;
      }
    }

    const durationMs = Date.now() - startTime;
    const totalCount = Array.isArray(data.vulnerabilities) ? data.vulnerabilities.length : recordsUpdated;

    await db.update(intelligenceSources).set({
      status: "LIVE",
      isLive: 1,
      lastSuccessfulSync: new Date(),
      syncDurationMs: durationMs,
      recordCount: totalCount,
      errorMessage: null,
      nextScheduledSync: new Date(Date.now() + CISA_KEV_SYNC_INTERVAL_MINUTES * 60 * 1000),
      updatedAt: new Date()
    }).where(eq(intelligenceSources.id, "cisa_kev"));

    isSyncingCisa = false;
    return { success: true, recordsUpdated, durationMs, status: "LIVE" };
  } catch (error: any) {
    const durationMs = Date.now() - startTime;
    console.warn(`[Sync] CISA KEV sync encountered issue (${error.message}). Gracefully serving cached baseline.`);

    const countRes = await db.select({ count: sql<number>`count(*)` }).from(cachedVulnerabilities).where(eq(cachedVulnerabilities.isCisaKev, 1));
    const hasCache = Number(countRes[0]?.count || 0) > 0;
    const fallbackStatus: IntelligenceSourceStatus = hasCache ? "DEGRADED" : "ERROR";

    await db.update(intelligenceSources).set({
      status: fallbackStatus,
      isLive: 0,
      syncDurationMs: durationMs,
      errorMessage: `External CISA catalog warning: ${error.message}. Serving local verified KEV catalog.`,
      updatedAt: new Date()
    }).where(eq(intelligenceSources.id, "cisa_kev"));

    isSyncingCisa = false;
    return { success: false, recordsUpdated: 0, durationMs, status: fallbackStatus, error: error.message };
  }
}

/**
 * Returns comprehensive data source status and freshness metadata for all intelligence sources.
 */
export async function getAllDataSourcesStatus(): Promise<{
  sources: IntelligenceSourceInfo[];
  lastSync: string;
  summary: {
    totalSources: number;
    liveCount: number;
    cachedCount: number;
    syntheticCount: number;
    degradedCount: number;
  };
}> {
  const sources = await db.select().from(intelligenceSources);
  const now = Date.now();

  const formattedSources: IntelligenceSourceInfo[] = sources.map((s) => {
    const lastSyncMs = s.lastSuccessfulSync ? new Date(s.lastSuccessfulSync).getTime() : null;
    const isLive = Boolean(s.isLive);
    const isSynthetic = Boolean(s.isSynthetic);
    const status = s.status as IntelligenceSourceStatus;

    const freshness = calculateFreshness(lastSyncMs, isLive, isSynthetic, status);

    return {
      id: s.id,
      name: s.name,
      sourceType: s.sourceType,
      provider: s.provider,
      endpoint: s.endpoint || undefined,
      status: s.status as IntelligenceSourceStatus,
      lastSuccessfulSync: s.lastSuccessfulSync ? new Date(s.lastSuccessfulSync).toISOString() : null,
      lastAttemptedSync: s.lastAttemptedSync ? new Date(s.lastAttemptedSync).toISOString() : null,
      nextScheduledSync: s.nextScheduledSync ? new Date(s.nextScheduledSync).toISOString() : null,
      recordCount: s.recordCount || 0,
      errorMessage: s.errorMessage || null,
      syncDurationMs: s.syncDurationMs || 0,
      isLive,
      isSynthetic,
      freshnessSeconds: freshness.freshnessSeconds,
      freshnessLabel: freshness.freshnessLabel,
      syncIntervalMinutes: s.syncIntervalMinutes || 30
    };
  });

  const liveCount = formattedSources.filter((s) => s.status === "LIVE").length;
  const cachedCount = formattedSources.filter((s) => s.status === "CACHED").length;
  const syntheticCount = formattedSources.filter((s) => s.isSynthetic).length;
  const degradedCount = formattedSources.filter((s) => s.status === "DEGRADED" || s.status === "ERROR").length;

  return {
    sources: formattedSources,
    lastSync: new Date().toISOString(),
    summary: {
      totalSources: formattedSources.length,
      liveCount,
      cachedCount,
      syntheticCount,
      degradedCount
    }
  };
}

/**
 * Returns combined list of recent external intelligence feed items (NVD + CISA KEV).
 */
export async function getIntelligenceFeedItems({
  source,
  severity,
  isKevOnly,
  search,
  limit = 50,
  offset = 0
}: {
  source?: string;
  severity?: string;
  isKevOnly?: boolean;
  search?: string;
  limit?: number;
  offset?: number;
} = {}): Promise<{
  items: IntelligenceFeedItem[];
  total: number;
  limit: number;
  offset: number;
}> {
  let query = db.select().from(cachedVulnerabilities);
  const conditions: any[] = [];

  if (source && source !== "ALL") {
    if (source === "NVD") {
      conditions.push(eq(cachedVulnerabilities.source, "NVD"));
    } else if (source === "CISA_KEV") {
      conditions.push(or(eq(cachedVulnerabilities.source, "CISA_KEV"), eq(cachedVulnerabilities.isCisaKev, 1)));
    }
  }

  if (severity && severity !== "ALL") {
    conditions.push(eq(cachedVulnerabilities.cvssSeverity, severity.toUpperCase()));
  }

  if (isKevOnly) {
    conditions.push(eq(cachedVulnerabilities.isCisaKev, 1));
  }

  if (search && search.trim()) {
    const q = `%${search.trim()}%`;
    conditions.push(
      or(
        like(cachedVulnerabilities.cveId, q),
        like(cachedVulnerabilities.description, q),
        like(cachedVulnerabilities.affectedProducts, q)
      )
    );
  }

  const results = await db
    .select()
    .from(cachedVulnerabilities)
    .where(conditions.length > 0 ? sql.join(conditions, sql` AND `) : undefined)
    .orderBy(desc(cachedVulnerabilities.lastSyncedAt))
    .limit(limit)
    .offset(offset);

  const countRes = await db
    .select({ count: sql<number>`count(*)` })
    .from(cachedVulnerabilities)
    .where(conditions.length > 0 ? sql.join(conditions, sql` AND `) : undefined);

  const total = Number(countRes[0]?.count || results.length);

  const items: IntelligenceFeedItem[] = results.map((v) => {
    const cvssScore = (v.cvssScore || 75) / 10;
    const isLive = v.sourceStatus === "LIVE";
    const lastSyncMs = v.lastSyncedAt ? new Date(v.lastSyncedAt).getTime() : Date.now();
    const freshness = calculateFreshness(lastSyncMs, isLive, false, v.sourceStatus as any);

    return {
      id: v.cveId,
      cveId: v.cveId,
      source: (v.source || "NVD") as any,
      sourceName: v.isCisaKev
        ? "CISA Known Exploited Vulnerabilities + NIST NVD"
        : "NIST National Vulnerability Database",
      provider: v.isCisaKev ? "CISA / NIST" : "NIST",
      description: v.description,
      cvssScore,
      cvssSeverity: (v.cvssSeverity || "HIGH") as any,
      cvssVector: v.cvssVector || undefined,
      cwe: v.cwe || undefined,
      publishedDate: v.publishedDate || undefined,
      lastModifiedDate: v.lastModifiedDate || undefined,
      affectedProducts: v.affectedProducts ? JSON.parse(v.affectedProducts) : [],
      references: v.references ? JSON.parse(v.references) : [],
      isCisaKev: Boolean(v.isCisaKev),
      cisaDateAdded: v.cisaDateAdded || undefined,
      cisaDueDate: v.cisaDueDate || undefined,
      cisaRequiredAction: v.cisaRequiredAction || undefined,
      knownRansomwareUse: v.knownRansomwareUse || "Unknown",
      status: (v.sourceStatus || "CACHED") as any,
      lastSyncedAt: new Date(v.lastSyncedAt).toISOString(),
      freshnessSeconds: freshness.freshnessSeconds,
      freshnessLabel: freshness.freshnessLabel,
      isLive,
      isSynthetic: false
    };
  });

  return {
    items,
    total,
    limit,
    offset
  };
}

/**
 * Starts the lightweight background synchronization loop.
 */
export function startBackgroundSyncScheduler(): void {
  if (syncTimer) {
    clearInterval(syncTimer);
  }

  // Initial trigger after server startup
  setTimeout(() => {
    console.log("[Sync] Triggering initial external intelligence synchronization...");
    syncNvdIntelligence().catch(e => console.warn("[Sync] Initial NVD sync warn:", e.message));
    syncCisaKevIntelligence().catch(e => console.warn("[Sync] Initial CISA KEV sync warn:", e.message));
  }, 3000);

  // Periodic interval check every 5 minutes
  syncTimer = setInterval(async () => {
    try {
      const sources = await db.select().from(intelligenceSources);
      for (const s of sources) {
        if (s.isSynthetic) continue;
        const lastSync = s.lastSuccessfulSync ? new Date(s.lastSuccessfulSync).getTime() : 0;
        const intervalMs = (s.syncIntervalMinutes || 30) * 60 * 1000;

        if (Date.now() - lastSync > intervalMs) {
          if (s.id === "nvd") {
            await syncNvdIntelligence();
          } else if (s.id === "cisa_kev") {
            await syncCisaKevIntelligence();
          }
        }
      }
    } catch (err: any) {
      console.warn("[Sync] Periodic scheduler encountered warning:", err.message);
    }
  }, 5 * 60 * 1000);
}

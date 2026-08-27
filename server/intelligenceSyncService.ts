import { db } from "../src/db";
import { intelligenceSources, cachedVulnerabilities, mitreTechniques } from "../src/db/schema";
import { eq, desc, or, like, sql } from "drizzle-orm";
import { VERIFIED_NVD_CATALOG, NvdVulnerability, getNvdHeaders, parseNvdCveItem } from "./nvdService";
import { VERIFIED_CISA_KEV_CATALOG, CisaKevEntry, parseCisaKevItem, setCachedKevEntries } from "./cisaKevService";
import { MITRE_ATTACK_MATRIX, MitreTechnique, parseMitreStixAttackPattern, setDynamicMitreCache } from "./mitreService";
import { ctiEventBus } from "./eventBus";

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
const MITRE_SYNC_INTERVAL_MINUTES = parseInt(process.env.MITRE_SYNC_INTERVAL_MINUTES || "1440", 10);

// In-memory runtime tracking
let syncTimer: NodeJS.Timeout | null = null;
let isSyncingNvd = false;
let isSyncingCisa = false;
let isSyncingMitre = false;


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
 * Implements NVD API 2.0 incremental range query with modification timestamps and pagination.
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
  const now = new Date();

  await db.update(intelligenceSources)
    .set({ lastAttemptedSync: now })
    .where(eq(intelligenceSources.id, "nvd"));

  try {
    // 1. Determine incremental sync window
    const nvdSource = await db.select().from(intelligenceSources).where(eq(intelligenceSources.id, "nvd"));
    const lastSyncCheckpoint = nvdSource[0]?.lastSuccessfulSync ? new Date(nvdSource[0].lastSuccessfulSync) : null;

    let startDate: Date;
    if (lastSyncCheckpoint && !isNaN(lastSyncCheckpoint.getTime())) {
      // NVD API 2.0 allows up to 120 consecutive days in a date query
      const maxWindowPast = new Date(now.getTime() - 120 * 24 * 60 * 60 * 1000);
      startDate = lastSyncCheckpoint > maxWindowPast ? lastSyncCheckpoint : maxWindowPast;
    } else {
      // Default initial incremental sync window: past 7 days
      startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    }

    const startIso = startDate.toISOString();
    const endIso = now.toISOString();

    console.log(`[NVD Sync] Fetching modified CVEs from ${startIso} to ${endIso}...`);

    let recordsUpdated = 0;
    let startIndex = 0;
    const resultsPerPage = 2000;
    let hasMore = true;
    const hasApiKey = Boolean(process.env.NVD_API_KEY && process.env.NVD_API_KEY !== "MY_NVD_API_KEY");

    while (hasMore) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 12000);

      const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=${encodeURIComponent(startIso)}&lastModEndDate=${encodeURIComponent(endIso)}&startIndex=${startIndex}&resultsPerPage=${resultsPerPage}`;

      const response = await fetch(url, {
        signal: controller.signal,
        headers: getNvdHeaders()
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`NVD API HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      const vulnerabilities = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
      const totalResults = typeof data.totalResults === "number" ? data.totalResults : vulnerabilities.length;

      for (const item of vulnerabilities) {
        const parsed = parseNvdCveItem(item.cve);
        if (!parsed) continue;

        const cveId = parsed.cveId;
        const kev = VERIFIED_CISA_KEV_CATALOG[cveId];

        const existing = await db.select().from(cachedVulnerabilities).where(eq(cachedVulnerabilities.cveId, cveId));
        if (existing.length > 0) {
          await db.update(cachedVulnerabilities).set({
            description: parsed.description,
            cvssScore: Math.round(parsed.cvssScore * 10),
            cvssSeverity: parsed.cvssSeverity,
            cvssVector: parsed.cvssVector || existing[0].cvssVector,
            cwe: parsed.cwe || existing[0].cwe,
            publishedDate: parsed.publishedDate || existing[0].publishedDate,
            lastModifiedDate: parsed.lastModifiedDate || existing[0].lastModifiedDate,
            affectedProducts: JSON.stringify(parsed.affectedProducts.length > 0 ? parsed.affectedProducts : JSON.parse(existing[0].affectedProducts || "[]")),
            references: JSON.stringify(parsed.references.length > 0 ? parsed.references : JSON.parse(existing[0].references || "[]")),
            sourceStatus: "LIVE",
            lastSyncedAt: new Date()
          }).where(eq(cachedVulnerabilities.cveId, cveId));
        } else {
          await db.insert(cachedVulnerabilities).values({
            cveId,
            source: kev ? "HYBRID" : "NVD",
            description: parsed.description,
            cvssScore: Math.round(parsed.cvssScore * 10),
            cvssSeverity: parsed.cvssSeverity,
            cvssVector: parsed.cvssVector,
            cwe: parsed.cwe,
            publishedDate: parsed.publishedDate,
            lastModifiedDate: parsed.lastModifiedDate,
            affectedProducts: JSON.stringify(parsed.affectedProducts),
            references: JSON.stringify(parsed.references),
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

      startIndex += vulnerabilities.length;
      if (vulnerabilities.length === 0 || startIndex >= totalResults) {
        hasMore = false;
      } else {
        // Rate-limit compliance pause between pagination requests
        await new Promise(r => setTimeout(r, hasApiKey ? 650 : 3500));
      }
    }

    const durationMs = Date.now() - startTime;
    const countRes = await db.select({ count: sql<number>`count(*)` }).from(cachedVulnerabilities);
    const totalCount = Number(countRes[0]?.count || recordsUpdated);

    // Save checkpoint ONLY upon complete successful synchronization
    await db.update(intelligenceSources).set({
      status: "LIVE",
      isLive: 1,
      lastSuccessfulSync: now,
      syncDurationMs: durationMs,
      recordCount: totalCount,
      errorMessage: null,
      nextScheduledSync: new Date(now.getTime() + NVD_SYNC_INTERVAL_MINUTES * 60 * 1000),
      updatedAt: now
    }).where(eq(intelligenceSources.id, "nvd"));

    console.log(`[NVD Sync] Successfully synced ${recordsUpdated} CVEs in ${durationMs}ms. Total cached: ${totalCount}. Checkpoint saved.`);
    ctiEventBus.emitCtiEvent("intelligence.synced", {
      source: "NVD",
      provider: "NIST National Vulnerability Database",
      recordsUpdated,
      totalCount,
      status: "LIVE"
    });
    isSyncingNvd = false;
    return { success: true, recordsUpdated, durationMs, status: "LIVE" };
  } catch (error: any) {
    const durationMs = Date.now() - startTime;
    console.warn(`[Sync] NIST NVD incremental sync warning: ${error.message}. Serving local cached vulnerability catalog.`);

    // Check if we have cached records
    const countRes = await db.select({ count: sql<number>`count(*)` }).from(cachedVulnerabilities);
    const cachedCount = Number(countRes[0]?.count || 0);
    const fallbackStatus: IntelligenceSourceStatus = cachedCount > 0 ? "DEGRADED" : "ERROR";

    // Update intelligence source status without resetting the lastSuccessfulSync checkpoint
    await db.update(intelligenceSources).set({
      status: fallbackStatus,
      isLive: 0,
      syncDurationMs: durationMs,
      errorMessage: `NVD API warning: ${error.message}. Local cached vulnerability catalog active (${cachedCount} records).`,
      updatedAt: new Date()
    }).where(eq(intelligenceSources.id, "nvd"));

    isSyncingNvd = false;
    return { success: false, recordsUpdated: 0, durationMs, status: fallbackStatus, error: error.message };
  }
}

/**
 * Synchronizes CISA Known Exploited Vulnerabilities catalog feed.
 * Ingests the complete official catalog (~1,200+ CVEs), deduplicates, and correlates with NVD records.
 */
export async function syncCisaKevIntelligence(): Promise<{
  success: boolean;
  recordsDiscovered?: number;
  recordsInserted?: number;
  recordsUpdated?: number;
  recordsUnchanged?: number;
  recordsUpdatedCount: number;
  durationMs: number;
  status: IntelligenceSourceStatus;
  totalKevCount?: number;
  hybridCount?: number;
  error?: string;
}> {
  if (isSyncingCisa) {
    return { success: true, recordsUpdatedCount: 0, durationMs: 0, status: "LIVE" };
  }

  isSyncingCisa = true;
  const startTime = Date.now();
  const now = new Date();

  await db.update(intelligenceSources)
    .set({ lastAttemptedSync: now })
    .where(eq(intelligenceSources.id, "cisa_kev"));

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 18000);

    console.log("[CISA Sync] Fetching official Known Exploited Vulnerabilities catalog feed...");
    const response = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", {
      signal: controller.signal,
      headers: { "User-Agent": "ShieldZen-CTI/2.4 (Security-Academic-Research)" }
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`CISA KEV feed returned HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    const vulnerabilities = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
    const recordsDiscovered = vulnerabilities.length;
    console.log(`[CISA Sync] Discovered ${recordsDiscovered} total CISA KEV catalog entries.`);

    let recordsInserted = 0;
    let recordsUpdated = 0;
    let recordsUnchanged = 0;
    const parsedKevEntries: CisaKevEntry[] = [];

    for (const item of vulnerabilities) {
      const parsed = parseCisaKevItem(item);
      if (!parsed) continue;

      const cveId = parsed.cveID;
      parsedKevEntries.push(parsed);

      const existing = await db.select().from(cachedVulnerabilities).where(eq(cachedVulnerabilities.cveId, cveId));
      if (existing.length > 0) {
        const current = existing[0];
        const alreadyKev = current.isCisaKev === 1;
        const matchingRansomware = current.knownRansomwareUse === parsed.knownRansomwareCampaignUse;
        const matchingDateAdded = current.cisaDateAdded === parsed.dateAdded;
        const matchingAction = current.cisaRequiredAction === parsed.requiredAction;

        if (alreadyKev && matchingRansomware && matchingDateAdded && matchingAction) {
          recordsUnchanged++;
        } else {
          // Update and link with NVD as HYBRID
          const isHybrid = current.source === "NVD" || current.source === "HYBRID";
          await db.update(cachedVulnerabilities).set({
            isCisaKev: 1,
            cisaDateAdded: parsed.dateAdded,
            cisaDueDate: parsed.dueDate,
            cisaRequiredAction: parsed.requiredAction,
            knownRansomwareUse: parsed.knownRansomwareCampaignUse || "Unknown",
            source: isHybrid ? "HYBRID" : "CISA_KEV",
            sourceStatus: "LIVE",
            lastSyncedAt: now
          }).where(eq(cachedVulnerabilities.cveId, cveId));
          recordsUpdated++;
        }
      } else {
        // Insert new CISA KEV record
        await db.insert(cachedVulnerabilities).values({
          cveId,
          source: "CISA_KEV",
          description: parsed.shortDescription || parsed.vulnerabilityName || "CISA Known Exploited Vulnerability",
          cvssScore: 90, // Default baseline 9.0 critical pending deep NVD sync
          cvssSeverity: "CRITICAL",
          cvssVector: null,
          cwe: null,
          publishedDate: parsed.dateAdded,
          lastModifiedDate: parsed.dateAdded,
          isCisaKev: 1,
          cisaDateAdded: parsed.dateAdded,
          cisaDueDate: parsed.dueDate,
          cisaRequiredAction: parsed.requiredAction,
          knownRansomwareUse: parsed.knownRansomwareCampaignUse || "Unknown",
          affectedProducts: JSON.stringify([`${parsed.vendorProject} ${parsed.product}`.trim()]),
          references: JSON.stringify([`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cveId}`]),
          sourceStatus: "LIVE",
          lastSyncedAt: now
        });
        recordsInserted++;
      }
    }

    // Refresh in-memory catalog
    setCachedKevEntries(parsedKevEntries);

    const durationMs = Date.now() - startTime;
    const totalKevRes = await db.select({ count: sql<number>`count(*)` }).from(cachedVulnerabilities).where(eq(cachedVulnerabilities.isCisaKev, 1));
    const totalKevCount = Number(totalKevRes[0]?.count || 0);

    const hybridRes = await db.select({ count: sql<number>`count(*)` }).from(cachedVulnerabilities).where(eq(cachedVulnerabilities.source, "HYBRID"));
    const hybridCount = Number(hybridRes[0]?.count || 0);

    // Save synchronization checkpoint
    await db.update(intelligenceSources).set({
      status: "LIVE",
      isLive: 1,
      lastSuccessfulSync: now,
      syncDurationMs: durationMs,
      recordCount: totalKevCount,
      errorMessage: null,
      nextScheduledSync: new Date(now.getTime() + CISA_KEV_SYNC_INTERVAL_MINUTES * 60 * 1000),
      updatedAt: now
    }).where(eq(intelligenceSources.id, "cisa_kev"));

    console.log(`[CISA Sync] Full catalog sync completed in ${durationMs}ms: Discovered=${recordsDiscovered}, Inserted=${recordsInserted}, Updated=${recordsUpdated}, Unchanged=${recordsUnchanged}. Total KEVs=${totalKevCount}, Hybrids=${hybridCount}.`);
    ctiEventBus.emitCtiEvent("intelligence.synced", {
      source: "CISA_KEV",
      provider: "CISA Known Exploited Vulnerabilities",
      recordsDiscovered,
      recordsInserted,
      recordsUpdated,
      totalKevCount,
      status: "LIVE"
    });
    isSyncingCisa = false;
    return {
      success: true,
      recordsDiscovered,
      recordsInserted,
      recordsUpdated,
      recordsUnchanged,
      recordsUpdatedCount: recordsInserted + recordsUpdated,
      totalKevCount,
      hybridCount,
      durationMs,
      status: "LIVE"
    };
  } catch (error: any) {
    const durationMs = Date.now() - startTime;
    console.warn(`[Sync] CISA KEV sync encountered issue (${error.message}). Gracefully serving cached baseline.`);

    const countRes = await db.select({ count: sql<number>`count(*)` }).from(cachedVulnerabilities).where(eq(cachedVulnerabilities.isCisaKev, 1));
    const cachedCount = Number(countRes[0]?.count || 0);
    const fallbackStatus: IntelligenceSourceStatus = cachedCount > 0 ? "DEGRADED" : "ERROR";

    // Update status without removing lastSuccessfulSync checkpoint
    await db.update(intelligenceSources).set({
      status: fallbackStatus,
      isLive: 0,
      syncDurationMs: durationMs,
      errorMessage: `External CISA catalog warning: ${error.message}. Serving local verified KEV catalog (${cachedCount} records).`,
      updatedAt: new Date()
    }).where(eq(intelligenceSources.id, "cisa_kev"));

    isSyncingCisa = false;
    return {
      success: false,
      recordsUpdatedCount: 0,
      durationMs,
      status: fallbackStatus,
      error: error.message
    };
  }
}

/**
 * Synchronizes MITRE ATT&CK Enterprise Matrix from official machine-readable STIX feed.
 * Ingests all active attack-patterns (~690+ techniques & subtechniques), tactics, detections, and metadata into SQLite.
 */
export async function syncMitreIntelligence(): Promise<{
  success: boolean;
  recordsDiscovered?: number;
  recordsInserted?: number;
  recordsUpdated?: number;
  recordsUnchanged?: number;
  totalTechniqueCount?: number;
  durationMs: number;
  status: IntelligenceSourceStatus;
  error?: string;
}> {
  if (isSyncingMitre) {
    return { success: true, durationMs: 0, status: "LIVE" };
  }

  isSyncingMitre = true;
  const startTime = Date.now();
  const now = new Date();

  await db.update(intelligenceSources)
    .set({ lastAttemptedSync: now })
    .where(eq(intelligenceSources.id, "mitre"));

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 20000);

    console.log("[MITRE Sync] Fetching official Enterprise ATT&CK STIX JSON feed...");
    const url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "ShieldZen-CTI/2.4 (Security-Academic-Research)" }
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`MITRE STIX feed returned HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    const objects = Array.isArray(data.objects) ? data.objects : [];

    let recordsInserted = 0;
    let recordsUpdated = 0;
    let recordsUnchanged = 0;
    let recordsDiscovered = 0;
    const dynamicCacheList: MitreTechnique[] = [];

    for (const obj of objects) {
      const parsed = parseMitreStixAttackPattern(obj);
      if (!parsed) continue;

      recordsDiscovered++;
      const id = parsed.id;
      const tacticsJson = JSON.stringify(parsed.tactics);
      const tacticIdsJson = JSON.stringify(parsed.tacticIds);

      dynamicCacheList.push({
        id,
        name: parsed.name,
        tactic: parsed.tactics[0] || "Enterprise",
        tacticId: parsed.tacticIds[0] || "TA0001",
        description: parsed.description,
        detection: parsed.detection,
        mitigation: parsed.mitigation,
        url: parsed.url,
        source: `MITRE ATT&CK Enterprise ${parsed.version}`
      });

      const existing = await db.select().from(mitreTechniques).where(eq(mitreTechniques.id, id));
      if (existing.length > 0) {
        const current = existing[0];
        if (current.name === parsed.name && current.tactics === tacticsJson && current.description === parsed.description) {
          recordsUnchanged++;
        } else {
          await db.update(mitreTechniques).set({
            name: parsed.name,
            tactics: tacticsJson,
            tacticIds: tacticIdsJson,
            description: parsed.description,
            detection: parsed.detection,
            mitigation: parsed.mitigation,
            url: parsed.url,
            version: parsed.version,
            isSubtechnique: parsed.isSubtechnique ? 1 : 0,
            parentTechniqueId: parsed.parentTechniqueId || null,
            sourceStatus: "LIVE",
            lastModifiedDate: parsed.lastModifiedDate,
            lastSyncedAt: now
          }).where(eq(mitreTechniques.id, id));
          recordsUpdated++;
        }
      } else {
        await db.insert(mitreTechniques).values({
          id,
          name: parsed.name,
          tactics: tacticsJson,
          tacticIds: tacticIdsJson,
          description: parsed.description,
          detection: parsed.detection,
          mitigation: parsed.mitigation,
          url: parsed.url,
          version: parsed.version,
          isSubtechnique: parsed.isSubtechnique ? 1 : 0,
          parentTechniqueId: parsed.parentTechniqueId || null,
          source: "MITRE ATT&CK Enterprise",
          sourceStatus: "LIVE",
          lastModifiedDate: parsed.lastModifiedDate,
          lastSyncedAt: now
        });
        recordsInserted++;
      }
    }

    setDynamicMitreCache(dynamicCacheList);

    const durationMs = Date.now() - startTime;
    const countRes = await db.select({ count: sql<number>`count(*)` }).from(mitreTechniques);
    const totalTechniqueCount = Number(countRes[0]?.count || recordsDiscovered);

    await db.update(intelligenceSources).set({
      status: "LIVE",
      isLive: 1,
      lastSuccessfulSync: now,
      syncDurationMs: durationMs,
      recordCount: totalTechniqueCount,
      errorMessage: null,
      nextScheduledSync: new Date(now.getTime() + MITRE_SYNC_INTERVAL_MINUTES * 60 * 1000),
      updatedAt: now
    }).where(eq(intelligenceSources.id, "mitre"));

    console.log(`[MITRE Sync] Ingested ${recordsDiscovered} techniques in ${durationMs}ms (Inserted: ${recordsInserted}, Updated: ${recordsUpdated}, Unchanged: ${recordsUnchanged}). Total stored: ${totalTechniqueCount}. Checkpoint saved.`);
    ctiEventBus.emitCtiEvent("intelligence.synced", {
      source: "MITRE_ATTACK",
      provider: "MITRE ATT&CK Enterprise",
      recordsDiscovered,
      recordsInserted,
      recordsUpdated,
      totalTechniqueCount,
      status: "LIVE"
    });
    isSyncingMitre = false;
    return {
      success: true,
      recordsDiscovered,
      recordsInserted,
      recordsUpdated,
      recordsUnchanged,
      totalTechniqueCount,
      durationMs,
      status: "LIVE"
    };
  } catch (error: any) {
    const durationMs = Date.now() - startTime;
    console.warn(`[Sync] MITRE ATT&CK STIX sync warning: ${error.message}. Serving local cached matrix.`);

    const countRes = await db.select({ count: sql<number>`count(*)` }).from(mitreTechniques);
    const cachedCount = Number(countRes[0]?.count || 0);
    const fallbackStatus: IntelligenceSourceStatus = cachedCount > 0 ? "DEGRADED" : "CACHED";

    await db.update(intelligenceSources).set({
      status: fallbackStatus,
      isLive: 0,
      syncDurationMs: durationMs,
      errorMessage: `MITRE STIX sync warning: ${error.message}. Serving cached ATT&CK matrix (${cachedCount || 12} techniques).`,
      updatedAt: new Date()
    }).where(eq(intelligenceSources.id, "mitre"));

    isSyncingMitre = false;
    return {
      success: false,
      durationMs,
      status: fallbackStatus,
      error: error.message
    };
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

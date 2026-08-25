import { drizzle } from "drizzle-orm/libsql";
import { createClient, type Client } from "@libsql/client";
import * as schema from "./schema";
import fs from "fs";
import path from "path";

const DB_FILE = path.join(process.cwd(), "local.db");
const DB_WAL = path.join(process.cwd(), "local.db-wal");
const DB_SHM = path.join(process.cwd(), "local.db-shm");
const DB_JOURNAL = path.join(process.cwd(), "local.db-journal");

function removeDatabaseFiles() {
  const files = [DB_FILE, DB_WAL, DB_SHM, DB_JOURNAL];
  for (const file of files) {
    try {
      if (fs.existsSync(file)) {
        fs.unlinkSync(file);
      }
    } catch (e) {
      console.warn(`[DB] Could not remove ${file}:`, e);
    }
  }
}

let activeClient: Client = createClient({
  url: "file:local.db",
});

let activeDb = drizzle(activeClient, { schema });

export function resetDatabase() {
  console.warn("[DB] Resetting database files and recreating LibSQL connection...");
  try {
    if (typeof (activeClient as any)?.close === "function") {
      (activeClient as any).close();
    }
  } catch (e) {
    // ignore close error
  }
  removeDatabaseFiles();
  activeClient = createClient({
    url: "file:local.db",
  });
  activeDb = drizzle(activeClient, { schema });
}

export const client = new Proxy({} as Client, {
  get(_target, prop, receiver) {
    const val = Reflect.get(activeClient, prop, receiver);
    if (typeof val === "function") {
      return val.bind(activeClient);
    }
    return val;
  },
});

export const db = new Proxy({} as any, {
  get(_target, prop, receiver) {
    const val = Reflect.get(activeDb, prop, receiver);
    if (typeof val === "function") {
      return val.bind(activeDb);
    }
    return val;
  },
});

async function configurePragmas() {
  try {
    await activeClient.execute("PRAGMA journal_mode = WAL;");
    await activeClient.execute("PRAGMA synchronous = NORMAL;");
    await activeClient.execute("PRAGMA busy_timeout = 10000;");
  } catch (err: any) {
    const msg = String(err?.message || err || "");
    if (msg.includes("SQLITE_CORRUPT") || msg.includes("malformed") || msg.includes("corrupt") || msg.includes("disk image")) {
      throw err;
    }
    console.warn("[DB] Warning configuring pragmas:", err);
  }
}

async function createTables() {
  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY,
      filename TEXT NOT NULL,
      fileType TEXT NOT NULL,
      uploadDate INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      rawText TEXT NOT NULL,
      summary TEXT,
      keyFindings TEXT,
      category TEXT NOT NULL DEFAULT 'Cyber Threat Intel',
      sourceOrigin TEXT DEFAULT 'Open Source Intelligence (OSINT)',
      status TEXT NOT NULL DEFAULT 'analyzed',
      aiConfidence INTEGER DEFAULT 88,
      analysisMode TEXT DEFAULT 'Gemini AI',
      severity TEXT DEFAULT 'HIGH',
      threatCount INTEGER DEFAULT 0,
      entityCount INTEGER DEFAULT 0,
      iocCount INTEGER DEFAULT 0
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS threats (
      id TEXT PRIMARY KEY,
      reportId TEXT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      category TEXT NOT NULL,
      severity TEXT NOT NULL,
      analystSeverityOverride TEXT,
      overrideReason TEXT,
      confidence INTEGER NOT NULL,
      reasoning TEXT NOT NULL,
      evidence TEXT,
      mitreTechniques TEXT,
      affectedSystems TEXT,
      detectedAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      status TEXT NOT NULL DEFAULT 'active'
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS entities (
      id TEXT PRIMARY KEY,
      reportId TEXT,
      threatId TEXT,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      confidence INTEGER DEFAULT 85
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS iocs (
      id TEXT PRIMARY KEY,
      reportId TEXT,
      threatId TEXT,
      type TEXT NOT NULL,
      value TEXT NOT NULL,
      confidence INTEGER DEFAULT 90,
      context TEXT,
      severity TEXT DEFAULT 'HIGH',
      firstSeen INTEGER,
      lastSeen INTEGER,
      tags TEXT,
      reputationScore INTEGER DEFAULT 85,
      enrichmentData TEXT
    );
  `);

  // Migrate existing tables if columns are missing
  try {
    await activeClient.execute("ALTER TABLE iocs ADD COLUMN severity TEXT DEFAULT 'HIGH';");
  } catch (_) {}
  try {
    await activeClient.execute("ALTER TABLE iocs ADD COLUMN firstSeen INTEGER;");
  } catch (_) {}
  try {
    await activeClient.execute("ALTER TABLE iocs ADD COLUMN lastSeen INTEGER;");
  } catch (_) {}
  try {
    await activeClient.execute("ALTER TABLE iocs ADD COLUMN tags TEXT;");
  } catch (_) {}
  try {
    await activeClient.execute("ALTER TABLE iocs ADD COLUMN reputationScore INTEGER DEFAULT 85;");
  } catch (_) {}
  try {
    await activeClient.execute("ALTER TABLE iocs ADD COLUMN enrichmentData TEXT;");
  } catch (_) {}

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      threatId TEXT,
      reportId TEXT,
      title TEXT NOT NULL,
      date TEXT NOT NULL,
      location TEXT NOT NULL,
      coordinates TEXT,
      category TEXT NOT NULL,
      severity TEXT NOT NULL,
      description TEXT NOT NULL,
      malware TEXT,
      threatActor TEXT,
      relatedIocCount INTEGER DEFAULT 1
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS recommendations (
      id TEXT PRIMARY KEY,
      threatId TEXT,
      recommendation TEXT NOT NULL,
      priority TEXT DEFAULT 'High',
      actionType TEXT DEFAULT 'Containment',
      completed INTEGER DEFAULT 0
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS predictions (
      id TEXT PRIMARY KEY,
      category TEXT NOT NULL,
      location TEXT NOT NULL,
      riskScore INTEGER NOT NULL,
      growthRate TEXT DEFAULT '+24%',
      trendDirection TEXT DEFAULT 'INCREASING',
      confidence INTEGER NOT NULL,
      predictionDate INTEGER NOT NULL,
      explanation TEXT NOT NULL,
      supportingIncidentsCount INTEGER DEFAULT 5
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS analystNotes (
      id TEXT PRIMARY KEY,
      threatId TEXT,
      reportId TEXT,
      author TEXT NOT NULL,
      note TEXT NOT NULL,
      timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS assets (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      hostname TEXT,
      ipAddress TEXT,
      assetType TEXT NOT NULL,
      operatingSystem TEXT,
      software TEXT,
      environment TEXT NOT NULL DEFAULT 'Production',
      criticality TEXT NOT NULL DEFAULT 'MEDIUM',
      exposure TEXT NOT NULL DEFAULT 'INTERNAL',
      owner TEXT,
      department TEXT,
      location TEXT,
      description TEXT,
      tags TEXT,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      updatedAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS threatActors (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      aliases TEXT,
      description TEXT NOT NULL,
      origin TEXT NOT NULL DEFAULT 'Unknown',
      motivation TEXT NOT NULL DEFAULT 'Unknown',
      sophistication TEXT NOT NULL DEFAULT 'Medium',
      confidence INTEGER NOT NULL DEFAULT 85,
      firstObserved INTEGER,
      lastObserved INTEGER,
      status TEXT NOT NULL DEFAULT 'Active',
      notes TEXT,
      isSynthetic INTEGER DEFAULT 1,
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      updatedAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS campaigns (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      threatActorId TEXT,
      firstObserved INTEGER,
      lastObserved INTEGER,
      targetSectors TEXT,
      targetRegions TEXT,
      objectives TEXT,
      status TEXT NOT NULL DEFAULT 'Active',
      confidence INTEGER NOT NULL DEFAULT 85,
      notes TEXT,
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      updatedAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS threatActorThreats (
      id TEXT PRIMARY KEY,
      threatActorId TEXT NOT NULL,
      threatId TEXT NOT NULL,
      relationshipConfidence TEXT NOT NULL DEFAULT 'confirmed',
      attributionType TEXT DEFAULT 'Primary Operator',
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS threatActorIocs (
      id TEXT PRIMARY KEY,
      threatActorId TEXT NOT NULL,
      iocId TEXT NOT NULL,
      relationshipConfidence TEXT NOT NULL DEFAULT 'confirmed',
      context TEXT,
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS threatActorIncidents (
      id TEXT PRIMARY KEY,
      threatActorId TEXT NOT NULL,
      incidentId TEXT NOT NULL,
      confidence INTEGER NOT NULL DEFAULT 85,
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS campaignThreats (
      id TEXT PRIMARY KEY,
      campaignId TEXT NOT NULL,
      threatId TEXT NOT NULL,
      relationshipConfidence TEXT NOT NULL DEFAULT 'confirmed',
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS campaignIocs (
      id TEXT PRIMARY KEY,
      campaignId TEXT NOT NULL,
      iocId TEXT NOT NULL,
      relationshipConfidence TEXT NOT NULL DEFAULT 'confirmed',
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS campaignIncidents (
      id TEXT PRIMARY KEY,
      campaignId TEXT NOT NULL,
      incidentId TEXT NOT NULL,
      confidence INTEGER NOT NULL DEFAULT 85,
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS campaignMitreTechniques (
      id TEXT PRIMARY KEY,
      campaignId TEXT NOT NULL,
      techniqueId TEXT NOT NULL,
      techniqueName TEXT,
      tactic TEXT,
      confidence INTEGER NOT NULL DEFAULT 90,
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS intelligenceSources (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      sourceType TEXT NOT NULL,
      provider TEXT NOT NULL,
      endpoint TEXT,
      status TEXT NOT NULL DEFAULT 'CACHED',
      lastSuccessfulSync INTEGER,
      lastAttemptedSync INTEGER,
      nextScheduledSync INTEGER,
      recordCount INTEGER DEFAULT 0,
      errorMessage TEXT,
      syncDurationMs INTEGER DEFAULT 0,
      isLive INTEGER DEFAULT 0,
      isSynthetic INTEGER DEFAULT 0,
      freshnessSeconds INTEGER DEFAULT 0,
      syncIntervalMinutes INTEGER DEFAULT 30,
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      updatedAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS cachedVulnerabilities (
      cveId TEXT PRIMARY KEY,
      source TEXT NOT NULL DEFAULT 'NVD',
      description TEXT NOT NULL,
      cvssScore INTEGER,
      cvssSeverity TEXT DEFAULT 'HIGH',
      cvssVector TEXT,
      cwe TEXT,
      publishedDate TEXT,
      lastModifiedDate TEXT,
      affectedProducts TEXT,
      "references" TEXT,
      isCisaKev INTEGER DEFAULT 0,
      cisaDateAdded TEXT,
      cisaDueDate TEXT,
      cisaRequiredAction TEXT,
      knownRansomwareUse TEXT DEFAULT 'Unknown',
      sourceStatus TEXT DEFAULT 'CACHED',
      lastSyncedAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      passwordHash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'analyst',
      emailVerified INTEGER NOT NULL DEFAULT 0,
      verificationTokenHash TEXT,
      verificationTokenExpiresAt INTEGER,
      resetPasswordTokenHash TEXT,
      resetPasswordTokenExpiresAt INTEGER,
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      updatedAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      lastLogin INTEGER
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expiresAt INTEGER NOT NULL,
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      ipAddress TEXT,
      userAgent TEXT
    );
  `);

  await activeClient.execute(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      userId TEXT,
      userEmail TEXT,
      action TEXT NOT NULL,
      resourceType TEXT,
      resourceId TEXT,
      timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      ipAddress TEXT,
      details TEXT
    );
  `);
}

export async function initDatabaseTables(): Promise<void> {
  try {
    // Verify database file health with quick check
    await activeClient.execute("PRAGMA schema_version;");
    await configurePragmas();
    await createTables();
  } catch (err: any) {
    const msg = String(err?.message || err || "");
    if (msg.includes("SQLITE_CORRUPT") || msg.includes("malformed") || msg.includes("corrupt") || msg.includes("disk image")) {
      console.error("[DB] Corrupted SQLite database detected during startup. Safely recreating clean database...", msg);
      resetDatabase();
      await configurePragmas();
      await createTables();
      console.log("[DB] Clean database recreated successfully after corruption recovery.");
    } else {
      console.error("[DB] Database initialization error:", msg);
      throw err;
    }
  }
}


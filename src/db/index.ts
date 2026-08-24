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
  } catch (err) {
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
      context TEXT
    );
  `);

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
}

export async function initDatabaseTables(retryCount = 0): Promise<void> {
  try {
    // Run integrity check
    const check = await activeClient.execute("PRAGMA integrity_check;");
    const checkRow = check.rows?.[0] as any;
    const checkResult = checkRow ? Object.values(checkRow)[0] : "ok";
    if (checkResult !== "ok") {
      throw new Error(`Database integrity check failed: ${JSON.stringify(checkResult)}`);
    }

    await configurePragmas();
    await createTables();
  } catch (err: any) {
    console.error(`[DB] Database initialization error (attempt ${retryCount + 1}):`, err?.message || err);
    if (retryCount < 2) {
      resetDatabase();
      return initDatabaseTables(retryCount + 1);
    }
    throw err;
  }
}


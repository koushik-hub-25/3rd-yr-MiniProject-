import { drizzle } from "drizzle-orm/libsql";
import { createClient } from "@libsql/client";
import * as schema from "./schema";

export const client = createClient({
  url: "file:local.db",
});

export const db = drizzle(client, { schema });

export async function initDatabaseTables() {
  await client.execute(`
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

  await client.execute(`
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

  await client.execute(`
    CREATE TABLE IF NOT EXISTS entities (
      id TEXT PRIMARY KEY,
      reportId TEXT,
      threatId TEXT,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      confidence INTEGER DEFAULT 85
    );
  `);

  await client.execute(`
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

  await client.execute(`
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

  await client.execute(`
    CREATE TABLE IF NOT EXISTS recommendations (
      id TEXT PRIMARY KEY,
      threatId TEXT,
      recommendation TEXT NOT NULL,
      priority TEXT DEFAULT 'High',
      actionType TEXT DEFAULT 'Containment',
      completed INTEGER DEFAULT 0
    );
  `);

  await client.execute(`
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

  await client.execute(`
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

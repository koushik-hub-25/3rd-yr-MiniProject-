import express from "express";
import path from "path";
import multer from "multer";
import { createServer as createViteServer } from "vite";
import { db, initDatabaseTables, resetDatabase } from "./src/db";
import {
  reports,
  threats,
  entities,
  iocs,
  incidents,
  recommendations,
  predictions,
  analystNotes,
  assets,
  threatActors,
  campaigns,
  threatActorThreats,
  threatActorIocs,
  threatActorIncidents,
  campaignThreats,
  campaignIocs,
  campaignIncidents,
  campaignMitreTechniques,
} from "./src/db/schema";
import { eq, desc, asc, sql, count, like, and } from "drizzle-orm";
import { analyzeIntelligenceReport } from "./server/ai";
import { generateSyntheticCTIDatabase } from "./server/seedData";
import { fetchNvdCve, getAllRecentNvdVulnerabilities } from "./server/nvdService";
import { checkCisaKev, getAllCisaKevEntries } from "./server/cisaKevService";
import { lookupMitreTechnique, getAllMitreTechniques } from "./server/mitreService";
import { correlateThreatIndicators } from "./server/correlationEngine";
import { processAIAnalystQuery } from "./server/aiAnalyst";
import {
  calculateDeterministicRiskScore,
  evaluateRiskWithLiveIntel,
  BENCHMARK_RISK_SCENARIOS,
  RiskEvaluationParams
} from "./server/riskEngine";
import {
  iocEnrichmentService,
  defangIoc,
  refangIoc,
  detectIocType
} from "./server/iocEnrichmentService";
import {
  listThreatActors,
  getThreatActorById,
  listCampaigns,
  getCampaignById
} from "./server/threatActorService";
import {
  initializeIntelligenceSources,
  getAllDataSourcesStatus,
  getIntelligenceFeedItems,
  syncNvdIntelligence,
  syncCisaKevIntelligence,
  startBackgroundSyncScheduler
} from "./server/intelligenceSyncService";

const upload = multer({ storage: multer.memoryStorage() });

async function seedDatabaseIfEmpty() {
  try {
    await initDatabaseTables();
    await initializeIntelligenceSources();
    
    let existingCount = 0;
    try {
      const existing = await db.select({ count: count() }).from(reports);
      existingCount = Number(existing[0]?.count || 0);
    } catch (queryErr: any) {
      console.warn("[DB] Non-blocking warning reading reports count:", queryErr?.message);
      const msg = String(queryErr?.message || queryErr || "");
      if (msg.includes("SQLITE_CORRUPT") || msg.includes("malformed") || msg.includes("corrupt") || msg.includes("disk image")) {
        console.error("[DB] Corrupted SQLite database detected during count. Recreating fresh clean database...", msg);
        resetDatabase();
        await initDatabaseTables();
        await initializeIntelligenceSources();
      }
      existingCount = 0;
    }

    if (existingCount === 0) {
      console.log("[DB] Database is empty. Seeding baseline synthetic CTI dataset...");
      await populateSyntheticData(false);
    } else {
      console.log(`[DB] Database verified with ${existingCount} reports. Preserving existing records.`);
      // Normalize dates on startup if needed
      try {
        const existingIncidents = await db.query.incidents.findMany();
        for (let i = 0; i < existingIncidents.length; i++) {
          const inc: any = existingIncidents[i];
          if (typeof inc?.id === "string" && inc.id.startsWith("inc-syn-") && !inc.date) {
            const num = parseInt(inc.id.replace("inc-syn-", ""), 10) || (i + 1);
            const daysAgo = num <= 6 ? ((num - 1) * 0.4) : (3 + (num - 7) * 4.8);
            const newDate = new Date(Date.now() - 1000 * 60 * 60 * 24 * daysAgo).toISOString();
            await db.update(incidents).set({ date: newDate }).where(eq(incidents.id, inc.id));
          }
        }
      } catch (e) {
        console.warn("[DB] Non-blocking notice during incident date check:", e);
      }
    }
  } catch (err) {
    console.error("[DB] Critical error during database startup initialization:", err);
  }
}

async function populateSyntheticData(forceClear = false) {
  const data = generateSyntheticCTIDatabase();

  if (forceClear) {
    console.log("[DB] Force clearing tables for manual reset...");
    try {
      await db.delete(campaignMitreTechniques);
      await db.delete(campaignIncidents);
      await db.delete(campaignIocs);
      await db.delete(campaignThreats);
      await db.delete(threatActorIncidents);
      await db.delete(threatActorIocs);
      await db.delete(threatActorThreats);
      await db.delete(campaigns);
      await db.delete(threatActors);
      await db.delete(analystNotes);
      await db.delete(recommendations);
      await db.delete(incidents);
      await db.delete(iocs);
      await db.delete(entities);
      await db.delete(threats);
      await db.delete(predictions);
      await db.delete(reports);
      await db.delete(assets);
    } catch (e: any) {
      console.warn("[DB] Notice during table clear:", e?.message);
    }
  }

  // Safe insertions
  try {
    const rCount = await db.select({ count: count() }).from(reports);
    if (forceClear || Number(rCount[0]?.count || 0) === 0) {
      if (data.reports.length > 0) await db.insert(reports).values(data.reports);
    }
  } catch (e: any) { console.warn("[DB] Insert reports error:", e?.message); }

  try {
    const tCount = await db.select({ count: count() }).from(threats);
    if (forceClear || Number(tCount[0]?.count || 0) === 0) {
      if (data.threats.length > 0) await db.insert(threats).values(data.threats);
    }
  } catch (e: any) { console.warn("[DB] Insert threats error:", e?.message); }

  try {
    const recCount = await db.select({ count: count() }).from(recommendations);
    if (forceClear || Number(recCount[0]?.count || 0) === 0) {
      if (data.recommendations.length > 0) await db.insert(recommendations).values(data.recommendations);
    }
  } catch (e: any) { console.warn("[DB] Insert recommendations error:", e?.message); }

  try {
    const entCount = await db.select({ count: count() }).from(entities);
    if (forceClear || Number(entCount[0]?.count || 0) === 0) {
      if (data.entities.length > 0) await db.insert(entities).values(data.entities);
    }
  } catch (e: any) { console.warn("[DB] Insert entities error:", e?.message); }

  try {
    const iocCnt = await db.select({ count: count() }).from(iocs);
    if (forceClear || Number(iocCnt[0]?.count || 0) === 0) {
      if (data.iocs.length > 0) await db.insert(iocs).values(data.iocs);
    }
  } catch (e: any) { console.warn("[DB] Insert iocs error:", e?.message); }

  try {
    const incCnt = await db.select({ count: count() }).from(incidents);
    if (forceClear || Number(incCnt[0]?.count || 0) === 0) {
      if (data.incidents.length > 0) await db.insert(incidents).values(data.incidents);
    }
  } catch (e: any) { console.warn("[DB] Insert incidents error:", e?.message); }

  try {
    const predCnt = await db.select({ count: count() }).from(predictions);
    if (forceClear || Number(predCnt[0]?.count || 0) === 0) {
      if (data.predictions.length > 0) await db.insert(predictions).values(data.predictions);
    }
  } catch (e: any) { console.warn("[DB] Insert predictions error:", e?.message); }

  try {
    const noteCnt = await db.select({ count: count() }).from(analystNotes);
    if (forceClear || Number(noteCnt[0]?.count || 0) === 0) {
      if (data.analystNotes.length > 0) await db.insert(analystNotes).values(data.analystNotes);
    }
  } catch (e: any) { console.warn("[DB] Insert analystNotes error:", e?.message); }

  try {
    const assetCnt = await db.select({ count: count() }).from(assets);
    if (forceClear || Number(assetCnt[0]?.count || 0) === 0) {
      if (data.assets && data.assets.length > 0) await db.insert(assets).values(data.assets);
    }
  } catch (e: any) { console.warn("[DB] Insert assets error:", e?.message); }

  try {
    const taCnt = await db.select({ count: count() }).from(threatActors);
    if (forceClear || Number(taCnt[0]?.count || 0) === 0) {
      if (data.threatActors && data.threatActors.length > 0) await db.insert(threatActors).values(data.threatActors);
    }
  } catch (e: any) { console.warn("[DB] Insert threatActors error:", e?.message); }

  try {
    const cmpCnt = await db.select({ count: count() }).from(campaigns);
    if (forceClear || Number(cmpCnt[0]?.count || 0) === 0) {
      if (data.campaigns && data.campaigns.length > 0) await db.insert(campaigns).values(data.campaigns);
    }
  } catch (e: any) { console.warn("[DB] Insert campaigns error:", e?.message); }

  try {
    const tatCnt = await db.select({ count: count() }).from(threatActorThreats);
    if (forceClear || Number(tatCnt[0]?.count || 0) === 0) {
      if (data.threatActorThreats && data.threatActorThreats.length > 0) await db.insert(threatActorThreats).values(data.threatActorThreats);
    }
  } catch (e: any) { console.warn("[DB] Insert threatActorThreats error:", e?.message); }

  try {
    const taiCnt = await db.select({ count: count() }).from(threatActorIocs);
    if (forceClear || Number(taiCnt[0]?.count || 0) === 0) {
      if (data.threatActorIocs && data.threatActorIocs.length > 0) await db.insert(threatActorIocs).values(data.threatActorIocs);
    }
  } catch (e: any) { console.warn("[DB] Insert threatActorIocs error:", e?.message); }

  try {
    const taincCnt = await db.select({ count: count() }).from(threatActorIncidents);
    if (forceClear || Number(taincCnt[0]?.count || 0) === 0) {
      if (data.threatActorIncidents && data.threatActorIncidents.length > 0) await db.insert(threatActorIncidents).values(data.threatActorIncidents);
    }
  } catch (e: any) { console.warn("[DB] Insert threatActorIncidents error:", e?.message); }

  try {
    const cthCnt = await db.select({ count: count() }).from(campaignThreats);
    if (forceClear || Number(cthCnt[0]?.count || 0) === 0) {
      if (data.campaignThreats && data.campaignThreats.length > 0) await db.insert(campaignThreats).values(data.campaignThreats);
    }
  } catch (e: any) { console.warn("[DB] Insert campaignThreats error:", e?.message); }

  try {
    const ciocCnt = await db.select({ count: count() }).from(campaignIocs);
    if (forceClear || Number(ciocCnt[0]?.count || 0) === 0) {
      if (data.campaignIocs && data.campaignIocs.length > 0) await db.insert(campaignIocs).values(data.campaignIocs);
    }
  } catch (e: any) { console.warn("[DB] Insert campaignIocs error:", e?.message); }

  try {
    const cincCnt = await db.select({ count: count() }).from(campaignIncidents);
    if (forceClear || Number(cincCnt[0]?.count || 0) === 0) {
      if (data.campaignIncidents && data.campaignIncidents.length > 0) await db.insert(campaignIncidents).values(data.campaignIncidents);
    }
  } catch (e: any) { console.warn("[DB] Insert campaignIncidents error:", e?.message); }

  try {
    const cmtCnt = await db.select({ count: count() }).from(campaignMitreTechniques);
    if (forceClear || Number(cmtCnt[0]?.count || 0) === 0) {
      if (data.campaignMitreTechniques && data.campaignMitreTechniques.length > 0) await db.insert(campaignMitreTechniques).values(data.campaignMitreTechniques);
    }
  } catch (e: any) { console.warn("[DB] Insert campaignMitreTechniques error:", e?.message); }

  console.log(`[DB] Seeding verification complete: Baseline initialized.`);
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: "25mb" }));

  // Seed on startup
  await seedDatabaseIfEmpty();

  // System Configuration & Engine Status
  app.get("/api/config", (req, res) => {
    const hasKey = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== "MY_GEMINI_API_KEY");
    res.json({
      platform: "ShieldZen",
      tagline: "Turning Cyber Threats into Actionable Intelligence",
      version: "2.4.0-ACADEMIC",
      aiEngine: hasKey ? "Gemini 3.7 Flash" : "Deterministic CTI Engine (Demo AI Mode)",
      hasApiKey: hasKey,
      academicMode: true,
      environment: "Sandboxed Synthetic Intelligence Environment"
    });
  });

  // Reset database endpoint
  app.post("/api/reset-data", async (req, res) => {
    try {
      await populateSyntheticData(true);
      res.json({ success: true, message: "Database reset to pristine synthetic CTI baseline." });
    } catch (e: any) {
      res.status(500).json({ error: "Failed to reset dataset: " + e.message });
    }
  });

  // Top-level Dashboard Stats
  app.get("/api/stats", async (req, res) => {
    try {
      const reportsCount = await db.select({ count: count() }).from(reports);
      const threatsCount = await db.select({ count: count() }).from(threats);
      const iocCount = await db.select({ count: count() }).from(iocs);
      const incidentCount = await db.select({ count: count() }).from(incidents);
      const predictionCount = await db.select({ count: count() }).from(predictions);

      const criticalThreats = await db.select({ count: count() }).from(threats).where(eq(threats.severity, "CRITICAL"));
      const highThreats = await db.select({ count: count() }).from(threats).where(eq(threats.severity, "HIGH"));
      const mediumThreats = await db.select({ count: count() }).from(threats).where(eq(threats.severity, "MEDIUM"));
      const lowThreats = await db.select({ count: count() }).from(threats).where(eq(threats.severity, "LOW"));

      const activeThreats = await db.select({ count: count() }).from(threats).where(eq(threats.status, "active"));
      const reviewedThreats = await db.select({ count: count() }).from(threats).where(eq(threats.status, "reviewed"));
      const escalatedThreats = await db.select({ count: count() }).from(threats).where(eq(threats.status, "escalated"));

      // Asset metrics
      let totalAssets = 0;
      let criticalAssets = 0;
      let internetExposedAssets = 0;

      try {
        const assetsCount = await db.select({ count: count() }).from(assets);
        totalAssets = Number(assetsCount[0]?.count || 0);

        const criticalAssetsCount = await db.select({ count: count() }).from(assets).where(eq(assets.criticality, "CRITICAL"));
        criticalAssets = Number(criticalAssetsCount[0]?.count || 0);

        const internetExposedCount = await db.select({ count: count() }).from(assets).where(eq(assets.exposure, "INTERNET"));
        internetExposedAssets = Number(internetExposedCount[0]?.count || 0);
      } catch (assetErr) {
        console.warn("[Stats] Error reading asset counts:", assetErr);
      }

      // Threat Actor & Campaign metrics
      let totalThreatActors = 0;
      let activeThreatActors = 0;
      let totalCampaigns = 0;
      let activeCampaigns = 0;

      try {
        const taCount = await db.select({ count: count() }).from(threatActors);
        totalThreatActors = Number(taCount[0]?.count || 0);

        const activeTaCount = await db.select({ count: count() }).from(threatActors).where(eq(threatActors.status, "Active"));
        activeThreatActors = Number(activeTaCount[0]?.count || 0);

        const campCount = await db.select({ count: count() }).from(campaigns);
        totalCampaigns = Number(campCount[0]?.count || 0);

        const activeCampCount = await db.select({ count: count() }).from(campaigns).where(eq(campaigns.status, "Active"));
        activeCampaigns = Number(activeCampCount[0]?.count || 0);
      } catch (taCampErr) {
        console.warn("[Stats] Error reading threat actor/campaign counts:", taCampErr);
      }

      res.json({
        totalReports: Number(reportsCount[0]?.count || 0),
        totalThreats: Number(threatsCount[0]?.count || 0),
        critical: Number(criticalThreats[0]?.count || 0),
        high: Number(highThreats[0]?.count || 0),
        medium: Number(mediumThreats[0]?.count || 0),
        low: Number(lowThreats[0]?.count || 0),
        totalIocs: Number(iocCount[0]?.count || 0),
        totalIncidents: Number(incidentCount[0]?.count || 0),
        emergingThreats: Number(predictionCount[0]?.count || 0),
        activeThreats: Number(activeThreats[0]?.count || 0),
        reviewedThreats: Number(reviewedThreats[0]?.count || 0),
        escalatedThreats: Number(escalatedThreats[0]?.count || 0),
        totalAssets,
        criticalAssets,
        internetExposedAssets,
        totalThreatActors,
        activeThreatActors,
        totalCampaigns,
        activeCampaigns,
      });
    } catch (error) {
      console.error("Stats error:", error);
      res.status(500).json({ error: "Failed to fetch stats" });
    }
  });

  // Assets Management API
  app.get("/api/assets", async (req, res) => {
    try {
      const { search, type, criticality, exposure, environment, status } = req.query;
      let allAssets = await db.query.assets.findMany({
        orderBy: [desc(assets.updatedAt)]
      });

      if (search && typeof search === "string" && search.trim()) {
        const query = search.toLowerCase().trim();
        allAssets = allAssets.filter((a: any) =>
          (a.name && a.name.toLowerCase().includes(query)) ||
          (a.hostname && a.hostname.toLowerCase().includes(query)) ||
          (a.ipAddress && a.ipAddress.toLowerCase().includes(query)) ||
          (a.owner && a.owner.toLowerCase().includes(query)) ||
          (a.department && a.department.toLowerCase().includes(query)) ||
          (a.software && a.software.toLowerCase().includes(query)) ||
          (a.operatingSystem && a.operatingSystem.toLowerCase().includes(query)) ||
          (a.tags && a.tags.toLowerCase().includes(query)) ||
          (a.description && a.description.toLowerCase().includes(query))
        );
      }

      if (type && typeof type === "string" && type !== "ALL") {
        allAssets = allAssets.filter((a: any) => a.assetType?.toUpperCase() === type.toUpperCase());
      }
      if (criticality && typeof criticality === "string" && criticality !== "ALL") {
        allAssets = allAssets.filter((a: any) => a.criticality?.toUpperCase() === criticality.toUpperCase());
      }
      if (exposure && typeof exposure === "string" && exposure !== "ALL") {
        allAssets = allAssets.filter((a: any) => a.exposure?.toUpperCase() === exposure.toUpperCase());
      }
      if (environment && typeof environment === "string" && environment !== "ALL") {
        allAssets = allAssets.filter((a: any) => a.environment?.toUpperCase() === environment.toUpperCase());
      }
      if (status && typeof status === "string" && status !== "ALL") {
        allAssets = allAssets.filter((a: any) => a.status?.toUpperCase() === status.toUpperCase());
      }

      res.json(allAssets);
    } catch (error: any) {
      console.error("Fetch assets error:", error);
      res.status(500).json({ error: "Failed to fetch assets: " + error.message });
    }
  });

  app.get("/api/assets/:id", async (req, res) => {
    try {
      const asset = await db.query.assets.findFirst({
        where: eq(assets.id, req.params.id)
      });
      if (!asset) {
        return res.status(404).json({ error: "Asset not found" });
      }
      res.json(asset);
    } catch (error: any) {
      console.error("Fetch asset by id error:", error);
      res.status(500).json({ error: "Failed to fetch asset: " + error.message });
    }
  });

  app.post("/api/assets", async (req, res) => {
    try {
      const {
        name,
        hostname,
        ipAddress,
        assetType,
        operatingSystem,
        software,
        environment,
        criticality,
        exposure,
        owner,
        department,
        location,
        description,
        tags,
        status
      } = req.body;

      // Validation
      if (!name || typeof name !== "string" || !name.trim()) {
        return res.status(400).json({ error: "Asset name is required" });
      }
      if (!assetType || typeof assetType !== "string" || !assetType.trim()) {
        return res.status(400).json({ error: "Asset type is required" });
      }

      const id = req.body.id && typeof req.body.id === "string" && req.body.id.trim()
        ? req.body.id.trim()
        : `ast-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

      const newAsset = {
        id,
        name: name.trim(),
        hostname: hostname ? hostname.trim() : null,
        ipAddress: ipAddress ? ipAddress.trim() : null,
        assetType: assetType.trim().toUpperCase(),
        operatingSystem: operatingSystem ? operatingSystem.trim() : null,
        software: software ? software.trim() : null,
        environment: environment ? environment.trim() : "Production",
        criticality: criticality ? criticality.trim().toUpperCase() : "MEDIUM",
        exposure: exposure ? exposure.trim().toUpperCase() : "INTERNAL",
        owner: owner ? owner.trim() : null,
        department: department ? department.trim() : null,
        location: location ? location.trim() : null,
        description: description ? description.trim() : null,
        tags: tags ? tags.trim() : null,
        status: status ? status.trim().toUpperCase() : "ACTIVE",
        createdAt: new Date(),
        updatedAt: new Date()
      };

      await db.insert(assets).values(newAsset);

      res.status(201).json(newAsset);
    } catch (error: any) {
      console.error("Create asset error:", error);
      res.status(500).json({ error: "Failed to create asset: " + error.message });
    }
  });

  app.patch("/api/assets/:id", async (req, res) => {
    try {
      const existing = await db.query.assets.findFirst({
        where: eq(assets.id, req.params.id)
      });

      if (!existing) {
        return res.status(404).json({ error: "Asset not found" });
      }

      const updates: any = {
        updatedAt: new Date()
      };

      if (req.body.name !== undefined) {
        if (!req.body.name || typeof req.body.name !== "string" || !req.body.name.trim()) {
          return res.status(400).json({ error: "Asset name cannot be empty" });
        }
        updates.name = req.body.name.trim();
      }
      if (req.body.hostname !== undefined) updates.hostname = req.body.hostname ? req.body.hostname.trim() : null;
      if (req.body.ipAddress !== undefined) updates.ipAddress = req.body.ipAddress ? req.body.ipAddress.trim() : null;
      if (req.body.assetType !== undefined) updates.assetType = req.body.assetType.trim().toUpperCase();
      if (req.body.operatingSystem !== undefined) updates.operatingSystem = req.body.operatingSystem ? req.body.operatingSystem.trim() : null;
      if (req.body.software !== undefined) updates.software = req.body.software ? req.body.software.trim() : null;
      if (req.body.environment !== undefined) updates.environment = req.body.environment.trim();
      if (req.body.criticality !== undefined) updates.criticality = req.body.criticality.trim().toUpperCase();
      if (req.body.exposure !== undefined) updates.exposure = req.body.exposure.trim().toUpperCase();
      if (req.body.owner !== undefined) updates.owner = req.body.owner ? req.body.owner.trim() : null;
      if (req.body.department !== undefined) updates.department = req.body.department ? req.body.department.trim() : null;
      if (req.body.location !== undefined) updates.location = req.body.location ? req.body.location.trim() : null;
      if (req.body.description !== undefined) updates.description = req.body.description ? req.body.description.trim() : null;
      if (req.body.tags !== undefined) updates.tags = req.body.tags ? req.body.tags.trim() : null;
      if (req.body.status !== undefined) updates.status = req.body.status.trim().toUpperCase();

      await db.update(assets).set(updates).where(eq(assets.id, req.params.id));

      const updatedAsset = await db.query.assets.findFirst({
        where: eq(assets.id, req.params.id)
      });

      res.json(updatedAsset);
    } catch (error: any) {
      console.error("Update asset error:", error);
      res.status(500).json({ error: "Failed to update asset: " + error.message });
    }
  });

  app.delete("/api/assets/:id", async (req, res) => {
    try {
      const existing = await db.query.assets.findFirst({
        where: eq(assets.id, req.params.id)
      });

      if (!existing) {
        return res.status(404).json({ error: "Asset not found" });
      }

      await db.delete(assets).where(eq(assets.id, req.params.id));

      res.json({ success: true, message: "Asset deleted successfully", id: req.params.id });
    } catch (error: any) {
      console.error("Delete asset error:", error);
      res.status(500).json({ error: "Failed to delete asset: " + error.message });
    }
  });

  // Reports
  app.get("/api/reports", async (req, res) => {
    try {
      const allReports = await db.query.reports.findMany({
        orderBy: [desc(reports.uploadDate)]
      });
      res.json(allReports);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch reports" });
    }
  });

  app.get("/api/reports/:id", async (req, res) => {
    try {
      const r = await db.query.reports.findFirst({
        where: eq(reports.id, req.params.id)
      });
      if (!r) return res.status(404).json({ error: "Report not found" });

      const relatedThreats = await db.query.threats.findMany({
        where: eq(threats.reportId, req.params.id)
      });
      const relatedEntities = await db.query.entities.findMany({
        where: eq(entities.reportId, req.params.id)
      });
      const relatedIocs = await db.query.iocs.findMany({
        where: eq(iocs.reportId, req.params.id)
      });
      const relatedIncidents = await db.query.incidents.findMany({
        where: eq(incidents.reportId, req.params.id)
      });

      res.json({
        ...r,
        threats: relatedThreats,
        entities: relatedEntities,
        iocs: relatedIocs,
        incidents: relatedIncidents
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch report" });
    }
  });

  app.delete("/api/reports/:id", async (req, res) => {
    try {
      await db.delete(reports).where(eq(reports.id, req.params.id));
      res.json({ success: true, message: "Report and related records deleted." });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete report" });
    }
  });

  app.post("/api/reports/:id/reanalyze", async (req, res) => {
    try {
      const r = await db.query.reports.findFirst({
        where: eq(reports.id, req.params.id)
      });
      if (!r) return res.status(404).json({ error: "Report not found" });

      // Clean existing threat records for this report
      await db.delete(threats).where(eq(threats.reportId, req.params.id));
      await db.delete(entities).where(eq(entities.reportId, req.params.id));
      await db.delete(iocs).where(eq(iocs.reportId, req.params.id));

      const analysis = await analyzeIntelligenceReport(r.rawText);

      await db.update(reports).set({
        summary: analysis.summary,
        keyFindings: JSON.stringify(analysis.keyFindings),
        category: analysis.category || r.category,
        sourceOrigin: analysis.sourceOrigin || r.sourceOrigin,
        severity: analysis.severity || r.severity,
        aiConfidence: analysis.aiConfidence || 90,
        status: "analyzed",
        threatCount: analysis.threats.length,
        entityCount: analysis.entities.length,
        iocCount: analysis.iocs.length
      }).where(eq(reports.id, req.params.id));

      await insertAnalysisArtifacts(req.params.id, analysis);

      res.json({ success: true, message: "Report re-analyzed successfully." });
    } catch (error) {
      res.status(500).json({ error: "Failed to re-analyze report" });
    }
  });

  // Upload Intelligence Report (TXT, PDF, DOCX)
  app.post("/api/upload", upload.single("file"), async (req, res) => {
    try {
      let text = "";
      let filename = "Raw_Intel_Upload_" + new Date().toISOString().substring(0, 10) + ".txt";
      let fileType = "text/plain";

      if (req.file) {
        filename = req.file.originalname;
        fileType = req.file.mimetype;

        const origNameLower = req.file.originalname.toLowerCase();
        if (
          req.file.mimetype === "application/pdf" ||
          origNameLower.endsWith(".pdf")
        ) {
          try {
            const pdfModule = await import("pdf-parse") as any;
            const pdfParse = pdfModule.default || pdfModule;
            const data = await pdfParse(req.file.buffer);
            text = data.text || "";
            if (!text.trim()) {
              return res.status(400).json({ error: "The uploaded PDF document contains no extractable text." });
            }
          } catch (e: any) {
            console.error("PDF parse error:", e);
            return res.status(400).json({ error: "Failed to extract text from PDF: " + (e?.message || "Invalid or unreadable document.") });
          }
        } else if (
          req.file.mimetype === "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
          req.file.mimetype === "application/msword" ||
          origNameLower.endsWith(".docx") ||
          origNameLower.endsWith(".doc")
        ) {
          try {
            const mammothModule = await import("mammoth") as any;
            const mammoth = mammothModule.default || mammothModule;
            const result = await mammoth.extractRawText({ buffer: req.file.buffer });
            text = result.value || "";
            if (!text.trim()) {
              return res.status(400).json({ error: "The uploaded DOCX document contains no extractable text content." });
            }
          } catch (e: any) {
            console.error("DOCX parse error:", e);
            return res.status(400).json({ error: "Failed to parse DOCX document: " + (e?.message || "Invalid or unreadable document.") });
          }
        } else {
          text = req.file.buffer.toString("utf-8");
          if (!text.trim()) {
            return res.status(400).json({ error: "Uploaded text document is empty." });
          }
        }
      } else if (req.body.text) {
        text = req.body.text;
        filename = req.body.title ? `${req.body.title.replace(/[^a-zA-Z0-9_-]/g, "_")}.txt` : filename;
      } else {
        return res.status(400).json({ error: "No file or text provided" });
      }

      const reportId = "rep-usr-" + Math.random().toString(36).substring(2, 9);
      const isGemini = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== "MY_GEMINI_API_KEY");

      await db.insert(reports).values({
        id: reportId,
        filename,
        fileType,
        rawText: text,
        summary: "Analyzing report with AI engine...",
        status: "processing",
        uploadDate: new Date(),
        analysisMode: isGemini ? "Gemini AI" : "Demo AI Mode",
        threatCount: 0,
        entityCount: 0,
        iocCount: 0
      });

      // Synchronously process or immediately complete so user sees output right away
      try {
        const analysis = await analyzeIntelligenceReport(text);

        await db.update(reports).set({
          summary: analysis.summary,
          keyFindings: JSON.stringify(analysis.keyFindings),
          category: analysis.category || "Cyber Threat Intel",
          sourceOrigin: analysis.sourceOrigin || "Uploaded Intelligence Document",
          severity: analysis.severity || "HIGH",
          aiConfidence: analysis.aiConfidence || 88,
          status: "analyzed",
          threatCount: analysis.threats.length,
          entityCount: analysis.entities.length,
          iocCount: analysis.iocs.length
        }).where(eq(reports.id, reportId));

        await insertAnalysisArtifacts(reportId, analysis);

        res.json({
          id: reportId,
          status: "analyzed",
          summary: analysis.summary,
          threatCount: analysis.threats.length,
          iocCount: analysis.iocs.length,
          severity: analysis.severity
        });
      } catch (analysisErr) {
        console.error("Direct analysis failed, marked as fallback analyzed:", analysisErr);
        await db.update(reports).set({ status: "analyzed" }).where(eq(reports.id, reportId));
        res.json({ id: reportId, status: "analyzed" });
      }

    } catch (error) {
      console.error("Upload error:", error);
      res.status(500).json({ error: "Failed to upload and analyze report" });
    }
  });

  // Threats
  app.get("/api/threats", async (req, res) => {
    try {
      const allThreats = await db.query.threats.findMany({
        orderBy: [desc(threats.detectedAt)]
      });
      const allReports = await db.query.reports.findMany();
      const reportMap = new Map(allReports.map(r => [r.id, r]));

      const enrichedThreats = allThreats.map((t: any) => {
        const rep: any = t.reportId ? reportMap.get(t.reportId) : null;
        return {
          ...t,
          source: rep ? `${rep.sourceOrigin || "Threat Report (OSINT)"} (${rep.analysisMode || "Gemini AI"})` : "Threat Report (OSINT)",
          sourceOrigin: rep?.sourceOrigin || "Threat Report (OSINT)",
          analysisMode: rep?.analysisMode || "Gemini AI",
          reportFilename: rep?.filename || "Intelligence Report"
        };
      });

      res.json(enrichedThreats);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch threats" });
    }
  });

  app.get("/api/threats/:id", async (req, res) => {
    try {
      const t = await db.query.threats.findFirst({
        where: eq(threats.id, req.params.id)
      });
      if (!t) return res.status(404).json({ error: "Threat not found" });

      const report = t.reportId ? await db.query.reports.findFirst({ where: eq(reports.id, t.reportId) }) : null;
      const relatedRecs = await db.query.recommendations.findMany({ where: eq(recommendations.threatId, req.params.id) });
      const relatedIocs = await db.query.iocs.findMany({ where: eq(iocs.threatId, req.params.id) });
      const relatedEntities = await db.query.entities.findMany({ where: eq(entities.threatId, req.params.id) });
      const relatedIncidents = await db.query.incidents.findMany({ where: eq(incidents.threatId, req.params.id) });
      const notes = await db.query.analystNotes.findMany({
        where: eq(analystNotes.threatId, req.params.id),
        orderBy: [desc(analystNotes.timestamp)]
      });

      res.json({
        ...t,
        report,
        recommendations: relatedRecs,
        iocs: relatedIocs,
        entities: relatedEntities,
        incidents: relatedIncidents,
        analystNotes: notes
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch threat details" });
    }
  });

  app.patch("/api/threats/:id", async (req, res) => {
    try {
      const updateData: any = {};
      if (req.body.status) updateData.status = req.body.status;
      if (req.body.severity) updateData.severity = req.body.severity;
      if (req.body.analystSeverityOverride) updateData.analystSeverityOverride = req.body.analystSeverityOverride;
      if (req.body.overrideReason) updateData.overrideReason = req.body.overrideReason;

      await db.update(threats).set(updateData).where(eq(threats.id, req.params.id));

      if (req.body.analystNote) {
        await db.insert(analystNotes).values({
          id: "note-usr-" + Math.random().toString(36).substring(2, 9),
          threatId: req.params.id,
          author: req.body.author || "Lead SOC Analyst",
          note: req.body.analystNote,
          timestamp: new Date()
        });
      }

      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Failed to update threat" });
    }
  });

  app.patch("/api/threats/:id/status", async (req, res) => {
    try {
      const { status } = req.body;
      if (!status) return res.status(400).json({ error: "Status is required." });
      await db.update(threats).set({ status }).where(eq(threats.id, req.params.id));
      res.json({ success: true, status });
    } catch (e) {
      res.status(500).json({ error: "Failed to update threat status" });
    }
  });

  app.post("/api/threats/:id/notes", async (req, res) => {
    try {
      const newNote = {
        id: "note-usr-" + Math.random().toString(36).substring(2, 9),
        threatId: req.params.id,
        author: req.body.author || "Analyst (You)",
        note: req.body.note,
        timestamp: new Date()
      };
      await db.insert(analystNotes).values(newNote);
      res.json(newNote);
    } catch (e) {
      res.status(500).json({ error: "Failed to add analyst note" });
    }
  });

  // Toggle recommendation completion
  app.patch("/api/recommendations/:id", async (req, res) => {
    try {
      const { completed } = req.body;
      await db.update(recommendations).set({ completed: completed ? 1 : 0 }).where(eq(recommendations.id, req.params.id));
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Failed to update recommendation" });
    }
  });

  // ==========================================
  // IOC (INDICATORS OF COMPROMISE) API
  // ==========================================

  // 1. Filtered & Enriched IOCs List
  app.get("/api/iocs", async (req, res) => {
    try {
      const { search, type, minConfidence, severity, threatId, reportId } = req.query;
      let allIocs = await db.query.iocs.findMany({
        orderBy: [desc(iocs.confidence), desc(iocs.reputationScore)]
      });

      // Join threats & reports context for rich list cards
      const allThreats = await db.query.threats.findMany();
      const allReports = await db.query.reports.findMany();
      const threatMap = new Map<string, any>(allThreats.map((t: any) => [t.id, t]));
      const reportMap = new Map<string, any>(allReports.map((r: any) => [r.id, r]));

      let enrichedList = allIocs.map((ioc: any) => {
        const threat = ioc.threatId ? threatMap.get(ioc.threatId) : null;
        const report = ioc.reportId ? reportMap.get(ioc.reportId) : null;
        const derivedSeverity = ioc.severity || threat?.severity || (ioc.confidence >= 90 ? "HIGH" : "MEDIUM");

        return {
          ...ioc,
          defangedValue: defangIoc(ioc.value, ioc.type),
          threatTitle: threat?.title || null,
          threatSeverity: threat?.severity || null,
          reportTitle: report?.filename || report?.summary || null,
          severity: derivedSeverity,
          reputationScore: ioc.reputationScore || (ioc.confidence >= 95 ? 95 : ioc.confidence >= 90 ? 88 : 75)
        };
      });

      // Filter: Search across value, context, type, tags
      if (search && typeof search === "string" && search.trim()) {
        const q = search.toLowerCase().trim();
        enrichedList = enrichedList.filter((i: any) =>
          i.value.toLowerCase().includes(q) ||
          i.type.toLowerCase().includes(q) ||
          (i.context && i.context.toLowerCase().includes(q)) ||
          (i.tags && i.tags.toLowerCase().includes(q)) ||
          (i.threatTitle && i.threatTitle.toLowerCase().includes(q))
        );
      }

      // Filter: Type
      if (type && typeof type === "string" && type !== "ALL") {
        enrichedList = enrichedList.filter((i: any) => {
          if (type.toUpperCase() === "IP") {
            return i.type.toUpperCase() === "IPV4" || i.type.toUpperCase() === "IPV6" || i.type.toUpperCase() === "IP";
          }
          return i.type.toUpperCase() === type.toUpperCase();
        });
      }

      // Filter: Confidence
      if (minConfidence) {
        const minConf = parseInt(String(minConfidence), 10);
        if (!isNaN(minConf)) {
          enrichedList = enrichedList.filter((i: any) => (i.confidence || 0) >= minConf);
        }
      }

      // Filter: Severity
      if (severity && typeof severity === "string" && severity !== "ALL") {
        enrichedList = enrichedList.filter((i: any) => i.severity?.toUpperCase() === severity.toUpperCase());
      }

      // Filter: Direct Threat or Report
      if (threatId && typeof threatId === "string") {
        enrichedList = enrichedList.filter((i: any) => i.threatId === threatId);
      }
      if (reportId && typeof reportId === "string") {
        enrichedList = enrichedList.filter((i: any) => i.reportId === reportId);
      }

      res.json(enrichedList);
    } catch (error: any) {
      console.error("Fetch IOCs error:", error);
      res.status(500).json({ error: "Failed to fetch IOCs: " + error.message });
    }
  });

  // 2. Real-time On-demand IOC Lookup & Investigation
  app.post("/api/iocs/lookup", async (req, res) => {
    try {
      const { ioc: rawInput, type } = req.body;
      if (!rawInput || typeof rawInput !== "string" || !rawInput.trim()) {
        return res.status(400).json({ error: "IOC query value is required for investigation lookup." });
      }

      const cleanValue = refangIoc(rawInput).trim();
      const detectedType = type || detectIocType(cleanValue);

      const dossier = await iocEnrichmentService.getIocDetails(cleanValue);
      if (!dossier) {
        return res.status(404).json({ error: "Could not generate intelligence dossier for indicator." });
      }

      res.json(dossier);
    } catch (error: any) {
      console.error("IOC lookup investigation error:", error);
      res.status(500).json({ error: "Investigation lookup failed: " + error.message });
    }
  });

  // 3. IOC Detail Endpoint (Deep Dossier, Relationships, Multi-Source Enrichment)
  app.get("/api/iocs/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const dossier = await iocEnrichmentService.getIocDetails(id);
      if (!dossier) {
        return res.status(404).json({ error: "Indicator of Compromise not found." });
      }
      res.json(dossier);
    } catch (error: any) {
      console.error("Fetch IOC detail error:", error);
      res.status(500).json({ error: "Failed to fetch IOC details: " + error.message });
    }
  });

  // 4. Create New Analyst IOC
  app.post("/api/iocs", async (req, res) => {
    try {
      const { value, type, confidence, context, threatId, reportId, severity, tags } = req.body;
      if (!value || typeof value !== "string" || !value.trim()) {
        return res.status(400).json({ error: "Artifact value is required." });
      }

      const cleanValue = refangIoc(value).trim();
      const iocType = type || detectIocType(cleanValue);
      const id = `ioc-analyst-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;

      const newIoc = {
        id,
        value: cleanValue,
        type: iocType,
        confidence: typeof confidence === "number" ? Math.min(100, Math.max(1, confidence)) : 90,
        context: context ? String(context).trim() : "Analyst verified indicator of compromise",
        threatId: threatId || null,
        reportId: reportId || null,
        severity: severity || "HIGH",
        firstSeen: new Date(),
        lastSeen: new Date(),
        tags: tags || "analyst-created",
        reputationScore: 85,
        enrichmentData: null
      };

      await db.insert(iocs).values(newIoc);
      res.status(201).json(newIoc);
    } catch (error: any) {
      console.error("Create IOC error:", error);
      res.status(500).json({ error: "Failed to create IOC: " + error.message });
    }
  });

  // 5. Update Existing IOC
  app.patch("/api/iocs/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const { context, confidence, severity, tags, reputationScore } = req.body;

      const existing = await db.query.iocs.findFirst({
        where: eq(iocs.id, id)
      });
      if (!existing) {
        return res.status(404).json({ error: "IOC not found" });
      }

      const updates: any = {};
      if (context !== undefined) updates.context = context;
      if (confidence !== undefined) updates.confidence = confidence;
      if (severity !== undefined) updates.severity = severity;
      if (tags !== undefined) updates.tags = tags;
      if (reputationScore !== undefined) updates.reputationScore = reputationScore;
      updates.lastSeen = new Date();

      await db.update(iocs).set(updates).where(eq(iocs.id, id));
      const updated = await db.query.iocs.findFirst({ where: eq(iocs.id, id) });
      res.json(updated);
    } catch (error: any) {
      console.error("Update IOC error:", error);
      res.status(500).json({ error: "Failed to update IOC: " + error.message });
    }
  });

  // 6. Delete IOC
  app.delete("/api/iocs/:id", async (req, res) => {
    try {
      const { id } = req.params;
      await db.delete(iocs).where(eq(iocs.id, id));
      res.json({ success: true, message: `IOC ${id} deleted successfully` });
    } catch (error: any) {
      console.error("Delete IOC error:", error);
      res.status(500).json({ error: "Failed to delete IOC: " + error.message });
    }
  });

  // 7. Export Single IOC in STIX 2.1 Bundle Format
  app.get("/api/iocs/:id/export", async (req, res) => {
    try {
      const dossier = await iocEnrichmentService.getIocDetails(req.params.id);
      if (!dossier) {
        return res.status(404).json({ error: "IOC not found" });
      }

      const stixBundle = {
        type: "bundle",
        id: `bundle--${Math.random().toString(36).substring(2, 10)}`,
        spec_version: "2.1",
        objects: [
          {
            type: "indicator",
            spec_version: "2.1",
            id: `indicator--${dossier.ioc.id}`,
            created: dossier.firstSeen,
            modified: dossier.lastSeen,
            name: `${dossier.ioc.type} Threat Artifact: ${dossier.defangedValue}`,
            description: dossier.ioc.context || "ShieldZen extracted cyber threat indicator",
            indicator_types: [dossier.ioc.type.toLowerCase()],
            pattern: `[${dossier.ioc.type.toLowerCase()}:value = '${dossier.ioc.value}']`,
            pattern_type: "stix",
            confidence: dossier.ioc.confidence,
            external_references: dossier.enrichment.vulnerabilityDetails ? [
              {
                source_name: "cve",
                external_id: dossier.enrichment.vulnerabilityDetails.cveId
              }
            ] : []
          }
        ]
      };

      res.setHeader("Content-Disposition", `attachment; filename="shieldzen-ioc-${dossier.ioc.id}.json"`);
      res.json(stixBundle);
    } catch (error: any) {
      res.status(500).json({ error: "Failed to export IOC STIX: " + error.message });
    }
  });

  // ==========================================
  // THREAT ACTORS INTELLIGENCE APIS
  // ==========================================

  // List all Threat Actors with filters
  app.get("/api/threat-actors", async (req, res) => {
    try {
      const { origin, motivation, sophistication, status, search } = req.query;
      const actorList = await listThreatActors({
        origin: origin as string,
        motivation: motivation as string,
        sophistication: sophistication as string,
        status: status as string,
        search: search as string
      });
      res.json(actorList);
    } catch (error: any) {
      console.error("List threat actors error:", error);
      res.status(500).json({ error: "Failed to list threat actors: " + error.message });
    }
  });

  // Get single Threat Actor Intelligence Dossier
  app.get("/api/threat-actors/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const dossier = await getThreatActorById(id);
      if (!dossier) {
        return res.status(404).json({ error: "Threat Actor not found" });
      }
      res.json(dossier);
    } catch (error: any) {
      console.error("Get threat actor dossier error:", error);
      res.status(500).json({ error: "Failed to get threat actor dossier: " + error.message });
    }
  });

  // Create new Threat Actor
  app.post("/api/threat-actors", async (req, res) => {
    try {
      const { name, aliases, description, origin, motivation, sophistication, confidence, status, notes } = req.body;
      if (!name || typeof name !== "string" || !name.trim()) {
        return res.status(400).json({ error: "Threat actor name is required." });
      }
      if (!description || typeof description !== "string" || !description.trim()) {
        return res.status(400).json({ error: "Threat actor description is required." });
      }

      const id = `act-user-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
      const aliasString = Array.isArray(aliases) ? JSON.stringify(aliases) : typeof aliases === "string" ? JSON.stringify(aliases.split(",").map((s) => s.trim()).filter(Boolean)) : JSON.stringify([]);

      const newActor = {
        id,
        name: name.trim(),
        aliases: aliasString,
        description: description.trim(),
        origin: origin || "Unknown",
        motivation: motivation || "Unknown",
        sophistication: sophistication || "Medium",
        confidence: typeof confidence === "number" ? Math.max(0, Math.min(100, confidence)) : 85,
        status: status || "Active",
        notes: notes || "",
        isSynthetic: 0,
        createdAt: new Date(),
        updatedAt: new Date()
      };

      await db.insert(threatActors).values(newActor);
      const dossier = await getThreatActorById(id);
      res.status(201).json(dossier);
    } catch (error: any) {
      console.error("Create threat actor error:", error);
      res.status(500).json({ error: "Failed to create threat actor: " + error.message });
    }
  });

  // Update Threat Actor
  app.patch("/api/threat-actors/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const { name, aliases, description, origin, motivation, sophistication, confidence, status, notes } = req.body;

      const existing = await db.select().from(threatActors).where(eq(threatActors.id, id));
      if (existing.length === 0) {
        return res.status(404).json({ error: "Threat actor not found." });
      }

      const updateData: any = {
        updatedAt: new Date()
      };

      if (name !== undefined) updateData.name = String(name).trim();
      if (aliases !== undefined) {
        updateData.aliases = Array.isArray(aliases) ? JSON.stringify(aliases) : JSON.stringify(String(aliases).split(",").map((s) => s.trim()).filter(Boolean));
      }
      if (description !== undefined) updateData.description = String(description).trim();
      if (origin !== undefined) updateData.origin = String(origin);
      if (motivation !== undefined) updateData.motivation = String(motivation);
      if (sophistication !== undefined) updateData.sophistication = String(sophistication);
      if (confidence !== undefined) updateData.confidence = Number(confidence);
      if (status !== undefined) updateData.status = String(status);
      if (notes !== undefined) updateData.notes = String(notes);

      await db.update(threatActors).set(updateData).where(eq(threatActors.id, id));
      const dossier = await getThreatActorById(id);
      res.json(dossier);
    } catch (error: any) {
      console.error("Update threat actor error:", error);
      res.status(500).json({ error: "Failed to update threat actor: " + error.message });
    }
  });

  // Delete Threat Actor
  app.delete("/api/threat-actors/:id", async (req, res) => {
    try {
      const { id } = req.params;
      await db.delete(threatActorThreats).where(eq(threatActorThreats.threatActorId, id));
      await db.delete(threatActorIocs).where(eq(threatActorIocs.threatActorId, id));
      await db.delete(threatActorIncidents).where(eq(threatActorIncidents.threatActorId, id));
      await db.update(campaigns).set({ threatActorId: null }).where(eq(campaigns.threatActorId, id));
      await db.delete(threatActors).where(eq(threatActors.id, id));
      res.json({ success: true, message: `Threat actor ${id} deleted.` });
    } catch (error: any) {
      console.error("Delete threat actor error:", error);
      res.status(500).json({ error: "Failed to delete threat actor: " + error.message });
    }
  });

  // Associate relationship with Threat Actor
  app.post("/api/threat-actors/:id/relationships", async (req, res) => {
    try {
      const { id } = req.params;
      const { type, targetId, confidence, attributionType, context } = req.body;

      if (!type || !targetId) {
        return res.status(400).json({ error: "type and targetId are required." });
      }

      if (type === "THREAT") {
        const linkId = `tat-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
        await db.insert(threatActorThreats).values({
          id: linkId,
          threatActorId: id,
          threatId: targetId,
          relationshipConfidence: confidence || "confirmed",
          attributionType: attributionType || "Primary Operator",
          createdAt: new Date()
        });
      } else if (type === "IOC") {
        const linkId = `tai-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
        await db.insert(threatActorIocs).values({
          id: linkId,
          threatActorId: id,
          iocId: targetId,
          relationshipConfidence: confidence || "confirmed",
          context: context || "Associated Adversary Artifact",
          createdAt: new Date()
        });
      } else if (type === "INCIDENT") {
        const linkId = `tainc-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
        await db.insert(threatActorIncidents).values({
          id: linkId,
          threatActorId: id,
          incidentId: targetId,
          confidence: typeof confidence === "number" ? confidence : 85,
          createdAt: new Date()
        });
      } else if (type === "CAMPAIGN") {
        await db.update(campaigns).set({ threatActorId: id }).where(eq(campaigns.id, targetId));
      } else {
        return res.status(400).json({ error: "Unsupported relationship type." });
      }

      const updated = await getThreatActorById(id);
      res.json(updated);
    } catch (error: any) {
      console.error("Add threat actor relationship error:", error);
      res.status(500).json({ error: "Failed to add relationship: " + error.message });
    }
  });

  // Remove relationship from Threat Actor
  app.delete("/api/threat-actors/:id/relationships", async (req, res) => {
    try {
      const { id } = req.params;
      const { type, targetId } = req.body;

      if (!type || !targetId) {
        return res.status(400).json({ error: "type and targetId are required." });
      }

      if (type === "THREAT") {
        await db.delete(threatActorThreats).where(and(eq(threatActorThreats.threatActorId, id), eq(threatActorThreats.threatId, targetId)));
      } else if (type === "IOC") {
        await db.delete(threatActorIocs).where(and(eq(threatActorIocs.threatActorId, id), eq(threatActorIocs.iocId, targetId)));
      } else if (type === "INCIDENT") {
        await db.delete(threatActorIncidents).where(and(eq(threatActorIncidents.threatActorId, id), eq(threatActorIncidents.incidentId, targetId)));
      } else if (type === "CAMPAIGN") {
        await db.update(campaigns).set({ threatActorId: null }).where(and(eq(campaigns.threatActorId, id), eq(campaigns.id, targetId)));
      }

      const updated = await getThreatActorById(id);
      res.json(updated);
    } catch (error: any) {
      console.error("Remove relationship error:", error);
      res.status(500).json({ error: "Failed to remove relationship: " + error.message });
    }
  });

  // ==========================================
  // CAMPAIGNS INTELLIGENCE APIS
  // ==========================================

  // List all Campaigns with filters
  app.get("/api/campaigns", async (req, res) => {
    try {
      const { status, threatActorId, sector, region, search } = req.query;
      const campaignList = await listCampaigns({
        status: status as string,
        threatActorId: threatActorId as string,
        sector: sector as string,
        region: region as string,
        search: search as string
      });
      res.json(campaignList);
    } catch (error: any) {
      console.error("List campaigns error:", error);
      res.status(500).json({ error: "Failed to list campaigns: " + error.message });
    }
  });

  // Get single Campaign Intelligence Dossier
  app.get("/api/campaigns/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const dossier = await getCampaignById(id);
      if (!dossier) {
        return res.status(404).json({ error: "Campaign not found" });
      }
      res.json(dossier);
    } catch (error: any) {
      console.error("Get campaign dossier error:", error);
      res.status(500).json({ error: "Failed to get campaign dossier: " + error.message });
    }
  });

  // Create new Campaign
  app.post("/api/campaigns", async (req, res) => {
    try {
      const { name, description, threatActorId, targetSectors, targetRegions, objectives, status, confidence, notes } = req.body;
      if (!name || typeof name !== "string" || !name.trim()) {
        return res.status(400).json({ error: "Campaign name is required." });
      }
      if (!description || typeof description !== "string" || !description.trim()) {
        return res.status(400).json({ error: "Campaign description is required." });
      }

      const id = `cmp-user-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
      const sectorsString = Array.isArray(targetSectors) ? JSON.stringify(targetSectors) : typeof targetSectors === "string" ? JSON.stringify(targetSectors.split(",").map((s) => s.trim()).filter(Boolean)) : JSON.stringify([]);
      const regionsString = Array.isArray(targetRegions) ? JSON.stringify(targetRegions) : typeof targetRegions === "string" ? JSON.stringify(targetRegions.split(",").map((s) => s.trim()).filter(Boolean)) : JSON.stringify([]);

      const newCampaign = {
        id,
        name: name.trim(),
        description: description.trim(),
        threatActorId: threatActorId || null,
        targetSectors: sectorsString,
        targetRegions: regionsString,
        objectives: objectives || "",
        status: status || "Active",
        confidence: typeof confidence === "number" ? Math.max(0, Math.min(100, confidence)) : 85,
        notes: notes || "",
        firstObserved: new Date(),
        lastObserved: new Date(),
        createdAt: new Date(),
        updatedAt: new Date()
      };

      await db.insert(campaigns).values(newCampaign);
      const dossier = await getCampaignById(id);
      res.status(201).json(dossier);
    } catch (error: any) {
      console.error("Create campaign error:", error);
      res.status(500).json({ error: "Failed to create campaign: " + error.message });
    }
  });

  // Update Campaign
  app.patch("/api/campaigns/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const { name, description, threatActorId, targetSectors, targetRegions, objectives, status, confidence, notes } = req.body;

      const existing = await db.select().from(campaigns).where(eq(campaigns.id, id));
      if (existing.length === 0) {
        return res.status(404).json({ error: "Campaign not found." });
      }

      const updateData: any = {
        updatedAt: new Date()
      };

      if (name !== undefined) updateData.name = String(name).trim();
      if (description !== undefined) updateData.description = String(description).trim();
      if (threatActorId !== undefined) updateData.threatActorId = threatActorId || null;
      if (targetSectors !== undefined) {
        updateData.targetSectors = Array.isArray(targetSectors) ? JSON.stringify(targetSectors) : JSON.stringify(String(targetSectors).split(",").map((s) => s.trim()).filter(Boolean));
      }
      if (targetRegions !== undefined) {
        updateData.targetRegions = Array.isArray(targetRegions) ? JSON.stringify(targetRegions) : JSON.stringify(String(targetRegions).split(",").map((s) => s.trim()).filter(Boolean));
      }
      if (objectives !== undefined) updateData.objectives = String(objectives);
      if (status !== undefined) updateData.status = String(status);
      if (confidence !== undefined) updateData.confidence = Number(confidence);
      if (notes !== undefined) updateData.notes = String(notes);

      await db.update(campaigns).set(updateData).where(eq(campaigns.id, id));
      const dossier = await getCampaignById(id);
      res.json(dossier);
    } catch (error: any) {
      console.error("Update campaign error:", error);
      res.status(500).json({ error: "Failed to update campaign: " + error.message });
    }
  });

  // Delete Campaign
  app.delete("/api/campaigns/:id", async (req, res) => {
    try {
      const { id } = req.params;
      await db.delete(campaignThreats).where(eq(campaignThreats.campaignId, id));
      await db.delete(campaignIocs).where(eq(campaignIocs.campaignId, id));
      await db.delete(campaignIncidents).where(eq(campaignIncidents.campaignId, id));
      await db.delete(campaignMitreTechniques).where(eq(campaignMitreTechniques.campaignId, id));
      await db.delete(campaigns).where(eq(campaigns.id, id));
      res.json({ success: true, message: `Campaign ${id} deleted.` });
    } catch (error: any) {
      console.error("Delete campaign error:", error);
      res.status(500).json({ error: "Failed to delete campaign: " + error.message });
    }
  });

  // Associate relationship with Campaign
  app.post("/api/campaigns/:id/relationships", async (req, res) => {
    try {
      const { id } = req.params;
      const { type, targetId, confidence, techniqueName, tactic } = req.body;

      if (!type || !targetId) {
        return res.status(400).json({ error: "type and targetId are required." });
      }

      if (type === "THREAT") {
        const linkId = `cth-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
        await db.insert(campaignThreats).values({
          id: linkId,
          campaignId: id,
          threatId: targetId,
          relationshipConfidence: confidence || "confirmed",
          createdAt: new Date()
        });
      } else if (type === "IOC") {
        const linkId = `cioc-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
        await db.insert(campaignIocs).values({
          id: linkId,
          campaignId: id,
          iocId: targetId,
          relationshipConfidence: confidence || "confirmed",
          createdAt: new Date()
        });
      } else if (type === "INCIDENT") {
        const linkId = `cinc-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
        await db.insert(campaignIncidents).values({
          id: linkId,
          campaignId: id,
          incidentId: targetId,
          confidence: typeof confidence === "number" ? confidence : 85,
          createdAt: new Date()
        });
      } else if (type === "TECHNIQUE") {
        const linkId = `cmt-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
        await db.insert(campaignMitreTechniques).values({
          id: linkId,
          campaignId: id,
          techniqueId: targetId,
          techniqueName: techniqueName || `Technique ${targetId}`,
          tactic: tactic || "Execution",
          confidence: typeof confidence === "number" ? confidence : 90,
          createdAt: new Date()
        });
      } else {
        return res.status(400).json({ error: "Unsupported campaign relationship type." });
      }

      const updated = await getCampaignById(id);
      res.json(updated);
    } catch (error: any) {
      console.error("Add campaign relationship error:", error);
      res.status(500).json({ error: "Failed to add campaign relationship: " + error.message });
    }
  });

  // Remove relationship from Campaign
  app.delete("/api/campaigns/:id/relationships", async (req, res) => {
    try {
      const { id } = req.params;
      const { type, targetId } = req.body;

      if (!type || !targetId) {
        return res.status(400).json({ error: "type and targetId are required." });
      }

      if (type === "THREAT") {
        await db.delete(campaignThreats).where(and(eq(campaignThreats.campaignId, id), eq(campaignThreats.threatId, targetId)));
      } else if (type === "IOC") {
        await db.delete(campaignIocs).where(and(eq(campaignIocs.campaignId, id), eq(campaignIocs.iocId, targetId)));
      } else if (type === "INCIDENT") {
        await db.delete(campaignIncidents).where(and(eq(campaignIncidents.campaignId, id), eq(campaignIncidents.incidentId, targetId)));
      } else if (type === "TECHNIQUE") {
        await db.delete(campaignMitreTechniques).where(and(eq(campaignMitreTechniques.campaignId, id), eq(campaignMitreTechniques.techniqueId, targetId)));
      }

      const updated = await getCampaignById(id);
      res.json(updated);
    } catch (error: any) {
      console.error("Remove campaign relationship error:", error);
      res.status(500).json({ error: "Failed to remove campaign relationship: " + error.message });
    }
  });

  // Incidents
  app.get("/api/incidents", async (req, res) => {
    try {
      const allIncidents = await db.query.incidents.findMany({
        orderBy: [desc(incidents.date)]
      });
      res.json(allIncidents);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch incidents" });
    }
  });

  // Predictions / Emerging Threats
  app.get("/api/predictions", async (req, res) => {
    try {
      const p = await db.query.predictions.findMany({
        orderBy: [desc(predictions.riskScore)]
      });
      res.json(p);
    } catch (e) {
      res.status(500).json({ error: "Failed to fetch predictions" });
    }
  });

  // Heatmap data with enriched coordinates and metrics
  app.get("/api/heatmap", async (req, res) => {
    try {
      const allInc = (await db.query.incidents.findMany()) as any[];
      const cityMap: Record<string, { lat: number; lng: number; incidents: any[]; categoryCount: Record<string, number>; maxSev: string }> = {};

      allInc.forEach(inc => {
        if (!inc.coordinates || typeof inc.coordinates !== "string") return;
        const [latStr, lngStr] = inc.coordinates.split(",");
        const lat = parseFloat(latStr);
        const lng = parseFloat(lngStr);
        if (isNaN(lat) || isNaN(lng)) return;

        const key = `${lat.toFixed(2)},${lng.toFixed(2)}`;
        if (!cityMap[key]) {
          cityMap[key] = {
            lat,
            lng,
            incidents: [],
            categoryCount: {},
            maxSev: "LOW"
          };
        }

        cityMap[key].incidents.push(inc);
        const cat = String(inc.category || "Cyber Threat");
        cityMap[key].categoryCount[cat] = (cityMap[key].categoryCount[cat] || 0) + 1;
        if (inc.severity === "CRITICAL") cityMap[key].maxSev = "CRITICAL";
        else if (inc.severity === "HIGH" && cityMap[key].maxSev !== "CRITICAL") cityMap[key].maxSev = "HIGH";
      });

      const heatmap = Object.values(cityMap).map(item => {
        const topCat = Object.entries(item.categoryCount).sort((a, b) => b[1] - a[1])[0]?.[0] || "Cyber Threat";
        const weight = item.maxSev === "CRITICAL" ? 9 : item.maxSev === "HIGH" ? 7 : item.maxSev === "MEDIUM" ? 5 : 3;
        return {
          lat: item.lat,
          lng: item.lng,
          location: item.incidents[0]?.location || "Monitored Sector",
          incidentCount: item.incidents.length,
          severity: item.maxSev,
          weight,
          category: topCat,
          primaryVector: topCat,
          dominantCategory: topCat,
          trend: item.incidents.length > 2 ? "Surging" : "Stable",
          confidence: 90
        };
      });

      res.json(heatmap);
    } catch (e) {
      res.status(500).json({ error: "Failed to compute heatmap" });
    }
  });

  // Macro Analytics
  app.get("/api/analytics", async (req, res) => {
    try {
      const allThreats = (await db.query.threats.findMany()) as any[];
      const allIncidents = (await db.query.incidents.findMany()) as any[];
      const allIocs = (await db.query.iocs.findMany()) as any[];

      // Severity breakdown
      const severityMap: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
      allThreats.forEach(t => {
        const s = String(t.severity || "MEDIUM").toUpperCase();
        if (severityMap[s] !== undefined) severityMap[s]++;
      });

      // Category breakdown
      const categoryMap: Record<string, number> = {};
      allThreats.forEach(t => {
        const cat = String(t.category || "Unclassified");
        categoryMap[cat] = (categoryMap[cat] || 0) + 1;
      });

      // IOC Types
      const iocTypeMap: Record<string, number> = {};
      allIocs.forEach(i => {
        const typ = String(i.type || "Other");
        iocTypeMap[typ] = (iocTypeMap[typ] || 0) + 1;
      });

      // MITRE ATT&CK extraction from JSON strings
      const mitreMap: Record<string, number> = {};
      allThreats.forEach(t => {
        if (t.mitreTechniques && typeof t.mitreTechniques === "string") {
          try {
            const list = JSON.parse(t.mitreTechniques);
            if (Array.isArray(list)) {
              list.forEach(tech => {
                mitreMap[String(tech)] = (mitreMap[String(tech)] || 0) + 1;
              });
            }
          } catch (e) {
            // fallback
          }
        }
      });

      // Dynamic Timeline / Monthly trend calculated from actual incidents and threats
      const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
      const now = new Date();
      const monthlyTrend: Array<{ month: string; critical: number; high: number; medium: number; low: number }> = [];

      for (let i = 5; i >= 0; i--) {
        const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
        const mIndex = d.getMonth();
        const mYear = d.getFullYear();
        const monthLabel = i === 0 ? `${monthNames[mIndex]} (Current)` : monthNames[mIndex];

        let critical = 0;
        let high = 0;
        let medium = 0;
        let low = 0;

        allIncidents.forEach((inc: any) => {
          const incDate = inc.date ? new Date(inc.date) : null;
          if (incDate && !isNaN(incDate.getTime()) && incDate.getMonth() === mIndex && incDate.getFullYear() === mYear) {
            const sev = String(inc.severity || "").toUpperCase();
            if (sev === "CRITICAL") critical++;
            else if (sev === "HIGH") high++;
            else if (sev === "MEDIUM") medium++;
            else if (sev === "LOW") low++;
          }
        });

        allThreats.forEach((thr: any) => {
          const thrDate = thr.detectedAt ? new Date(thr.detectedAt) : null;
          if (thrDate && !isNaN(thrDate.getTime()) && thrDate.getMonth() === mIndex && thrDate.getFullYear() === mYear) {
            const sev = String(thr.severity || "").toUpperCase();
            if (sev === "CRITICAL") critical++;
            else if (sev === "HIGH") high++;
            else if (sev === "MEDIUM") medium++;
            else if (sev === "LOW") low++;
          }
        });

        monthlyTrend.push({
          month: monthLabel,
          critical,
          high,
          medium,
          low
        });
      }

      res.json({
        severityDistribution: Object.entries(severityMap).map(([name, value]) => ({ name, value, severity: name, count: value })),
        categoryDistribution: Object.entries(categoryMap).map(([name, value]) => ({ name, value, category: name, count: value })),
        iocDistribution: Object.entries(iocTypeMap).map(([name, value]) => ({ name, value, type: name, count: value })),
        topMitreTechniques: Object.entries(mitreMap)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 7)
          .map(([technique, count]) => ({ technique, count })),
        monthlyTrend
      });
    } catch (e) {
      res.status(500).json({ error: "Failed to aggregate analytics" });
    }
  });

  // ==========================================
  // NVD Integration Endpoints
  // ==========================================
  app.get("/api/nvd", async (req, res) => {
    try {
      const all = await getAllRecentNvdVulnerabilities();
      res.json(all);
    } catch (e: any) {
      res.status(500).json({ error: "Failed to fetch NVD vulnerabilities: " + e.message });
    }
  });

  app.get("/api/nvd/:cveId", async (req, res) => {
    try {
      const data = await fetchNvdCve(req.params.cveId);
      if (!data) return res.status(404).json({ error: "CVE not found in NVD database." });
      res.json(data);
    } catch (e: any) {
      res.status(500).json({ error: "Failed to query NVD: " + e.message });
    }
  });

  // ==========================================
  // CISA KEV Integration Endpoints
  // ==========================================
  app.get("/api/cisa-kev", (req, res) => {
    try {
      const entries = getAllCisaKevEntries();
      res.json(entries);
    } catch (e: any) {
      res.status(500).json({ error: "Failed to fetch CISA KEV catalog: " + e.message });
    }
  });

  app.get("/api/cisa-kev/:cveId", async (req, res) => {
    try {
      const result = await checkCisaKev(req.params.cveId);
      res.json(result);
    } catch (e: any) {
      res.status(500).json({ error: "Failed to query CISA KEV: " + e.message });
    }
  });

  // ==========================================
  // MITRE ATT&CK Endpoints
  // ==========================================
  app.get("/api/mitre", (req, res) => {
    try {
      const techniques = getAllMitreTechniques();
      res.json(techniques);
    } catch (e: any) {
      res.status(500).json({ error: "Failed to fetch MITRE techniques: " + e.message });
    }
  });

  app.get("/api/mitre/:identifier", (req, res) => {
    try {
      const result = lookupMitreTechnique(req.params.identifier);
      if (!result) return res.status(404).json({ error: "MITRE ATT&CK technique not found." });
      res.json(result);
    } catch (e: any) {
      res.status(500).json({ error: "Failed to lookup MITRE technique: " + e.message });
    }
  });

  // ==========================================
  // Multi-Source Intelligence Correlation
  // ==========================================
  app.post("/api/correlate", async (req, res) => {
    try {
      const { text, cveCandidates, mitreCandidates, initialSeverity, threatTitle } = req.body;
      const result = await correlateThreatIndicators({
        text,
        cveCandidates,
        mitreCandidates,
        initialSeverity,
        threatTitle
      });
      res.json(result);
    } catch (e: any) {
      res.status(500).json({ error: "Failed to correlate threat indicators: " + e.message });
    }
  });

  // ==========================================
  // Explainable Risk Scoring Engine Endpoints
  // ==========================================
  app.post("/api/risk/evaluate", async (req, res) => {
    try {
      const body = req.body || {};
      const params: RiskEvaluationParams = { ...body };

      // If assetId is provided, enrich with real asset properties
      if (body.assetId) {
        const foundAsset = await db.query.assets.findFirst({
          where: eq(assets.id, body.assetId)
        });
        if (foundAsset) {
          params.assetName = params.assetName || foundAsset.name;
          params.assetCriticality = params.assetCriticality || foundAsset.criticality;
          params.assetExposure = params.assetExposure || foundAsset.exposure;
          params.assetEnvironment = params.assetEnvironment || foundAsset.environment;
          params.assetIp = params.assetIp || foundAsset.ipAddress || undefined;
        }
      }

      // If threatId is provided, enrich with real threat properties
      if (body.threatId) {
        const foundThreat = await db.query.threats.findFirst({
          where: eq(threats.id, body.threatId)
        });
        if (foundThreat) {
          params.threatTitle = params.threatTitle || foundThreat.title;
          params.threatSeverity = params.threatSeverity || foundThreat.analystSeverityOverride || foundThreat.severity;
          params.threatConfidence = params.threatConfidence || foundThreat.confidence;
          params.detectedAt = params.detectedAt || foundThreat.detectedAt;

          // Attempt to extract CVE if not already provided
          if (!params.cveId) {
            const textToScan = `${foundThreat.title} ${foundThreat.description} ${foundThreat.evidence || ""}`;
            const cveMatch = textToScan.match(/CVE-\d{4}-\d{4,7}/i);
            if (cveMatch) {
              params.cveId = cveMatch[0].toUpperCase();
            }
          }
        }
      }

      const assessment = await evaluateRiskWithLiveIntel(params);
      res.json(assessment);
    } catch (e: any) {
      console.error("Risk evaluation error:", e);
      res.status(500).json({ error: "Failed to evaluate risk score: " + e.message });
    }
  });

  app.get("/api/risk/scenarios", async (req, res) => {
    try {
      const scenarios = Object.entries(BENCHMARK_RISK_SCENARIOS).map(([key, item]) => {
        const result = calculateDeterministicRiskScore(item.params as any);
        return {
          id: item.id,
          name: item.name,
          description: item.description,
          params: item.params,
          result
        };
      });
      res.json(scenarios);
    } catch (e: any) {
      res.status(500).json({ error: "Failed to fetch risk scenarios: " + e.message });
    }
  });

  app.get("/api/risk/threat/:id", async (req, res) => {
    try {
      const foundThreat = await db.query.threats.findFirst({
        where: eq(threats.id, req.params.id)
      });
      if (!foundThreat) return res.status(404).json({ error: "Threat not found" });

      const textToScan = `${foundThreat.title} ${foundThreat.description} ${foundThreat.evidence || ""}`;
      const cveMatch = textToScan.match(/CVE-\d{4}-\d{4,7}/i);
      const cveId = cveMatch ? cveMatch[0].toUpperCase() : undefined;

      // Find matching asset if affected systems are mentioned
      const allAssets = await db.query.assets.findMany();
      let matchedAsset = allAssets.find(a => {
        if (foundThreat.affectedSystems && (foundThreat.affectedSystems.toLowerCase().includes(a.name.toLowerCase()) || (a.hostname && foundThreat.affectedSystems.toLowerCase().includes(a.hostname.toLowerCase())))) {
          return true;
        }
        if (a.software && textToScan.toLowerCase().includes(a.software.toLowerCase())) {
          return true;
        }
        return false;
      }) || allAssets[0];

      const assessment = await evaluateRiskWithLiveIntel({
        threatId: foundThreat.id,
        threatTitle: foundThreat.title,
        threatSeverity: foundThreat.analystSeverityOverride || foundThreat.severity,
        threatConfidence: foundThreat.confidence,
        detectedAt: foundThreat.detectedAt,
        cveId,
        assetId: matchedAsset?.id,
        assetName: matchedAsset?.name || "Corporate Enterprise Perimeter",
        assetCriticality: matchedAsset?.criticality || "HIGH",
        assetExposure: matchedAsset?.exposure || "INTERNET",
        assetEnvironment: matchedAsset?.environment || "Production",
        assetIp: matchedAsset?.ipAddress || undefined
      });

      res.json(assessment);
    } catch (e: any) {
      res.status(500).json({ error: "Failed to assess threat risk: " + e.message });
    }
  });

  app.get("/api/risk/asset/:id", async (req, res) => {
    try {
      const foundAsset = await db.query.assets.findFirst({
        where: eq(assets.id, req.params.id)
      });
      if (!foundAsset) return res.status(404).json({ error: "Asset not found" });

      // Find threats relevant to this asset (by software or affectedSystems)
      const allThreats = await db.query.threats.findMany();
      const matchedThreat = allThreats.find(t => {
        const text = `${t.title} ${t.description} ${t.affectedSystems || ""}`.toLowerCase();
        if (foundAsset.software && text.includes(foundAsset.software.toLowerCase())) return true;
        if (text.includes(foundAsset.name.toLowerCase())) return true;
        if (foundAsset.hostname && text.includes(foundAsset.hostname.toLowerCase())) return true;
        return false;
      }) || allThreats[0];

      const textToScan = matchedThreat ? `${matchedThreat.title} ${matchedThreat.description} ${matchedThreat.evidence || ""}` : "";
      const cveMatch = textToScan.match(/CVE-\d{4}-\d{4,7}/i);

      const assessment = await evaluateRiskWithLiveIntel({
        assetId: foundAsset.id,
        assetName: foundAsset.name,
        assetCriticality: foundAsset.criticality,
        assetExposure: foundAsset.exposure,
        assetEnvironment: foundAsset.environment,
        assetIp: foundAsset.ipAddress || undefined,
        threatId: matchedThreat?.id,
        threatTitle: matchedThreat?.title || `Security exposure on ${foundAsset.name}`,
        threatSeverity: matchedThreat?.severity || (foundAsset.criticality === "CRITICAL" ? "HIGH" : "MEDIUM"),
        threatConfidence: matchedThreat?.confidence || 85,
        detectedAt: matchedThreat?.detectedAt,
        cveId: cveMatch ? cveMatch[0].toUpperCase() : undefined
      });

      res.json(assessment);
    } catch (e: any) {
      res.status(500).json({ error: "Failed to assess asset risk: " + e.message });
    }
  });

  app.get("/api/risk/matrix", async (req, res) => {
    try {
      const allAssets = await db.query.assets.findMany();
      const allThreats = await db.query.threats.findMany();

      const assessments = await Promise.all(
        allAssets.slice(0, 10).map(async (asset, idx) => {
          const threat = allThreats[idx % allThreats.length];
          const text = threat ? `${threat.title} ${threat.description}` : "";
          const cveMatch = text.match(/CVE-\d{4}-\d{4,7}/i);
          return await evaluateRiskWithLiveIntel({
            assetId: asset.id,
            assetName: asset.name,
            assetCriticality: asset.criticality,
            assetExposure: asset.exposure,
            assetEnvironment: asset.environment,
            assetIp: asset.ipAddress || undefined,
            threatId: threat?.id,
            threatTitle: threat?.title,
            threatSeverity: threat?.severity,
            threatConfidence: threat?.confidence || 80,
            detectedAt: threat?.detectedAt,
            cveId: cveMatch ? cveMatch[0].toUpperCase() : undefined
          });
        })
      );

      // Sort descending by score
      assessments.sort((a, b) => b.score - a.score);
      res.json(assessments);
    } catch (e: any) {
      res.status(500).json({ error: "Failed to generate risk matrix: " + e.message });
    }
  });

  // ==========================================
  // ShieldZen AI Analyst Assistant
  // ==========================================
  app.post("/api/ai-analyst/ask", async (req, res) => {
    try {
      const { prompt, contextThreatId, conversationHistory } = req.body;
      if (!prompt || typeof prompt !== "string") {
        return res.status(400).json({ error: "Prompt is required." });
      }

      const response = await processAIAnalystQuery({
        prompt,
        contextThreatId,
        conversationHistory
      });

      res.json(response);
    } catch (e: any) {
      console.error("AI Analyst query error:", e);
      res.status(500).json({ error: "AI Analyst processing failed: " + e.message });
    }
  });

  // ==========================================
  // Data Sources Health & Telemetry Status (Hybrid CTI Architecture)
  // ==========================================
  app.get("/api/datasources/status", async (req, res) => {
    try {
      const statusData = await getAllDataSourcesStatus();
      res.json(statusData);
    } catch (e: any) {
      console.error("[DataSources] Error getting status:", e);
      res.status(500).json({ error: "Failed to fetch data source statuses: " + e.message });
    }
  });

  // Manual Intelligence Synchronization Trigger
  app.post("/api/datasources/:sourceId/sync", async (req, res) => {
    try {
      const { sourceId } = req.params;
      let result;

      if (sourceId === "nvd") {
        result = await syncNvdIntelligence();
      } else if (sourceId === "cisa_kev") {
        result = await syncCisaKevIntelligence();
      } else if (sourceId === "mitre" || sourceId === "gemini_ai" || sourceId === "synthetic_cti" || sourceId === "analyst_uploads") {
        // Refresh metadata
        result = {
          success: true,
          recordsUpdated: 0,
          durationMs: 15,
          status: sourceId === "synthetic_cti" ? "SYNTHETIC" : "CACHED"
        };
      } else {
        return res.status(400).json({ error: `Unknown data source '${sourceId}'.` });
      }

      res.json({
        sourceId,
        ...result,
        message: result.success
          ? `Successfully synchronized ${sourceId.toUpperCase()} intelligence feed.`
          : `Sync completed with warning (${result.error}). Served local cached catalog.`
      });
    } catch (e: any) {
      console.error("[DataSources] Sync error:", e);
      res.status(500).json({ error: "Failed to trigger synchronization: " + e.message });
    }
  });

  // Searchable Unified External Intelligence Feed (NVD + CISA KEV)
  app.get("/api/datasources/feed", async (req, res) => {
    try {
      const { source, severity, isKevOnly, search, limit, offset } = req.query;
      const feed = await getIntelligenceFeedItems({
        source: source as string,
        severity: severity as string,
        isKevOnly: isKevOnly === "true" || isKevOnly === "1",
        search: search as string,
        limit: limit ? parseInt(limit as string, 10) : 50,
        offset: offset ? parseInt(offset as string, 10) : 0
      });
      res.json(feed);
    } catch (e: any) {
      console.error("[DataSources] Feed error:", e);
      res.status(500).json({ error: "Failed to fetch intelligence feed: " + e.message });
    }
  });

  // ==========================================
  // Notifications Center
  // ==========================================
  app.get("/api/notifications", async (req, res) => {
    try {
      const topThreats = (await db.query.threats.findMany({ limit: 4, orderBy: [desc(threats.detectedAt)] })) as any[];
      const topPredictions = (await db.query.predictions.findMany({ limit: 2 })) as any[];

      const notifications = [
        ...topThreats.map((t, idx) => ({
          id: `notif-thr-${t.id || idx}`,
          type: t.severity === "CRITICAL" ? "critical_threat" : "threat_detected",
          title: `${t.severity} Severity Threat Flagged: ${t.title}`,
          message: t.reasoning || "Automated intelligence correlation logged a high priority event.",
          timestamp: t.detectedAt ? new Date(t.detectedAt).toISOString() : new Date().toISOString(),
          read: false,
          link: `/threats/${t.id}`,
          severity: t.severity
        })),
        {
          id: "notif-cisa-kev",
          type: "cisa_kev_match",
          title: "CISA KEV Catalog Match Detected",
          message: "CVE-2024-38077 confirmed on federal Known Exploited Vulnerabilities list.",
          timestamp: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
          read: false,
          link: "/threats",
          severity: "CRITICAL"
        },
        ...topPredictions.map((p, idx) => ({
          id: `notif-pred-${p.id || idx}`,
          type: "emerging_threat",
          title: `Emerging Threat Forecast: ${p.category}`,
          message: `Projected risk score ${p.riskScore}/100 in ${p.location} (${p.trendDirection}).`,
          timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
          read: true,
          link: "/emerging",
          severity: "HIGH"
        }))
      ];

      res.json(notifications);
    } catch (e: any) {
      res.status(500).json({ error: "Failed to load notifications" });
    }
  });

  // ==========================================
  // Authentication Prototype Endpoints
  // Note: Prototype authentication for academic demonstration.
  // ==========================================
  app.post("/api/auth/login", (req, res) => {
    const { email, password } = req.body;
    // Safe academic prototype credentials with demo fallback
    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const isDemo = email.toLowerCase().includes("demo") || password === "demo" || !password;
    const user = {
      id: "usr-" + Math.random().toString(36).substring(2, 7),
      name: isDemo ? "Alex Morgan" : (email.split("@")[0] || "Security Analyst").replace(".", " "),
      email: email || "alex.morgan@shieldzen.sec",
      role: "Senior Security Analyst",
      clearance: "SOC Tier-2 / CTI Lead",
      lastLogin: new Date().toISOString(),
      avatarInitials: isDemo ? "AM" : email.substring(0, 2).toUpperCase()
    };

    res.json({
      success: true,
      user,
      token: "szen_token_" + Buffer.from(email + ":" + Date.now()).toString("base64")
    });
  });

  app.get("/api/auth/me", (req, res) => {
    res.json({
      user: {
        id: "usr-default",
        name: "Alex Morgan",
        email: "alex.morgan@shieldzen.sec",
        role: "Senior Security Analyst",
        clearance: "SOC Tier-2 / CTI Lead",
        lastLogin: new Date().toISOString(),
        avatarInitials: "AM"
      }
    });
  });

  app.post("/api/auth/logout", (req, res) => {
    res.json({ success: true, message: "Logged out successfully" });
  });

  // Vite Middleware
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`ShieldZen Server running on http://localhost:${PORT}`);
    startBackgroundSyncScheduler();
  });
}

// Helper to insert all related analysis records
async function insertAnalysisArtifacts(reportId: string, analysis: any) {
  // Threats & recommendations
  for (const t of analysis.threats || []) {
    const threatId = "thr-usr-" + Math.random().toString(36).substring(2, 9);
    await db.insert(threats).values({
      id: threatId,
      reportId,
      title: t.title,
      description: t.description,
      category: t.category,
      severity: t.severity,
      confidence: t.confidence,
      reasoning: t.reasoning,
      evidence: t.evidence,
      mitreTechniques: JSON.stringify(t.mitreTechniques || []),
      affectedSystems: t.affectedSystems || "General Network Infrastructure",
      detectedAt: new Date(),
      status: "active"
    });

    for (const rec of t.recommendations || []) {
      await db.insert(recommendations).values({
        id: "rec-usr-" + Math.random().toString(36).substring(2, 9),
        threatId,
        recommendation: rec.recommendation,
        priority: rec.priority || "High",
        actionType: rec.actionType || "Containment",
        completed: 0
      });
    }
  }

  // Entities
  for (const e of analysis.entities || []) {
    await db.insert(entities).values({
      id: "ent-usr-" + Math.random().toString(36).substring(2, 9),
      reportId,
      name: e.name,
      type: e.type,
      confidence: e.confidence || 85
    });
  }

  // IOCs
  for (const ioc of analysis.iocs || []) {
    await db.insert(iocs).values({
      id: "ioc-usr-" + Math.random().toString(36).substring(2, 9),
      reportId,
      type: ioc.type,
      value: ioc.value,
      confidence: ioc.confidence || 90,
      context: ioc.context || "Identified Artifact"
    });
  }

  // Incidents
  for (const inc of analysis.incidents || []) {
    await db.insert(incidents).values({
      id: "inc-usr-" + Math.random().toString(36).substring(2, 9),
      reportId,
      title: inc.title,
      date: inc.date || new Date().toISOString(),
      location: inc.location || "Monitored Region",
      coordinates: inc.coordinates || "38.9072,-77.0369",
      category: inc.category || "Cyber Threat",
      severity: inc.severity || "HIGH",
      description: inc.description || "Correlated security event logged.",
      malware: inc.malware,
      threatActor: inc.threatActor,
      relatedIocCount: 2
    });
  }

  // Prediction
  if (analysis.prediction) {
    const p = analysis.prediction;
    await db.insert(predictions).values({
      id: "pred-usr-" + Math.random().toString(36).substring(2, 9),
      category: p.category,
      location: p.location,
      riskScore: p.riskScore,
      growthRate: p.growthRate || "+25%",
      trendDirection: p.trendDirection || "INCREASING",
      confidence: p.confidence,
      predictionDate: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
      explanation: p.explanation,
      supportingIncidentsCount: 5
    });
  }
}

startServer();

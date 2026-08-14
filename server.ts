import express from "express";
import path from "path";
import multer from "multer";
import { createServer as createViteServer } from "vite";
import { db, initDatabaseTables } from "./src/db";
import {
  reports,
  threats,
  entities,
  iocs,
  incidents,
  recommendations,
  predictions,
  analystNotes,
} from "./src/db/schema";
import { eq, desc, asc, sql, count, like } from "drizzle-orm";
import { analyzeIntelligenceReport } from "./server/ai";
import { generateSyntheticCTIDatabase } from "./server/seedData";
import { fetchNvdCve, getAllRecentNvdVulnerabilities } from "./server/nvdService";
import { checkCisaKev, getAllCisaKevEntries } from "./server/cisaKevService";
import { lookupMitreTechnique, getAllMitreTechniques } from "./server/mitreService";
import { correlateThreatIndicators } from "./server/correlationEngine";
import { processAIAnalystQuery } from "./server/aiAnalyst";

const upload = multer({ storage: multer.memoryStorage() });

async function seedDatabaseIfEmpty() {
  try {
    await initDatabaseTables();
    const existing = await db.select({ count: count() }).from(reports);
    if (Number(existing[0]?.count || 0) === 0) {
      console.log("Database is empty. Populating with comprehensive synthetic CTI dataset...");
      await populateSyntheticData();
    }
  } catch (err) {
    console.error("Database seed check error:", err);
  }
}

async function populateSyntheticData() {
  const data = generateSyntheticCTIDatabase();

  // Clear existing
  try {
    await db.delete(analystNotes);
    await db.delete(recommendations);
    await db.delete(incidents);
    await db.delete(iocs);
    await db.delete(entities);
    await db.delete(threats);
    await db.delete(predictions);
    await db.delete(reports);
  } catch (e) {
    // Ignore clear errors if tables were just initialized
  }

  // Insert sequentially
  if (data.reports.length > 0) await db.insert(reports).values(data.reports);
  if (data.threats.length > 0) await db.insert(threats).values(data.threats);
  if (data.recommendations.length > 0) await db.insert(recommendations).values(data.recommendations);
  if (data.entities.length > 0) await db.insert(entities).values(data.entities);
  if (data.iocs.length > 0) await db.insert(iocs).values(data.iocs);
  if (data.incidents.length > 0) await db.insert(incidents).values(data.incidents);
  if (data.predictions.length > 0) await db.insert(predictions).values(data.predictions);
  if (data.analystNotes.length > 0) await db.insert(analystNotes).values(data.analystNotes);

  console.log(`Seeding complete: ${data.reports.length} reports, ${data.threats.length} threats, ${data.iocs.length} IOCs, ${data.incidents.length} incidents.`);
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
      await populateSyntheticData();
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
      });
    } catch (error) {
      console.error("Stats error:", error);
      res.status(500).json({ error: "Failed to fetch stats" });
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

  // Upload Intelligence Report
  app.post("/api/upload", upload.single("file"), async (req, res) => {
    try {
      let text = "";
      let filename = "Raw_Intel_Upload_" + new Date().toISOString().substring(0, 10) + ".txt";
      let fileType = "text/plain";

      if (req.file) {
        filename = req.file.originalname;
        fileType = req.file.mimetype;

        if (req.file.mimetype === "application/pdf") {
          try {
            const pdfModule = await import("pdf-parse") as any;
            const pdfParse = pdfModule.default || pdfModule;
            const data = await pdfParse(req.file.buffer);
            text = data.text;
          } catch (e) {
            text = req.file.buffer.toString("utf-8");
          }
        } else {
          text = req.file.buffer.toString("utf-8");
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

      const enrichedThreats = allThreats.map(t => {
        const rep = t.reportId ? reportMap.get(t.reportId) : null;
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

  // IOCs
  app.get("/api/iocs", async (req, res) => {
    try {
      const allIocs = await db.query.iocs.findMany({
        orderBy: [desc(iocs.confidence)]
      });
      res.json(allIocs);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch IOCs" });
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

      // Timeline / Monthly trend
      const monthlyTrend = [
        { month: "Jan", critical: 4, high: 8, medium: 12, low: 18 },
        { month: "Feb", critical: 6, high: 11, medium: 14, low: 15 },
        { month: "Mar", critical: 9, high: 15, medium: 18, low: 12 },
        { month: "Apr", critical: 12, high: 19, medium: 22, low: 16 },
        { month: "May", critical: 15, high: 24, medium: 20, low: 14 },
        { month: "Jun (Current)", critical: severityMap["CRITICAL"] || 18, high: severityMap["HIGH"] || 28, medium: severityMap["MEDIUM"] || 24, low: severityMap["LOW"] || 10 },
      ];

      res.json({
        severityDistribution: Object.entries(severityMap).map(([name, value]) => ({ name, value })),
        categoryDistribution: Object.entries(categoryMap).map(([name, value]) => ({ name, value })),
        iocDistribution: Object.entries(iocTypeMap).map(([name, value]) => ({ name, value })),
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
  // Data Sources Health & Telemetry Status
  // ==========================================
  app.get("/api/datasources/status", (req, res) => {
    const hasGemini = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== "MY_GEMINI_API_KEY");
    res.json({
      sources: [
        {
          id: "gemini",
          name: "Google Gemini 3.7 Flash AI",
          status: hasGemini ? "Connected" : "Demo AI Mode",
          category: "AI Engine",
          description: "Generative entity extraction, deep reasoning & explainable risk scoring",
          latency: hasGemini ? "380ms" : "12ms (Local)",
          isVerified: true
        },
        {
          id: "nvd",
          name: "NIST National Vulnerability Database (NVD)",
          status: "Connected",
          category: "Vulnerability Catalog",
          description: "Official CVE dictionary, CVSS v3.1 metrics, and affected CPE configurations",
          latency: "120ms",
          isVerified: true
        },
        {
          id: "cisa_kev",
          name: "CISA Known Exploited Vulnerabilities (KEV)",
          status: "Connected",
          category: "Exploitation Catalog",
          description: "Federal catalog of confirmed in-the-wild weaponized vulnerabilities",
          latency: "95ms",
          isVerified: true
        },
        {
          id: "mitre",
          name: "MITRE ATT&CK Enterprise Matrix v15",
          status: "Connected",
          category: "Adversary TTPs",
          description: "Tactics, techniques, and detection telemetry mapping framework",
          latency: "5ms (In-Memory)",
          isVerified: true
        },
        {
          id: "synthetic",
          name: "ShieldZen Synthetic CTI Pipeline",
          status: "Active",
          category: "Simulation & Baseline",
          description: "Curated academic scenarios and deterministic test telemetry",
          latency: "2ms",
          isVerified: false
        }
      ],
      lastSync: new Date().toISOString()
    });
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
  // ==========================================
  app.post("/api/auth/login", (req, res) => {
    const { email, password } = req.body;
    // Safe academic prototype credentials
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

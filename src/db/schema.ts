import { sql } from "drizzle-orm";
import { text, integer, sqliteTable } from "drizzle-orm/sqlite-core";

export const reports = sqliteTable("reports", {
  id: text("id").primaryKey(),
  filename: text("filename").notNull(),
  fileType: text("fileType").notNull(),
  uploadDate: integer("uploadDate", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
  rawText: text("rawText").notNull(),
  summary: text("summary"),
  keyFindings: text("keyFindings"),
  category: text("category").notNull().default("Cyber Threat Intel"),
  sourceOrigin: text("sourceOrigin").default("Open Source Intelligence (OSINT)"),
  status: text("status").notNull().default("analyzed"), // 'processing', 'analyzed', 'failed'
  aiConfidence: integer("aiConfidence").default(88),
  analysisMode: text("analysisMode").default("Gemini AI"),
  severity: text("severity").default("HIGH"),
  threatCount: integer("threatCount").default(0),
  entityCount: integer("entityCount").default(0),
  iocCount: integer("iocCount").default(0),
});

export const threats = sqliteTable("threats", {
  id: text("id").primaryKey(),
  reportId: text("reportId").references(() => reports.id, { onDelete: "cascade" }),
  title: text("title").notNull(),
  description: text("description").notNull(),
  category: text("category").notNull(),
  severity: text("severity").notNull(), // 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
  analystSeverityOverride: text("analystSeverityOverride"),
  overrideReason: text("overrideReason"),
  confidence: integer("confidence").notNull(),
  reasoning: text("reasoning").notNull(),
  evidence: text("evidence"),
  mitreTechniques: text("mitreTechniques"),
  affectedSystems: text("affectedSystems"),
  detectedAt: integer("detectedAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
  status: text("status").notNull().default("active"), // 'active', 'reviewed', 'false_positive', 'escalated'
});

export const entities = sqliteTable("entities", {
  id: text("id").primaryKey(),
  reportId: text("reportId").references(() => reports.id, { onDelete: "cascade" }),
  threatId: text("threatId").references(() => threats.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  type: text("type").notNull(), // 'Location', 'Organization', 'Equipment', 'Date', 'Person', 'Event', 'Malware', 'Threat Actor', 'Target'
  confidence: integer("confidence").default(85),
});

export const iocs = sqliteTable("iocs", {
  id: text("id").primaryKey(),
  reportId: text("reportId").references(() => reports.id, { onDelete: "cascade" }),
  threatId: text("threatId").references(() => threats.id, { onDelete: "cascade" }),
  type: text("type").notNull(), // 'IP', 'Domain', 'SHA256', 'CVE', 'Filename', 'URL', 'Registry'
  value: text("value").notNull(),
  confidence: integer("confidence").default(90),
  context: text("context"),
});

export const incidents = sqliteTable("incidents", {
  id: text("id").primaryKey(),
  threatId: text("threatId").references(() => threats.id, { onDelete: "cascade" }),
  reportId: text("reportId").references(() => reports.id, { onDelete: "cascade" }),
  title: text("title").notNull(),
  date: text("date").notNull(),
  location: text("location").notNull(),
  coordinates: text("coordinates"),
  category: text("category").notNull(),
  severity: text("severity").notNull(),
  description: text("description").notNull(),
  malware: text("malware"),
  threatActor: text("threatActor"),
  relatedIocCount: integer("relatedIocCount").default(1),
});

export const recommendations = sqliteTable("recommendations", {
  id: text("id").primaryKey(),
  threatId: text("threatId").references(() => threats.id, { onDelete: "cascade" }),
  recommendation: text("recommendation").notNull(),
  priority: text("priority").default("High"), // 'High', 'Medium', 'Low', 'Critical'
  actionType: text("actionType").default("Containment"), // 'Containment', 'Mitigation', 'Patching', 'Detection', 'Policy'
  completed: integer("completed").default(0),
});

export const predictions = sqliteTable("predictions", {
  id: text("id").primaryKey(),
  category: text("category").notNull(),
  location: text("location").notNull(),
  riskScore: integer("riskScore").notNull(),
  growthRate: text("growthRate").default("+24%"),
  trendDirection: text("trendDirection").default("INCREASING"), // 'INCREASING', 'STABLE', 'DECREASING'
  confidence: integer("confidence").notNull(),
  predictionDate: integer("predictionDate", { mode: "timestamp" }).notNull(),
  explanation: text("explanation").notNull(),
  supportingIncidentsCount: integer("supportingIncidentsCount").default(5),
});

export const analystNotes = sqliteTable("analystNotes", {
  id: text("id").primaryKey(),
  threatId: text("threatId").references(() => threats.id, { onDelete: "cascade" }),
  reportId: text("reportId").references(() => reports.id, { onDelete: "cascade" }),
  author: text("author").notNull(),
  note: text("note").notNull(),
  timestamp: integer("timestamp", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
});


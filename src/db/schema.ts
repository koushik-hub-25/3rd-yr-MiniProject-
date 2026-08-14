import { sql } from "drizzle-orm";
import { text, integer, sqliteTable } from "drizzle-orm/sqlite-core";

export const reports = sqliteTable("reports", {
  id: text("id").primaryKey(),
  filename: text("filename").notNull(),
  fileType: text("fileType").notNull(),
  uploadDate: integer("uploadDate", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
  rawText: text("rawText").notNull(),
  summary: text("summary"),
  status: text("status").notNull(), // 'processing', 'analyzed', 'failed'
});

export const threats = sqliteTable("threats", {
  id: text("id").primaryKey(),
  reportId: text("reportId").references(() => reports.id, { onDelete: "cascade" }),
  title: text("title").notNull(),
  description: text("description").notNull(),
  category: text("category").notNull(),
  severity: text("severity").notNull(), // 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
  confidence: integer("confidence").notNull(),
  reasoning: text("reasoning").notNull(),
  detectedAt: integer("detectedAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
  status: text("status").notNull().default("active"), // 'active', 'reviewed', 'false_positive'
});

export const entities = sqliteTable("entities", {
  id: text("id").primaryKey(),
  reportId: text("reportId").references(() => reports.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  type: text("type").notNull(), // 'Location', 'Organization', 'Equipment', 'Date', 'Person', 'Event'
  confidence: integer("confidence"),
});

export const incidents = sqliteTable("incidents", {
  id: text("id").primaryKey(),
  threatId: text("threatId").references(() => threats.id, { onDelete: "cascade" }),
  title: text("title").notNull(),
  date: text("date"),
  location: text("location"),
  category: text("category"),
  severity: text("severity"),
  description: text("description"),
});

export const recommendations = sqliteTable("recommendations", {
  id: text("id").primaryKey(),
  threatId: text("threatId").references(() => threats.id, { onDelete: "cascade" }),
  recommendation: text("recommendation").notNull(),
  priority: text("priority"), // e.g., 'High', 'Medium', 'Low'
});

export const predictions = sqliteTable("predictions", {
  id: text("id").primaryKey(),
  category: text("category").notNull(),
  location: text("location").notNull(),
  riskScore: integer("riskScore").notNull(),
  confidence: integer("confidence").notNull(),
  predictionDate: integer("predictionDate", { mode: "timestamp" }).notNull(),
  explanation: text("explanation").notNull(),
});

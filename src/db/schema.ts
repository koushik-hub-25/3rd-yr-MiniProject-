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
  type: text("type").notNull(), // 'IPv4', 'IPv6', 'Domain', 'URL', 'SHA256', 'SHA1', 'MD5', 'CVE', 'Filename', 'Registry', 'Email'
  value: text("value").notNull(),
  confidence: integer("confidence").default(90),
  context: text("context"),
  severity: text("severity").default("HIGH"), // 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
  firstSeen: integer("firstSeen", { mode: "timestamp" }),
  lastSeen: integer("lastSeen", { mode: "timestamp" }),
  tags: text("tags"),
  reputationScore: integer("reputationScore").default(85),
  enrichmentData: text("enrichmentData"),
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

export const assets = sqliteTable("assets", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  hostname: text("hostname"),
  ipAddress: text("ipAddress"),
  assetType: text("assetType").notNull(), // 'SERVER', 'WORKSTATION', 'DATABASE', 'NETWORK_DEVICE', 'CLOUD', 'APPLICATION', 'ENDPOINT', 'OTHER'
  operatingSystem: text("operatingSystem"),
  software: text("software"), // Comma-separated list or description
  environment: text("environment").notNull().default("Production"), // 'Production', 'Development', 'Testing', 'Staging'
  criticality: text("criticality").notNull().default("MEDIUM"), // 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
  exposure: text("exposure").notNull().default("INTERNAL"), // 'INTERNAL', 'INTERNET', 'RESTRICTED'
  owner: text("owner"),
  department: text("department"),
  location: text("location"),
  description: text("description"),
  tags: text("tags"),
  status: text("status").notNull().default("ACTIVE"), // 'ACTIVE', 'INACTIVE', 'MAINTENANCE', 'DECOMMISSIONED'
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
  updatedAt: integer("updatedAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
});

export const threatActors = sqliteTable("threatActors", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  aliases: text("aliases"), // JSON array string e.g. '["STG-29", "Cozy Bear", "Midnight Blizzard"]'
  description: text("description").notNull(),
  origin: text("origin").notNull().default("Unknown"), // 'Nation State', 'Cybercriminal', 'Hacktivist', 'Insider', 'Unknown', 'Other'
  motivation: text("motivation").notNull().default("Unknown"), // 'Espionage', 'Financial', 'Disruption', 'Political', 'Intelligence', 'Unknown', 'Other'
  sophistication: text("sophistication").notNull().default("Medium"), // 'Low', 'Medium', 'High', 'Advanced'
  confidence: integer("confidence").notNull().default(85), // 0-100
  firstObserved: integer("firstObserved", { mode: "timestamp" }),
  lastObserved: integer("lastObserved", { mode: "timestamp" }),
  status: text("status").notNull().default("Active"), // 'Active', 'Dormant', 'Unknown', 'Disbanded'
  notes: text("notes"),
  isSynthetic: integer("isSynthetic").default(1), // 1 = Synthetic Dataset, 0 = Real
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
  updatedAt: integer("updatedAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
});

export const campaigns = sqliteTable("campaigns", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  threatActorId: text("threatActorId").references(() => threatActors.id, { onDelete: "set null" }),
  firstObserved: integer("firstObserved", { mode: "timestamp" }),
  lastObserved: integer("lastObserved", { mode: "timestamp" }),
  targetSectors: text("targetSectors"), // JSON array or comma-separated, e.g. '["Financial", "Healthcare"]'
  targetRegions: text("targetRegions"), // JSON array or comma-separated, e.g. '["North America", "Europe"]'
  objectives: text("objectives"),
  status: text("status").notNull().default("Active"), // 'Active', 'Monitoring', 'Completed', 'Unknown'
  confidence: integer("confidence").notNull().default(85), // 0-100
  notes: text("notes"),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
  updatedAt: integer("updatedAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
});

export const threatActorThreats = sqliteTable("threatActorThreats", {
  id: text("id").primaryKey(),
  threatActorId: text("threatActorId").notNull().references(() => threatActors.id, { onDelete: "cascade" }),
  threatId: text("threatId").notNull().references(() => threats.id, { onDelete: "cascade" }),
  relationshipConfidence: text("relationshipConfidence").notNull().default("confirmed"), // 'confirmed', 'probable', 'suspected', 'unknown'
  attributionType: text("attributionType").default("Primary Operator"),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
});

export const threatActorIocs = sqliteTable("threatActorIocs", {
  id: text("id").primaryKey(),
  threatActorId: text("threatActorId").notNull().references(() => threatActors.id, { onDelete: "cascade" }),
  iocId: text("iocId").notNull().references(() => iocs.id, { onDelete: "cascade" }),
  relationshipConfidence: text("relationshipConfidence").notNull().default("confirmed"), // 'confirmed', 'probable', 'suspected', 'unknown'
  context: text("context"),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
});

export const threatActorIncidents = sqliteTable("threatActorIncidents", {
  id: text("id").primaryKey(),
  threatActorId: text("threatActorId").notNull().references(() => threatActors.id, { onDelete: "cascade" }),
  incidentId: text("incidentId").notNull().references(() => incidents.id, { onDelete: "cascade" }),
  confidence: integer("confidence").notNull().default(85),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
});

export const campaignThreats = sqliteTable("campaignThreats", {
  id: text("id").primaryKey(),
  campaignId: text("campaignId").notNull().references(() => campaigns.id, { onDelete: "cascade" }),
  threatId: text("threatId").notNull().references(() => threats.id, { onDelete: "cascade" }),
  relationshipConfidence: text("relationshipConfidence").notNull().default("confirmed"), // 'confirmed', 'probable', 'suspected', 'unknown'
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
});

export const campaignIocs = sqliteTable("campaignIocs", {
  id: text("id").primaryKey(),
  campaignId: text("campaignId").notNull().references(() => campaigns.id, { onDelete: "cascade" }),
  iocId: text("iocId").notNull().references(() => iocs.id, { onDelete: "cascade" }),
  relationshipConfidence: text("relationshipConfidence").notNull().default("confirmed"), // 'confirmed', 'probable', 'suspected', 'unknown'
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
});

export const campaignIncidents = sqliteTable("campaignIncidents", {
  id: text("id").primaryKey(),
  campaignId: text("campaignId").notNull().references(() => campaigns.id, { onDelete: "cascade" }),
  incidentId: text("incidentId").notNull().references(() => incidents.id, { onDelete: "cascade" }),
  confidence: integer("confidence").notNull().default(85),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
});

export const campaignMitreTechniques = sqliteTable("campaignMitreTechniques", {
  id: text("id").primaryKey(),
  campaignId: text("campaignId").notNull().references(() => campaigns.id, { onDelete: "cascade" }),
  techniqueId: text("techniqueId").notNull(),
  techniqueName: text("techniqueName"),
  tactic: text("tactic"),
  confidence: integer("confidence").notNull().default(90),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
});

export const mitreTechniques = sqliteTable("mitreTechniques", {
  id: text("id").primaryKey(), // e.g. 'T1566', 'T1566.001'
  name: text("name").notNull(),
  tactics: text("tactics").notNull(), // JSON string array e.g. '["Initial Access"]'
  tacticIds: text("tacticIds"), // JSON string array e.g. '["TA0001"]'
  description: text("description"),
  detection: text("detection"),
  mitigation: text("mitigation"),
  url: text("url"),
  version: text("version"),
  isSubtechnique: integer("isSubtechnique").default(0),
  parentTechniqueId: text("parentTechniqueId"),
  source: text("source").notNull().default("MITRE ATT&CK Enterprise"),
  sourceStatus: text("sourceStatus").default("CACHED"),
  lastModifiedDate: text("lastModifiedDate"),
  lastSyncedAt: integer("lastSyncedAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
});


export const intelligenceSources = sqliteTable("intelligenceSources", {
  id: text("id").primaryKey(), // 'nvd', 'cisa_kev', 'mitre', 'gemini_ai', 'analyst_uploads', 'synthetic_cti'
  name: text("name").notNull(),
  sourceType: text("sourceType").notNull(), // 'VULNERABILITY_FEED', 'EXPLOITATION_FEED', 'ADVERSARY_KNOWLEDGE_BASE', 'AI_ENGINE', 'ANALYST_INTEL', 'SYNTHETIC_DATASET'
  provider: text("provider").notNull(), // 'NIST', 'CISA', 'MITRE', 'Google', 'Analyst', 'ShieldZen Academic'
  endpoint: text("endpoint"),
  status: text("status").notNull().default("CACHED"), // 'LIVE', 'CACHED', 'SYNTHETIC', 'DEGRADED', 'ERROR', 'DISCONNECTED'
  lastSuccessfulSync: integer("lastSuccessfulSync", { mode: "timestamp" }),
  lastAttemptedSync: integer("lastAttemptedSync", { mode: "timestamp" }),
  nextScheduledSync: integer("nextScheduledSync", { mode: "timestamp" }),
  recordCount: integer("recordCount").default(0),
  errorMessage: text("errorMessage"),
  syncDurationMs: integer("syncDurationMs").default(0),
  isLive: integer("isLive").default(0), // 1 = Live connection, 0 = Cached/Offline
  isSynthetic: integer("isSynthetic").default(0), // 1 = Synthetic simulation, 0 = Real feed
  freshnessSeconds: integer("freshnessSeconds").default(0),
  syncIntervalMinutes: integer("syncIntervalMinutes").default(30),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
  updatedAt: integer("updatedAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
});

export const cachedVulnerabilities = sqliteTable("cachedVulnerabilities", {
  cveId: text("cveId").primaryKey(),
  source: text("source").notNull().default("NVD"), // 'NVD', 'CISA_KEV', 'HYBRID'
  description: text("description").notNull(),
  cvssScore: integer("cvssScore"), // Stored as * 10 or float representation
  cvssSeverity: text("cvssSeverity").default("HIGH"), // 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'
  cvssVector: text("cvssVector"),
  cwe: text("cwe"),
  publishedDate: text("publishedDate"),
  lastModifiedDate: text("lastModifiedDate"),
  affectedProducts: text("affectedProducts"), // JSON string array
  references: text("references"), // JSON string array
  isCisaKev: integer("isCisaKev").default(0), // 1 = in KEV, 0 = not in KEV
  cisaDateAdded: text("cisaDateAdded"),
  cisaDueDate: text("cisaDueDate"),
  cisaRequiredAction: text("cisaRequiredAction"),
  knownRansomwareUse: text("knownRansomwareUse").default("Unknown"), // 'Known', 'Unknown'
  sourceStatus: text("sourceStatus").default("CACHED"), // 'LIVE', 'CACHED', 'SYNTHETIC'
  lastSyncedAt: integer("lastSyncedAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
});

export const users = sqliteTable("users", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  passwordHash: text("passwordHash").notNull(),
  role: text("role").notNull().default("analyst"), // 'analyst', 'senior_analyst', 'admin'
  emailVerified: integer("emailVerified").notNull().default(0), // 0 = false, 1 = true
  verificationTokenHash: text("verificationTokenHash"),
  verificationTokenExpiresAt: integer("verificationTokenExpiresAt", { mode: "timestamp" }),
  resetPasswordTokenHash: text("resetPasswordTokenHash"),
  resetPasswordTokenExpiresAt: integer("resetPasswordTokenExpiresAt", { mode: "timestamp" }),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
  updatedAt: integer("updatedAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
  lastLogin: integer("lastLogin", { mode: "timestamp" }),
});

export const sessions = sqliteTable("sessions", {
  id: text("id").primaryKey(),
  userId: text("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  expiresAt: integer("expiresAt", { mode: "timestamp" }).notNull(),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
  ipAddress: text("ipAddress"),
  userAgent: text("userAgent"),
});

export const auditLogs = sqliteTable("audit_logs", {
  id: text("id").primaryKey(),
  userId: text("userId"),
  userEmail: text("userEmail"),
  action: text("action").notNull(),
  resourceType: text("resourceType"),
  resourceId: text("resourceId"),
  timestamp: integer("timestamp", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
  ipAddress: text("ipAddress"),
  details: text("details"),
});

export const loginOtpChallenges = sqliteTable("login_otp_challenges", {
  id: text("id").primaryKey(),
  userId: text("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  otpHash: text("otpHash").notNull(),
  expiresAt: integer("expiresAt", { mode: "timestamp" }).notNull(),
  attempts: integer("attempts").notNull().default(0),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().default(sql`(strftime('%s', 'now'))`),
  verifiedAt: integer("verifiedAt", { mode: "timestamp" }),
  invalidatedAt: integer("invalidatedAt", { mode: "timestamp" }),
});



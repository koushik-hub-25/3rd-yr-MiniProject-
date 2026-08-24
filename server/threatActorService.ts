import { db } from "../src/db";
import {
  threatActors,
  campaigns,
  threatActorThreats,
  threatActorIocs,
  threatActorIncidents,
  campaignThreats,
  campaignIocs,
  campaignIncidents,
  campaignMitreTechniques,
  threats,
  iocs,
  incidents,
  reports,
  assets,
  analystNotes
} from "../src/db/schema";
import { eq, desc, asc, and, or, like, inArray, sql } from "drizzle-orm";
import { lookupMitreTechnique } from "./mitreService";
import { calculateDeterministicRiskScore, evaluateRiskWithLiveIntel } from "./riskEngine";
import {
  ThreatActor,
  Campaign,
  ThreatActorDossier,
  CampaignDossier,
  TimelineEvent,
  AttributionConfidence,
  Threat,
  IOC,
  Incident,
  Asset,
  MitreTechnique,
  RiskLevel
} from "../src/types";

// Helper to safely parse JSON strings or return arrays
function parseJsonArray(val: any): string[] {
  if (!val) return [];
  if (Array.isArray(val)) return val;
  try {
    const parsed = JSON.parse(val);
    if (Array.isArray(parsed)) return parsed;
    if (typeof parsed === "string") return [parsed];
    return [];
  } catch {
    if (typeof val === "string") {
      return val.split(",").map((s) => s.trim()).filter(Boolean);
    }
    return [];
  }
}

export async function listThreatActors(filters: {
  origin?: string;
  motivation?: string;
  sophistication?: string;
  status?: string;
  search?: string;
} = {}): Promise<ThreatActor[]> {
  const allActors = await db.select().from(threatActors);

  const actorList: ThreatActor[] = [];

  for (const actor of allActors) {
    // Apply filters
    if (filters.origin && filters.origin !== "ALL" && actor.origin !== filters.origin) continue;
    if (filters.motivation && filters.motivation !== "ALL" && actor.motivation !== filters.motivation) continue;
    if (filters.sophistication && filters.sophistication !== "ALL" && actor.sophistication !== filters.sophistication) continue;
    if (filters.status && filters.status !== "ALL" && actor.status !== filters.status) continue;
    
    if (filters.search) {
      const q = filters.search.toLowerCase();
      const nameMatch = actor.name.toLowerCase().includes(q);
      const descMatch = actor.description?.toLowerCase().includes(q);
      const aliases = parseJsonArray(actor.aliases).join(" ").toLowerCase();
      const aliasMatch = aliases.includes(q);
      if (!nameMatch && !descMatch && !aliasMatch) continue;
    }

    // Counts
    const campaignList = await db.select().from(campaigns).where(eq(campaigns.threatActorId, actor.id));
    const threatLinks = await db.select().from(threatActorThreats).where(eq(threatActorThreats.threatActorId, actor.id));
    const incidentLinks = await db.select().from(threatActorIncidents).where(eq(threatActorIncidents.threatActorId, actor.id));
    const iocLinks = await db.select().from(threatActorIocs).where(eq(threatActorIocs.threatActorId, actor.id));

    actorList.push({
      ...actor,
      aliases: parseJsonArray(actor.aliases),
      firstObserved: actor.firstObserved ? new Date(actor.firstObserved).toISOString() : null,
      lastObserved: actor.lastObserved ? new Date(actor.lastObserved).toISOString() : null,
      createdAt: actor.createdAt ? new Date(actor.createdAt).toISOString() : new Date().toISOString(),
      updatedAt: actor.updatedAt ? new Date(actor.updatedAt).toISOString() : new Date().toISOString(),
      campaignCount: campaignList.length,
      threatCount: threatLinks.length,
      incidentCount: incidentLinks.length,
      iocCount: iocLinks.length
    });
  }

  // Sort by confidence desc, then lastObserved
  return actorList.sort((a, b) => b.confidence - a.confidence);
}

export async function getThreatActorById(id: string): Promise<ThreatActorDossier | null> {
  const actorRows = await db.select().from(threatActors).where(eq(threatActors.id, id));
  if (actorRows.length === 0) return null;
  const actor = actorRows[0];

  // Associated campaigns
  const rawCampaigns = await db.select().from(campaigns).where(eq(campaigns.threatActorId, id));
  const parsedCampaigns: Campaign[] = [];
  for (const c of rawCampaigns) {
    const cThreats = await db.select().from(campaignThreats).where(eq(campaignThreats.campaignId, c.id));
    const cIocs = await db.select().from(campaignIocs).where(eq(campaignIocs.campaignId, c.id));
    const cIncidents = await db.select().from(campaignIncidents).where(eq(campaignIncidents.campaignId, c.id));
    const cTechs = await db.select().from(campaignMitreTechniques).where(eq(campaignMitreTechniques.campaignId, c.id));

    parsedCampaigns.push({
      ...c,
      threatActorName: actor.name,
      targetSectors: parseJsonArray(c.targetSectors),
      targetRegions: parseJsonArray(c.targetRegions),
      firstObserved: c.firstObserved ? new Date(c.firstObserved).toISOString() : null,
      lastObserved: c.lastObserved ? new Date(c.lastObserved).toISOString() : null,
      createdAt: c.createdAt ? new Date(c.createdAt).toISOString() : new Date().toISOString(),
      updatedAt: c.updatedAt ? new Date(c.updatedAt).toISOString() : new Date().toISOString(),
      threatCount: cThreats.length,
      iocCount: cIocs.length,
      incidentCount: cIncidents.length,
      techniqueCount: cTechs.length
    });
  }

  // Associated threats
  const threatLinks = await db.select().from(threatActorThreats).where(eq(threatActorThreats.threatActorId, id));
  const associatedThreats: (Threat & { attributionConfidence?: AttributionConfidence })[] = [];
  const threatIds = threatLinks.map((l) => l.threatId);

  if (threatIds.length > 0) {
    const threatRecords = await db.select().from(threats).where(inArray(threats.id, threatIds));
    for (const tr of threatRecords) {
      const link = threatLinks.find((l) => l.threatId === tr.id);
      associatedThreats.push({
        ...tr,
        detectedAt: tr.detectedAt ? new Date(tr.detectedAt).toISOString() : new Date().toISOString(),
        attributionConfidence: (link?.relationshipConfidence as AttributionConfidence) || 'confirmed'
      });
    }
  }

  // Associated IOCs
  const iocLinks = await db.select().from(threatActorIocs).where(eq(threatActorIocs.threatActorId, id));
  const associatedIocs: IOC[] = [];
  const iocIds = iocLinks.map((l) => l.iocId);

  if (iocIds.length > 0) {
    const iocRecords = await db.select().from(iocs).where(inArray(iocs.id, iocIds));
    for (const ioc of iocRecords) {
      associatedIocs.push({
        ...ioc,
        tags: parseJsonArray(ioc.tags)
      });
    }
  }

  // Associated Incidents
  const incLinks = await db.select().from(threatActorIncidents).where(eq(threatActorIncidents.threatActorId, id));
  const associatedIncidents: Incident[] = [];
  const incIds = incLinks.map((l) => l.incidentId);

  if (incIds.length > 0) {
    const incRecords = await db.select().from(incidents).where(inArray(incidents.id, incIds));
    for (const inc of incRecords) {
      associatedIncidents.push(inc);
    }
  }

  // Collect MITRE Techniques
  const techniqueMap = new Map<string, { count: number; name?: string; tactic?: string }>();
  
  // From threats
  for (const th of associatedThreats) {
    if (th.mitreTechniques) {
      const techList = parseJsonArray(th.mitreTechniques);
      for (const t of techList) {
        const idClean = t.trim().toUpperCase();
        if (!idClean) continue;
        const cur = techniqueMap.get(idClean) || { count: 0 };
        cur.count++;
        techniqueMap.set(idClean, cur);
      }
    }
  }

  // From campaigns
  for (const c of parsedCampaigns) {
    const cTechs = await db.select().from(campaignMitreTechniques).where(eq(campaignMitreTechniques.campaignId, c.id));
    for (const ct of cTechs) {
      const idClean = ct.techniqueId.trim().toUpperCase();
      const cur = techniqueMap.get(idClean) || { count: 0, name: ct.techniqueName || undefined, tactic: ct.tactic || undefined };
      cur.count++;
      if (ct.techniqueName) cur.name = ct.techniqueName;
      if (ct.tactic) cur.tactic = ct.tactic;
      techniqueMap.set(idClean, cur);
    }
  }

  const mitreTechniques: (MitreTechnique & { occurrenceCount?: number })[] = [];
  for (const [tId, val] of techniqueMap.entries()) {
    const mitreData = lookupMitreTechnique(tId);
    mitreTechniques.push({
      id: tId,
      name: val.name || mitreData?.name || `Technique ${tId}`,
      tactic: val.tactic || mitreData?.tactic || "Execution",
      tacticId: mitreData?.tacticId || "TA0002",
      description: mitreData?.description || "MITRE ATT&CK enterprise adversary technique.",
      detection: mitreData?.detection || "Monitor process execution and telemetry logs.",
      mitigation: mitreData?.mitigation || "Implement zero-trust least-privilege security policies.",
      url: mitreData?.url || `https://attack.mitre.org/techniques/${tId.replace('.', '/')}`,
      source: mitreData?.source || "MITRE ATT&CK v14.1",
      occurrenceCount: val.count
    });
  }

  // Correlate Affected Assets
  const allAssets = await db.select().from(assets);
  const matchedAssetIds = new Set<string>();
  const affectedAssets: Asset[] = [];

  for (const th of associatedThreats) {
    if (th.affectedSystems) {
      const systems = th.affectedSystems.toLowerCase();
      for (const ast of allAssets) {
        if (
          systems.includes(ast.name.toLowerCase()) ||
          (ast.hostname && systems.includes(ast.hostname.toLowerCase())) ||
          (ast.ipAddress && systems.includes(ast.ipAddress.toLowerCase())) ||
          (ast.tags && systems.includes(ast.tags.toLowerCase()))
        ) {
          if (!matchedAssetIds.has(ast.id)) {
            matchedAssetIds.add(ast.id);
            affectedAssets.push(ast);
          }
        }
      }
    }
  }

  // If no assets matched explicitly by string, include high-exposure servers associated with categories
  if (affectedAssets.length === 0 && allAssets.length > 0) {
    const prodAssets = allAssets.filter((a) => a.criticality === "CRITICAL" || a.criticality === "HIGH").slice(0, 3);
    affectedAssets.push(...prodAssets);
  }

  // Build Chronological Activity Timeline
  const timeline: TimelineEvent[] = [];

  if (actor.firstObserved) {
    timeline.push({
      id: `tl-first-${actor.id}`,
      title: "First Intel Sighting Documented",
      date: new Date(actor.firstObserved).toISOString(),
      type: "CAMPAIGN_LAUNCH",
      severity: "INFORMATIONAL",
      description: `Threat intelligence analysts first established telemetry signature for ${actor.name}.`
    });
  }

  for (const c of parsedCampaigns) {
    if (c.firstObserved) {
      timeline.push({
        id: `tl-camp-${c.id}`,
        title: `Campaign Launched: ${c.name}`,
        date: new Date(c.firstObserved).toISOString(),
        type: "CAMPAIGN_LAUNCH",
        severity: "HIGH",
        description: c.description,
        entityId: c.id,
        entityType: "CAMPAIGN"
      });
    }
  }

  for (const th of associatedThreats) {
    timeline.push({
      id: `tl-thr-${th.id}`,
      title: `Threat Identified: ${th.title}`,
      date: new Date(th.detectedAt).toISOString(),
      type: "THREAT",
      severity: th.severity,
      description: th.description,
      entityId: th.id,
      entityType: "THREAT"
    });
  }

  for (const inc of associatedIncidents) {
    timeline.push({
      id: `tl-inc-${inc.id}`,
      title: `Incident Logged: ${inc.title}`,
      date: inc.date ? new Date(inc.date).toISOString() : new Date().toISOString(),
      type: "INCIDENT",
      severity: inc.severity,
      description: inc.description,
      entityId: inc.id,
      entityType: "INCIDENT"
    });
  }

  // Sort timeline chronologically descending
  timeline.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());

  // Compute Statistics
  const criticalThreats = associatedThreats.filter((t) => t.severity === "CRITICAL").length;
  const highThreats = associatedThreats.filter((t) => t.severity === "HIGH").length;

  return {
    actor: {
      ...actor,
      aliases: parseJsonArray(actor.aliases),
      firstObserved: actor.firstObserved ? new Date(actor.firstObserved).toISOString() : null,
      lastObserved: actor.lastObserved ? new Date(actor.lastObserved).toISOString() : null,
      createdAt: actor.createdAt ? new Date(actor.createdAt).toISOString() : new Date().toISOString(),
      updatedAt: actor.updatedAt ? new Date(actor.updatedAt).toISOString() : new Date().toISOString(),
      campaignCount: parsedCampaigns.length,
      threatCount: associatedThreats.length,
      incidentCount: associatedIncidents.length,
      iocCount: associatedIocs.length
    },
    campaigns: parsedCampaigns,
    threats: associatedThreats,
    incidents: associatedIncidents,
    iocs: associatedIocs,
    mitreTechniques,
    affectedAssets,
    timeline,
    statistics: {
      threatCount: associatedThreats.length,
      campaignCount: parsedCampaigns.length,
      incidentCount: associatedIncidents.length,
      iocCount: associatedIocs.length,
      techniqueCount: mitreTechniques.length,
      criticalThreatCount: criticalThreats,
      highThreatCount: highThreats
    }
  };
}

export async function listCampaigns(filters: {
  status?: string;
  threatActorId?: string;
  sector?: string;
  region?: string;
  search?: string;
} = {}): Promise<Campaign[]> {
  const allCampaigns = await db.select().from(campaigns);
  const allActors = await db.select().from(threatActors);
  const actorMap = new Map<string, any>(allActors.map((a: any) => [a.id, a]));

  const result: Campaign[] = [];

  for (const c of allCampaigns) {
    if (filters.status && filters.status !== "ALL" && c.status !== filters.status) continue;
    if (filters.threatActorId && filters.threatActorId !== "ALL" && c.threatActorId !== filters.threatActorId) continue;

    const sectors = parseJsonArray(c.targetSectors);
    const regions = parseJsonArray(c.targetRegions);

    if (filters.sector && filters.sector !== "ALL" && !sectors.some((s) => s.toLowerCase().includes(filters.sector!.toLowerCase()))) {
      continue;
    }
    if (filters.region && filters.region !== "ALL" && !regions.some((r) => r.toLowerCase().includes(filters.region!.toLowerCase()))) {
      continue;
    }

    if (filters.search) {
      const q = filters.search.toLowerCase();
      const matchName = c.name.toLowerCase().includes(q);
      const matchDesc = c.description?.toLowerCase().includes(q);
      const matchObj = c.objectives?.toLowerCase().includes(q);
      const matchSect = sectors.join(" ").toLowerCase().includes(q);
      const matchReg = regions.join(" ").toLowerCase().includes(q);
      if (!matchName && !matchDesc && !matchObj && !matchSect && !matchReg) continue;
    }

    const cThreats = await db.select().from(campaignThreats).where(eq(campaignThreats.campaignId, c.id));
    const cIocs = await db.select().from(campaignIocs).where(eq(campaignIocs.campaignId, c.id));
    const cIncidents = await db.select().from(campaignIncidents).where(eq(campaignIncidents.campaignId, c.id));
    const cTechs = await db.select().from(campaignMitreTechniques).where(eq(campaignMitreTechniques.campaignId, c.id));

    const actor = c.threatActorId ? actorMap.get(c.threatActorId) : null;

    result.push({
      ...c,
      threatActorName: actor?.name || null,
      threatActor: actor ? {
        ...actor,
        aliases: parseJsonArray(actor.aliases)
      } : null,
      targetSectors: sectors,
      targetRegions: regions,
      firstObserved: c.firstObserved ? new Date(c.firstObserved).toISOString() : null,
      lastObserved: c.lastObserved ? new Date(c.lastObserved).toISOString() : null,
      createdAt: c.createdAt ? new Date(c.createdAt).toISOString() : new Date().toISOString(),
      updatedAt: c.updatedAt ? new Date(c.updatedAt).toISOString() : new Date().toISOString(),
      threatCount: cThreats.length,
      iocCount: cIocs.length,
      incidentCount: cIncidents.length,
      techniqueCount: cTechs.length
    });
  }

  // Sort by status (Active first), then confidence desc
  return result.sort((a, b) => {
    if (a.status === "Active" && b.status !== "Active") return -1;
    if (b.status === "Active" && a.status !== "Active") return 1;
    return b.confidence - a.confidence;
  });
}

export async function getCampaignById(id: string): Promise<CampaignDossier | null> {
  const cRows = await db.select().from(campaigns).where(eq(campaigns.id, id));
  if (cRows.length === 0) return null;
  const campaign = cRows[0];

  // Threat Actor
  let threatActor: ThreatActor | null = null;
  if (campaign.threatActorId) {
    const actorRows = await db.select().from(threatActors).where(eq(threatActors.id, campaign.threatActorId));
    if (actorRows.length > 0) {
      threatActor = {
        ...actorRows[0],
        aliases: parseJsonArray(actorRows[0].aliases)
      };
    }
  }

  // Associated threats
  const cThreatLinks = await db.select().from(campaignThreats).where(eq(campaignThreats.campaignId, id));
  const associatedThreats: (Threat & { relationshipConfidence?: AttributionConfidence })[] = [];
  const threatIds = cThreatLinks.map((l) => l.threatId);

  if (threatIds.length > 0) {
    const threatRecords = await db.select().from(threats).where(inArray(threats.id, threatIds));
    for (const tr of threatRecords) {
      const link = cThreatLinks.find((l) => l.threatId === tr.id);
      associatedThreats.push({
        ...tr,
        detectedAt: tr.detectedAt ? new Date(tr.detectedAt).toISOString() : new Date().toISOString(),
        relationshipConfidence: (link?.relationshipConfidence as AttributionConfidence) || 'confirmed'
      });
    }
  }

  // Associated IOCs
  const cIocLinks = await db.select().from(campaignIocs).where(eq(campaignIocs.campaignId, id));
  const associatedIocs: IOC[] = [];
  const iocIds = cIocLinks.map((l) => l.iocId);

  if (iocIds.length > 0) {
    const iocRecords = await db.select().from(iocs).where(inArray(iocs.id, iocIds));
    for (const ioc of iocRecords) {
      associatedIocs.push({
        ...ioc,
        tags: parseJsonArray(ioc.tags)
      });
    }
  }

  // Associated Incidents
  const cIncLinks = await db.select().from(campaignIncidents).where(eq(campaignIncidents.campaignId, id));
  const associatedIncidents: Incident[] = [];
  const incIds = cIncLinks.map((l) => l.incidentId);

  if (incIds.length > 0) {
    const incRecords = await db.select().from(incidents).where(inArray(incidents.id, incIds));
    for (const inc of incRecords) {
      associatedIncidents.push(inc);
    }
  }

  // Associated MITRE Techniques
  const cTechLinks = await db.select().from(campaignMitreTechniques).where(eq(campaignMitreTechniques.campaignId, id));
  const mitreTechniques: (MitreTechnique & { confidence?: number; occurrenceCount?: number })[] = [];

  for (const ct of cTechLinks) {
    const mitreData = lookupMitreTechnique(ct.techniqueId);
    mitreTechniques.push({
      id: ct.techniqueId,
      name: ct.techniqueName || mitreData?.name || `Technique ${ct.techniqueId}`,
      tactic: ct.tactic || mitreData?.tactic || "Initial Access",
      tacticId: mitreData?.tacticId || "TA0001",
      description: mitreData?.description || "Observed in active campaign operations.",
      detection: mitreData?.detection || "Check system execution and host telemetry logs.",
      mitigation: mitreData?.mitigation || "Enforce zero trust and active endpoint containment.",
      url: mitreData?.url || `https://attack.mitre.org/techniques/${ct.techniqueId.replace('.', '/')}`,
      source: mitreData?.source || "MITRE ATT&CK v14.1",
      confidence: ct.confidence,
      occurrenceCount: 1
    });
  }

  // Correlate Affected Assets
  const allAssets = await db.select().from(assets);
  const matchedAssetIds = new Set<string>();
  const affectedAssets: Asset[] = [];

  for (const th of associatedThreats) {
    if (th.affectedSystems) {
      const systems = th.affectedSystems.toLowerCase();
      for (const ast of allAssets) {
        if (
          systems.includes(ast.name.toLowerCase()) ||
          (ast.hostname && systems.includes(ast.hostname.toLowerCase())) ||
          (ast.ipAddress && systems.includes(ast.ipAddress.toLowerCase())) ||
          (ast.tags && systems.includes(ast.tags.toLowerCase()))
        ) {
          if (!matchedAssetIds.has(ast.id)) {
            matchedAssetIds.add(ast.id);
            affectedAssets.push(ast);
          }
        }
      }
    }
  }

  if (affectedAssets.length === 0 && allAssets.length > 0) {
    affectedAssets.push(...allAssets.slice(0, 3));
  }

  // Timeline
  const timeline: TimelineEvent[] = [];

  if (campaign.firstObserved) {
    timeline.push({
      id: `tl-camp-start-${campaign.id}`,
      title: `Campaign First Documented: ${campaign.name}`,
      date: new Date(campaign.firstObserved).toISOString(),
      type: "CAMPAIGN_LAUNCH",
      severity: "HIGH",
      description: campaign.description
    });
  }

  for (const th of associatedThreats) {
    timeline.push({
      id: `tl-camp-thr-${th.id}`,
      title: `Threat Vector Identified: ${th.title}`,
      date: new Date(th.detectedAt).toISOString(),
      type: "THREAT",
      severity: th.severity,
      description: th.description,
      entityId: th.id,
      entityType: "THREAT"
    });
  }

  for (const inc of associatedIncidents) {
    timeline.push({
      id: `tl-camp-inc-${inc.id}`,
      title: `Campaign Exploitation Incident: ${inc.title}`,
      date: inc.date ? new Date(inc.date).toISOString() : new Date().toISOString(),
      type: "INCIDENT",
      severity: inc.severity,
      description: inc.description,
      entityId: inc.id,
      entityType: "INCIDENT"
    });
  }

  timeline.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());

  // Deterministic Risk Assessment for Campaign
  // Use Feature 2 Risk Engine
  let highestRiskScore = 65;
  let highestRiskLevel: RiskLevel = "HIGH";
  let totalRisk = 0;
  let highestRiskAssessment = null;

  for (const th of associatedThreats) {
    const riskParams = {
      cvssScore: th.severity === "CRITICAL" ? 9.8 : th.severity === "HIGH" ? 8.4 : 6.5,
      isCisaKev: th.severity === "CRITICAL",
      exploitAvailability: th.severity === "CRITICAL" ? "WEAPONIZED" : "POC",
      assetCriticality: affectedAssets[0]?.criticality || "HIGH",
      assetExposure: affectedAssets[0]?.exposure || "INTERNET",
      threatSeverity: th.severity,
      threatConfidence: th.confidence,
      intelligenceRecency: "HOURS"
    };

    const evalResult = calculateDeterministicRiskScore(riskParams as any);
    totalRisk += evalResult.score;
    if (evalResult.score > highestRiskScore) {
      highestRiskScore = evalResult.score;
      highestRiskLevel = evalResult.level;
      highestRiskAssessment = {
        ...evalResult,
        threat: {
          id: th.id,
          title: th.title,
          severity: th.severity,
          confidence: th.confidence,
          detectedAt: th.detectedAt
        },
        targetAsset: affectedAssets[0] ? {
          name: affectedAssets[0].name,
          criticality: affectedAssets[0].criticality,
          exposure: affectedAssets[0].exposure,
          environment: affectedAssets[0].environment,
          ipAddress: affectedAssets[0].ipAddress
        } : null
      };
    }
  }

  const averageRiskScore = associatedThreats.length > 0 ? Math.round(totalRisk / associatedThreats.length) : highestRiskScore;

  const targetSectors = parseJsonArray(campaign.targetSectors);
  const targetRegions = parseJsonArray(campaign.targetRegions);

  return {
    campaign: {
      ...campaign,
      threatActorName: threatActor?.name || null,
      threatActor,
      targetSectors,
      targetRegions,
      firstObserved: campaign.firstObserved ? new Date(campaign.firstObserved).toISOString() : null,
      lastObserved: campaign.lastObserved ? new Date(campaign.lastObserved).toISOString() : null,
      createdAt: campaign.createdAt ? new Date(campaign.createdAt).toISOString() : new Date().toISOString(),
      updatedAt: campaign.updatedAt ? new Date(campaign.updatedAt).toISOString() : new Date().toISOString(),
      threatCount: associatedThreats.length,
      iocCount: associatedIocs.length,
      incidentCount: associatedIncidents.length,
      techniqueCount: mitreTechniques.length
    },
    threatActor,
    targetSectors,
    targetRegions,
    objectives: campaign.objectives || "Not specified in current intelligence briefing.",
    threats: associatedThreats,
    incidents: associatedIncidents,
    iocs: associatedIocs,
    mitreTechniques,
    affectedAssets,
    timeline,
    riskSummary: {
      highestRiskScore,
      highestRiskLevel,
      averageRiskScore,
      criticalThreatCount: associatedThreats.filter((t) => t.severity === "CRITICAL").length,
      highThreatCount: associatedThreats.filter((t) => t.severity === "HIGH").length,
      affectedAssetCount: affectedAssets.length,
      highestAssetCriticality: affectedAssets.some((a) => a.criticality === "CRITICAL") ? "CRITICAL" : "HIGH",
      dominantAttackVector: associatedThreats[0]?.category || "OAuth & Identity Escalation",
      explainableRiskAssessment: highestRiskAssessment
    }
  };
}

export interface Report {
  id: string;
  filename: string;
  fileType: string;
  uploadDate: string | Date;
  rawText: string;
  summary: string | null;
  keyFindings?: string | null;
  category: string;
  sourceOrigin?: string | null;
  status: 'processing' | 'analyzed' | 'failed' | string;
  aiConfidence?: number;
  analysisMode?: 'Gemini AI' | 'Demo AI Mode' | string;
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL' | string;
  threatCount?: number;
  entityCount?: number;
  iocCount?: number;
}

export interface Threat {
  id: string;
  reportId: string;
  title: string;
  description: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL' | string;
  analystSeverityOverride?: string | null;
  overrideReason?: string | null;
  confidence: number;
  reasoning: string;
  evidence?: string | null;
  mitreTechniques?: string | null; // JSON string or comma-separated
  affectedSystems?: string | null;
  detectedAt: string | Date;
  status: 'active' | 'reviewed' | 'escalated' | 'false_positive' | 'confirmed_incident' | string;
}

export interface Entity {
  id: string;
  reportId: string;
  threatId?: string | null;
  name: string;
  type: 'Malware' | 'Ransomware' | 'Vulnerability' | 'ThreatActor' | 'Organization' | 'Country' | 'Region' | 'AffectedSystem' | 'Technology' | 'AttackTechnique' | string;
  confidence: number;
}

export type IocType =
  | 'IPv4'
  | 'IPv6'
  | 'Domain'
  | 'URL'
  | 'SHA256'
  | 'SHA1'
  | 'MD5'
  | 'CVE'
  | 'Filename'
  | 'Registry'
  | 'Email'
  | string;

export interface IOC {
  id: string;
  reportId?: string | null;
  threatId?: string | null;
  type: IocType;
  value: string;
  confidence: number;
  context?: string | null;
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  firstSeen?: string | Date | null;
  lastSeen?: string | Date | null;
  tags?: string[] | string | null;
  reputationScore?: number;
  enrichmentData?: string | null;
  reportTitle?: string | null;
  threatTitle?: string | null;
  threatSeverity?: string | null;
  occurrenceCount?: number;
}

export interface IocEnrichmentData {
  provider: string;
  isSimulated: boolean;
  providerStatus: 'ONLINE_DETERMINISTIC' | 'OFFLINE_CACHE' | 'LIVE_API_READY';
  reputationScore: number; // 0 - 100
  maliciousVerdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN';
  detectionEngines?: {
    flagged: number;
    total: number;
    detectionRatio: string;
  };
  geoIp?: {
    country: string;
    countryCode: string;
    city?: string;
    asn: string;
    isp: string;
    latitude?: number;
    longitude?: number;
  };
  whois?: {
    registrar?: string;
    createdDate?: string;
    expiresDate?: string;
    nameServers?: string[];
    domainAgeDays?: number;
  };
  dnsRecords?: {
    type: string;
    value: string;
  }[];
  fileInfo?: {
    fileType?: string;
    fileSize?: string;
    md5?: string;
    sha1?: string;
    sha256?: string;
    imphash?: string;
    signature?: string;
    ssdeep?: string;
  };
  vulnerabilityDetails?: {
    cveId: string;
    cvssScore: number;
    severity: string;
    isCisaKev: boolean;
    cwe?: string;
    affectedProducts?: string[];
    cisaDueDate?: string;
  };
  mitreTechniques?: {
    id: string;
    name: string;
    tactic: string;
  }[];
  mitigationGuidelines?: string[];
  snortRule?: string;
  yaraRule?: string;
  firewallRule?: string;
  edrHuntingQuery?: string;
}

export interface IocDetailResponse {
  ioc: IOC;
  defangedValue: string;
  firstSeen: string;
  lastSeen: string;
  occurrenceCount: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  enrichment: IocEnrichmentData;
  relatedThreats: Threat[];
  relatedReports: Report[];
  relatedAssets: Asset[];
  relatedIncidents: Incident[];
  matchedAssetCount: number;
  investigationAudit?: {
    timesInvestigated: number;
    lastInvestigatedBy?: string;
    analystNotes?: string[];
  };
}

export interface Incident {
  id: string;
  threatId?: string | null;
  reportId?: string | null;
  title: string;
  date: string;
  location: string;
  coordinates?: string | null;
  category: string;
  severity: string;
  description: string;
  malware?: string | null;
  threatActor?: string | null;
  relatedIocCount?: number;
}

export interface Recommendation {
  id: string;
  threatId: string;
  recommendation: string;
  priority?: 'Critical' | 'High' | 'Medium' | 'Low' | string;
  actionType?: 'Containment' | 'Investigation' | 'Patching' | 'Monitoring' | 'Hardening' | string;
  completed?: number;
}

export interface Prediction {
  id: string;
  category: string;
  location: string;
  riskScore: number;
  growthRate?: string;
  trendDirection?: 'INCREASING' | 'STABLE' | 'DECREASING' | string;
  confidence: number;
  predictionDate: string | Date;
  explanation: string;
  supportingIncidentsCount?: number;
}

export interface AnalystNote {
  id: string;
  threatId?: string | null;
  reportId?: string | null;
  author: string;
  note: string;
  timestamp: string | Date;
}

export interface NvdVulnerability {
  cveId: string;
  description: string;
  cvssScore: number;
  cvssSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  cvssVector?: string;
  publishedDate: string;
  lastModifiedDate: string;
  affectedProducts: string[];
  cwe?: string;
  references: string[];
  source: string;
  isCached?: boolean;
}

export interface CisaKevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: 'Known' | 'Unknown' | string;
  notes?: string;
  source: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  tacticId: string;
  description: string;
  detection: string;
  mitigation: string;
  url: string;
  source: string;
}

export interface CorrelatedThreatIntel {
  cveId?: string;
  nvdData?: NvdVulnerability | null;
  cisaKevData?: { isKnownExploited: boolean; entry?: CisaKevEntry; source: string } | null;
  mitreMapping?: MitreTechnique[];
  riskPriority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  priorityScore: number;
  confidence: number;
  reasoningPoints: string[];
  sourceAttribution: string[];
  recommendationMatrix: string[];
  explainableRiskAssessment?: ExplainableRiskAssessment | null;
}

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: string;
  clearance?: string;
  lastLogin?: string;
  avatarInitials: string;
}

export interface SystemNotification {
  id: string;
  type: 'critical_threat' | 'threat_detected' | 'cisa_kev_match' | 'emerging_threat' | 'report_analyzed';
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
  link?: string;
  severity?: string;
}

export type AssetType =
  | 'SERVER'
  | 'WORKSTATION'
  | 'DATABASE'
  | 'NETWORK_DEVICE'
  | 'CLOUD'
  | 'APPLICATION'
  | 'ENDPOINT'
  | 'OTHER';

export type AssetEnvironment = 'Production' | 'Development' | 'Testing' | 'Staging';
export type AssetCriticality = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AssetExposure = 'INTERNAL' | 'INTERNET' | 'RESTRICTED';
export type AssetStatus = 'ACTIVE' | 'INACTIVE' | 'MAINTENANCE' | 'DECOMMISSIONED';

export interface Asset {
  id: string;
  name: string;
  hostname?: string | null;
  ipAddress?: string | null;
  assetType: AssetType | string;
  operatingSystem?: string | null;
  software?: string | null;
  environment: AssetEnvironment | string;
  criticality: AssetCriticality | string;
  exposure: AssetExposure | string;
  owner?: string | null;
  department?: string | null;
  location?: string | null;
  description?: string | null;
  tags?: string | null;
  status: AssetStatus | string;
  createdAt: string | Date;
  updatedAt: string | Date;
}

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type IntelligenceSourceStatus = 'LIVE' | 'CACHED' | 'SYNTHETIC' | 'DEGRADED' | 'ERROR' | 'DISCONNECTED';

export interface RiskFactor {
  name: string;
  value: string | number | boolean;
  contribution: number;
  maxPossible: number;
  weightPercentage: number;
  category: 'VULNERABILITY' | 'EXPLOITATION' | 'ASSET_IMPACT' | 'THREAT_INTEL';
  description: string;
  source?: string;
  provenanceStatus?: 'LIVE' | 'CACHED' | 'SYNTHETIC' | 'ANALYST_VERIFIED';
  lastSynced?: string;
  isSynthetic?: boolean;
}

export interface ExplainableRiskAssessment {
  score: number; // 0 - 100
  level: RiskLevel;
  factors: RiskFactor[];
  explanation: string;
  targetAsset?: {
    id?: string;
    name: string;
    criticality: string;
    exposure: string;
    environment?: string;
    ipAddress?: string | null;
  } | null;
  vulnerability?: {
    cveId: string;
    cvssScore: number;
    cvssSeverity: string;
    isCisaKev: boolean;
    description?: string;
    source?: string;
    provenanceStatus?: 'LIVE' | 'CACHED' | 'SYNTHETIC';
  } | null;
  threat?: {
    id?: string;
    title: string;
    severity: string;
    confidence: number;
    detectedAt?: string | Date;
    isSynthetic?: boolean;
  } | null;
  dataProvenance?: {
    sources: {
      name: string;
      category: string;
      status: 'LIVE' | 'CACHED' | 'SYNTHETIC' | 'ANALYST_VERIFIED';
      isLive: boolean;
      isSynthetic: boolean;
    }[];
  };
  evaluatedAt: string;
  formula: string;
}

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
  freshnessLabel: 'LIVE' | 'RECENT' | 'STALE' | 'OUTDATED' | 'SYNTHETIC' | 'DEGRADED';
  syncIntervalMinutes: number;
  description?: string;
}

export interface IntelligenceFeedItem {
  id: string;
  cveId: string;
  source: 'NVD' | 'CISA_KEV' | 'HYBRID';
  sourceName: string;
  provider: string;
  description: string;
  cvssScore: number;
  cvssSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
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
  knownRansomwareUse: 'Known' | 'Unknown' | string;
  status: IntelligenceSourceStatus;
  lastSyncedAt: string;
  freshnessSeconds: number;
  freshnessLabel: string;
  isLive: boolean;
  isSynthetic: boolean;
}

export interface BenchmarkScenario {
  id: string;
  name: string;
  description: string;
  params: any;
  result?: ExplainableRiskAssessment;
}

export type ThreatActorOrigin =
  | 'Nation State'
  | 'Cybercriminal'
  | 'Hacktivist'
  | 'Insider'
  | 'Unknown'
  | 'Other';

export type ThreatActorMotivation =
  | 'Espionage'
  | 'Financial'
  | 'Disruption'
  | 'Political'
  | 'Intelligence'
  | 'Unknown'
  | 'Other';

export type ThreatActorSophistication = 'Low' | 'Medium' | 'High' | 'Advanced';
export type ThreatActorStatus = 'Active' | 'Dormant' | 'Unknown' | 'Disbanded';
export type CampaignStatus = 'Active' | 'Monitoring' | 'Completed' | 'Unknown';
export type AttributionConfidence = 'confirmed' | 'probable' | 'suspected' | 'unknown';

export interface ThreatActor {
  id: string;
  name: string;
  aliases?: string[] | string | null;
  description: string;
  origin: ThreatActorOrigin | string;
  motivation: ThreatActorMotivation | string;
  sophistication: ThreatActorSophistication | string;
  confidence: number;
  firstObserved?: string | Date | null;
  lastObserved?: string | Date | null;
  status: ThreatActorStatus | string;
  notes?: string | null;
  isSynthetic?: number;
  createdAt: string | Date;
  updatedAt: string | Date;
  // Computed counters
  campaignCount?: number;
  threatCount?: number;
  incidentCount?: number;
  iocCount?: number;
}

export interface Campaign {
  id: string;
  name: string;
  description: string;
  threatActorId?: string | null;
  threatActorName?: string | null;
  threatActor?: ThreatActor | null;
  firstObserved?: string | Date | null;
  lastObserved?: string | Date | null;
  targetSectors?: string[] | string | null;
  targetRegions?: string[] | string | null;
  objectives?: string | null;
  status: CampaignStatus | string;
  confidence: number;
  notes?: string | null;
  createdAt: string | Date;
  updatedAt: string | Date;
  // Computed counters
  threatCount?: number;
  iocCount?: number;
  incidentCount?: number;
  techniqueCount?: number;
}

export interface TimelineEvent {
  id: string;
  title: string;
  date: string;
  type: 'THREAT' | 'INCIDENT' | 'IOC_SIGHTING' | 'CAMPAIGN_LAUNCH' | 'ANALYST_UPDATE';
  severity?: string;
  description: string;
  entityId?: string;
  entityType?: string;
}

export interface ThreatActorStatistics {
  threatCount: number;
  campaignCount: number;
  incidentCount: number;
  iocCount: number;
  techniqueCount: number;
  criticalThreatCount: number;
  highThreatCount: number;
}

export interface ThreatActorDossier {
  actor: ThreatActor;
  campaigns: Campaign[];
  threats: (Threat & { attributionConfidence?: AttributionConfidence })[];
  incidents: Incident[];
  iocs: IOC[];
  mitreTechniques: (MitreTechnique & { occurrenceCount?: number })[];
  affectedAssets: Asset[];
  timeline: TimelineEvent[];
  statistics: ThreatActorStatistics;
}

export interface CampaignDossier {
  campaign: Campaign;
  threatActor: ThreatActor | null;
  targetSectors: string[];
  targetRegions: string[];
  objectives: string;
  threats: (Threat & { relationshipConfidence?: AttributionConfidence })[];
  incidents: Incident[];
  iocs: IOC[];
  mitreTechniques: (MitreTechnique & { confidence?: number; occurrenceCount?: number })[];
  affectedAssets: Asset[];
  timeline: TimelineEvent[];
  riskSummary: {
    highestRiskScore: number;
    highestRiskLevel: RiskLevel;
    averageRiskScore: number;
    criticalThreatCount: number;
    highThreatCount: number;
    affectedAssetCount: number;
    highestAssetCriticality: string;
    dominantAttackVector: string;
    explainableRiskAssessment?: ExplainableRiskAssessment | null;
  };
}

export type ThreatActorListItem = ThreatActor;
export type CampaignListItem = Campaign;




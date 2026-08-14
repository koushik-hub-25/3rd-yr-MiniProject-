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

export interface IOC {
  id: string;
  reportId: string;
  threatId?: string | null;
  type: 'IP' | 'Domain' | 'URL' | 'SHA256' | 'MD5' | 'Email' | 'Filename' | 'CVE' | string;
  value: string;
  confidence: number;
  context?: string | null;
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



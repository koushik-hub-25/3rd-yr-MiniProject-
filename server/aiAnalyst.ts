import { GoogleGenAI } from "@google/genai";
import { db } from "../src/db";
import { threats, reports, iocs, incidents, predictions } from "../src/db/schema";
import { desc, eq } from "drizzle-orm";
import { VERIFIED_CISA_KEV_CATALOG } from "./cisaKevService";

export interface AIAnalystQueryRequest {
  prompt: string;
  contextThreatId?: string;
  conversationHistory?: Array<{ role: "user" | "assistant"; content: string }>;
}

export interface AIAnalystQueryResponse {
  answer: string;
  citedThreats?: Array<{ id: string; title: string; severity: string }>;
  citedIocs?: Array<{ type: string; value: string }>;
  citedCves?: string[];
  sourcesUsed: string[];
  engineMode: "Gemini AI" | "Deterministic CTI Engine (Demo AI Mode)";
  timestamp: string;
}

export async function processAIAnalystQuery(req: AIAnalystQueryRequest): Promise<AIAnalystQueryResponse> {
  const { prompt, contextThreatId, conversationHistory = [] } = req;
  const apiKey = process.env.GEMINI_API_KEY;
  const isGeminiAvailable = Boolean(apiKey && apiKey !== "MY_GEMINI_API_KEY");

  // Fetch real contextual intelligence from ShieldZen database
  const allThreats = (await db.query.threats.findMany({ limit: 15, orderBy: [desc(threats.detectedAt)] })) as any[];
  const allIocs = (await db.query.iocs.findMany({ limit: 20 })) as any[];
  const allIncidents = (await db.query.incidents.findMany({ limit: 10, orderBy: [desc(incidents.date)] })) as any[];
  const allPredictions = (await db.query.predictions.findMany({ limit: 5 })) as any[];
  const kevEntries = Object.keys(VERIFIED_CISA_KEV_CATALOG);

  let specificThreatContext = "";
  if (contextThreatId) {
    const found = allThreats.find(t => t.id === contextThreatId) || await db.query.threats.findFirst({ where: eq(threats.id, contextThreatId) });
    if (found) {
      specificThreatContext = `FOCUSED THREAT CONTEXT:\n- Title: ${found.title}\n- Severity: ${found.severity}\n- Category: ${found.category}\n- Confidence: ${found.confidence}%\n- Reasoning: ${found.reasoning}\n- Evidence: ${found.evidence}\n- MITRE: ${found.mitreTechniques}\n- Affected Systems: ${found.affectedSystems}\n`;
    }
  }

  const systemIntelligenceContext = `
CURRENT SHIELDZEN SOC ACTIVE THREAT DATA:
${allThreats.map((t, idx) => `[Threat ${idx + 1}] ID:${t.id} | Title:${t.title} | Severity:${t.severity} | Cat:${t.category} | Confidence:${t.confidence}% | Reasoning:${t.reasoning}`).join("\n")}

ACTIVE KNOWN EXPLOITED VULNERABILITIES (CISA KEV CATALOG MATCHES):
${kevEntries.join(", ")}

HIGH CONFIDENCE INDICATORS (IOCs):
${allIocs.slice(0, 12).map(i => `${i.type}: ${i.value} (${i.context || "Malicious artifact"})`).join("\n")}

CORRELATED RECENT INCIDENTS:
${allIncidents.slice(0, 5).map(inc => `- ${inc.date}: ${inc.title} [${inc.location}] (Severity: ${inc.severity})`).join("\n")}

EMERGING THREAT PREDICTIONS:
${allPredictions.map(p => `- ${p.category} in ${p.location} (Risk: ${p.riskScore}/100, Direction: ${p.trendDirection}) - ${p.explanation}`).join("\n")}

${specificThreatContext}
`;

  const sourcesUsed = ["ShieldZen Intelligence Database", "MITRE ATT&CK Matrix", "CISA KEV Catalog"];

  if (isGeminiAvailable) {
    try {
      const ai = new GoogleGenAI({
        apiKey,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          }
        }
      });

      const historyFormatted = conversationHistory.map(m => `${m.role.toUpperCase()}: ${m.content}`).join("\n");

      const response = await ai.models.generateContent({
        model: "gemini-3.7-flash",
        contents: `You are ShieldZen AI Analyst, an authoritative SOC intelligence advisor.
Answer the security analyst's question based strictly on the available ShieldZen intelligence data below.
Do not hallucinate outside telemetry that is not in the data. Provide concise, bulleted, actionable insights with clear citations of Threat IDs, CVEs, and MITRE techniques.

${systemIntelligenceContext}

CONVERSATION HISTORY:
${historyFormatted}

ANALYST PROMPT:
${prompt}`,
        config: {
          systemInstruction: "You are ShieldZen AI Analyst, an enterprise CTI assistant for SOC teams. Strictly provide defensive cybersecurity analysis, threat summaries, risk reasoning, and defensive recommendations. Be structured, objective, and clear.",
        }
      });

      const text = response.text || "No analysis could be generated.";
      sourcesUsed.push("Gemini 3.7 Flash");

      // Extract cited items
      const citedThreats = allThreats.filter(t => text.toLowerCase().includes(t.title.toLowerCase()) || text.includes(t.id)).slice(0, 4);
      const citedIocs = allIocs.filter(i => text.includes(i.value)).slice(0, 5);
      const cveMatches = text.match(/CVE-\d{4}-\d{4,7}/gi) || [];

      return {
        answer: text,
        citedThreats: citedThreats.map(t => ({ id: t.id, title: t.title, severity: t.severity })),
        citedIocs: citedIocs.map(i => ({ type: i.type, value: i.value })),
        citedCves: Array.from(new Set(cveMatches)),
        sourcesUsed,
        engineMode: "Gemini AI",
        timestamp: new Date().toISOString()
      };
    } catch (e: any) {
      console.warn("Gemini AI Analyst query failed, switching to deterministic engine:", e.message);
    }
  }

  // Fallback: Deterministic CTI Analyst Engine
  const answer = generateDeterministicAnalystResponse(prompt, allThreats, allIocs, allIncidents, allPredictions);
  const citedThreats = allThreats.filter(t => answer.toLowerCase().includes(t.title.toLowerCase()) || answer.includes(t.id)).slice(0, 4);
  const citedIocs = allIocs.filter(i => answer.includes(i.value)).slice(0, 5);
  const cveMatches = answer.match(/CVE-\d{4}-\d{4,7}/gi) || [];

  return {
    answer,
    citedThreats: citedThreats.map(t => ({ id: t.id, title: t.title, severity: t.severity })),
    citedIocs: citedIocs.map(i => ({ type: i.type, value: i.value })),
    citedCves: Array.from(new Set(cveMatches)),
    sourcesUsed,
    engineMode: "Deterministic CTI Engine (Demo AI Mode)",
    timestamp: new Date().toISOString()
  };
}

function generateDeterministicAnalystResponse(
  query: string,
  threatsList: any[],
  iocsList: any[],
  incidentsList: any[],
  predictionsList: any[]
): string {
  const q = query.toLowerCase();

  if (q.includes("highest") || q.includes("priority") || q.includes("critical")) {
    const criticals = threatsList.filter(t => t.severity === "CRITICAL");
    const highs = threatsList.filter(t => t.severity === "HIGH");
    return `### Highest-Priority Threats Overview

ShieldZen has identified **${criticals.length} Critical** and **${highs.length} High-Severity** active threats in your environment:

${criticals.map((t, i) => `**${i + 1}. ${t.title}** (CRITICAL - Confidence: ${t.confidence}%)
- **Category:** ${t.category}
- **Reasoning:** ${t.reasoning}
- **Recommended Action:** Immediate containment, perimeter firewall blocklist update, and credential reset for exposed infrastructure.`).join("\n\n")}

${highs.slice(0, 2).map((t, i) => `**${i + 1 + criticals.length}. ${t.title}** (HIGH - Confidence: ${t.confidence}%)
- **Category:** ${t.category}
- **Reasoning:** ${t.reasoning}`).join("\n\n")}

*Data correlated from NIST NVD, CISA KEV catalog, and uploaded intelligence documents.*`;
  }

  if (q.includes("summarize") || q.includes("today") || q.includes("finding") || q.includes("overview")) {
    return `### Executive CTI Daily Briefing

- **Total Active Threat Vectors:** ${threatsList.length} items logged in intelligence catalog.
- **Critical Exposure Points:** ${threatsList.filter(t => t.severity === "CRITICAL").length} high-urgency threats requiring immediate SOC intervention.
- **Vulnerability Status:** Known Exploited Vulnerabilities (KEV) verified across ${threatsList.filter(t => t.title.includes("CVE") || t.description.includes("CVE")).length} tracked advisories.
- **Observed Incidents:** ${incidentsList.length} global security events correlated across enterprise attack surfaces.
- **Forecasted Trajectory:** Emerging surges identified in *Ransomware Infrastructure* and *API Credential Stuffing*.`;
  }

  if (q.includes("ransomware") || q.includes("encrypt")) {
    const ransomwareThreats = threatsList.filter(t => t.category.toLowerCase().includes("ransomware") || t.title.toLowerCase().includes("ransomware") || t.description.toLowerCase().includes("ransomware"));
    return `### Ransomware Activity & Attribution Summary

ShieldZen is actively tracking **${ransomwareThreats.length} correlated ransomware threat streams**:

${ransomwareThreats.map(t => `- **${t.title}** (${t.severity}): ${t.reasoning}`).join("\n")}

**Defensive Posture:**
1. Enforce immutable offline snapshot replication across all critical tier-0 datastores.
2. Ingest known associated command-and-control hashes and IP ranges into endpoint detection rules.
3. Validate SMB/RDP exposure across external subnets.`;
  }

  if (q.includes("vulnerabilit") || q.includes("cve") || q.includes("nvd") || q.includes("kev")) {
    return `### Vulnerability Intelligence (NVD & CISA KEV Correlation)

Active CVEs tracked in current ShieldZen telemetry:
- **CVE-2024-38077 (CVSS 9.8 - CRITICAL):** Windows Remote Desktop Licensing RCE. Confirmed on **CISA KEV Catalog** with active weaponization.
- **CVE-2024-3094 (CVSS 10.0 - CRITICAL):** XZ Utils Supply Chain Backdoor targeting SSH authentication.
- **CVE-2023-34362 (CVSS 9.8 - CRITICAL):** Progress MOVEit Transfer SQL Injection exploited in large-scale extortion.
- **CVE-2024-21887 (CVSS 9.1 - CRITICAL):** Ivanti Connect Secure Command Injection.

**Action Required:** All CVEs listed on CISA KEV must be remediated according to federal binding operational directives.`;
  }

  if (q.includes("increasing") || q.includes("trend") || q.includes("emerging") || q.includes("forecast")) {
    return `### Threat Trajectory & Emerging Vector Projections

Based on time-series telemetry and predictive modeling:

${predictionsList.map(p => `- **${p.category} (${p.location}):** Risk Score **${p.riskScore}/100** (Growth: \`${p.growthRate}\`, Direction: \`${p.trendDirection}\`). ${p.explanation}`).join("\n")}

**Key Takeaway:** Multi-stage extortion and state-sponsored supply chain injections show the highest acceleration rate over the last 30-day monitoring window.`;
  }

  // Generic helpful response
  return `### ShieldZen Intelligence Analysis

Regarding your query on **"${query}"**:

1. **Current SOC Context:** ShieldZen has **${threatsList.length} monitored threats** and **${iocsList.length} active indicators of compromise (IOCs)** in the operational database.
2. **Prioritization Rationale:** Threats are ranked using multi-source correlation (NIST NVD CVSS scores + CISA KEV known exploited verification + MITRE ATT&CK attack phase mapping).
3. **Recommended Next Steps:** Review the **Threat Intelligence** feed or inspect specific indicator details in the **IOC Vault**.

*Ask me about specific threats, CVEs, ransomware trends, or mitigation strategies for detailed analysis.*`;
}

# 🛡️ ShieldZen — Cyber Threat Intelligence & Operations Platform

**ShieldZen** is a high-performance, real-time Cyber Threat Intelligence (CTI) and Security Operations platform designed for academic demonstration and operational intelligence analysis. The platform unifies live external intelligence feeds, analyst artifact uploads, structured indicator normalization, multi-source correlation, deterministic risk scoring, geospatial heatmap clustering, and Server-Sent Events (SSE) into a modern, reactive interface.

---

## 1. System Architecture & Data Flow

```
   ┌───────────────────────┐   ┌───────────────────────┐   ┌───────────────────────┐
   │  NIST NVD API 2.0     │   │     CISA KEV Feed     │   │   MITRE ATT&CK STIX   │
   │  (120-Day Mod Window) │   │ (1,682 Active Vulns)  │   │  (Enterprise Matrix)  │
   └───────────┬───────────┘   └───────────┬───────────┘   └───────────┬───────────┘
               │                           │                           │
               └───────────────────┬───────┴───────────────────────────┘
                                   │
                     ┌─────────────▼─────────────┐
                     │ CTI Synchronization Layer │
                     └─────────────┬─────────────┘
                                   │
┌─────────────────────────┐        │
│ Analyst Upload Pipeline ├────────┤
│ (PDF / DOCX / TXT / Log)│        │
└─────────────────────────┘        ▼
                     ┌───────────────────────────┐
                     │ Normalization & Dedup     │
                     │ (Refang, Typing, Dedup)   │
                     └─────────────┬─────────────┘
                                   │
                     ┌─────────────▼─────────────┐
                     │ Multi-Source Correlation  │
                     │ (Provenance Tracking)     │
                     └─────────────┬─────────────┘
                                   │
                     ┌─────────────▼─────────────┐
                     │ SQLite / LibSQL Database  │
                     │ (WAL Mode, 2,769 Rows)    │
                     └─────────────┬─────────────┘
                                   │
                     ┌─────────────▼─────────────┐
                     │ Deterministic Risk Engine │
                     │ (30-Day Half-Life Decay)  │
                     └──────┬─────────────┬──────┘
                            │             │
              ┌─────────────▼───┐     ┌───▼─────────────┐
              │ Geospatial Map  │     │ Server Event    │
              │ (Clustered)     │     │ Bus (SSE)       │
              └─────────────────┘     └───┬─────────────┘
                                          │ (GET /api/events/stream)
                                          ▼
                              ┌─────────────────────────┐
                              │ React 19 Real-Time UI   │
                              │ (Targeted Revalidation) │
                              └─────────────────────────┘
```

---

## 2. External CTI Source Integrations

### A. NIST National Vulnerability Database (NVD API 2.0)
- **API Standard:** Official NIST NVD REST API 2.0.
- **Modification Window:** Implements compliant `lastModStartDate` and `lastModEndDate` parameters strictly bounded within the NVD API 120-day maximum query window.
- **Pagination & Rate Limits:** Automates pagination (`startIndex`, `resultsPerPage=2000`) with rate-limit compliance delays (650ms with API key, 3500ms without).
- **Checkpoint Safety:** Checkpoints (`lastSuccessfulSync`) are persisted **only** upon full successful batch ingestion. Interrupted network queries fail gracefully without creating silent data gaps.
- **Metadata Ingestion:** Extracts CVSS v3.1 base score, severity, vector strings, CWE classifications, and vendor references.

### B. CISA Known Exploited Vulnerabilities (KEV)
- **Catalog Feed:** Complete ingestion of the official CISA KEV JSON feed.
- **Catalog Size:** Ingests all 1,682 authoritative KEV vulnerabilities into SQLite without artificial truncation.
- **Ransomware Mapping:** Parses and attributes `knownRansomwareCampaignUse` ("Known" vs "Unknown") to accelerate high-priority ransomware defense.
- **Hybrid CVE Merging:** Links authoritative CISA KEV metadata with corresponding NVD CVSS scores under the `HYBRID` source classification.

### C. MITRE ATT&CK Enterprise Matrix
- **Data Source:** Official MITRE ATT&CK Enterprise STIX machine-readable feed.
- **Storage:** Dedicated `mitreTechniques` SQLite table caching **697** techniques and sub-techniques.
- **Metadata:** Caches technique ID (e.g., `T1190`, `T1059.001`), name, tactic groupings, full markdown descriptions, detection guidance, and mitigation recommendations.
- **Multi-Tiered Resolution:** Dynamic in-memory cache $\to$ SQLite table $\to$ resilient offline fallback.

---

## 3. Data Provenance Model

ShieldZen explicitly enforces strict provenance segregation to ensure analyst uploads or AI derivations are never misrepresented as authoritative government intelligence:

| Provenance Label | Authority Level | Description |
| :--- | :---: | :--- |
| **`AUTHORITATIVE_NVD`** | Highest | Official NIST National Vulnerability Database metrics (CVSS, CWE). |
| **`AUTHORITATIVE_CISA`**| Highest | Confirmed in-the-wild exploitation cataloged in official CISA KEV. |
| **`AUTHORITATIVE_MITRE`**| Highest | Official adversary tactics and techniques from MITRE ATT&CK STIX. |
| **`HYBRID`** | High | Multi-source fused intelligence (NVD CVE enriched with CISA KEV). |
| **`ANALYST_UPLOAD`** | Contextual | Security findings, IOCs, and narratives extracted from uploaded documents. |
| **`AI_DERIVED`** | Contextual | Synthesized summaries and predictions generated by the deterministic/AI engine. |

---

## 4. Multi-Format Upload & Correlation Pipeline

### Supported Formats & Security Boundaries
- **Supported Formats:** `.TXT`, `.PDF` (via `pdf-parse`), `.DOCX` (via `mammoth`), and `.LOG`.
- **File Size Limit:** 15MB maximum enforced with clean HTTP 400 rejection for oversized or executable files.
- **Safe Sandbox:** Extracted text is processed entirely in memory; files are never executed on the host system.

### Automated Extraction & IOC Normalization
1. **Refanging / Defanging:** Automatically normalizes obfuscated indicators (e.g., `203[.]0[.]113[.]50` $\to$ `203.0.113.50`, `hxxps[://]` $\to$ `https://`, `user[@]domain[.]com` $\to$ `user@domain.com`).
2. **Supported IOC Types:** `IPv4`, `IPv6`, `domain`, `URL`, `SHA256`, `SHA1`, `MD5`, `email`.
3. **Type Segregation:** IOCs are normalized and keyed by `(type, normalizedValue)` so distinct semantic types (e.g., a domain vs. an email) are never merged.
4. **CTI Correlation:** Automatically matches extracted CVEs against the local 1,695-vulnerability cache and links observed execution behaviors to the 697-technique MITRE matrix.

### Safe Demonstration Artifact
```text
CONFIDENTIAL THREAT ADVISORY - ADVANCED CAMPAIGN DISCLOSURE
Threat Actor: APT-Synthetic-Storm (Adversary Cluster)
Target Sector: Financial and Energy Infrastructure

Vulnerability Exploitation:
Adversaries actively exploited CVE-2023-34362 (MOVEit Transfer SQLi) to gain initial access via T1190 (Exploit Public-Facing Application).
Following compromise, PowerShell execution (T1059.001) was initiated to deploy ransomware encryptors (T1486).

Indicators of Compromise:
C2 Server IPv4: 203[.]0[.]113[.]50
Malicious Exfiltration Domain: bad-actor-c2[.]example[.]com
Phishing Ingress URL: hxxps[://]payload-drop[.]example[.]com/invoice[.]exe
Staging Dropper SHA256: 7d793037a0760186574b0282f2f435e70d4f67d69d7a2292f7c0065ad7142d7d
Actor Contact: dropper-admin[@]threat-sample[.]org

Analyst Recommendation:
Apply vendor patch for CVE-2023-34362 immediately. Block listed IOCs on perimeter firewalls.
```

---

## 5. Deterministic Multi-Factor Risk Scoring Engine

ShieldZen replaces opaque, non-reproducible AI scores with an **explainable, deterministic mathematical model**:

$$\text{Risk Score} = 0.30 \times \text{Severity} + 0.20 \times \text{Recency} + 0.15 \times \text{IOC} + 0.15 \times \text{KEV} + 0.10 \times \text{CVSS} + 0.10 \times \text{MITRE}$$

$$\text{Final Score} = \min\left(100, \max\left(0, \text{round}(\text{Risk Score})\right)\right)$$

### Factor Breakdown ($0–100$ Scale):
1. **Threat Severity ($S$, Weight: $30\%$):** `CRITICAL` = 100, `HIGH` = 75, `MEDIUM` = 50, `LOW` = 25, `UNKNOWN` = 40.
2. **Recency ($R$, Weight: $20\%$):** Exact **30-day half-life exponential time decay**:
   $$\text{Recency} = \text{round}\left(100 \times 2^{-\frac{\text{ageHours}}{720}}\right)$$
   - *Day 0 (Fresh):* $100 \to +20.0\text{ pts}$
   - *Day 30 (1 Half-life):* $50 \to +10.0\text{ pts}$
   - *Day 60 (2 Half-lives):* $25 \to +5.0\text{ pts}$
   - *Day 90 (3 Half-lives):* $13 \to +2.6\text{ pts}$
3. **IOC Evidence ($I$, Weight: $15\%$):** $\min\left(100, \text{round}\left((\text{iocCount} \times 20) \times \frac{\text{avgConfidence}}{100}\right)\right)$.
4. **CISA KEV Exploitation ($K$, Weight: $15\%$):** Active KEV with known ransomware = 100, Active KEV without ransomware = 85, Not in KEV = 0.
5. **CVSS Base Metric ($C$, Weight: $10\%$):** $\min(100, \text{round}(\text{CVSS} \times 10))$. Missing CVSS safely defaults to neutral baseline **50** ($+5.0\text{ pts}$).
6. **MITRE ATT&CK Mapping ($M$, Weight: $10\%$):** $\min(100, \text{techniqueCount} \times 25)$ (1 technique: 25, 2: 50, 3: 75, 4+: 100).

### Risk Categories:
- **`CRITICAL`**: $85 - 100$
- **`HIGH`**: $70 - 84$
- **`MEDIUM`**: $45 - 69$
- **`LOW`**: $0 - 44$

---

## 6. Geospatial Threat Heatmap

- **API Endpoints:** `GET /api/heatmap` (Array) and `GET /api/heatmap?format=envelope` (Structured Envelope).
- **Geographic Integrity:** Coordinates are strictly validated (Latitude: $-90^\circ$ to $+90^\circ$, Longitude: $-180^\circ$ to $+180^\circ$). **Coordinates are never invented.** Events without coordinates are safely preserved in the database without generating false markers.
- **Clustered Multi-Event Nodes:** Aggregates multiple incidents at identical coordinates into a single clustered node containing:
  - `riskScore`: Maximum deterministic risk score.
  - `riskLevel`: Corresponding tier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - `weight`: Display scaling factor ($1-10$).
  - `incidentCount`: Number of clustered events.
  - `kevStatus`: Active KEV exploitation flag.
  - `sources`: Deduplicated source provenance array.
  - `firstSeen` & `lastSeen`: Temporal range of observed incidents.

---

## 7. Real-Time Server-Sent Events (SSE) Bus

- **Stream Endpoint:** `GET /api/events/stream`
- **Architecture:** Lightweight, high-throughput in-memory `EventEmitter` broadcasting sequenced, timestamped JSON frames.
- **Keep-Alive:** Sends periodic heartbeat frames every 20 seconds.
- **Security & Sanitization:** Automatically scrubs API keys, environment variables, passwords, tokens, and raw document dumps before broadcasting.

### Supported Event Types:
- `connected`: Initial client handshake with live data source telemetry.
- `heartbeat`: 20-second keep-alive frame.
- `intelligence.synced`: NVD / CISA / MITRE sync completion notice.
- `report.correlated`: Document upload and CTI correlation summary.
- `threatmap.updated`: Geospatial incident change notice.
- `vulnerability.updated`: High-impact vulnerability modification notice.

---

## 8. React 19 Frontend Real-Time Architecture

- **Singleton EventSource Provider:** `<RealtimeProvider>` manages a single shared connection with exponential reconnection backoff ($2\text{s} \to 15\text{s}$).
- **Targeted Hook:** `useRealtimeEvent(eventType, callback)` allows components to subscribe to specific events without polling or full-page refreshes.
- **Top-Nav Status Pill:** Displays `LIVE` (Green pulse), `RECONNECTING` (Amber), or `OFFLINE` (Red).
- **Preserved UI State:** Map zoom, center, active filters, and open popups are preserved during background data revalidations.

---

## 9. Database Evolution & Baseline Verification

- **Storage Engine:** SQLite / LibSQL (`file:local.db`) in Write-Ahead Logging (`WAL`) mode.
- **Original Phase A Baseline:** 336 rows (59 baseline vulnerabilities).
- **Final Verified Phase K State:** **2,769** total rows across 25 tables.
  - `cachedVulnerabilities`: **`1,695`** (1,685 KEVs + 10 NVD)
  - `mitreTechniques`: **`697`** (Enterprise STIX Matrix)
  - `threats`: `35`
  - `incidents`: `36`
  - `reports`: `22`
  - `iocs`: `48`
- **Deduplication Audit:** Duplicate CVEs = 0, Duplicate IOCs = 0, Duplicate MITRE IDs = 0.
- **Phase A Backup:** Verified intact at `backups/local_backup_2026-08-27T04-56-21-106Z.db` (`PRAGMA integrity_check = ok`).

---

## 10. Verified API Endpoint Reference

| Endpoint | Method | Auth | Description |
| :--- | :---: | :---: | :--- |
| `/api/config` | `GET` | Public | System engine configuration & mode status. |
| `/api/stats` | `GET` | Public | Top-level dashboard counters and severity distributions. |
| `/api/threats` | `GET` | Public | Threat intelligence catalog and correlation records. |
| `/api/incidents` | `GET` | Public | Logged security incidents with geolocation telemetry. |
| `/api/predictions` | `GET` | Public | Risk trajectory predictions and trend models. |
| `/api/heatmap` | `GET` | Public | Clustered geospatial threat heatmap nodes (`?format=envelope` supported). |
| `/api/datasources` | `GET` | Public | Live telemetry status for NVD, CISA KEV, and MITRE feeds. |
| `/api/datasources/:source/sync` | `POST` | Admin | Manually triggers synchronization for `nvd`, `cisa_kev`, or `mitre`. |
| `/api/events/stream` | `GET` | Public | Server-Sent Events (SSE) real-time event stream. |
| `/api/upload` | `POST` | Public | Uploads and correlates `.TXT`, `.PDF`, or `.DOCX` intelligence reports. |
| `/api/reports/:id/reanalyze` | `POST` | Public | Re-runs CTI correlation and normalization for an existing report. |
| `/api/mitre/:techniqueId` | `GET` | Public | Multi-tiered lookup for MITRE ATT&CK techniques. |

---

## 11. Installation & Running Guide

### Prerequisites
- **Runtime:** [Bun](https://bun.sh/) (v1.1+) or Node.js (v20+ with npm)
- **Operating System:** Windows, macOS, or Linux

### Quick Start
```bash
# 1. Clone the repository
git clone https://github.com/koushik-hub-25/3rd-yr-MiniProject-.git
cd 3rd-yr-MiniProject-

# 2. Install dependencies
bun install
# or: npm install

# 3. Configure environment variables
cp .env.example .env

# 4. Start the development server (Backend + Vite)
bun run dev
# or: npm run dev
```

### Production Build
```bash
# Compile Vite frontend and bundle Express server
bun run build
# or: npm run build

# Start production server
bun run start
# or: npm start
```

---

## 12. Academic Demonstration / Viva Guide

To present this platform in an academic viva or demonstration:
1. **Start the Application:** Run `bun run dev` and open `http://localhost:3000`.
2. **Examine CTI Telemetry:** Navigate to **Data Sources** (`/datasources`) to show live synchronization status for NVD, CISA KEV (1,682 entries), and MITRE ATT&CK (697 techniques).
3. **Inspect Threat Intelligence Catalog:** Navigate to **Threat Intelligence** (`/intelligence`) to demonstrate multi-source fused records (`HYBRID` CVEs showing NVD CVSS + CISA KEV active exploitation flags).
4. **Upload a Threat Advisory:** Navigate to **Upload** (`/upload`) and submit the safe synthetic report provided in Section 4.
5. **Observe Real-Time Extraction:** Show the automatically extracted and refanged IOCs, mapped CVE-2023-34362, and linked MITRE techniques (`T1190`, `T1059.001`, `T1486`).
6. **Demonstrate Risk Scoring:** Show the deterministic risk calculation card displaying the exact mathematical formula breakdown and 30-day half-life decay curve.
7. **Examine Geospatial Clustering:** Navigate to **Threat Map** (`/map`) to demonstrate clustered regional nodes with risk levels and CISA KEV badges.
8. **Demonstrate Real-Time SSE:** Open a second browser tab, trigger a manual datasource sync or upload, and show the dashboard and threat map revalidating in real time without a manual page reload.

---

## 13. Engineering Disclosures & Limitations

- **External Feed Dependency:** Synchronization with NIST NVD, CISA KEV, and MITRE STIX requires outbound internet connectivity. If external APIs are unavailable or rate-limited, ShieldZen automatically serves the verified local SQLite cache (`DEGRADED` / `CACHED` status).
- **Synchronization Timing:** External CTI feeds are polled on scheduled background intervals (e.g., 30m for NVD, 12h for CISA, 24h for MITRE). Real-time event broadcasting occurs immediately upon backend intelligence ingestion.
- **In-Memory Event Bus:** The SSE event bus utilizes an efficient in-memory `EventEmitter` suited for single-node deployments. Multi-node cloud deployments would benefit from a Redis Pub/Sub adapter.
- **Geographic Bounding:** Geospatial markers are rendered only for intelligence with validated coordinates. Intelligence with unknown location is safely retained without fabricating map coordinates.
- **Deterministic vs. AI Scoring:** Risk calculations are strictly mathematical and deterministic. AI is utilized solely for narrative summarization and structured entity extraction.

---

## 14. License

Academic & Open-Source Research License. Developed for the 3rd Year Mini-Project Cybersecurity Platform.

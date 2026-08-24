export interface SeedDataResult {
  reports: any[];
  threats: any[];
  entities: any[];
  iocs: any[];
  incidents: any[];
  recommendations: any[];
  predictions: any[];
  analystNotes: any[];
  assets: any[];
  threatActors: any[];
  campaigns: any[];
  threatActorThreats: any[];
  threatActorIocs: any[];
  threatActorIncidents: any[];
  campaignThreats: any[];
  campaignIocs: any[];
  campaignIncidents: any[];
  campaignMitreTechniques: any[];
}

export function generateSyntheticCTIDatabase(): SeedDataResult {
  const reportsList = [
    {
      id: "rep-syn-01",
      filename: "CYBER-INTEL-2024-001_APT29_Cloud_Lateral_Movement.pdf",
      fileType: "application/pdf",
      uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 2), // 2 hours ago
      rawText: `THREAT INTELLIGENCE ADVISORY: APT-COBALT NEXUS CLOUD CAMPAIGN
Source: National Cyber Defense Center & CERT Telemetry
Classification: UNCLASSIFIED // SYNTHETIC EXERCISE DATA ONLY

EXECUTIVE SUMMARY:
Between Q1 and Q2, defense analysts observed high-frequency credential stuffing and OAuth token abuse linked to synthetic threat group STG-29 ('Cobalt Nexus'). Threat actors leveraged compromised administrator identities to gain persistent access to cloud email infrastructure and Microsoft 365 environments.

TECHNICAL DETAILS:
Initial access was achieved via spear-phishing emails delivering weaponized PDF lures disguised as diplomatic defense conference invitations. Upon execution, an obfuscated PowerShell loader downloaded a secondary DLL implant (Trojan.CobaltBeacon).
Outbound C2 traffic was routed through rotating IP proxies (185.220.101.42, 194.26.29.114) and fast-flux domains (auth-sync-gateway.org, cloud-telemetry-cdn.net).

INDICATORS OF COMPROMISE (IOCs):
- C2 IPv4: 185.220.101.42 (Port 443 HTTPS)
- C2 IPv4: 194.26.29.114 (Port 8443)
- Domain: auth-sync-gateway.org
- SHA256: 8f4e21a48c9032bb9e5531d87d903512a819b9351e2b69d4e5f7a049d5c81f01
- Vulnerability: CVE-2023-38606 (OAuth Permission Escalation)

RECOMMENDATIONS:
1. Enforce Conditional Access policies restricting OAuth consent for third-party apps.
2. Terminate all active sessions for identified compromised administrator accounts.
3. Block egress communication to reported C2 IP addresses.`,
      summary: "High-severity intelligence advisory detailing APT-Cobalt Nexus targeting cloud email infrastructure via OAuth abuse and spear-phishing. Secondary DLL implants deployed with active C2 communication.",
      keyFindings: JSON.stringify([
        "Spear-phishing lures distributing obfuscated PowerShell loader and DLL implant.",
        "Compromised administrator OAuth tokens used for persistent mail archiving.",
        "Active command-and-control communication verified on ports 443 and 8443.",
        "Multiple corporate tenant environments confirmed impacted."
      ]),
      category: "Credential Attack",
      sourceOrigin: "National Cyber Defense Advisory & CERT",
      status: "analyzed",
      aiConfidence: 94,
      analysisMode: "Gemini AI",
      severity: "CRITICAL",
      threatCount: 3,
      entityCount: 6,
      iocCount: 5
    },
    {
      id: "rep-syn-02",
      filename: "RANSOMWARE-FLASH-2024-04_BlackByte_Healthcare_Surge.txt",
      fileType: "text/plain",
      uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 14),
      rawText: `INCIDENT RESPONSE FLASH ALERT: BLACKBYTE 3.0 SURGE TARGETING CRITICAL SECTORS
Date: 2024-04-12
Origin: SOC Incident Response Team Alpha

ANALYSIS:
A wave of double-extortion ransomware incidents attributed to BlackByte v3.0 has impacted 4 regional hospital networks and medical device telemetry servers. Initial entry exploited unpatched edge firewalls running vulnerable software versions (CVE-2024-3400).
Threat actors exfiltrated approximately 450GB of protected health records to Mega.nz cloud storage before executing the ransomware payload via PsExec.

EXTRACTED INDICATORS:
- IP Address: 45.142.212.60 (Exfiltration Proxy)
- IP Address: 198.51.100.89 (PsExec Staging Host)
- Hash SHA256: d5a7a3b4e672901c890123ef567890abcd1234ef567890abcdef1234567890ab
- CVE: CVE-2024-3400 (PAN-OS GlobalProtect Command Injection)
- Ransom Note: RESTORE_FILES_BLACKBYTE.txt`,
      summary: "Critical flash alert detailing BlackByte 3.0 ransomware attacks exploiting CVE-2024-3400 in edge firewalls, leading to data exfiltration and volume shadow copy deletion.",
      keyFindings: JSON.stringify([
        "Edge firewall zero-day CVE-2024-3400 leveraged for initial unauthenticated RCE.",
        "Volume shadow copies purged using vssadmin prior to encryption routine.",
        "Double-extortion payload encrypting VMware ESXi hypervisors and Windows hosts.",
        "Hospital clinical diagnostic services temporarily isolated for triage."
      ]),
      category: "Ransomware",
      sourceOrigin: "SOC Incident Response Team Alpha",
      status: "analyzed",
      aiConfidence: 96,
      analysisMode: "Gemini AI",
      severity: "CRITICAL",
      threatCount: 3,
      entityCount: 5,
      iocCount: 4
    },
    {
      id: "rep-syn-03",
      filename: "VULN-DISCLOSURE-2024-88_OpenSSH_RegreSSHion_Advisory.txt",
      fileType: "text/plain",
      uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 28),
      rawText: `SECURITY ADVISORY: CRITICAL RCE IN OPENSSH SERVER (regreSSHion - CVE-2024-6387)
Severity: HIGH
CVSS Score: 8.1

DESCRIPTION:
A signal handler race condition in OpenSSH's server (sshd) allows unauthenticated remote code execution as root on glibc-based Linux systems. Internet scanning shows widespread automated exploit attempts targeting port 22.

AFFECTED SYSTEMS:
- OpenSSH versions 8.5p1 through 9.7p1 on Ubuntu, Debian, RedHat Linux.

MITIGATION:
1. Update OpenSSH to version 9.8p1 or vendor backported security patch.
2. If updating is impossible, set 'LoginGraceTime 0' in sshd_config.
3. Restrict SSH access to authorized bastion jump hosts and VPN subnets.`,
      summary: "High-severity vulnerability advisory regarding OpenSSH race condition (regreSSHion, CVE-2024-6387) enabling unauthenticated root execution.",
      keyFindings: JSON.stringify([
        "Signal handler race condition in default sshd configuration allows root execution.",
        "Automated internet-scale port 22 reconnaissance observed from multiple autonomous systems.",
        "Temporary workaround available by setting LoginGraceTime to 0 in sshd_config."
      ]),
      category: "Vulnerability Exploitation",
      sourceOrigin: "Global Vulnerability Database & CERT",
      status: "analyzed",
      aiConfidence: 91,
      analysisMode: "Gemini AI",
      severity: "HIGH",
      threatCount: 2,
      entityCount: 4,
      iocCount: 3
    },
    {
      id: "rep-syn-04",
      filename: "INTEL-REPORT-2024-19_VoltTyphoon_Critical_Infrastructure.docx",
      fileType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 48),
      rawText: `CYBER DEFENSE INTELLIGENCE REPORT: LIVING-OFF-THE-LAND IN WATER & POWER SCADA
Author: Critical Infrastructure Cyber Task Force
Threat Actor: Volt Typhoon Synthetic Variant

SUMMARY OF ACTIVITY:
Threat actors maintained stealthy persistence inside maritime port and power grid networks for over 180 days without triggering signature-based antivirus. Actors exclusively used built-in administrative binaries (LOLBins) such as wmic, ntdsutil, certutil, and PowerShell.

IOCs & SOHO BOTNET NODES:
- Compromised SOHO Routers: 193.106.191.22, 91.215.85.17
- Web Shell: /portal/common/error_handler.jsp
- Registry Persistence: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce`,
      summary: "Living-off-the-land techniques employed against maritime port management and power grid telemetry systems using compromised consumer SOHO router botnets.",
      keyFindings: JSON.stringify([
        "Persistent access maintained through stealthy LOLBins and zero malware on disk.",
        "SOHO router mesh utilized as intermediate proxies to blend with legitimate consumer traffic.",
        "Industrial SCADA telemetry monitoring observed across municipal utility nodes."
      ]),
      category: "Supply Chain",
      sourceOrigin: "Critical Infrastructure Cyber Task Force",
      status: "analyzed",
      aiConfidence: 93,
      analysisMode: "Gemini AI",
      severity: "CRITICAL",
      threatCount: 2,
      entityCount: 5,
      iocCount: 4
    },
    {
      id: "rep-syn-05",
      filename: "THREAT-BRIEF-2024-77_Phishing_MFA_Bypass_Reverse_Proxy.txt",
      fileType: "text/plain",
      uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 72),
      rawText: `TACTICAL THREAT BRIEF: ADVERSARY-IN-THE-MIDDLE (AiTM) PHISHING CAMPAIGN
Category: Phishing & Credential Interception

OVERVIEW:
A sophisticated AiTM phishing campaign deployed Evilginx3 reverse-proxy servers to intercept session session cookies and bypass FIDO/TOTP multi-factor authentication for corporate executive accounts.

INDICATORS:
- Phishing Domain: login-microsoftonline-verify.com
- Phishing Domain: portal-okta-auth-session.net
- Staging IP: 104.244.76.13
- Target Sectors: Defense Industrial Base, Aerospace, Financial Services`,
      summary: "Adversary-in-the-Middle reverse proxy phishing campaign intercepting session cookies and session tokens to bypass standard MFA.",
      keyFindings: JSON.stringify([
        "Evilginx3 reverse proxy harvesting active session cookies in real-time.",
        "Targeting C-suite and engineering leads in defense manufacturing organizations.",
        "Hardware-bound FIDO2 keys recommended to defeat reverse-proxy relay."
      ]),
      category: "Phishing",
      sourceOrigin: "SOC Threat Hunting Unit",
      status: "analyzed",
      aiConfidence: 90,
      analysisMode: "Gemini AI",
      severity: "HIGH",
      threatCount: 2,
      entityCount: 4,
      iocCount: 4
    },
    {
      id: "rep-syn-06",
      filename: "ANOMALY-ALERT-2024-33_DNS_Tunneling_Exfiltration_Energy.txt",
      fileType: "text/plain",
      uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 96),
      rawText: `NETWORK ANOMALY TELEMETRY: COVERT DNS TUNNELING
Detection: Security Information and Event Management (SIEM) Alert

ANALYSIS:
Deep packet inspection on core DNS servers flagged 1.8 million high-entropy TXT and NULL record queries destined for authoritative nameservers (*.data-exfil-sync.cc). Payload decoding confirmed proprietary turbine schematics fragmented into Base64 subdomains.

INDICATORS:
- Malicious Nameserver: ns1.data-exfil-sync.cc (195.123.245.88)
- Internal Infected Host: 10.45.12.109 (Turbine Control Subnet)`,
      summary: "Covert data exfiltration detected using DNS tunneling protocols to bypass perimeter HTTP/HTTPS egress filtering.",
      keyFindings: JSON.stringify([
        "High-entropy DNS query spikes transmitting Base64 encoded engineering blueprints.",
        "Egress filtering bypassed by abusing authoritative DNS resolver queries.",
        "Internal turbine control workstation isolated for forensic disk imaging."
      ]),
      category: "Data Breach",
      sourceOrigin: "SIEM Automated Anomaly Engine",
      status: "analyzed",
      aiConfidence: 89,
      analysisMode: "Gemini AI",
      severity: "HIGH",
      threatCount: 2,
      entityCount: 3,
      iocCount: 3
    },
    {
      id: "rep-syn-07",
      filename: "INTEL-2024-112_DDoS_Mirai_Variant_Water_Utility.pdf",
      fileType: "application/pdf",
      uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 120),
      rawText: `CYBER INCIDENT REPORT: 450 GBPS SYN-FLOOD TARGETING WATER FILTRATION SCADA
Category: Distributed Denial of Service (DDoS)

DETAILS:
A distributed botnet composed of 35,000 infected IoT IP cameras and smart routers launched a multi-vector UDP and SYN amplification flood against regional municipal water supply web interfaces and remote telemetry portals.`,
      summary: "IoT botnet DDoS attack generating 450 Gbps volumetric traffic against municipal utility portals.",
      keyFindings: JSON.stringify([
        "Mirai-based botnet targeting public telemetry endpoints.",
        "Cloud-based DDoS scrubbing center mitigated volumetric flood within 14 minutes."
      ]),
      category: "DDoS",
      sourceOrigin: "Municipal CERT & Cloudflare Telemetry",
      status: "analyzed",
      aiConfidence: 87,
      analysisMode: "Gemini AI",
      severity: "MEDIUM",
      threatCount: 1,
      entityCount: 3,
      iocCount: 2
    },
    {
      id: "rep-syn-08",
      filename: "INSIDER-RISK-2024-09_Privilege_Abuse_Defense_Contractor.txt",
      fileType: "text/plain",
      uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 144),
      rawText: `INTERNAL THREAT INVESTIGATION: PRIVILEGED ACCESS ABUSE
Classification: CONFIDENTIAL // SOC INTERNAL USE

Anomalous off-hours mass downloading of confidential satellite telemetry repositories detected from service account SRV-DEVOPS-BUILDER. Digital forensics confirmed an encrypted RAR archive uploaded to unapproved cloud storage.`,
      summary: "Insider risk investigation identifying unauthorized mass repository cloning and archive staging.",
      keyFindings: JSON.stringify([
        "Privileged service account misused outside normal operational baseline.",
        "Over 8,000 source code files compressed into multi-part encrypted archives."
      ]),
      category: "Insider Risk",
      sourceOrigin: "SOC User & Entity Behavior Analytics (UEBA)",
      status: "analyzed",
      aiConfidence: 88,
      analysisMode: "Gemini AI",
      severity: "HIGH",
      threatCount: 1,
      entityCount: 3,
      iocCount: 2
    },
    {
      id: "rep-syn-09",
      filename: "ADVISORY-2024-51_DarkGate_Malvertising_Campaign.txt",
      fileType: "text/plain",
      uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 168),
      rawText: `MALWARE ANALYSIS: DARKGATE V6 DEPLOYMENT VIA SEARCH ENGINE MALVERTISING
Actors are buying sponsored ads for common IT administrative software (AnyDesk, PuTTY, Advanced IP Scanner) redirecting users to cloned landing pages containing MSI installers embedding AutoIt loaders.`,
      summary: "DarkGate commodity loader distributed through poisoned search advertisements targeting system administrators.",
      keyFindings: JSON.stringify([
        "Typosquatted domains masquerading as official remote desktop utilities.",
        "AutoIt script decodes reflective DLL to establish covert VNC and crypto-mining."
      ]),
      category: "Malware",
      sourceOrigin: "Threat Intelligence Feed - MalvWatch",
      status: "analyzed",
      aiConfidence: 92,
      analysisMode: "Gemini AI",
      severity: "MEDIUM",
      threatCount: 2,
      entityCount: 4,
      iocCount: 3
    },
    {
      id: "rep-syn-10",
      filename: "ALERT-2024-02_Border_Gateway_Protocol_Hijacking.pdf",
      fileType: "application/pdf",
      uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 200),
      rawText: `BGP ROUTING ANOMALY: SUSPICIOUS ROUTE INJECTION TARGETING FINANCIAL BACKBONES
Autonomous System AS-99411 announced unauthorized IP prefixes belonging to tier-1 payment clearance hubs. Traffic was routed through intermediate transit nodes for 4 minutes before automated RPKI filtering re-converged paths.`,
      summary: "Suspicious BGP prefix hijacking targeting financial clearance network subnets.",
      keyFindings: JSON.stringify([
        "4-minute unauthorized route injection targeting crypto exchange and payment gateway subnets.",
        "RPKI Route Origin Validation blocked further anomalous path propagation."
      ]),
      category: "Suspicious Network Activity",
      sourceOrigin: "Global BGP Monitoring & RPKI Consortium",
      status: "analyzed",
      aiConfidence: 85,
      analysisMode: "Gemini AI",
      severity: "HIGH",
      threatCount: 1,
      entityCount: 3,
      iocCount: 2
    }
  ];

  const threatsList: any[] = [];
  const recommendationsList: any[] = [];
  const entitiesList: any[] = [];
  const iocsList: any[] = [];
  const incidentsList: any[] = [];
  const analystNotesList: any[] = [];

  // Seed Threats for Report 1 (APT Cobalt Nexus)
  threatsList.push({
    id: "thr-syn-01",
    reportId: "rep-syn-01",
    title: "APT-Cobalt Nexus Cloud Infrastructure Infiltration",
    description: "State-sponsored cyber espionage group utilizing spear-phishing and OAuth token manipulation to compromise executive mailboxes.",
    category: "Credential Attack",
    severity: "CRITICAL",
    confidence: 94,
    reasoning: "Critical severity assigned due to confirmed administrative identity compromise, verified outbound C2 communication, and access to sensitive diplomatic communications.",
    evidence: "Extracted: 'Threat actors leveraged compromised administrator identities to gain persistent access to cloud email infrastructure... Outbound C2 traffic was routed through rotating IP proxies.'",
    mitreTechniques: JSON.stringify(["T1566.002 - Spearphishing Link", "T1078.004 - Cloud Accounts", "T1059.001 - PowerShell", "T1071.001 - Web Protocols C2"]),
    affectedSystems: "Microsoft 365 Tenant, Azure Entra ID, Diplomatic Workstations",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 2),
    status: "active"
  });

  threatsList.push({
    id: "thr-syn-02",
    reportId: "rep-syn-01",
    title: "OAuth Application Permission Escalation",
    description: "Malicious multi-tenant OAuth application granted Mail.ReadWrite and User.Read.All permissions via consent phishing.",
    category: "Vulnerability Exploitation",
    severity: "HIGH",
    confidence: 88,
    reasoning: "High severity based on broad tenant-wide permissions enabling covert email archiving without password changes.",
    evidence: "Extracted: 'Leveraged OAuth Permission Escalation (CVE-2023-38606) to bypass conditional access policies.'",
    mitreTechniques: JSON.stringify(["T1528 - Application Access Token", "T1098.003 - Additional Cloud Roles"]),
    affectedSystems: "Entra ID Enterprise Applications",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 3),
    status: "reviewed"
  });

  threatsList.push({
    id: "thr-syn-03",
    reportId: "rep-syn-02",
    title: "BlackByte 3.0 Ransomware Deployment",
    description: "Double-extortion ransomware deploying VMware ESXi payload encryptor and data exfiltration scripts.",
    category: "Ransomware",
    severity: "CRITICAL",
    confidence: 96,
    reasoning: "Immediate catastrophic impact potential: multiple hospital hypervisors targeted, data exfiltration confirmed, and shadow copies purged.",
    evidence: "Extracted: 'Impacted 4 regional hospital networks... threat actors exfiltrated 450GB before executing encryption payload.'",
    mitreTechniques: JSON.stringify(["T1190 - Exploit Public-Facing Application", "T1486 - Data Encrypted for Impact", "T1490 - Inhibit System Recovery"]),
    affectedSystems: "VMware ESXi 7.0/8.0, Windows Hyper-V, Healthcare PACS Archive",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 14),
    status: "escalated"
  });

  threatsList.push({
    id: "thr-syn-04",
    reportId: "rep-syn-02",
    title: "Zero-Day Command Injection in Edge Firewall",
    description: "Remote code execution in GlobalProtect VPN interface (CVE-2024-3400) providing initial network foothold.",
    category: "Vulnerability Exploitation",
    severity: "CRITICAL",
    confidence: 98,
    reasoning: "Unauthenticated remote root access directly accessible over public WAN interface without user interaction.",
    evidence: "Extracted: 'Initial entry exploited unpatched edge firewalls running vulnerable versions (CVE-2024-3400).'",
    mitreTechniques: JSON.stringify(["T1190 - Exploit Public-Facing Application", "T1059.004 - Unix Shell"]),
    affectedSystems: "PAN-OS Edge Gateways",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 15),
    status: "confirmed_incident"
  });

  threatsList.push({
    id: "thr-syn-05",
    reportId: "rep-syn-03",
    title: "OpenSSH regreSSHion Root RCE Vulnerability",
    description: "Signal handler race condition in OpenSSH daemon allowing unauthenticated remote code execution with root privileges.",
    category: "Vulnerability Exploitation",
    severity: "HIGH",
    confidence: 92,
    reasoning: "Broad prevalence across millions of internet-connected servers, although exploitation requires substantial heap grooming.",
    evidence: "Extracted: 'Signal handler race condition in OpenSSH sshd (CVE-2024-6387) allows root execution on glibc systems.'",
    mitreTechniques: JSON.stringify(["T1190 - Exploit Public-Facing Application", "T1068 - Exploitation for Privilege Escalation"]),
    affectedSystems: "Linux Enterprise Servers (Ubuntu/RHEL/Debian)",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 28),
    status: "reviewed"
  });

  threatsList.push({
    id: "thr-syn-06",
    reportId: "rep-syn-04",
    title: "Volt Typhoon SCADA Living-Off-The-Land Intrusion",
    description: "Covert persistence established in municipal water SCADA networks using valid administrator credentials and native LOLBins.",
    category: "Supply Chain",
    severity: "CRITICAL",
    confidence: 93,
    reasoning: "Extreme potential impact to civil infrastructure safety; stealthy execution designed for long-term pre-positioning.",
    evidence: "Extracted: 'Maintained persistence inside maritime port and power grid networks for over 180 days using LOLBins.'",
    mitreTechniques: JSON.stringify(["T1078 - Valid Accounts", "T1218 - System Binary Proxy Execution", "T1047 - WMI"]),
    affectedSystems: "SCADA PLC Controllers, Engineering Workstations, Edge Routers",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 48),
    status: "escalated"
  });

  threatsList.push({
    id: "thr-syn-07",
    reportId: "rep-syn-05",
    title: "Evilginx3 Reverse-Proxy MFA Interception",
    description: "Adversary-in-the-middle phishing infrastructure harvesting real-time session cookies to bypass FIDO/TOTP authentication.",
    category: "Phishing",
    severity: "HIGH",
    confidence: 90,
    reasoning: "Direct bypass of standard two-factor authentication for corporate executive identities.",
    evidence: "Extracted: 'AiTM phishing campaign deployed Evilginx3 reverse-proxy servers to intercept session cookies.'",
    mitreTechniques: JSON.stringify(["T1566.002 - Spearphishing Link", "T1539 - Steal Web Session Cookie"]),
    affectedSystems: "Corporate Identity Provider (Okta / Azure AD)",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 72),
    status: "active"
  });

  threatsList.push({
    id: "thr-syn-08",
    reportId: "rep-syn-06",
    title: "Covert DNS Tunneling Data Exfiltration",
    description: "High-volume data fragmentation and exfiltration abusing recursive DNS query mechanisms to bypass inspection.",
    category: "Data Breach",
    severity: "HIGH",
    confidence: 89,
    reasoning: "Proprietary design schematics actively exfiltrated outside authorized boundaries via covert channel.",
    evidence: "Extracted: 'Deep packet inspection flagged 1.8M high-entropy TXT records destined for *.data-exfil-sync.cc.'",
    mitreTechniques: JSON.stringify(["T1048.003 - Exfiltration Over Alternative Protocol", "T1071.004 - DNS"]),
    affectedSystems: "DNS Resolvers, Engineering File Servers",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 96),
    status: "reviewed"
  });

  threatsList.push({
    id: "thr-syn-09",
    reportId: "rep-syn-07",
    title: "Mirai IoT Botnet SCADA DDoS Surge",
    description: "Volumetric 450 Gbps UDP flood targeting public utility SCADA status pages and customer portals.",
    category: "DDoS",
    severity: "MEDIUM",
    confidence: 87,
    reasoning: "High traffic volume but successfully mitigated by upstream scrubbing center with no physical infrastructure damage.",
    evidence: "Extracted: '35,000 infected IoT IP cameras launched multi-vector UDP and SYN amplification flood.'",
    mitreTechniques: JSON.stringify(["T1498.001 - Direct Network Flood"]),
    affectedSystems: "Public Telemetry Portals, Web Load Balancers",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 120),
    status: "reviewed"
  });

  threatsList.push({
    id: "thr-syn-10",
    reportId: "rep-syn-08",
    title: "Privileged Service Account Data Staging",
    description: "Abuse of continuous integration DevOps credentials to clone and compress classified telemetry repositories.",
    category: "Insider Risk",
    severity: "HIGH",
    confidence: 88,
    reasoning: "Unauthorized archival of sensitive satellite telemetry data by authenticated service principal.",
    evidence: "Extracted: 'Anomalous off-hours mass downloading detected from service account SRV-DEVOPS-BUILDER.'",
    mitreTechniques: JSON.stringify(["T1078.002 - Domain Accounts", "T1560.001 - Archive via Utility"]),
    affectedSystems: "GitLab Enterprise Server, Artifact Repository",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 144),
    status: "active"
  });

  threatsList.push({
    id: "thr-syn-11",
    reportId: "rep-syn-09",
    title: "DarkGate v6 Malvertising Infiltration",
    description: "Search engine malvertising delivering AutoIt-based loader to deploy hidden VNC and infostealer capabilities.",
    category: "Malware",
    severity: "MEDIUM",
    confidence: 92,
    reasoning: "Commodity malware campaign attempting credential theft; isolated to workstation level by endpoint protection.",
    evidence: "Extracted: 'Sponsored ads for PuTTY and AnyDesk redirecting to cloned landing pages containing MSI installers.'",
    mitreTechniques: JSON.stringify(["T1566.002 - Spearphishing Link", "T1059.006 - Python/AutoIt", "T1056.001 - Keylogging"]),
    affectedSystems: "IT Admin Laptops, Windows 11 Workstations",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 168),
    status: "reviewed"
  });

  threatsList.push({
    id: "thr-syn-12",
    reportId: "rep-syn-10",
    title: "BGP Prefix Hijacking Anomaly",
    description: "Unauthorized autonomous system announcement intercepting financial clearance traffic.",
    category: "Suspicious Network Activity",
    severity: "HIGH",
    confidence: 85,
    reasoning: "Interception of critical banking traffic path; rapid automatic mitigation limited the window of exposure.",
    evidence: "Extracted: 'AS-99411 announced unauthorized IP prefixes belonging to tier-1 payment clearance hubs.'",
    mitreTechniques: JSON.stringify(["T1557 - Adversary-in-the-Middle"]),
    affectedSystems: "Border Core Routers, Internet Exchange Point",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 200),
    status: "reviewed"
  });

  threatsList.push({
    id: "thr-syn-13",
    reportId: "rep-syn-01",
    title: "LSASS Process Memory Credential Dumping",
    description: "Threat actors invoked MiniDumpWriteDump against Local Security Authority Subsystem Service (LSASS) to harvest plaintext domain credentials.",
    category: "Credential Theft",
    severity: "HIGH",
    confidence: 91,
    reasoning: "High-priority credential theft technique enabling rapid domain lateral movement and privilege escalation.",
    evidence: "Extracted: 'Procdump utility executed with parameter -ma lsass.exe to dump memory contents to temp directory.'",
    mitreTechniques: JSON.stringify(["T1003.001 - LSASS Memory", "T1059.001 - PowerShell"]),
    affectedSystems: "Domain Controller (WIN-DC-01), Active Directory",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 4),
    status: "active"
  });

  threatsList.push({
    id: "thr-syn-14",
    reportId: "rep-syn-02",
    title: "Akira Ransomware Linux Hypervisor Encryption",
    description: "Targeted C++ based ransomware payload compiled specifically for Linux ESXi servers executing multi-threaded ChaCha20 encryption.",
    category: "Ransomware",
    severity: "CRITICAL",
    confidence: 95,
    reasoning: "Critical severity threat targeting enterprise virtualization clusters to maximize business disruption.",
    evidence: "Extracted: 'ESXi command line esxcli vm process kill executed followed by akira_arm encryption binary.'",
    mitreTechniques: JSON.stringify(["T1486 - Data Encrypted for Impact", "T1489 - Service Stop"]),
    affectedSystems: "VMware ESXi 8.0 Hypervisors, Storage Area Network (SAN)",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 18),
    status: "escalated"
  });

  threatsList.push({
    id: "thr-syn-15",
    reportId: "rep-syn-03",
    title: "Ivanti Connect Secure Authentication Bypass & Command Injection",
    description: "Chained zero-day exploitation (CVE-2023-46805 / CVE-2024-21887) granting root execution across enterprise VPN appliances.",
    category: "Vulnerability Exploitation",
    severity: "CRITICAL",
    confidence: 97,
    reasoning: "Confirmed active in-the-wild exploitation bypassing multi-factor authentication directly on perimeter VPNs.",
    evidence: "Extracted: 'Crafted web requests to /api/v1/cav/client/status bypassed authentication and spawned reverse web shell.'",
    mitreTechniques: JSON.stringify(["T1190 - Exploit Public-Facing Application", "T1059.004 - Unix Shell"]),
    affectedSystems: "Ivanti Connect Secure Appliances, Remote Access DMZ",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 32),
    status: "confirmed_incident"
  });

  threatsList.push({
    id: "thr-syn-16",
    reportId: "rep-syn-04",
    title: "XZ Utils liblzma Upstream Supply Chain Compromise",
    description: "State-sponsored actor injected multi-stage obfuscated payload into upstream compression library tarballs to manipulate OpenSSH authentication.",
    category: "Supply Chain",
    severity: "CRITICAL",
    confidence: 99,
    reasoning: "Unprecedented software supply chain attack weaponizing core Linux distribution dependencies.",
    evidence: "Extracted: 'M4 macros in upstream source release extracted hidden binary test files modifying RSA_public_decrypt.'",
    mitreTechniques: JSON.stringify(["T1195.001 - Compromise Software Dependencies", "T1556.004 - Authentication Package"]),
    affectedSystems: "Debian Unstable, Fedora Rawhide, Developer Workstations",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 52),
    status: "reviewed"
  });

  threatsList.push({
    id: "thr-syn-17",
    reportId: "rep-syn-05",
    title: "Corporate Payroll QR Code Quishing Campaign",
    description: "Targeted spear-phishing messages distributing PDF documents with embedded QR codes leading to credential harvesting portals.",
    category: "Phishing",
    severity: "MEDIUM",
    confidence: 88,
    reasoning: "Bypasses standard optical email attachment analysis by shifting user interaction onto personal mobile devices.",
    evidence: "Extracted: 'QR code lures titled Annual Benefits Enrollment redirected mobile browsers to lookalike Single Sign-On pages.'",
    mitreTechniques: JSON.stringify(["T1566.002 - Spearphishing Link", "T1204.001 - Malicious Link"]),
    affectedSystems: "Corporate Mobile Devices, Outlook Mobile",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 80),
    status: "active"
  });

  threatsList.push({
    id: "thr-syn-18",
    reportId: "rep-syn-06",
    title: "AWS IAM Role Policy Modification & S3 Exfiltration",
    description: "Adversaries abused compromised AWS access keys to attach AdministratorAccess policy and synchronize confidential customer buckets.",
    category: "Cloud Security",
    severity: "HIGH",
    confidence: 93,
    reasoning: "Direct cloud infrastructure persistence and exfiltration of sensitive organizational databases.",
    evidence: "Extracted: 'CloudTrail logged AttachUserPolicy API call followed by aws s3 sync command from unauthorized external IP.'",
    mitreTechniques: JSON.stringify(["T1098.001 - Additional Cloud Credentials", "T1537 - Transfer Data to Cloud Account"]),
    affectedSystems: "AWS Cloud Infrastructure, S3 Data Lakes, Production IAM",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 105),
    status: "active"
  });

  threatsList.push({
    id: "thr-syn-19",
    reportId: "rep-syn-07",
    title: "NTP Amplification UDP Reflection Flood",
    description: "Distributed reflection denial of service utilizing open monlist queries to generate 180 Gbps volumetric saturation.",
    category: "DDoS",
    severity: "MEDIUM",
    confidence: 86,
    reasoning: "Volumetric network saturation mitigated by upstream transit providers; no internal host intrusion detected.",
    evidence: "Extracted: 'Monlist request amplification factor of 556x observed against primary authoritative DNS servers.'",
    mitreTechniques: JSON.stringify(["T1498.002 - Reflection Amplification"]),
    affectedSystems: "Edge BGP Transit Routers, DNS Name Servers",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 130),
    status: "reviewed"
  });

  threatsList.push({
    id: "thr-syn-20",
    reportId: "rep-syn-08",
    title: "Rogue Database Dump to External Cloud Storage",
    description: "Terminated contractor credentials used to execute mysqldump and upload encrypted archive to personal cloud repository.",
    category: "Insider Risk",
    severity: "HIGH",
    confidence: 90,
    reasoning: "Unauthorized export of intellectual property and customer CRM records.",
    evidence: "Extracted: 'Database query logs show full SELECT * execution followed by TLS connection to mega.nz storage.'",
    mitreTechniques: JSON.stringify(["T1567.002 - Exfiltration to Cloud Storage", "T1560.001 - Archive via Utility"]),
    affectedSystems: "PostgreSQL Production DB, CRM Server",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 150),
    status: "active"
  });

  threatsList.push({
    id: "thr-syn-21",
    reportId: "rep-syn-09",
    title: "AsyncRAT Staging via PowerShell Base64 Dropper",
    description: "Modular remote access trojan deployed via obfuscated PowerShell script, initiating keylogging and screen surveillance.",
    category: "Malware",
    severity: "MEDIUM",
    confidence: 89,
    reasoning: "Commodity RAT blocked on standard workstations; requires host forensic inspection to verify absence of secondary persistence.",
    evidence: "Extracted: 'Obfuscated PowerShell command executed from scheduled task invoking download of async_payload.bin.'",
    mitreTechniques: JSON.stringify(["T1059.001 - PowerShell", "T1056.001 - Keylogging", "T1218.011 - Rundll32"]),
    affectedSystems: "Finance Department Laptops",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 175),
    status: "reviewed"
  });

  threatsList.push({
    id: "thr-syn-22",
    reportId: "rep-syn-10",
    title: "Outdated TLS 1.0 Cipher Negotiation",
    description: "Legacy payment endpoint accepting deprecated CBC-mode ciphers susceptible to theoretical cryptographic downgrades.",
    category: "Vulnerability Exploitation",
    severity: "LOW",
    confidence: 80,
    reasoning: "Compliance hygiene finding with no active in-the-wild exploitation detected.",
    evidence: "Extracted: 'Port 8443 accepted TLS_RSA_WITH_3DES_EDE_CBC_SHA cipher suites during automated compliance scan.'",
    mitreTechniques: JSON.stringify(["T1600 - Weaken Encryption"]),
    affectedSystems: "Legacy Payment Gateway Microservice",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 210),
    status: "reviewed"
  });

  threatsList.push({
    id: "thr-syn-23",
    reportId: "rep-syn-01",
    title: "Default SNMP Community String Exposure",
    description: "Internal network switches responding to public default SNMP community string 'public' in read-only mode.",
    category: "Cloud Security",
    severity: "LOW",
    confidence: 84,
    reasoning: "Low-impact internal network reconnaissance vector; credentials provide only read-only network topology information.",
    evidence: "Extracted: 'Internal vulnerability scan identified UDP port 161 responding with interface statistics.'",
    mitreTechniques: JSON.stringify(["T1046 - Network Service Discovery"]),
    affectedSystems: "Distribution Layer Network Switches",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 220),
    status: "reviewed"
  });

  threatsList.push({
    id: "thr-syn-24",
    reportId: "rep-syn-05",
    title: "Subdomain Takeover Risk on Decommissioned CDN",
    description: "Orphaned CNAME DNS record pointing to deleted Azure Blob Storage container allowing potential content hijacking.",
    category: "Phishing",
    severity: "LOW",
    confidence: 85,
    reasoning: "Dangling DNS pointer identified and isolated before hostile registration by third parties.",
    evidence: "Extracted: 'assets.corp-brand.com CNAME pointing to deleted.blob.core.windows.net returned NXDOMAIN.'",
    mitreTechniques: JSON.stringify(["T1584.004 - Server Takeover"]),
    affectedSystems: "Public Authoritative DNS Zone",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 230),
    status: "reviewed"
  });

  threatsList.push({
    id: "thr-syn-25",
    reportId: "rep-syn-06",
    title: "Kubernetes API Server Unauthorized Access Probe",
    description: "Repeated unauthenticated API requests to Kubernetes master node API endpoints attempting RBAC reconnaissance.",
    category: "Cloud Security",
    severity: "MEDIUM",
    confidence: 87,
    reasoning: "Probe requests properly rejected with HTTP 403 Forbidden; alerts indicate automated discovery scanning.",
    evidence: "Extracted: 'Kube-apiserver audit logs show 1,400 anonymous GET requests to /api/v1/namespaces/default/secrets.'",
    mitreTechniques: JSON.stringify(["T1613 - Container and Resource Discovery"]),
    affectedSystems: "Production EKS Kubernetes Control Plane",
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 240),
    status: "reviewed"
  });

  // Seed Recommendations
  const sampleRecs = [
    { threatId: "thr-syn-01", rec: "Revoke OAuth refresh tokens and force password reset for all Global Admin accounts.", pri: "Critical", type: "Containment" },
    { threatId: "thr-syn-01", rec: "Block egress communication to C2 IP addresses 185.220.101.42 and 194.26.29.114 on all edge firewalls.", pri: "Critical", type: "Containment" },
    { threatId: "thr-syn-01", rec: "Configure Microsoft 365 Defender alerts for high-risk OAuth consent grants.", pri: "High", type: "Monitoring" },
    { threatId: "thr-syn-03", rec: "Isolate all VMware ESXi hypervisor management interfaces into dedicated out-of-band VLANs.", pri: "Critical", type: "Containment" },
    { threatId: "thr-syn-03", rec: "Apply emergency PAN-OS hotfix to remediate CVE-2024-3400 across all perimeter firewalls.", pri: "Critical", type: "Patching" },
    { threatId: "thr-syn-03", rec: "Verify immutable air-gapped backups for all hospital patient databases.", pri: "High", type: "Hardening" },
    { threatId: "thr-syn-05", rec: "Upgrade OpenSSH packages to version 9.8p1 or apply vendor backported patch immediately.", pri: "High", type: "Patching" },
    { threatId: "thr-syn-05", rec: "Configure 'LoginGraceTime 0' in sshd_config as temporary mitigation for vulnerable hosts.", pri: "Medium", type: "Hardening" },
    { threatId: "thr-syn-06", rec: "Audit active domain controller accounts for unexpected LOLBin execution (wmic, ntdsutil).", pri: "Critical", type: "Investigation" },
    { threatId: "thr-syn-06", rec: "Replace consumer-grade SOHO router appliances at remote substation perimeters.", pri: "High", type: "Hardening" },
    { threatId: "thr-syn-07", rec: "Implement FIDO2 hardware security keys (YubiKeys) for all privileged administrators.", pri: "High", type: "Hardening" },
    { threatId: "thr-syn-08", rec: "Deploy DNS-layer threat protection to detect and sinkhole high-entropy exfiltration queries.", pri: "High", type: "Monitoring" }
  ];

  sampleRecs.forEach((r, idx) => {
    recommendationsList.push({
      id: `rec-syn-${idx + 1}`,
      threatId: r.threatId,
      recommendation: r.rec,
      priority: r.pri,
      actionType: r.type,
      completed: idx % 3 === 0 ? 1 : 0
    });
  });

  // Seed IOCs - Covering all 11 Analyst Supported Types
  const rawIocs = [
    // 1. IPv4
    { reportId: "rep-syn-01", threatId: "thr-syn-01", type: "IPv4", value: "185.220.101.42", confidence: 95, context: "APT29 Primary C2 Proxy (Port 443 HTTPS)", severity: "CRITICAL", tags: "c2, apt29, tor-exit, https", score: 96 },
    { reportId: "rep-syn-01", threatId: "thr-syn-01", type: "IPv4", value: "194.26.29.114", confidence: 94, context: "Secondary Beacon Listener Host", severity: "HIGH", tags: "c2, secondary-listener, beacon", score: 94 },
    { reportId: "rep-syn-02", threatId: "thr-syn-03", type: "IPv4", value: "45.142.212.60", confidence: 98, context: "BlackByte Exfiltration Drop Server", severity: "CRITICAL", tags: "ransomware, exfil, blackbyte", score: 98 },
    { reportId: "rep-syn-02", threatId: "thr-syn-03", type: "IPv4", value: "198.51.100.89", confidence: 92, context: "Lateral Movement PsExec Staging Host", severity: "HIGH", tags: "lateral-movement, psexec, stager", score: 91 },
    { reportId: "rep-syn-03", threatId: "thr-syn-05", type: "IPv4", value: "91.92.240.11", confidence: 88, context: "Mass OpenSSH Vulnerability Scanner Probe", severity: "MEDIUM", tags: "scanner, ssh, regresshion", score: 89 },
    { reportId: "rep-syn-04", threatId: "thr-syn-06", type: "IPv4", value: "193.106.191.22", confidence: 93, context: "Volt Typhoon SOHO Relay Node", severity: "CRITICAL", tags: "volt-typhoon, soho, router-proxy", score: 95 },
    { reportId: "rep-syn-05", threatId: "thr-syn-07", type: "IPv4", value: "104.244.76.13", confidence: 90, context: "AiTM Phishing Gateway Server", severity: "HIGH", tags: "phishing, aitm, evilginx", score: 92 },
    { reportId: "rep-syn-06", threatId: "thr-syn-08", type: "IPv4", value: "195.123.245.88", confidence: 92, context: "Malicious Authoritative DNS Nameserver", severity: "HIGH", tags: "dns-tunneling, nameserver", score: 93 },

    // 2. IPv6
    { reportId: "rep-syn-01", threatId: "thr-syn-01", type: "IPv6", value: "2a01:4f8:c010:d56::1", confidence: 92, context: "APT29 IPv6 Egress Proxy Relay", severity: "HIGH", tags: "ipv6, c2, apt29, stealth", score: 91 },
    { reportId: "rep-syn-04", threatId: "thr-syn-06", type: "IPv6", value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", confidence: 89, context: "Edge Router Substation IPv6 Tunnel Endpoint", severity: "MEDIUM", tags: "ipv6, router-tunnel, scada", score: 86 },

    // 3. Domain
    { reportId: "rep-syn-01", threatId: "thr-syn-01", type: "Domain", value: "auth-sync-gateway.org", confidence: 91, context: "OAuth Consent Phishing Domain", severity: "CRITICAL", tags: "oauth-abuse, phishing, credential-theft", score: 94 },
    { reportId: "rep-syn-05", threatId: "thr-syn-07", type: "Domain", value: "login-microsoftonline-verify.com", confidence: 95, context: "Evilginx3 Reverse Proxy Landing", severity: "CRITICAL", tags: "lookalike, brand-impersonation, microsoft", score: 96 },
    { reportId: "rep-syn-05", threatId: "thr-syn-07", type: "Domain", value: "portal-okta-auth-session.net", confidence: 94, context: "Okta Session Harvesting Host", severity: "HIGH", tags: "okta, session-theft, mfa-bypass", score: 95 },
    { reportId: "rep-syn-06", threatId: "thr-syn-08", type: "Domain", value: "data-exfil-sync.cc", confidence: 96, context: "DNS Tunneling Authoritative Server", severity: "CRITICAL", tags: "dns-tunnel, data-loss, apex-c2", score: 97 },
    { reportId: "rep-syn-09", threatId: "thr-syn-11", type: "Domain", value: "download-anydesk-support-setup.com", confidence: 92, context: "Malvertising Impersonation Domain", severity: "HIGH", tags: "malvertising, dropper, impersonation", score: 92 },

    // 4. URL
    { reportId: "rep-syn-01", threatId: "thr-syn-01", type: "URL", value: "https://auth-sync-gateway.org/oauth/v2/authorize?client_id=sec-adm", confidence: 96, context: "Malicious OAuth Authorization Endpoint", severity: "CRITICAL", tags: "oauth-url, consent-lure", score: 96 },
    { reportId: "rep-syn-02", threatId: "thr-syn-03", type: "URL", value: "http://45.142.212.60/stage/payload.bin", confidence: 97, context: "Secondary Ransomware Dropper URL", severity: "CRITICAL", tags: "dropper-url, binary-stage", score: 97 },
    { reportId: "rep-syn-05", threatId: "thr-syn-07", type: "URL", value: "https://login-microsoftonline-verify.com/login.srf?auth=ad", confidence: 94, context: "AiTM Reverse Proxy Login URL", severity: "HIGH", tags: "phish-url, reverse-proxy", score: 94 },

    // 5. SHA256
    { reportId: "rep-syn-01", threatId: "thr-syn-01", type: "SHA256", value: "8f4e21a48c9032bb9e5531d87d903512a819b9351e2b69d4e5f7a049d5c81f01", confidence: 96, context: "Trojan.Win64.CobaltBeacon DLL Implant", severity: "CRITICAL", tags: "dll-implant, cobalt-strike, in-memory", score: 98 },
    { reportId: "rep-syn-02", threatId: "thr-syn-03", type: "SHA256", value: "d5a7a3b4e672901c890123ef567890abcd1234ef567890abcdef1234567890ab", confidence: 97, context: "BlackByte.v3 Windows Locker Payload", severity: "CRITICAL", tags: "ransomware-bin, blackbyte, locker", score: 99 },
    { reportId: "rep-syn-09", threatId: "thr-syn-11", type: "SHA256", value: "7c3a9f8b2e1d0c4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f", confidence: 94, context: "DarkGate AutoIt Dropper Binary", severity: "HIGH", tags: "darkgate, autoit, rat-dropper", score: 94 },

    // 6. SHA1
    { reportId: "rep-syn-01", threatId: "thr-syn-01", type: "SHA1", value: "3b890f6b5b5c92c90e0b9687e1f422998a44b82d", confidence: 93, context: "Cobalt Beacon Loader Stub SHA1", severity: "HIGH", tags: "sha1, loader, stub", score: 93 },
    { reportId: "rep-syn-02", threatId: "thr-syn-03", type: "SHA1", value: "9a3f2b1c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a", confidence: 95, context: "BlackByte Unpacker Stub SHA1", severity: "HIGH", tags: "sha1, unpacker, ransomware", score: 95 },

    // 7. MD5
    { reportId: "rep-syn-01", threatId: "thr-syn-01", type: "MD5", value: "44d88612fea8a8f36de82e1278abb02f", confidence: 91, context: "Reflective DLL Loader MD5", severity: "HIGH", tags: "md5, reflective-dll", score: 91 },
    { reportId: "rep-syn-02", threatId: "thr-syn-03", type: "MD5", value: "e1112131415161718192021222324252", confidence: 92, context: "PsExec Process Injection Binary MD5", severity: "HIGH", tags: "md5, psexec-injector", score: 92 },

    // 8. CVE
    { reportId: "rep-syn-01", threatId: "thr-syn-01", type: "CVE", value: "CVE-2023-38606", confidence: 99, context: "OAuth Permission Escalation Flaw", severity: "HIGH", tags: "cve, oauth, privilege-escalation", score: 92 },
    { reportId: "rep-syn-02", threatId: "thr-syn-03", type: "CVE", value: "CVE-2024-3400", confidence: 99, context: "PAN-OS GlobalProtect Command Injection", severity: "CRITICAL", tags: "cve, cisa-kev, pan-os, rce", score: 100 },
    { reportId: "rep-syn-03", threatId: "thr-syn-05", type: "CVE", value: "CVE-2024-6387", confidence: 99, context: "regreSSHion OpenSSH Signal Race Condition RCE", severity: "CRITICAL", tags: "cve, cisa-kev, ssh, rce", score: 98 },
    { reportId: "rep-syn-01", threatId: "thr-syn-01", type: "CVE", value: "CVE-2024-38077", confidence: 99, context: "Windows Remote Desktop Licensing Service RCE (MadLicense)", severity: "CRITICAL", tags: "cve, cisa-kev, rdp, rce", score: 100 },

    // 9. Filename
    { reportId: "rep-syn-04", threatId: "thr-syn-06", type: "Filename", value: "/portal/common/error_handler.jsp", confidence: 95, context: "SCADA Ingress Web Shell Persistence", severity: "CRITICAL", tags: "webshell, jsp, scada, persistence", score: 96 },
    { reportId: "rep-syn-02", threatId: "thr-syn-03", type: "Filename", value: "RESTORE_FILES_BLACKBYTE.txt", confidence: 98, context: "BlackByte Ransomware Extortion Note", severity: "HIGH", tags: "ransom-note, extortion, blackbyte", score: 95 },
    { reportId: "rep-syn-09", threatId: "thr-syn-11", type: "Filename", value: "async_payload.bin", confidence: 91, context: "AsyncRAT Encrypted Dropper Binary", severity: "MEDIUM", tags: "rat-payload, bin, dropper", score: 88 },

    // 10. Registry
    { reportId: "rep-syn-01", threatId: "thr-syn-01", type: "Registry", value: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\CobaltService", confidence: 96, context: "Persistence via Windows Run Key Auto-start", severity: "HIGH", tags: "registry, persistence, run-key, auto-start", score: 94 },
    { reportId: "rep-syn-09", threatId: "thr-syn-11", type: "Registry", value: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Updater", confidence: 90, context: "AsyncRAT User Registry RunOnce Persistence", severity: "MEDIUM", tags: "registry, runonce, user-hive", score: 89 },

    // 11. Email
    { reportId: "rep-syn-01", threatId: "thr-syn-01", type: "Email", value: "admin-security@defense-update-summit.org", confidence: 93, context: "Spear-phishing Lure Sender Address", severity: "HIGH", tags: "spearphishing, email, sender-spoof", score: 93 },
    { reportId: "rep-syn-05", threatId: "thr-syn-07", type: "Email", value: "billing-update@health-telemetry-portal.com", confidence: 92, context: "Corporate Payroll Phishing Notification", severity: "MEDIUM", tags: "phishing-email, payroll-lure", score: 88 }
  ];

  rawIocs.forEach((ioc, idx) => {
    const daysAgo = (idx * 0.4) + 1;
    const firstSeen = new Date(Date.now() - 1000 * 60 * 60 * 24 * (daysAgo + 5));
    const lastSeen = new Date(Date.now() - 1000 * 60 * 60 * 24 * daysAgo);

    iocsList.push({
      id: `ioc-syn-${idx + 1}`,
      reportId: ioc.reportId,
      threatId: ioc.threatId,
      type: ioc.type,
      value: ioc.value,
      confidence: ioc.confidence,
      context: ioc.context,
      severity: ioc.severity,
      firstSeen,
      lastSeen,
      tags: ioc.tags,
      reputationScore: ioc.score,
      enrichmentData: null
    });
  });

  // Seed Entities
  const rawEntities = [
    { reportId: "rep-syn-01", threatId: "thr-syn-01", name: "APT29 (Cobalt Nexus)", type: "ThreatActor", confidence: 95 },
    { reportId: "rep-syn-01", threatId: "thr-syn-01", name: "Trojan.CobaltBeacon", type: "Malware", confidence: 96 },
    { reportId: "rep-syn-01", threatId: "thr-syn-01", name: "Microsoft 365 & Entra ID", type: "Technology", confidence: 99 },
    { reportId: "rep-syn-01", threatId: "thr-syn-01", name: "Western Diplomatic Missions", type: "Organization", confidence: 88 },
    { reportId: "rep-syn-01", threatId: "thr-syn-01", name: "United States & Belgium", type: "Country", confidence: 90 },

    { reportId: "rep-syn-02", threatId: "thr-syn-03", name: "BlackByte Ransomware Group", type: "ThreatActor", confidence: 97 },
    { reportId: "rep-syn-02", threatId: "thr-syn-03", name: "BlackByte.v3", type: "Ransomware", confidence: 98 },
    { reportId: "rep-syn-02", threatId: "thr-syn-04", name: "CVE-2024-3400", type: "Vulnerability", confidence: 99 },
    { reportId: "rep-syn-02", threatId: "thr-syn-03", name: "Regional Hospital Consortium", type: "Organization", confidence: 91 },
    { reportId: "rep-syn-02", threatId: "thr-syn-03", name: "Germany & France", type: "Country", confidence: 92 },

    { reportId: "rep-syn-03", threatId: "thr-syn-05", name: "CVE-2024-6387 (regreSSHion)", type: "Vulnerability", confidence: 99 },
    { reportId: "rep-syn-03", threatId: "thr-syn-05", name: "OpenSSH Project", type: "Organization", confidence: 95 },
    { reportId: "rep-syn-03", threatId: "thr-syn-05", name: "Global Enterprise Cloud", type: "Region", confidence: 85 },

    { reportId: "rep-syn-04", threatId: "thr-syn-06", name: "Volt Typhoon (Synthetic)", type: "ThreatActor", confidence: 94 },
    { reportId: "rep-syn-04", threatId: "thr-syn-06", name: "Pacific Port Logistics Authority", type: "Organization", confidence: 92 },
    { reportId: "rep-syn-04", threatId: "thr-syn-06", name: "Singapore & Japan", type: "Country", confidence: 90 },

    { reportId: "rep-syn-05", threatId: "thr-syn-07", name: "Evilginx3 AiTM Framework", type: "Technology", confidence: 93 },
    { reportId: "rep-syn-05", threatId: "thr-syn-07", name: "Defense Contractor Nexus", type: "Organization", confidence: 89 },
    { reportId: "rep-syn-06", threatId: "thr-syn-08", name: "National Energy Transmission Grid", type: "Organization", confidence: 94 },
    { reportId: "rep-syn-09", threatId: "thr-syn-11", name: "DarkGate v6", type: "Malware", confidence: 95 },
    { reportId: "rep-syn-07", threatId: "thr-syn-09", name: "Mirai IoT Botnet Nexus", type: "ThreatActor", confidence: 91 },
    { reportId: "rep-syn-08", threatId: "thr-syn-10", name: "GitLab Enterprise Server", type: "Technology", confidence: 96 },
    { reportId: "rep-syn-10", threatId: "thr-syn-12", name: "Autonomous System AS-99411", type: "ThreatActor", confidence: 88 },
    { reportId: "rep-syn-02", threatId: "thr-syn-14", name: "Akira Ransomware Group", type: "ThreatActor", confidence: 96 },
    { reportId: "rep-syn-03", threatId: "thr-syn-15", name: "Ivanti Policy & Connect Secure", type: "Technology", confidence: 98 },
    { reportId: "rep-syn-04", threatId: "thr-syn-16", name: "liblzma (XZ Utils)", type: "Technology", confidence: 99 },
    { reportId: "rep-syn-06", threatId: "thr-syn-18", name: "AWS S3 Cloud Storage", type: "Technology", confidence: 97 },
    { reportId: "rep-syn-09", threatId: "thr-syn-21", name: "AsyncRAT Malware Strain", type: "Malware", confidence: 93 },
    { reportId: "rep-syn-07", threatId: "thr-syn-19", name: "Global Authoritative DNS Fabric", type: "Technology", confidence: 92 }
  ];

  rawEntities.forEach((ent, idx) => {
    entitiesList.push({
      id: `ent-syn-${idx + 1}`,
      reportId: ent.reportId,
      threatId: ent.threatId,
      name: ent.name,
      type: ent.type,
      confidence: ent.confidence
    });
  });

  // Seed Incidents (30+ for timeline and map)
  const locations = [
    { city: "Washington D.C., USA", coords: "38.9072,-77.0369" },
    { city: "Frankfurt, Germany", coords: "50.1109,8.6821" },
    { city: "London, UK", coords: "51.5074,-0.1278" },
    { city: "Tokyo, Japan", coords: "35.6762,139.6503" },
    { city: "Singapore", coords: "1.3521,103.8198" },
    { city: "Paris, France", coords: "48.8566,2.3522" },
    { city: "Sydney, Australia", coords: "-33.8688,151.2093" },
    { city: "Brussels, Belgium", coords: "50.8503,4.3517" },
    { city: "San Francisco, USA", coords: "37.7749,-122.4194" },
    { city: "Zurich, Switzerland", coords: "47.3769,8.5417" },
    { city: "Dubai, UAE", coords: "25.2048,55.2708" },
    { city: "Seoul, South Korea", coords: "37.5665,126.9780" }
  ];

  const incidentTemplates = [
    { title: "Spear-Phishing Lure Delivered to Diplomatic Accounts", cat: "Credential Attack", sev: "CRITICAL", mal: "Trojan.CobaltBeacon", act: "APT29 (Cobalt Nexus)", thrId: "thr-syn-01" },
    { title: "OAuth Token Misuse Alert on Mail Archiving API", cat: "Credential Attack", sev: "HIGH", mal: "OAuth Exploit", act: "APT29", thrId: "thr-syn-02" },
    { title: "Hospital PACs Telemetry Server Encrypted", cat: "Ransomware", sev: "CRITICAL", mal: "BlackByte.v3", act: "BlackByte Group", thrId: "thr-syn-03" },
    { title: "Emergency VPN Gateway Patching Incident", cat: "Vulnerability Exploitation", sev: "CRITICAL", mal: "CVE-2024-3400 Exploit", act: "Unattributed", thrId: "thr-syn-04" },
    { title: "Automated Mass OpenSSH Port 22 Sweep", cat: "Vulnerability Exploitation", sev: "HIGH", mal: "regreSSHion Probe", act: "Botnet Cluster", thrId: "thr-syn-05" },
    { title: "Anomalous SCADA WMI Query in Port Logistics Subnet", cat: "Supply Chain", sev: "CRITICAL", mal: "LOLBins Native", act: "Volt Typhoon", thrId: "thr-syn-06" },
    { title: "Executive Session Cookie Replay Detected in Cloud IdP", cat: "Phishing", sev: "HIGH", mal: "Evilginx3 Reverse-Proxy", act: "AiTM Phishing Syndicate", thrId: "thr-syn-07" },
    { title: "High-Entropy DNS Query Spike from Turbine Workstation", cat: "Data Breach", sev: "HIGH", mal: "DNS Tunneling Protocol", act: "Unknown Insider/Actor", thrId: "thr-syn-08" },
    { title: "Volumetric UDP Syn-Flood on Municipal Water Portal", cat: "DDoS", sev: "MEDIUM", mal: "Mirai IoT Variant", act: "Distributed Botnet", thrId: "thr-syn-09" },
    { title: "DevOps CI/CD Token Accessing Satellite Repositories", cat: "Insider Risk", sev: "HIGH", mal: "RAR Staging Script", act: "Compromised Service Principal", thrId: "thr-syn-10" },
    { title: "AutoIt Process Spawning Hidden VNC on Admin Host", cat: "Malware", sev: "MEDIUM", mal: "DarkGate v6", act: "Malvertising Nexus", thrId: "thr-syn-11" },
    { title: "BGP Prefix Route Hijack Flagged by RPKI Validator", cat: "Suspicious Network Activity", sev: "HIGH", mal: "BGP AS Injection", act: "AS-99411 Cluster", thrId: "thr-syn-12" }
  ];

  let incCount = 0;
  for (let round = 0; round < 3; round++) {
    incidentTemplates.forEach((t, i) => {
      incCount++;
      const loc = locations[(i + round * 4) % locations.length];
      const daysAgo = incCount <= 6 ? ((incCount - 1) * 0.4) : (3 + (incCount - 7) * 4.8);
      incidentsList.push({
        id: `inc-syn-${incCount}`,
        threatId: t.thrId,
        reportId: `rep-syn-0${(i % 10) + 1}`,
        title: `${t.title} [Event #${incCount}]`,
        date: new Date(Date.now() - 1000 * 60 * 60 * 24 * daysAgo).toISOString(),
        location: loc.city,
        coordinates: loc.coords,
        category: t.cat,
        severity: t.sev,
        description: `Correlated sensor alert: ${t.title} observed in ${loc.city}. Automated IOC verification confirmed matching signatures with active threat profile.`,
        malware: t.mal,
        threatActor: t.act,
        relatedIocCount: Math.floor(Math.random() * 3) + 2
      });
    });
  }

  // Seed Predictions / Emerging Threats
  const predictionsList = [
    {
      id: "pred-syn-01",
      category: "Ransomware",
      location: "Western Europe & North America (Healthcare)",
      riskScore: 94,
      growthRate: "+48%",
      trendDirection: "INCREASING",
      confidence: 91,
      predictionDate: new Date(Date.now() + 1000 * 60 * 60 * 24 * 14),
      explanation: "Ransomware groups are accelerating double-extortion campaigns utilizing zero-day edge gateway vulnerabilities (e.g. CVE-2024-3400) targeting VMware ESXi infrastructure.",
      supportingIncidentsCount: 14
    },
    {
      id: "pred-syn-02",
      category: "Vulnerability Exploitation",
      location: "Global Enterprise Cloud Infrastructure",
      riskScore: 89,
      growthRate: "+36%",
      trendDirection: "INCREASING",
      confidence: 88,
      predictionDate: new Date(Date.now() + 1000 * 60 * 60 * 24 * 21),
      explanation: "OpenSSH race conditions (regreSSHion) and edge VPN appliance vulnerabilities are triggering automated exploitation botnet sweeps across internet-facing port ranges.",
      supportingIncidentsCount: 19
    },
    {
      id: "pred-syn-03",
      category: "Credential Attack",
      location: "North America & East Asia",
      riskScore: 84,
      growthRate: "+28%",
      trendDirection: "INCREASING",
      confidence: 86,
      predictionDate: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
      explanation: "Adversary-in-the-Middle reverse proxy tools (Evilginx3) are circumventing legacy SMS/TOTP MFA. Organizations must expedite FIDO2 hardware key rollouts.",
      supportingIncidentsCount: 11
    },
    {
      id: "pred-syn-04",
      category: "Supply Chain",
      location: "Maritime Ports & Critical SCADA",
      riskScore: 92,
      growthRate: "+22%",
      trendDirection: "INCREASING",
      confidence: 90,
      predictionDate: new Date(Date.now() + 1000 * 60 * 60 * 24 * 45),
      explanation: "Living-off-the-land techniques targeting critical infrastructure SCADA and operational technologies continue to evade traditional antivirus through compromised SOHO router meshes.",
      supportingIncidentsCount: 8
    },
    {
      id: "pred-syn-05",
      category: "DDoS",
      location: "Municipal Utilities & Telemetry",
      riskScore: 68,
      growthRate: "-12%",
      trendDirection: "DECREASING",
      confidence: 82,
      predictionDate: new Date(Date.now() + 1000 * 60 * 60 * 24 * 60),
      explanation: "Volumetric DDoS attempts show slight decline as ISP-level scrubbing and upstream routing countermeasures filter amplification reflectors more rapidly.",
      supportingIncidentsCount: 6
    },
    {
      id: "pred-syn-06",
      category: "Data Breach",
      location: "Energy & Aerospace Sectors",
      riskScore: 81,
      growthRate: "+18%",
      trendDirection: "STABLE",
      confidence: 85,
      predictionDate: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
      explanation: "Covert data exfiltration utilizing DNS tunneling and fragmented cloud API uploads remains an active operational risk requiring deep packet inspection.",
      supportingIncidentsCount: 9
    },
    {
      id: "pred-syn-07",
      category: "Cloud Security",
      location: "Multi-Cloud SaaS & Entra ID Deployments",
      riskScore: 88,
      growthRate: "+42%",
      trendDirection: "INCREASING",
      confidence: 89,
      predictionDate: new Date(Date.now() + 1000 * 60 * 60 * 24 * 18),
      explanation: "Adversaries are targeting misconfigured cloud IAM permissions and OAuth consent workflows to persist across hybrid multi-cloud perimeters without deploying malware.",
      supportingIncidentsCount: 13
    },
    {
      id: "pred-syn-08",
      category: "Insider Risk",
      location: "Financial Services & Defense Supply Contractors",
      riskScore: 79,
      growthRate: "+15%",
      trendDirection: "STABLE",
      confidence: 84,
      predictionDate: new Date(Date.now() + 1000 * 60 * 60 * 24 * 25),
      explanation: "Offboarding telemetry reveals increased risk of unauthorized repository cloning and cloud database dumps by departing technical personnel.",
      supportingIncidentsCount: 7
    }
  ];

  // Seed Initial Analyst Notes
  analystNotesList.push({
    id: "note-syn-01",
    threatId: "thr-syn-01",
    reportId: "rep-syn-01",
    author: "Jordan Chen (L2 SOC Analyst)",
    note: "Cross-referenced C2 IP 185.220.101.42 against internal proxy logs. Blocked on edge firewalls at 14:15 UTC. Zero matching internal connections detected in last 24h.",
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 1.5)
  });

  analystNotesList.push({
    id: "note-syn-02",
    threatId: "thr-syn-03",
    reportId: "rep-syn-02",
    author: "Dr. Elena Rostova (Lead Incident Responder)",
    note: "Coordinated with clinical engineering team to verify isolated ESXi clusters. Hospital diagnostic networks restored safely under active EDR monitoring.",
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 10)
  });

  const assetsList = [
    {
      id: "ast-syn-01",
      name: "Primary Edge API Gateway",
      hostname: "gw-edge-01.prod.shieldzen.net",
      ipAddress: "52.14.88.192",
      assetType: "SERVER",
      operatingSystem: "Ubuntu 22.04 LTS (Kernel 5.15)",
      software: "NGINX Plus 1.25, OpenSSL 3.0.2, Envoy Proxy 1.28, CrowdStrike Falcon Sensor 7.12",
      environment: "Production",
      criticality: "CRITICAL",
      exposure: "INTERNET",
      owner: "DevOps Infrastructure Team",
      department: "Platform Engineering",
      location: "US-East (N. Virginia Datacenter)",
      description: "Public reverse proxy and TLS termination gateway handling all inbound traffic for customer portal and external REST APIs.",
      tags: "edge, api-gateway, internet-facing, pci-dss, tier-1",
      status: "ACTIVE",
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 120),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 12),
    },
    {
      id: "ast-syn-02",
      name: "Customer Core Database Cluster (Primary)",
      hostname: "db-core-primary.internal.shieldzen.net",
      ipAddress: "10.100.4.15",
      assetType: "DATABASE",
      operatingSystem: "Red Hat Enterprise Linux 9.2",
      software: "PostgreSQL 16.2, pgBackRest 2.50, SentinelOne Agent 23.4, HashiCorp Vault Agent",
      environment: "Production",
      criticality: "CRITICAL",
      exposure: "INTERNAL",
      owner: "Database Administration Team",
      department: "Data Operations",
      location: "US-East (Dedicated Secure Enclave)",
      description: "Primary relational database storing sensitive customer identities, encrypted credentials, and transaction ledgers.",
      tags: "database, pii, encrypted-at-rest, core-system, restricted-access",
      status: "ACTIVE",
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 180),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 2),
    },
    {
      id: "ast-syn-03",
      name: "Corporate Active Directory Domain Controller",
      hostname: "dc01.corp.shieldzen.local",
      ipAddress: "172.16.10.5",
      assetType: "SERVER",
      operatingSystem: "Windows Server 2022 Datacenter",
      software: "Active Directory Domain Services, DNS Server, Microsoft Defender for Identity, Kerberos KDC",
      environment: "Production",
      criticality: "CRITICAL",
      exposure: "INTERNAL",
      owner: "Identity & Access Management (IAM)",
      department: "Enterprise IT",
      location: "Corporate HQ Server Room (Chicago, IL)",
      description: "Primary root Domain Controller managing identity federation, Kerberos authentication, and Group Policy Objects.",
      tags: "active-directory, identity, domain-controller, high-value-target",
      status: "ACTIVE",
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 240),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 6),
    },
    {
      id: "ast-syn-04",
      name: "External Customer Portal Frontend",
      hostname: "portal-web-01.shieldzen.io",
      ipAddress: "34.211.19.45",
      assetType: "APPLICATION",
      operatingSystem: "Alpine Linux (Containerized K8s Pod)",
      software: "Node.js 20.11, React 18, Nginx 1.25, Web Application Firewall (WAF)",
      environment: "Production",
      criticality: "HIGH",
      exposure: "INTERNET",
      owner: "Frontend Engineering Team",
      department: "Product Engineering",
      location: "AWS us-west-2 (Oregon)",
      description: "Public customer-facing web portal facilitating threat dashboard access and report downloads.",
      tags: "web, public-facing, kubernetes, waf-protected",
      status: "ACTIVE",
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 90),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 18),
    },
    {
      id: "ast-syn-05",
      name: "SOC Lead Analyst Workstation",
      hostname: "ws-soc-04.corp.shieldzen.local",
      ipAddress: "172.16.40.88",
      assetType: "WORKSTATION",
      operatingSystem: "Windows 11 Enterprise (Build 23H2)",
      software: "CrowdStrike Falcon Sensor, Wireshark, Burp Suite Pro, Splunk Universal Forwarder, VS Code",
      environment: "Production",
      criticality: "MEDIUM",
      exposure: "INTERNAL",
      owner: "Sarah Jenkins (Senior SOC Lead)",
      department: "Security Operations Center",
      location: "Cyber Defense Hub (Floor 3)",
      description: "Dedicated analyst workstation with privileged access to SIEM consoles and threat response playbooks.",
      tags: "workstation, soc, privileged-user, edr-enforced",
      status: "ACTIVE",
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 60),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 4),
    },
    {
      id: "ast-syn-06",
      name: "Core Edge Perimeter Firewall",
      hostname: "fw-edge-ha-01.shieldzen.net",
      ipAddress: "198.51.100.1",
      assetType: "NETWORK_DEVICE",
      operatingSystem: "Palo Alto PAN-OS 11.1.2",
      software: "PAN-OS Threat Prevention, WildFire Cloud Analysis, GlobalProtect VPN Gateway",
      environment: "Production",
      criticality: "CRITICAL",
      exposure: "INTERNET",
      owner: "Network Security Operations",
      department: "Infrastructure & Security",
      location: "US-East Perimeter Co-location",
      description: "Next-Generation Firewall cluster enforcing ingress zero-trust access, SSL decryption, and IPS inspection.",
      tags: "firewall, perimeter, vpn, ips, zero-trust",
      status: "ACTIVE",
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 300),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24),
    },
    {
      id: "ast-syn-07",
      name: "Kubernetes Production Worker Node 03",
      hostname: "k8s-prod-worker-03.us-east1.cloud",
      ipAddress: "10.240.12.83",
      assetType: "CLOUD",
      operatingSystem: "Google Container-Optimized OS (cos-109)",
      software: "Kubernetes v1.28.6, containerd 1.7.11, Cilium eBPF CNI, Datadog Agent",
      environment: "Production",
      criticality: "HIGH",
      exposure: "INTERNAL",
      owner: "Cloud Platform SRE",
      department: "DevOps",
      location: "GCP us-east1 (South Carolina)",
      description: "Cloud compute node executing core CTI enrichment microservices and background threat ingestion pipelines.",
      tags: "cloud, kubernetes, gcp, compute, auto-scaling",
      status: "ACTIVE",
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 45),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 1),
    },
    {
      id: "ast-syn-08",
      name: "Staging API Gateway & Ingress",
      hostname: "gw-stage-01.stage.shieldzen.net",
      ipAddress: "54.198.42.110",
      assetType: "SERVER",
      operatingSystem: "Ubuntu 22.04 LTS",
      software: "NGINX 1.24, OpenSSL 3.0.2, Docker 24.0",
      environment: "Staging",
      criticality: "MEDIUM",
      exposure: "INTERNET",
      owner: "Quality Assurance & Release Engineering",
      department: "Platform Engineering",
      location: "AWS us-east-1",
      description: "Staging environment proxy mirroring production routing for pre-release integration tests.",
      tags: "staging, pre-prod, test-bed, external",
      status: "ACTIVE",
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 30),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 14),
    },
    {
      id: "ast-syn-09",
      name: "Internal CI/CD Build Runner",
      hostname: "runner-ci-02.corp.internal",
      ipAddress: "10.50.20.14",
      assetType: "SERVER",
      operatingSystem: "Debian 12 Bookworm",
      software: "GitLab Runner 16.8, Docker CE 25.0, SonarQube Scanner, Trivy Vulnerability Scanner",
      environment: "Development",
      criticality: "MEDIUM",
      exposure: "RESTRICTED",
      owner: "Release Engineering Team",
      department: "DevSecOps",
      location: "On-Premises Dev Lab (Austin, TX)",
      description: "Automated continuous integration server compiling software binaries and executing SAST security scans.",
      tags: "cicd, build-runner, devsecops, internal",
      status: "ACTIVE",
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 75),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 8),
    },
    {
      id: "ast-syn-10",
      name: "Legacy VPN Gateway (Scheduled Decommission)",
      hostname: "vpn-legacy-gw.shieldzen.org",
      ipAddress: "194.33.191.22",
      assetType: "NETWORK_DEVICE",
      operatingSystem: "Cisco ASA 5525-X Software 9.14",
      software: "Cisco AnyConnect VPN, SSLv3 Disabled, OpenSSL 1.1.1",
      environment: "Production",
      criticality: "LOW",
      exposure: "INTERNET",
      owner: "Enterprise IT Legacy Ops",
      department: "Enterprise IT",
      location: "Legacy Frankfurt Datacenter",
      description: "Standby backup remote access gateway currently being phased out in favor of modern Zero Trust Access.",
      tags: "legacy, vpn, deprecation-target, cisco",
      status: "MAINTENANCE",
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 400),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 48),
    }
  ];

  const threatActorsList = [
    {
      id: "act-syn-01",
      name: "Shadow Meridian",
      aliases: JSON.stringify(["STG-29", "Meridian Phantom", "Cobalt Nexus", "UNC-4102"]),
      description: "Advanced state-sponsored cyber espionage cluster specializing in stealthy cloud infrastructure lateral movement, OAuth token theft, and persistent Microsoft 365 mailbox harvesting. Operates with high operational discipline and custom memory-resident implants.",
      origin: "Nation State",
      motivation: "Espionage",
      sophistication: "Advanced",
      confidence: 95,
      firstObserved: new Date(Date.now() - 1000 * 60 * 60 * 24 * 365),
      lastObserved: new Date(Date.now() - 1000 * 60 * 60 * 18),
      status: "Active",
      notes: "Attributed to the CYBER-INTEL-2024-001 advisory. Focuses on diplomatic foreign affairs, aerospace contractors, and cloud identity providers.",
      isSynthetic: 1,
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 300),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 18),
    },
    {
      id: "act-syn-02",
      name: "Crimson Viper",
      aliases: JSON.stringify(["Viper Syndicate", "RansomViper", "Viper-33", "SectorB-04"]),
      description: "Prolific financially motivated cybercriminal syndicate operating double-extortion ransomware schemes targeting healthcare networks, manufacturing supply chains, and municipal services. Known for weaponizing edge network appliance vulnerabilities within 48 hours of public disclosure.",
      origin: "Cybercriminal",
      motivation: "Financial",
      sophistication: "High",
      confidence: 92,
      firstObserved: new Date(Date.now() - 1000 * 60 * 60 * 24 * 280),
      lastObserved: new Date(Date.now() - 1000 * 60 * 60 * 6),
      status: "Active",
      notes: "Frequently utilizes BlackByte 3.0 codebase variants, Mega.nz staging egress, and vssadmin shadow copy purges.",
      isSynthetic: 1,
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 250),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 6),
    },
    {
      id: "act-syn-03",
      name: "Iron Specter",
      aliases: JSON.stringify(["STG-44", "Specter Forge", "Onyx Tempest", "VoltHarvester"]),
      description: "Highly disciplined state-backed APT operator specializing in industrial control systems (ICS/SCADA) reconnaissance, supply chain tampering, and strategic pre-positioning within critical energy, water, and transportation grids.",
      origin: "Nation State",
      motivation: "Intelligence",
      sophistication: "Advanced",
      confidence: 90,
      firstObserved: new Date(Date.now() - 1000 * 60 * 60 * 24 * 500),
      lastObserved: new Date(Date.now() - 1000 * 60 * 60 * 48),
      status: "Active",
      notes: "Leverages edge VPN appliances (CVE-2024-21887), living-off-the-land binaries (LOLBins), and custom web shells disguised as GIF telemetry files.",
      isSynthetic: 1,
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 400),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 48),
    },
    {
      id: "act-syn-04",
      name: "Ghost Lantern",
      aliases: JSON.stringify(["Lantern Brigade", "NullZero Anonymous", "Ghost Cell"]),
      description: "Ideologically driven hacktivist consortium executing high-volume distributed denial of service (DDoS) campaigns, website defacements, and opportunistic public data leaks against international financial and governmental institutions.",
      origin: "Hacktivist",
      motivation: "Political",
      sophistication: "Medium",
      confidence: 82,
      firstObserved: new Date(Date.now() - 1000 * 60 * 60 * 24 * 180),
      lastObserved: new Date(Date.now() - 1000 * 60 * 60 * 72),
      status: "Active",
      notes: "Coordinates operations via public Telegram channels, GitHub weaponized repos, and darknet leak mirrors.",
      isSynthetic: 1,
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 150),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 72),
    },
    {
      id: "act-syn-05",
      name: "Northern Eclipse",
      aliases: JSON.stringify(["Eclipse Core", "SubZero-9", "Lazarus Nexus", "BlueNoroff-Syn"]),
      description: "Strategic state-backed persistent threat entity conducting dual-purpose cryptocurrency theft operations to generate illicit revenue while executing long-term espionage against defense contractors and aerospace developers.",
      origin: "Nation State",
      motivation: "Financial",
      sophistication: "Advanced",
      confidence: 88,
      firstObserved: new Date(Date.now() - 1000 * 60 * 60 * 24 * 450),
      lastObserved: new Date(Date.now() - 1000 * 60 * 60 * 24 * 28),
      status: "Dormant",
      notes: "Historical operations include Trojanized DeFi client applications and targeted spear-phishing over LinkedIn developer channels.",
      isSynthetic: 1,
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 380),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 28),
    }
  ];

  const campaignsList = [
    {
      id: "cmp-syn-01",
      name: "Operation Cloud Breach 2024",
      description: "Systematic multi-vector cyber campaign targeting Microsoft 365 and AWS cloud tenant identity planes via OAuth consent abuse, password spraying, and spear-phishing diplomatic conference invitations.",
      threatActorId: "act-syn-01",
      firstObserved: new Date(Date.now() - 1000 * 60 * 60 * 24 * 120),
      lastObserved: new Date(Date.now() - 1000 * 60 * 60 * 18),
      targetSectors: JSON.stringify(["Government", "Defense Industrial Base", "Cloud Service Providers", "Aerospace"]),
      targetRegions: JSON.stringify(["North America", "Western Europe", "NATO Member States"]),
      objectives: "Long-term persistent surveillance of executive communications, diplomatic policy negotiations, and defense supply chain logistics.",
      status: "Active",
      confidence: 94,
      notes: "Correlated with Threat thr-syn-01 and Report rep-syn-01. High reliance on proxy infrastructure and rotating Tor exit nodes.",
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 90),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 18),
    },
    {
      id: "cmp-syn-02",
      name: "ViperLocker Healthcare Extortion Wave",
      description: "Aggressive ransomware extortion operation targeting regional hospital networks and medical device telemetry infrastructure by exploiting unpatched edge firewall devices (CVE-2024-3400) to exfiltrate electronic health records prior to enterprise-wide encryption.",
      threatActorId: "act-syn-02",
      firstObserved: new Date(Date.now() - 1000 * 60 * 60 * 24 * 60),
      lastObserved: new Date(Date.now() - 1000 * 60 * 60 * 6),
      targetSectors: JSON.stringify(["Healthcare & Public Health", "Pharmaceutical", "Medical Technology", "Emergency Services"]),
      targetRegions: JSON.stringify(["North America", "Western Europe"]),
      objectives: "Financial extortion demanding 50 to 100 BTC ransom payments per victim facility under threat of public patient record disclosure.",
      status: "Active",
      confidence: 96,
      notes: "Linked to Incident inc-syn-02 and Threat thr-syn-04. Requires urgent patch rollout of CVE-2024-3400 across all edge firewalls.",
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 45),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 6),
    },
    {
      id: "cmp-syn-03",
      name: "Specter Grid Infiltration & ICS Recon",
      description: "Stealthy persistent access campaign focused on electric utility sub-stations, operational technology networks, and SCADA monitoring gateways.",
      threatActorId: "act-syn-03",
      firstObserved: new Date(Date.now() - 1000 * 60 * 60 * 24 * 180),
      lastObserved: new Date(Date.now() - 1000 * 60 * 60 * 48),
      targetSectors: JSON.stringify(["Energy & Power Utilities", "Water Treatment", "Critical Manufacturing", "Oil & Gas"]),
      targetRegions: JSON.stringify(["North America", "APAC", "Eastern Europe"]),
      objectives: "Pre-positioning disruptive operational shutdown capabilities and exfiltrating engineering proprietary schematics.",
      status: "Monitoring",
      confidence: 88,
      notes: "Mapped to Threat thr-syn-07 and IOCs ioc-syn-11 / ioc-syn-12. Employs obfuscated PowerShell loaders.",
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 140),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 48),
    },
    {
      id: "cmp-syn-04",
      name: "Echo Leak Financial Disruption Surge",
      description: "Publicly declared hacktivism campaign conducting volumetric DDoS attacks against central banking portals, exploiting web application flaws, and publishing scraped customer registration databases.",
      threatActorId: "act-syn-04",
      firstObserved: new Date(Date.now() - 1000 * 60 * 60 * 24 * 45),
      lastObserved: new Date(Date.now() - 1000 * 60 * 60 * 72),
      targetSectors: JSON.stringify(["Financial Services", "Banking", "Telecommunications", "Media"]),
      targetRegions: JSON.stringify(["Global", "Middle East", "Western Europe"]),
      objectives: "Public embarrassment, reputational damage, and financial transaction processing disruption.",
      status: "Monitoring",
      confidence: 80,
      notes: "Targeting public-facing API gateways and corporate website frontends.",
      createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 30),
      updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 72),
    }
  ];

  const threatActorThreatsList = [
    { id: "tat-syn-01", threatActorId: "act-syn-01", threatId: "thr-syn-01", relationshipConfidence: "confirmed", attributionType: "Primary Operator", createdAt: new Date() },
    { id: "tat-syn-02", threatActorId: "act-syn-01", threatId: "thr-syn-02", relationshipConfidence: "confirmed", attributionType: "Primary Operator", createdAt: new Date() },
    { id: "tat-syn-03", threatActorId: "act-syn-01", threatId: "thr-syn-03", relationshipConfidence: "probable", attributionType: "Infrastructure Provider", createdAt: new Date() },
    { id: "tat-syn-04", threatActorId: "act-syn-02", threatId: "thr-syn-04", relationshipConfidence: "confirmed", attributionType: "Primary Operator", createdAt: new Date() },
    { id: "tat-syn-05", threatActorId: "act-syn-02", threatId: "thr-syn-05", relationshipConfidence: "confirmed", attributionType: "Payload Developer", createdAt: new Date() },
    { id: "tat-syn-06", threatActorId: "act-syn-03", threatId: "thr-syn-07", relationshipConfidence: "confirmed", attributionType: "Primary Operator", createdAt: new Date() },
    { id: "tat-syn-07", threatActorId: "act-syn-03", threatId: "thr-syn-08", relationshipConfidence: "probable", attributionType: "Exploit Developer", createdAt: new Date() },
    { id: "tat-syn-08", threatActorId: "act-syn-04", threatId: "thr-syn-09", relationshipConfidence: "confirmed", attributionType: "Primary Operator", createdAt: new Date() },
    { id: "tat-syn-09", threatActorId: "act-syn-05", threatId: "thr-syn-10", relationshipConfidence: "suspected", attributionType: "Affiliated Group", createdAt: new Date() }
  ];

  const threatActorIocsList = [
    { id: "tai-syn-01", threatActorId: "act-syn-01", iocId: "ioc-syn-01", relationshipConfidence: "confirmed", context: "Command and Control Proxy Node", createdAt: new Date() },
    { id: "tai-syn-02", threatActorId: "act-syn-01", iocId: "ioc-syn-02", relationshipConfidence: "confirmed", context: "Secondary C2 Listener", createdAt: new Date() },
    { id: "tai-syn-03", threatActorId: "act-syn-01", iocId: "ioc-syn-03", relationshipConfidence: "confirmed", context: "Phishing & Exfiltration Domain", createdAt: new Date() },
    { id: "tai-syn-04", threatActorId: "act-syn-01", iocId: "ioc-syn-04", relationshipConfidence: "confirmed", context: "PowerShell Stager Dropper Hash", createdAt: new Date() },
    { id: "tai-syn-05", threatActorId: "act-syn-01", iocId: "ioc-syn-05", relationshipConfidence: "confirmed", context: "Weaponized OAuth Exploit", createdAt: new Date() },
    { id: "tai-syn-06", threatActorId: "act-syn-02", iocId: "ioc-syn-06", relationshipConfidence: "confirmed", context: "Exfiltration Staging Host", createdAt: new Date() },
    { id: "tai-syn-07", threatActorId: "act-syn-02", iocId: "ioc-syn-07", relationshipConfidence: "confirmed", context: "PsExec Distribution Node", createdAt: new Date() },
    { id: "tai-syn-08", threatActorId: "act-syn-02", iocId: "ioc-syn-08", relationshipConfidence: "confirmed", context: "Ransomware Binary Executable", createdAt: new Date() },
    { id: "tai-syn-09", threatActorId: "act-syn-02", iocId: "ioc-syn-09", relationshipConfidence: "confirmed", context: "PAN-OS Zero-Day Vulnerability", createdAt: new Date() },
    { id: "tai-syn-10", threatActorId: "act-syn-03", iocId: "ioc-syn-11", relationshipConfidence: "confirmed", context: "ICS Reconnaissance Tool", createdAt: new Date() },
    { id: "tai-syn-11", threatActorId: "act-syn-03", iocId: "ioc-syn-12", relationshipConfidence: "confirmed", context: "Ivanti Connect Secure Exploit", createdAt: new Date() },
    { id: "tai-syn-12", threatActorId: "act-syn-04", iocId: "ioc-syn-14", relationshipConfidence: "confirmed", context: "DDoS Botnet Gateway", createdAt: new Date() }
  ];

  const threatActorIncidentsList = [
    { id: "tainc-syn-01", threatActorId: "act-syn-01", incidentId: "inc-syn-01", confidence: 95, createdAt: new Date() },
    { id: "tainc-syn-02", threatActorId: "act-syn-01", incidentId: "inc-syn-02", confidence: 85, createdAt: new Date() },
    { id: "tainc-syn-03", threatActorId: "act-syn-02", incidentId: "inc-syn-03", confidence: 94, createdAt: new Date() },
    { id: "tainc-syn-04", threatActorId: "act-syn-02", incidentId: "inc-syn-04", confidence: 90, createdAt: new Date() },
    { id: "tainc-syn-05", threatActorId: "act-syn-03", incidentId: "inc-syn-05", confidence: 92, createdAt: new Date() },
    { id: "tainc-syn-06", threatActorId: "act-syn-04", incidentId: "inc-syn-06", confidence: 80, createdAt: new Date() }
  ];

  const campaignThreatsList = [
    { id: "cth-syn-01", campaignId: "cmp-syn-01", threatId: "thr-syn-01", relationshipConfidence: "confirmed", createdAt: new Date() },
    { id: "cth-syn-02", campaignId: "cmp-syn-01", threatId: "thr-syn-02", relationshipConfidence: "confirmed", createdAt: new Date() },
    { id: "cth-syn-03", campaignId: "cmp-syn-02", threatId: "thr-syn-04", relationshipConfidence: "confirmed", createdAt: new Date() },
    { id: "cth-syn-04", campaignId: "cmp-syn-02", threatId: "thr-syn-05", relationshipConfidence: "confirmed", createdAt: new Date() },
    { id: "cth-syn-05", campaignId: "cmp-syn-03", threatId: "thr-syn-07", relationshipConfidence: "confirmed", createdAt: new Date() },
    { id: "cth-syn-06", campaignId: "cmp-syn-04", threatId: "thr-syn-09", relationshipConfidence: "confirmed", createdAt: new Date() }
  ];

  const campaignIocsList = [
    { id: "cioc-syn-01", campaignId: "cmp-syn-01", iocId: "ioc-syn-01", relationshipConfidence: "confirmed", createdAt: new Date() },
    { id: "cioc-syn-02", campaignId: "cmp-syn-01", iocId: "ioc-syn-02", relationshipConfidence: "confirmed", createdAt: new Date() },
    { id: "cioc-syn-03", campaignId: "cmp-syn-01", iocId: "ioc-syn-03", relationshipConfidence: "confirmed", createdAt: new Date() },
    { id: "cioc-syn-04", campaignId: "cmp-syn-01", iocId: "ioc-syn-04", relationshipConfidence: "confirmed", createdAt: new Date() },
    { id: "cioc-syn-05", campaignId: "cmp-syn-02", iocId: "ioc-syn-06", relationshipConfidence: "confirmed", createdAt: new Date() },
    { id: "cioc-syn-06", campaignId: "cmp-syn-02", iocId: "ioc-syn-07", relationshipConfidence: "confirmed", createdAt: new Date() },
    { id: "cioc-syn-07", campaignId: "cmp-syn-02", iocId: "ioc-syn-08", relationshipConfidence: "confirmed", createdAt: new Date() },
    { id: "cioc-syn-08", campaignId: "cmp-syn-02", iocId: "ioc-syn-09", relationshipConfidence: "confirmed", createdAt: new Date() },
    { id: "cioc-syn-09", campaignId: "cmp-syn-03", iocId: "ioc-syn-11", relationshipConfidence: "confirmed", createdAt: new Date() },
    { id: "cioc-syn-10", campaignId: "cmp-syn-03", iocId: "ioc-syn-12", relationshipConfidence: "confirmed", createdAt: new Date() },
    { id: "cioc-syn-11", campaignId: "cmp-syn-04", iocId: "ioc-syn-14", relationshipConfidence: "confirmed", createdAt: new Date() }
  ];

  const campaignIncidentsList = [
    { id: "cinc-syn-01", campaignId: "cmp-syn-01", incidentId: "inc-syn-01", confidence: 95, createdAt: new Date() },
    { id: "cinc-syn-02", campaignId: "cmp-syn-02", incidentId: "inc-syn-03", confidence: 96, createdAt: new Date() },
    { id: "cinc-syn-03", campaignId: "cmp-syn-03", incidentId: "inc-syn-05", confidence: 90, createdAt: new Date() },
    { id: "cinc-syn-04", campaignId: "cmp-syn-04", incidentId: "inc-syn-06", confidence: 85, createdAt: new Date() }
  ];

  const campaignMitreTechniquesList = [
    { id: "cmt-syn-01", campaignId: "cmp-syn-01", techniqueId: "T1566.001", techniqueName: "Spearphishing Attachment", tactic: "Initial Access", confidence: 95, createdAt: new Date() },
    { id: "cmt-syn-02", campaignId: "cmp-syn-01", techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "Execution", confidence: 92, createdAt: new Date() },
    { id: "cmt-syn-03", campaignId: "cmp-syn-01", techniqueId: "T1528", techniqueName: "Steal Application Access Token", tactic: "Credential Access", confidence: 96, createdAt: new Date() },
    { id: "cmt-syn-04", campaignId: "cmp-syn-01", techniqueId: "T1071.001", techniqueName: "Web Protocols (HTTPS C2)", tactic: "Command and Control", confidence: 90, createdAt: new Date() },
    { id: "cmt-syn-05", campaignId: "cmp-syn-02", techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access", confidence: 98, createdAt: new Date() },
    { id: "cmt-syn-06", campaignId: "cmp-syn-02", techniqueId: "T1486", techniqueName: "Data Encrypted for Impact", tactic: "Impact", confidence: 96, createdAt: new Date() },
    { id: "cmt-syn-07", campaignId: "cmp-syn-02", techniqueId: "T1490", techniqueName: "Inhibit System Recovery", tactic: "Impact", confidence: 94, createdAt: new Date() },
    { id: "cmt-syn-08", campaignId: "cmp-syn-02", techniqueId: "T1567", techniqueName: "Exfiltration Over Web Service", tactic: "Exfiltration", confidence: 90, createdAt: new Date() },
    { id: "cmt-syn-09", campaignId: "cmp-syn-03", techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access", confidence: 90, createdAt: new Date() },
    { id: "cmt-syn-10", campaignId: "cmp-syn-03", techniqueId: "T1046", techniqueName: "Network Service Discovery", tactic: "Discovery", confidence: 88, createdAt: new Date() },
    { id: "cmt-syn-11", campaignId: "cmp-syn-04", techniqueId: "T1498", techniqueName: "Network Denial of Service", tactic: "Impact", confidence: 92, createdAt: new Date() }
  ];

  return {
    reports: reportsList,
    threats: threatsList,
    entities: entitiesList,
    iocs: iocsList,
    incidents: incidentsList,
    recommendations: recommendationsList,
    predictions: predictionsList,
    analystNotes: analystNotesList,
    assets: assetsList,
    threatActors: threatActorsList,
    campaigns: campaignsList,
    threatActorThreats: threatActorThreatsList,
    threatActorIocs: threatActorIocsList,
    threatActorIncidents: threatActorIncidentsList,
    campaignThreats: campaignThreatsList,
    campaignIocs: campaignIocsList,
    campaignIncidents: campaignIncidentsList,
    campaignMitreTechniques: campaignMitreTechniquesList
  };
}


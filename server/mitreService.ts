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

export const MITRE_ATTACK_MATRIX: Record<string, MitreTechnique> = {
  "T1566": {
    id: "T1566",
    name: "Phishing",
    tactic: "Initial Access",
    tacticId: "TA0001",
    description: "Adversaries may send phishing messages with malicious attachments or links to gain initial access to victim systems.",
    detection: "Monitor inbound email telemetry for suspicious sender domains, SPF/DKIM/DMARC anomalies, and attachment analysis.",
    mitigation: "Deploy user awareness training, anti-spoofing gateway policies, and endpoint sandbox detestation.",
    url: "https://attack.mitre.org/techniques/T1566/",
    source: "MITRE ATT&CK Framework Enterprise v15"
  },
  "T1190": {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    tactic: "Initial Access",
    tacticId: "TA0001",
    description: "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands to cause unintended execution.",
    detection: "Inspect web application firewall (WAF) logs, reverse proxy errors, and unauthorized child processes spawned by web server processes.",
    mitigation: "Strict vulnerability management, rapid patching of internet-facing assets, and network segmentation.",
    url: "https://attack.mitre.org/techniques/T1190/",
    source: "MITRE ATT&CK Framework Enterprise v15"
  },
  "T1059": {
    id: "T1059",
    name: "Command and Scripting Interpreter",
    tactic: "Execution",
    tacticId: "TA0002",
    description: "Adversaries may abuse command and script interpreters (PowerShell, Bash, Python, Windows Command Shell) to execute arbitrary commands.",
    detection: "Enable script block logging (EID 4104), command line process tracking (EID 4688 / Sysmon EID 1), and audit obfuscated strings.",
    mitigation: "Restrict PowerShell execution policies, enforce Constrained Language Mode, and block unauthorized scripting tools with AppLocker/WDAC.",
    url: "https://attack.mitre.org/techniques/T1059/",
    source: "MITRE ATT&CK Framework Enterprise v15"
  },
  "T1078": {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "Defense Evasion / Initial Access",
    tacticId: "TA0005",
    description: "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
    detection: "Correlate atypical travel logins, simultaneous logins from divergent geographic IPs, and non-business hour privilege escalations.",
    mitigation: "Enforce phishing-resistant MFA (FIDO2/WebAuthn), just-in-time privileged access, and periodic credential rotation.",
    url: "https://attack.mitre.org/techniques/T1078/",
    source: "MITRE ATT&CK Framework Enterprise v15"
  },
  "T1486": {
    id: "T1486",
    name: "Data Encrypted for Impact",
    tactic: "Impact",
    tacticId: "TA0040",
    description: "Adversaries may encrypt data on target systems to interrupt availability to system and network resources (Ransomware).",
    detection: "Monitor sudden high-volume file rename/write operations across file shares, volume shadow copy deletions (vssadmin), and known ransom note generation.",
    mitigation: "Maintain immutable offline backups, restrict local admin privileges, and deploy behavioral anti-ransomware EDR rules.",
    url: "https://attack.mitre.org/techniques/T1486/",
    source: "MITRE ATT&CK Framework Enterprise v15"
  },
  "T1027": {
    id: "T1027",
    name: "Obfuscated Files or Information",
    tactic: "Defense Evasion",
    tacticId: "TA0005",
    description: "Adversaries may attempt to make an executable or file difficult to discover or analyze by encoding, encrypting, or packing payload contents.",
    detection: "Analyze entropy levels of binary sections, inspect encoded Base64 CLI arguments, and use memory scanning for unhooked DLLs.",
    mitigation: "Deploy AMSI (Antimalware Scan Interface) inspection and block untrusted packed binaries via EDR policies.",
    url: "https://attack.mitre.org/techniques/T1027/",
    source: "MITRE ATT&CK Framework Enterprise v15"
  },
  "T1071": {
    id: "T1071",
    name: "Application Layer Protocol",
    tactic: "Command and Control",
    tacticId: "TA0011",
    description: "Adversaries may communicate using application layer protocols (HTTP/S, DNS) to avoid detection/network filtering by blending in with existing traffic.",
    detection: "Inspect DNS query volume/entropy for tunneling, monitor outbound TLS connections to newly registered domains (NRDs), and analyze beaconing intervals.",
    mitigation: "Implement TLS interception with DPI, enforce web content filtering, and sinkhole suspicious dynamic DNS domains.",
    url: "https://attack.mitre.org/techniques/T1071/",
    source: "MITRE ATT&CK Framework Enterprise v15"
  },
  "T1003": {
    id: "T1003",
    name: "OS Credential Dumping",
    tactic: "Credential Access",
    tacticId: "TA0006",
    description: "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a cleartext password (e.g. LSASS dumping).",
    detection: "Alert on unauthorized handles opened to lsass.exe (Sysmon EID 10) and invocation of MiniDumpWriteDump or procdump.",
    mitigation: "Enable Windows Defender Credential Guard (LSA Protection) and disable WDigest authentication.",
    url: "https://attack.mitre.org/techniques/T1003/",
    source: "MITRE ATT&CK Framework Enterprise v15"
  },
  "T1567": {
    id: "T1567",
    name: "Exfiltration Over Web Service",
    tactic: "Exfiltration",
    tacticId: "TA0010",
    description: "Adversaries may exfiltrate data to an external web service or cloud storage provider (MEGA, Dropbox, AWS S3) rather than their own command and control server.",
    detection: "Monitor DLP alerts for large outbound POST requests and cloud storage upload API spikes from non-standard endpoints.",
    mitigation: "Enforce CASB (Cloud Access Security Broker) policies and restrict unapproved cloud storage destinations via egress filtering.",
    url: "https://attack.mitre.org/techniques/T1567/",
    source: "MITRE ATT&CK Framework Enterprise v15"
  },
  "T1218": {
    id: "T1218",
    name: "System Binary Proxy Execution",
    tactic: "Defense Evasion",
    tacticId: "TA0005",
    description: "Adversaries may bypass process and signature-based defenses by proxying execution of malicious code through signed binaries (LOLBins such as msiexec, rundll32, certutil).",
    detection: "Monitor command-line parent-child relationships and anomalous network connections initiated by native Windows utilities.",
    mitigation: "Enforce AppLocker/WDAC application control policies and enable PowerShell constrained language mode.",
    url: "https://attack.mitre.org/techniques/T1218/",
    source: "MITRE ATT&CK Framework Enterprise v15"
  },
  "T1539": {
    id: "T1539",
    name: "Steal Web Session Cookie",
    tactic: "Credential Access",
    tacticId: "TA0006",
    description: "Adversaries may steal web application session cookies to bypass multi-factor authentication and hijack authenticated browser sessions.",
    detection: "Correlate simultaneous session activity from disparate IP ranges and inspect browser storage access by non-browser processes.",
    mitigation: "Implement token binding, device compliance verification, short session lifespans, and phishing-resistant FIDO2 hardware keys.",
    url: "https://attack.mitre.org/techniques/T1539/",
    source: "MITRE ATT&CK Framework Enterprise v15"
  },
  "T1498": {
    id: "T1498",
    name: "Network Denial of Service",
    tactic: "Impact",
    tacticId: "TA0040",
    description: "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted services to users.",
    detection: "Monitor network boundary ingress traffic rates, packet-per-second anomalies, and SYN/UDP flood ratios.",
    mitigation: "Deploy cloud DDoS mitigation scrubbers, upstream BGP flowspec filtering, and ingress rate limiters.",
    url: "https://attack.mitre.org/techniques/T1498/",
    source: "MITRE ATT&CK Framework Enterprise v15"
  }
};

export function lookupMitreTechnique(identifierOrName: string): MitreTechnique | null {
  const clean = identifierOrName.trim().toUpperCase();
  // Check exact ID or substring ID (e.g. "T1566" or "T1566.001" or "T1566 - Phishing")
  for (const [id, tech] of Object.entries(MITRE_ATTACK_MATRIX)) {
    if (clean.includes(id) || clean.includes(tech.name.toUpperCase())) {
      return tech;
    }
  }
  return null;
}

export function getAllMitreTechniques(): MitreTechnique[] {
  return Object.values(MITRE_ATTACK_MATRIX);
}

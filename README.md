🛡️ ShieldZen
AI-Powered Cyber Threat Intelligence & Security Operations Platform

ShieldZen is an AI-assisted Cyber Threat Intelligence (CTI) and Security Operations platform designed to help security analysts collect, correlate, investigate, prioritize, and respond to cyber threats.

The platform combines external threat intelligence sources, vulnerability intelligence, IOC analysis, MITRE ATT&CK techniques, AI-assisted analysis, risk scoring, incident management, and security analytics into a unified interface.

📌 Overview

Modern cybersecurity teams receive information from many different sources:

Vulnerability databases
Threat intelligence feeds
Security reports
Indicators of compromise (IOCs)
Malware intelligence
Threat actor information
Security incidents
MITRE ATT&CK techniques

The challenge is not simply collecting this information, but correlating it and determining what actually matters.

ShieldZen aims to solve this problem by providing a centralized platform that can:

Collect → Extract → Correlate → Prioritize → Investigate → Respond

🎯 Objectives

The main objectives of ShieldZen are:

Centralize cyber threat intelligence from multiple sources.
Extract useful security information from threat reports.
Identify and manage Indicators of Compromise (IOCs).
Correlate vulnerabilities with known exploitation and threat intelligence.
Map threats to MITRE ATT&CK techniques.
Prioritize threats using explainable risk scoring.
Assist analysts using AI-powered threat analysis.
Track security incidents and their investigation lifecycle.
Provide visualization and analytics for security operations.
Support future integration with structured CTI standards such as STIX/TAXII.
🚀 Current Features

ShieldZen currently provides several cybersecurity intelligence capabilities.

🔍 Threat Intelligence
Threat intelligence dashboard
Threat reports
Threat severity classification
Threat categorization
Threat search and filtering
Threat intelligence analytics
🧩 IOC Intelligence

Support for multiple IOC types, including:

IP addresses
Domains
URLs
File hashes
CVEs
Filenames
Other extracted indicators
🧠 AI-Assisted Analysis

AI capabilities are used to assist with:

Threat report analysis
IOC extraction
Threat classification
Threat summaries
Security recommendations
Analyst assistance
🛡️ Vulnerability Intelligence

Integration with vulnerability intelligence sources including:

National Vulnerability Database (NVD)
CISA Known Exploited Vulnerabilities (KEV)

Vulnerabilities can be correlated with threat intelligence to improve prioritization.

🎯 MITRE ATT&CK

Threats can be associated with MITRE ATT&CK techniques to help analysts understand attacker behavior and tactics.

📊 Analytics

The platform provides security analytics including:

Threat trends
Severity distribution
Threat activity
Incident statistics
Risk information
🗺️ Threat Visualization

Threat activity can be visualized geographically to provide an overview of potential threat activity.

🚨 Incident Management

Security incidents can be created and tracked alongside associated threats, indicators, and recommendations.

🏗️ Planned Security Operations Features

ShieldZen is being continuously developed toward a more complete Security Operations platform.

The planned roadmap includes:

1. Asset Management

Track organizational assets and correlate them with:

Software
Vulnerabilities
Threats
IOCs
Exposure
Risk
2. Explainable Risk Scoring

A transparent risk engine will consider factors such as:

CVSS severity
Known exploitation
CISA KEV status
Asset criticality
Internet exposure
Threat activity
Recency
Exploit availability

The goal is to provide analysts with both a score and an explanation of why a threat is considered high risk.

3. IOC Investigation

Analysts will be able to investigate an IOC and discover relationships with:

Threats
Reports
Malware
Campaigns
Threat actors
Other IOCs
Vulnerabilities
4. Incident Response Workflow

Incidents will follow a structured lifecycle:

New
 ↓
Triage
 ↓
Investigation
 ↓
Containment
 ↓
Eradication
 ↓
Recovery
 ↓
Closed

5. AI SOC Analyst

An AI-assisted SOC analyst will help security analysts:

Investigate threats
Explain risk
Summarize incidents
Recommend actions
Identify related IOCs
Prioritize investigations
6. Threat Knowledge Graph

A relationship graph will connect:

Threat Actor
      ↓
Campaign
      ↓
Malware
      ↓
IOC
      ↓
Threat
      ↓
Vulnerability
      ↓
Asset

7. MITRE ATT&CK Attack-Chain Visualization

Threat activity will be visualized using MITRE ATT&CK tactics and techniques to help analysts understand possible attack chains.

8. Real-Time Alerts

The platform will support configurable alerts for events such as:

Critical vulnerabilities
CISA KEV matches
High-risk assets
New IOCs
Emerging threats
Suspicious activity
9. AI Evaluation

AI capabilities will be evaluated using metrics such as:

Accuracy
Precision
Recall
F1 Score
Confusion Matrix
10. STIX/TAXII Integration

Future versions will support structured threat intelligence standards such as:

STIX 2.x
TAXII
🧱 System Architecture

The planned architecture follows this general workflow:

                   ┌───────────────────────┐
                   │  Intelligence Sources │
                   └───────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
             NVD              CISA            MITRE
              │                │                │
              └────────────────┼────────────────┘
                               │
                               ▼
                   ┌────────────────────┐
                   │ Intelligence       │
                   │ Normalization      │
                   └─────────┬──────────┘
                             │
                             ▼
                   ┌────────────────────┐
                   │ AI / NLP Analysis  │
                   └─────────┬──────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
             IOCs          Threats        Entities
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                   ┌────────────────────┐
                   │ Correlation Engine │
                   └─────────┬──────────┘
                             │
                             ▼
                   ┌────────────────────┐
                   │ Risk Prioritization│
                   └─────────┬──────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
           Alerts        Incidents       Analytics
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                   ┌────────────────────┐
                   │ SOC Analyst        │
                   │ Dashboard          │
                   └────────────────────┘

🛠️ Technology Stack
Frontend
React
TypeScript
Vite
Tailwind CSS
shadcn/ui
Recharts
React Leaflet
Backend
Node.js
Express
TypeScript
Database
SQLite
Drizzle ORM
AI
Google Gemini
Cybersecurity Intelligence
NVD
CISA KEV
MITRE ATT&CK
📂 Project Structure
.
├── src/
│   ├── components/
│   ├── pages/
│   ├── db/
│   ├── hooks/
│   └── ...
│
├── server/
│   ├── correlationEngine.ts
│   ├── nvdService.ts
│   └── ...
│
├── public/
│
├── package.json
├── drizzle.config.ts
├── vite.config.ts
└── README.md

⚙️ Installation
1. Clone the repository
git clone https://github.com/koushik-hub-25/3rd-yr-MiniProject-.git
cd 3rd-yr-MiniProject-

2. Install dependencies
npm install

3. Configure environment variables

Create a .env file in the project root.

Example:

DATABASE_URL=./data/shieldzen.db

GEMINI_API_KEY=your_gemini_api_key

NVD_API_KEY=your_nvd_api_key


Never commit API keys or secrets to GitHub.

4. Start the development server
npm run dev


The application should then be available through the local development URL shown by Vite.

🔐 Environment Variables
Variable	Description	Required
DATABASE_URL	SQLite database location	Yes
GEMINI_API_KEY	Google Gemini API key	Optional
NVD_API_KEY	NVD API key	Optional

Actual environment variable requirements may change as the project develops.

🧪 Testing

Testing infrastructure is being expanded as part of the project roadmap.

Planned testing areas include:

Unit tests
API tests
Risk scoring tests
IOC extraction tests
Authentication tests
Integration tests
Frontend component tests
🔒 Security Considerations

ShieldZen is a cybersecurity-focused application, therefore application security is an important part of the project.

Planned security improvements include:

Secure authentication
Role-based access control
Input validation
File upload validation
API rate limiting
Security headers
Audit logging
Secure secret management
Error handling
Dependency security checks
📈 Development Roadmap
Feature	Status
Threat Intelligence Dashboard	✅
IOC Management	✅
NVD Integration	✅
CISA KEV Integration	✅
MITRE ATT&CK Integration	✅
AI-Assisted Analysis	✅
Threat Analytics	✅
Incident Management	✅
Asset Management	🚧
Explainable Risk Engine	🚧
IOC Relationship Graph	🚧
Incident Response Workflow	🚧
AI SOC Analyst	🚧
Threat Knowledge Graph	🚧
ATT&CK Attack Chain	🚧
Real-Time Alerts	🚧
AI Evaluation	🚧
STIX/TAXII	🔮

Legend:

✅ Implemented
🚧 In Development
🔮 Planned
🎓 Academic Scope

ShieldZen is being developed as a third-year mini-project with a focus on combining:

Cyber Threat Intelligence
Artificial Intelligence
Natural Language Processing
Vulnerability Intelligence
Threat Correlation
Risk Analysis
Security Operations
Data Visualization

The project is intended as an educational cybersecurity platform and should not be considered a production-ready security product without additional security testing and hardening.

🔮 Future Scope

Future development may include:

Machine-learning-based threat classification
Advanced anomaly detection
Threat actor profiling
Automated response playbooks
SIEM integration
SOAR integration
EDR integration
STIX/TAXII feeds
Advanced threat hunting
Threat intelligence sharing
Cloud security intelligence
Container security intelligence
👨‍💻 Development

ShieldZen is actively being developed and improved.

The project follows an incremental development approach where new security intelligence, analytics, automation, and investigation capabilities are added and tested progressively.

⚠️ Disclaimer

ShieldZen is an educational cybersecurity project.

Threat intelligence, vulnerability information, AI-generated analysis, and recommendations should be independently verified before being used for real-world security decisions.

Do not use the platform to conduct unauthorized security testing, exploitation, scanning, or other malicious activity.

📄 License

Add the project's chosen license here before public distribution.

⭐ Project Goal

The long-term goal of ShieldZen is to provide a unified platform that transforms large amounts of cyber threat intelligence into actionable, explainable security decisions.

Collect
   ↓
Understand
   ↓
Correlate
   ↓
Prioritize
   ↓
Investigate
   ↓
Respond


ShieldZen — Turning Cyber Threat Intelligence into Actionable Security Intelligence.

<div align="center">
<img width="120" height="120" alt="Shield Logo" src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/shield.svg" />
</div>

# ThreatWeave

**Multi-Resource Cyber Threat Intelligence Correlation Engine**

ThreatWeave is an advanced, AI-powered security operations dashboard built to help SOC (Security Operations Center) analysts triage, correlate, and respond to cyber threats at machine speed. By leveraging the **Google Gemini AI API**, ThreatWeave ingests fragmented telemetry from firewalls, EDRs, active directories, and phishing gateways, and weaves them together into cohesive, explainable attack campaigns.

## ✨ Core Features & What Works Today

### 1. 🧠 AI Threat Ingest Hub & Correlation Engine
* **Raw SIEM Log Parsing:** Paste raw, disjointed firewall alerts, syslog transcripts, or AWS CloudTrail logs directly into the engine.
* **Gemini-Powered Intelligence:** The backend uses the Gemini 3.5 Flash model to extract structured security incidents and hunt for overlapping techniques, IP addresses, hashes, or temporal linkages to identify coordinated multi-stage attacks.
* **Pre-built Attack Scenarios:** Instantly test the engine using built-in simulated data templates (e.g., *Conti Ransomware* or *AWS Cloud Leak*).

### 2. 🕸️ Interactive Threat Graph & Dashboard
* **Dynamic Node Association Map:** A deterministic, interactive SVG orbit map visually links central Threat Campaigns to individual Alerts, and maps those alerts down to granular Indicators of Compromise (IOCs).
* **Explainable AI (XAI):** A dedicated panel provides a plain-English explanation of exactly *why* the AI decided to link specific logs together, establishing confidence and trust.
* **Recommended Security Playbook:** The AI automatically generates a checklist of tactical incident response actions to mitigate the identified threat.

### 3. 📡 Real-Time Webhook Ingestion & SSE Streaming
* **Live Ingested Feed Stream:** The frontend maintains a live Server-Sent Events (SSE) connection to the backend.
* **API Webhook:** External systems can send real-time alerts by firing a `POST` request to `/api/ingest`. The UI instantly updates to display the incoming telemetry without a page refresh!

### 4. 🕵️ APT Catalog (Threat Actor Dossiers)
* A federated catalog of simulated OSINT threat databases, allowing analysts to review signature TTPs, target sectors, and aliases of known Advanced Persistent Threat actors.

---

## 🚀 Run Locally

**Prerequisites:** Node.js (v18+)

### 1. Install dependencies:
```bash
npm install
```

### 2. Configure Environment:
Set your `GEMINI_API_KEY` in `.env` or `.env.local`:
```bash
GEMINI_API_KEY="your_api_key_here"
```
*(Note: If you do not provide a key, the application will still launch in a "Simulated Mode" displaying mock graphs and data, but live AI correlation will be disabled).*

### 3. Run the Development Server:
```bash
npm run dev
```
The server will boot up and the UI will be accessible at **http://localhost:3001**.

### 4. Test the Real-Time Log Ingestion Webhook:
While the server is running, open a new PowerShell terminal and run the following command to see a live log instantly appear on the dashboard feed:
```powershell
Invoke-RestMethod -Uri "http://localhost:3001/api/ingest" -Method Post -ContentType "application/json" -Body '{"title": "Test Alert", "severity": "HIGH", "sourceSystem": "Firewall", "description": "Suspicious request blocked", "iocs": "192.168.1.100"}'
```

## 🏗️ Tech Stack
* **Frontend:** React, TailwindCSS v4, Vite, Lucide Icons
* **Backend:** Node.js, Express, Server-Sent Events (SSE)
* **AI:** `@google/genai` SDK (Gemini 3.5 Flash)

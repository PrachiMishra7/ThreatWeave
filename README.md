# ThreatWeave

ThreatWeave is an intelligent security operations tool that leverages AI to parse, correlate, and analyze raw security logs and alerts to identify coordinated campaigns.

## ✨ Core Features & What Works Today

**Prerequisites:** Node.js

1. Install dependencies:
   ```bash
   npm install
   ```

2. Configure Environment:
   Set your `GEMINI_API_KEY` in `.env.local` or `.env`:
   ```bash
   GEMINI_API_KEY="your_api_key_here"
   ```

3. Run in development mode:
   ```bash
   npm run dev
   ```

4. Build and run for production:
   ```bash
   npm run build
   npm start
   ```
ThreatWeave
ThreatWeave is an AI-powered cybersecurity platform that correlates security logs into attack campaigns and visualizes relationships using a Neo4j knowledge graph.

Setup
Install Dependencies
npm install
Configure Environment Variables
Create a .env.local file:

GROQ_API_KEY=<your_groq_api_key>

NEO4J_URI=<your_neo4j_uri>
NEO4J_USERNAME=<your_neo4j_username>
NEO4J_PASSWORD=<your_neo4j_password>
⚠️ Never commit real credentials to GitHub.

Run Development Server
npm run dev
Threat Correlation API
Endpoint
POST /api/gemini/correlate
Sample Request
Invoke-RestMethod `
  -Uri "http://localhost:3001/api/gemini/correlate" `
  -Method POST `
  -ContentType "application/json" `
  -Body '{
    "logs": "[Firewall] Failed login from 185.220.101.5 targeting admin account. [Proxy] User admin accessed evil-login.com. [EDR] PowerShell execution detected."
  }'
Neo4j Graph Model
Campaign
 ├── CONTAINS ──► Alert
 │                 ├── USES ──► IP
 │                 ├── USES ──► Domain
 │                 └── USES ──► User
 │
 └── USES_TACTIC ──► MitreTactic
Verification Queries
View Complete Graph
MATCH (n)-[r]->(m)
RETURN n,r,m
LIMIT 100
View MITRE Mapping
MATCH (c:Campaign)-[:USES_TACTIC]->(m:MitreTactic)
RETURN c.name, m.name
Current Features
AI Threat Correlation

Campaign Generation

MITRE ATT&CK Mapping

IOC Extraction (IPs, Domains, Users)

Neo4j Graph Persistence

Dynamic Relationship Generation
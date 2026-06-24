import dotenv from "dotenv";
dotenv.config();

// Bypass SSL certificate errors for local development (fixes UNABLE_TO_VERIFY_LEAF_SIGNATURE)
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Patch BigInt serialization for Neo4j driver results
(BigInt.prototype as any).toJSON = function () {
  return this.toString();
};

import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import Groq from "groq-sdk";
import { EventEmitter } from "events";
import {
  saveThreatGraph,
  getThreatGraph,
  getNodes,
  getCampaigns,
  getCampaignByName,
  getAlerts,
  getLiveFeed,
  getEnrichedNeo4jCampaigns,
  executeCypherQuery
} from "./graph/threatGraph";

// V-module: Correlation Engine
import { getAlertStore, addAlert, getAlertStats } from "./backend/alertStore";
import { generateCampaigns } from "./backend/correlation/correlation_service";

// Threat Intelligence module imports
import threatIntelRouter from "./threat-intel/router";
import { startIngestion } from "./threat-intel/ingestionService";
const app = express();
const PORT = Number(process.env.PORT) || 3001;

// Global event emitter for log streaming
const logEmitter = new EventEmitter();

// Parse json bodies
app.use(express.json({ limit: "10mb" }));

// Handle JSON parsing errors so the server doesn't crash on bad inputs
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (err instanceof SyntaxError && 'body' in err) {
    console.error("JSON parsing error from client payload:", err.message);
    return res.status(400).json({ error: "Invalid JSON payload format. Please check your quotes/escaping." });
  }
  next(err);
});

// Helper to initialize Gemini safely
const getGroqClient = () => {
  const apiKey = process.env.GROQ_API_KEY;

  if (!apiKey || apiKey.trim() === "") {
    return null;
  }

  return new Groq({
    apiKey,
  });
};

// Check API status
app.get("/api/health", (req, res) => {
  const hasKey =
    !!process.env.GROQ_API_KEY &&
    process.env.GROQ_API_KEY.trim() !== "";

  res.json({
    status: "ok",
    hasApiKey: hasKey,
    environment: process.env.NODE_ENV || "development"
  });
});

// Endpoint to ingest raw logs
app.post("/api/ingest", (req, res) => {
  try {
    const logData = req.body;
    if (!logData || Object.keys(logData).length === 0) {
      return res.status(400).json({ error: "Empty log payload." });
    }

    // Assign default structure
    const newLog = {
      id: `ingest-${Date.now()}`,
      timestamp: logData.timestamp || new Date().toISOString(),
      sourceSystem: logData.sourceSystem || "API Webhook",
      severity: logData.severity || "MEDIUM",
      title: logData.title || "External System Alert",
      description: logData.description || JSON.stringify(logData),
      iocs: Array.isArray(logData.iocs) ? logData.iocs : [],
      affectedAsset: logData.affectedAsset || "Unknown",
      actionTaken: logData.actionTaken || "alerted",
      mitreTTPs: logData.mitreTTPs || [],
    };

    // Feed into the correlation alert store so it affects campaign generation
    addAlert(newLog as any);

    // Emit event to connected SSE clients (Live Feed page)
    logEmitter.emit("new_log", newLog);

    res.status(201).json({ status: "success", message: "Log ingested and added to correlation store.", log: newLog });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Endpoint for SSE stream
app.get("/api/stream/logs", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  // Send an initial connected ping
  res.write(`data: ${JSON.stringify({ status: "connected" })}\n\n`);

  const onNewLog = (log: any) => {
    res.write(`data: ${JSON.stringify(log)}\n\n`);
  };

  logEmitter.on("new_log", onNewLog);

  req.on("close", () => {
    logEmitter.off("new_log", onNewLog);
  });
});
app.get("/api/test-graph", async (req, res) => {
  await saveThreatGraph({
  campaignProposedName: "ShadowFox",
  threatActor: "APT29",

  extractedAlerts: [
      {
        id: "A1",
        title: "Malicious Login",
        severity: "HIGH",
        sourceSystem: "Firewall",

        iocs: [
          {
            type: "IP",
            value: "185.220.101.5"
          },
          {
            type: "Domain",
            value: "evil-login.com"
          },
          {
            type: "User",
            value: "admin"
          }
        ]
      }
    ],

    correlations: []
  });

  res.json({
    success: true
  });
});

// Endpoint to correlate alerts or raw logs
app.post("/api/gemini/correlate", async (req, res) => {
  try {
    const ai = getGroqClient();

if (!ai) {
  return res.status(500).json({
    error: "Groq API key is missing."
  });
}

    const { logs, systemContext } = req.body;
    if (!logs) {
      return res.status(400).json({ error: "No threat logs provided for correlation analysis." });
    }

    const logString = typeof logs === "string" ? logs : JSON.stringify(logs, null, 2);

    const promptText = `
    You are a principal Security Analyst and AI correlation expert at a security operations center.
    You are analyzing a set of raw security alerts, log strings, and Indicators of Compromise (IOCs).
    
    TASK:
    1. Parse the log data and extract any security incidents/alerts as structured records.
    2. Correlate these parsed alerts by identifying connections between them (e.g. same source IP, same destination subnet, overlapping attacker techniques, matching hashes, sequential active directories logins, temporal linkages).
    3. Determine if they are part of a coordinated campaign. If so, propose a threat campaign name, map the MITRE ATT&CK tactics, and provide a plain English explanation of why they are linked (Explainable AI Layer).
    4. Provide tactical recommendation response actions for the security engineering team to mitigate the attack quickly.

    Analyze the following input logs:
    """
    ${logString}
    """

    ${systemContext ? `Additional System Context/Feeds:\n${systemContext}` : ""}
    `;
const response = await ai.chat.completions.create({
  model: "llama-3.3-70b-versatile",

  messages: [
    {
      role: "system",
      content:
        "You are the ThreatWeave Cyber Threat Intelligence correlation engine. Return ONLY valid JSON. Do not return markdown."
    },
    {
      role: "user",
      content: promptText
    }
  ],

  temperature: 0.2
});

const textOutput =
  response.choices[0]?.message?.content || "{}";

const cleanedOutput = textOutput
  .replace(/```json/g, "")
  .replace(/```/g, "")
  .trim();
console.log("GROQ RAW RESPONSE:");
console.log(textOutput);
const result = JSON.parse(cleanedOutput);

await saveThreatGraph(result);

    res.json(result);
  } catch (error: any) {
    console.error("AI correlation error:", error);
    res.status(500).json({ error: error.message || "An error occurred during log correlation modeling." });
  }
});

// Endpoint for the Chatbot
app.post("/api/chat", async (req, res) => {
  try {
    const ai = getGroqClient();

    if (!ai) {
      return res.status(500).json({
        error: "Groq API key is missing."
      });
    }

    const { messages } = req.body;
    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: "Messages array is required." });
    }

    const response = await ai.chat.completions.create({
      model: "llama-3.3-70b-versatile",
      messages: messages,
      temperature: 0.7
    });

    const textOutput = response.choices[0]?.message?.content || "";
    res.json({ reply: textOutput });
  } catch (error: any) {
    console.error("Chat error:", error);
    res.status(500).json({ error: error.message || "An error occurred during chat generation." });
  }
});

app.get("/api/graph", async (req, res) => {
  try {
    const graph = await getThreatGraph();
    res.json(graph);
  } catch (err: any) {
    console.error("Neo4j connection failed, dynamically generating graph from memory store.");
    
    const alerts = getAlertStore();
    const campaigns = generateCampaigns(alerts);
    
    const nodes: any[] = [];
    const edges: any[] = [];
    let edgeIdCounter = 0;
    
    campaigns.forEach((camp, index) => {
      // Add Campaign Node
      nodes.push({ id: camp.id, label: camp.name, type: "Campaign", properties: { threatActor: camp.threatActor, riskScore: camp.riskScore, confidence: camp.confidence, summary: camp.summary } });
      
      // Add Threat Actor Node
      const actorId = `actor-${camp.threatActor}`;
      nodes.push({ id: actorId, label: camp.threatActor, type: "ThreatActor", properties: {} });
      edges.push({ id: `e-${edgeIdCounter++}`, source: actorId, target: camp.id, label: "ATTRIBUTED_TO" });
      
      // Add Alert Nodes & link to Campaign
      (camp.relatedAlertIds || []).forEach(alertId => {
         const alert = alerts.find(a => a.id === alertId);
         if (alert) {
            nodes.push({ id: alert.id, label: alert.title, type: "Alert", properties: { id: alert.id, severity: alert.severity, sourceSystem: alert.sourceSystem, description: alert.description } });
            edges.push({ id: `e-${edgeIdCounter++}`, source: camp.id, target: alert.id, label: "CONTAINS" });
            
            // Add IOCs & link to Alert
            if (alert.iocs && Array.isArray(alert.iocs)) {
               alert.iocs.forEach(ioc => {
                  const iocId = `ioc-${ioc.value}`;
                  nodes.push({ id: iocId, label: ioc.value, type: ioc.type || "UnknownIOC", properties: { value: ioc.value } });
                  edges.push({ id: `e-${edgeIdCounter++}`, source: alert.id, target: iocId, label: "USES" });
               });
            }
         }
      });
    });
    
    // De-duplicate nodes
    const uniqueNodes = Array.from(new Map(nodes.map(item => [item.id, item])).values());
    
    res.json({ nodes: uniqueNodes, edges });
  }
});

app.post("/api/graph/query", async (req, res) => {
  try {
    const { query } = req.body;
    if (!query) {
      return res.status(400).json({ error: "Cypher query is required" });
    }
    const graphData = await executeCypherQuery(query);
    res.json(graphData);
  } catch (err: any) {
    console.error("Custom query failed:", err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/graph/query", async (req, res) => {
  try {
    const { query } = req.body;
    if (!query) {
      return res.status(400).json({ error: "Cypher query is required" });
    }
    const graphData = await executeCypherQuery(query);
    res.json(graphData);
  } catch (err: any) {
    console.error("Custom query failed:", err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/nodes", async (req, res) => {
  try {
    const nodes = await getNodes();
    res.json(nodes);
  } catch (err: any) {
    res.status(500).json({
      error: err.message
    });
  }
});app.get("/api/campaigns", async (req, res) => {
  try {
    const campaigns = await getCampaigns();
    res.json(campaigns);
  } catch (err: any) {
    res.status(500).json({
      error: err.message
    });
  }
});

app.get("/api/campaign/:name", async (req, res) => {
  try {
    const campaign = await getCampaignByName(
      req.params.name
    );

    if (!campaign) {
      return res.status(404).json({
        error: "Campaign not found"
      });
    }

    res.json(campaign);
  } catch (err: any) {
    res.status(500).json({
      error: err.message
    });
  }
});
app.get("/api/alerts", async (req, res) => {
  try {
    const alerts = await getAlerts();
    res.json(alerts);
  } catch (err: any) {
    res.status(500).json({
      error: err.message
    });
  }
});
app.get("/api/live-feed", async (req, res) => {
  try {
    const feed = await getLiveFeed();
    res.json(feed);
  } catch (err: any) {
    res.status(500).json({
      error: err.message
    });
  }
});

// ─── V-Module: Real Correlation Engine Endpoints ────────────────────────────

/**
 * Helper to fetch in-memory campaigns and Neo4j graph campaigns, and merge them.
 */
async function getMergedCampaigns(): Promise<any[]> {
  const alerts = getAlertStore();
  const inMemoryCampaigns = generateCampaigns(alerts);
  
  let neo4jCampaigns: any[] = [];
  try {
    neo4jCampaigns = await getEnrichedNeo4jCampaigns();
  } catch (err: any) {
    console.warn("[V-Module] Failed to fetch campaigns from Neo4j, using rule-based only:", err.message);
  }

  const mergedCampaigns = [...inMemoryCampaigns];
  
  for (const neoCamp of neo4jCampaigns) {
    const existingIdx = mergedCampaigns.findIndex(
      c => c.name.toLowerCase() === neoCamp.name.toLowerCase()
    );
    if (existingIdx >= 0) {
      const existing = mergedCampaigns[existingIdx];
      mergedCampaigns[existingIdx] = {
        ...existing,
        ...neoCamp,
        riskScore: Math.max(existing.riskScore, neoCamp.riskScore),
        confidence: Math.max(existing.confidence, neoCamp.confidence),
        relatedAlertIds: Array.from(new Set([...existing.relatedAlertIds, ...neoCamp.relatedAlertIds])),
        alertsCount: Math.max(existing.alertsCount, neoCamp.alertsCount),
        iocsCount: Math.max(existing.iocsCount, neoCamp.iocsCount),
        ttps: Array.from(new Set([...existing.ttps, ...neoCamp.ttps])),
      };
    } else {
      mergedCampaigns.push(neoCamp);
    }
  }

  // Sort by riskScore descending
  return mergedCampaigns.sort((a, b) => b.riskScore - a.riskScore);
}

/**
 * GET /api/v/campaigns
 * Runs the full correlation pipeline on the alert store and returns
 * dynamically generated AttackCampaign objects.
 */
app.get("/api/v/campaigns", async (req, res) => {
  try {
    const campaigns = await getMergedCampaigns();
    res.json(campaigns);
  } catch (err: any) {
    console.error("[V-Module] Campaign generation error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/v/alerts
 * Returns all alerts currently in the correlation store as SecurityAlert[].
 */
app.get("/api/v/alerts", (req, res) => {
  try {
    const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 100;
    const alerts = getAlertStore().slice(0, limit);
    res.json(alerts);
  } catch (err: any) {
    console.error("[V-Module] Alert store fetch error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/v/stats
 * Returns alert severity counts and system-level risk score derived from the store.
 */
app.get("/api/v/stats", async (req, res) => {
  try {
    const alerts = getAlertStore();
    const campaigns = await getMergedCampaigns();
    const severityCounts = getAlertStats();
    const systemRiskScore = campaigns.length > 0 ? Math.max(...campaigns.map(c => c.riskScore)) : 0;
    res.json({
      totalAlerts: alerts.length,
      activeCampaigns: campaigns.length,
      systemRiskScore,
      severityCounts,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Mount Threat Intelligence API router
app.use("/api/threat-intel", threatIntelRouter);

// Configure Vite middleware or Static files
async function initServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`ThreatWeave server booting... listening at http://localhost:${PORT}`);

    // Start the background threat intelligence ingestion service.
    // Runs immediately on startup, then repeats every INGESTION_INTERVAL_HOURS (default: 6h).
    startIngestion(logEmitter);
  });
}

initServer().catch((err) => {
  console.error("Server startup crash:", err);
});

import dotenv from "dotenv";
dotenv.config();

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
  getLiveFeed
} from "./graph/threatGraph";
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
  next();
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
      timestamp: logData.timestamp || new Date().toISOString(),
      sourceSystem: logData.sourceSystem || "API Webhook",
      severity: logData.severity || "MEDIUM",
      title: logData.title || "External System Alert",
      description: logData.description || JSON.stringify(logData),
      iocs: logData.iocs || "N/A"
    };

    // Emit event to connected clients
    logEmitter.emit("new_log", newLog);

    res.status(201).json({ status: "success", message: "Log ingested.", log: newLog });
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
app.get("/api/graph", async (req, res) => {
  try {
    const graph = await getThreatGraph();
    res.json(graph);
  } catch (err: any) {
    res.status(500).json({
      error: err.message
    });
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
  });
}

initServer().catch((err) => {
  console.error("Server startup crash:", err);
});

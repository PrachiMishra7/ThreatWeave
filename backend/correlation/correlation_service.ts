import { SecurityAlert, AttackCampaign, IOCType } from "../../src/types";
import { evaluateRules } from "./rules";
import { calculateRisk } from "./risk_engine";
import { detectCampaign, classifyAlert } from "./campaign_engine";
import { buildTimeline } from "./timeline_builder";

export interface CorrelationResult {
  attackType: string;
  campaignName: string;
  confidence: number;
  score: number;
  riskLevel: "Low" | "Medium" | "High" | "Critical";
  timeline: string[];
}

/**
 * Main Orchestrator of the Threat Correlation Engine.
 * Correlates a set of security alerts and returns detailed threat intelligence campaign metrics.
 */
export function correlateAlerts(alerts: SecurityAlert[]): CorrelationResult {
  if (!alerts || alerts.length === 0) {
    return {
      attackType: "Unknown Activity",
      campaignName: "Generic Campaign",
      confidence: 0,
      score: 0,
      riskLevel: "Low",
      timeline: [],
    };
  }

  const attackType = evaluateRules(alerts);
  const campaignInfo = detectCampaign(alerts);
  const riskInfo = calculateRisk(alerts);
  const timeline = buildTimeline(alerts);

  return {
    attackType,
    campaignName: campaignInfo.campaignName,
    confidence: campaignInfo.confidence,
    score: riskInfo.score,
    riskLevel: riskInfo.riskLevel,
    timeline,
  };
}

// ─── Internal helpers for generateCampaigns ──────────────────────────────────

function countUniqueIocs(alerts: SecurityAlert[]): number {
  const iocValues = alerts.flatMap(a => a.iocs.map(ioc => ioc.value));
  return new Set(iocValues).size;
}

function extractTTPsList(alerts: SecurityAlert[]): string[] {
  const ttps = alerts.flatMap(a => a.mitreTTPs || []).map(t => t.split(" ")[0]);
  return Array.from(new Set(ttps));
}

function deriveTargetSector(assets: string[], fallback: string): string {
  const joined = assets.join(" ").toLowerCase();
  if (joined.includes("logistics") || joined.includes("supply")) return "Logistics and Supply Chain";
  if (joined.includes("cloud") || joined.includes("aws") || joined.includes("s3")) return "Cloud Infrastructure / Defense Technology";
  if (joined.includes("hospital") || joined.includes("health")) return "Healthcare";
  if (joined.includes("bank") || joined.includes("finance")) return "Finance";
  if (joined.includes("hr") || joined.includes("database")) return "Enterprise IT / HR Systems";
  return fallback;
}

function buildAiExplanation(alerts: SecurityAlert[], correlation: CorrelationResult): string {
  const uniqueAssets = Array.from(new Set(alerts.filter(a => a.affectedAsset).map(a => a.affectedAsset)));
  const uniqueSystems = Array.from(new Set(alerts.map(a => a.sourceSystem)));

  return [
    `Correlation engine linked ${alerts.length} disparate security events based on:`,
    `1. Chronological attack progression: ${correlation.timeline.slice(0, 4).join(" → ")}.`,
    `2. Attack pattern classified as: ${correlation.attackType} (Confidence: ${correlation.confidence}%).`,
    `3. Shared indicators detected across sources: ${uniqueSystems.join(", ")}.`,
    `4. Target entities compromised: ${uniqueAssets.slice(0, 3).join(", ")}.`,
    `Risk Level: ${correlation.riskLevel} (Score: ${correlation.score}/100).`,
  ].join("\n");
}

function buildRecommendedActions(
  key: string,
  alerts: SecurityAlert[],
  ips: string[],
  domains: string[]
): string[] {
  const actions: string[] = [];

  if (key === "shadowlock") {
    const laptopAlert = alerts.find(a => a.affectedAsset?.toLowerCase().includes("laptop"));
    if (laptopAlert) {
      actions.push(
        `Quarantine host ${laptopAlert.affectedAsset.split(" ")[0]} immediately and isolate the backup domain administrator credential.`
      );
    }
    if (ips.length > 0) {
      actions.push(`Block traffic to threat infrastructure IPs: ${ips.filter(ip => !ip.startsWith("10.")).slice(0, 3).join(", ")}.`);
    }
    if (domains.length > 0) {
      actions.push(`Blackhole malicious domains in DNS controller: ${domains.slice(0, 2).join(", ")}.`);
    }
    const encAlert = alerts.find(a => {
      const t = a.title.toLowerCase();
      return t.includes("encrypt") || t.includes("rename") || t.includes("ryuk") || t.includes("conti");
    });
    if (encAlert) {
      actions.push(
        `Kill process on ${encAlert.affectedAsset?.split(" ")[0] || "affected host"} and deploy volume shadow copy recovery immediately.`
      );
    }
    actions.push("Shut down WinRM remote access temporarily on all critical production databases and rotate administrator passwords.");
  } else if (key === "arcticrift") {
    const iamAlert = alerts.find(a => {
      const t = a.title.toLowerCase();
      return t.includes("iam") || t.includes("assumerole") || t.includes("privilege");
    });
    if (iamAlert) {
      actions.push("Revoke compromised IAM role credentials immediately and enforce MFA on all AWS AssumeRole API requests.");
    }
    if (ips.length > 0) {
      actions.push(`Block outbound connections to exfiltration infrastructure: ${ips.slice(0, 3).join(", ")}.`);
    }
    const s3Alert = alerts.find(a => a.title.toLowerCase().includes("s3") || a.title.toLowerCase().includes("bucket"));
    if (s3Alert) {
      actions.push("Apply CloudTrail quarantine policies to isolate S3 bucket vaults from unauthorized IP ranges and enable versioning protection.");
    }
    if (domains.length > 0) {
      actions.push(`Deploy WAF rules to block traffic to malicious domains: ${domains.join(", ")}.`);
    }
    actions.push("Enable AWS GuardDuty threat detection and audit all CloudTrail events from the past 72 hours.");
  } else {
    actions.push("Isolate all affected systems from the production network.");
    actions.push("Review IOCs against external threat intelligence feeds.");
    actions.push("Escalate to Tier-3 analyst for manual correlation review.");
  }

  return actions;
}

function deriveCampaignContext(
  key: string,
  alerts: SecurityAlert[],
  correlation: CorrelationResult
) {
  const sortedAlerts = [...alerts].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
  const allAssets = Array.from(new Set(alerts.filter(a => a.affectedAsset).map(a => a.affectedAsset)));
  const allIPs = Array.from(new Set(alerts.flatMap(a => a.iocs.filter(i => i.type === IOCType.IP).map(i => i.value))));
  const allDomains = Array.from(new Set(alerts.flatMap(a => a.iocs.filter(i => i.type === IOCType.DOMAIN).map(i => i.value))));

  if (key === "shadowlock") {
    const phishingAlert = alerts.find(a => a.sourceSystem === "Phishing Gateway" || a.title.toLowerCase().includes("phishing"));
    const powershellAlert = alerts.find(a => a.title.toLowerCase().includes("powershell"));
    const lateralAlert = alerts.find(a => {
      const t = a.title.toLowerCase();
      return t.includes("lateral") || t.includes("smb") || t.includes("winrm") || t.includes("remote");
    });

    return {
      name: `${correlation.campaignName} Ransomware Deployment`,
      threatActor: "Wizard Spider",
      status: "active" as const,
      initialAccess: phishingAlert ? "Spearphishing Attachment" : sortedAlerts[0]?.title || "Unknown Initial Access",
      persistence: powershellAlert ? "PowerShell Backdoor / Remote Payload Download" : "Unknown Persistence Mechanism",
      lateralMovement: lateralAlert ? "SMB Scanning + Remote PowerShell (WinRM)" : "Unknown Lateral Movement",
      targetSector: deriveTargetSector(allAssets, "Logistics and Supply Chain"),
      summary: `A ${correlation.attackType.toLowerCase()} campaign targeting ${deriveTargetSector(allAssets, "enterprise infrastructure")}. Detected ${alerts.length} correlated alerts spanning ${correlation.timeline.length} distinct attack stages. Kill chain: ${correlation.timeline.slice(0, 3).join(" → ")}.`,
      recommendedActions: buildRecommendedActions(key, alerts, allIPs, allDomains),
    };
  }

  if (key === "arcticrift") {
    const cloudAlert = alerts.find(a => a.sourceSystem === "CloudTrail" || a.title.toLowerCase().includes("aws"));
    const iamAlert = alerts.find(a => a.title.toLowerCase().includes("iam") || a.title.toLowerCase().includes("privilege"));

    return {
      name: `${correlation.campaignName} Cyber Espionage`,
      threatActor: "Fancy Bear",
      status: "monitoring" as const,
      initialAccess: cloudAlert ? "Compromised cloud egress application" : "Unknown Cloud Initial Access",
      persistence: "Stolen Cloud IAM Access Keys",
      lateralMovement: iamAlert ? "IAM Cross-Account Role Assumption" : "Cloud Service Pivoting",
      targetSector: "Defense Technology Blueprints / Cloud Infrastructure",
      summary: `State-sponsored cyber espionage campaign using compromised cloud application egress channels to escalate privileges and exfiltrate sensitive data. Detected ${alerts.length} correlated cloud events. Timeline: ${correlation.timeline.slice(0, 3).join(" → ")}.`,
      recommendedActions: buildRecommendedActions(key, alerts, allIPs, allDomains),
    };
  }

  // Generic
  return {
    name: `${correlation.campaignName} (${correlation.attackType})`,
    threatActor: "Unknown Threat Actor",
    status: "monitoring" as const,
    initialAccess: sortedAlerts[0]?.title || "Unknown",
    persistence: "Under Analysis",
    lateralMovement: "Under Analysis",
    targetSector: allAssets.slice(0, 2).join(", ") || "Unknown",
    summary: `Detected ${alerts.length} correlated security events classified as ${correlation.attackType}. Risk level: ${correlation.riskLevel}. Further analysis required.`,
    recommendedActions: buildRecommendedActions(key, alerts, allIPs, allDomains),
  };
}

// ─── Main Campaign Generator ──────────────────────────────────────────────────

/**
 * Generates a full AttackCampaign[] from a raw array of SecurityAlerts.
 *
 * Pipeline:
 *   1. Group alerts by campaign pattern (shadowlock | arcticrift | generic)
 *   2. For each group, run the full correlation pipeline
 *   3. Assemble complete AttackCampaign objects with dynamic fields
 *   4. Return sorted by risk score descending
 */
export function generateCampaigns(alerts: SecurityAlert[]): AttackCampaign[] {
  if (!alerts || alerts.length === 0) return [];

  // Step 1: Group alerts by campaign key
  const groups = new Map<string, SecurityAlert[]>();
  for (const alert of alerts) {
    const key = classifyAlert(alert);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(alert);
  }

  const campaigns: AttackCampaign[] = [];
  let index = 1;

  for (const [key, groupAlerts] of groups.entries()) {
    if (groupAlerts.length === 0) continue;

    // Step 2: Run full correlation pipeline on this group
    const correlation = correlateAlerts(groupAlerts);

    // Step 3: Derive campaign-specific context
    const context = deriveCampaignContext(key, groupAlerts, correlation);

    // Sort alerts chronologically for createdAt
    const sortedAlerts = [...groupAlerts].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    campaigns.push({
      id: `camp-${String(index).padStart(3, "0")}`,
      name: context.name,
      threatActor: context.threatActor,
      confidence: correlation.confidence,
      riskScore: correlation.score,
      status: context.status,
      initialAccess: context.initialAccess,
      persistence: context.persistence,
      lateralMovement: context.lateralMovement,
      targetSector: context.targetSector,
      summary: context.summary,
      aiExplanation: buildAiExplanation(groupAlerts, correlation),
      recommendedActions: context.recommendedActions,
      alertsCount: groupAlerts.length,
      iocsCount: countUniqueIocs(groupAlerts),
      createdAt: sortedAlerts[0]?.timestamp || new Date().toISOString(),
      ttps: extractTTPsList(groupAlerts),
    });

    index++;
  }

  // Sort by risk score descending (highest threat first)
  return campaigns.sort((a, b) => b.riskScore - a.riskScore);
}

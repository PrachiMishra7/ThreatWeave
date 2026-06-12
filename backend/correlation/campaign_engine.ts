import { SecurityAlert } from "../../src/types";

/**
 * Recognizes and returns the threat campaign name and confidence score from a set of correlated alerts.
 */
export function detectCampaign(alerts: SecurityAlert[]): {
  campaignName: string;
  confidence: number;
} {
  let hasPhishing = false;
  let hasPowerShell = false;
  let hasCredDump = false;
  let hasLateral = false;
  let hasEncryption = false;
  let hasCloud = false;

  for (const alert of alerts) {
    const title = (alert.title || "").toLowerCase();
    const desc = (alert.description || "").toLowerCase();
    const text = `${title} ${desc}`;
    const ttps = alert.mitreTTPs || [];

    if (
      text.includes("phishing") ||
      ttps.some(t => t.includes("T1566"))
    ) {
      hasPhishing = true;
    }
    if (
      text.includes("powershell") ||
      ttps.some(t => t.includes("T1059.001"))
    ) {
      hasPowerShell = true;
    }
    if (
      text.includes("lsass") ||
      text.includes("credential dump") ||
      text.includes("memory dump") ||
      ttps.some(t => t.includes("T1003"))
    ) {
      hasCredDump = true;
    }
    if (
      text.includes("lateral") ||
      text.includes("smb") ||
      text.includes("winrm") ||
      text.includes("remote session") ||
      ttps.some(t => t.includes("T1021") || t.includes("T1046"))
    ) {
      hasLateral = true;
    }
    if (
      text.includes("encrypt") ||
      text.includes("rename") ||
      text.includes("ryuk") ||
      text.includes("conti") ||
      ttps.some(t => t.includes("T1486"))
    ) {
      hasEncryption = true;
    }
    if (
      text.includes("cloud") ||
      text.includes("aws") ||
      text.includes("s3") ||
      text.includes("iam") ||
      text.includes("assumerole") ||
      alert.sourceSystem === "CloudTrail"
    ) {
      hasCloud = true;
    }
  }

  // Exact rule for ShadowLock:
  // If alerts contain all five techniques
  if (hasPhishing && hasPowerShell && hasCredDump && hasLateral && hasEncryption) {
    return {
      campaignName: "ShadowLock",
      confidence: 89,
    };
  }

  // Fallback / Partial match for ShadowLock
  const shadowLockIndicatorsCount = [
    hasPhishing,
    hasPowerShell,
    hasCredDump,
    hasLateral,
    hasEncryption
  ].filter(Boolean).length;

  if (shadowLockIndicatorsCount >= 3) {
    return {
      campaignName: "ShadowLock",
      confidence: Math.round((shadowLockIndicatorsCount / 5) * 89),
    };
  }

  // Check for Operation ArcticRift from cloud compromise alerts
  if (hasCloud) {
    return {
      campaignName: "Operation ArcticRift",
      confidence: 76,
    };
  }

  return {
    campaignName: "Generic Campaign",
    confidence: 50,
  };
}

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

    if (text.includes("phishing") || ttps.some(t => t.includes("T1566"))) {
      hasPhishing = true;
    }
    if (text.includes("powershell") || ttps.some(t => t.includes("T1059.001"))) {
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
      text.includes("tls connection") ||
      alert.sourceSystem === "CloudTrail"
    ) {
      hasCloud = true;
    }
  }

  // Exact rule for ShadowLock: all five techniques present
  if (hasPhishing && hasPowerShell && hasCredDump && hasLateral && hasEncryption) {
    return { campaignName: "ShadowLock", confidence: 89 };
  }

  // Partial match for ShadowLock (3+ indicators)
  const shadowLockCount = [hasPhishing, hasPowerShell, hasCredDump, hasLateral, hasEncryption].filter(Boolean).length;
  if (shadowLockCount >= 3) {
    return {
      campaignName: "ShadowLock",
      confidence: Math.round((shadowLockCount / 5) * 89),
    };
  }

  // ArcticRift: cloud-based compromise
  if (hasCloud) {
    const cloudCount = [
      hasCloud,
      alerts.some(a => a.sourceSystem === "CloudTrail"),
      alerts.some(a => (a.title + a.description).toLowerCase().includes("iam")),
      alerts.some(a => (a.title + a.description).toLowerCase().includes("s3")),
    ].filter(Boolean).length;
    return {
      campaignName: "Operation ArcticRift",
      confidence: Math.round(60 + cloudCount * 5),
    };
  }

  return { campaignName: "Generic Campaign", confidence: 50 };
}

/**
 * Classifies a single alert into its most likely campaign bucket.
 * Used by generateCampaigns() to group alerts before running correlation.
 */
export function classifyAlert(alert: SecurityAlert): "shadowlock" | "arcticrift" | "generic" {
  const title = (alert.title || "").toLowerCase();
  const desc = (alert.description || "").toLowerCase();
  const text = `${title} ${desc}`;
  const ttps = alert.mitreTTPs || [];

  // Cloud / AWS indicators → ArcticRift
  if (
    text.includes("cloud") ||
    text.includes("aws") ||
    text.includes("s3") ||
    text.includes("iam") ||
    text.includes("assumerole") ||
    text.includes("egress") ||
    alert.sourceSystem === "CloudTrail"
  ) {
    return "arcticrift";
  }

  // Ransomware / credential / lateral movement indicators → ShadowLock
  if (
    text.includes("phishing") ||
    text.includes("powershell") ||
    text.includes("lsass") ||
    text.includes("credential") ||
    text.includes("lateral") ||
    text.includes("smb") ||
    text.includes("winrm") ||
    text.includes("remote session") ||
    text.includes("encrypt") ||
    text.includes("rename") ||
    text.includes("ryuk") ||
    text.includes("conti") ||
    ttps.some(t =>
      t.includes("T1566") ||
      t.includes("T1059") ||
      t.includes("T1003") ||
      t.includes("T1021") ||
      t.includes("T1046") ||
      t.includes("T1486")
    )
  ) {
    return "shadowlock";
  }

  return "generic";
}

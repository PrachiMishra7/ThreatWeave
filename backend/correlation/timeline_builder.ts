import { SecurityAlert } from "../../src/types";

/**
 * Sorts alerts by timestamp chronologically and returns an ordered array of timeline strings.
 */
export function buildTimeline(alerts: SecurityAlert[]): string[] {
  // Sort a copy of the alerts array chronologically
  const sortedAlerts = [...alerts].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  return sortedAlerts.map((alert) => {
    // Extract HH:MM from ISO timestamp (e.g. "2026-06-08T08:12:00Z" -> "08:12")
    let timeStr = "";
    try {
      const date = new Date(alert.timestamp);
      const hours = String(date.getUTCHours()).padStart(2, "0");
      const minutes = String(date.getUTCMinutes()).padStart(2, "0");
      timeStr = `${hours}:${minutes}`;
    } catch {
      timeStr = alert.timestamp || "00:00";
    }

    // Determine clean event display name
    let eventName = alert.title || "Alert Event";
    const lowerTitle = eventName.toLowerCase();

    if (lowerTitle.includes("spearphishing")) {
      eventName = "Spearphishing";
    } else if (lowerTitle.includes("powershell")) {
      eventName = "PowerShell";
    } else if (lowerTitle.includes("lsass") || lowerTitle.includes("credential dump") || lowerTitle.includes("memory dump")) {
      eventName = "Credential Dumping";
    } else if (lowerTitle.includes("lateral") || lowerTitle.includes("smb") || lowerTitle.includes("winrm") || lowerTitle.includes("remote powerShell") || lowerTitle.includes("remote session")) {
      eventName = "Lateral Movement";
    } else if (lowerTitle.includes("encrypt") || lowerTitle.includes("rename") || lowerTitle.includes("ryuk") || lowerTitle.includes("conti")) {
      eventName = "Ransomware";
    } else if (lowerTitle.includes("tls connection") || lowerTitle.includes("egress")) {
      eventName = "Cloud Egress";
    } else if (lowerTitle.includes("privilege escalation") || lowerTitle.includes("iam")) {
      eventName = "IAM Escalation";
    } else if (lowerTitle.includes("s3") || lowerTitle.includes("exfiltrat")) {
      eventName = "Data Exfiltration";
    }

    return `${timeStr} ${eventName}`;
  });
}

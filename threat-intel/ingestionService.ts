/**
 * threat-intel/ingestionService.ts
 * Background threat intelligence ingestion service.
 *
 * Periodically fetches threat indicators from all configured external sources
 * (AbuseIPDB, AlienVault OTX) and upserts them into the local SQLite database.
 *
 * Design:
 *   - Runs immediately on first call, then repeats on a configurable interval
 *   - Gracefully handles API key absence (skips that source, logs a warning)
 *   - Reports results via the shared logEmitter so live clients see ingestion events
 *   - Seeds the DB with a set of known-bad IOCs from existing mockData if no API keys set
 */

import { EventEmitter } from "events";
import { fetchBlacklist, checkIP } from "./sources/abuseipdb.js";
import { fetchRecentPulses } from "./sources/otx.js";
import { upsertIndicators } from "./db.js";
import { normalizeAndFilter } from "./normalizer.js";
import type { ThreatIndicator } from "./schema.js";
import { randomUUID } from "crypto";
import { OFFLINE_DATASET } from "./offlineDataset.js";

/** Interval in milliseconds between ingestion runs (default: 6 hours) */
const DEFAULT_INTERVAL_MS = 6 * 60 * 60 * 1000;

/**
 * A hardcoded seed set of known malicious IOCs extracted from the mockData alerts.
 * This ensures the database has useful data even without API keys configured.
 * These match the IOCs used in the existing mock campaign data.
 */
const SEED_INDICATORS: Omit<ThreatIndicator, "id">[] = [
  {
    type: "IP",
    value: "185.247.72.128",
    reputation: "malicious",
    confidence_score: 95,
    country: "NL",
    sources: JSON.stringify(["ThreatWeave-Seed"]),
    tags: JSON.stringify(["c2", "powershell-dropper", "wizard-spider"]),
    first_seen: "2026-06-08T08:14:15Z",
    last_seen: "2026-06-08T08:44:00Z",
    raw_data: JSON.stringify({ note: "Seed IOC from ShadowLock campaign mockData" }),
  },
  {
    type: "Domain",
    value: "security-update-service-microsoft.com",
    reputation: "malicious",
    confidence_score: 90,
    country: undefined,
    sources: JSON.stringify(["ThreatWeave-Seed"]),
    tags: JSON.stringify(["dga", "backdoor", "c2", "typosquatting"]),
    first_seen: "2026-06-08T08:15:30Z",
    last_seen: "2026-06-08T08:15:30Z",
    raw_data: JSON.stringify({ note: "Seed IOC from ShadowLock campaign mockData" }),
  },
  {
    type: "Domain",
    value: "secure-dns-route.net",
    reputation: "malicious",
    confidence_score: 82,
    country: undefined,
    sources: JSON.stringify(["ThreatWeave-Seed"]),
    tags: JSON.stringify(["exfiltration", "ssl-tunnel", "fancy-bear"]),
    first_seen: "2026-06-08T05:00:10Z",
    last_seen: "2026-06-08T05:12:00Z",
    raw_data: JSON.stringify({ note: "Seed IOC from ArcticRift campaign mockData" }),
  },
  {
    type: "IP",
    value: "203.0.113.88",
    reputation: "malicious",
    confidence_score: 78,
    country: "CN",
    sources: JSON.stringify(["ThreatWeave-Seed"]),
    tags: JSON.stringify(["apt", "cloud-exfiltration", "iam-abuse"]),
    first_seen: "2026-06-08T05:00:10Z",
    last_seen: "2026-06-08T05:12:00Z",
    raw_data: JSON.stringify({ note: "Seed IOC from ArcticRift campaign mockData" }),
  },
  {
    type: "Hash",
    value: "ffac3e4d693a8cf8becb71e19488a03c",
    reputation: "malicious",
    confidence_score: 99,
    country: undefined,
    sources: JSON.stringify(["ThreatWeave-Seed"]),
    tags: JSON.stringify(["ransomware", "conti", "ryuk", "wizard-spider"]),
    first_seen: "2026-06-08T08:35:45Z",
    last_seen: "2026-06-08T08:35:45Z",
    raw_data: JSON.stringify({ note: "Seed IOC — Conti ransomware binary hash from mockData" }),
  },
  {
    type: "Hash",
    value: "4a8e3f9a77cd5ac244a0e98f09faef4c",
    reputation: "malicious",
    confidence_score: 88,
    country: undefined,
    sources: JSON.stringify(["ThreatWeave-Seed"]),
    tags: JSON.stringify(["spearphishing", "macro", "excel-dropper"]),
    first_seen: "2026-06-08T08:12:00Z",
    last_seen: "2026-06-08T08:12:00Z",
    raw_data: JSON.stringify({ note: "Seed IOC — malicious Excel attachment from mockData" }),
  },
  {
    type: "Hash",
    value: "c9ce6e902a7b88939e9fbfa7eb4db3bc",
    reputation: "malicious",
    confidence_score: 94,
    country: undefined,
    sources: JSON.stringify(["ThreatWeave-Seed"]),
    tags: JSON.stringify(["credential-dumping", "lsass", "mimikatz"]),
    first_seen: "2026-06-08T08:22:11Z",
    last_seen: "2026-06-08T08:22:11Z",
    raw_data: JSON.stringify({ note: "Seed IOC — LSASS dump DLL hash from mockData" }),
  },
  {
    type: "Email",
    value: "finance@billing-dept-portal.com",
    reputation: "malicious",
    confidence_score: 85,
    country: undefined,
    sources: JSON.stringify(["ThreatWeave-Seed"]),
    tags: JSON.stringify(["phishing", "bec", "spearphishing-sender"]),
    first_seen: "2026-06-08T08:12:00Z",
    last_seen: "2026-06-08T08:12:00Z",
    raw_data: JSON.stringify({ note: "Seed IOC — phishing sender email from mockData" }),
  },
  {
    type: "URL",
    value: "https://secure-dns-route.net/upload/sys-data.bin",
    reputation: "malicious",
    confidence_score: 80,
    country: undefined,
    sources: JSON.stringify(["ThreatWeave-Seed"]),
    tags: JSON.stringify(["exfiltration", "data-theft", "s3-exfil"]),
    first_seen: "2026-06-08T05:12:00Z",
    last_seen: "2026-06-08T05:12:00Z",
    raw_data: JSON.stringify({ note: "Seed IOC — exfiltration endpoint from ArcticRift mockData" }),
  },
];

/**
 * Runs a single ingestion cycle: fetches from all configured sources,
 * normalizes, and upserts to the database.
 *
 * @param logEmitter - Optional EventEmitter to broadcast ingestion events to SSE clients
 */
export async function runIngestionCycle(logEmitter?: EventEmitter): Promise<void> {
  console.log("[Ingestion] Starting threat intelligence ingestion cycle...");
  const startTime = Date.now();
  let totalIngested = 0;

  try {
    // 1. Seed with mock-data IOCs + Offline Dataset
    const combinedSeed = [...SEED_INDICATORS, ...OFFLINE_DATASET];
    const seedWithIds: ThreatIndicator[] = combinedSeed.map((s) => ({
      ...s,
      id: randomUUID(),
    }));
    const seedCount = await upsertIndicators(seedWithIds);
    console.log(`[Ingestion] Seeded ${seedCount} baseline IOCs from internal campaign and offline dataset.`);
    totalIngested += seedCount;

    // 2. AbuseIPDB Blacklist
    try {
      const rawAbuse = await fetchBlacklist();
      const normalized = normalizeAndFilter(rawAbuse);
      if (normalized.length > 0) {
        const count = await upsertIndicators(normalized);
        console.log(`[Ingestion] AbuseIPDB: ingested ${count} indicators.`);
        totalIngested += count;
      }
    } catch (err: any) {
      console.warn("[Ingestion] AbuseIPDB failed:", err.message);
    }

    // 3. AlienVault OTX Pulses
    try {
      const rawOtx = await fetchRecentPulses();
      const normalized = normalizeAndFilter(rawOtx);
      if (normalized.length > 0) {
        const count = await upsertIndicators(normalized);
        console.log(`[Ingestion] OTX: ingested ${count} indicators.`);
        totalIngested += count;
      }
    } catch (err: any) {
      console.warn("[Ingestion] OTX failed:", err.message);
    }

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    const summary = `Ingestion cycle complete: ${totalIngested} total indicators in ${elapsed}s`;
    console.log(`[Ingestion] ${summary}`);

    // Emit event to connected SSE clients so the LiveAlerts panel shows ingestion activity
    if (logEmitter) {
      logEmitter.emit("new_log", {
        timestamp: new Date().toISOString(),
        sourceSystem: "Threat Intel Ingestion",
        severity: "LOW",
        title: "Threat Feed Update Complete",
        description: summary,
        iocs: `total_indicators=${totalIngested}`,
      });
    }
  } catch (err: any) {
    console.error("[Ingestion] Cycle failed with unexpected error:", err.message);
  }
}

/**
 * Starts the background ingestion service.
 * Runs immediately on call, then repeats on INGESTION_INTERVAL_HOURS schedule.
 *
 * @param logEmitter - The shared EventEmitter from server.ts for live log streaming
 */
export function startIngestion(logEmitter?: EventEmitter): void {
  const intervalHours = Number(process.env.INGESTION_INTERVAL_HOURS) || 6;
  const intervalMs = intervalHours * 60 * 60 * 1000;

  console.log(
    `[Ingestion] Service started. Running now, then every ${intervalHours}h.`
  );

  // Run immediately
  runIngestionCycle(logEmitter).catch((err) =>
    console.error("[Ingestion] Initial cycle error:", err)
  );

  // Schedule recurring runs
  setInterval(() => {
    runIngestionCycle(logEmitter).catch((err) =>
      console.error("[Ingestion] Scheduled cycle error:", err)
    );
  }, intervalMs);
}

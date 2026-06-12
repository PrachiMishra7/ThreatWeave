/**
 * threat-intel/sources/abuseipdb.ts
 * Integration with the AbuseIPDB API (https://www.abuseipdb.com/api.html).
 *
 * Provides two functions:
 *   - fetchBlacklist(): Bulk-fetches known malicious IPs for background ingestion.
 *   - checkIP(ip): On-demand single-IP enrichment for the /lookup endpoint.
 */

import type { ThreatIndicator, Reputation } from "../schema.js";
import { randomUUID } from "crypto";

const BASE_URL = "https://api.abuseipdb.com/api/v2";

/** Headers required by the AbuseIPDB API */
function getHeaders(): Record<string, string> {
  const key = process.env.ABUSEIPDB_API_KEY;
  if (!key) throw new Error("ABUSEIPDB_API_KEY is not set in environment");
  return {
    Key: key,
    Accept: "application/json",
  };
}

/** Maps an AbuseIPDB score (0-100) to our normalized reputation level */
function scoreToReputation(score: number): Reputation {
  if (score >= 80) return "malicious";
  if (score >= 30) return "suspicious";
  if (score > 0) return "suspicious";
  return "clean";
}

/**
 * Fetches up to 10,000 known malicious IPs from the AbuseIPDB blacklist.
 * Used by the background ingestion service.
 *
 * @returns Array of normalized ThreatIndicators (empty if API key missing or error)
 */
export async function fetchBlacklist(): Promise<ThreatIndicator[]> {
  const key = process.env.ABUSEIPDB_API_KEY;
  if (!key) {
    console.warn("[AbuseIPDB] API key not set — skipping blacklist fetch.");
    return [];
  }

  try {
    console.log("[AbuseIPDB] Fetching blacklist...");
    const url = `${BASE_URL}/blacklist?confidenceMinimum=75&limit=10000&plaintext=false`;
    const response = await fetch(url, { headers: getHeaders() });

    if (!response.ok) {
      const body = await response.text();
      console.error(`[AbuseIPDB] Blacklist fetch failed: ${response.status} — ${body}`);
      return [];
    }

    const json = (await response.json()) as {
      data: {
        ipAddress: string;
        abuseConfidenceScore: number;
        countryCode?: string;
        lastReportedAt?: string;
      }[];
    };

    const now = new Date().toISOString();
    return json.data.map((entry) => ({
      id: randomUUID(),
      type: "IP",
      value: entry.ipAddress,
      reputation: scoreToReputation(entry.abuseConfidenceScore),
      confidence_score: entry.abuseConfidenceScore,
      country: entry.countryCode,
      sources: JSON.stringify(["AbuseIPDB"]),
      tags: JSON.stringify(["blacklist"]),
      first_seen: entry.lastReportedAt ?? now,
      last_seen: entry.lastReportedAt ?? now,
      raw_data: JSON.stringify(entry),
    }));
  } catch (err: any) {
    console.error("[AbuseIPDB] Unexpected error during blacklist fetch:", err.message);
    return [];
  }
}

/**
 * On-demand enrichment for a single IP address.
 * Called when a lookup query targets an IP not already in the database.
 *
 * @param ip - The IP address to enrich
 * @returns A normalized ThreatIndicator or null if not found / API unavailable
 */
export async function checkIP(ip: string): Promise<ThreatIndicator | null> {
  const key = process.env.ABUSEIPDB_API_KEY;
  if (!key) {
    console.warn("[AbuseIPDB] API key not set — skipping IP check.");
    return null;
  }

  try {
    const url = `${BASE_URL}/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
    const response = await fetch(url, { headers: getHeaders() });

    if (!response.ok) {
      console.error(`[AbuseIPDB] IP check failed for ${ip}: ${response.status}`);
      return null;
    }

    const json = (await response.json()) as {
      data: {
        ipAddress: string;
        abuseConfidenceScore: number;
        countryCode?: string;
        isp?: string;
        usageType?: string;
        totalReports?: number;
        lastReportedAt?: string;
        reports?: { categories: number[]; comment?: string }[];
      };
    };

    const data = json.data;
    const now = new Date().toISOString();

    // Aggregate tags from usage type and abuse categories
    const tags: string[] = [];
    if (data.usageType) tags.push(data.usageType.toLowerCase().replace(/\s+/g, "-"));
    if (data.totalReports && data.totalReports > 0) tags.push(`reports:${data.totalReports}`);

    return {
      id: randomUUID(),
      type: "IP",
      value: data.ipAddress,
      reputation: scoreToReputation(data.abuseConfidenceScore),
      confidence_score: data.abuseConfidenceScore,
      country: data.countryCode,
      sources: JSON.stringify(["AbuseIPDB"]),
      tags: JSON.stringify(tags),
      first_seen: now,
      last_seen: data.lastReportedAt ?? now,
      raw_data: JSON.stringify(data),
    };
  } catch (err: any) {
    console.error(`[AbuseIPDB] Error checking IP ${ip}:`, err.message);
    return null;
  }
}

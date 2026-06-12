/**
 * threat-intel/sources/otx.ts
 * Integration with AlienVault OTX (Open Threat Exchange) API.
 * Documentation: https://otx.alienvault.com/api/
 *
 * Provides:
 *   - fetchRecentPulses(): Bulk-ingest IOCs from subscribed OTX pulses
 *   - lookupIndicator(type, value): On-demand enrichment for a specific IOC
 */

import type { ThreatIndicator, IndicatorType, Reputation } from "../schema.js";
import { randomUUID } from "crypto";

const BASE_URL = "https://otx.alienvault.com/api/v1";

/** Maps OTX indicator types to our normalized IndicatorType */
function mapOtxType(otxType: string): IndicatorType | null {
  const map: Record<string, IndicatorType> = {
    IPv4: "IP",
    IPv6: "IP",
    domain: "Domain",
    hostname: "Domain",
    URL: "URL",
    "FileHash-MD5": "Hash",
    "FileHash-SHA1": "Hash",
    "FileHash-SHA256": "Hash",
    email: "Email",
  };
  return map[otxType] ?? null;
}

/** Returns auth headers for OTX API */
function getHeaders(): Record<string, string> {
  const key = process.env.OTX_API_KEY;
  if (!key) throw new Error("OTX_API_KEY is not set in environment");
  return { "X-OTX-API-KEY": key };
}

/**
 * Fetches the most recent IOCs from subscribed OTX pulses (up to last 7 days).
 * Used by the background ingestion service for bulk updates.
 *
 * @returns Array of normalized ThreatIndicators
 */
export async function fetchRecentPulses(): Promise<ThreatIndicator[]> {
  const key = process.env.OTX_API_KEY;
  if (!key) {
    console.warn("[OTX] API key not set — skipping pulse fetch.");
    return [];
  }

  try {
    console.log("[OTX] Fetching recent pulses...");
    // Calculate a week ago in ISO format for the modified_since filter
    const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const url = `${BASE_URL}/pulses/subscribed?modified_since=${oneWeekAgo}&limit=20`;

    const response = await fetch(url, { headers: getHeaders() });

    if (!response.ok) {
      const body = await response.text();
      console.error(`[OTX] Pulses fetch failed: ${response.status} — ${body}`);
      return [];
    }

    const json = (await response.json()) as {
      results: {
        name: string;
        tags: string[];
        created: string;
        modified: string;
        indicators: {
          type: string;
          indicator: string;
          created: string;
        }[];
      }[];
    };

    const indicators: ThreatIndicator[] = [];
    const now = new Date().toISOString();

    for (const pulse of json.results) {
      for (const ioc of pulse.indicators) {
        const normalizedType = mapOtxType(ioc.type);
        if (!normalizedType) continue; // Skip unsupported types

        indicators.push({
          id: randomUUID(),
          type: normalizedType,
          value: ioc.indicator,
          // OTX pulses are published threat intel — treat as malicious by default
          reputation: "malicious",
          confidence_score: 70, // OTX doesn't provide a per-IOC score; use moderate default
          country: undefined,
          sources: JSON.stringify(["OTX"]),
          tags: JSON.stringify(pulse.tags.slice(0, 10)), // Limit tag count
          first_seen: ioc.created ?? now,
          last_seen: pulse.modified ?? now,
          raw_data: JSON.stringify({ pulse_name: pulse.name, ioc }),
        });
      }
    }

    console.log(`[OTX] Collected ${indicators.length} indicators from pulses.`);
    return indicators;
  } catch (err: any) {
    console.error("[OTX] Unexpected error during pulse fetch:", err.message);
    return [];
  }
}

/**
 * On-demand enrichment for a single indicator.
 * Called when a lookup query does not match anything in the local database.
 *
 * @param type - The normalized indicator type (IP, Domain, Hash, etc.)
 * @param value - The indicator value to look up
 * @returns A normalized ThreatIndicator or null if not available
 */
export async function lookupIndicator(
  type: IndicatorType,
  value: string
): Promise<ThreatIndicator | null> {
  const key = process.env.OTX_API_KEY;
  if (!key) {
    console.warn("[OTX] API key not set — skipping indicator lookup.");
    return null;
  }

  // Map our type to OTX section path
  const sectionMap: Record<IndicatorType, string> = {
    IP: "IPv4",
    Domain: "domain",
    Hash: "file",
    URL: "url",
    Email: "email",
  };

  const section = sectionMap[type];

  try {
    const url = `${BASE_URL}/indicators/${section}/${encodeURIComponent(value)}/general`;
    const response = await fetch(url, { headers: getHeaders() });

    if (!response.ok) {
      console.warn(`[OTX] Lookup failed for ${type}:${value}: ${response.status}`);
      return null;
    }

    const data = (await response.json()) as {
      pulse_info?: { count: number; pulses: { name: string; tags: string[] }[] };
      country_code?: string;
      type_title?: string;
    };

    const now = new Date().toISOString();
    const pulseCount = data.pulse_info?.count ?? 0;
    const tags: string[] = [];

    // Aggregate tags from related pulses
    if (data.pulse_info?.pulses) {
      for (const p of data.pulse_info.pulses.slice(0, 3)) {
        tags.push(...p.tags.slice(0, 3));
      }
    }

    // Determine reputation from pulse count
    let reputation: Reputation = "unknown";
    let confidence = 0;
    if (pulseCount >= 5) {
      reputation = "malicious";
      confidence = Math.min(95, 50 + pulseCount * 5);
    } else if (pulseCount >= 1) {
      reputation = "suspicious";
      confidence = 20 + pulseCount * 10;
    }

    return {
      id: randomUUID(),
      type,
      value,
      reputation,
      confidence_score: confidence,
      country: data.country_code,
      sources: JSON.stringify(["OTX"]),
      tags: JSON.stringify([...new Set(tags)].slice(0, 10)),
      first_seen: now,
      last_seen: now,
      raw_data: JSON.stringify(data),
    };
  } catch (err: any) {
    console.error(`[OTX] Error looking up ${type}:${value}:`, err.message);
    return null;
  }
}

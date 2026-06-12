/**
 * threat-intel/normalizer.ts
 * Utility functions to normalize raw ThreatIndicator objects before DB insertion.
 *
 * Responsibilities:
 *   - Merge duplicate indicators from different sources (union their source arrays)
 *   - Sanitize values (trim whitespace, lowercase domains)
 *   - Upgrade/downgrade reputation based on combined confidence
 *   - Ensure all required fields have valid values
 */

import type { ThreatIndicator, Reputation, IndicatorType } from "./schema.js";

/**
 * Sanitizes and normalizes a single ThreatIndicator's value field
 * based on its type (e.g., lowercase domains, strip URL schemes from domains).
 */
export function normalizeIndicatorValue(type: IndicatorType, value: string): string {
  const trimmed = value.trim();
  switch (type) {
    case "Domain":
      // Strip http(s):// scheme if accidentally included, normalize to lowercase
      return trimmed.replace(/^https?:\/\//i, "").split("/")[0].toLowerCase();
    case "IP":
      return trimmed; // IPs stay as-is
    case "Hash":
      return trimmed.toLowerCase(); // Hashes are case-insensitive
    case "Email":
      return trimmed.toLowerCase();
    case "URL":
      return trimmed;
    default:
      return trimmed;
  }
}

/**
 * Merges a new indicator with an existing one already in the database.
 * Used when an on-demand lookup fetches a record that already exists —
 * combines sources and picks the higher confidence score.
 *
 * @param existing - The record currently in the DB
 * @param incoming - The freshly fetched record
 * @returns A merged ThreatIndicator ready for upsert
 */
export function mergeIndicators(
  existing: ThreatIndicator,
  incoming: ThreatIndicator
): ThreatIndicator {
  // Union source arrays
  const existingSources: string[] = JSON.parse(existing.sources);
  const incomingSources: string[] = JSON.parse(incoming.sources);
  const mergedSources = [...new Set([...existingSources, ...incomingSources])];

  // Union tags
  const existingTags: string[] = JSON.parse(existing.tags);
  const incomingTags: string[] = JSON.parse(incoming.tags);
  const mergedTags = [...new Set([...existingTags, ...incomingTags])].slice(0, 15);

  // Use the higher confidence score between the two sources
  const confidence = Math.max(existing.confidence_score, incoming.confidence_score);

  // Escalate reputation (malicious > suspicious > clean > unknown)
  const reputationRank: Record<Reputation, number> = {
    malicious: 3,
    suspicious: 2,
    clean: 1,
    unknown: 0,
  };
  const reputation: Reputation =
    reputationRank[existing.reputation] >= reputationRank[incoming.reputation]
      ? existing.reputation
      : incoming.reputation;

  return {
    ...existing,
    reputation,
    confidence_score: confidence,
    sources: JSON.stringify(mergedSources),
    tags: JSON.stringify(mergedTags),
    last_seen: incoming.last_seen,
    raw_data: JSON.stringify({
      merged: true,
      sources: mergedSources,
    }),
  };
}

/**
 * Validates that a ThreatIndicator has all required fields and sensible values.
 * Filters out garbage entries before DB insertion.
 *
 * @returns true if the indicator is valid
 */
export function isValidIndicator(ind: ThreatIndicator): boolean {
  if (!ind.value || ind.value.trim().length === 0) return false;
  if (!ind.type) return false;
  if (typeof ind.confidence_score !== "number") return false;

  // Basic IP format check
  if (ind.type === "IP") {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$/;
    if (!ipRegex.test(ind.value)) return false;
    // Skip private/loopback IPs — they're not useful in a threat feed
    if (isPrivateIP(ind.value)) return false;
  }

  // Skip hashes that are clearly empty (all zeros)
  if (ind.type === "Hash" && /^0+$/.test(ind.value)) return false;

  return true;
}

/**
 * Returns true if the given IPv4 address belongs to a private/reserved range.
 * These should never appear in threat intelligence feeds.
 */
function isPrivateIP(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return false;
  const [a, b] = parts;
  return (
    a === 10 ||                          // 10.0.0.0/8
    (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12
    (a === 192 && b === 168) ||           // 192.168.0.0/16
    a === 127 ||                          // 127.0.0.0/8 loopback
    a === 0                               // 0.0.0.0/8
  );
}

/**
 * Normalizes and filters an array of raw indicators fetched from external sources.
 * Applies value normalization, validation, and deduplication within the batch.
 *
 * @param indicators - Raw array from a source fetcher
 * @returns Deduplicated, validated, normalized array ready for DB upsert
 */
export function normalizeAndFilter(indicators: ThreatIndicator[]): ThreatIndicator[] {
  const seen = new Map<string, ThreatIndicator>();

  for (const ind of indicators) {
    // Normalize the value
    const normalizedValue = normalizeIndicatorValue(ind.type, ind.value);
    const normalized = { ...ind, value: normalizedValue };

    // Skip invalid indicators
    if (!isValidIndicator(normalized)) continue;

    // Deduplicate within the batch using (type, value) key
    const key = `${normalized.type}:${normalizedValue}`;
    if (seen.has(key)) {
      // Merge with existing entry in the batch
      seen.set(key, mergeIndicators(seen.get(key)!, normalized));
    } else {
      seen.set(key, normalized);
    }
  }

  return Array.from(seen.values());
}

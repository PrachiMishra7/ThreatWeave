/**
 * threat-intel/schema.ts
 * Normalized schema for threat indicators stored in SQLite.
 * All external API sources (AbuseIPDB, OTX, etc.) are mapped to this common type.
 */

/** The canonical set of IOC types the module supports */
export type IndicatorType = "IP" | "Domain" | "Hash" | "URL" | "Email";

/** Reputation level derived from source confidence scores */
export type Reputation = "malicious" | "suspicious" | "clean" | "unknown";

/**
 * A single normalized threat indicator as stored in the database.
 * Fields with JSON-encoded values (sources, tags) are stored as strings in SQLite
 * and parsed at the service layer.
 */
export interface ThreatIndicator {
  /** UUID primary key */
  id: string;
  /** The type of indicator (IP, Domain, etc.) */
  type: IndicatorType;
  /** The raw indicator value (e.g., "185.247.72.128") */
  value: string;
  /** Aggregated reputation across all sources */
  reputation: Reputation;
  /** 0-100 confidence score aggregated from source scores */
  confidence_score: number;
  /** ISO 3166-1 alpha-2 country code (if applicable) */
  country?: string;
  /** JSON-encoded string array of source names (e.g., '["AbuseIPDB","OTX"]') */
  sources: string;
  /** JSON-encoded string array of threat tags (e.g., '["brute-force","scanner"]') */
  tags: string;
  /** ISO 8601 datetime of first observation */
  first_seen: string;
  /** ISO 8601 datetime of most recent observation */
  last_seen: string;
  /** Full JSON blob of raw API response for debugging/auditing */
  raw_data: string;
}

/**
 * A parsed, consumer-ready indicator with JSON arrays decoded.
 * Returned by API endpoints to frontend clients.
 */
export interface ThreatIndicatorParsed extends Omit<ThreatIndicator, "sources" | "tags" | "raw_data"> {
  sources: string[];
  tags: string[];
}

/** Response shape for GET /api/threat-intel/stats */
export interface ThreatIntelStats {
  total: number;
  malicious: number;
  suspicious: number;
  clean: number;
  unknown: number;
  byReputation: Record<string, number>;
  byType: Record<string, number>;
  bySource: Record<string, number>;
  lastUpdated: string | null;
}

/** Response shape for GET /api/threat-intel/lookup */
export interface LookupResult {
  found: boolean;
  indicator?: ThreatIndicatorParsed;
  /** Enriched live data if the indicator was not in DB and was fetched on-demand */
  liveEnriched?: boolean;
  /** Alert matches from internal mock/graph data */
  relatedAlerts?: {
    id: string;
    title: string;
    severity: string;
    description: string;
    iocs: { type: string; value: string }[];
  }[];
}

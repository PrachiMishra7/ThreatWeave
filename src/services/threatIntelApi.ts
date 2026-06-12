/**
 * src/services/threatIntelApi.ts
 * Typed API client for the Threat Intelligence module backend endpoints.
 * Uses the existing api.fetch helper pattern from src/services/api.ts.
 */

import { api } from "./api";
import type {
  ThreatIndicatorParsed,
  ThreatIntelStats,
  LookupResult,
} from "../../threat-intel/schema";

/** Re-export types from schema for convenience in consumer components */
export type { ThreatIndicatorParsed, ThreatIntelStats, LookupResult };

/** Response shape for GET /api/threat-intel/indicators */
export interface IndicatorsResponse {
  data: ThreatIndicatorParsed[];
  pagination: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  };
}

/** Response shape for GET /api/threat-intel/malicious-ips */
export interface MaliciousIPsResponse {
  count: number;
  data: ThreatIndicatorParsed[];
}

/**
 * Searches all threat intelligence sources for a given IOC value.
 * Falls back to live API enrichment if not in the local database.
 *
 * @param query - The IOC to look up (IP, domain, hash, email, URL)
 */
export async function lookupThreat(query: string): Promise<LookupResult> {
  return api.fetch<LookupResult>(
    `/threat-intel/lookup?q=${encodeURIComponent(query)}`
  );
}

/**
 * Fetches a paginated list of all stored threat indicators.
 *
 * @param opts - Optional filters and pagination options
 */
export async function getIndicators(opts?: {
  type?: string;
  reputation?: string;
  page?: number;
  limit?: number;
}): Promise<IndicatorsResponse> {
  const params = new URLSearchParams();
  if (opts?.type) params.set("type", opts.type);
  if (opts?.reputation) params.set("reputation", opts.reputation);
  if (opts?.page) params.set("page", String(opts.page));
  if (opts?.limit) params.set("limit", String(opts.limit));

  const qs = params.toString();
  return api.fetch<IndicatorsResponse>(`/threat-intel/indicators${qs ? `?${qs}` : ""}`);
}

/**
 * Fetches all known malicious IP indicators.
 *
 * @param limit - Maximum number of IPs to return
 */
export async function getMaliciousIPs(limit = 100): Promise<MaliciousIPsResponse> {
  return api.fetch<MaliciousIPsResponse>(
    `/threat-intel/malicious-ips?limit=${limit}`
  );
}

/**
 * Fetches aggregate statistics about the threat intelligence database.
 */
export async function getThreatIntelStats(): Promise<ThreatIntelStats> {
  return api.fetch<ThreatIntelStats>("/threat-intel/stats");
}

/**
 * Maps a reputation string to a display-friendly color class.
 * Matches the existing TailwindCSS dark-theme palette used in SeverityBadge.
 */
export function reputationToColorClass(reputation: string): {
  bg: string;
  text: string;
  border: string;
  dot: string;
} {
  switch (reputation) {
    case "malicious":
      return {
        bg: "bg-red-500/15",
        text: "text-red-400",
        border: "border-red-500/30",
        dot: "bg-red-500",
      };
    case "suspicious":
      return {
        bg: "bg-amber-500/15",
        text: "text-amber-400",
        border: "border-amber-500/30",
        dot: "bg-amber-500",
      };
    case "clean":
      return {
        bg: "bg-emerald-500/15",
        text: "text-emerald-400",
        border: "border-emerald-500/30",
        dot: "bg-emerald-500",
      };
    default:
      return {
        bg: "bg-slate-500/15",
        text: "text-slate-400",
        border: "border-slate-500/30",
        dot: "bg-slate-500",
      };
  }
}

/**
 * Maps an indicator type to a display icon name from lucide-react.
 */
export function typeToIcon(type: string): string {
  const map: Record<string, string> = {
    IP: "Globe",
    Domain: "Link",
    Hash: "Hash",
    URL: "ExternalLink",
    Email: "Mail",
  };
  return map[type] ?? "Shield";
}

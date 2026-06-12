/**
 * src/services/correlationApi.ts
 *
 * Typed API client for the V-module correlation engine endpoints.
 * Fetches dynamically generated campaigns and alerts from the server.
 */

import type { AttackCampaign, SecurityAlert } from "../../src/types";

const BASE = "/api/v";

async function apiFetch<T>(endpoint: string): Promise<T> {
  const response = await fetch(`${BASE}${endpoint}`);
  if (!response.ok) {
    throw new Error(`[CorrelationAPI] ${response.status} ${response.statusText} — ${endpoint}`);
  }
  return response.json() as Promise<T>;
}

/** Fetch all dynamically generated campaigns from the correlation engine. */
export async function fetchGeneratedCampaigns(): Promise<AttackCampaign[]> {
  return apiFetch<AttackCampaign[]>("/campaigns");
}

/** Fetch all alerts currently in the server-side alert store. */
export async function fetchCorrelatedAlerts(limit = 100): Promise<SecurityAlert[]> {
  return apiFetch<SecurityAlert[]>(`/alerts?limit=${limit}`);
}

export interface VStats {
  totalAlerts: number;
  activeCampaigns: number;
  systemRiskScore: number;
  severityCounts: Record<string, number>;
}

/** Fetch aggregate stats derived from the correlation engine. */
export async function fetchVStats(): Promise<VStats> {
  return apiFetch<VStats>("/stats");
}

/**
 * src/hooks/useCampaigns.ts
 *
 * React hook that fetches dynamically generated AttackCampaign objects
 * from the V-module correlation engine via GET /api/v/campaigns.
 */

import { useState, useEffect, useCallback } from "react";
import type { AttackCampaign } from "../../src/types";
import { fetchGeneratedCampaigns } from "../services/correlationApi";

export interface UseCampaignsResult {
  campaigns: AttackCampaign[];
  loading: boolean;
  error: string | null;
  refresh: () => void;
}

export function useCampaigns(): UseCampaignsResult {
  const [campaigns, setCampaigns] = useState<AttackCampaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchGeneratedCampaigns();
      setCampaigns(data);
    } catch (err: any) {
      setError(err.message ?? "Failed to load campaigns");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return { campaigns, loading, error, refresh: load };
}

/**
 * src/hooks/useAlerts.ts
 *
 * React hook that fetches SecurityAlert[] from the V-module alert store
 * via GET /api/v/alerts.
 */

import { useState, useEffect } from "react";
import type { SecurityAlert } from "../../src/types";
import { fetchCorrelatedAlerts } from "../services/correlationApi";

export interface UseAlertsResult {
  alerts: SecurityAlert[];
  loading: boolean;
  error: string | null;
}

export function useAlerts(limit = 100): UseAlertsResult {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    fetchCorrelatedAlerts(limit)
      .then((data) => {
        if (!cancelled) setAlerts(data);
      })
      .catch((err: any) => {
        if (!cancelled) setError(err.message ?? "Failed to load alerts");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => { cancelled = true; };
  }, [limit]);

  return { alerts, loading, error };
}

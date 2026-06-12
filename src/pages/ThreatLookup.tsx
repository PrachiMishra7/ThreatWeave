import React, { useState, useEffect, useCallback } from "react";
import {
  Search,
  Hash,
  Globe,
  Mail,
  Link,
  ExternalLink,
  Shield,
  Terminal,
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  Loader2,
  Database,
  Activity,
  Crosshair,
  MapPin,
  Clock,
  Tag,
  Zap,
  BarChart3,
} from "lucide-react";
import {
  lookupThreat,
  getThreatIntelStats,
  getMaliciousIPs,
  reputationToColorClass,
  type ThreatIndicatorParsed,
  type LookupResult,
  type ThreatIntelStats,
} from "../services/threatIntelApi";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { Severity } from "../types";

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

/** Icon for a given IOC type */
function TypeIcon({ type, className = "h-4 w-4" }: { type: string; className?: string }) {
  const map: Record<string, React.ElementType> = {
    IP: Globe,
    Domain: Link,
    Hash: Hash,
    URL: ExternalLink,
    Email: Mail,
  };
  const Icon = map[type] ?? Shield;
  return <Icon className={className} />;
}

/** Reputation badge (matches the existing SeverityBadge aesthetic) */
function ReputationBadge({ reputation }: { reputation: string }) {
  const colors = reputationToColorClass(reputation);
  const icons: Record<string, React.ElementType> = {
    malicious: AlertTriangle,
    suspicious: AlertTriangle,
    clean: CheckCircle,
    unknown: HelpCircle,
  };
  const Icon = icons[reputation] ?? HelpCircle;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold uppercase tracking-wider border ${colors.bg} ${colors.text} ${colors.border}`}
    >
      <Icon className="h-3 w-3" />
      {reputation}
    </span>
  );
}

/** Confidence score bar */
function ConfidenceBar({ score }: { score: number }) {
  const color =
    score >= 80
      ? "bg-red-500"
      : score >= 40
      ? "bg-amber-500"
      : score >= 1
      ? "bg-sky-400"
      : "bg-slate-600";

  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${color}`}
          style={{ width: `${score}%` }}
        />
      </div>
      <span className="text-xs font-mono text-slate-400 w-8 text-right">{score}%</span>
    </div>
  );
}

/** A single stat card used in the stats panel */
function StatItem({
  label,
  value,
  color = "text-teal-400",
  icon: Icon,
}: {
  label: string;
  value: number | string;
  color?: string;
  icon?: React.ElementType;
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className={`text-2xl font-bold font-mono ${color}`}>{value}</span>
      <span className="text-xs text-slate-500 flex items-center gap-1">
        {Icon && <Icon className="h-3 w-3" />}
        {label}
      </span>
    </div>
  );
}

/** Enriched indicator card shown after a successful lookup */
function IndicatorCard({
  indicator,
  liveEnriched,
}: {
  indicator: ThreatIndicatorParsed;
  liveEnriched?: boolean;
}) {
  const colors = reputationToColorClass(indicator.reputation);

  return (
    <div
      className={`rounded-xl border ${colors.border} bg-slate-900 overflow-hidden`}
    >
      {/* Header */}
      <div className={`px-5 py-4 flex items-center justify-between ${colors.bg}`}>
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg bg-slate-950/40 ${colors.text}`}>
            <TypeIcon type={indicator.type} className="h-5 w-5" />
          </div>
          <div>
            <p className="text-xs text-slate-500 font-mono uppercase tracking-wider">
              {indicator.type}
              {liveEnriched && (
                <span className="ml-2 px-1.5 py-0.5 bg-teal-500/20 text-teal-400 border border-teal-500/30 rounded text-[9px]">
                  LIVE ENRICHED
                </span>
              )}
            </p>
            <p className="font-mono font-semibold text-white text-lg break-all">
              {indicator.value}
            </p>
          </div>
        </div>
        <ReputationBadge reputation={indicator.reputation} />
      </div>

      {/* Body */}
      <div className="px-5 py-4 grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Confidence */}
        <div>
          <p className="text-xs text-slate-500 mb-1.5">Confidence Score</p>
          <ConfidenceBar score={indicator.confidence_score} />
        </div>

        {/* Country */}
        {indicator.country && (
          <div>
            <p className="text-xs text-slate-500 mb-1 flex items-center gap-1">
              <MapPin className="h-3 w-3" /> Country
            </p>
            <p className="text-sm font-mono text-slate-200">{indicator.country}</p>
          </div>
        )}

        {/* Sources */}
        <div>
          <p className="text-xs text-slate-500 mb-1.5 flex items-center gap-1">
            <Database className="h-3 w-3" /> Sources
          </p>
          <div className="flex flex-wrap gap-1">
            {indicator.sources.map((src) => (
              <span
                key={src}
                className="px-2 py-0.5 bg-slate-800 border border-slate-700 rounded text-xs font-mono text-slate-300"
              >
                {src}
              </span>
            ))}
          </div>
        </div>

        {/* Tags */}
        {indicator.tags.length > 0 && (
          <div>
            <p className="text-xs text-slate-500 mb-1.5 flex items-center gap-1">
              <Tag className="h-3 w-3" /> Tags
            </p>
            <div className="flex flex-wrap gap-1">
              {indicator.tags.map((tag) => (
                <span
                  key={tag}
                  className="px-2 py-0.5 bg-teal-500/10 border border-teal-500/20 rounded text-xs font-mono text-teal-400"
                >
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Timestamps */}
        <div className="md:col-span-2 flex gap-6 pt-2 border-t border-slate-800">
          <div>
            <p className="text-xs text-slate-500 flex items-center gap-1 mb-0.5">
              <Clock className="h-3 w-3" /> First Seen
            </p>
            <p className="text-xs font-mono text-slate-400">
              {new Date(indicator.first_seen).toLocaleString()}
            </p>
          </div>
          <div>
            <p className="text-xs text-slate-500 flex items-center gap-1 mb-0.5">
              <Clock className="h-3 w-3" /> Last Seen
            </p>
            <p className="text-xs font-mono text-slate-400">
              {new Date(indicator.last_seen).toLocaleString()}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

/** Card for a related internal alert */
function RelatedAlertCard({
  alert,
}: {
  alert: LookupResult["relatedAlerts"] extends Array<infer T> ? T : never;
  key?: React.Key;
}) {
  return (
    <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex flex-col gap-2">
      <div className="flex justify-between items-start">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-slate-500 shrink-0" />
          <span className="font-semibold text-slate-200 text-sm">{alert.title}</span>
        </div>
        <SeverityBadge severity={alert.severity as Severity} />
      </div>
      <p className="text-xs text-slate-500 font-mono leading-relaxed">{alert.description}</p>
      <div className="flex flex-wrap gap-1.5 mt-1">
        {alert.iocs.map((ioc, i) => (
          <span
            key={i}
            className="px-2 py-0.5 bg-slate-950 border border-slate-700 rounded text-xs font-mono text-teal-400 flex items-center gap-1"
          >
            <TypeIcon type={ioc.type} className="h-3 w-3" />
            {ioc.value.length > 40 ? `${ioc.value.slice(0, 37)}...` : ioc.value}
          </span>
        ))}
      </div>
    </div>
  );
}

/** Stats overview panel */
function StatsPanel({ stats }: { stats: ThreatIntelStats }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <div className="flex items-center gap-2 mb-4">
        <BarChart3 className="h-4 w-4 text-teal-500" />
        <h3 className="text-sm font-semibold text-slate-300">Threat Intelligence Database</h3>
        {stats.lastUpdated && (
          <span className="ml-auto text-xs text-slate-600 font-mono">
            Updated {new Date(stats.lastUpdated).toLocaleTimeString()}
          </span>
        )}
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
        <StatItem label="Total Indicators" value={stats.total.toLocaleString()} icon={Database} />
        <StatItem
          label="Malicious"
          value={(stats.byReputation?.malicious ?? 0).toLocaleString()}
          color="text-red-400"
          icon={AlertTriangle}
        />
        <StatItem
          label="Suspicious"
          value={(stats.byReputation?.suspicious ?? 0).toLocaleString()}
          color="text-amber-400"
          icon={AlertTriangle}
        />
        <StatItem
          label="IPs Tracked"
          value={(stats.byType?.IP ?? 0).toLocaleString()}
          color="text-sky-400"
          icon={Globe}
        />
      </div>

      {/* Type breakdown */}
      {Object.keys(stats.byType ?? {}).length > 0 && (
        <div className="mt-4 pt-4 border-t border-slate-800 flex flex-wrap gap-2">
          {Object.entries(stats.byType).map(([type, count]) => (
            <div
              key={type}
              className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-800 rounded-lg text-xs"
            >
              <TypeIcon type={type} className="h-3 w-3 text-slate-400" />
              <span className="text-slate-400">{type}</span>
              <span className="font-mono font-bold text-slate-200">{count}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Example queries for the search bar placeholder cycling
// ---------------------------------------------------------------------------
const EXAMPLE_QUERIES = [
  "185.247.72.128",
  "ffac3e4d693a8cf8becb71e19488a03c",
  "secure-dns-route.net",
  "finance@billing-dept-portal.com",
];

// ---------------------------------------------------------------------------
// Main Page Component
// ---------------------------------------------------------------------------

export default function ThreatLookup() {
  const [query, setQuery] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [hasSearched, setHasSearched] = useState(false);
  const [result, setResult] = useState<LookupResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<ThreatIntelStats | null>(null);
  const [statsError, setStatsError] = useState(false);
  const [placeholderIdx, setPlaceholderIdx] = useState(0);

  // Cycle through example queries in the placeholder
  useEffect(() => {
    const interval = setInterval(() => {
      setPlaceholderIdx((i) => (i + 1) % EXAMPLE_QUERIES.length);
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  // Fetch stats on mount
  useEffect(() => {
    getThreatIntelStats()
      .then(setStats)
      .catch(() => setStatsError(true));
  }, []);

  const handleSearch = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      const trimmed = query.trim();
      if (!trimmed) return;

      setIsLoading(true);
      setHasSearched(true);
      setError(null);
      setResult(null);

      try {
        const data = await lookupThreat(trimmed);
        setResult(data);

        // Refresh stats after a successful lookup (may have added new indicator)
        if (data.liveEnriched) {
          getThreatIntelStats().then(setStats).catch(() => {});
        }
      } catch (err: any) {
        setError(err.message || "An unexpected error occurred during lookup.");
      } finally {
        setIsLoading(false);
      }
    },
    [query]
  );

  return (
    <div className="flex flex-col gap-6 pb-10">
      {/* ------------------------------------------------------------------ */}
      {/* Hero / Search Section */}
      {/* ------------------------------------------------------------------ */}
      <div className="flex flex-col items-center justify-center pt-10 pb-2">
        {/* Glow orb behind the heading */}
        <div className="relative mb-6 text-center">
          <div className="absolute inset-0 blur-3xl bg-teal-500/10 rounded-full scale-150 pointer-events-none" />
          <div className="relative flex items-center justify-center gap-3 mb-2">
            <div className="p-2.5 bg-teal-500/10 border border-teal-500/20 rounded-xl">
              <Crosshair className="h-6 w-6 text-teal-400" />
            </div>
            <h1 className="text-3xl font-bold text-white tracking-tight">
              Universal Threat Lookup
            </h1>
          </div>
          <p className="text-slate-400 text-sm max-w-md mx-auto">
            Search across AbuseIPDB, AlienVault OTX, and internal campaign data.
            Covers IPs, domains, file hashes, emails, and URLs.
          </p>
        </div>

        {/* Search form */}
        <form onSubmit={handleSearch} className="w-full max-w-2xl relative group">
          {/* Glowing border effect on focus */}
          <div className="absolute -inset-0.5 bg-gradient-to-r from-teal-500/20 to-emerald-500/20 rounded-xl blur opacity-0 group-focus-within:opacity-100 transition-opacity duration-500 pointer-events-none" />
          <div className="relative flex items-center">
            <Search className="absolute left-4 h-5 w-5 text-teal-500 pointer-events-none" />
            <input
              id="threat-lookup-input"
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={`e.g. ${EXAMPLE_QUERIES[placeholderIdx]}`}
              className="w-full bg-slate-900 border-2 border-slate-700 focus:border-teal-500 text-lg text-slate-200 rounded-xl pl-12 pr-36 py-4 focus:outline-none focus:ring-4 focus:ring-teal-500/15 transition-all font-mono shadow-2xl placeholder:text-slate-600"
            />
            <button
              id="threat-lookup-submit"
              type="submit"
              disabled={isLoading || !query.trim()}
              className="absolute right-3 flex items-center gap-2 bg-teal-500 hover:bg-teal-400 disabled:bg-slate-700 disabled:text-slate-500 text-slate-950 font-bold px-4 py-2 rounded-lg transition-all active:scale-95"
            >
              {isLoading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Zap className="h-4 w-4" />
              )}
              {isLoading ? "Analyzing..." : "Analyze"}
            </button>
          </div>
        </form>

        {/* Quick example chips */}
        <div className="flex flex-wrap gap-2 mt-3 justify-center">
          {EXAMPLE_QUERIES.map((ex) => (
            <button
              key={ex}
              onClick={() => setQuery(ex)}
              className="px-2.5 py-1 bg-slate-900 border border-slate-800 hover:border-teal-500/40 hover:text-teal-400 rounded-lg text-xs font-mono text-slate-500 transition-colors"
            >
              {ex}
            </button>
          ))}
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Stats Panel — always visible */}
      {/* ------------------------------------------------------------------ */}
      <div className="max-w-4xl mx-auto w-full">
        {stats ? (
          <StatsPanel stats={stats} />
        ) : !statsError ? (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex items-center gap-3 text-slate-500 text-sm">
            <Loader2 className="h-4 w-4 animate-spin text-teal-500" />
            Loading threat intelligence database stats...
          </div>
        ) : (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex items-center gap-3 text-slate-600 text-sm">
            <Activity className="h-4 w-4" />
            Stats unavailable — threat intel service may still be initializing.
          </div>
        )}
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Results Section */}
      {/* ------------------------------------------------------------------ */}
      {hasSearched && (
        <div className="max-w-4xl mx-auto w-full flex flex-col gap-4 animate-in fade-in slide-in-from-bottom-4 duration-300">
          <h2 className="text-xl font-bold text-slate-200 border-b border-slate-800 pb-2 flex items-center gap-2">
            <Search className="h-5 w-5 text-teal-500" />
            Results for{" "}
            <span className="font-mono text-teal-400 truncate max-w-xs">{query}</span>
          </h2>

          {/* Loading skeleton */}
          {isLoading && (
            <div className="space-y-3">
              {[1, 2].map((i) => (
                <div
                  key={i}
                  className="h-36 bg-slate-900 border border-slate-800 rounded-xl animate-pulse"
                />
              ))}
            </div>
          )}

          {/* Error state */}
          {!isLoading && error && (
            <div className="p-6 bg-red-500/10 border border-red-500/30 rounded-xl flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-red-300 mb-1">Lookup Failed</p>
                <p className="text-sm text-red-400/80">{error}</p>
              </div>
            </div>
          )}

          {/* Results */}
          {!isLoading && !error && result && (
            <>
              {/* Primary enriched indicator */}
              {result.found && result.indicator ? (
                <IndicatorCard
                  indicator={result.indicator}
                  liveEnriched={result.liveEnriched}
                />
              ) : (
                <div className="p-8 text-center bg-slate-900 border border-slate-800 rounded-xl">
                  <HelpCircle className="h-10 w-10 text-slate-700 mx-auto mb-3" />
                  <p className="text-slate-400 font-semibold mb-1">
                    No threat intelligence found
                  </p>
                  <p className="text-slate-600 text-sm">
                    "{query}" was not found in the threat database or external APIs.
                    {!process.env.ABUSEIPDB_API_KEY &&
                      " Configure ABUSEIPDB_API_KEY and OTX_API_KEY in .env for live enrichment."}
                  </p>
                </div>
              )}

              {/* Related internal alerts */}
              {result.relatedAlerts && result.relatedAlerts.length > 0 && (
                <div className="flex flex-col gap-3 mt-2">
                  <h3 className="text-sm font-semibold text-slate-400 flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-slate-500" />
                    Related Internal Alerts ({result.relatedAlerts.length})
                  </h3>
                  {result.relatedAlerts.map((alert) => (
                    <RelatedAlertCard key={alert.id} alert={alert} />
                  ))}
                </div>
              )}

              {/* "No related alerts" note — only show when found but no alerts */}
              {result.found && (!result.relatedAlerts || result.relatedAlerts.length === 0) && (
                <p className="text-xs text-slate-600 text-center py-2">
                  No related internal campaign alerts found for this indicator.
                </p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

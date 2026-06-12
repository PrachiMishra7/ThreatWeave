import { useState } from "react";
import { Layers, Activity, Users, ShieldAlert, RefreshCw, AlertCircle } from "lucide-react";
import { StatCard } from "../components/ui/StatCard";
import { useCampaigns } from "../hooks/useCampaigns";

function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse bg-slate-800 rounded ${className}`} />;
}

export default function CampaignViewer() {
  const { campaigns, loading, error, refresh } = useCampaigns();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const campaign = campaigns.find(c => c.id === (selectedId ?? campaigns[0]?.id)) ?? campaigns[0];

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] gap-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Layers className="h-6 w-6 text-teal-500" />
          <h1 className="text-2xl font-bold text-white">Campaign Viewer</h1>
        </div>
        <button
          onClick={refresh}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 hover:text-white transition-all disabled:opacity-40"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          Re-correlate
        </button>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400 text-sm">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      <div className="flex gap-6 h-full overflow-hidden">
        {/* Campaign List */}
        <div className="w-80 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col shrink-0">
          <div className="p-4 border-b border-slate-800 font-semibold text-slate-200 flex items-center justify-between">
            <span>Detected Campaigns</span>
            {!loading && (
              <span className="text-xs font-mono text-teal-500 bg-teal-500/10 border border-teal-500/20 px-2 py-0.5 rounded-full">
                {campaigns.length} active
              </span>
            )}
          </div>
          <div className="flex-1 overflow-y-auto p-2">
            {loading ? (
              Array.from({ length: 2 }).map((_, i) => (
                <div key={i} className="p-3 rounded-lg border border-slate-800 mb-1 space-y-2">
                  <Skeleton className="h-3 w-3/4" />
                  <Skeleton className="h-2 w-1/2" />
                  <Skeleton className="h-2 w-1/3 ml-auto" />
                </div>
              ))
            ) : campaigns.length === 0 ? (
              <div className="p-4 text-xs text-slate-500 text-center">
                No campaigns detected from alert data.
              </div>
            ) : (
              campaigns.map(camp => (
                <button
                  key={camp.id}
                  onClick={() => setSelectedId(camp.id)}
                  className={`w-full text-left p-3 rounded-lg border transition-all text-xs mb-1 ${
                    (selectedId ?? campaigns[0]?.id) === camp.id
                      ? "bg-slate-800 border-teal-500/50 text-slate-200"
                      : "bg-transparent border-transparent text-slate-400 hover:bg-slate-800/50"
                  }`}
                >
                  <div className="font-bold truncate text-sm">{camp.name}</div>
                  <div className="flex justify-between items-center mt-1">
                    <span>Actor: {camp.threatActor}</span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${camp.riskScore > 85 ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-500'}`}>
                      Risk: {camp.riskScore}%
                    </span>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Campaign Details */}
        <div className="flex-1 bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col overflow-y-auto">
          {loading ? (
            <div className="space-y-4">
              <Skeleton className="h-8 w-2/3" />
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-3/4" />
              <div className="grid grid-cols-3 gap-4 mt-6">
                {Array.from({ length: 3 }).map((_, i) => (
                <div key={i}><Skeleton className="h-20 rounded-xl" /></div>
              ))}
              </div>
              <div className="grid grid-cols-2 gap-6 mt-4">
                <Skeleton className="h-40 rounded-xl" />
                <Skeleton className="h-40 rounded-xl" />
              </div>
              <Skeleton className="h-32 rounded-xl mt-4" />
            </div>
          ) : !campaign ? (
            <div className="flex flex-col items-center justify-center h-full text-slate-500 gap-3">
              <ShieldAlert className="h-12 w-12 opacity-20" />
              <p className="text-sm">No campaign selected or correlation produced no results.</p>
            </div>
          ) : (
            <>
              <div className="flex justify-between items-start mb-6">
                <div>
                  <h2 className="text-3xl font-bold text-white mb-2">{campaign.name}</h2>
                  <p className="text-slate-400">{campaign.summary}</p>
                </div>
                <div className="text-center px-4 py-2 bg-slate-950 border border-slate-800 rounded-lg shrink-0 ml-4">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Status</span>
                  <span className={`font-bold uppercase text-xs ${
                    campaign.status === 'active' ? 'text-rose-400' :
                    campaign.status === 'monitoring' ? 'text-amber-400' : 'text-teal-400'
                  }`}>{campaign.status}</span>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4 mb-8">
                <StatCard title="Confidence" value={`${campaign.confidence}%`} icon={<Activity className="h-5 w-5" />} glowColor="teal" />
                <StatCard title="Alerts Linked" value={campaign.alertsCount} icon={<ShieldAlert className="h-5 w-5" />} glowColor="rose" />
                <StatCard title="IOCs Extracted" value={campaign.iocsCount} icon={<Users className="h-5 w-5" />} glowColor="indigo" />
              </div>

              <div className="grid grid-cols-2 gap-6">
                <div className="p-4 bg-slate-950/50 border border-slate-800 rounded-xl">
                  <h3 className="font-semibold text-slate-200 mb-3 border-b border-slate-800 pb-2">Kill Chain Progression</h3>
                  <ul className="text-sm font-mono text-slate-400 space-y-2">
                    <li><strong className="text-slate-300">Target:</strong> {campaign.targetSector}</li>
                    <li><strong className="text-slate-300">Initial Access:</strong> {campaign.initialAccess}</li>
                    <li><strong className="text-slate-300">Persistence:</strong> {campaign.persistence}</li>
                    <li><strong className="text-slate-300">Lateral:</strong> {campaign.lateralMovement}</li>
                    <li><strong className="text-slate-300">Threat Actor:</strong> {campaign.threatActor}</li>
                  </ul>
                </div>
                <div className="p-4 bg-slate-950/50 border border-slate-800 rounded-xl">
                  <h3 className="font-semibold text-slate-200 mb-3 border-b border-slate-800 pb-2">Mitre ATT&CK TTPs</h3>
                  <div className="flex flex-wrap gap-2">
                    {campaign.ttps.map(ttp => (
                      <span key={ttp} className="px-2 py-1 bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 rounded font-mono text-[10px]">
                        {ttp}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              <div className="mt-6 p-4 bg-slate-950/50 border border-slate-800 rounded-xl">
                <h3 className="font-semibold text-slate-200 mb-3 border-b border-slate-800 pb-2">
                  Correlation Engine — AI Analysis & Recommendations
                </h3>
                <p className="text-sm text-slate-300 leading-relaxed mb-4 whitespace-pre-line">{campaign.aiExplanation}</p>
                <ul className="list-disc pl-5 text-sm text-slate-400 space-y-1">
                  {campaign.recommendedActions.map((action, i) => (
                    <li key={i}>{action}</li>
                  ))}
                </ul>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

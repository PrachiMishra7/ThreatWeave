import { useState } from "react";
import { Layers, Activity, Users, ShieldAlert } from "lucide-react";
import { mockCampaigns } from "../mockData";
import { StatCard } from "../components/ui/StatCard";

export default function CampaignViewer() {
  const [selectedId, setSelectedId] = useState<string>(mockCampaigns[0].id);
  const campaign = mockCampaigns.find(c => c.id === selectedId) || mockCampaigns[0];

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] gap-6">
      <div className="flex items-center gap-3">
        <Layers className="h-6 w-6 text-teal-500" />
        <h1 className="text-2xl font-bold text-white">Campaign Viewer</h1>
      </div>

      <div className="flex gap-6 h-full">
        {/* Campaign List */}
        <div className="w-80 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
          <div className="p-4 border-b border-slate-800 font-semibold text-slate-200">
            Detected Campaigns
          </div>
          <div className="flex-1 overflow-y-auto p-2">
            {mockCampaigns.map(camp => (
              <button
                key={camp.id}
                onClick={() => setSelectedId(camp.id)}
                className={`w-full text-left p-3 rounded-lg border transition-all text-xs mb-1 ${
                  selectedId === camp.id
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
            ))}
          </div>
        </div>

        {/* Campaign Details */}
        <div className="flex-1 bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col overflow-y-auto">
          <div className="flex justify-between items-start mb-6">
            <div>
              <h2 className="text-3xl font-bold text-white mb-2">{campaign.name}</h2>
              <p className="text-slate-400">{campaign.summary}</p>
            </div>
            <div className="text-center px-4 py-2 bg-slate-950 border border-slate-800 rounded-lg">
              <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Status</span>
              <span className="text-teal-400 font-bold uppercase text-xs">{campaign.status}</span>
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
              <h3 className="font-semibold text-slate-200 mb-3 border-b border-slate-800 pb-2">AI-Generated Context & Recommendations</h3>
              <p className="text-sm text-slate-300 leading-relaxed mb-4">{campaign.aiExplanation}</p>
              <ul className="list-disc pl-5 text-sm text-slate-400 space-y-1">
                {campaign.recommendedActions.map((action, i) => (
                  <li key={i}>{action}</li>
                ))}
              </ul>
            </div>
        </div>
      </div>
    </div>
  );
}

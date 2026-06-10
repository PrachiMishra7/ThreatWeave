import { useState } from "react";
import { AlertTriangle, Layers, Activity, Users, Terminal } from "lucide-react";
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  PieChart, Pie, Cell
} from "recharts";
import { StatCard } from "../components/ui/StatCard";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { mockAlerts, mockCampaigns } from "../mockData";

// Mock data for charts
const volumeData = [
  { time: '00:00', alerts: 12 }, { time: '04:00', alerts: 19 },
  { time: '08:00', alerts: 45 }, { time: '12:00', alerts: 82 },
  { time: '16:00', alerts: 65 }, { time: '20:00', alerts: 30 },
  { time: '24:00', alerts: 15 }
];

const severityData = [
  { name: 'CRITICAL', value: 12, color: '#f43f5e' }, // rose-500
  { name: 'HIGH', value: 45, color: '#f59e0b' },     // amber-500
  { name: 'MEDIUM', value: 89, color: '#14b8a6' },   // teal-500
  { name: 'LOW', value: 134, color: '#64748b' }      // slate-500
];

export default function Dashboard() {
  const [activeCampaignId, setActiveCampaignId] = useState<string>(mockCampaigns[0].id);
  
  const activeCampaign = mockCampaigns.find(c => c.id === activeCampaignId) || mockCampaigns[0];
  const recentAlerts = mockAlerts.slice(0, 8);

  return (
    <div className="flex flex-col gap-6">
      
      {/* Top Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard 
          title="Total Alerts" 
          value="1,284" 
          icon={<AlertTriangle className="h-5 w-5" />} 
          trend="12%" 
          trendUp={false} 
          glowColor="rose" 
        />
        <StatCard 
          title="Active Campaigns" 
          value={mockCampaigns.length} 
          icon={<Layers className="h-5 w-5" />} 
          trend="2" 
          trendUp={true} 
          glowColor="teal" 
        />
        <StatCard 
          title="System Risk Score" 
          value="64" 
          icon={<Activity className="h-5 w-5" />} 
          trend="5%" 
          trendUp={false} 
          glowColor="amber" 
        />
        <StatCard 
          title="Actors Tracked" 
          value="14" 
          icon={<Users className="h-5 w-5" />} 
          glowColor="indigo" 
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Alert Volume Trend (Line Chart) */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col h-[300px]">
          <h3 className="font-semibold text-sm text-slate-200 mb-4">Alert Volume (24h)</h3>
          <div className="flex-1 w-full min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={volumeData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                <XAxis dataKey="time" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <RechartsTooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#f8fafc', borderRadius: '8px' }}
                  itemStyle={{ color: '#14b8a6' }}
                />
                <Line type="monotone" dataKey="alerts" stroke="#14b8a6" strokeWidth={3} dot={{ r: 4, fill: '#0f172a', strokeWidth: 2 }} activeDot={{ r: 6 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution (Donut Chart) */}
        <div className="lg:col-span-1 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col h-[300px]">
          <h3 className="font-semibold text-sm text-slate-200 mb-4">Alert Severity Distribution</h3>
          <div className="flex-1 w-full min-h-0 flex items-center justify-center relative">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                  stroke="none"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <RechartsTooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#f8fafc', borderRadius: '8px' }}
                />
              </PieChart>
            </ResponsiveContainer>
            {/* Center Label */}
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-2xl font-bold text-white">280</span>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Total</span>
            </div>
          </div>
        </div>

      </div>

      {/* Bottom Row: Campaigns & Details */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Campaigns & Alert Feed */}
        <div className="lg:col-span-1 flex flex-col gap-6">
          
          {/* Active Campaigns Widget */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl flex flex-col overflow-hidden h-[300px]">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <h3 className="font-semibold text-sm flex items-center gap-2">
                <Layers className="h-4 w-4 text-teal-400" />
                Active Campaigns
              </h3>
            </div>
            <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-1">
              {mockCampaigns.map(camp => (
                <button
                  key={camp.id}
                  onClick={() => setActiveCampaignId(camp.id)}
                  className={`text-left p-3 rounded-lg border transition-all text-xs ${
                    activeCampaignId === camp.id
                      ? "bg-slate-800 border-teal-500/50 text-slate-200"
                      : "bg-transparent border-transparent text-slate-400 hover:bg-slate-800/50"
                  }`}
                >
                  <div className="flex justify-between items-center mb-1">
                    <span className="font-semibold truncate pr-2">{camp.name}</span>
                    <span className={`font-mono px-1.5 py-0.5 rounded text-[10px] ${camp.riskScore > 85 ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-500'}`}>
                      {camp.riskScore}%
                    </span>
                  </div>
                  <div className="text-[10px] font-mono opacity-70">
                    Actor: {camp.threatActor}
                  </div>
                </button>
              ))}
            </div>
          </div>

        </div>

        {/* Right Column: Campaign Details & Alerts */}
        <div className="lg:col-span-2 flex flex-col gap-6">
          
          {/* Campaign Overview Widget */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg relative overflow-hidden">
            <div className="absolute top-0 right-0 p-6 opacity-5 pointer-events-none">
              <Activity className="h-32 w-32" />
            </div>
            
            <div className="flex items-start justify-between relative z-10">
              <div>
                <span className="text-[10px] uppercase font-mono tracking-wider text-teal-500 mb-1 block">Selected Campaign Profile</span>
                <h2 className="text-xl font-bold text-white mb-2">{activeCampaign.name}</h2>
                <p className="text-sm text-slate-400 max-w-xl leading-relaxed">
                  {activeCampaign.summary}
                </p>
              </div>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 border-t border-slate-800 pt-5 relative z-10">
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">Target Sector</span>
                <span className="text-xs font-mono text-slate-300">{activeCampaign.targetSector}</span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">Initial Access</span>
                <span className="text-xs font-mono text-slate-300">{activeCampaign.initialAccess}</span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">Persistence</span>
                <span className="text-xs font-mono text-slate-300">{activeCampaign.persistence}</span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">Confidence</span>
                <span className="text-xs font-mono text-teal-400 font-bold">{activeCampaign.confidence}%</span>
              </div>
            </div>
          </div>

          {/* Live Alerts Feed preview */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl flex flex-col overflow-hidden flex-1 min-h-[300px]">
             <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <h3 className="font-semibold text-sm flex items-center gap-2">
                <Terminal className="h-4 w-4 text-rose-400" />
                Latest Incident Alerts
              </h3>
              <span className="flex h-2 w-2 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-rose-500"></span>
              </span>
            </div>
            
            <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
              {recentAlerts.map(alert => (
                <div key={alert.id} className="p-3 bg-slate-950/50 border border-slate-800/80 rounded-lg hover:border-slate-700 transition-colors">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[10px] font-mono text-slate-500">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                    <SeverityBadge severity={alert.severity} />
                  </div>
                  <h4 className="text-sm font-semibold text-slate-200">{alert.title}</h4>
                  <p className="text-xs font-mono text-slate-400 mt-1 line-clamp-1">{alert.description}</p>
                </div>
              ))}
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}

import { useState } from "react";
import { AlertTriangle, Layers, Activity, Users, Terminal, RefreshCw } from "lucide-react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  PieChart, Pie, Cell
} from "recharts";
import { motion } from "motion/react";
import { StatCard } from "../components/ui/StatCard";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { useCampaigns } from "../hooks/useCampaigns";
import { useAlerts } from "../hooks/useAlerts";

// Helper to compute volume data dynamically from alerts
function computeVolumeData(alerts: any[]) {
  if (!alerts || alerts.length === 0) {
    return [
      { time: '00:00', alerts: 0 }, { time: '04:00', alerts: 0 },
      { time: '08:00', alerts: 0 }, { time: '12:00', alerts: 0 },
      { time: '16:00', alerts: 0 }, { time: '20:00', alerts: 0 },
      { time: '24:00', alerts: 0 }
    ];
  }
  
  // Create 6 buckets for the last 24 hours
  const buckets = new Array(6).fill(0);
  const now = new Date().getTime();
  const bucketSize = 4 * 60 * 60 * 1000; // 4 hours in ms
  
  alerts.forEach(a => {
    const timeDiff = now - new Date(a.timestamp).getTime();
    if (timeDiff >= 0 && timeDiff <= 24 * 60 * 60 * 1000) {
      const bucketIndex = Math.floor(timeDiff / bucketSize);
      if (bucketIndex >= 0 && bucketIndex < 6) {
        buckets[5 - bucketIndex]++; // Reverse so latest is at the end
      }
    }
  });
  
  return buckets.map((count, i) => {
    const date = new Date(now - (5 - i) * bucketSize);
    return {
      time: `${String(date.getHours()).padStart(2, '0')}:00`,
      alerts: count
    };
  });
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#f43f5e',
  HIGH: '#f59e0b',
  MEDIUM: '#14b8a6',
  LOW: '#64748b',
};

// Skeleton loader component
function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse bg-slate-800 rounded ${className}`} />;
}

export default function Dashboard() {
  const { campaigns, loading: camLoading, error: camError, refresh } = useCampaigns();
  const { alerts, loading: alertLoading } = useAlerts(8);

  const [activeCampaignId, setActiveCampaignId] = useState<string | null>(null);

  // Derive the active campaign — use first by default once loaded
  const activeCampaign = campaigns.find(c => c.id === (activeCampaignId ?? campaigns[0]?.id)) ?? campaigns[0];

  // Derive severity distribution from live alerts
  const severityData = Object.entries(
    alerts.reduce<Record<string, number>>((acc, a) => {
      const key = (a.severity as string).toUpperCase();
      acc[key] = (acc[key] ?? 0) + 1;
      return acc;
    }, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 })
  ).map(([name, value]) => ({ name, value, color: SEVERITY_COLORS[name] ?? '#64748b' }));

  const totalAlerts = alerts.length;
  const systemRiskScore = campaigns.length > 0 ? Math.max(...campaigns.map(c => c.riskScore)) : 0;
  
  const volumeData = computeVolumeData(alerts);

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.1 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 300, damping: 24 } }
  };

  return (
    <motion.div 
      className="flex flex-col gap-6"
      variants={containerVariants}
      initial="hidden"
      animate="show"
    >

      {/* Top Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <motion.div variants={itemVariants} whileHover={{ y: -5 }} className="transition-all hover:glow-rose rounded-xl">
          <StatCard
            title="Total Alerts"
            value={alertLoading ? "—" : totalAlerts.toLocaleString()}
            icon={<AlertTriangle className="h-5 w-5" />}
            trend="12%"
            trendUp={false}
            glowColor="rose"
          />
        </motion.div>
        <motion.div variants={itemVariants} whileHover={{ y: -5 }} className="transition-all hover:glow-teal rounded-xl">
          <StatCard
            title="Active Campaigns"
            value={camLoading ? "—" : campaigns.length}
            icon={<Layers className="h-5 w-5" />}
            trend={String(campaigns.length)}
            trendUp={true}
            glowColor="teal"
          />
        </motion.div>
        <motion.div variants={itemVariants} whileHover={{ y: -5 }} className="transition-all hover:glow-amber rounded-xl">
          <StatCard
            title="System Risk Score"
            value={camLoading ? "—" : systemRiskScore}
            icon={<Activity className="h-5 w-5" />}
            trend="5%"
            trendUp={false}
            glowColor="amber"
          />
        </motion.div>
        <motion.div variants={itemVariants} whileHover={{ y: -5 }} className="transition-all hover:glow-indigo rounded-xl">
          <StatCard
            title="Actors Tracked"
            value={camLoading ? "—" : new Set(campaigns.map(c => c.threatActor)).size}
            icon={<Users className="h-5 w-5" />}
            glowColor="indigo"
          />
        </motion.div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Alert Volume Trend */}
        <motion.div variants={itemVariants} className="lg:col-span-2 glass rounded-xl p-5 flex flex-col h-[300px]">
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
        </motion.div>

        {/* Severity Distribution */}
        <motion.div variants={itemVariants} className="lg:col-span-1 glass rounded-xl p-5 flex flex-col h-[300px]">
          <h3 className="font-semibold text-sm text-slate-200 mb-4">Alert Severity Distribution</h3>
          <div className="flex-1 w-full min-h-0 flex items-center justify-center relative">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData.filter(d => d.value > 0)}
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
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-2xl font-bold text-white">{alertLoading ? "—" : totalAlerts}</span>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Total</span>
            </div>
          </div>
        </motion.div>

      </div>

      {/* Bottom Row: Campaigns & Details */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Left: Active Campaigns Widget */}
        <motion.div variants={itemVariants} className="lg:col-span-1 flex flex-col gap-6">
          <div className="glass rounded-xl flex flex-col overflow-hidden h-[300px]">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <h3 className="font-semibold text-sm flex items-center gap-2">
                <Layers className="h-4 w-4 text-teal-400" />
                Active Campaigns
              </h3>
              <button
                onClick={refresh}
                disabled={camLoading}
                title="Refresh campaigns"
                className="p-1 rounded hover:bg-slate-800 transition-colors text-slate-400 hover:text-teal-400 disabled:opacity-40"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${camLoading ? 'animate-spin' : ''}`} />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-1">
              {camLoading ? (
                Array.from({ length: 2 }).map((_, i) => (
                  <div key={i} className="p-3 rounded-lg border border-slate-800 space-y-2">
                    <Skeleton className="h-3 w-3/4" />
                    <Skeleton className="h-2 w-1/2" />
                  </div>
                ))
              ) : camError ? (
                <div className="p-3 text-xs text-rose-400 font-mono">{camError}</div>
              ) : campaigns.length === 0 ? (
                <div className="p-3 text-xs text-slate-500 text-center">No campaigns detected</div>
              ) : (
                campaigns.map(camp => (
                  <button
                    key={camp.id}
                    onClick={() => setActiveCampaignId(camp.id)}
                    className={`text-left p-3 rounded-lg border transition-all text-xs ${
                      (activeCampaignId ?? campaigns[0]?.id) === camp.id
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
                ))
              )}
            </div>
          </div>
        </motion.div>

        {/* Right: Campaign Details & Alerts */}
        <motion.div variants={itemVariants} className="lg:col-span-2 flex flex-col gap-6">

          {/* Campaign Overview Widget */}
          <div className="glass rounded-xl p-5 shadow-lg relative overflow-hidden group">
            <div className="absolute inset-0 bg-gradient-to-r from-teal-500/0 via-teal-500/5 to-teal-500/0 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-1000 ease-in-out pointer-events-none"></div>
            <div className="absolute top-0 right-0 p-6 opacity-5 pointer-events-none">
              <Activity className="h-32 w-32" />
            </div>

            {camLoading ? (
              <div className="space-y-3 relative z-10">
                <Skeleton className="h-3 w-40" />
                <Skeleton className="h-6 w-64" />
                <Skeleton className="h-3 w-full" />
                <Skeleton className="h-3 w-3/4" />
              </div>
            ) : activeCampaign ? (
              <>
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
              </>
            ) : (
              <p className="text-sm text-slate-500 relative z-10">No campaign data available.</p>
            )}
          </div>

          {/* Live Alerts Feed */}
          <div className="glass rounded-xl flex flex-col overflow-hidden flex-1 min-h-[300px]">
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
              {alertLoading ? (
                Array.from({ length: 4 }).map((_, i) => (
                  <div key={i} className="p-3 bg-slate-950/50 border border-slate-800/80 rounded-lg space-y-2">
                    <Skeleton className="h-2 w-24" />
                    <Skeleton className="h-3 w-3/4" />
                    <Skeleton className="h-2 w-full" />
                  </div>
                ))
              ) : alerts.length === 0 ? (
                <div className="text-xs text-slate-500 text-center py-8">No alerts in store</div>
              ) : (
                alerts.slice(0, 8).map(alert => (
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
                ))
              )}
            </div>
          </div>

        </motion.div>
      </div>
    </motion.div>
  );
}

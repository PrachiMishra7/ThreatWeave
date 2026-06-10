import { useState, useEffect } from "react";
import { Terminal, Search, Filter, ShieldAlert, Pause, Play, Download } from "lucide-react";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { simulatedStreamLogs } from "../mockData";

export default function LiveAlerts() {
  const [streamData, setStreamData] = useState<any[]>(simulatedStreamLogs);
  const [isStreaming, setIsStreaming] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);

  useEffect(() => {
    if (!isStreaming) return;

    const eventSource = new EventSource("/api/stream/logs");

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.status === "connected") return;
        setStreamData((prev) => [data, ...prev.slice(0, 99)]); // Keep last 100
      } catch (err) {
        console.error("SSE parse error", err);
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [isStreaming]);

  // Derived state for filtering
  const filteredAlerts = streamData.filter(alert => {
    const matchesSearch = alert.title?.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          alert.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          alert.iocs?.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = selectedSeverity ? alert.severity === selectedSeverity : true;
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] gap-6">
      
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Terminal className="h-6 w-6 text-rose-500" />
            Live Threat Feed
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time ingestion of correlated SIEM and firewall events.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button 
            onClick={() => setIsStreaming(!isStreaming)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg font-semibold text-sm transition-all border ${
              isStreaming 
                ? "bg-rose-500/10 text-rose-400 border-rose-500/30 hover:bg-rose-500/20" 
                : "bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700"
            }`}
          >
            {isStreaming ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
            {isStreaming ? "Pause Stream" : "Resume Stream"}
          </button>
          
          <button className="flex items-center gap-2 px-4 py-2 rounded-lg font-semibold text-sm transition-all border bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700">
            <Download className="h-4 w-4" />
            Export PCAP
          </button>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row gap-4 items-center justify-between shadow-sm">
        
        <div className="relative w-full md:w-96">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <input 
            type="text" 
            placeholder="Search payload signatures or IOCs..." 
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 text-sm text-slate-200 rounded-lg pl-9 pr-4 py-2 focus:outline-none focus:border-teal-500/50 focus:ring-1 focus:ring-teal-500/50 transition-all placeholder:text-slate-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto overflow-x-auto pb-2 md:pb-0">
          <Filter className="h-4 w-4 text-slate-500 mr-1" />
          {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(sev => (
            <button
              key={sev}
              onClick={() => setSelectedSeverity(selectedSeverity === sev ? null : sev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold font-mono tracking-wider transition-all border ${
                selectedSeverity === sev 
                  ? "bg-slate-800 text-white border-slate-600" 
                  : "bg-slate-950 text-slate-500 border-slate-800 hover:border-slate-700 hover:text-slate-300"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Stream Container */}
      <div className="flex-1 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col shadow-inner relative">
        
        {/* Table Header */}
        <div className="grid grid-cols-12 gap-4 p-4 border-b border-slate-800 bg-slate-950/50 text-xs font-semibold text-slate-400 uppercase tracking-wider sticky top-0 z-10">
          <div className="col-span-2">Timestamp</div>
          <div className="col-span-1">Severity</div>
          <div className="col-span-2">Source System</div>
          <div className="col-span-4">Event Signature</div>
          <div className="col-span-3 text-right">IOC Highlights</div>
        </div>

        {/* Scrollable Event List */}
        <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-1">
          {filteredAlerts.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-slate-500 gap-3">
              <ShieldAlert className="h-10 w-10 opacity-20" />
              <p>No telemetry events match your filters.</p>
            </div>
          ) : (
            filteredAlerts.map((log, index) => (
              <div 
                key={index} 
                className="grid grid-cols-12 gap-4 p-3 bg-slate-950/40 hover:bg-slate-800/60 border border-transparent hover:border-slate-700/50 rounded-lg transition-colors items-center group"
              >
                <div className="col-span-2 text-xs font-mono text-slate-400">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </div>
                <div className="col-span-1">
                  <SeverityBadge severity={log.severity} />
                </div>
                <div className="col-span-2 text-xs font-mono text-slate-300">
                  {log.sourceSystem || log.title?.split(':')[0] || "Unknown"}
                </div>
                <div className="col-span-4">
                  <p className="text-xs text-slate-200 font-medium truncate">{log.title}</p>
                  <p className="text-[10px] text-slate-500 font-mono mt-0.5 truncate">{log.description}</p>
                </div>
                <div className="col-span-3 text-right">
                  {log.iocs && (
                    <span className="inline-block px-2 py-1 bg-slate-900 border border-slate-800 rounded text-[10px] font-mono text-teal-400 truncate max-w-full">
                      {log.iocs}
                    </span>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>

    </div>
  );
}

import React, { useState } from "react";
import { Search, Hash, Globe, User, Terminal } from "lucide-react";
import { mockAlerts } from "../mockData";
import { SeverityBadge } from "../components/ui/SeverityBadge";

export default function ThreatLookup() {
  const [query, setQuery] = useState("");
  const [hasSearched, setHasSearched] = useState(false);

  // Very simple mockup search
  const results = mockAlerts.filter(a => 
    a.iocs.some(ioc => ioc.value.toLowerCase().includes(query.toLowerCase())) ||
    a.description.toLowerCase().includes(query.toLowerCase())
  );

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (query.trim()) {
      setHasSearched(true);
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] gap-6">
      <div className="flex flex-col items-center justify-center pt-10 pb-6">
        <h1 className="text-3xl font-bold text-white mb-2">Universal Threat Lookup</h1>
        <p className="text-slate-400 mb-8">Search across all databases for IPs, Domains, Hashes, or Actor names.</p>
        
        <form onSubmit={handleSearch} className="w-full max-w-2xl relative">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-teal-500" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="e.g. 185.247.72.128, ffac3e4d693a8cf8becb71e19488a03c"
            className="w-full bg-slate-900 border-2 border-slate-700 hover:border-teal-500/50 focus:border-teal-500 text-lg text-slate-200 rounded-xl pl-12 pr-4 py-4 focus:outline-none focus:ring-4 focus:ring-teal-500/20 transition-all font-mono shadow-xl"
          />
          <button type="submit" className="absolute right-3 top-1/2 -translate-y-1/2 bg-teal-500 hover:bg-teal-400 text-slate-950 font-bold px-4 py-2 rounded-lg transition-colors">
            Analyze
          </button>
        </form>
      </div>

      {hasSearched && (
        <div className="max-w-4xl mx-auto w-full flex flex-col gap-4 animate-in fade-in slide-in-from-bottom-4">
          <h2 className="text-xl font-bold text-slate-200 mb-2 border-b border-slate-800 pb-2">
            Global Search Results
          </h2>
          
          {results.length === 0 ? (
            <div className="p-8 text-center bg-slate-900 border border-slate-800 rounded-xl text-slate-500">
              No matching intelligence found for "{query}".
            </div>
          ) : (
            <div className="flex flex-col gap-3">
              {results.map(res => (
                <div key={res.id} className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex flex-col gap-2">
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <Terminal className="h-4 w-4 text-slate-400" />
                      <span className="font-semibold text-slate-200">{res.title}</span>
                    </div>
                    <SeverityBadge severity={res.severity} />
                  </div>
                  <p className="text-sm text-slate-400 font-mono">{res.description}</p>
                  <div className="flex flex-wrap gap-2 mt-2">
                    {res.iocs.map((ioc, i) => (
                      <span key={i} className="px-2 py-1 bg-slate-950 border border-slate-700 rounded text-xs font-mono text-teal-400 flex items-center gap-1">
                        {ioc.type.toLowerCase() === 'ip' ? <Globe className="h-3 w-3" /> : <Hash className="h-3 w-3" />}
                        {ioc.value}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

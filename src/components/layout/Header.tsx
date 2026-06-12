import { useState } from "react";
import { Search } from "lucide-react";
import { useNavigate } from "react-router-dom";

export default function Header() {
  const [query, setQuery] = useState("");
  const navigate = useNavigate();

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (query.trim()) {
      navigate(`/lookup?q=${encodeURIComponent(query.trim())}`);
    }
  };

  return (
    <header className="h-16 border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-40 px-6 flex items-center justify-between">
      {/* Global Search */}
      <div className="flex-1 max-w-xl">
        <form onSubmit={handleSearch} className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <input 
            type="text" 
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search IOCs, Alerts, or Campaigns..." 
            className="w-full bg-slate-950 border border-slate-800 text-sm text-slate-200 rounded-full pl-10 pr-4 py-2 focus:outline-none focus:border-teal-500/50 focus:ring-1 focus:ring-teal-500/50 transition-all placeholder:text-slate-500 font-mono"
          />
        </form>
      </div>

      {/* Right Actions */}
      <div className="flex items-center gap-4 ml-4">
        {/* Risk Score Indicator */}
        <div className="hidden md:flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-full border border-slate-800">
          <div className="h-2 w-2 rounded-full bg-amber-500"></div>
          <span className="text-xs font-mono text-slate-300">
            System Risk: <span className="text-amber-500 font-bold">64</span>/100
          </span>
        </div>
      </div>
    </header>
  );
}

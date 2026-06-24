import { useState } from "react";
import type React from "react";
import { Search, Sun, Moon } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useCampaigns } from "../../hooks/useCampaigns";
import { useTheme } from "../../context/ThemeContext";

export default function Header() {
  const [query, setQuery] = useState("");
  const navigate = useNavigate();
  const { campaigns } = useCampaigns();
  const { theme, toggleTheme } = useTheme();

  // Calculate system risk score
  const systemRiskScore = campaigns.length > 0 ? Math.max(...campaigns.map(c => c.riskScore)) : 0;
  
  // Determine color based on risk severity
  const riskColorClass = systemRiskScore > 85 ? "bg-red-500" : systemRiskScore > 50 ? "bg-amber-500" : "bg-teal-500";
  const textColorClass = systemRiskScore > 85 ? "text-red-500" : systemRiskScore > 50 ? "text-amber-500" : "text-teal-500";

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (query.trim()) {
      navigate(`/lookup?q=${encodeURIComponent(query.trim())}`);
    }
  };

  return (
    <header className="h-16 border-b glass sticky top-0 z-40 px-6 flex items-center justify-between border-slate-800/60">
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
          <div className={`h-2 w-2 rounded-full ${riskColorClass}`}></div>
          <span className="text-xs font-mono text-slate-300">
            System Risk: <span className={`${textColorClass} font-bold`}>{systemRiskScore}</span>/100
          </span>
        </div>

        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="p-2 rounded-full bg-slate-950 border border-slate-800 text-slate-400 hover:text-teal-400 hover:border-teal-500/50 transition-colors"
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        >
          {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </button>
      </div>
    </header>
  );
}

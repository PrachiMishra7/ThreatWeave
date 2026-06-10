import { NavLink } from "react-router-dom";
import { 
  Shield, 
  Activity, 
  Layers, 
  Search, 
  Terminal, 
  Cpu, 
  Settings 
} from "lucide-react";
import { cn } from "../../lib/utils";

const navItems = [
  { path: "/dashboard", icon: Activity, label: "Dashboard" },
  { path: "/alerts", icon: Terminal, label: "Live Alerts" },
  { path: "/campaigns", icon: Layers, label: "Campaigns" },
  { path: "/graph", icon: Shield, label: "Graph Explorer" },
  { path: "/lookup", icon: Search, label: "Threat Lookup" },
  { path: "/ai", icon: Cpu, label: "AI Assistant" },
];

export default function Sidebar() {
  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-800 flex flex-col h-screen sticky top-0">
      {/* Brand */}
      <div className="h-16 flex items-center px-6 border-b border-slate-800">
        <div className="h-8 w-8 bg-gradient-to-br from-teal-500 to-emerald-600 rounded-lg flex items-center justify-center shadow-lg shadow-teal-500/10 mr-3">
          <Shield className="h-4 w-4 text-slate-900 stroke-[2.5]" />
        </div>
        <div>
          <span className="font-semibold text-white tracking-tight">ThreatWeave</span>
        </div>
      </div>

      {/* Navigation */}
      <div className="flex-1 overflow-y-auto py-4 px-3 flex flex-col gap-1">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors font-medium",
                isActive 
                  ? "bg-slate-900 text-teal-400" 
                  : "text-slate-400 hover:bg-slate-900/50 hover:text-slate-200"
              )
            }
          >
            <item.icon className="h-4 w-4" />
            {item.label}
          </NavLink>
        ))}
      </div>

      {/* Bottom links */}
      <div className="p-3 border-t border-slate-800">
        <button className="flex w-full items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors font-medium text-slate-400 hover:bg-slate-900/50 hover:text-slate-200">
          <Settings className="h-4 w-4" />
          Settings
        </button>
      </div>
    </aside>
  );
}

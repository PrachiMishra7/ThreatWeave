import { NavLink, useLocation } from "react-router-dom";
import { motion } from "motion/react";
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
  const location = useLocation();

  return (
    <aside className="w-64 glass flex flex-col h-screen sticky top-0 border-r-slate-800/60 z-20">
      {/* Brand */}
      <div className="h-16 flex items-center px-6 border-b border-slate-800/60">
        <motion.div 
          initial={{ rotate: -90, scale: 0.5 }}
          animate={{ rotate: 0, scale: 1 }}
          transition={{ type: "spring", stiffness: 200, damping: 10 }}
          className="h-8 w-8 bg-gradient-to-br from-teal-500 to-emerald-600 rounded-lg flex items-center justify-center glow-teal mr-3"
        >
          <Shield className="h-4 w-4 text-[#0f172a] stroke-[2.5]" />
        </motion.div>
        <div>
          <span className="font-bold text-[#0f172a] dark:text-white tracking-tight drop-shadow-md">ThreatWeave</span>
        </div>
      </div>

      {/* Navigation */}
      <div className="flex-1 overflow-y-auto py-4 px-3 flex flex-col gap-1">
        {navItems.map((item) => {
          const isActive = location.pathname.startsWith(item.path);
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={cn(
                "group relative flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-300 font-medium overflow-hidden",
                isActive 
                  ? "text-teal-600 dark:text-teal-400 bg-slate-800/40 glow-teal border border-teal-500/20" 
                  : "text-slate-600 dark:text-slate-400 hover:bg-slate-800/30 hover:text-slate-900 dark:hover:text-slate-200"
              )}
            >
              {isActive && (
                <motion.div 
                  layoutId="activeNavIndicator"
                  className="absolute left-0 top-0 bottom-0 w-1 bg-teal-500 shadow-[0_0_10px_rgba(20,184,166,0.8)]"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                />
              )}
              <motion.div whileHover={{ scale: 1.1 }} whileTap={{ scale: 0.95 }}>
                <item.icon className={cn("h-4 w-4 transition-colors", isActive ? "text-teal-600 dark:text-teal-400" : "text-slate-500 group-hover:text-teal-600 dark:group-hover:text-teal-500")} />
              </motion.div>
              <span className="relative z-10">{item.label}</span>
            </NavLink>
          );
        })}
      </div>

      {/* Bottom links */}
      <div className="p-3 border-t border-slate-800">
        <button className="flex w-full items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-900/50 hover:text-slate-900 dark:hover:text-slate-200">
          <Settings className="h-4 w-4" />
          Settings
        </button>
      </div>
    </aside>
  );
}

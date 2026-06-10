import { ReactNode } from "react";
import { cn } from "../../lib/utils";

interface StatCardProps {
  title: string;
  value: string | number;
  icon: ReactNode;
  trend?: string;
  trendUp?: boolean;
  className?: string;
  glowColor?: "teal" | "emerald" | "amber" | "red" | "indigo" | "rose";
}

export function StatCard({
  title,
  value,
  icon,
  trend,
  trendUp,
  className,
  glowColor = "teal",
}: StatCardProps) {
  return (
    <div
      className={cn(
        "bg-slate-900 border border-slate-800 rounded-xl p-5 relative overflow-hidden group",
        className
      )}
    >
      {/* Background glow effect */}
      <div
        className={cn(
          "absolute -right-8 -top-8 w-32 h-32 blur-3xl opacity-20 transition-opacity duration-500 group-hover:opacity-40 rounded-full",
          {
            "bg-teal-500": glowColor === "teal",
            "bg-emerald-500": glowColor === "emerald",
            "bg-amber-500": glowColor === "amber",
            "bg-red-500": glowColor === "red",
            "bg-indigo-500": glowColor === "indigo",
            "bg-rose-500": glowColor === "rose",
          }
        )}
      />

      <div className="flex items-start justify-between relative z-10">
        <div>
          <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider mb-1">
            {title}
          </p>
          <h3 className="text-2xl font-bold text-white font-mono">{value}</h3>
          
          {trend && (
            <p className="mt-2 text-[11px] font-mono flex items-center gap-1">
              <span className={cn(trendUp ? "text-emerald-400" : "text-red-400")}>
                {trendUp ? "↑" : "↓"} {trend}
              </span>
              <span className="text-slate-500 ml-1">vs last 24h</span>
            </p>
          )}
        </div>
        
        <div className={cn(
          "p-2.5 rounded-lg border",
          {
            "bg-teal-500/10 border-teal-500/20 text-teal-400": glowColor === "teal",
            "bg-emerald-500/10 border-emerald-500/20 text-emerald-400": glowColor === "emerald",
            "bg-amber-500/10 border-amber-500/20 text-amber-400": glowColor === "amber",
            "bg-red-500/10 border-red-500/20 text-red-400": glowColor === "red",
            "bg-indigo-500/10 border-indigo-500/20 text-indigo-400": glowColor === "indigo",
            "bg-rose-500/10 border-rose-500/20 text-rose-400": glowColor === "rose",
          }
        )}>
          {icon}
        </div>
      </div>
    </div>
  );
}

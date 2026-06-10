import { ReactNode } from "react";
import { cn } from "../../lib/utils";

interface TimelineItemProps {
  title: string;
  description?: string;
  time: string;
  icon?: ReactNode;
  isActive?: boolean;
  isLast?: boolean;
}

export function TimelineItem({
  title,
  description,
  time,
  icon,
  isActive = false,
  isLast = false,
}: TimelineItemProps) {
  return (
    <div className="relative pl-8 pb-6 group">
      {/* Vertical line connecting items */}
      {!isLast && (
        <div className="absolute left-3.5 top-8 bottom-0 w-px bg-slate-800 group-hover:bg-slate-700 transition-colors" />
      )}
      
      {/* Icon or dot marker */}
      <div
        className={cn(
          "absolute left-0 top-1.5 w-7 h-7 rounded-full flex items-center justify-center border-2",
          isActive 
            ? "bg-slate-900 border-teal-500 text-teal-400 shadow-[0_0_10px_rgba(20,184,166,0.3)]" 
            : "bg-slate-950 border-slate-800 text-slate-500"
        )}
      >
        {icon ? (
          <div className="scale-75">{icon}</div>
        ) : (
          <div className={cn("w-2 h-2 rounded-full", isActive ? "bg-teal-500" : "bg-slate-700")} />
        )}
      </div>

      <div className="flex flex-col gap-1">
        <span className="text-[10px] text-slate-500 font-mono tracking-wider uppercase">
          {time}
        </span>
        <h4 className={cn("text-sm font-semibold", isActive ? "text-slate-200" : "text-slate-300")}>
          {title}
        </h4>
        {description && (
          <p className="text-xs text-slate-400 leading-relaxed mt-1 font-mono">
            {description}
          </p>
        )}
      </div>
    </div>
  );
}

export function Timeline({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("flex flex-col", className)}>{children}</div>;
}

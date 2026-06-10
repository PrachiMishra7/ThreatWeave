import { cn } from "../../lib/utils";
import { Severity } from "../../types";

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span
      className={cn(
        "px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase tracking-wider",
        {
          "bg-red-500/20 text-red-400 border border-red-500/30": severity === Severity.CRITICAL,
          "bg-rose-500/10 text-rose-400 border border-rose-500/30": severity === Severity.HIGH,
          "bg-amber-500/10 text-amber-500 border border-amber-500/30": severity === Severity.MEDIUM,
          "bg-sky-500/10 text-sky-400 border border-sky-500/30": severity === Severity.LOW,
        },
        className
      )}
    >
      {severity}
    </span>
  );
}

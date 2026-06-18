import { Handle, Position, NodeProps } from "@xyflow/react";
import { Layers, Terminal, Hash, Globe, User, ShieldAlert } from "lucide-react";
import { cn } from "../../lib/utils";
import { SeverityBadge } from "../ui/SeverityBadge";
import { Severity } from "../../types";

export function CampaignNode({ data }: NodeProps) {
  return (
    <div className="px-4 py-3 shadow-lg rounded-xl bg-slate-900 border-2 border-teal-500/50 min-w-[200px] shadow-teal-500/20 group">
      <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-teal-500" />
      <div className="flex items-center gap-2 mb-2">
        <div className="p-1.5 rounded-lg bg-teal-500/20 text-teal-400 group-hover:bg-teal-500/30 transition-colors">
          <Layers className="w-4 h-4" />
        </div>
        <div className="text-xs font-bold text-slate-200 uppercase tracking-wider">Campaign</div>
      </div>
      <div className="font-bold text-sm text-white mb-1">{data.label as string}</div>
      <div className="text-[10px] text-slate-400 font-mono">Actor: {data.actor as string}</div>
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-teal-500" />
    </div>
  );
}

export function AlertNode({ data }: NodeProps) {
  const sev = data.severity as Severity;
  return (
    <div className="px-3 py-2 shadow-lg rounded-xl bg-slate-950 border border-slate-700 min-w-[180px]">
      <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-slate-500" />
      <div className="flex justify-between items-start mb-2">
        <div className="flex items-center gap-1.5">
          <Terminal className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-[10px] font-semibold text-slate-300">ALERT</span>
        </div>
        <SeverityBadge severity={sev} />
      </div>
      <div className="text-xs font-medium text-slate-200 truncate" title={data.label as string}>
        {data.label as string}
      </div>
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-slate-500" />
    </div>
  );
}

export function IOCNode({ data }: NodeProps) {
  const type = (data.iocType as string)?.toLowerCase();
  
  let Icon = Hash;
  let color = "text-indigo-400";
  let bg = "bg-indigo-500/10";
  let border = "border-indigo-500/30";

  if (type === "ip" || type === "domain") {
    Icon = Globe;
    color = "text-sky-400";
    bg = "bg-sky-500/10";
    border = "border-sky-500/30";
  } else if (type === "user") {
    Icon = User;
    color = "text-amber-400";
    bg = "bg-amber-500/10";
    border = "border-amber-500/30";
  } else if (type === "mitretactic" || type === "tactic") {
    Icon = ShieldAlert;
    color = "text-rose-400";
    bg = "bg-rose-500/10";
    border = "border-rose-500/30";
  } else if (type === "threatactor" || type === "actor") {
    Icon = User;
    color = "text-purple-400";
    bg = "bg-purple-500/10";
    border = "border-purple-500/30";
  }

  return (
    <div className={cn("px-3 py-2 rounded-lg border min-w-[140px] flex items-center gap-2", bg, border)}>
      <Handle type="target" position={Position.Top} className="w-1.5 h-1.5 !bg-slate-500 opacity-50" />
      <Icon className={cn("w-3.5 h-3.5", color)} />
      <div className="flex flex-col">
        <span className={cn("text-[9px] uppercase font-mono font-bold tracking-wider", color)}>
          {type}
        </span>
        <span className="text-xs font-mono text-slate-200 truncate max-w-[120px]" title={data.label as string}>
          {data.label as string}
        </span>
      </div>
      <Handle type="source" position={Position.Bottom} className="w-1.5 h-1.5 !bg-slate-500 opacity-50" />
    </div>
  );
}

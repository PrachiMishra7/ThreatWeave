import { Handle, Position, NodeProps } from "@xyflow/react";
import { Layers, Terminal, Hash, Globe, User, ShieldAlert } from "lucide-react";
import { motion } from "motion/react";
import { cn } from "../../lib/utils";
import { SeverityBadge } from "../ui/SeverityBadge";
import { Severity } from "../../types";

export function CampaignNode({ data }: NodeProps) {
  return (
    <motion.div 
      initial={{ scale: 0.8, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      whileHover={{ scale: 1.05 }}
      transition={{ type: "spring", stiffness: 300, damping: 20 }}
      className="px-5 py-4 rounded-xl glass border-2 border-teal-500/50 min-w-[220px] glow-teal group cursor-grab active:cursor-grabbing"
    >
      <Handle type="target" position={Position.Top} className="w-3 h-3 !bg-teal-400 !border-teal-900 shadow-[0_0_10px_rgba(45,212,191,0.8)]" />
      <div className="flex items-center gap-3 mb-3 border-b border-teal-500/20 pb-2">
        <div className="p-2 rounded-lg bg-teal-500/20 text-teal-400 group-hover:bg-teal-500/40 transition-colors shadow-inner">
          <Layers className="w-5 h-5" />
        </div>
        <div className="flex flex-col">
          <span className="text-xs font-black text-teal-500 uppercase tracking-widest drop-shadow-sm">Campaign</span>
          <span className="text-[11px] font-bold text-slate-300 font-mono">ID: {((data.id as string) || "").substring(0, 8)}</span>
        </div>
      </div>
      <div className="font-extrabold text-lg text-white mb-1.5 drop-shadow-sm leading-tight">{data.label as string}</div>
      <div className="text-xs font-bold text-teal-100 font-mono flex items-center gap-1.5 bg-slate-950/60 px-2.5 py-1.5 rounded-md border border-slate-800">
        <User className="h-3.5 w-3.5 text-teal-400" /> {data.actor as string}
      </div>
      <Handle type="source" position={Position.Bottom} className="w-3 h-3 !bg-teal-400 !border-teal-900 shadow-[0_0_10px_rgba(45,212,191,0.8)]" />
    </motion.div>
  );
}

export function AlertNode({ data }: NodeProps) {
  const sev = data.severity as Severity;
  return (
    <motion.div 
      initial={{ scale: 0.8, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      whileHover={{ scale: 1.05 }}
      transition={{ type: "spring", stiffness: 300, damping: 20 }}
      className="px-4 py-3 rounded-xl glass min-w-[200px] border-l-4 border-l-slate-500 shadow-xl cursor-grab active:cursor-grabbing"
    >
      <Handle type="target" position={Position.Top} className="w-2.5 h-2.5 !bg-slate-400 !border-slate-800" />
      <div className="flex justify-between items-center mb-3">
        <div className="flex items-center gap-2 bg-slate-900/60 px-2 py-1 rounded-md border border-slate-700/50">
          <Terminal className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-[10px] font-black tracking-widest text-slate-300">ALERT</span>
        </div>
        <SeverityBadge severity={sev} />
      </div>
      <div className="text-base font-bold text-slate-100 truncate" title={data.label as string}>
        {data.label as string}
      </div>
      <Handle type="source" position={Position.Bottom} className="w-2.5 h-2.5 !bg-slate-400 !border-slate-800" />
    </motion.div>
  );
}

export function IOCNode({ data }: NodeProps) {
  const type = (data.iocType as string)?.toLowerCase();
  
  let Icon = Hash;
  let color = "text-indigo-400";
  let bg = "bg-indigo-500/10";
  let border = "border-indigo-500/30";
  let glow = "glow-indigo";

  if (type === "ip" || type === "domain") {
    Icon = Globe;
    color = "text-sky-400";
    bg = "bg-sky-500/10";
    border = "border-sky-500/30";
    glow = "shadow-[0_0_15px_rgba(56,189,248,0.15)]";
  } else if (type === "user") {
    Icon = User;
    color = "text-amber-400";
    bg = "bg-amber-500/10";
    border = "border-amber-500/30";
    glow = "glow-amber";
  } else if (type === "mitretactic" || type === "tactic") {
    Icon = ShieldAlert;
    color = "text-rose-400";
    bg = "bg-rose-500/10";
    border = "border-rose-500/40";
    glow = "glow-red";
  } else if (type === "threatactor" || type === "actor") {
    Icon = User;
    color = "text-purple-400";
    bg = "bg-purple-500/10";
    border = "border-purple-500/40";
    glow = "shadow-[0_0_15px_rgba(168,85,247,0.2)]";
  }

  return (
    <motion.div 
      initial={{ scale: 0.8, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      whileHover={{ scale: 1.1, y: -2 }}
      className={cn("px-3 py-2.5 rounded-lg border min-w-[150px] flex items-center gap-3 cursor-pointer backdrop-blur-md transition-shadow", bg, border, glow)}
    >
      <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-slate-500 opacity-0 group-hover:opacity-100 transition-opacity" />
      <div className={cn("p-1.5 rounded-md bg-slate-950/50 shadow-inner", color)}>
        <Icon className="w-4 h-4" />
      </div>
      <div className="flex flex-col min-w-0">
        <span className={cn("text-[10px] uppercase font-mono font-black tracking-widest", color)}>
          {type}
        </span>
        <span className="text-sm font-bold font-mono text-slate-100 truncate w-full" title={data.label as string}>
          {data.label as string}
        </span>
      </div>
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-slate-500 opacity-0 group-hover:opacity-100 transition-opacity" />
    </motion.div>
  );
}

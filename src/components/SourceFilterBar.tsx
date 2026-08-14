import React from "react";
import { Database, Radio, Shield, FileText, Cpu, Layers } from "lucide-react";
import { cn } from "./ui";

export type SourceFilterType = "ALL" | "REPORTS" | "NVD" | "CISA_KEV" | "MITRE" | "AI" | "DEMO";

interface SourceFilterBarProps {
  activeFilter: SourceFilterType;
  onFilterChange: (filter: SourceFilterType) => void;
  counts?: Partial<Record<SourceFilterType, number>>;
  className?: string;
}

export function SourceFilterBar({
  activeFilter,
  onFilterChange,
  counts = {},
  className
}: SourceFilterBarProps) {
  const filters: Array<{ id: SourceFilterType; label: string; icon: any; colorClass: string }> = [
    { id: "ALL", label: "All Sources", icon: Layers, colorClass: "text-slate-400" },
    { id: "REPORTS", label: "Threat Reports", icon: FileText, colorClass: "text-blue-400" },
    { id: "NVD", label: "NIST NVD", icon: Database, colorClass: "text-cyan-400" },
    { id: "CISA_KEV", label: "CISA KEV", icon: Radio, colorClass: "text-red-400" },
    { id: "MITRE", label: "MITRE ATT&CK", icon: Shield, colorClass: "text-indigo-400" },
    { id: "AI", label: "AI Analysis", icon: Cpu, colorClass: "text-purple-400" }
  ];

  return (
    <div className={cn("flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-none", className)}>
      {filters.map(item => {
        const Icon = item.icon;
        const isActive = activeFilter === item.id;
        const count = counts[item.id];

        return (
          <button
            key={item.id}
            id={`source-filter-${item.id.toLowerCase()}`}
            onClick={() => onFilterChange(item.id)}
            className={cn(
              "flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all border",
              isActive
                ? "bg-slate-800 text-white border-cyan-500/50 shadow-sm shadow-cyan-950/40"
                : "bg-[#090F1D]/70 text-slate-400 border-slate-800/80 hover:text-slate-200 hover:bg-slate-800/50 hover:border-slate-700"
            )}
          >
            <Icon className={cn("w-3.5 h-3.5", isActive ? "text-cyan-400" : item.colorClass)} />
            <span>{item.label}</span>
            {count !== undefined && (
              <span className={cn(
                "text-[10px] px-1.5 py-0.2 rounded-full font-mono font-bold",
                isActive ? "bg-cyan-950 text-cyan-300 border border-cyan-500/30" : "bg-slate-800 text-slate-400"
              )}>
                {count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

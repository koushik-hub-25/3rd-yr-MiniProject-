import React from "react";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { Shield, AlertTriangle, AlertCircle, Info, CheckCircle2, Database, Cpu, FileText, Globe, Radio } from "lucide-react";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Original ShieldZen Brand Logo Component
export function ShieldZenLogo({
  size = "default",
  showTagline = true,
  className
}: {
  size?: "small" | "default" | "large";
  showTagline?: boolean;
  className?: string;
}) {
  const iconSizes = {
    small: "w-7 h-7",
    default: "w-9 h-9",
    large: "w-12 h-12"
  };

  const titleSizes = {
    small: "text-base",
    default: "text-lg",
    large: "text-2xl"
  };

  return (
    <div className={cn("flex items-center gap-3 select-none", className)}>
      <div className={cn(
        "relative rounded-xl bg-gradient-to-b from-[#0e2748] to-[#0a182c] border border-cyan-500/40 p-2 flex items-center justify-center shadow-lg shadow-cyan-950/50 flex-shrink-0 group",
        iconSizes[size]
      )}>
        {/* Subtle background glow */}
        <div className="absolute inset-0 bg-cyan-500/10 rounded-xl blur-sm group-hover:bg-cyan-500/20 transition-colors" />
        
        {/* Shield outline with signal nodes */}
        <svg viewBox="0 0 24 24" className="w-full h-full text-cyan-400 drop-shadow-[0_0_8px_rgba(6,182,212,0.6)]" fill="none" stroke="currentColor" strokeWidth="1.75">
          <path d="M12 2L4 6v6c0 5.5 3.5 10.5 8 12 4.5-1.5 8-6.5 8-12V6l-8-4z" />
          <circle cx="12" cy="11" r="2.2" fill="currentColor" />
          <path d="M12 6.5v2.2M12 13.5v2.5M7.5 11h2.2M14.3 11h2.2" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      </div>

      <div>
        <div className="flex items-center gap-1.5 leading-none">
          <span className={cn("font-extrabold tracking-tight text-white", titleSizes[size])}>
            Shield<span className="text-cyan-400">Zen</span>
          </span>
          <span className="text-[9px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 px-1.5 py-0.5 rounded tracking-widest">
            CTI
          </span>
        </div>
        {showTagline && (
          <p className="text-[10px] text-slate-400 font-medium tracking-tight mt-0.5">
            AI Threat Intelligence & Prioritization
          </p>
        )}
      </div>
    </div>
  );
}

export function Card({ className, children, id, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div id={id} {...props} className={cn("bg-[#0B1222] border border-slate-800/80 rounded-xl overflow-hidden flex flex-col shadow-xl shadow-black/40 hover:border-slate-700/80 transition-colors", className)}>
      {children}
    </div>
  );
}

export function CardHeader({ className, children }: { className?: string; children: React.ReactNode }) {
  return <div className={cn("px-5 py-4 border-b border-slate-800/70 flex justify-between items-center bg-[#0d162b]/40", className)}>{children}</div>;
}

export function CardTitle({ className, children }: { className?: string; children: React.ReactNode }) {
  return <h3 className={cn("text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2", className)}>{children}</h3>;
}

export function CardContent({ className, children }: { className?: string; children: React.ReactNode }) {
  return <div className={cn("p-5 flex-1 flex flex-col", className)}>{children}</div>;
}

export function Badge({
  children,
  variant = "default",
  className,
  id
}: {
  children: React.ReactNode;
  variant?: "default" | "critical" | "high" | "medium" | "low" | "info" | "outline" | "success" | "cyan";
  className?: string;
  id?: string;
}) {
  const variants = {
    default: "bg-slate-800/80 text-slate-300 border border-slate-700/50",
    critical: "bg-red-950/70 text-red-400 border border-red-500/40 shadow-sm shadow-red-950/50",
    high: "bg-orange-950/70 text-orange-400 border border-orange-500/40 shadow-sm shadow-orange-950/50",
    medium: "bg-amber-950/70 text-amber-300 border border-amber-500/40 shadow-sm shadow-amber-950/50",
    low: "bg-emerald-950/70 text-emerald-400 border border-emerald-500/40 shadow-sm shadow-emerald-950/50",
    info: "bg-blue-950/70 text-blue-400 border border-blue-500/40 shadow-sm shadow-blue-950/50",
    cyan: "bg-cyan-950/70 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-950/50",
    success: "bg-emerald-950/70 text-emerald-400 border border-emerald-500/40",
    outline: "border border-slate-700 text-slate-300 bg-slate-900/30"
  };

  return (
    <span
      id={id}
      className={cn(
        "inline-flex items-center px-2.5 py-0.5 rounded text-[11px] uppercase font-bold tracking-wider whitespace-nowrap gap-1 font-mono",
        variants[variant],
        className
      )}
    >
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const s = severity?.toUpperCase() || "MEDIUM";
  if (s === "CRITICAL") return <Badge variant="critical"><AlertCircle className="w-3 h-3 text-red-400" /> CRITICAL</Badge>;
  if (s === "HIGH") return <Badge variant="high"><AlertTriangle className="w-3 h-3 text-orange-400" /> HIGH</Badge>;
  if (s === "MEDIUM") return <Badge variant="medium"><AlertTriangle className="w-3 h-3 text-amber-400" /> MEDIUM</Badge>;
  if (s === "LOW") return <Badge variant="low"><CheckCircle2 className="w-3 h-3 text-emerald-400" /> LOW</Badge>;
  return <Badge variant="info"><Info className="w-3 h-3 text-blue-400" /> {s}</Badge>;
}

// Visual Data Source Labels
export function DataOriginLabel({ origin }: { origin: "PUBLIC" | "AI" | "SYNTHETIC" | string }) {
  const o = origin?.toUpperCase();
  if (o === "PUBLIC" || o === "VERIFIED PUBLIC DATA") {
    return (
      <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-500/40">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
        VERIFIED PUBLIC DATA
      </span>
    );
  }
  if (o === "AI" || o === "AI ANALYSIS") {
    return (
      <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-500/40">
        <span className="w-1.5 h-1.5 rounded-full bg-indigo-400"></span>
        AI ANALYSIS
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-700">
      <span className="w-1.5 h-1.5 rounded-full bg-slate-500"></span>
      SYNTHETIC DEMO
    </span>
  );
}

// Source Identification Badges
export function SourceBadge({ source }: { source: string }) {
  const s = source?.toUpperCase() || "";
  if (s.includes("NVD") || s.includes("NIST")) {
    return <Badge variant="cyan" className="text-[10px]"><Database className="w-3 h-3 text-cyan-400" /> NVD</Badge>;
  }
  if (s.includes("CISA") || s.includes("KEV")) {
    return <Badge variant="critical" className="text-[10px] bg-red-950/80 text-red-300 border-red-500/50"><Radio className="w-3 h-3 text-red-400 animate-pulse" /> CISA KEV</Badge>;
  }
  if (s.includes("MITRE") || s.includes("ATT&CK")) {
    return <Badge variant="info" className="text-[10px]"><Shield className="w-3 h-3 text-blue-400" /> MITRE ATT&CK</Badge>;
  }
  if (s.includes("GEMINI") || s.includes("AI")) {
    return <Badge variant="default" className="text-[10px] bg-indigo-950/70 text-indigo-300 border-indigo-500/40"><Cpu className="w-3 h-3 text-indigo-400" /> GEMINI AI</Badge>;
  }
  if (s.includes("REPORT") || s.includes("UPLOAD")) {
    return <Badge variant="outline" className="text-[10px]"><FileText className="w-3 h-3 text-slate-400" /> UPLOADED REPORT</Badge>;
  }
  return <Badge variant="outline" className="text-[10px]">{source}</Badge>;
}

export function ConfidenceMeter({ confidence }: { confidence: number }) {
  let color = "bg-blue-500";
  if (confidence >= 90) color = "bg-emerald-500";
  else if (confidence >= 75) color = "bg-cyan-500";
  else if (confidence >= 50) color = "bg-amber-500";
  else color = "bg-red-500";

  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
        <div className={cn("h-full rounded-full transition-all duration-500", color)} style={{ width: `${confidence}%` }} />
      </div>
      <span className="text-[11px] font-mono font-medium text-slate-300">{confidence}%</span>
    </div>
  );
}

export function Modal({
  isOpen,
  onClose,
  title,
  children,
  maxWidth = "max-w-3xl"
}: {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  maxWidth?: string;
}) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-in fade-in duration-200">
      <div className={cn("w-full bg-[#090F1C] border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]", maxWidth)}>
        <div className="px-6 py-4 border-b border-slate-800/80 flex items-center justify-between bg-[#0D1527]">
          <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">{title}</h3>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1.5 rounded-lg hover:bg-slate-800 transition-colors"
          >
            ✕
          </button>
        </div>
        <div className="p-6 overflow-y-auto flex-1">{children}</div>
      </div>
    </div>
  );
}


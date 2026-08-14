import React, { useState, useRef, useEffect } from "react";
import { Bot, Send, Sparkles, X, ChevronRight, AlertTriangle, Shield, Terminal, ArrowRight, ExternalLink, RefreshCw } from "lucide-react";
import { cn, Badge, SeverityBadge } from "./ui";
import { Link } from "react-router-dom";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  citedThreats?: Array<{ id: string; title: string; severity: string }>;
  citedIocs?: Array<{ type: string; value: string }>;
  citedCves?: string[];
  engineMode?: string;
  timestamp: string;
}

interface AIAnalystDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  focusedThreatId?: string;
  initialPrompt?: string;
}

const PREBUILT_QUERIES = [
  "What are the highest-priority threats?",
  "Summarize today's critical findings.",
  "Which vulnerabilities appear most frequently?",
  "Which threats are increasing?",
  "Show me incidents related to ransomware.",
  "Explain why recent threats were classified as High or Critical."
];

export function AIAnalystDrawer({
  isOpen,
  onClose,
  focusedThreatId,
  initialPrompt
}: AIAnalystDrawerProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "welcome-msg",
      role: "assistant",
      content: "Hello Analyst. I am **ShieldZen AI Analyst**, connected directly to your operational intelligence database, NIST NVD, CISA KEV catalog, and MITRE ATT&CK Matrix.\n\nAsk me any question about active attack campaigns, vulnerability exploitation, or risk prioritization rationale.",
      timestamp: new Date().toISOString(),
      engineMode: "ShieldZen Core AI"
    }
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (initialPrompt && isOpen) {
      handleSend(initialPrompt);
    }
  }, [initialPrompt, isOpen]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, loading]);

  const handleSend = async (queryText?: string) => {
    const textToSend = queryText || input;
    if (!textToSend.trim() || loading) return;

    const userMessage: Message = {
      id: "user-" + Date.now(),
      role: "user",
      content: textToSend,
      timestamp: new Date().toISOString()
    };

    setMessages(prev => [...prev, userMessage]);
    setInput("");
    setLoading(true);

    try {
      const history = messages.slice(-4).map(m => ({ role: m.role, content: m.content }));
      const res = await fetch("/api/ai-analyst/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          prompt: textToSend,
          contextThreatId: focusedThreatId,
          conversationHistory: history
        })
      });

      if (!res.ok) {
        throw new Error("Analysis failed");
      }

      const data = await res.json();
      const assistantMessage: Message = {
        id: "asst-" + Date.now(),
        role: "assistant",
        content: data.answer,
        citedThreats: data.citedThreats,
        citedIocs: data.citedIocs,
        citedCves: data.citedCves,
        engineMode: data.engineMode,
        timestamp: data.timestamp || new Date().toISOString()
      };

      setMessages(prev => [...prev, assistantMessage]);
    } catch (e: any) {
      const errorMessage: Message = {
        id: "err-" + Date.now(),
        role: "assistant",
        content: `**Analysis Telemetry Interruption:** ${e.message}. Please verify local API service state.`,
        timestamp: new Date().toISOString(),
        engineMode: "Deterministic Fallback"
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-xl bg-[#090F1C] border-l border-slate-800 flex flex-col h-full shadow-2xl animate-in slide-in-from-right duration-300">
        {/* Header */}
        <div className="px-5 py-4 border-b border-slate-800/80 bg-[#0D1527] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-b from-indigo-500/30 to-indigo-900/40 border border-indigo-500/40 flex items-center justify-center text-indigo-400">
              <Bot className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-white tracking-tight">ShieldZen AI Analyst</h2>
                <span className="text-[10px] font-mono font-bold bg-indigo-950 text-indigo-300 border border-indigo-500/40 px-1.5 py-0.2 rounded">
                  SOC Copilot
                </span>
              </div>
              <p className="text-[11px] text-slate-400">Context-aware conversational threat triage</p>
            </div>
          </div>
          <button
            id="btn-close-ai-drawer"
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Quick Query Chips */}
        <div className="px-5 py-3 border-b border-slate-800/60 bg-[#0B1220]/60 overflow-x-auto scrollbar-none flex items-center gap-2">
          <span className="text-[10px] uppercase font-bold text-slate-500 font-mono flex-shrink-0">Quick Ask:</span>
          {PREBUILT_QUERIES.map((q, idx) => (
            <button
              key={idx}
              onClick={() => handleSend(q)}
              disabled={loading}
              className="text-[11px] text-slate-300 bg-slate-800/80 hover:bg-cyan-950 hover:text-cyan-300 hover:border-cyan-500/40 border border-slate-700/60 rounded-full px-3 py-1 whitespace-nowrap transition-colors flex-shrink-0"
            >
              {q}
            </button>
          ))}
        </div>

        {/* Chat Messages Body */}
        <div ref={scrollRef} className="flex-1 p-5 overflow-y-auto space-y-4">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={cn(
                "flex flex-col max-w-[92%]",
                msg.role === "user" ? "ml-auto items-end" : "mr-auto items-start"
              )}
            >
              <div
                className={cn(
                  "p-4 rounded-2xl text-xs leading-relaxed",
                  msg.role === "user"
                    ? "bg-cyan-600 text-white rounded-br-none shadow-md shadow-cyan-950/40"
                    : "bg-[#0E162B] text-slate-200 border border-slate-800/80 rounded-bl-none shadow-md"
                )}
              >
                {/* Format markdown-like text */}
                <div className="whitespace-pre-wrap font-sans space-y-2">
                  {msg.content}
                </div>

                {/* Cited Threats Pillbox */}
                {msg.citedThreats && msg.citedThreats.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-slate-700/60">
                    <p className="text-[10px] font-mono uppercase text-slate-400 font-bold mb-1.5">Referenced Threats:</p>
                    <div className="flex flex-wrap gap-1.5">
                      {msg.citedThreats.map(t => (
                        <Link
                          key={t.id}
                          to={`/threats/${t.id}`}
                          onClick={onClose}
                          className="inline-flex items-center gap-1.5 bg-[#090F1C] border border-slate-700 hover:border-cyan-500 text-slate-300 hover:text-cyan-300 px-2 py-0.5 rounded text-[11px] font-medium transition-colors"
                        >
                          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                          <span className="truncate max-w-[150px]">{t.title}</span>
                          <SeverityBadge severity={t.severity} />
                        </Link>
                      ))}
                    </div>
                  </div>
                )}

                {/* Cited CVEs */}
                {msg.citedCves && msg.citedCves.length > 0 && (
                  <div className="mt-2.5 flex items-center gap-1.5 flex-wrap">
                    <span className="text-[10px] font-mono text-slate-400 font-bold">CVEs:</span>
                    {msg.citedCves.map(cve => (
                      <span key={cve} className="px-2 py-0.5 bg-cyan-950 text-cyan-300 border border-cyan-500/30 rounded text-[10px] font-mono font-bold">
                        {cve}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Message metadata */}
              <div className="flex items-center gap-2 mt-1 px-1 text-[10px] text-slate-500 font-mono">
                <span>{new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                {msg.engineMode && (
                  <>
                    <span>•</span>
                    <span className="text-indigo-400">{msg.engineMode}</span>
                  </>
                )}
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex items-center gap-2 text-slate-400 text-xs p-3 bg-[#0E162B] border border-slate-800 rounded-xl max-w-xs animate-pulse">
              <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
              <span>Correlating intelligence & querying models...</span>
            </div>
          )}
        </div>

        {/* Input Box */}
        <div className="p-4 border-t border-slate-800/80 bg-[#0D1527]">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSend();
            }}
            className="flex items-center gap-2"
          >
            <input
              id="input-ai-analyst-prompt"
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask ShieldZen AI about threats, IOCs, CVEs..."
              className="flex-1 bg-[#090F1C] border border-slate-700/80 rounded-xl px-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/80 transition-colors font-sans"
              disabled={loading}
            />
            <button
              id="btn-send-ai-analyst"
              type="submit"
              disabled={loading || !input.trim()}
              className="p-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-xl transition-colors flex items-center justify-center shadow-lg shadow-cyan-950/50"
            >
              <Send className="w-4 h-4" />
            </button>
          </form>
          <div className="flex items-center justify-between mt-2 px-1 text-[10px] text-slate-500">
            <span>Powered by Gemini 3.7 Flash & Multi-Source CTI</span>
            <span>Deterministic Sandbox Ready</span>
          </div>
        </div>
      </div>
    </div>
  );
}

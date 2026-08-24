import React, { useState, useEffect } from "react";
import { Plus, X, AlertCircle, CheckCircle, ShieldAlert } from "lucide-react";
import type { IocType } from "../types";

interface AddIocModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (newIoc: any) => void;
}

export default function AddIocModal({ isOpen, onClose, onSuccess }: AddIocModalProps) {
  const [value, setValue] = useState("");
  const [type, setType] = useState<IocType>("IPv4");
  const [confidence, setConfidence] = useState(90);
  const [severity, setSeverity] = useState("HIGH");
  const [context, setContext] = useState("");
  const [tags, setTags] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Auto-detect type when value changes
  useEffect(() => {
    if (!value.trim()) return;
    const v = value.trim();
    if (/^CVE-\d{4}-\d{4,8}$/i.test(v)) setType("CVE");
    else if (/^[a-fA-F0-9]{64}$/.test(v)) setType("SHA256");
    else if (/^[a-fA-F0-9]{40}$/.test(v)) setType("SHA1");
    else if (/^[a-fA-F0-9]{32}$/.test(v)) setType("MD5");
    else if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(v)) setType("IPv4");
    else if (/:/.test(v) && /^[a-fA-F0-9:]+$/.test(v)) setType("IPv6");
    else if (/^https?:\/\//i.test(v)) setType("URL");
    else if (/@/.test(v) && /\.[a-z]{2,}$/i.test(v)) setType("Email");
    else if (/^HKLM|^HKCU/i.test(v)) setType("Registry");
    else if (/\.(exe|dll|sys|jsp|bin|elf|sh|ps1)$/i.test(v)) setType("Filename");
    else if (/\.[a-z]{2,}$/i.test(v)) setType("Domain");
  }, [value]);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!value.trim()) {
      setError("Please specify an indicator artifact value.");
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const res = await fetch("/api/iocs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          value: value.trim(),
          type,
          confidence,
          severity,
          context: context.trim() || undefined,
          tags: tags.trim() || undefined
        })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || "Failed to register indicator");
      }

      const created = await res.json();
      onSuccess(created);
      onClose();
      setValue("");
      setContext("");
      setTags("");
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-[#0b101b] border border-slate-800 rounded-xl max-w-lg w-full shadow-2xl overflow-hidden font-sans">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-2">
            <Plus className="w-5 h-5 text-blue-400" />
            <h3 className="text-base font-bold text-white">Register Threat Indicator</h3>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4 text-xs">
          {error && (
            <div className="p-3 rounded-lg bg-red-950/60 border border-red-500/40 text-red-300 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div>
            <label className="block text-slate-300 font-semibold mb-1 font-mono text-[11px] uppercase">
              Indicator Artifact Value *
            </label>
            <input
              type="text"
              required
              placeholder="e.g. 185.220.101.42, evil-c2.org, 8f4e21a4..., CVE-2024-3400"
              value={value}
              onChange={e => setValue(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white font-mono placeholder-slate-600 focus:ring-1 focus:ring-blue-500 outline-none"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-300 font-semibold mb-1 font-mono text-[11px] uppercase">
                Artifact Type
              </label>
              <select
                value={type}
                onChange={e => setType(e.target.value as IocType)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 font-mono focus:ring-1 focus:ring-blue-500 outline-none"
              >
                <option value="IPv4">IPv4</option>
                <option value="IPv6">IPv6</option>
                <option value="Domain">Domain</option>
                <option value="URL">URL</option>
                <option value="SHA256">SHA256</option>
                <option value="SHA1">SHA1</option>
                <option value="MD5">MD5</option>
                <option value="CVE">CVE</option>
                <option value="Filename">Filename</option>
                <option value="Registry">Registry</option>
                <option value="Email">Email</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-semibold mb-1 font-mono text-[11px] uppercase">
                Threat Severity
              </label>
              <select
                value={severity}
                onChange={e => setSeverity(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 font-mono focus:ring-1 focus:ring-blue-500 outline-none"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-slate-300 font-semibold font-mono text-[11px] uppercase">
                Analyst Confidence
              </label>
              <span className="text-emerald-400 font-mono font-bold">{confidence}%</span>
            </div>
            <input
              type="range"
              min="10"
              max="100"
              value={confidence}
              onChange={e => setConfidence(parseInt(e.target.value, 10))}
              className="w-full accent-blue-500 bg-slate-800"
            />
          </div>

          <div>
            <label className="block text-slate-300 font-semibold mb-1 font-mono text-[11px] uppercase">
              Threat Context / Role
            </label>
            <textarea
              rows={2}
              placeholder="e.g. Cobalt Strike egress proxy observed in credential theft campaign..."
              value={context}
              onChange={e => setContext(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white font-sans placeholder-slate-600 focus:ring-1 focus:ring-blue-500 outline-none"
            />
          </div>

          <div>
            <label className="block text-slate-300 font-semibold mb-1 font-mono text-[11px] uppercase">
              Tags (Comma separated)
            </label>
            <input
              type="text"
              placeholder="c2, apt29, tor-exit, cobalt-strike"
              value={tags}
              onChange={e => setTags(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-white font-mono placeholder-slate-600 focus:ring-1 focus:ring-blue-500 outline-none text-xs"
            />
          </div>

          <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold uppercase tracking-wider font-mono border border-slate-700 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold uppercase tracking-wider font-mono transition-colors shadow-md shadow-blue-600/30"
            >
              {loading ? "Registering..." : "Add to Vault"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

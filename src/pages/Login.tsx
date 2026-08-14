/**
 * ShieldZen Academic Research Prototype - Analyst Authentication View
 * Note: Features prototype authentication with simulated RBAC roles for academic demonstrations.
 */
import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { ShieldCheck, Lock, User, ArrowRight, Database, Radio, Cpu, Sparkles, Shield, KeyRound, Check } from "lucide-react";
import { cn } from "../components/ui";

export default function Login() {
  const [email, setEmail] = useState("alex.morgan@shieldzen.sec");
  const [password, setPassword] = useState("••••••••");
  const [rememberMe, setRememberMe] = useState(true);
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    await login(email, password);
    setLoading(false);
    navigate("/");
  };

  const handleQuickDemoLogin = async (roleEmail: string) => {
    setLoading(true);
    await login(roleEmail, "demo123");
    setLoading(false);
    navigate("/");
  };

  return (
    <div className="min-h-screen bg-[#070B14] text-[#E0E6ED] flex flex-col justify-between relative overflow-hidden font-sans selection:bg-cyan-500/20 selection:text-cyan-200">
      {/* Ambient background glowing orbs & subtle grid */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b12_1px,transparent_1px),linear-gradient(to_bottom,#1e293b12_1px,transparent_1px)] bg-[size:40px_40px] pointer-events-none" />
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-cyan-600/10 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute bottom-10 right-10 w-[400px] h-[300px] bg-indigo-600/10 rounded-full blur-[120px] pointer-events-none" />

      {/* Top Brand Header */}
      <header className="w-full max-w-7xl mx-auto px-6 py-6 flex items-center justify-between relative z-10">
        <Link to="/" className="flex items-center gap-3 group">
          <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-600 p-[1px] shadow-md shadow-cyan-950/50">
            <div className="w-full h-full bg-[#080D1A] rounded-[11px] flex items-center justify-center">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
            </div>
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-extrabold tracking-tight text-white">
              Shield<span className="text-cyan-400">Zen</span>
            </span>
            <span className="text-[9px] font-mono text-slate-400 tracking-wider uppercase">
              Cyber Threat Intelligence
            </span>
          </div>
        </Link>

        <span className="text-[10px] font-mono bg-cyan-950/70 border border-cyan-500/30 px-2.5 py-1 rounded-full text-cyan-300 font-bold">
          SOC TIER-1 CLEARANCE REQUIRED
        </span>
      </header>

      {/* Main Center Content */}
      <main className="w-full max-w-md mx-auto px-4 py-8 relative z-10 flex flex-col items-center">
        {/* Hero Copy */}
        <div className="text-center mb-8 space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-[10px] font-mono font-bold text-cyan-300 uppercase">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            SECURE ANALYST ACCESS
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            See Beyond the <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-indigo-400">Noise.</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 max-w-sm mx-auto leading-relaxed">
            ShieldZen turns complex cybersecurity intelligence into clear, prioritized insight.
          </p>
        </div>

        {/* Authentication Card */}
        <div className="w-full bg-[#090F1C] border border-slate-800/90 rounded-3xl p-7 shadow-2xl space-y-6">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800/80">
            <div className="flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider">
                Sign In to Console
              </span>
            </div>
            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/80 border border-emerald-500/30 px-2 py-0.5 rounded font-bold">
              VERIFIED
            </span>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-[11px] font-mono font-bold uppercase text-slate-400 mb-1.5">
                Analyst Identity (Email)
              </label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                <input
                  id="login-email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  placeholder="analyst@shieldzen.sec"
                  className="w-full bg-[#070B14] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/80 transition-colors font-mono"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="block text-[11px] font-mono font-bold uppercase text-slate-400">
                  Security Credential (Password)
                </label>
              </div>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                <input
                  id="login-password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  placeholder="••••••••"
                  className="w-full bg-[#070B14] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/80 transition-colors font-mono"
                />
              </div>
            </div>

            {/* Remember Me Checkbox */}
            <div className="flex items-center justify-between pt-1">
              <label
                onClick={() => setRememberMe(!rememberMe)}
                className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer select-none"
              >
                <div
                  className={cn(
                    "w-4 h-4 rounded border flex items-center justify-center transition-colors",
                    rememberMe
                      ? "bg-cyan-600 border-cyan-500 text-white"
                      : "border-slate-700 bg-[#070B14]"
                  )}
                >
                  {rememberMe && <Check className="w-3 h-3" />}
                </div>
                <span>Remember this workstation</span>
              </label>
            </div>

            <button
              id="btn-submit-login"
              type="submit"
              disabled={loading}
              className="w-full mt-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold py-3 rounded-xl text-xs uppercase tracking-wider flex items-center justify-center gap-2 shadow-lg shadow-cyan-950/60 transition-all cursor-pointer"
            >
              {loading ? "Authenticating Clearance..." : "Access ShieldZen Console"}
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          {/* Quick Demo Analyst Preset Profiles */}
          <div className="pt-5 border-t border-slate-800/80 space-y-2.5">
            <p className="text-[10px] font-mono uppercase text-slate-500 font-bold text-center">
              1-Click Demo Analyst Profiles
            </p>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                id="btn-demo-alex-morgan"
                onClick={() => handleQuickDemoLogin("alex.morgan@shieldzen.sec")}
                className="p-3 rounded-xl bg-[#070B14] hover:bg-cyan-950/40 border border-slate-800 hover:border-cyan-500/40 text-left transition-colors group cursor-pointer"
              >
                <div className="text-xs font-bold text-slate-200 group-hover:text-cyan-300">Alex Morgan</div>
                <div className="text-[10px] text-slate-400 font-mono">Senior CTI Analyst</div>
              </button>
              <button
                type="button"
                id="btn-demo-jordan-chen"
                onClick={() => handleQuickDemoLogin("jordan.chen@shieldzen.sec")}
                className="p-3 rounded-xl bg-[#070B14] hover:bg-cyan-950/40 border border-slate-800 hover:border-cyan-500/40 text-left transition-colors group cursor-pointer"
              >
                <div className="text-xs font-bold text-slate-200 group-hover:text-cyan-300">Jordan Chen</div>
                <div className="text-[10px] text-slate-400 font-mono">SOC Incident Lead</div>
              </button>
            </div>
          </div>
        </div>

        {/* Feature Badges */}
        <div className="mt-8 flex items-center justify-center gap-4 text-[11px] text-slate-500 font-mono flex-wrap">
          <span className="flex items-center gap-1.5"><Database className="w-3.5 h-3.5 text-cyan-400" /> NIST NVD</span>
          <span className="flex items-center gap-1.5"><Radio className="w-3.5 h-3.5 text-red-400" /> CISA KEV</span>
          <span className="flex items-center gap-1.5"><Shield className="w-3.5 h-3.5 text-indigo-400" /> MITRE ATT&CK</span>
          <span className="flex items-center gap-1.5"><Cpu className="w-3.5 h-3.5 text-purple-400" /> Gemini AI</span>
        </div>
      </main>

      {/* Footer */}
      <footer className="w-full max-w-7xl mx-auto px-6 py-6 text-center text-[10px] font-mono text-slate-600 relative z-10">
        ShieldZen Enterprise Cyber Intelligence • Academic Research Prototype
      </footer>
    </div>
  );
}

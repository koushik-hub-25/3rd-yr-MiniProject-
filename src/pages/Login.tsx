import React, { useState, useEffect } from "react";
import { useNavigate, useLocation, Link, useSearchParams } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import {
  ShieldCheck,
  Lock,
  User,
  ArrowRight,
  Database,
  Radio,
  Cpu,
  Shield,
  KeyRound,
  Mail,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  Inbox,
  Sparkles,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  UserPlus
} from "lucide-react";
import { cn } from "../components/ui";

type AuthMode = "login" | "register" | "verify" | "forgot" | "reset";

interface TestEmail {
  id: string;
  to: string;
  subject: string;
  previewUrl?: string;
  verificationToken?: string;
  resetToken?: string;
  timestamp: string;
  type: "verification" | "password_reset" | "notification";
}

export default function Login() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [mode, setMode] = useState<AuthMode>("login");

  // Form Fields
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [role, setRole] = useState("analyst");
  const [token, setToken] = useState("");

  // States & Feedback
  const [statusMsg, setStatusMsg] = useState<{ type: "success" | "error" | "info"; text: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);

  // Test Mailbox Drawer
  const [testEmails, setTestEmails] = useState<TestEmail[]>([]);
  const [showMailbox, setShowMailbox] = useState(false);

  const { login, register, verifyEmail, resendVerification, forgotPassword, resetPassword, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // Redirect if already logged in
  useEffect(() => {
    if (isAuthenticated) {
      const from = (location.state as any)?.from?.pathname || "/";
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, navigate, location]);

  // Sync mode from URL search params (e.g. ?mode=verify&email=...&token=...)
  useEffect(() => {
    const urlMode = searchParams.get("mode") as AuthMode;
    const urlEmail = searchParams.get("email");
    const urlToken = searchParams.get("token");

    if (urlEmail) setEmail(urlEmail);
    if (urlToken) setToken(urlToken);

    if (urlMode && ["login", "register", "verify", "forgot", "reset"].includes(urlMode)) {
      setMode(urlMode);
    }
  }, [searchParams]);

  // Fetch sandbox test emails for developer convenience
  const fetchTestEmails = async () => {
    try {
      const res = await fetch("/api/auth/test-emails");
      if (res.ok) {
        const data = await res.json();
        setTestEmails(data);
      }
    } catch (e) {
      // ignore
    }
  };

  useEffect(() => {
    fetchTestEmails();
    const interval = setInterval(fetchTestEmails, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleModeChange = (newMode: AuthMode) => {
    setMode(newMode);
    setStatusMsg(null);
    setSearchParams(newMode === "login" ? {} : { mode: newMode });
  };

  // 1. Submit Login
  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatusMsg(null);
    setLoading(true);

    const res = await login(email, password);
    setLoading(false);

    if (res.success) {
      const from = (location.state as any)?.from?.pathname || "/";
      navigate(from, { replace: true });
    } else {
      if (res.requiresVerification) {
        setStatusMsg({
          type: "error",
          text: res.error || "Email not verified. Please verify your account to proceed."
        });
        setMode("verify");
        setSearchParams({ mode: "verify", email });
      } else {
        setStatusMsg({
          type: "error",
          text: res.error || "Invalid credentials."
        });
      }
    }
  };

  // 2. Submit Register
  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatusMsg(null);

    if (password.length < 8) {
      setStatusMsg({ type: "error", text: "Password must be at least 8 characters long." });
      return;
    }

    setLoading(true);
    const res = await register(name, email, password, role);
    setLoading(false);

    if (res.success) {
      setStatusMsg({
        type: "success",
        text: res.message || "Registration successful! Verification token has been sent to your email."
      });
      fetchTestEmails();
      setMode("verify");
      setSearchParams({ mode: "verify", email });
    } else {
      setStatusMsg({
        type: "error",
        text: res.error || "Registration failed. Please check your information."
      });
    }
  };

  // 3. Submit Email Verification
  const handleVerifySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatusMsg(null);

    if (!token.trim()) {
      setStatusMsg({ type: "error", text: "Please enter your verification token." });
      return;
    }

    setLoading(true);
    const res = await verifyEmail(email, token);
    setLoading(false);

    if (res.success) {
      setStatusMsg({
        type: "success",
        text: "Email verified successfully! Logging you in..."
      });
      setTimeout(() => {
        navigate("/", { replace: true });
      }, 1000);
    } else {
      setStatusMsg({
        type: "error",
        text: res.error || "Invalid or expired verification token."
      });
    }
  };

  // Resend Verification Email
  const handleResend = async () => {
    if (!email) {
      setStatusMsg({ type: "error", text: "Please enter your email address to resend token." });
      return;
    }
    setResending(true);
    const res = await resendVerification(email);
    setResending(false);

    if (res.success) {
      setStatusMsg({ type: "info", text: res.message || "A fresh verification link has been sent." });
      fetchTestEmails();
    } else {
      setStatusMsg({ type: "error", text: res.error || "Failed to resend token." });
    }
  };

  // 4. Submit Forgot Password
  const handleForgotSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatusMsg(null);
    setLoading(true);

    const res = await forgotPassword(email);
    setLoading(false);

    if (res.success) {
      setStatusMsg({
        type: "info",
        text: res.message || "Password reset instructions have been sent to your email."
      });
      fetchTestEmails();
      setMode("reset");
      setSearchParams({ mode: "reset", email });
    } else {
      setStatusMsg({
        type: "error",
        text: res.error || "Failed to request password reset."
      });
    }
  };

  // 5. Submit Reset Password
  const handleResetSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatusMsg(null);

    if (!token.trim()) {
      setStatusMsg({ type: "error", text: "Security token is required." });
      return;
    }
    if (password.length < 8) {
      setStatusMsg({ type: "error", text: "Password must be at least 8 characters long." });
      return;
    }
    if (password !== confirmPassword) {
      setStatusMsg({ type: "error", text: "Passwords do not match." });
      return;
    }

    setLoading(true);
    const res = await resetPassword(email, token, password);
    setLoading(false);

    if (res.success) {
      setStatusMsg({
        type: "success",
        text: res.message || "Password reset complete! You can now log in."
      });
      setTimeout(() => {
        setMode("login");
        setSearchParams({});
      }, 1500);
    } else {
      setStatusMsg({
        type: "error",
        text: res.error || "Failed to reset password. Please check your token."
      });
    }
  };

  // Apply token from test mailbox directly
  const applyTestEmail = (item: TestEmail) => {
    setEmail(item.to);
    if (item.verificationToken) {
      setToken(item.verificationToken);
      setMode("verify");
      setSearchParams({ mode: "verify", email: item.to, token: item.verificationToken });
    } else if (item.resetToken) {
      setToken(item.resetToken);
      setMode("reset");
      setSearchParams({ mode: "reset", email: item.to, token: item.resetToken });
    }
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

        <div className="flex items-center gap-3">
          <span className="text-[10px] font-mono bg-cyan-950/70 border border-cyan-500/30 px-2.5 py-1 rounded-full text-cyan-300 font-bold hidden sm:inline-block">
            AUTHENTICATED ACCESS CONTROL
          </span>
          <button
            type="button"
            onClick={() => setShowMailbox(!showMailbox)}
            className="flex items-center gap-1.5 px-3 py-1 text-[11px] font-mono font-medium rounded-full bg-slate-900/90 border border-slate-700 text-slate-300 hover:text-cyan-300 hover:border-cyan-500/40 transition-colors cursor-pointer"
          >
            <Inbox className="w-3.5 h-3.5 text-cyan-400" />
            <span>Sandbox Mailbox ({testEmails.length})</span>
            {showMailbox ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
        </div>
      </header>

      {/* Sandbox Test Mailbox Drawer (If opened) */}
      {showMailbox && (
        <div className="w-full max-w-2xl mx-auto px-4 z-20 mb-4 animate-in fade-in slide-in-from-top-2 duration-200">
          <div className="bg-[#0D1527] border border-cyan-500/40 rounded-2xl p-4 shadow-2xl backdrop-blur-md">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Inbox className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                  Sandbox Dispatch Log (Local Email Outbox)
                </span>
              </div>
              <span className="text-[10px] font-mono text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded">
                Auto-refreshed
              </span>
            </div>

            <div className="mt-3 max-h-48 overflow-y-auto space-y-2 pr-1">
              {testEmails.length === 0 ? (
                <p className="text-xs text-slate-400 py-3 text-center font-mono">
                  No emails dispatched yet. Register an account or request a password reset to see outgoing links here.
                </p>
              ) : (
                testEmails.map((mail) => (
                  <div
                    key={mail.id}
                    className="p-2.5 rounded-xl bg-[#080D1A] border border-slate-800 hover:border-cyan-500/40 flex items-center justify-between gap-3 text-xs transition-colors"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className={cn(
                          "text-[9px] font-mono font-bold px-1.5 py-0.5 rounded uppercase",
                          mail.type === "verification" ? "bg-cyan-950 text-cyan-300 border border-cyan-800" : "bg-red-950 text-red-300 border border-red-800"
                        )}>
                          {mail.type}
                        </span>
                        <span className="font-semibold text-slate-200 truncate">{mail.to}</span>
                      </div>
                      <p className="text-[11px] text-slate-400 truncate mt-0.5">{mail.subject}</p>
                    </div>

                    <button
                      type="button"
                      onClick={() => applyTestEmail(mail)}
                      className="px-2.5 py-1 text-[11px] font-mono font-semibold bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 rounded-lg flex items-center gap-1 transition-colors cursor-pointer shrink-0"
                    >
                      <span>Fill Token</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* Main Center Content */}
      <main className="w-full max-w-md mx-auto px-4 py-4 relative z-10 flex flex-col items-center">
        {/* Header Text */}
        <div className="text-center mb-6 space-y-2">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-[10px] font-mono font-bold text-cyan-300 uppercase">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            SHIELDZEN SECURITY ACCESS
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            {mode === "login" && "Sign In to Analyst Console"}
            {mode === "register" && "Create Analyst Account"}
            {mode === "verify" && "Verify Email Address"}
            {mode === "forgot" && "Reset Credential Access"}
            {mode === "reset" && "Set New Password"}
          </h1>
          <p className="text-xs text-slate-400 max-w-sm mx-auto leading-relaxed">
            {mode === "login" && "Enter your verified corporate credentials to access intelligence telemetry."}
            {mode === "register" && "Register your profile to participate in cyber threat investigation."}
            {mode === "verify" && "Enter the verification token sent to your email to activate clearance."}
            {mode === "forgot" && "Provide your registered email address to receive reset instructions."}
            {mode === "reset" && "Enter your security token and configure a new strong password."}
          </p>
        </div>

        {/* Authentication Card */}
        <div className="w-full bg-[#090F1C] border border-slate-800/90 rounded-3xl p-6 sm:p-7 shadow-2xl space-y-5">
          {/* Status Message Banner */}
          {statusMsg && (
            <div
              className={cn(
                "p-3 rounded-xl border text-xs flex items-start gap-2.5",
                statusMsg.type === "success" && "bg-emerald-950/60 border-emerald-500/40 text-emerald-300",
                statusMsg.type === "error" && "bg-red-950/60 border-red-500/40 text-red-300",
                statusMsg.type === "info" && "bg-cyan-950/60 border-cyan-500/40 text-cyan-300"
              )}
            >
              {statusMsg.type === "success" && <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-emerald-400" />}
              {statusMsg.type === "error" && <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />}
              {statusMsg.type === "info" && <Sparkles className="w-4 h-4 shrink-0 mt-0.5 text-cyan-400" />}
              <span className="leading-relaxed">{statusMsg.text}</span>
            </div>
          )}

          {/* Mode 1: LOGIN */}
          {mode === "login" && (
            <form onSubmit={handleLoginSubmit} className="space-y-4">
              <div>
                <label className="block text-[11px] font-mono font-bold uppercase text-slate-400 mb-1.5">
                  Analyst Identity (Email)
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
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
                    Security Password
                  </label>
                  <button
                    type="button"
                    onClick={() => handleModeChange("forgot")}
                    className="text-[11px] font-mono text-cyan-400 hover:underline cursor-pointer"
                  >
                    Forgot Password?
                  </button>
                </div>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    id="login-password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    placeholder="••••••••••••"
                    className="w-full bg-[#070B14] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/80 transition-colors font-mono"
                  />
                </div>
              </div>

              <button
                id="btn-submit-login"
                type="submit"
                disabled={loading}
                className="w-full mt-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold py-3 rounded-xl text-xs uppercase tracking-wider flex items-center justify-center gap-2 shadow-lg shadow-cyan-950/60 transition-all cursor-pointer disabled:opacity-50"
              >
                {loading ? "Verifying Credentials..." : "Authenticate & Open Console"}
                <ArrowRight className="w-4 h-4" />
              </button>

              <div className="pt-3 text-center border-t border-slate-800/80">
                <span className="text-xs text-slate-400">Need analyst clearance? </span>
                <button
                  type="button"
                  onClick={() => handleModeChange("register")}
                  className="text-xs text-cyan-400 font-semibold hover:underline cursor-pointer"
                >
                  Create Account
                </button>
              </div>
            </form>
          )}

          {/* Mode 2: REGISTER */}
          {mode === "register" && (
            <form onSubmit={handleRegisterSubmit} className="space-y-3.5">
              <div>
                <label className="block text-[11px] font-mono font-bold uppercase text-slate-400 mb-1.5">
                  Full Name
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    id="reg-name"
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    required
                    placeholder="e.g. Jordan Chen"
                    className="w-full bg-[#070B14] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/80 transition-colors font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-mono font-bold uppercase text-slate-400 mb-1.5">
                  Corporate Email
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    id="reg-email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    placeholder="jordan.chen@shieldzen.sec"
                    className="w-full bg-[#070B14] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/80 transition-colors font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-mono font-bold uppercase text-slate-400 mb-1.5">
                  Initial Assigned Clearance
                </label>
                <div className="w-full bg-[#070B14]/70 border border-slate-700/80 rounded-xl px-3.5 py-2.5 text-xs text-slate-300 font-mono flex items-center justify-between">
                  <span>Cyber Threat Intelligence Analyst (Tier-1)</span>
                  <span className="text-[10px] bg-cyan-950 text-cyan-400 px-2 py-0.5 rounded border border-cyan-800/60">Standard</span>
                </div>
                <p className="text-[10px] text-slate-500 mt-1 font-mono">
                  Administrative and Tier-2 clearance upgrades must be provisioned by a SOC Administrator.
                </p>
              </div>

              <div>
                <label className="block text-[11px] font-mono font-bold uppercase text-slate-400 mb-1.5">
                  Password (min 8 characters)
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    id="reg-password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    minLength={8}
                    placeholder="••••••••••••"
                    className="w-full bg-[#070B14] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/80 transition-colors font-mono"
                  />
                </div>
              </div>

              <button
                id="btn-submit-register"
                type="submit"
                disabled={loading}
                className="w-full mt-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold py-3 rounded-xl text-xs uppercase tracking-wider flex items-center justify-center gap-2 shadow-lg shadow-cyan-950/60 transition-all cursor-pointer disabled:opacity-50"
              >
                {loading ? "Registering Account..." : "Register & Dispatch Verification"}
                <UserPlus className="w-4 h-4" />
              </button>

              <div className="pt-3 text-center border-t border-slate-800/80">
                <span className="text-xs text-slate-400">Already registered? </span>
                <button
                  type="button"
                  onClick={() => handleModeChange("login")}
                  className="text-xs text-cyan-400 font-semibold hover:underline cursor-pointer"
                >
                  Sign In Instead
                </button>
              </div>
            </form>
          )}

          {/* Mode 3: EMAIL VERIFICATION */}
          {mode === "verify" && (
            <form onSubmit={handleVerifySubmit} className="space-y-4">
              <div>
                <label className="block text-[11px] font-mono font-bold uppercase text-slate-400 mb-1.5">
                  Account Email
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    id="verify-email"
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
                    64-Character Verification Token
                  </label>
                  <button
                    type="button"
                    disabled={resending}
                    onClick={handleResend}
                    className="text-[11px] font-mono text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer disabled:opacity-50"
                  >
                    <RefreshCw className={cn("w-3 h-3", resending && "animate-spin")} />
                    <span>Resend Token</span>
                  </button>
                </div>
                <div className="relative">
                  <KeyRound className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    id="verify-token"
                    type="text"
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    required
                    placeholder="Paste security token from email..."
                    className="w-full bg-[#070B14] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-xs text-cyan-300 placeholder-slate-500 focus:outline-none focus:border-cyan-500/80 transition-colors font-mono"
                  />
                </div>
              </div>

              <button
                id="btn-submit-verify"
                type="submit"
                disabled={loading}
                className="w-full mt-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold py-3 rounded-xl text-xs uppercase tracking-wider flex items-center justify-center gap-2 shadow-lg shadow-emerald-950/60 transition-all cursor-pointer disabled:opacity-50"
              >
                {loading ? "Validating Token..." : "Verify & Activate Account"}
                <CheckCircle2 className="w-4 h-4" />
              </button>

              <div className="pt-3 text-center border-t border-slate-800/80">
                <button
                  type="button"
                  onClick={() => handleModeChange("login")}
                  className="text-xs text-slate-400 hover:text-cyan-400 cursor-pointer"
                >
                  Back to Sign In
                </button>
              </div>
            </form>
          )}

          {/* Mode 4: FORGOT PASSWORD */}
          {mode === "forgot" && (
            <form onSubmit={handleForgotSubmit} className="space-y-4">
              <div>
                <label className="block text-[11px] font-mono font-bold uppercase text-slate-400 mb-1.5">
                  Registered Email Address
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    id="forgot-email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    placeholder="analyst@shieldzen.sec"
                    className="w-full bg-[#070B14] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/80 transition-colors font-mono"
                  />
                </div>
              </div>

              <button
                id="btn-submit-forgot"
                type="submit"
                disabled={loading}
                className="w-full mt-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold py-3 rounded-xl text-xs uppercase tracking-wider flex items-center justify-center gap-2 shadow-lg shadow-cyan-950/60 transition-all cursor-pointer disabled:opacity-50"
              >
                {loading ? "Sending Reset Email..." : "Send Password Reset Link"}
                <ArrowRight className="w-4 h-4" />
              </button>

              <div className="pt-3 text-center border-t border-slate-800/80">
                <button
                  type="button"
                  onClick={() => handleModeChange("login")}
                  className="text-xs text-slate-400 hover:text-cyan-400 cursor-pointer"
                >
                  Cancel and Return to Sign In
                </button>
              </div>
            </form>
          )}

          {/* Mode 5: RESET PASSWORD */}
          {mode === "reset" && (
            <form onSubmit={handleResetSubmit} className="space-y-3.5">
              <div>
                <label className="block text-[11px] font-mono font-bold uppercase text-slate-400 mb-1.5">
                  Account Email
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    id="reset-email"
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
                <label className="block text-[11px] font-mono font-bold uppercase text-slate-400 mb-1.5">
                  Password Reset Token
                </label>
                <div className="relative">
                  <KeyRound className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    id="reset-token"
                    type="text"
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    required
                    placeholder="Paste reset token from email..."
                    className="w-full bg-[#070B14] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-xs text-cyan-300 placeholder-slate-500 focus:outline-none focus:border-cyan-500/80 transition-colors font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-mono font-bold uppercase text-slate-400 mb-1.5">
                  New Password (min 8 characters)
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    id="reset-password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    minLength={8}
                    placeholder="••••••••••••"
                    className="w-full bg-[#070B14] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/80 transition-colors font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-mono font-bold uppercase text-slate-400 mb-1.5">
                  Confirm New Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    id="reset-password-confirm"
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    required
                    minLength={8}
                    placeholder="••••••••••••"
                    className="w-full bg-[#070B14] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/80 transition-colors font-mono"
                  />
                </div>
              </div>

              <button
                id="btn-submit-reset"
                type="submit"
                disabled={loading}
                className="w-full mt-2 bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white font-bold py-3 rounded-xl text-xs uppercase tracking-wider flex items-center justify-center gap-2 shadow-lg shadow-red-950/60 transition-all cursor-pointer disabled:opacity-50"
              >
                {loading ? "Updating Security Password..." : "Update Password"}
                <CheckCircle2 className="w-4 h-4" />
              </button>

              <div className="pt-3 text-center border-t border-slate-800/80">
                <button
                  type="button"
                  onClick={() => handleModeChange("login")}
                  className="text-xs text-slate-400 hover:text-cyan-400 cursor-pointer"
                >
                  Back to Sign In
                </button>
              </div>
            </form>
          )}
        </div>

        {/* Security Feature Badges */}
        <div className="mt-8 flex items-center justify-center gap-4 text-[11px] text-slate-500 font-mono flex-wrap">
          <span className="flex items-center gap-1.5"><Database className="w-3.5 h-3.5 text-cyan-400" /> NIST NVD</span>
          <span className="flex items-center gap-1.5"><Radio className="w-3.5 h-3.5 text-red-400" /> CISA KEV</span>
          <span className="flex items-center gap-1.5"><Shield className="w-3.5 h-3.5 text-indigo-400" /> MITRE ATT&CK</span>
          <span className="flex items-center gap-1.5"><Cpu className="w-3.5 h-3.5 text-purple-400" /> Gemini AI</span>
        </div>
      </main>

      {/* Footer */}
      <footer className="w-full max-w-7xl mx-auto px-6 py-6 text-center text-[10px] font-mono text-slate-600 relative z-10">
        ShieldZen Enterprise Cyber Threat Intelligence &bull; Production Authentication &bull; Sandboxed SOC Environment
      </footer>
    </div>
  );
}

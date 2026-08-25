import { BrowserRouter as Router, Routes, Route, Link, useLocation, useNavigate, Navigate } from "react-router-dom";
import {
  LayoutDashboard,
  UploadCloud,
  FileText,
  ShieldAlert,
  Activity,
  Map as MapIcon,
  TrendingUp,
  BarChart3,
  Database,
  Settings as SettingsIcon,
  Search,
  Cpu,
  ShieldCheck,
  Bell,
  UserCheck,
  Bot,
  Layers,
  LogOut,
  ChevronDown,
  Sparkles,
  ExternalLink,
  Menu,
  X,
  Radio,
  ArrowRight,
  Shield,
  Server,
  Skull,
  Flame
} from "lucide-react";
import React, { useState, useEffect } from "react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { ShieldZenLogo, cn } from "./components/ui";
import { NotificationCenter } from "./components/NotificationCenter";
import { AIAnalystDrawer } from "./components/AIAnalystDrawer";

// Pages
import Dashboard from "./pages/Dashboard";
import ThreatIntelligence from "./pages/ThreatIntelligence";
import Upload from "./pages/Upload";
import Reports from "./pages/Reports";
import Threats from "./pages/Threats";
import ThreatDetails from "./pages/ThreatDetails";
import Incidents from "./pages/Incidents";
import AssetManagement from "./pages/AssetManagement";
import ThreatMap from "./pages/ThreatMap";
import EmergingThreats from "./pages/EmergingThreats";
import Analytics from "./pages/Analytics";
import IOCVault from "./pages/IOCVault";
import Settings from "./pages/Settings";
import Login from "./pages/Login";
import RiskScoringEngine from "./pages/RiskScoringEngine";
import ThreatActors from "./pages/ThreatActors";
import ThreatActorDetails from "./pages/ThreatActorDetails";
import Campaigns from "./pages/Campaigns";
import CampaignDetails from "./pages/CampaignDetails";
import DatabaseExplorer from "./pages/DatabaseExplorer";

function TopNavigation({ onOpenAiAssistant }: { onOpenAiAssistant: () => void }) {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const [globalSearch, setGlobalSearch] = useState("");
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [moreMenuOpen, setMoreMenuOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  // Track scroll position for translucent sticky effect
  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > 20) {
        setScrolled(true);
      } else {
        setScrolled(false);
      }
    };
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (globalSearch.trim()) {
      navigate(`/threat-intelligence?q=${encodeURIComponent(globalSearch)}`);
      setGlobalSearch("");
    }
  };

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const mainNavItems = [
    { name: "Dashboard", path: "/" },
    { name: "Intelligence", path: "/threat-intelligence" },
    { name: "Risk Engine", path: "/risk-engine" },
    { name: "Assets", path: "/assets" },
    { name: "Threats", path: "/threats" },
    { name: "Reports", path: "/reports" },
    { name: "Incidents", path: "/incidents" },
    { name: "Analytics", path: "/analytics" },
  ];

  const moreNavItems = [
    { name: "Database Explorer", path: "/database-explorer", icon: Database, desc: "SQLite database & table schemas" },
    { name: "Threat Actors", path: "/threat-actors", icon: Skull, desc: "Adversary intelligence dossiers" },
    { name: "Threat Campaigns", path: "/campaigns", icon: Flame, desc: "Multi-stage cyber operations" },
    { name: "Risk Scoring Engine", path: "/risk-engine", icon: Activity, desc: "Deterministic 0-100 scoring" },
    { name: "Asset Inventory", path: "/assets", icon: Server, desc: "Endpoints & network exposure" },
    { name: "Threat Map", path: "/map", icon: MapIcon, desc: "Geographic risk heatmap" },
    { name: "Emerging Threats", path: "/emerging", icon: TrendingUp, desc: "AI trend forecast" },
    { name: "Upload Report", path: "/upload", icon: UploadCloud, desc: "Extract IOCs & synthesize" },
    { name: "IOC Vault", path: "/iocs", icon: Database, desc: "Indicators database" },
  ];

  const isMoreActive = moreNavItems.some(
    (item) => location.pathname === item.path || location.pathname.startsWith(item.path)
  );

  return (
    <>
      <header
        className={cn(
          "sticky top-0 z-40 w-full transition-all duration-200 border-b",
          scrolled
            ? "bg-[#070B14]/85 backdrop-blur-md border-slate-800/90 shadow-lg shadow-black/40 py-2.5"
            : "bg-[#070B14]/95 backdrop-blur-sm border-slate-800/60 py-3"
        )}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between gap-4">
          {/* Left: ShieldZen Logo & Title */}
          <div className="flex items-center gap-6 shrink-0">
            <Link to="/" className="flex items-center gap-3 group">
              <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-600 p-[1px] shadow-md shadow-cyan-950/50 group-hover:shadow-cyan-500/20 transition-all">
                <div className="w-full h-full bg-[#080D1A] rounded-[11px] flex items-center justify-center">
                  <ShieldCheck className="w-4 h-4 text-cyan-400 group-hover:scale-110 transition-transform" />
                </div>
              </div>
              <div className="flex flex-col">
                <span className="text-sm font-extrabold tracking-tight text-white group-hover:text-cyan-300 transition-colors">
                  Shield<span className="text-cyan-400">Zen</span>
                </span>
                <span className="text-[9px] font-mono text-slate-400 tracking-wider uppercase hidden sm:inline-block leading-tight">
                  AI Cyber Threat Intelligence
                </span>
              </div>
            </Link>
          </div>

          {/* Center: Main Navigation */}
          <nav className="hidden lg:flex items-center gap-1">
            {mainNavItems.map((item) => {
              const isActive =
                item.path === "/"
                  ? location.pathname === "/"
                  : location.pathname.startsWith(item.path);

              return (
                <Link
                  key={item.name}
                  id={`top-nav-${item.name.toLowerCase()}`}
                  to={item.path}
                  className={cn(
                    "px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all duration-150 relative",
                    isActive
                      ? "text-white bg-slate-800/80 shadow-inner"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                  )}
                >
                  {item.name}
                  {isActive && (
                    <span className="absolute bottom-0 left-1/2 -translate-x-1/2 w-4 h-0.5 bg-cyan-400 rounded-full" />
                  )}
                </Link>
              );
            })}

            {/* More dropdown */}
            <div className="relative">
              <button
                id="top-nav-more"
                onClick={() => setMoreMenuOpen(!moreMenuOpen)}
                className={cn(
                  "px-3 py-1.5 rounded-lg text-xs font-semibold transition-all duration-150 flex items-center gap-1",
                  isMoreActive
                    ? "text-cyan-300 bg-slate-800/80"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                )}
              >
                <span>More</span>
                <ChevronDown className={cn("w-3 h-3 transition-transform", moreMenuOpen && "rotate-180")} />
              </button>

              {moreMenuOpen && (
                <>
                  <div className="fixed inset-0 z-40" onClick={() => setMoreMenuOpen(false)} />
                  <div className="absolute left-0 mt-2 w-56 bg-[#090F1C] border border-slate-700/80 rounded-xl shadow-2xl z-50 overflow-hidden py-1 animate-in fade-in zoom-in-95 duration-150">
                    {moreNavItems.map((sub) => (
                      <Link
                        key={sub.name}
                        to={sub.path}
                        onClick={() => setMoreMenuOpen(false)}
                        className="px-3.5 py-2 hover:bg-slate-800/60 flex items-start gap-2.5 text-left transition-colors group"
                      >
                        <sub.icon className="w-4 h-4 text-cyan-400 mt-0.5 group-hover:text-cyan-300" />
                        <div>
                          <div className="text-xs font-bold text-slate-200 group-hover:text-white">{sub.name}</div>
                          <div className="text-[10px] text-slate-400">{sub.desc}</div>
                        </div>
                      </Link>
                    ))}
                  </div>
                </>
              )}
            </div>
          </nav>

          {/* Right: Quick Search, AI Analyst, Notifications, User Profile */}
          <div className="flex items-center gap-2 sm:gap-3 shrink-0">
            {/* Search Input */}
            <form onSubmit={handleSearch} className="relative hidden md:block">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                id="global-search-input"
                type="text"
                placeholder="Search CVEs, threats, IOCs..."
                value={globalSearch}
                onChange={(e) => setGlobalSearch(e.target.value)}
                className="bg-[#080D1A] border border-slate-700/80 text-slate-200 placeholder-slate-500 text-xs pl-8 pr-3 py-1.5 rounded-xl w-40 lg:w-56 focus:outline-none focus:border-cyan-500/80 focus:ring-1 focus:ring-cyan-500/30 transition-all font-sans"
              />
            </form>

            {/* AI Analyst Button */}
            <button
              id="top-nav-ai-analyst-btn"
              onClick={onOpenAiAssistant}
              className="px-3 py-1.5 bg-gradient-to-r from-indigo-950/80 to-blue-950/80 hover:from-indigo-900 hover:to-blue-900 border border-indigo-500/40 text-indigo-200 hover:text-white rounded-xl text-xs font-bold flex items-center gap-1.5 shadow-sm shadow-indigo-950/50 transition-all cursor-pointer"
              title="Open ShieldZen AI Analyst Copilot"
            >
              <Bot className="w-3.5 h-3.5 text-indigo-400 animate-pulse" />
              <span className="hidden sm:inline">AI Analyst</span>
            </button>

            {/* Notifications Dropdown */}
            <NotificationCenter />

            {/* User Profile */}
            <div className="relative">
              <button
                id="btn-user-profile-menu"
                onClick={() => setUserMenuOpen(!userMenuOpen)}
                className="flex items-center gap-2 bg-[#080D1A] border border-slate-800 hover:border-slate-700 px-2 py-1 rounded-xl transition-colors"
              >
                <div className="w-6 h-6 rounded-lg bg-gradient-to-br from-cyan-600 to-blue-700 flex items-center justify-center text-[10px] font-extrabold text-white">
                  {user?.avatarInitials || "AM"}
                </div>
                <ChevronDown className="w-3 h-3 text-slate-500 hidden sm:inline" />
              </button>

              {userMenuOpen && (
                <>
                  <div className="fixed inset-0 z-40" onClick={() => setUserMenuOpen(false)} />
                  <div className="absolute right-0 mt-2 w-60 bg-[#090F1C] border border-slate-700/80 rounded-xl shadow-2xl z-50 overflow-hidden py-1 animate-in fade-in zoom-in-95 duration-150">
                    <div className="px-4 py-2.5 border-b border-slate-800">
                      <p className="text-xs font-bold text-white">{user?.name || "Alex Morgan"}</p>
                      <p className="text-[10px] text-slate-400 font-mono truncate">{user?.email || "alex.morgan@shieldzen.sec"}</p>
                      <div className="mt-1 flex items-center gap-1.5">
                        <span className="text-[9px] font-mono bg-cyan-950 text-cyan-300 px-1.5 py-0.2 rounded border border-cyan-500/30">
                          {user?.clearance || "SOC Tier-2"}
                        </span>
                        <span className="text-[9px] font-mono text-emerald-400">● Live</span>
                      </div>
                    </div>

                    <Link
                      to="/settings"
                      onClick={() => setUserMenuOpen(false)}
                      className="w-full text-left px-4 py-2 text-xs text-slate-300 hover:text-white hover:bg-slate-800/60 flex items-center gap-2"
                    >
                      <SettingsIcon className="w-3.5 h-3.5 text-slate-400" /> System Settings
                    </Link>

                    <Link
                      to="/database-explorer"
                      onClick={() => setUserMenuOpen(false)}
                      className="w-full text-left px-4 py-2 text-xs text-cyan-300 hover:text-cyan-200 hover:bg-slate-800/60 flex items-center gap-2"
                    >
                      <Database className="w-3.5 h-3.5 text-cyan-400" /> Database Explorer
                    </Link>

                    <button
                      onClick={() => {
                        setUserMenuOpen(false);
                        setHelpOpen(true);
                      }}
                      className="w-full text-left px-4 py-2 text-xs text-slate-300 hover:text-white hover:bg-slate-800/60 flex items-center gap-2"
                    >
                      <FileText className="w-3.5 h-3.5 text-slate-400" /> Help & Architecture Guide
                    </button>

                    <button
                      onClick={() => {
                        setUserMenuOpen(false);
                        handleLogout();
                      }}
                      className="w-full text-left px-4 py-2 text-xs text-red-400 hover:text-red-300 hover:bg-red-950/30 flex items-center gap-2 border-t border-slate-800/80"
                    >
                      <LogOut className="w-3.5 h-3.5" /> Sign Out
                    </button>
                  </div>
                </>
              )}
            </div>

            {/* Mobile Hamburger Menu Toggle */}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="lg:hidden p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
              title="Toggle Menu"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Dropdown Navigation */}
        {mobileMenuOpen && (
          <div className="lg:hidden border-t border-slate-800/80 bg-[#080D1A] px-4 py-4 space-y-3 animate-in slide-in-from-top-2 duration-150">
            {/* Mobile Search */}
            <form onSubmit={handleSearch} className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search CVEs, threats, IOCs..."
                value={globalSearch}
                onChange={(e) => setGlobalSearch(e.target.value)}
                className="w-full bg-[#070B14] border border-slate-700 text-slate-200 placeholder-slate-500 text-xs pl-9 pr-3 py-2 rounded-xl"
              />
            </form>

            <div className="grid grid-cols-2 gap-1.5 pt-2">
              {mainNavItems.map((item) => (
                <Link
                  key={item.name}
                  to={item.path}
                  onClick={() => setMobileMenuOpen(false)}
                  className={cn(
                    "px-3 py-2 rounded-lg text-xs font-semibold transition-colors",
                    location.pathname === item.path
                      ? "bg-cyan-950 text-cyan-300 font-bold border border-cyan-500/30"
                      : "text-slate-300 hover:bg-slate-800"
                  )}
                >
                  {item.name}
                </Link>
              ))}
              {moreNavItems.map((item) => (
                <Link
                  key={item.name}
                  to={item.path}
                  onClick={() => setMobileMenuOpen(false)}
                  className={cn(
                    "px-3 py-2 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5",
                    location.pathname === item.path
                      ? "bg-cyan-950 text-cyan-300 font-bold border border-cyan-500/30"
                      : "text-slate-300 hover:bg-slate-800"
                  )}
                >
                  <item.icon className="w-3.5 h-3.5 text-cyan-400" />
                  <span>{item.name}</span>
                </Link>
              ))}
            </div>

            <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs">
              <button
                onClick={() => {
                  setMobileMenuOpen(false);
                  onOpenAiAssistant();
                }}
                className="text-indigo-400 font-bold flex items-center gap-1.5"
              >
                <Bot className="w-4 h-4" /> AI Analyst Copilot
              </button>
              <button
                onClick={() => {
                  setMobileMenuOpen(false);
                  handleLogout();
                }}
                className="text-red-400 font-bold flex items-center gap-1"
              >
                <LogOut className="w-3.5 h-3.5" /> Sign Out
              </button>
            </div>
          </div>
        )}
      </header>

      {/* Help Modal */}
      {helpOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="w-full max-w-xl bg-[#090F1C] border border-slate-700 rounded-2xl shadow-2xl overflow-hidden p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  ShieldZen Architecture & Threat Model Guide
                </h3>
              </div>
              <button onClick={() => setHelpOpen(false)} className="text-slate-400 hover:text-white p-1">✕</button>
            </div>
            <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
              <p>
                <strong className="text-white">ShieldZen</strong> is an AI-powered Cyber Threat Intelligence & Risk Prioritization platform designed to transform raw security telemetry and threat reports into actionable SOC workflows.
              </p>
              <div className="space-y-2 pt-2 border-t border-slate-800/80">
                <div className="flex items-start gap-2">
                  <span className="font-mono text-cyan-400 font-bold">● Multi-Source Correlation:</span>
                  <span>Harmonizes NIST NVD (vulnerabilities), CISA KEV (actively exploited zero-days), MITRE ATT&CK matrix tactics, and unstructured threat reports.</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="font-mono text-indigo-400 font-bold">● AI Analyst Copilot:</span>
                  <span>Leverages Google Gemini models to generate executive briefs, explain threat vectors, extract IOCs, and suggest remediation steps.</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="font-mono text-emerald-400 font-bold">● Transparent Attribution:</span>
                  <span>Clearly differentiates verified public government feeds from AI syntheses and synthetic simulation records.</span>
                </div>
              </div>
            </div>
            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setHelpOpen(false)}
                className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-bold transition-colors"
              >
                Close Guide
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function MainLayout() {
  const [aiAssistantOpen, setAiAssistantOpen] = useState(false);

  return (
    <div className="min-h-screen w-full bg-[#070B14] text-[#E0E6ED] font-sans selection:bg-cyan-500/20 selection:text-cyan-200 flex flex-col">
      {/* Top Global Navigation Bar */}
      <TopNavigation onOpenAiAssistant={() => setAiAssistantOpen(true)} />

      {/* Main Page Content - Naturally Scrolls with Document */}
      <main className="flex-1 w-full">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
          <Route path="/risk-engine" element={<RiskScoringEngine />} />
          <Route path="/assets" element={<AssetManagement />} />
          <Route path="/threat-actors" element={<ThreatActors />} />
          <Route path="/threat-actors/:id" element={<ThreatActorDetails />} />
          <Route path="/campaigns" element={<Campaigns />} />
          <Route path="/campaigns/:id" element={<CampaignDetails />} />
          <Route path="/upload" element={<Upload />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/threats" element={<Threats />} />
          <Route path="/threats/:id" element={<ThreatDetails />} />
          <Route path="/iocs" element={<IOCVault />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/map" element={<ThreatMap />} />
          <Route path="/emerging" element={<EmergingThreats />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/database-explorer" element={<DatabaseExplorer />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>

      {/* Global AI Analyst Copilot Drawer */}
      <AIAnalystDrawer
        isOpen={aiAssistantOpen}
        onClose={() => setAiAssistantOpen(false)}
      />
    </div>
  );
}

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="min-h-screen bg-[#070B14] flex flex-col items-center justify-center text-cyan-400 gap-3 font-mono text-xs">
        <div className="w-8 h-8 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin" />
        <span>Validating Security Clearance...</span>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}

function AdminRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading, user } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="min-h-screen bg-[#070B14] flex flex-col items-center justify-center text-cyan-400 gap-3 font-mono text-xs">
        <div className="w-8 h-8 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin" />
        <span>Validating Security Clearance...</span>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (user?.role !== "admin") {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}

export default function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/*"
            element={
              <ProtectedRoute>
                <MainLayout />
              </ProtectedRoute>
            }
          />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

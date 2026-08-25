import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { Database, Search, RefreshCw, AlertTriangle, ShieldCheck, Server, Table, Activity, LogIn, KeyRound } from "lucide-react";
import { cn } from "../components/ui";
import { useAuth } from "../context/AuthContext";

type TableMeta = {
  name: string;
  count: number;
};

type TableData = {
  table: string;
  rows: any[];
  page: number;
  limit: number;
};

export default function DatabaseExplorer() {
  const { user, getAuthHeaders, token } = useAuth();
  const [tables, setTables] = useState<TableMeta[]>([]);
  const [selectedTable, setSelectedTable] = useState<string>("cachedVulnerabilities");
  const [tableData, setTableData] = useState<TableData | null>(null);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");

  const [apiDiagnostics, setApiDiagnostics] = useState<any>({ tablesStatus: "pending", tableDataStatus: "pending" });
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchTables = async () => {
    try {
      setApiDiagnostics((prev: any) => ({ ...prev, tablesStatus: "requesting" }));
      
      const headers = getAuthHeaders();
      let res = await fetch(`/api/database/tables?t=${Date.now()}`, { headers });
      if (!res.ok) {
        res = await fetch(`/api/admin/database/tables?t=${Date.now()}`, { headers });
      }

      setApiDiagnostics((prev: any) => ({ ...prev, tablesUrl: res.url, tablesStatus: res.status }));
      if (res.ok) {
        const json = await res.json();
        const tablesArray = Array.isArray(json)
          ? json
          : Array.isArray(json.rows)
            ? json.rows
            : Array.isArray(json.data)
              ? json.data
              : Array.isArray(json.records)
                ? json.records
                : [];
        setTables(tablesArray);
        setErrorMsg(null);
      } else {
        const text = await res.text();
        setErrorMsg(`Tables API returned HTTP ${res.status}: ${text.substring(0, 200)}`);
      }
    } catch (err: any) {
      console.error("Failed to fetch tables", err);
      setErrorMsg(`Tables fetch error: ${err.message}`);
    }
  };

  const fetchTableData = async (tableName: string) => {
    setLoading(true);
    try {
      setApiDiagnostics((prev: any) => ({ ...prev, tableDataStatus: "requesting" }));
      const headers = getAuthHeaders();
      let res = await fetch(`/api/database/table/${tableName}?t=${Date.now()}`, { headers });
      if (!res.ok) {
        res = await fetch(`/api/admin/database/table/${tableName}?t=${Date.now()}`, { headers });
      }
      setApiDiagnostics((prev: any) => ({ ...prev, tableDataUrl: res.url, tableDataStatus: res.status }));
      
      if (res.ok) {
        const json = await res.json();
        
        const normalizedRows = Array.isArray(json)
          ? json
          : Array.isArray(json.rows)
            ? json.rows
            : Array.isArray(json.data)
              ? json.data
              : Array.isArray(json.records)
                ? json.records
                : [];

        setTableData({
          table: tableName,
          rows: normalizedRows,
          page: json.page || 1,
          limit: json.limit || 50
        });
        setErrorMsg(null);
      } else {
         const text = await res.text();
         setErrorMsg(`Table Data API returned HTTP ${res.status}: ${text.substring(0, 200)}`);
      }
    } catch (err: any) {
      console.error("Failed to fetch table data", err);
      setErrorMsg(`Table Data fetch error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTables();
    fetchTableData(selectedTable);
  }, []);

  const handleRefresh = () => {
    fetchTables();
    fetchTableData(selectedTable);
  };

  const handleTableSelect = (name: string) => {
    setSelectedTable(name);
    fetchTableData(name);
    setSearch("");
  };

  const renderBadge = (tableName: string, row: any) => {
    if (tableName === "cachedVulnerabilities") {
      const badges = [];
      if (row.sourceStatus === "LIVE") badges.push(<span key="live" className="px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">LIVE</span>);
      if (row.sourceStatus === "CACHED") badges.push(<span key="cached" className="px-2 py-0.5 rounded-full text-xs font-semibold bg-blue-500/20 text-blue-400 border border-blue-500/30">CACHED</span>);
      if (row.isCisaKev) badges.push(<span key="cisa" className="px-2 py-0.5 rounded-full text-xs font-semibold bg-red-500/20 text-red-400 border border-red-500/30">CISA KEV</span>);
      if (row.source === "NVD") badges.push(<span key="nvd" className="px-2 py-0.5 rounded-full text-xs font-semibold bg-purple-500/20 text-purple-400 border border-purple-500/30">NVD</span>);
      if (row.source === "HYBRID") badges.push(<span key="hybrid" className="px-2 py-0.5 rounded-full text-xs font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30">HYBRID</span>);
      return <div className="flex gap-1">{badges}</div>;
    }
    if (tableName === "threatActors" && row.isSynthetic) {
      return <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">SYNTHETIC</span>;
    }
    if (tableName === "intelligenceSources") {
      if (row.isLive) return <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">LIVE</span>;
      if (row.isSynthetic) return <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">SYNTHETIC</span>;
      return <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-blue-500/20 text-blue-400 border border-blue-500/30">CACHED</span>;
    }
    return null;
  };

  const filteredRows = tableData?.rows.filter((row) => {
    if (!search) return true;
    return Object.values(row).some(
      (val) => val && String(val).toLowerCase().includes(search.toLowerCase())
    );
  }) || [];

  const columns = tableData?.rows.length > 0 ? Object.keys(tableData.rows[0]) : [];

  // Summary logic for cachedVulnerabilities
  let cisaKevCount = 0;
  let liveCount = 0;
  let cachedCount = 0;
  
  if (selectedTable === "cachedVulnerabilities" && tableData?.rows) {
    tableData.rows.forEach(r => {
      if (r.isCisaKev) cisaKevCount++;
      if (r.sourceStatus === "LIVE") liveCount++;
      if (r.sourceStatus === "CACHED") cachedCount++;
    });
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight flex items-center gap-3">
            <Database className="w-8 h-8 text-indigo-400" />
            Database Explorer
          </h1>
          <p className="text-slate-400 mt-1 flex items-center gap-2">
            <Server className="w-4 h-4" />
            SQLite Database: <span className="font-mono text-slate-300">local.db</span>
            <span className="text-slate-500">|</span>
            <span className="text-amber-400/90 font-semibold flex items-center gap-1">
              <ShieldCheck className="w-4 h-4" /> Mode: READ ONLY
            </span>
          </p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 bg-slate-800/80 hover:bg-slate-700/80 text-white rounded-lg border border-slate-700 transition-colors"
        >
          <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
          Refresh Data
        </button>
      </div>

      <div className="bg-slate-900 border border-slate-700/80 p-4 rounded-xl text-xs font-mono text-slate-300">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 mb-2">
          <h3 className="font-semibold text-white uppercase flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            Database Explorer Live Status
          </h3>
          <span className="text-[11px] text-cyan-400 font-sans font-medium">
            Active User: {user ? `${user.email} (${user.role})` : 'All Security Team Members (Unrestricted Inspection)'}
          </span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-slate-800 text-[11px]">
          <div><span className="text-slate-500">Database:</span> <span className="text-slate-200">local.db (SQLite)</span></div>
          <div><span className="text-slate-500">API Status:</span> <span className="text-emerald-400 font-bold">{apiDiagnostics.tablesStatus === 200 ? '200 OK' : apiDiagnostics.tablesStatus}</span></div>
          <div><span className="text-slate-500">Tables Loaded:</span> <span className="text-indigo-300 font-bold">{tables.length}</span></div>
          <div><span className="text-slate-500">Selected Records:</span> <span className="text-cyan-300 font-bold">{tableData?.rows?.length || 0}</span></div>
        </div>
        {errorMsg && (
          <div className="mt-3 p-3 bg-red-900/30 border border-red-500 text-red-300 rounded-lg flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 font-sans">
            <div>
              <p className="font-mono text-xs text-red-400 font-semibold mb-1">Notice: {errorMsg}</p>
              <p className="text-xs text-slate-300">
                Failed to load live database records. Click retry to refresh connection.
              </p>
            </div>
            <button
              onClick={handleRefresh}
              className="inline-flex items-center gap-2 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-md text-xs font-semibold shrink-0 transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Retry Connection
            </button>
          </div>
        )}
      </div>

      <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
        <div>
          <h3 className="font-semibold text-amber-500">READ-ONLY DATABASE VIEW</h3>
          <p className="text-sm text-amber-500/80 mt-1">
            No database modifications are permitted. Sensitive credentials, hashes, and tokens are redacted from this view.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Sidebar */}
        <div className="lg:col-span-1 space-y-4">
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Table className="w-5 h-5 text-slate-400" />
              Tables
            </h3>
            <div className="space-y-1">
              {tables.map((t) => (
                <button
                  key={t.name}
                  onClick={() => handleTableSelect(t.name)}
                  className={cn(
                    "w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-colors",
                    selectedTable === t.name
                      ? "bg-indigo-500/20 text-indigo-300 border border-indigo-500/30"
                      : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-300 border border-transparent"
                  )}
                >
                  <span className="font-mono">{t.name}</span>
                  <span className={cn(
                    "px-2 py-0.5 rounded-full text-xs font-semibold",
                    selectedTable === t.name ? "bg-indigo-500/30" : "bg-slate-800"
                  )}>
                    {t.count}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="lg:col-span-3 space-y-4">
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl flex flex-col min-h-[600px] overflow-hidden">
            
            <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-slate-900">
              <div>
                <h2 className="text-xl font-bold text-white font-mono">{selectedTable}</h2>
                <p className="text-sm text-slate-400 mt-1">
                  Total rows: {tables.find(t => t.name === selectedTable)?.count || 0}
                </p>
              </div>
              <div className="relative w-full sm:w-64">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  placeholder="Filter records..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm text-white focus:outline-none focus:border-indigo-500 transition-colors"
                />
              </div>
            </div>

            {selectedTable === "cachedVulnerabilities" && (
              <div className="grid grid-cols-4 divide-x divide-slate-800 border-b border-slate-800 bg-slate-900/80">
                <div className="p-3 text-center">
                  <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Total</div>
                  <div className="text-xl font-bold text-white mt-1">{tables.find(t => t.name === "cachedVulnerabilities")?.count || 0}</div>
                </div>
                <div className="p-3 text-center">
                  <div className="text-xs font-semibold text-emerald-500/70 uppercase tracking-wider">Live</div>
                  <div className="text-xl font-bold text-emerald-400 mt-1">{liveCount}</div>
                </div>
                <div className="p-3 text-center">
                  <div className="text-xs font-semibold text-blue-500/70 uppercase tracking-wider">Cached</div>
                  <div className="text-xl font-bold text-blue-400 mt-1">{cachedCount}</div>
                </div>
                <div className="p-3 text-center">
                  <div className="text-xs font-semibold text-red-500/70 uppercase tracking-wider">CISA KEV</div>
                  <div className="text-xl font-bold text-red-400 mt-1">{cisaKevCount}</div>
                </div>
              </div>
            )}

            <div className="overflow-x-auto flex-1">
              {loading ? (
                <div className="flex items-center justify-center h-64">
                  <Activity className="w-8 h-8 text-indigo-500 animate-pulse" />
                </div>
              ) : (
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr>
                      <th className="sticky top-0 bg-slate-950 p-3 text-xs font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800 whitespace-nowrap">
                        Provenance
                      </th>
                      {columns.map((col) => (
                        <th
                          key={col}
                          className="sticky top-0 bg-slate-950 p-3 text-xs font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800 whitespace-nowrap"
                        >
                          {col}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {filteredRows.map((row, i) => (
                      <tr key={i} className="hover:bg-slate-800/30 transition-colors">
                        <td className="p-3 whitespace-nowrap">
                          {renderBadge(selectedTable, row)}
                        </td>
                        {columns.map((col) => (
                          <td key={col} className="p-3 text-sm text-slate-300 max-w-[200px] truncate" title={String(row[col])}>
                            {row[col] === null ? (
                              <span className="text-slate-600 italic">null</span>
                            ) : (
                              String(row[col])
                            )}
                          </td>
                        ))}
                      </tr>
                    ))}
                    {filteredRows.length === 0 && (
                      <tr>
                        <td colSpan={columns.length + 1} className="p-8 text-center text-slate-500">
                          No records found.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

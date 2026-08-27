import React, { useEffect, useState, useCallback } from "react";
import { Card, CardHeader, CardTitle, CardContent, Badge, SeverityBadge } from "../components/ui";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import { MapPin, Globe, ShieldAlert, Filter, Layers, ExternalLink, Activity, Radio } from "lucide-react";
import { Link } from "react-router-dom";
import { useRealtimeEvent, useRealtime } from "../context/RealtimeContext";

export default function ThreatMap() {
  const [points, setPoints] = useState<any[]>([]);
  const [selectedFilter, setSelectedFilter] = useState("ALL");
  const [loading, setLoading] = useState(true);
  const { status: sseStatus } = useRealtime();

  const fetchHeatmap = useCallback(() => {
    fetch("/api/heatmap")
      .then(r => r.json())
      .then(data => {
        setPoints(Array.isArray(data) ? data : []);
        setLoading(false);
      })
      .catch(e => {
        console.error(e);
        setPoints([]);
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    fetchHeatmap();
  }, [fetchHeatmap]);

  // Real-Time Event Listeners
  useRealtimeEvent("threatmap.updated", () => {
    fetchHeatmap();
  });
  useRealtimeEvent("intelligence.synced", () => {
    fetchHeatmap();
  });
  useRealtimeEvent("report.correlated", () => {
    fetchHeatmap();
  });

  const filteredPoints = points.filter(p => {
    const w = p.weight ?? (p.severity === "CRITICAL" ? 9 : p.severity === "HIGH" ? 7 : p.severity === "MEDIUM" ? 5 : 3);
    if (selectedFilter === "CRITICAL") return w >= 8;
    if (selectedFilter === "HIGH") return w >= 6 && w < 8;
    if (selectedFilter === "MEDIUM") return w >= 4 && w < 6;
    if (selectedFilter === "LOW") return w < 4;
    return true;
  });

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6 flex flex-col h-[calc(100vh-5rem)]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 shrink-0">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="bg-blue-600/20 text-blue-400 text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase border border-blue-500/30">
              Geospatial Telemetry
            </span>
            <span className="text-slate-400 text-xs font-mono">
              [SYNTHETIC EXERCISE SIMULATION]
            </span>
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Geographic Threat Heatmap</h1>
          <p className="text-slate-400 text-sm mt-1">
            Global visualization of incident densities, targeting vectors, and regional infrastructure impact.
          </p>
        </div>

        <div className="flex items-center gap-3 self-start sm:self-auto">
          <div className="flex items-center gap-1.5 text-xs text-slate-400 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
            <Filter className="w-3.5 h-3.5" />
            <select
              value={selectedFilter}
              onChange={e => setSelectedFilter(e.target.value)}
              className="bg-transparent text-slate-200 text-xs font-semibold focus:outline-none cursor-pointer"
            >
              <option value="ALL" className="bg-slate-900">All Risk Densities</option>
              <option value="CRITICAL" className="bg-slate-900">Critical Density (&gt;= 8)</option>
              <option value="HIGH" className="bg-slate-900">High Density (6-7)</option>
              <option value="MEDIUM" className="bg-slate-900">Medium Density (4-5)</option>
              <option value="LOW" className="bg-slate-900">Low Density (&lt; 4)</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main Map + Sidebar Container */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 flex-1 min-h-0">
        {/* Left 3 Cols: Interactive Map */}
        <Card className="lg:col-span-3 min-h-[450px] relative overflow-hidden border-slate-800">
          <MapContainer
            center={[25, 10]}
            zoom={2.2}
            minZoom={2}
            style={{ height: "100%", width: "100%", backgroundColor: "#070B14" }}
          >
            <TileLayer
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
              attribution='&copy; <a href="https://carto.com/">CARTO</a>'
            />
            {filteredPoints.map((p, idx) => {
              const w = p.weight ?? (p.severity === "CRITICAL" ? 9 : p.severity === "HIGH" ? 7 : p.severity === "MEDIUM" ? 5 : 3);
              const isCrit = w >= 8;
              const isHigh = w >= 6 && w < 8;
              const isMed = w >= 4 && w < 6;
              const color = isCrit ? "#ef4444" : isHigh ? "#f97316" : isMed ? "#eab308" : "#10b981";

              return (
                <CircleMarker
                  key={idx}
                  center={[p.lat, p.lng]}
                  radius={Math.max(6, w * 2.5)}
                  fillColor={color}
                  fillOpacity={0.7}
                  color={color}
                  weight={1.5}
                >
                  <Popup className="custom-popup">
                    <div className="p-2 space-y-1.5 text-slate-900 font-sans min-w-[200px]">
                      <div className="flex items-center justify-between border-b pb-1">
                        <div className="font-bold text-xs uppercase tracking-wider text-slate-900">
                          {p.location || "Regional Node"}
                        </div>
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                          p.riskLevel === "CRITICAL" ? "bg-red-100 text-red-700" :
                          p.riskLevel === "HIGH" ? "bg-orange-100 text-orange-700" :
                          p.riskLevel === "MEDIUM" ? "bg-amber-100 text-amber-700" : "bg-emerald-100 text-emerald-700"
                        }`}>
                          Risk {p.riskScore ?? (w * 10)}/100
                        </span>
                      </div>
                      <div className="text-[11px] font-semibold text-slate-800">
                        Vector: {p.category || "Cyber Threat"}
                      </div>
                      <div className="text-[11px] text-slate-700 flex items-center justify-between">
                        <span>Events: {p.incidentCount || 1}</span>
                        {p.kevStatus && (
                          <span className="bg-red-600 text-white font-bold text-[9px] px-1.5 py-0.2 rounded">
                            CISA KEV
                          </span>
                        )}
                      </div>
                      {p.iocCount > 0 && (
                        <div className="text-[10px] text-slate-600">
                          Linked IOCs: {p.iocCount}
                        </div>
                      )}
                      <div className="text-[9px] text-slate-500 pt-1 border-t flex items-center justify-between font-mono">
                        <span>[{p.lat.toFixed(2)}, {p.lng.toFixed(2)}]</span>
                        <span>{p.sources?.[0] || "Telemetry"}</span>
                      </div>
                    </div>
                  </Popup>
                </CircleMarker>
              );
            })}
          </MapContainer>

          {/* Map Legend Overlay */}
          <div className="absolute bottom-4 left-4 z-[1000] bg-slate-950/90 backdrop-blur border border-slate-800 p-3 rounded-lg text-xs space-y-1.5 shadow-2xl pointer-events-auto">
            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
              Deterministic Threat Risk
            </div>
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1 text-[11px] text-slate-300">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span> Critical (85-100)
              </span>
              <span className="flex items-center gap-1 text-[11px] text-slate-300">
                <span className="w-2.5 h-2.5 rounded-full bg-orange-500"></span> High (70-84)
              </span>
              <span className="flex items-center gap-1 text-[11px] text-slate-300">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span> Med (45-69)
              </span>
              <span className="flex items-center gap-1 text-[11px] text-slate-300">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span> Low (0-44)
              </span>
            </div>
          </div>
        </Card>

        {/* Right Col: Regional Incident Hotspots list */}
        <Card className="flex flex-col h-full overflow-hidden">
          <CardHeader>
            <CardTitle>
              <Globe className="w-4 h-4 text-blue-400" /> Active Regional Hubs
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 space-y-3 overflow-y-auto flex-1">
            {filteredPoints.slice(0, 10).map((pt, i) => (
              <div
                key={i}
                className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5 hover:border-slate-700 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white flex items-center gap-1.5">
                    <MapPin className="w-3.5 h-3.5 text-red-400 shrink-0" />
                    {pt.location}
                  </span>
                  <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                    (pt.riskScore ?? (pt.weight * 10)) >= 85 ? "bg-red-950 text-red-400 border border-red-800/40" :
                    (pt.riskScore ?? (pt.weight * 10)) >= 70 ? "bg-orange-950 text-orange-400 border border-orange-800/40" :
                    (pt.riskScore ?? (pt.weight * 10)) >= 45 ? "bg-amber-950 text-amber-400 border border-amber-800/40" :
                    "bg-emerald-950 text-emerald-400 border border-emerald-800/40"
                  }`}>
                    Risk {pt.riskScore ?? (pt.weight * 10)}/100
                  </span>
                </div>
                <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                  <span>{pt.category}</span>
                  <span>[{pt.lat.toFixed(1)}, {pt.lng.toFixed(1)}]</span>
                </div>
                {pt.kevStatus && (
                  <div className="flex items-center gap-1 text-[10px] text-red-400 font-semibold">
                    <ShieldAlert className="w-3 h-3 text-red-400" /> CISA KEV Active Exploitation
                  </div>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

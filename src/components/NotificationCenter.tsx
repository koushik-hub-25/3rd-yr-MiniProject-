import React, { useState, useEffect } from "react";
import { Bell, AlertCircle, Radio, TrendingUp, CheckCircle, ExternalLink, X } from "lucide-react";
import { SystemNotification } from "../types";
import { Link } from "react-router-dom";
import { cn, SeverityBadge } from "./ui";

export function NotificationCenter() {
  const [isOpen, setIsOpen] = useState(false);
  const [notifications, setNotifications] = useState<SystemNotification[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);

  const fetchNotifications = async () => {
    try {
      const res = await fetch("/api/notifications");
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) {
          setNotifications(data);
          setUnreadCount(data.filter(n => !n.read).length);
        }
      }
    } catch (e) {
      console.warn("Could not load notifications");
    }
  };

  useEffect(() => {
    fetchNotifications();
    const interval = setInterval(fetchNotifications, 45000);
    return () => clearInterval(interval);
  }, []);

  const markAllAsRead = () => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
    setUnreadCount(0);
  };

  const getIcon = (type: string, severity?: string) => {
    if (type === "cisa_kev_match") return <Radio className="w-4 h-4 text-red-400 animate-pulse" />;
    if (type === "emerging_threat") return <TrendingUp className="w-4 h-4 text-amber-400" />;
    if (severity === "CRITICAL") return <AlertCircle className="w-4 h-4 text-red-400" />;
    return <AlertCircle className="w-4 h-4 text-cyan-400" />;
  };

  return (
    <div className="relative">
      <button
        id="btn-notifications-bell"
        onClick={() => setIsOpen(!isOpen)}
        className="relative p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
        title="Intelligence Alerts"
      >
        <Bell className="w-5 h-5" />
        {unreadCount > 0 && (
          <span className="absolute top-1.5 right-1.5 w-4 h-4 rounded-full bg-red-500 text-white text-[9px] font-bold font-mono flex items-center justify-center animate-pulse">
            {unreadCount}
          </span>
        )}
      </button>

      {isOpen && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />
          <div className="absolute right-0 mt-2 w-80 sm:w-96 bg-[#090F1C] border border-slate-700/90 rounded-xl shadow-2xl z-50 overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            {/* Header */}
            <div className="px-4 py-3 border-b border-slate-800 bg-[#0D1527] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Bell className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-bold text-white uppercase tracking-wider">Intelligence Alerts</span>
                {unreadCount > 0 && (
                  <span className="px-1.5 py-0.2 rounded bg-red-950 text-red-400 border border-red-500/30 text-[10px] font-mono font-bold">
                    {unreadCount} NEW
                  </span>
                )}
              </div>
              {unreadCount > 0 && (
                <button
                  onClick={markAllAsRead}
                  className="text-[10px] font-semibold text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  Mark all read
                </button>
              )}
            </div>

            {/* List */}
            <div className="max-h-80 overflow-y-auto divide-y divide-slate-800/60">
              {notifications.length === 0 ? (
                <div className="p-6 text-center text-xs text-slate-500">
                  No active intelligence notifications.
                </div>
              ) : (
                notifications.map((n) => (
                  <div
                    key={n.id}
                    className={cn(
                      "p-3.5 hover:bg-slate-800/40 transition-colors flex gap-3 items-start",
                      !n.read ? "bg-cyan-950/20" : ""
                    )}
                  >
                    <div className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 flex-shrink-0 mt-0.5">
                      {getIcon(n.type, n.severity)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-1 mb-1">
                        <h4 className="text-xs font-semibold text-slate-200 truncate">{n.title}</h4>
                        {n.severity && <SeverityBadge severity={n.severity} />}
                      </div>
                      <p className="text-[11px] text-slate-400 leading-snug line-clamp-2">{n.message}</p>
                      <div className="flex items-center justify-between mt-2 pt-1 border-t border-slate-800/40">
                        <span className="text-[10px] text-slate-500 font-mono">
                          {new Date(n.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                        {n.link && (
                          <Link
                            to={n.link}
                            onClick={() => setIsOpen(false)}
                            className="text-[10px] text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1"
                          >
                            Investigate <ExternalLink className="w-2.5 h-2.5" />
                          </Link>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>

            <div className="p-2 border-t border-slate-800 bg-[#0B1220] text-center">
              <Link
                to="/threats"
                onClick={() => setIsOpen(false)}
                className="text-[11px] text-slate-400 hover:text-cyan-400 font-semibold"
              >
                View all security telemetry →
              </Link>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

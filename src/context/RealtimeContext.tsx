import React, { createContext, useContext, useEffect, useState, useRef, useCallback } from "react";

export type ConnectionStatus = "LIVE" | "RECONNECTING" | "OFFLINE";

export interface RealtimeEvent {
  type: string;
  sequence?: number;
  timestamp: string;
  [key: string]: any;
}

export interface RealtimeContextType {
  status: ConnectionStatus;
  lastEventTime: string | null;
  sourceStatus: Record<string, string>;
  lastEvent: RealtimeEvent | null;
  subscribe: (eventType: string, callback: (event: RealtimeEvent) => void) => () => void;
}

const RealtimeContext = createContext<RealtimeContextType>({
  status: "OFFLINE",
  lastEventTime: null,
  sourceStatus: { nvd: "LIVE", cisa: "LIVE", mitre: "LIVE" },
  lastEvent: null,
  subscribe: () => () => {}
});

export const RealtimeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [status, setStatus] = useState<ConnectionStatus>("CONNECTING" as any);
  const [lastEventTime, setLastEventTime] = useState<string | null>(null);
  const [sourceStatus, setSourceStatus] = useState<Record<string, string>>({
    nvd: "LIVE",
    cisa: "LIVE",
    mitre: "LIVE"
  });
  const [lastEvent, setLastEvent] = useState<RealtimeEvent | null>(null);

  const listenersRef = useRef<Map<string, Set<(event: RealtimeEvent) => void>>>(new Map());
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimeoutRef = useRef<any>(null);
  const retryCountRef = useRef(0);

  const broadcastEvent = useCallback((event: RealtimeEvent) => {
    setLastEvent(event);
    setLastEventTime(event.timestamp || new Date().toISOString());

    if (event.type === "connected" && event.sources) {
      setSourceStatus(event.sources);
    }
    if (event.type === "intelligence.synced" && event.source) {
      const srcKey = event.source.toLowerCase().includes("nvd") ? "nvd" :
                     event.source.toLowerCase().includes("cisa") ? "cisa" :
                     event.source.toLowerCase().includes("mitre") ? "mitre" : event.source;
      setSourceStatus(prev => ({ ...prev, [srcKey]: "LIVE" }));
    }

    // Notify specific type listeners
    const specific = listenersRef.current.get(event.type);
    if (specific) {
      specific.forEach(cb => {
        try { cb(event); } catch (e) { console.error("[Realtime] Listener error:", e); }
      });
    }

    // Notify wildcard listeners
    const wildcard = listenersRef.current.get("*");
    if (wildcard) {
      wildcard.forEach(cb => {
        try { cb(event); } catch (e) { console.error("[Realtime] Wildcard listener error:", e); }
      });
    }
  }, []);

  const connect = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }

    setStatus(retryCountRef.current > 0 ? "RECONNECTING" : ("CONNECTING" as any));

    try {
      const es = new EventSource("/api/events/stream");
      eventSourceRef.current = es;

      es.onopen = () => {
        setStatus("LIVE");
        retryCountRef.current = 0;
      };

      es.onmessage = (e) => {
        try {
          const parsed = JSON.parse(e.data);
          broadcastEvent(parsed);
        } catch (err) {
          // heartbeat or non-json ping
        }
      };

      // Specific named event listeners
      const namedEvents = [
        "connected",
        "heartbeat",
        "intelligence.synced",
        "vulnerability.updated",
        "ioc.discovered",
        "report.correlated",
        "threatmap.updated",
        "threat.updated"
      ];

      namedEvents.forEach(evtName => {
        es.addEventListener(evtName, (e: any) => {
          try {
            const parsed = JSON.parse(e.data);
            broadcastEvent({ ...parsed, type: evtName });
          } catch (err) {
            broadcastEvent({ type: evtName, timestamp: new Date().toISOString() });
          }
        });
      });

      es.onerror = () => {
        es.close();
        eventSourceRef.current = null;
        setStatus("RECONNECTING");

        // Exponential backoff reconnect: min 2s, max 15s
        retryCountRef.current++;
        const backoff = Math.min(15000, Math.max(2000, Math.pow(1.5, retryCountRef.current) * 1000));

        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, backoff);
      };
    } catch (e) {
      setStatus("OFFLINE");
    }
  }, [broadcastEvent]);

  useEffect(() => {
    connect();

    return () => {
      clearTimeout(reconnectTimeoutRef.current);
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, [connect]);

  const subscribe = useCallback((eventType: string, callback: (event: RealtimeEvent) => void) => {
    if (!listenersRef.current.has(eventType)) {
      listenersRef.current.set(eventType, new Set());
    }
    listenersRef.current.get(eventType)!.add(callback);

    return () => {
      const set = listenersRef.current.get(eventType);
      if (set) {
        set.delete(callback);
        if (set.size === 0) {
          listenersRef.current.delete(eventType);
        }
      }
    };
  }, []);

  return (
    <RealtimeContext.Provider value={{
      status: status === ("CONNECTING" as any) ? "RECONNECTING" : status,
      lastEventTime,
      sourceStatus,
      lastEvent,
      subscribe
    }}>
      {children}
    </RealtimeContext.Provider>
  );
};

export function useRealtime() {
  return useContext(RealtimeContext);
}

export function useRealtimeEvent(eventType: string, callback: (event: RealtimeEvent) => void) {
  const { subscribe } = useRealtime();

  useEffect(() => {
    const unsubscribe = subscribe(eventType, callback);
    return () => {
      unsubscribe();
    };
  }, [eventType, callback, subscribe]);
}

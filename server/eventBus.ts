import { EventEmitter } from "events";
import { Response } from "express";

export type CtiEventType =
  | "connected"
  | "heartbeat"
  | "intelligence.synced"
  | "vulnerability.updated"
  | "ioc.discovered"
  | "report.correlated"
  | "threatmap.updated"
  | "threat.updated";

export interface CtiEventPayload {
  type: CtiEventType;
  timestamp: string;
  [key: string]: any;
}

class CtiEventBus extends EventEmitter {
  private clientCount: number = 0;
  private eventSequence: number = 0;

  constructor() {
    super();
    this.setMaxListeners(200); // Support multiple simultaneous dashboard instances
  }

  public emitCtiEvent(eventType: CtiEventType, data: Record<string, any>) {
    this.eventSequence++;
    const payload: CtiEventPayload = {
      ...data,
      type: eventType,
      sequence: this.eventSequence,
      timestamp: new Date().toISOString()
    };

    // Sanitize any potential secret or raw content before broadcasting
    const sanitized = this.sanitizePayload(payload);
    this.emit(eventType, sanitized);
    this.emit("any", sanitized);
  }

  public registerClient(res: Response, initialSourceStatus?: Record<string, string>): () => void {
    this.clientCount++;

    // Initial connection event
    const initEvent: CtiEventPayload = {
      type: "connected",
      sequence: ++this.eventSequence,
      timestamp: new Date().toISOString(),
      sources: initialSourceStatus || {
        nvd: "LIVE",
        cisa: "LIVE",
        mitre: "LIVE"
      }
    };
    this.sendSseMessage(res, "connected", initEvent);

    // Heartbeat every 20 seconds to maintain long-lived connection and avoid proxy timeouts
    const heartbeatInterval = setInterval(() => {
      if (res.writableEnded) {
        clearInterval(heartbeatInterval);
        return;
      }
      this.sendSseMessage(res, "heartbeat", {
        type: "heartbeat",
        timestamp: new Date().toISOString()
      });
    }, 20000);

    // Global listener for this client connection
    const eventHandler = (event: CtiEventPayload) => {
      if (res.writableEnded) return;
      this.sendSseMessage(res, event.type, event);
    };

    this.on("any", eventHandler);

    // Clean up on disconnect
    const cleanup = () => {
      clearInterval(heartbeatInterval);
      this.off("any", eventHandler);
      this.clientCount = Math.max(0, this.clientCount - 1);
    };

    return cleanup;
  }

  public getActiveClients(): number {
    return this.clientCount;
  }

  private sendSseMessage(res: Response, eventName: string, data: any) {
    try {
      if (res.writableEnded) return;
      res.write(`id: ${data.sequence || Date.now()}\n`);
      res.write(`event: ${eventName}\n`);
      res.write(`data: ${JSON.stringify(data)}\n\n`);
      if (typeof (res as any).flush === "function") {
        (res as any).flush();
      }
    } catch (err) {
      // Client connection likely dropped
    }
  }

  private sanitizePayload(payload: any): any {
    if (!payload || typeof payload !== "object") return payload;
    const clean = { ...payload };
    delete clean.rawText;
    delete clean.apiKey;
    delete clean.password;
    delete clean.sessionSecret;
    delete clean.secret;
    delete clean.fileBuffer;
    delete clean.token;
    return clean;
  }
}

export const ctiEventBus = new CtiEventBus();

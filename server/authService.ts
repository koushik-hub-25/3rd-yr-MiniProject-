import crypto from "crypto";
import bcrypt from "bcryptjs";
import { eq, and, gt, desc } from "drizzle-orm";
import { db } from "../src/db";
import { users, sessions, auditLogs } from "../src/db/schema";
import type { Request, Response, NextFunction } from "express";

export interface SafeUser {
  id: string;
  name: string;
  email: string;
  role: 'analyst' | 'senior_analyst' | 'admin' | string;
  emailVerified: boolean;
  clearance: string;
  avatarInitials: string;
  lastLogin?: string;
  createdAt: string;
}

export function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function generateSecureToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

export function generateSessionId(): string {
  return "szen_sess_" + crypto.randomBytes(32).toString("hex");
}

export function generate6DigitOtp(): string {
  // Cryptographically secure uniform random integer between 100000 and 999999 inclusive
  return crypto.randomInt(100000, 1000000).toString();
}

export function maskEmail(email: string): string {
  if (!email || !email.includes("@")) return "u***@***.***";
  const [local, domain] = email.split("@");
  if (local.length <= 2) {
    return `${local[0]}*@${domain}`;
  }
  const maskedLocal = local[0] + "*".repeat(Math.max(4, local.length - 2)) + local[local.length - 1];
  return `${maskedLocal}@${domain}`;
}

export function timingSafeCompareHash(a: string, b: string): boolean {
  try {
    const bufA = Buffer.from(a, "utf-8");
    const bufB = Buffer.from(b, "utf-8");
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

export function getClearanceForRole(role: string): string {
  switch (role) {
    case "admin":
      return "SOC Lead / Full System Admin (Tier-3)";
    case "senior_analyst":
      return "Senior Threat Analyst / Attribution Lead (Tier-2)";
    case "analyst":
    default:
      return "Cyber Threat Intelligence Analyst (Tier-1)";
  }
}

export function formatSafeUser(u: any): SafeUser {
  const nameParts = (u.name || "Analyst").trim().split(" ");
  let avatarInitials = "SA";
  if (nameParts.length >= 2) {
    avatarInitials = (nameParts[0][0] + nameParts[1][0]).toUpperCase();
  } else if (nameParts.length === 1 && nameParts[0].length > 0) {
    avatarInitials = nameParts[0].substring(0, 2).toUpperCase();
  }

  return {
    id: u.id,
    name: u.name,
    email: u.email,
    role: u.role || "analyst",
    emailVerified: Boolean(u.emailVerified === 1 || u.emailVerified === true),
    clearance: getClearanceForRole(u.role || "analyst"),
    avatarInitials,
    lastLogin: u.lastLogin ? new Date(u.lastLogin).toISOString() : undefined,
    createdAt: u.createdAt ? new Date(u.createdAt).toISOString() : new Date().toISOString()
  };
}

export async function logAuditEvent({
  userId,
  userEmail,
  action,
  resourceType,
  resourceId,
  ipAddress,
  details
}: {
  userId?: string | null;
  userEmail?: string | null;
  action: string;
  resourceType?: string | null;
  resourceId?: string | null;
  ipAddress?: string | null;
  details?: Record<string, any> | string | null;
}): Promise<void> {
  try {
    const detailsStr = typeof details === "object" && details !== null ? JSON.stringify(details) : (details || null);
    await db.insert(auditLogs).values({
      id: "audit-" + Math.random().toString(36).substring(2, 10),
      userId: userId || null,
      userEmail: userEmail || null,
      action,
      resourceType: resourceType || null,
      resourceId: resourceId || null,
      timestamp: new Date(),
      ipAddress: ipAddress || null,
      details: detailsStr
    });
  } catch (err) {
    console.warn("[AuditLog] Failed to record audit log:", err);
  }
}

// Ensure default verified Admin account exists on startup if users table is empty
export async function seedInitialAdmin(): Promise<void> {
  try {
    const existingUsers = await db.select().from(users).limit(1);
    if (existingUsers.length === 0) {
      const adminEmail = (process.env.INITIAL_ADMIN_EMAIL || "admin@shieldzen.sec").toLowerCase().trim();
      
      // If INITIAL_ADMIN_PASSWORD is set in environment, use it; otherwise generate a cryptographically secure random credential
      const isEnvProvided = Boolean(process.env.INITIAL_ADMIN_PASSWORD);
      const adminPassword = process.env.INITIAL_ADMIN_PASSWORD || crypto.randomBytes(16).toString("base64").replace(/[+/=]/g, "A").slice(0, 16) + "#1A!";
      const passwordHash = await bcrypt.hash(adminPassword, 10);

      const adminId = "usr-admin-001";
      await db.insert(users).values({
        id: adminId,
        name: "Security Director",
        email: adminEmail,
        passwordHash,
        role: "admin",
        emailVerified: 1,
        createdAt: new Date(),
        updatedAt: new Date()
      });

      console.log(`[AuthService] Initialized SOC Administrator: ${adminEmail}`);
      if (!isEnvProvided) {
        console.log(`[AuthService] ONE-TIME GENERATED ADMIN PASSWORD: ${adminPassword} (Set INITIAL_ADMIN_PASSWORD in environment to customize)`);
      }
      
      await logAuditEvent({
        userId: adminId,
        userEmail: adminEmail,
        action: "INITIAL_ADMIN_BOOTSTRAP",
        resourceType: "USER",
        resourceId: adminId,
        details: { message: "System bootstrap created primary administrator account.", isEnvConfigured: isEnvProvided }
      });
    }
  } catch (err) {
    console.warn("[AuthService] Notice during admin user seeding check:", err);
  }
}

// Session Validation Helper
export async function getUserFromSession(token: string): Promise<SafeUser | null> {
  if (!token) return null;

  try {
    const session = await db.query.sessions.findFirst({
      where: and(
        eq(sessions.id, token),
        gt(sessions.expiresAt, new Date())
      )
    });

    if (!session) return null;

    const user = await db.query.users.findFirst({
      where: eq(users.id, session.userId)
    });

    if (!user) return null;

    return formatSafeUser(user);
  } catch (err) {
    console.error("[AuthService] Error reading session:", err);
    return null;
  }
}

// Express Auth Middleware
export interface AuthenticatedRequest extends Request {
  user?: SafeUser;
  sessionToken?: string;
}

export function extractSessionToken(req: Request): string | null {
  // 1. Check HTTP-Only Cookie 'szen_session'
  if (req.headers.cookie) {
    const match = req.headers.cookie.match(/szen_session=([^;]+)/);
    if (match) return decodeURIComponent(match[1]);
  }
  // 2. Check cookie-parser cookies object
  if ((req as any).cookies && (req as any).cookies.szen_session) {
    return String((req as any).cookies.szen_session).trim();
  }
  // 3. Check Authorization Bearer header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return authHeader.substring(7).trim();
  }
  // 4. Check custom header
  if (req.headers["x-session-token"]) {
    return String(req.headers["x-session-token"]).trim();
  }
  return null;
}

export async function authenticate(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const token = extractSessionToken(req);

  const isDbEndpoint = req.originalUrl?.includes("/api/admin/database");
  if (isDbEndpoint) {
    console.log(`[DIAGNOSTIC] Endpoint: ${req.method} ${req.originalUrl}`);
    console.log(`[DIAGNOSTIC] Has szen_session cookie in headers:`, Boolean(req.headers.cookie && req.headers.cookie.includes("szen_session")));
    console.log(`[DIAGNOSTIC] Has session token extracted (cookie or header):`, Boolean(token));
  }

  if (!token) {
    if (isDbEndpoint) console.log(`[DIAGNOSTIC] authenticate: Session NOT found (No token provided) -> 401`);
    return res.status(401).json({ error: "Authentication required. Please log in." });
  }

  const user = await getUserFromSession(token);
  
  if (isDbEndpoint) {
    console.log(`[DIAGNOSTIC] authenticate: Session found in DB:`, Boolean(user));
    if (user) {
      console.log(`[DIAGNOSTIC] User ID: ${user.id}`);
      console.log(`[DIAGNOSTIC] User Role: ${user.role}`);
    }
  }

  if (!user) {
    if (isDbEndpoint) console.log(`[DIAGNOSTIC] authenticate: Session expired or invalid in DB -> 401`);
    return res.status(401).json({ error: "Session expired or invalid. Please log in again." });
  }

  req.user = user;
  req.sessionToken = token;
  next();
}

export async function optionalAuthenticate(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const token = extractSessionToken(req);
  if (token) {
    const user = await getUserFromSession(token);
    if (user) {
      req.user = user;
      req.sessionToken = token;
    }
  }
  next();
}

export function requireRole(...allowedRoles: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const isDbEndpoint = req.originalUrl?.includes("/api/admin/database");
    if (!req.user) {
      if (isDbEndpoint) console.log(`[DIAGNOSTIC] requireRole: No user attached -> 401`);
      return res.status(401).json({ error: "Authentication required." });
    }
    const passes = allowedRoles.includes(req.user.role);
    if (isDbEndpoint) {
      console.log(`[DIAGNOSTIC] requireAdmin/Role check: Allowed=[${allowedRoles.join(",")}], UserRole=${req.user.role}, Passes=${passes}`);
    }
    if (!passes) {
      return res.status(403).json({
        error: `Access forbidden: Role '${req.user.role}' lacks required clearance (${allowedRoles.join(", ")}).`
      });
    }
    next();
  };
}

export const requireAdmin = requireRole("admin");


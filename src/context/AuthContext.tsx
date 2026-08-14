/**
 * ShieldZen Academic Research Prototype - Authentication Context
 * Note: This provides lightweight client-side authentication and session state
 * management for academic and demonstration purposes.
 */
import React, { createContext, useContext, useState, useEffect } from "react";
import { UserProfile } from "../types";

interface AuthContextType {
  user: UserProfile | null;
  isAuthenticated: boolean;
  login: (email: string, password?: string) => Promise<boolean>;
  logout: () => void;
  loading: boolean;
}

const DEFAULT_USER: UserProfile = {
  id: "usr-demo-alex",
  name: "Alex Morgan",
  email: "alex.morgan@shieldzen.sec",
  role: "Senior Security Analyst",
  clearance: "SOC Tier-2 / CTI Lead",
  lastLogin: new Date().toISOString(),
  avatarInitials: "AM"
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(() => {
    const saved = localStorage.getItem("shieldzen_auth_user");
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        return DEFAULT_USER;
      }
    }
    // Default to authenticated demo analyst for smooth experience
    return DEFAULT_USER;
  });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (user) {
      localStorage.setItem("shieldzen_auth_user", JSON.stringify(user));
    } else {
      localStorage.removeItem("shieldzen_auth_user");
    }
  }, [user]);

  const login = async (email: string, password?: string): Promise<boolean> => {
    setLoading(true);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (data.success && data.user) {
        setUser(data.user);
        return true;
      } else {
        // Fallback demo user
        setUser(DEFAULT_USER);
        return true;
      }
    } catch (e) {
      setUser(DEFAULT_USER);
      return true;
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem("shieldzen_auth_user");
    fetch("/api/auth/logout", { method: "POST" }).catch(() => {});
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        login,
        logout,
        loading
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

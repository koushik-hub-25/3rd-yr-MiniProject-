import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import { UserProfile } from "../types";

export interface AuthResult {
  success: boolean;
  message?: string;
  error?: string;
  requiresVerification?: boolean;
  otpRequired?: boolean;
  challengeId?: string;
  maskedEmail?: string;
  expiresAt?: string;
  resendCooldown?: number;
  email?: string;
  user?: UserProfile;
}

interface AuthContextType {
  user: UserProfile | null;
  isAuthenticated: boolean;
  loading: boolean;
  login: (email: string, password: string) => Promise<AuthResult>;
  verifyOtp: (challengeId: string, otp: string) => Promise<AuthResult>;
  resendOtp: (challengeId: string) => Promise<{ success: boolean; challengeId?: string; maskedEmail?: string; expiresAt?: string; resendCooldown?: number; message?: string; error?: string }>;
  register: (name: string, email: string, password: string, role?: string) => Promise<AuthResult>;
  verifyEmail: (email: string, token: string) => Promise<AuthResult>;
  resendVerification: (email: string) => Promise<AuthResult>;
  forgotPassword: (email: string) => Promise<AuthResult>;
  resetPassword: (email: string, token: string, newPassword: string) => Promise<AuthResult>;
  logout: () => Promise<void>;
  refreshProfile: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  // Restore authenticated session from server on startup
  const refreshProfile = useCallback(async () => {
    try {
      const res = await fetch("/api/auth/me", {
        headers: { "Accept": "application/json" }
      });
      if (res.ok) {
        const data = await res.json();
        if (data && data.user) {
          setUser(data.user);
        } else {
          setUser(null);
        }
      } else {
        setUser(null);
      }
    } catch (e) {
      console.warn("[Auth] Session validation check failed:", e);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshProfile();
  }, [refreshProfile]);

  const login = async (email: string, password: string): Promise<AuthResult> => {
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), password })
      });
      const data = await res.json();

      // Check if 2FA OTP challenge is returned
      if (res.ok && data.success && data.otpRequired) {
        return {
          success: true,
          otpRequired: true,
          challengeId: data.challengeId,
          maskedEmail: data.maskedEmail,
          expiresAt: data.expiresAt,
          resendCooldown: data.resendCooldown,
          email: email.trim()
        };
      }

      if (res.ok && data.success && data.user) {
        setUser(data.user);
        return { success: true, user: data.user };
      }

      // Explicitly check for unverified email status
      if (res.status === 403 && data.requiresVerification) {
        return {
          success: false,
          error: data.error || "Please verify your email address to proceed.",
          requiresVerification: true,
          email: data.email || email
        };
      }

      return {
        success: false,
        error: data.error || "Invalid email or password."
      };
    } catch (e: any) {
      return {
        success: false,
        error: "Unable to connect to authentication service. Please try again."
      };
    }
  };

  const verifyOtp = async (challengeId: string, otp: string): Promise<AuthResult> => {
    try {
      const res = await fetch("/api/auth/verify-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId, otp: otp.trim() })
      });
      const data = await res.json();

      if (res.ok && data.success && data.user) {
        setUser(data.user);
        return { success: true, user: data.user };
      }

      return {
        success: false,
        error: data.error || "Invalid verification code."
      };
    } catch (e: any) {
      return {
        success: false,
        error: "Network error while verifying authentication code."
      };
    }
  };

  const resendOtp = async (challengeId: string) => {
    try {
      const res = await fetch("/api/auth/resend-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId })
      });
      const data = await res.json();

      if (res.ok && data.success) {
        return {
          success: true,
          challengeId: data.challengeId,
          maskedEmail: data.maskedEmail,
          expiresAt: data.expiresAt,
          resendCooldown: data.resendCooldown || 30,
          message: data.message || "A new 6-digit code has been sent."
        };
      }

      return {
        success: false,
        error: data.error || "Failed to resend verification code.",
        resendCooldown: data.resendCooldown
      };
    } catch (e: any) {
      return {
        success: false,
        error: "Failed to connect to verification server."
      };
    }
  };

  const register = async (name: string, email: string, password: string, role?: string): Promise<AuthResult> => {
    try {
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: name.trim(), email: email.trim(), password, role })
      });
      const data = await res.json();

      if (res.ok && data.success) {
        return {
          success: true,
          message: data.message || "Registration successful! A verification email has been sent.",
          requiresVerification: true,
          email: data.email || email
        };
      }

      return {
        success: false,
        error: data.error || "Registration failed. Please verify your details."
      };
    } catch (e: any) {
      return {
        success: false,
        error: "Network error during registration. Please check your connection."
      };
    }
  };

  const verifyEmail = async (email: string, token: string): Promise<AuthResult> => {
    try {
      const res = await fetch("/api/auth/verify-email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), token: token.trim() })
      });
      const data = await res.json();

      if (res.ok && data.success) {
        if (data.user) {
          setUser(data.user);
        }
        return {
          success: true,
          message: data.message || "Email verified successfully!",
          user: data.user
        };
      }

      return {
        success: false,
        error: data.error || "Invalid or expired verification token."
      };
    } catch (e: any) {
      return {
        success: false,
        error: "Failed to connect to verification service."
      };
    }
  };

  const resendVerification = async (email: string): Promise<AuthResult> => {
    try {
      const res = await fetch("/api/auth/resend-verification", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim() })
      });
      const data = await res.json();

      if (res.ok && data.success) {
        return {
          success: true,
          message: data.message || "Verification link sent to your inbox."
        };
      }

      return {
        success: false,
        error: data.error || "Failed to resend verification link."
      };
    } catch (e: any) {
      return {
        success: false,
        error: "Failed to communicate with verification server."
      };
    }
  };

  const forgotPassword = async (email: string): Promise<AuthResult> => {
    try {
      const res = await fetch("/api/auth/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim() })
      });
      const data = await res.json();

      if (res.ok && data.success) {
        return {
          success: true,
          message: data.message || "Password reset instructions dispatched."
        };
      }

      return {
        success: false,
        error: data.error || "Failed to request password reset."
      };
    } catch (e: any) {
      return {
        success: false,
        error: "Network error during password reset request."
      };
    }
  };

  const resetPassword = async (email: string, token: string, newPassword: string): Promise<AuthResult> => {
    try {
      const res = await fetch("/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), token: token.trim(), newPassword })
      });
      const data = await res.json();

      if (res.ok && data.success) {
        return {
          success: true,
          message: data.message || "Password updated successfully. You can now log in."
        };
      }

      return {
        success: false,
        error: data.error || "Password reset failed. Invalid or expired token."
      };
    } catch (e: any) {
      return {
        success: false,
        error: "Network error during password update."
      };
    }
  };

  const logout = async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch (e) {
      console.warn("[Auth] Logout API call error:", e);
    } finally {
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        loading,
        login,
        verifyOtp,
        resendOtp,
        register,
        verifyEmail,
        resendVerification,
        forgotPassword,
        resetPassword,
        logout,
        refreshProfile
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

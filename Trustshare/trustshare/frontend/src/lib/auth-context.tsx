"use client";

import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api, clearTokens, getAccessToken, setTokens } from "./api";
import { AuthResponse, User } from "./types";

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<AuthResponse>;
  verifyMfaLogin: (mfaToken: string, code: string) => Promise<void>;
  register: (email: string, fullName: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  can: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const refreshUser = useCallback(async () => {
    const token = getAccessToken();
    if (!token) {
      setUser(null);
      setLoading(false);
      return;
    }
    try {
      const res = await api.get<User>("/auth/me");
      setUser(res.data);
    } catch {
      clearTokens();
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshUser();
  }, [refreshUser]);

  const login = async (email: string, password: string): Promise<AuthResponse> => {
    const res = await api.post<AuthResponse>("/auth/login", { email, password });
    const data = res.data;
    if (!data.mfa_required && data.access_token && data.refresh_token && data.user) {
      setTokens(data.access_token, data.refresh_token);
      setUser(data.user);
    }
    return data;
  };

  const verifyMfaLogin = async (mfaToken: string, code: string): Promise<void> => {
    const res = await api.post<AuthResponse>("/auth/mfa/verify-login", {
      mfa_token: mfaToken,
      code,
    });
    if (res.data.access_token && res.data.refresh_token && res.data.user) {
      setTokens(res.data.access_token, res.data.refresh_token);
      setUser(res.data.user);
    }
  };

  const register = async (email: string, fullName: string, password: string): Promise<void> => {
    const res = await api.post<AuthResponse>("/auth/register", {
      email,
      full_name: fullName,
      password,
    });
    if (res.data.access_token && res.data.refresh_token && res.data.user) {
      setTokens(res.data.access_token, res.data.refresh_token);
      setUser(res.data.user);
    }
  };

  const logout = async (): Promise<void> => {
    try {
      await api.post("/auth/logout");
    } catch {
      // ignore network/expired errors during logout
    } finally {
      clearTokens();
      setUser(null);
    }
  };

  const can = useCallback(
    (permission: string) => Boolean(user?.permissions?.includes(permission)),
    [user]
  );

  return (
    <AuthContext.Provider
      value={{ user, loading, login, verifyMfaLogin, register, logout, refreshUser, can }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}

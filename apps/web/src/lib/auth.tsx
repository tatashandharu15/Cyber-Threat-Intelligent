"use client";

import { useRouter } from "next/navigation";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { apiFetch, clearToken, getToken, setToken } from "./api";
import type { LoginResponse, MeResponse } from "./types";

interface AuthContextValue {
  me: MeResponse | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (
    tenant: string,
    email: string,
    password: string,
    mfa?: string,
  ) => Promise<void>;
  logout: () => Promise<void>;
  hasPermission: (permission?: string) => boolean;
  hasAnyPermission: (permissions: string[]) => boolean;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [me, setMe] = useState<MeResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const loadMe = useCallback(async () => {
    const data = await apiFetch<MeResponse>("/api/auth/me");
    setMe(data);
    return data;
  }, []);

  useEffect(() => {
    let active = true;
    const token = getToken();
    if (!token) {
      setIsLoading(false);
      return;
    }
    loadMe()
      .catch(() => {
        clearToken();
        if (active) setMe(null);
      })
      .finally(() => {
        if (active) setIsLoading(false);
      });
    return () => {
      active = false;
    };
  }, [loadMe]);

  const login = useCallback(
    async (tenant: string, email: string, password: string, mfa?: string) => {
      const data = await apiFetch<LoginResponse>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({
          tenant_slug: tenant,
          email,
          password,
          ...(mfa ? { mfa_code: mfa } : {}),
        }),
      });
      setToken(data.token);
      await loadMe();
    },
    [loadMe],
  );

  const logout = useCallback(async () => {
    try {
      await apiFetch<unknown>("/api/auth/logout", { method: "POST" });
    } catch {
      // best-effort; clear local state regardless
    }
    clearToken();
    setMe(null);
    router.push("/login");
  }, [router]);

  const hasPermission = useCallback(
    (permission?: string) => {
      if (!permission) return true;
      if (!me) return false;
      return me.permissions.includes(permission);
    },
    [me],
  );

  const hasAnyPermission = useCallback(
    (permissions: string[]) => {
      if (permissions.length === 0) return true;
      if (!me) return false;
      return permissions.some((p) => me.permissions.includes(p));
    },
    [me],
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      me,
      isLoading,
      isAuthenticated: me !== null,
      login,
      logout,
      hasPermission,
      hasAnyPermission,
    }),
    [me, isLoading, login, logout, hasPermission, hasAnyPermission],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}

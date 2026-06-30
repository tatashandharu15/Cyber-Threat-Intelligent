"use client";

import { useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";
import { AppShell } from "@/components/app-shell";
import { LoadingState } from "@/components/states";
import { getToken } from "@/lib/api";
import { useAuth } from "@/lib/auth";

export default function ProtectedLayout({ children }: { children: ReactNode }) {
  const router = useRouter();
  const { isLoading, isAuthenticated } = useAuth();

  useEffect(() => {
    if (typeof window === "undefined") return;
    if (!getToken()) {
      router.replace("/login");
      return;
    }
    if (!isLoading && !isAuthenticated) {
      router.replace("/login");
    }
  }, [isLoading, isAuthenticated, router]);

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <LoadingState label="Loading workspace…" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <LoadingState label="Redirecting to sign in…" />
      </div>
    );
  }

  return <AppShell>{children}</AppShell>;
}

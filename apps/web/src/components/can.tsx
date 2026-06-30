"use client";

import type { ReactNode } from "react";
import { useAuth } from "@/lib/auth";

/**
 * Renders children only when the current user holds the given permission.
 * Omitting `permission` always renders children.
 */
export function Can({
  permission,
  fallback = null,
  children,
}: {
  permission?: string;
  fallback?: ReactNode;
  children: ReactNode;
}) {
  const { hasPermission } = useAuth();
  if (!hasPermission(permission)) return <>{fallback}</>;
  return <>{children}</>;
}

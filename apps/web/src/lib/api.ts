import type { ApiErrorEnvelope, ApiSuccess } from "./types";

const TOKEN_KEY = "cti_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly details?: unknown;

  constructor(message: string, code: string, status: number, details?: unknown) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

/**
 * apiFetch calls the same-origin Next.js proxy (path already starts with /api).
 * It attaches the bearer token, parses the standard envelope, throws ApiError on
 * failures, and clears the token + redirects to /login on a 401.
 */
export async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers = new Headers(options.headers);
  headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const res = await fetch(path, { ...options, headers });

  if (res.status === 401) {
    clearToken();
    if (typeof window !== "undefined" && window.location.pathname !== "/login") {
      window.location.assign("/login");
    }
  }

  let body: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }

  if (!res.ok) {
    const errBody = body as ApiErrorEnvelope | null;
    const err = errBody?.error;
    throw new ApiError(
      err?.message || res.statusText || "Request failed",
      err?.code || "UNKNOWN",
      res.status,
      err?.details,
    );
  }

  return (body as ApiSuccess<T>).data;
}

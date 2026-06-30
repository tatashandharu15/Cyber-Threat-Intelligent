import type { Page, Route } from "@playwright/test";
import { ALL_PERMISSIONS, E2E_TOKEN, meResponse, ok } from "./fixtures";

/** localStorage key the app reads the JWT from (see src/lib/api.ts). */
export const TOKEN_KEY = "cti_token";

/**
 * Register the network-guard catch-all so no test ever silently hits a real
 * `/api/...` endpoint. Unstubbed GETs return an empty list and other methods an
 * empty object — both wrapped in the standard `{ data, meta }` envelope.
 *
 * Playwright evaluates `page.route` handlers in REVERSE registration order
 * (most-recently-added wins). This MUST therefore be registered FIRST (it is —
 * `loginAs` calls it before everything else) so it has the LOWEST priority and
 * only handles requests that no more-specific stub (`/api/auth/me`, the page
 * data stubs) claimed.
 *
 * `/api/auth/*` is intentionally NOT matched here so the `/api/auth/me` stub
 * (registered right after) is the one that resolves the session.
 */
function registerNetworkGuard(page: Page): Promise<void> {
  return page.route("**/api/**", (route: Route) => {
    if (route.request().url().includes("/api/auth/")) {
      return route.fallback();
    }
    const method = route.request().method();
    if (method === "GET") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: ok([]),
      });
    }
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: ok({}),
    });
  });
}

/**
 * Seed an authenticated session WITHOUT touching the real backend.
 *
 * The protected `(app)` layout reads `localStorage.cti_token` synchronously in
 * a `useEffect` and redirects to /login when it is missing, so the token must
 * exist before any app script runs — hence `addInitScript`, which executes on
 * every navigation/document creation prior to page scripts.
 *
 * It also stubs `GET /api/auth/me` so `AuthProvider` can resolve the session.
 * Pass a narrower `permissions` array to exercise RBAC gating.
 *
 * Call this BEFORE `page.goto(...)`. Register any page-specific data stubs
 * (also before navigation) so the loaded route has its data ready; because
 * Playwright runs handlers most-recent-first, those later stubs take priority
 * over the network guard installed here.
 */
export async function loginAs(
  page: Page,
  permissions: string[] = ALL_PERMISSIONS,
): Promise<void> {
  await page.addInitScript(
    ([key, token]) => {
      window.localStorage.setItem(key, token);
    },
    [TOKEN_KEY, E2E_TOKEN] as const,
  );

  // Lowest-priority guard first, then the auth/me stub on top of it.
  await registerNetworkGuard(page);

  await page.route("**/api/auth/me", (route: Route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: ok(meResponse(permissions)),
    }),
  );
}

/**
 * Fulfill a GET request with a `{ data, meta }` success envelope. Non-GET
 * methods fall through to the next handler / continue, so write stubs stay
 * read-focused. Returns a handler suitable for `page.route`.
 */
export function jsonRoute<T>(data: T) {
  return (route: Route) => {
    if (route.request().method() !== "GET") {
      return route.fallback();
    }
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: ok(data),
    });
  };
}

/**
 * Back-compat shim for tests that register page data stubs and then call this
 * to "close off" the network. The real guard is now installed by `loginAs`
 * (registered first, so it is the lowest-priority fallback). Registering it a
 * second time here would SHADOW the page's specific data stubs (most-recent
 * handler wins), so this handler simply defers via `route.fallback()`, letting
 * the earlier specific stubs — and finally the `loginAs` guard — resolve each
 * request.
 */
export async function stubRemainingApi(page: Page): Promise<void> {
  await page.route("**/api/**", (route: Route) => route.fallback());
}

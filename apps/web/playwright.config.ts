import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright E2E configuration for the SiberIndo CTI web app.
 *
 * Two test layers live under ./e2e:
 *   A. Deterministic UI E2E (default) — every `/api/...` request is fulfilled
 *      by Playwright via `page.route`, so the suite runs in CI with NO backend.
 *   B. Optional real-backend smoke — guarded by E2E_REAL_BACKEND (skipped by
 *      default). See e2e/smoke.realbackend.spec.ts.
 *
 * IMPORTANT: the `webServer` below runs the PRODUCTION server (`npm run start`),
 * which requires a prior build. Run one of:
 *     npm run build && PORT=3100 npx playwright test
 * or set the command to `npm run build && npm run start` (slower; rebuilds each
 * run). We keep `npm run start` here so an already-built app starts instantly,
 * and `reuseExistingServer` lets a locally running dev/start server be reused.
 */
export default defineConfig({
  testDir: "./e2e",
  // Run files in parallel; each test owns its own page + routes so they are
  // independent.
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  timeout: 30_000,
  expect: { timeout: 10_000 },

  use: {
    baseURL: "http://localhost:3100",
    trace: "on-first-retry",
    // The sidebar is `hidden md:flex`, so RBAC nav assertions need a desktop
    // viewport. Keep it wide enough for the md+ breakpoint.
    viewport: { width: 1280, height: 800 },
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],

  webServer: {
    // Requires `npm run build` to have produced `.next` first. The MANDATORY
    // verify flow runs `npm run build && PORT=3100 npx playwright test`.
    command: "npm run start",
    port: 3100,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: { PORT: "3100" },
  },
});

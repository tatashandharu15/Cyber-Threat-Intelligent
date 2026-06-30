import { expect, test } from "@playwright/test";

/**
 * Layer B — OPTIONAL real-backend smoke test.
 *
 * SKIPPED unless E2E_REAL_BACKEND is set. This talks to the actual services
 * through the Next.js `/api/*` proxy (no request interception), so it requires:
 *
 *   1. Backend up + seeded:   make up && make seed   (from the repo root)
 *   2. The web app built and served WITH the proxy pointing at the backend:
 *        cd apps/web
 *        npm run build
 *        BACKEND_HOST=http://localhost PORT=3100 npm run start
 *      (next.config.ts rewrites /api/auth/* -> :8081/v1/auth/*, etc.)
 *   3. Run only this spec with the gate enabled:
 *        E2E_REAL_BACKEND=1 npx playwright test smoke.realbackend
 *
 * Demo credentials (from the seed): tenant `demo`,
 *   analyst@demo.siberindo.io / Demo!Passw0rd
 */
test.describe("real-backend smoke", () => {
  test.skip(
    !process.env.E2E_REAL_BACKEND,
    "Set E2E_REAL_BACKEND=1 with backend running (make up && make seed) to enable.",
  );

  test("real login then dashboard loads", async ({ page }) => {
    await page.goto("/login");

    await page.locator("#tenant").fill("demo");
    await page.locator("#email").fill("analyst@demo.siberindo.io");
    await page.locator("#password").fill("Demo!Passw0rd");
    await page.getByRole("button", { name: "Sign in" }).click();

    await page.waitForURL("**/dashboard");
    await expect(
      page.getByRole("heading", { name: "Dashboard" }),
    ).toBeVisible();

    // The app shell renders with navigation.
    await expect(
      page.locator("aside").getByRole("link", { name: "Dashboard", exact: true }),
    ).toBeVisible();
  });
});

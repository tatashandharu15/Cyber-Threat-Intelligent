import { expect, test } from "@playwright/test";
import { loginAs } from "./support/auth";
import { LOGIN_RESPONSE, meResponse, ok } from "./support/fixtures";

test.describe("authentication", () => {
  test("login page renders the form", async ({ page }) => {
    await page.goto("/login");

    // "SiberIndo CTI" is a shadcn CardTitle (a styled <div>, not a heading
    // role), so match it by visible text rather than role.
    await expect(page.getByText("SiberIndo CTI")).toBeVisible();
    await expect(
      page.getByText("Sign in to your threat intelligence workspace"),
    ).toBeVisible();
    await expect(page.locator("#tenant")).toBeVisible();
    await expect(page.locator("#email")).toBeVisible();
    await expect(page.locator("#password")).toBeVisible();
    await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();

    // Tenant defaults to "demo" (see login/page.tsx initial state).
    await expect(page.locator("#tenant")).toHaveValue("demo");
  });

  test("unauthenticated visit to /dashboard redirects to /login", async ({
    page,
  }) => {
    // No token seeded → the protected layout must bounce to /login.
    await page.goto("/dashboard");
    await page.waitForURL("**/login");
    await expect(page.getByText("SiberIndo CTI")).toBeVisible();
  });

  test("successful login redirects to dashboard and renders the shell", async ({
    page,
  }) => {
    let loginBody: Record<string, unknown> | null = null;

    await page.route("**/api/auth/login", async (route) => {
      loginBody = JSON.parse(route.request().postData() ?? "{}");
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: ok(LOGIN_RESPONSE),
      });
    });

    await page.route("**/api/auth/me", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: ok(meResponse()),
      }),
    );

    await page.goto("/login");

    await page.locator("#tenant").fill("demo");
    await page.locator("#email").fill("analyst@demo.siberindo.io");
    await page.locator("#password").fill("Demo!Passw0rd");
    await page.getByRole("button", { name: "Sign in" }).click();

    // Redirect to the dashboard and the protected shell renders.
    await page.waitForURL("**/dashboard");
    await expect(
      page.getByRole("heading", { name: "Dashboard" }),
    ).toBeVisible();
    // Sidebar (app shell) renders with the brand + nav.
    await expect(
      page.getByRole("link", { name: "Dashboard" }),
    ).toBeVisible();

    // The token was persisted under the expected localStorage key.
    const token = await page.evaluate(() =>
      window.localStorage.getItem("cti_token"),
    );
    expect(token).toBe("e2e.jwt.token");

    // Login request carried the form fields in the documented shape.
    expect(loginBody).toMatchObject({
      tenant_slug: "demo",
      email: "analyst@demo.siberindo.io",
      password: "Demo!Passw0rd",
    });
  });

  test("invalid credentials surface an error and stay on /login", async ({
    page,
  }) => {
    await page.route("**/api/auth/login", (route) =>
      route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({
          error: { code: "INVALID_CREDENTIALS", message: "Invalid credentials" },
          meta: { request_id: "e2e", timestamp: "2026-06-21T00:00:00Z" },
        }),
      }),
    );

    await page.goto("/login");
    await page.locator("#email").fill("wrong@demo.siberindo.io");
    await page.locator("#password").fill("nope");
    await page.getByRole("button", { name: "Sign in" }).click();

    // The login form renders the error as an inline <p role="alert">. A bare
    // getByRole("alert") is ambiguous because Next.js also mounts a route
    // announcer with role="alert" (and sonner toasts use alert/status roles),
    // so scope to the inline paragraph specifically.
    await expect(page.locator('p[role="alert"]')).toContainText(
      "Invalid credentials",
    );
    await expect(page).toHaveURL(/\/login$/);
  });

  test("loginAs helper establishes a session for /dashboard", async ({
    page,
  }) => {
    await loginAs(page);
    await page.goto("/dashboard");
    await expect(
      page.getByRole("heading", { name: "Dashboard" }),
    ).toBeVisible();
  });
});

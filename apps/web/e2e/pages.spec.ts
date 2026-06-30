import { expect, test, type Page } from "@playwright/test";
import { jsonRoute, loginAs, stubRemainingApi } from "./support/auth";
import {
  ALERT_METRICS,
  ASSETS,
  AUDIT_EVENTS,
  DLM_FINDINGS,
  INDICATORS,
  NOTIFICATIONS,
  ok,
  RECENT_ALERTS,
  TAKEDOWNS,
} from "./support/fixtures";

/**
 * Each test seeds auth, stubs the page's data endpoints with small fixtures,
 * then a catch-all for everything else, navigates, and asserts the DataTable /
 * cards render the data. A second pass with empty fixtures asserts the
 * empty-state copy.
 */

async function row(page: Page) {
  return page.locator("table tbody tr");
}

test.describe("data pages render fixtures", () => {
  test("dashboard renders metric cards, chart, and recent alerts", async ({
    page,
  }) => {
    await loginAs(page);
    await page.route("**/api/alerts/metrics", jsonRoute(ALERT_METRICS));
    await page.route("**/api/alerts?**", jsonRoute(RECENT_ALERTS));
    await stubRemainingApi(page);

    await page.goto("/dashboard");

    await expect(
      page.getByRole("heading", { name: "Dashboard" }),
    ).toBeVisible();

    // Total open = 2+5+9+3+1 = 20. The "Total open" summary card shows it.
    await expect(page.getByText("Total open")).toBeVisible();
    await expect(page.getByText("20", { exact: true })).toBeVisible();

    // Recent alerts table shows fixture rows.
    await expect(
      page.getByText("Leaked credential set on paste site"),
    ).toBeVisible();
    await expect(
      page.getByText("Phishing kit targeting brand login"),
    ).toBeVisible();
  });

  test("dashboard recent-alerts empty state", async ({ page }) => {
    await loginAs(page);
    await page.route("**/api/alerts/metrics", jsonRoute({ open_by_severity: {} }));
    await page.route("**/api/alerts?**", jsonRoute([]));
    await stubRemainingApi(page);

    await page.goto("/dashboard");
    await expect(page.getByText("No recent alerts.")).toBeVisible();
  });

  test("findings page renders DLM findings", async ({ page }) => {
    await loginAs(page);
    await page.route("**/api/dlm/findings**", jsonRoute(DLM_FINDINGS));
    await stubRemainingApi(page);

    await page.goto("/findings");
    await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();

    // DLM is the default tab.
    await expect(page.getByText("Customer DB dump on dark web")).toBeVisible();
    await expect(page.getByText("Source code repository exposed")).toBeVisible();
    expect(await (await row(page)).count()).toBeGreaterThanOrEqual(2);
  });

  test("findings page empty state", async ({ page }) => {
    await loginAs(page);
    await page.route("**/api/dlm/findings**", jsonRoute([]));
    await stubRemainingApi(page);

    await page.goto("/findings");
    await expect(
      page.getByText("No DLM findings match the current filter."),
    ).toBeVisible();
  });

  test("indicators page renders rows", async ({ page }) => {
    await loginAs(page);
    await page.route("**/api/indicators?**", jsonRoute(INDICATORS));
    await stubRemainingApi(page);

    await page.goto("/indicators");
    await expect(
      page.getByRole("heading", { name: "Indicators" }),
    ).toBeVisible();
    await expect(page.getByText("evil-phish.example.com")).toBeVisible();
    await expect(page.getByText("203.0.113.66")).toBeVisible();
  });

  test("indicators page empty state", async ({ page }) => {
    await loginAs(page);
    await page.route("**/api/indicators?**", jsonRoute([]));
    await stubRemainingApi(page);

    await page.goto("/indicators");
    await expect(
      page.getByText("No indicators match the current filter."),
    ).toBeVisible();
  });

  test("takedowns page renders rows", async ({ page }) => {
    await loginAs(page);
    await page.route("**/api/takedowns?**", jsonRoute(TAKEDOWNS));
    await stubRemainingApi(page);

    await page.goto("/takedowns");
    await expect(
      page.getByRole("heading", { name: "Takedowns" }),
    ).toBeVisible();
    await expect(page.getByText("abuse@registrar.example")).toBeVisible();
  });

  test("takedowns page empty state", async ({ page }) => {
    await loginAs(page);
    await page.route("**/api/takedowns?**", jsonRoute([]));
    await stubRemainingApi(page);

    await page.goto("/takedowns");
    await expect(
      page.getByText("No takedowns match the current filter."),
    ).toBeVisible();
  });

  test("notifications page renders rows", async ({ page }) => {
    await loginAs(page);
    await page.route("**/api/notifications?**", jsonRoute(NOTIFICATIONS));
    await stubRemainingApi(page);

    await page.goto("/notifications");
    await expect(
      page.getByRole("heading", { name: "Notifications" }),
    ).toBeVisible();
    await expect(
      page.getByText("New critical alert assigned"),
    ).toBeVisible();
  });

  test("notifications page empty state", async ({ page }) => {
    await loginAs(page);
    await page.route("**/api/notifications?**", jsonRoute([]));
    await stubRemainingApi(page);

    await page.goto("/notifications");
    await expect(
      page.getByText("No notifications match the current filter."),
    ).toBeVisible();
  });

  test("audit page renders rows", async ({ page }) => {
    await loginAs(page);
    await page.route("**/api/audit-logs?**", jsonRoute(AUDIT_EVENTS));
    await stubRemainingApi(page);

    await page.goto("/audit");
    await expect(page.getByRole("heading", { name: "Audit" })).toBeVisible();
    await expect(page.getByText("auth.login")).toBeVisible();
  });

  test("audit page empty state", async ({ page }) => {
    await loginAs(page);
    await page.route("**/api/audit-logs?**", jsonRoute([]));
    await stubRemainingApi(page);

    await page.goto("/audit");
    await expect(
      page.getByText("No audit events match the current filter."),
    ).toBeVisible();
  });

  test("assets page renders rows", async ({ page }) => {
    await loginAs(page);
    await page.route("**/api/assets?**", jsonRoute(ASSETS));
    await stubRemainingApi(page);

    await page.goto("/assets");
    await expect(page.getByRole("heading", { name: "Assets" })).toBeVisible();
    await expect(page.getByText("siberindo.io")).toBeVisible();
    await expect(page.getByText("Primary corporate domain")).toBeVisible();
  });

  test("assets page empty state", async ({ page }) => {
    await loginAs(page);
    await page.route("**/api/assets?**", jsonRoute([]));
    await stubRemainingApi(page);

    await page.goto("/assets");
    await expect(
      page.getByText("No assets match the current filter."),
    ).toBeVisible();
  });

  test("loading -> loaded transition (skeleton then rows)", async ({ page }) => {
    await loginAs(page);

    // Delay the indicators response so the loading skeleton is observable.
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    await page.route("**/api/indicators?**", async (route) => {
      if (route.request().method() !== "GET") return route.fallback();
      await gate;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: ok(INDICATORS),
      });
    });
    await stubRemainingApi(page);

    await page.goto("/indicators");

    // While the request is pending, the DataTable shows skeleton placeholders
    // and NOT the data rows.
    await expect(page.getByText("evil-phish.example.com")).toHaveCount(0);

    // Release the response → rows appear (loaded state).
    release();
    await expect(page.getByText("evil-phish.example.com")).toBeVisible();
  });
});

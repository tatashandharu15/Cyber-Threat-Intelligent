import { expect, test, type Page } from "@playwright/test";
import { loginAs, stubRemainingApi } from "./support/auth";

/**
 * Sidebar destinations and the header each route renders. The sidebar is
 * `hidden md:flex` (see app-shell.tsx), so a desktop viewport is required —
 * configured globally in playwright.config.ts.
 */
const DESTINATIONS = [
  { nav: "Dashboard", href: "/dashboard", heading: "Dashboard" },
  { nav: "Findings", href: "/findings", heading: "Findings" },
  { nav: "Investigation", href: "/investigations", heading: "Investigations" },
  { nav: "Indicators", href: "/indicators", heading: "Indicators" },
  { nav: "Takedowns", href: "/takedowns", heading: "Takedowns" },
  { nav: "Notifications", href: "/notifications", heading: "Notifications" },
  { nav: "Audit", href: "/audit", heading: "Audit" },
  { nav: "Assets", href: "/assets", heading: "Assets" },
];

function sidebar(page: Page) {
  return page.locator("aside");
}

test.describe("RBAC-aware navigation", () => {
  test("full-permission user sees all 8 destinations and each route loads its header", async ({
    page,
  }) => {
    await loginAs(page); // ALL_PERMISSIONS by default
    await stubRemainingApi(page);

    await page.goto("/dashboard");
    await expect(
      page.getByRole("heading", { name: "Dashboard" }),
    ).toBeVisible();

    // All 8 nav links are present in the sidebar.
    for (const dest of DESTINATIONS) {
      await expect(
        sidebar(page).getByRole("link", { name: dest.nav, exact: true }),
      ).toBeVisible();
    }
    await expect(sidebar(page).getByRole("link")).toHaveCount(
      DESTINATIONS.length,
    );

    // Visiting each route renders its page header.
    for (const dest of DESTINATIONS) {
      await page.goto(dest.href);
      await expect(
        page.getByRole("heading", { name: dest.heading, exact: true }),
      ).toBeVisible();
    }
  });

  test("restricted user (finding:read only) hides gated nav items", async ({
    page,
  }) => {
    await loginAs(page, ["finding:read"]);
    await stubRemainingApi(page);

    await page.goto("/dashboard");
    await expect(
      page.getByRole("heading", { name: "Dashboard" }),
    ).toBeVisible();

    // Dashboard (always visible) + Findings (finding:read) = 2 links only.
    const visible = ["Dashboard", "Findings"];
    const hidden = [
      "Investigation",
      "Indicators",
      "Takedowns",
      "Notifications",
      "Audit",
      "Assets",
    ];

    for (const name of visible) {
      await expect(
        sidebar(page).getByRole("link", { name, exact: true }),
      ).toBeVisible();
    }
    for (const name of hidden) {
      await expect(
        sidebar(page).getByRole("link", { name, exact: true }),
      ).toHaveCount(0);
    }
    await expect(sidebar(page).getByRole("link")).toHaveCount(visible.length);
  });

  test("no-permission user sees only the always-visible Dashboard link", async ({
    page,
  }) => {
    await loginAs(page, []);
    await stubRemainingApi(page);

    await page.goto("/dashboard");
    await expect(
      sidebar(page).getByRole("link", { name: "Dashboard", exact: true }),
    ).toBeVisible();
    await expect(sidebar(page).getByRole("link")).toHaveCount(1);
  });
});

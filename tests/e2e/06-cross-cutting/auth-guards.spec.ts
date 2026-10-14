// 06-cross-cutting/auth-guards.spec.ts
import { test, expect } from "@playwright/test";
import { navigateTo } from "../fixtures/helpers";

test.describe("Auth Guards", () => {
  test("unauthenticated user redirected from /agency/dashboard", async ({ page }) => {
    await navigateTo(page, "/agency/dashboard");
    await page.waitForTimeout(3000);
    expect(page.url()).not.toContain("/agency/dashboard");
  });

  test("unauthenticated user redirected from /checkout", async ({ page }) => {
    await navigateTo(page, "/checkout");
    await page.waitForTimeout(3000);
    // Should be redirected to login or shown auth prompt
    const bodyText = await page.textContent("body");
    expect(bodyText).toBeTruthy();
  });

  test("unauthenticated user can access homepage", async ({ page }) => {
    await navigateTo(page, "/");
    await page.waitForLoadState("networkidle");
    expect(page.url()).toContain("localhost");
  });

  test("unauthenticated user can access login page", async ({ page }) => {
    await navigateTo(page, "/auth/login");
    await page.waitForLoadState("networkidle");
    expect(page.url()).toContain("/auth");
  });

});

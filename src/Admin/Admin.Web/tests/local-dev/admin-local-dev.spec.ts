import { test, expect } from '@playwright/test';

test('M5_LOCAL_DEV_01 shows DevelopmentAuth then authenticates through the Vite proxy and renders seeded PostgreSQL data', async ({ page }) => {
  const baseUrl = process.env.M5_ADMIN_DEV_BASE_URL ?? 'https://localhost:5173/admin/';
  await page.goto(baseUrl);
  await expect(page.getByRole('heading', { name: 'Administrative access' })).toBeVisible();
  await page.getByRole('button', { name: 'Security Administrator' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  const sessionStatus = await page.evaluate(async () => (await fetch('/admin/auth/me', { credentials: 'same-origin' })).status);
  expect(sessionStatus).toBe(200);
  await page.getByRole('link', { name: 'Tenants' }).click();
  await expect(page.getByText('Demo tenant')).toBeVisible();
  await page.getByRole('link', { name: 'Connectors' }).click();
  await expect(page.getByText('demo-orders')).toBeVisible();

  for (const pageName of ['Dashboard', 'Applications', 'Installations', 'Bindings', 'Grants', 'Approvals', 'Access control', 'Audit', 'Health']) {
    await page.getByRole('link', { name: pageName }).click();
    await expect(page.getByRole('heading', { name: pageName }).first()).toBeVisible();
  }
});

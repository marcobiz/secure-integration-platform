import { test, expect } from '@playwright/test';

test('M5_LOCAL_DEV_01 authenticates through the Vite proxy and renders seeded PostgreSQL data', async ({ context, page }) => {
  const baseUrl = process.env.M5_ADMIN_DEV_BASE_URL ?? 'https://localhost:5173/admin/';
  const csrfResponse = await context.request.get(new URL('auth/csrf', baseUrl).toString());
  expect(csrfResponse.status()).toBe(200);
  const csrf = await csrfResponse.json() as { token: string };
  const loginResponse = await context.request.post(new URL('auth/development/login', baseUrl).toString(), {
    headers: { 'X-CSRF-TOKEN': csrf.token },
    data: { userName: 'security-admin' }
  });
  expect(loginResponse.status()).toBe(200);

  const session = await context.request.get(new URL('auth/me', baseUrl).toString());
  expect(session.status()).toBe(200);
  await page.goto(baseUrl);
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  await page.getByRole('link', { name: 'Tenants' }).click();
  await expect(page.getByText('Demo tenant')).toBeVisible();
  await page.getByRole('link', { name: 'Connectors' }).click();
  await expect(page.getByText('demo-orders')).toBeVisible();

  for (const pageName of ['Dashboard', 'Applications', 'Installations', 'Bindings', 'Grants', 'Approvals', 'Access control', 'Audit', 'Health']) {
    await page.getByRole('link', { name: pageName }).click();
    await expect(page.getByRole('heading', { name: pageName }).first()).toBeVisible();
  }
});

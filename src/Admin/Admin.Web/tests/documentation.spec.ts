import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

for (const role of ['Viewer', 'ConnectorEditor', 'ConnectorApprover', 'Operator', 'SecurityAdministrator']) {
  test(`GUIDE-01 menu and direct link are available to ${role}`, async ({ page }) => {
    await page.route('**/admin/auth/me', route => route.fulfill({ json: { id: 'guide-reader', displayName: 'Guide reader', roles: [{ role, tenantId: null }] } }));
    await page.route('**/admin/api/**', route => {
      if (route.request().url().endsWith('/dashboard')) return route.fulfill({ json: { tenants: 0, applications: 0, database: 'healthy', provider: 'healthy', generatedAtUtc: '2026-09-07T14:30:00Z' } });
      return route.abort();
    });
    await page.goto('./');
    await page.getByRole('link', { name: 'Documentation', exact: true }).click();
    await expect(page).toHaveURL(/\/admin\/documentation$/);
    await expect(page.getByRole('article')).toHaveAttribute('lang', 'en');
    await page.getByRole('navigation', { name: 'Contents' }).getByRole('link', { name: 'Guided onboarding', exact: true }).click();
    await expect(page).toHaveURL(/#onboarding$/);
    await expect(page.locator('#onboarding')).toBeFocused();
    await page.reload();
    await expect(page.locator('#onboarding')).toBeFocused();
    await expect(page.locator('#onboarding')).toBeInViewport();
    await page.goto('documentation#activation-handoff');
    await expect(page.locator('#activation-handoff')).toBeFocused();
    await expect(page.locator('#activation-handoff')).toBeInViewport();
  });
}

test('GUIDE-02 small viewport, localized navigation, keyboard links and accessible themes', async ({ page }) => {
  test.setTimeout(60_000);
  await page.setViewportSize({ width: 375, height: 812 });
  await page.route('**/admin/auth/me', route => route.fulfill({ json: { id: 'guide-reader', displayName: 'Guide reader', roles: [{ role: 'Viewer', tenantId: null }] } }));
  const apiRequests: string[] = [];
  await page.route('**/admin/api/**', route => { apiRequests.push(route.request().url()); return route.abort(); });
  for (const choice of [{ language: 'en', theme: 'light', menu: 'Open navigation', label: 'Documentation', contents: 'Contents' }, { language: 'it', theme: 'dark', menu: 'Apri navigazione', label: 'Documentazione', contents: 'Indice' }]) {
    await page.addInitScript(value => { localStorage.setItem('sip.language', value.language); localStorage.setItem('sip.theme', value.theme); }, choice);
    await page.goto('documentation');
    await expect(page.getByRole('heading', { name: choice.label, exact: true })).toBeVisible();
    await page.getByRole('button', { name: choice.menu, exact: true }).click();
    await page.getByRole('link', { name: choice.label, exact: true }).click();
    const topic = page.getByRole('navigation', { name: choice.contents }).getByRole('link', { name: 'Audit and safe diagnostics' });
    await topic.focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#audit')).toBeFocused();
    await expect(page.locator('#audit')).toBeInViewport();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    const result = await new AxeBuilder({ page }).include('#admin-guide').analyze();
    expect(result.violations.filter(violation => ['critical', 'serious'].includes(violation.impact ?? ''))).toEqual([]);
  }
  expect(apiRequests).toEqual([]);
});

test('GUIDE-03 an unauthenticated direct link stays behind the existing session boundary', async ({ page }) => {
  await page.route('**/admin/auth/me', route => route.fulfill({ status: 401, json: {} }));
  await page.goto('documentation#onboarding');
  await expect(page).toHaveURL(/\/admin\/login$/);
  await expect(page.getByRole('article')).toHaveCount(0);
});

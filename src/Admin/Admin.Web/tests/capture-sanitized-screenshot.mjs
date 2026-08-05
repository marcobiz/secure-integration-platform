/* global process, fetch, setTimeout */
import { spawn } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { chromium } from 'playwright';

const server = spawn(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['run', 'dev', '--', '--strictPort'], { stdio: 'ignore', windowsHide: true, shell: process.platform === 'win32' });
try {
  let ready = false;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try { const response = await fetch('http://127.0.0.1:5173/admin/'); ready = response.ok; if (ready) break; } catch { /* startup */ }
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  if (!ready) throw new Error('SANITIZED_SCREENSHOT_SERVER_NOT_READY');
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 960 } });
  await page.route('**/admin/auth/me', route => route.fulfill({ json: { id: '20000000-0000-0000-0000-000000000001', displayName: 'Preview administrator', roles: [{ role: 'SecurityAdministrator', tenantId: null }] } }));
  await page.route('**/admin/api/v1/dashboard', route => route.fulfill({ json: { tenants: 3, applications: 5, database: 'healthy', provider: 'healthy', generatedAtUtc: '2026-08-05T11:30:00Z' } }));
  await page.goto('http://127.0.0.1:5173/admin/');
  await page.getByRole('heading', { name: 'Dashboard' }).waitFor();
  await mkdir('../../../docs/images', { recursive: true });
  await page.screenshot({ path: '../../../docs/images/admin-dashboard.png', fullPage: true });
  await browser.close();
} finally {
  server.kill();
}

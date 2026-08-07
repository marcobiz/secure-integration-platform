import { defineConfig, devices } from '@playwright/test';

const testPort = process.env.ADMIN_WEB_TEST_PORT ?? '5173';
const adminBaseUrl = `http://127.0.0.1:${testPort}/admin/`;

export default defineConfig({
  testDir: './tests', testIgnore: 'full-stack/**', timeout: 30_000, retries: 0, workers: 1,
  reporter: [['list'], ['json', { outputFile: 'test-results/results.json' }]],
  use: { baseURL: adminBaseUrl, trace: 'retain-on-failure', screenshot: 'off', video: 'off' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: { command: `npm run dev -- --strictPort --port ${testPort}`, url: adminBaseUrl, reuseExistingServer: true, timeout: 120_000 }
});

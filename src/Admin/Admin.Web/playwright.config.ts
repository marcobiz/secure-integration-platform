import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests', testIgnore: ['full-stack/**', 'local-dev/**'], timeout: 30_000, retries: 0, workers: 1,
  reporter: [['list'], ['json', { outputFile: 'test-results/results.json' }]],
  use: { baseURL: 'http://127.0.0.1:5173/admin/', trace: 'retain-on-failure', screenshot: 'off', video: 'off' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: { command: 'npm run dev -- --strictPort', url: 'http://127.0.0.1:5173/admin/', reuseExistingServer: true, timeout: 120_000 }
});

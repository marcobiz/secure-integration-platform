import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/full-stack',
  timeout: 120_000,
  outputDir: 'test-results/artifacts',
  retries: 0,
  workers: 1,
  reporter: [['list'], ['json', { outputFile: 'test-results/full-stack-results.json' }]],
  use: {
    baseURL: process.env.M5_FULLSTACK_BASE_URL ?? 'https://localhost:18443/admin/',
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off'
  },
  projects: [{ name: 'chromium-full-stack', use: { ...devices['Desktop Chrome'] } }]
});

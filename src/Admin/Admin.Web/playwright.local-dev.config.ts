import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/local-dev',
  timeout: 30_000,
  retries: 0,
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: process.env.M5_ADMIN_DEV_BASE_URL ?? 'https://localhost:5173/admin/',
    trace: 'off',
    screenshot: 'off',
    video: 'off'
  },
  projects: [{ name: 'chromium-local-dev', use: { ...devices['Desktop Chrome'] } }]
});

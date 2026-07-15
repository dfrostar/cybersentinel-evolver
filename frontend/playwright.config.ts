import { defineConfig, devices } from '@playwright/test';

const PORT = 8090;

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: 'list',
  timeout: 30_000,
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: 'on-first-retry',
    headless: true,
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    command: `python scripts/run_server.py --test-db --port ${PORT}`,
    cwd: '..',
    port: PORT,
    timeout: 30_000,
    reuseExistingServer: false,
  },
});

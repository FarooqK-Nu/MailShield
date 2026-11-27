import { defineConfig, devices } from '@playwright/test';

const PORT = 5199;

export default defineConfig({
  testDir: 'apps/web/e2e',
  use: { baseURL: `http://localhost:${PORT}` },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `npm run dev -w @mailshield/web -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}/preview-harness.html`,
    reuseExistingServer: false,
  },
});

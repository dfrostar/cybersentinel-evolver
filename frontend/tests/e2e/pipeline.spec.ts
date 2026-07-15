import { test, expect } from '@playwright/test';

const API_BASE = '/api';

async function getJSON(page, path) {
  return await page.evaluate(async (url) => {
    const res = await fetch(url);
    return await res.json();
  }, `${API_BASE}${path}`);
}

test.describe('CyberSentinel Evolver E2E', () => {
  test('full pipeline: dashboard → scenarios → tournament', async ({ page }) => {
    // ---- 1. Dashboard loads with empty state ----
    await page.goto('/');
    await expect(page.locator('h1')).toHaveText('CyberSentinel Evolver');

    // Metrics should show 0 initially
    const initial = await getJSON(page, '/metrics');
    expect(initial.total_scenarios).toBe(0);
    expect(initial.total_tournaments).toBe(0);

    // ---- 2. Generate scenarios ----
    await page.click('button:has-text("Generate Scenarios")');

    // Wait for metrics to update (scenarios >= 12)
    await expect.poll(async () => (await getJSON(page, '/metrics')).total_scenarios, {
      timeout: 15_000,
    }).toBeGreaterThanOrEqual(12);

    // ---- 3. Run tournament ----
    await page.click('button:has-text("Run Tournament")');

    // Wait for tournament results to persist
    await expect.poll(async () => (await getJSON(page, '/metrics')).total_tournaments, {
      timeout: 15_000,
    }).toBe(3);

    // ---- 4. Scenarios page ----
    await page.click('nav a:has-text("Scenarios")');
    await expect(page.locator('h2')).toContainText('Scenarios');
    const rows = page.locator('table tbody tr');
    await expect(rows.first()).toBeVisible();
    await expect.poll(async () => await rows.count()).toBeGreaterThanOrEqual(12);

    // ---- 5. Tournaments page ----
    await page.click('nav a:has-text("Tournaments")');
    await expect(page.locator('h2')).toContainText('Tournament History');
    const tourneyRows = page.locator('table tbody tr');
    await expect(tourneyRows.first()).toBeVisible();
    await expect(await tourneyRows.count()).toBe(3);
  });

  test('gap analysis and self-prompt endpoints work', async ({ page }) => {
    // Generate scenarios first
    await page.goto('/');
    await page.click('button:has-text("Generate Scenarios")');
    await expect.poll(async () => (await getJSON(page, '/metrics')).total_scenarios, {
      timeout: 15_000,
    }).toBeGreaterThanOrEqual(12);

    // Trigger gap analysis
    const gapRes = await page.evaluate(async () => {
      const res = await fetch('/api/gap-analysis/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'coverage' }),
      });
      return await res.json();
    });
    expect(gapRes.status).toBe('ok');
  });

  test('health and metrics endpoints respond', async ({ page }) => {
    const health = await getJSON(page, '/health');
    expect(health.status).toBe('healthy');

    const metrics = await getJSON(page, '/metrics');
    expect(metrics).toHaveProperty('total_scenarios');
    expect(metrics).toHaveProperty('total_tournaments');
    expect(metrics).toHaveProperty('avg_win_rate');
  });
});

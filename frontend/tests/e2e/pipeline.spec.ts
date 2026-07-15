import { test, expect } from '@playwright/test';

const API_BASE = '/api';

async function getJSON(page, path) {
  return await page.evaluate(async (url) => {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
    return await res.json();
  }, `${API_BASE}${path}`);
}

async function postJSON(page, path, body) {
  return await page.evaluate(async ({ url, b }) => {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(b),
    });
    return await res.json();
  }, { url: `${API_BASE}${path}`, b: body });
}

async function getCardValue(page, title) {
  return await page.evaluate((t) => {
    const cards = document.querySelectorAll('.card');
    for (const card of cards) {
      const h3 = card.querySelector('h3');
      if (h3?.textContent === t) {
        return card.querySelector('.value')?.textContent || '';
      }
    }
    return '';
  }, title);
}

test.describe('CyberSentinel Evolver E2E', () => {
  test('frontend renders and shows empty dashboard', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('h1')).toHaveText('CyberSentinel Evolver');
    await expect(page.locator('nav a')).toHaveText(['Dashboard', 'Scenarios', 'Tournaments']);
  });

  test('full pipeline: generate scenarios, run tournament, verify DOM', async ({ page }) => {
    await page.goto('/');

    // Wait for dashboard to load
    await expect(page.locator('.grid .card').first()).toBeVisible();

    // Generate scenarios via UI button
    await page.click('button:has-text("Generate Scenarios")');

    // Wait for the scenarios metric card to update (poll the DOM)
    await expect.poll(async () => parseInt(await getCardValue(page, 'Scenarios') || '0'), {
      timeout: 15_000,
    }).toBeGreaterThanOrEqual(12);

    // Run tournament
    await page.click('button:has-text("Run Tournament")');
    await expect.poll(async () => parseInt(await getCardValue(page, 'Tournaments') || '0'), {
      timeout: 15_000,
    }).toBe(3);

    // Verify scenarios page
    await page.click('nav a:has-text("Scenarios")');
    await expect(page.locator('h2')).toContainText('Scenarios');
    await expect(page.locator('table tbody tr').first()).toBeVisible({ timeout: 10_000 });

    // Verify tournaments page
    await page.click('nav a:has-text("Tournaments")');
    await expect(page.locator('h2')).toContainText('Tournament History');
    await expect(page.locator('table tbody tr')).toHaveCount(3, { timeout: 10_000 });
  });

  test('gap analysis and self-prompt endpoints respond', async ({ page }) => {
    await page.goto('/');
    await page.click('button:has-text("Generate Scenarios")');
    await expect.poll(async () => parseInt(await getCardValue(page, 'Scenarios') || '0'), {
      timeout: 15_000,
    }).toBeGreaterThanOrEqual(12);

    // Trigger gap analysis via API
    const gapRes = await postJSON(page, '/gap-analysis/run', { type: 'coverage' });
    expect(gapRes.status).toBe('ok');

    // Trigger self-prompt via API
    const spRes = await postJSON(page, '/self-prompt', { trigger: 'mutation_escaped', context: '{}' });
    expect(spRes.status).toBe('ok');
    expect(spRes.record).toBeDefined();
    expect(Array.isArray(spRes.scenarios)).toBe(true);
  });

  test('evolve endpoint runs the evolution loop', async ({ page }) => {
    await page.goto('/');
    await page.click('button:has-text("Generate Scenarios")');
    await expect.poll(async () => parseInt(await getCardValue(page, 'Scenarios') || '0'), {
      timeout: 15_000,
    }).toBeGreaterThanOrEqual(12);

    // Trigger evolve with auto_promote
    const evoRes = await page.evaluate(async () => {
      const res = await fetch('/api/evolve?weeks=1&auto_promote=true', { method: 'POST' });
      return await res.json();
    });
    expect(evoRes.status).toBe('ok');
    expect(evoRes.winner).toBeTruthy();
  });

  test('health and metrics endpoints respond', async ({ page }) => {
    await page.goto('/');
    // /health is not under /api/ — call it directly
    const health = await page.evaluate(async () => {
      const res = await fetch('/health');
      return await res.json();
    });
    expect(health.status).toBe('healthy');

    const metrics = await getJSON(page, '/metrics');
    expect(metrics).toHaveProperty('total_scenarios');
    expect(metrics).toHaveProperty('total_tournaments');
    expect(metrics).toHaveProperty('avg_win_rate');
  });
});

# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: pipeline.spec.ts >> CyberSentinel Evolver E2E >> gap analysis and self-prompt endpoints work
- Location: tests/e2e/pipeline.spec.ts:54:3

# Error details

```
Test timeout of 30000ms exceeded.
```

```
Error: page.click: Test timeout of 30000ms exceeded.
Call log:
  - waiting for locator('button:has-text("Generate Scenarios")')

```

# Page snapshot

```yaml
- generic [ref=e2]: "{\"detail\":\"Not Found\"}"
```

# Test source

```ts
  1  | import { test, expect } from '@playwright/test';
  2  | 
  3  | const API_BASE = '/api';
  4  | 
  5  | async function getJSON(page, path) {
  6  |   return await page.evaluate(async (url) => {
  7  |     const res = await fetch(url);
  8  |     return await res.json();
  9  |   }, `${API_BASE}${path}`);
  10 | }
  11 | 
  12 | test.describe('CyberSentinel Evolver E2E', () => {
  13 |   test('full pipeline: dashboard → scenarios → tournament', async ({ page }) => {
  14 |     // ---- 1. Dashboard loads with empty state ----
  15 |     await page.goto('/');
  16 |     await expect(page.locator('h1')).toHaveText('CyberSentinel Evolver');
  17 | 
  18 |     // Metrics should show 0 initially
  19 |     const initial = await getJSON(page, '/metrics');
  20 |     expect(initial.total_scenarios).toBe(0);
  21 |     expect(initial.total_tournaments).toBe(0);
  22 | 
  23 |     // ---- 2. Generate scenarios ----
  24 |     await page.click('button:has-text("Generate Scenarios")');
  25 | 
  26 |     // Wait for metrics to update (scenarios >= 12)
  27 |     await expect.poll(async () => (await getJSON(page, '/metrics')).total_scenarios, {
  28 |       timeout: 15_000,
  29 |     }).toBeGreaterThanOrEqual(12);
  30 | 
  31 |     // ---- 3. Run tournament ----
  32 |     await page.click('button:has-text("Run Tournament")');
  33 | 
  34 |     // Wait for tournament results to persist
  35 |     await expect.poll(async () => (await getJSON(page, '/metrics')).total_tournaments, {
  36 |       timeout: 15_000,
  37 |     }).toBe(3);
  38 | 
  39 |     // ---- 4. Scenarios page ----
  40 |     await page.click('nav a:has-text("Scenarios")');
  41 |     await expect(page.locator('h2')).toContainText('Scenarios');
  42 |     const rows = page.locator('table tbody tr');
  43 |     await expect(rows.first()).toBeVisible();
  44 |     await expect.poll(async () => await rows.count()).toBeGreaterThanOrEqual(12);
  45 | 
  46 |     // ---- 5. Tournaments page ----
  47 |     await page.click('nav a:has-text("Tournaments")');
  48 |     await expect(page.locator('h2')).toContainText('Tournament History');
  49 |     const tourneyRows = page.locator('table tbody tr');
  50 |     await expect(tourneyRows.first()).toBeVisible();
  51 |     await expect(await tourneyRows.count()).toBe(3);
  52 |   });
  53 | 
  54 |   test('gap analysis and self-prompt endpoints work', async ({ page }) => {
  55 |     // Generate scenarios first
  56 |     await page.goto('/');
> 57 |     await page.click('button:has-text("Generate Scenarios")');
     |                ^ Error: page.click: Test timeout of 30000ms exceeded.
  58 |     await expect.poll(async () => (await getJSON(page, '/metrics')).total_scenarios, {
  59 |       timeout: 15_000,
  60 |     }).toBeGreaterThanOrEqual(12);
  61 | 
  62 |     // Trigger gap analysis
  63 |     const gapRes = await page.evaluate(async () => {
  64 |       const res = await fetch('/api/gap-analysis/run', {
  65 |         method: 'POST',
  66 |         headers: { 'Content-Type': 'application/json' },
  67 |         body: JSON.stringify({ type: 'coverage' }),
  68 |       });
  69 |       return await res.json();
  70 |     });
  71 |     expect(gapRes.status).toBe('ok');
  72 |   });
  73 | 
  74 |   test('health and metrics endpoints respond', async ({ page }) => {
  75 |     const health = await getJSON(page, '/health');
  76 |     expect(health.status).toBe('healthy');
  77 | 
  78 |     const metrics = await getJSON(page, '/metrics');
  79 |     expect(metrics).toHaveProperty('total_scenarios');
  80 |     expect(metrics).toHaveProperty('total_tournaments');
  81 |     expect(metrics).toHaveProperty('avg_win_rate');
  82 |   });
  83 | });
  84 | 
```
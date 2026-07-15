# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: pipeline.spec.ts >> CyberSentinel Evolver E2E >> health and metrics endpoints respond
- Location: tests/e2e/pipeline.spec.ts:74:3

# Error details

```
Error: page.evaluate: TypeError: Failed to execute 'fetch' on 'Window': Failed to parse URL from /api/health
    at eval (eval at evaluate (:303:30), <anonymous>:2:23)
    at UtilityScript.evaluate (<anonymous>:305:16)
    at UtilityScript.<anonymous> (<anonymous>:1:44)
```
/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const { test, expect } = require('@playwright/test');

test('a one-use local SSH handoff enters this Hub without a password in the browser URL', async ({ page }) => {
  const login = await page.request.post('/api/v1/session', {
    data: { username: 'owner', password: 'fixture-owner-passphrase' },
  });
  expect(login.ok()).toBe(true);
  const session = await login.json();
  const grant = 'A'.repeat(43);
  await page.route('http://127.0.0.1:49310/grant', async (route) => {
    expect(route.request().headers().origin).toBe('http://127.0.0.1:8900');
    await route.fulfill({ status: 200, contentType: 'application/json',
      headers: { 'Access-Control-Allow-Origin': 'http://127.0.0.1:8900', 'Cache-Control': 'no-store' },
      body: JSON.stringify({ grant }) });
  });
  await page.route('**/api/v1/session/ssh-grant', async (route) => {
    expect(route.request().method()).toBe('POST');
    expect(route.request().postDataJSON()).toEqual({ grant });
    await route.fulfill({ status: 200, contentType: 'application/json',
      headers: { 'Cache-Control': 'no-store' }, body: JSON.stringify(session) });
  });
  await page.goto('/#sg-bootstrap=49310');
  await expect(page.locator('#appView')).toBeVisible();
  await expect(page.locator('#sessionIdentity')).toContainText('owner');
  expect(new URL(page.url()).hash).toBe('');
  expect(await page.evaluate(() => localStorage.getItem('sovagrid.hub'))).toBeNull();
  expect(page.url()).not.toContain(grant);
});

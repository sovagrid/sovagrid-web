/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const { test, expect } = require('@playwright/test');

async function login(page, username) {
  await page.locator('#hubLoginMode').click();
  await expect(page.locator('#hubLoginMode')).toHaveAttribute('aria-selected', 'true');
  await page.locator('#hubUrl').fill('http://127.0.0.1:8900');
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(`fixture-${username}-passphrase`);
  await page.locator('#loginButton').click();
  await expect(page.locator('#appView')).toBeVisible();
}

test('install guidance is accessible before login and for every role in both phone themes', async ({ page }, info) => {
  await page.goto('/');
  const entry = page.locator('#loginView [data-install-open]');
  await entry.click(); await expect(page.locator('#installDialog')).toBeVisible();
  await expect(page.locator('#installOrigin')).toHaveText('http://127.0.0.1:8900/sovagrid/monitoring/');
  await expect(page.locator('#installConnection')).toContainText('само SSH-соединение не создаёт');
  if (info.project.name === 'webkit-phone') {
    await expect(page.locator('#installGuideTitle')).toContainText('iPhone или iPad');
    await expect(page.locator('#installSteps')).toContainText('На экран Домой');
    await expect(page.locator('#installSteps')).toContainText('Открыть как веб-приложение');
    await expect(page.locator('#installConfirm')).toBeHidden();
  }
  await page.keyboard.press('Escape'); await expect(page.locator('#installDialog')).toBeHidden();
  await expect(entry).toBeFocused();
  for (const username of ['owner', 'operator', 'reader']) {
    await login(page, username);
    await page.locator('#appView [data-install-open]').click();
    await expect(page.locator('#installDialog')).toBeVisible();
    await page.locator('#installDone').click();
    await page.locator('#logoutButton').click();
  }
  for (const theme of ['light', 'dark']) {
    await page.locator('#loginThemeSelect').selectOption(theme);
    await entry.click();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const box = await page.locator('#installDialog').boundingBox();
    expect(box.x).toBeGreaterThanOrEqual(0);
    expect(box.x + box.width).toBeLessThanOrEqual(page.viewportSize().width);
    await page.screenshot({ path: info.outputPath(`installation-${theme}.png`) });
    await page.locator('#installClose').click();
  }
});

test('custom button invokes a captured browser event only on click and waits for completion', async ({ page }, info) => {
  test.skip(info.project.name !== 'chromium-desktop', 'iPhone uses the real manual Safari guidance test');
  await page.goto('/');
  // Browser UI integration only: CI cannot confirm an operating-system install.
  // The deferred browser event is simulated; no native OS prompt is claimed.
  await page.evaluate(() => {
    window.fixtureInstallCalls = 0;
    const event = new Event('beforeinstallprompt', { cancelable: true });
    Object.defineProperties(event, {
      prompt: { value: () => { window.fixtureInstallCalls++; return Promise.resolve({ outcome: 'accepted' }); } },
      userChoice: { value: Promise.resolve({ outcome: 'accepted' }) },
    });
    window.dispatchEvent(event);
  });
  expect(await page.evaluate(() => window.fixtureInstallCalls)).toBe(0);
  await page.locator('#loginView [data-install-open]').click();
  expect(await page.evaluate(() => window.fixtureInstallCalls)).toBe(0);
  await page.locator('#installConfirm').click();
  await expect(page.locator('#installStatus')).toContainText('Браузер принял запрос');
  await expect(page.locator('#installTitle')).not.toContainText('добавлен');
  expect(await page.evaluate(() => window.fixtureInstallCalls)).toBe(1);
  await expect(page.locator('#installConfirm')).toBeHidden();
  await page.evaluate(() => window.dispatchEvent(new Event('appinstalled')));
  await expect(page.locator('#installTitle')).toHaveText('SovaGrid добавлен на устройство');
});

test('configured path opens the same full panel and shows its PWA address', async ({ page }) => {
  await page.goto('/sovagrid/monitoring/');
  await expect(page.locator('#loginView')).toBeVisible();
  await expect(page.locator('#sshLoginMode')).toHaveAttribute('aria-selected', 'true');
  await page.locator('#loginView [data-install-open]').click();
  await expect(page.locator('#installOrigin')).toHaveText('http://127.0.0.1:8900/sovagrid/monitoring/');
  const manifest = await page.evaluate(async () => (await fetch('manifest.webmanifest')).json());
  expect(new URL(manifest.start_url, page.url()).pathname).toBe('/sovagrid/monitoring/');
});

test.describe('PWA launch route after a configurable path', () => {
  test.use({ serviceWorkers: 'allow' });
  test('Chromium parses the custom-path manifest and opens the stable offline shell', async ({ page, context }, info) => {
    test.skip(info.project.name !== 'chromium-desktop', 'manifest inspection uses Chromium DevTools');
    const origin = 'http://localhost:8900';
    await page.goto(origin + '/ops/monitoring/');
    await expect(page.locator('#loginView')).toBeVisible();
    await page.locator('#loginView [data-install-open]').click();
    await expect(page.locator('#installStableLink')).toBeVisible();
    await expect(page.locator('#installStableLink')).toHaveAttribute('href', origin + '/sovagrid/monitoring/');
    const report = await (await context.newCDPSession(page)).send('Page.getAppManifest');
    expect(report.errors).toEqual([]);
    const manifest = JSON.parse(report.data);
    const launch = new URL(manifest.start_url, report.url);
    expect(launch.pathname).toBe('/sovagrid/monitoring/');
    expect(manifest.scope).toBe('/');
    await expect.poll(() => page.evaluate(async () =>
      Boolean((await navigator.serviceWorker.getRegistration('/sovagrid/monitoring/'))?.active))).toBe(true);
    await page.goto(launch.href);
    await expect(page.locator('#loginView')).toBeVisible();
    await expect.poll(() => page.evaluate(() => Boolean(navigator.serviceWorker.controller))).toBe(true);
    expect(await page.evaluate(async () => Boolean(await navigator.serviceWorker.getRegistration('/')))).toBe(false);
    const root = await page.goto(origin + '/');
    expect(root.status()).toBe(404);
    await expect(page.locator('#loginView')).toHaveCount(0);
    await page.goto(launch.href);
    await expect(page.locator('#loginView')).toBeVisible();
    await context.setOffline(true);
    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(page.locator('#loginView')).toBeVisible();
    await context.setOffline(false);
  });
});

test.describe('actual public service worker cache', () => {
  test.use({ serviceWorkers: 'allow' });
  test('manifest, icons and offline shell do not cache authenticated API traffic', async ({ page, request, context }, info) => {
    test.skip(info.project.name !== 'chromium-desktop', 'actual service-worker cache proof runs on Chromium');
    await page.goto('/sovagrid/monitoring/');
    await page.evaluate(() => navigator.serviceWorker.ready);
    await expect.poll(() => page.evaluate(() => Boolean(navigator.serviceWorker.controller))).toBe(true);
    await login(page, 'reader');
    const keys = await page.evaluate(async () => {
      const names = await caches.keys();
      return Promise.all(names.map(async (name) => ({ name, urls: (await (await caches.open(name)).keys()).map((r) => r.url) })));
    });
    expect(keys.length).toBe(1);
    expect(keys[0].urls.length).toBeGreaterThan(10);
    expect(keys[0].urls.every((url) => !new URL(url).pathname.startsWith('/api/'))).toBe(true);
    expect(keys[0].urls.join(' ')).not.toMatch(/fixture-reader|passphrase|token=/);
    const manifest = await (await request.get('/manifest.webmanifest')).json();
    expect(manifest.id).toBe('/');
    expect(manifest.start_url).toBe('/sovagrid/monitoring/');
    expect(manifest.scope).toBe('/');
    for (const icon of manifest.icons)
      expect((await request.get(icon.src)).ok()).toBe(true);
    await expect(page.locator('#appView [data-install-open]')).toBeVisible();
    await context.setOffline(true);
    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(page.locator('#loginView')).toBeVisible();
    await page.locator('#loginView [data-install-open]').click();
    await expect(page.locator('#installDialog')).toBeVisible();
    await context.setOffline(false);
  });
});

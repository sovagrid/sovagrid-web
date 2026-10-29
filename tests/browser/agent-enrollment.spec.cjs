/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const { test, expect } = require('@playwright/test');

const target = 'example.test';
const fingerprint = `SHA256:${'A'.repeat(43)}`;
const hubFingerprint = `SHA256:${'B'.repeat(43)}`;
const requestId = '11111111-2222-4333-8444-555555555555';

test('SSH wizard requires host-key review and a separate install confirmation', async ({ page }) => {
  const actions = [];
  const secret = 'temporary-browser-test-password';
  await page.route('**/api/v1/browser-ssh/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = route.request().postDataJSON();
    actions.push({ path, body });
    let reply;
    if (path.endsWith('/agent/list')) reply = [];
    else if (path.endsWith('/target-host-key')) reply = {
      protocol: 1, scope: 'entered_target', reverify_required: true,
      host: target, port: 22, key_type: 'ssh-ed25519', fingerprint,
    };
    else if (path.endsWith('/target-status')) reply = {
      protocol: 1, scope: 'entered_target', host: target, port: 22,
      host_key_fingerprint: fingerprint, kind: 'missing',
    };
    else if (path.endsWith('/target-install-preview')) reply = {
      protocol: 1, action: 'install_preview', host: target, port: 22,
      host_key_fingerprint: fingerprint, target_kind: 'missing',
      hub_route: 'reachable', preflight_passed: true, writes: false,
    };
    else if (path.endsWith('/agent/prepare')) reply = {
      protocol: 1, request_id: requestId, revision: 1, phase: 'prepared',
      name: 'Example', writes: true, activation_writes: false,
      hub_fingerprint: hubFingerprint, platform: { ubuntu_version: '24.04' },
      source_commits: { 'sovagrid-agent': 'a'.repeat(40) },
    };
    else if (path.endsWith('/agent/apply')) reply = {
      protocol: 1, request_id: requestId, revision: 2, phase: 'active',
    };
    else throw new Error(`Unexpected route ${path}`);
    await route.fulfill({ status: 200, contentType: 'application/json',
      headers: { 'Cache-Control': 'no-store' }, body: JSON.stringify(reply) });
  });

  await page.goto('/');
  await page.locator('#hubLoginMode').click();
  await page.locator('#hubUrl').fill('http://127.0.0.1:8900');
  await page.locator('#username').fill('owner');
  await page.locator('#password').fill('fixture-owner-passphrase');
  await page.locator('#loginButton').click();
  await expect(page.locator('#appView')).toBeVisible();
  await page.locator('#addServerButton').click();
  await page.locator('#serverSetupHost').fill(target);
  await page.locator('#serverSetupInspect').click();
  await expect(page.locator('#serverSetupFingerprint')).toHaveText(fingerprint);
  await expect(page.locator('#serverSetupStatusButton')).toBeDisabled();
  await page.locator('#serverSetupTrust').check();
  await page.locator('#serverSetupUsername').fill('root');
  await page.locator('#serverSetupPassword').fill(secret);
  await page.locator('#serverSetupStatusButton').click();
  await expect(page.locator('#serverSetupInstallPanel')).toBeVisible();
  await expect(page.locator('#serverSetupPassword')).toHaveValue('');
  await page.locator('#serverSetupInstallName').fill('Example');
  await page.locator('#serverSetupHubHost').fill('192.0.2.1');
  await page.locator('#serverSetupPassword').fill(secret);
  await page.locator('#serverSetupPrepareButton').click();
  await expect(page.locator('#serverSetupJobReview')).toBeVisible();
  await expect(page.locator('#serverSetupJobHubFingerprint')).toHaveText(hubFingerprint);
  await expect(page.locator('#serverSetupApplyButton')).toBeDisabled();
  expect(actions.some(({ path }) => path.endsWith('/agent/apply'))).toBe(false);
  await page.locator('#serverSetupApplyConfirm').check();
  await page.locator('#serverSetupApplyButton').click();
  await expect(page.locator('#serverSetupJobStatus')).toContainText('установлен и подключён');

  expect(actions.filter(({ path }) => path.endsWith('/agent/prepare'))).toHaveLength(1);
  expect(actions.filter(({ path }) => path.endsWith('/agent/apply'))).toHaveLength(1);
  const preview = actions.find(({ path }) => path.endsWith('/target-install-preview'));
  expect(preview.body.password).toBe(secret);
  expect(actions.find(({ path }) => path.endsWith('/agent/apply')).body).toEqual({
    request_id: requestId, expected_revision: 1,
  });
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain(secret);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

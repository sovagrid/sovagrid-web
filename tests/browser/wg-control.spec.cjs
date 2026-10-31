/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ../../ATTRIBUTION.md. */
const { test, expect } = require('@playwright/test');

test('entered Ubuntu host reviews plain WireGuard, confirms install, and recovers explicitly', async ({ page }) => {
  const fingerprint = `SHA256:${'A'.repeat(43)}`;
  const host = 'wg.example', port = 2202, secret = 'disposable-wg-ssh-password';
  const scope = { protocol: 1, scope: 'entered_target', host, port,
    host_key_fingerprint: fingerprint };
  const expected = { state_revision: 'a'.repeat(64), source_revision: 'b'.repeat(64) };
  const full = { ...scope, schema_version: 1, action: 'preview', writes: false,
    ...expected, installed_current: false, socket_active: false, service_active: false,
    socket_enabled: false, pending_recovery: false, inventory_timer_active: false,
    inventory_timer_enabled: false, inventory_snapshot_present: false,
    missing_dependencies: ['wg'], apparmor_profile_present: false,
    can_apply: true, requires_service_restart: false };
  const requests = [];
  let recovery = false;
  await page.route('**/api/v1/browser-ssh/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = route.request().postDataJSON();
    let reply;
    if (path.endsWith('/agent/list')) reply = [];
    else if (path.endsWith('/target-host-key')) reply = { ...scope,
      key_type: 'ssh-ed25519', fingerprint, reverify_required: true };
    else if (path.endsWith('/target-status')) reply = { ...scope, kind: 'agent_only' };
    else if (path.endsWith('/wg-control/preview')) reply = recovery ? { ...scope,
      schema_version: 1, action: 'preview', writes: false, can_apply: false,
      pending_recovery: true, reason: 'RECOVERY_REQUIRED' } : full;
    else if (path.endsWith('/wg-control/apply')) {
      recovery = true;
      reply = { ...scope, action: 'installed', socket_active: true, service_active: true,
        vpn_interface_changed: false, inventory_timer_active: true,
        inventory_snapshot_present: true, source_revision: expected.source_revision };
    } else if (path.endsWith('/wg-control/recover')) reply = { ...scope,
      action: 'recovered', changed: true };
    else throw new Error(`Unexpected gateway route: ${path}`);
    requests.push({ path, body });
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
  await page.locator('[data-view="vpn"]').click();
  await page.locator('#amneziaSetupScopeRemote').check();
  await expect(page.locator('#wgControlPanel')).toBeVisible();
  await expect(page.locator('#wgControlPanel')).toContainText('Обычный WireGuard');
  await page.locator('#amneziaSetupRemoteHost').fill(host);
  await page.locator('#amneziaSetupRemotePort').fill(String(port));
  await page.locator('#amneziaSetupInspect').click();
  await expect(page.locator('#amneziaSetupFingerprint')).toHaveText(fingerprint);
  await page.locator('#amneziaSetupTrust').check();
  await page.locator('#amneziaSetupUsername').fill('root');
  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#wgControlPreview').click();
  await expect(page.locator('#wgControlApply')).toBeVisible();
  await expect(page.locator('#amneziaSetupPassword')).toHaveValue('');
  await expect(page.locator('#wgControlDetails')).toContainText('Недостающие пакеты: wg');

  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#wgControlApply').click();
  await expect(page.locator('#wgControlDialog')).toBeVisible();
  expect(requests.filter(({ path }) => path.endsWith('/wg-control/apply'))).toHaveLength(0);
  await expect(page.locator('#wgControlDialogSummary')).toContainText('VPN-интерфейс');
  await page.locator('#wgControlDialogConfirm').click();
  await expect(page.locator('#wgControlNotice')).toContainText('VPN-интерфейс не включён');
  await expect(page.locator('#amneziaSetupPassword')).toHaveValue('');
  const applied = requests.find(({ path }) => path.endsWith('/wg-control/apply'));
  expect(applied.body.expected).toEqual(expected);
  expect(applied.body.confirm).toBe(true);

  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#wgControlPreview').click();
  await expect(page.locator('#wgControlRecover')).toBeVisible();
  await expect(page.locator('#wgControlApply')).toBeHidden();
  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#wgControlRecover').click();
  await expect(page.locator('#wgControlDialog')).toBeVisible();
  expect(requests.filter(({ path }) => path.endsWith('/wg-control/recover'))).toHaveLength(0);
  await page.locator('#wgControlDialogConfirm').click();
  await expect(page.locator('#wgControlNotice')).toContainText('Восстановление завершено');
  const recovered = requests.find(({ path }) => path.endsWith('/wg-control/recover'));
  expect(recovered.body.confirm).toBe(true);
  expect(recovered.body.expected).toBeUndefined();
  expect(await page.evaluate(() => JSON.stringify({ local: { ...localStorage },
    session: { ...sessionStorage } }))).not.toContain(secret);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

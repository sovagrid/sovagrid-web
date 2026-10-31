/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ../../ATTRIBUTION.md. */
const { createHash } = require('node:crypto');
const { test, expect } = require('@playwright/test');

function hostKey(seed) {
  const type = Buffer.from('ssh-ed25519');
  const blob = Buffer.concat([Buffer.from([0, 0, 0, type.length]), type,
    Buffer.from([0, 0, 0, 32]), Buffer.alloc(32, seed)]);
  return { host_key_blob: blob.toString('base64'),
    fingerprint: `SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}` };
}

test('VPN ProxyJump reviews two keys, confirms WireGuard and rejects a changed route', async ({ page }) => {
  const jump = { host: 'relay.example', port: 2201, ...hostKey(1) };
  const target = { host: '127.0.0.1', port: 2222, ...hostKey(2) };
  const jumpSecret = 'disposable-relay-passphrase';
  const targetSecret = 'disposable-target-passphrase';
  const scope = { protocol: 1, scope: 'entered_target', host: target.host, port: target.port,
    host_key_fingerprint: target.fingerprint,
    jump_host: jump.host, jump_port: jump.port,
    jump_host_key_fingerprint: jump.fingerprint };
  const expected = { state_revision: 'a'.repeat(64), source_revision: 'b'.repeat(64) };
  const requests = [];
  await page.route('**/api/v1/browser-ssh/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = route.request().postDataJSON();
    const { password, private_key: _privateKey, passphrase: _passphrase,
      jump: rawJump, ...publicBody } = body;
    const { password: jumpPassword, private_key: _jumpPrivateKey,
      passphrase: _jumpPassphrase, ...publicJump } = rawJump ?? {};
    requests.push({ path, body: rawJump ? { ...publicBody, jump: publicJump } : publicBody,
      passwordMatched: password === targetSecret,
      jumpPasswordMatched: jumpPassword === jumpSecret });
    let reply;
    if (path.endsWith('/agent/list')) reply = [];
    else if (path.endsWith('/target-host-key') && !body.jump) reply = {
      protocol: 1, scope: 'entered_target', host: jump.host, port: jump.port,
      key_type: 'ssh-ed25519', ...hostKey(1), reverify_required: true };
    else if (path.endsWith('/target-host-key')) reply = {
      protocol: 1, scope: 'entered_target', host: target.host, port: target.port,
      key_type: 'ssh-ed25519', ...hostKey(2),
      jump_host: jump.host, jump_port: jump.port,
      jump_host_key_fingerprint: jump.fingerprint, reverify_required: true };
    else if (path.endsWith('/target-status')) reply = { ...scope, kind: 'agent_only' };
    else if (path.endsWith('/wg-control/preview')) reply = { ...scope,
      schema_version: 1, action: 'preview', writes: false, ...expected,
      installed_current: false, socket_active: false, service_active: false,
      socket_enabled: false, pending_recovery: false, inventory_timer_active: false,
      inventory_timer_enabled: false, inventory_snapshot_present: false,
      missing_dependencies: ['wg'], apparmor_profile_present: false,
      can_apply: true, requires_service_restart: false };
    else if (path.endsWith('/wg-control/apply')) reply = { ...scope,
      action: 'installed', socket_active: true, service_active: true,
      vpn_interface_changed: false, inventory_timer_active: true,
      inventory_snapshot_present: true, source_revision: expected.source_revision };
    else throw new Error(`Unexpected gateway route: ${path}`);
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
  await page.locator('#vpnJumpPanel summary').click();

  await page.locator('#vpnJumpHost').fill(jump.host);
  await page.locator('#vpnJumpPort').fill(String(jump.port));
  await page.locator('#vpnJumpUser').fill('relay');
  await page.locator('#vpnJumpTargetHost').fill(target.host);
  await page.locator('#vpnJumpTargetPort').fill(String(target.port));
  await page.locator('#vpnJumpTargetUser').fill('root');
  await expect(page.locator('#vpnJumpInspectTarget')).toBeDisabled();
  await page.locator('#vpnJumpInspect').click();
  await expect(page.locator('#vpnJumpFingerprint')).toHaveText(jump.fingerprint);
  await page.locator('#vpnJumpTrust').check();
  await page.locator('#vpnJumpPassword').fill(jumpSecret);
  await page.locator('#vpnJumpInspectTarget').click();
  await expect(page.locator('#vpnJumpTargetFingerprint')).toHaveText(target.fingerprint);
  await page.locator('#vpnJumpTargetTrust').check();
  await page.locator('#vpnJumpPassword').fill(jumpSecret);
  await page.locator('#vpnJumpTargetPassword').fill(targetSecret);
  await page.locator('#vpnJumpStatus').click();
  await expect(page.locator('#vpnJumpResult')).toContainText('Agent отвечает');
  await expect(page.locator('#vpnJumpPassword')).toHaveValue('');
  await expect(page.locator('#vpnJumpTargetPassword')).toHaveValue('');

  await page.locator('#amneziaSetupScopeRemote').check();
  await page.locator('#amneziaSetupRemoteHost').fill(target.host);
  await page.locator('#amneziaSetupRemotePort').fill(String(target.port));
  await page.locator('#amneziaSetupViaJump').check();
  await page.locator('#amneziaSetupInspect').click();
  await expect(page.locator('#amneziaSetupFingerprint')).toHaveText(target.fingerprint);
  await page.locator('#amneziaSetupTrust').check();
  await page.locator('#amneziaSetupUsername').fill('root');
  await page.locator('#amneziaSetupPassword').fill(targetSecret);
  await page.locator('#vpnJumpPassword').fill(jumpSecret);
  await page.locator('#wgControlPreview').click();
  await expect(page.locator('#wgControlApply')).toBeVisible();
  await expect(page.locator('#amneziaSetupPassword')).toHaveValue('');
  await expect(page.locator('#vpnJumpPassword')).toHaveValue('');
  const preview = requests.find(({ path }) => path.endsWith('/wg-control/preview'));
  expect(preview).toBeTruthy();
  expect(preview.body).toMatchObject({ host: target.host, port: target.port,
    fingerprint: target.fingerprint, host_key_blob: target.host_key_blob,
    jump: { host: jump.host, port: jump.port, fingerprint: jump.fingerprint,
      host_key_blob: jump.host_key_blob } });
  expect(preview.passwordMatched).toBe(true);
  expect(preview.jumpPasswordMatched).toBe(true);

  await page.locator('#amneziaSetupPassword').fill(targetSecret);
  await page.locator('#vpnJumpPassword').fill(jumpSecret);
  await page.locator('#wgControlApply').click();
  await expect(page.locator('#wgControlDialog')).toBeVisible();
  expect(requests.filter(({ path }) => path.endsWith('/wg-control/apply'))).toHaveLength(0);
  await page.locator('#wgControlDialogConfirm').click();
  await expect(page.locator('#wgControlNotice')).toContainText('VPN-интерфейс не включён');
  const applied = requests.find(({ path }) => path.endsWith('/wg-control/apply'));
  expect(applied.body.expected).toEqual(expected);
  expect(applied.body.confirm).toBe(true);
  expect(applied.body.jump.host_key_blob).toBe(jump.host_key_blob);
  expect(applied.body.host_key_blob).toBe(target.host_key_blob);
  expect(applied.passwordMatched).toBe(true);
  expect(applied.jumpPasswordMatched).toBe(true);

  await page.locator('#amneziaSetupPassword').fill(targetSecret);
  await page.locator('#vpnJumpPassword').fill(jumpSecret);
  await page.locator('#wgControlPreview').click();
  await expect(page.locator('#wgControlApply')).toBeVisible();
  const writesBeforeChange = requests.filter(({ path }) => path.endsWith('/wg-control/apply')).length;
  await page.locator('#vpnJumpHost').fill('different-relay.example');
  await page.locator('#vpnJumpHost').press('Tab');
  await expect(page.locator('#wgControlApply')).toBeHidden();
  await expect(page.locator('#wgControlPreview')).toBeDisabled();
  expect(requests.filter(({ path }) => path.endsWith('/wg-control/apply')).length)
    .toBe(writesBeforeChange);
  expect(await page.evaluate(() => JSON.stringify({ local: { ...localStorage },
    session: { ...sessionStorage } }))).not.toContain(jumpSecret);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

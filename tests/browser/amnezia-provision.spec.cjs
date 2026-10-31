/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ../../ATTRIBUTION.md. */
const { test, expect } = require('@playwright/test');

test('entered Ubuntu host prepares source and explicitly creates AmneziaWG 3.1', async ({ page }) => {
  const host = 'awg.example', port = 2202, fingerprint = `SHA256:${'A'.repeat(43)}`;
  const secret = 'disposable-provision-ssh-password';
  const scope = { scope: 'entered_target', host, port, host_key_fingerprint: fingerprint };
  const hashes = { source_manifest_sha256: 'a'.repeat(64), candidate_sha256: 'b'.repeat(64),
    installed_sha256: '0'.repeat(64), state_sha256: '0'.repeat(64) };
  const config = { listen_port: 51820, subnet: '10.44.0.0/24', route_mode: 'full' };
  const revision = 'c'.repeat(64);
  let sourceReady = false, provisioned = false;
  const requests = [];
  await page.route('**/api/v1/browser-ssh/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = route.request().postDataJSON();
    let reply;
    if (path.endsWith('/agent/list')) reply = [];
    else if (path.endsWith('/target-host-key')) reply = { protocol: 1, ...scope,
      key_type: 'ssh-ed25519', fingerprint, reverify_required: true };
    else if (path.endsWith('/target-status')) reply = { protocol: 1, ...scope, kind: 'agent_only' };
    else if (path.endsWith('/vpn-source/preview')) reply = { protocol: 1, ...scope,
      ...hashes, expected: hashes, change: sourceReady ? 'current' : 'install',
      temporary_writes: true, activation_writes: false, cleanup_required: false };
    else if (path.endsWith('/vpn-source/apply')) {
      sourceReady = true;
      reply = { protocol: 1, ...scope, installed: true, changed: true,
        cleanup_required: false, source_manifest_sha256: hashes.source_manifest_sha256,
        candidate_sha256: hashes.candidate_sha256 };
    } else if (path.endsWith('/amnezia-provision/preview')) reply = { protocol: 1, ...scope,
      schema_version: 1, action: 'preview', writes: false, target: 'awg2',
      container: 'amnezia-awg2', ...config, image_digest: `sha256:${'d'.repeat(64)}`,
      image_cached: false, state_revision: revision, can_apply: !provisioned,
      ...(provisioned ? { reason: 'ALREADY_INSTALLED' } : {}) };
    else if (path.endsWith('/amnezia-provision/apply')) {
      provisioned = true;
      reply = { protocol: 1, ...scope, schema_version: 1, action: 'installed',
        target: 'awg2', container: 'amnezia-awg2', container_id: 'e'.repeat(64),
        image_id: `sha256:${'f'.repeat(64)}`, ...config, recovery_required: false };
    } else if (path.endsWith('/vpn-setup/preview')) reply = { protocol: 1, ...scope,
      target: 'awg2', enrolled: false, marker: 'absent', other_marker: 'absent',
      socket_active: false, service_active: false, installer_ready: true,
      installed_current: false, can_arm: false, reason: 'NOT_ENROLLED' };
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
  await expect(page.locator('#amneziaProvisionPanel')).toBeVisible();
  await expect(page.locator('#amneziaProvisionPanel')).toContainText('AmneziaWG 3.1');
  await page.locator('#amneziaSetupRemoteHost').fill(host);
  await page.locator('#amneziaSetupRemotePort').fill(String(port));
  await page.locator('#amneziaSetupInspect').click();
  await expect(page.locator('#amneziaSetupFingerprint')).toHaveText(fingerprint);
  await page.locator('#amneziaSetupTrust').check();
  await page.locator('#amneziaSetupUsername').fill('root');
  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaSourcePreview').click();
  await expect(page.locator('#amneziaSourceApply')).toBeVisible();
  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaSourceApply').click();
  await page.locator('#amneziaSetupDialogConfirm').click();
  await expect(page.locator('#amneziaSourceNotice')).toContainText('VPN-код подготовлен');

  await expect(page.locator('#amneziaProvisionRoute')).toHaveValue('full');
  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaProvisionPreview').click();
  await expect(page.locator('#amneziaProvisionApply')).toBeVisible();
  await expect(page.locator('#amneziaProvisionSummary')).toContainText('IPv4 через VPN');
  await expect(page.locator('#amneziaSetupPassword')).toHaveValue('');
  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaProvisionApply').click();
  await expect(page.locator('#amneziaProvisionDialog')).toBeVisible();
  await expect(page.locator('#amneziaProvisionDialogSummary')).toContainText('включён awg0');
  expect(requests.filter(({ path }) => path.endsWith('/amnezia-provision/apply'))).toHaveLength(0);
  await page.locator('#amneziaProvisionDialogConfirm').click();
  await expect(page.locator('#amneziaProvisionNotice')).toContainText('Docker опубликовал UDP 51820');
  await expect(page.locator('#amneziaProvisionNotice')).toContainText('сетевой экран провайдера');
  await expect(page.locator('#amneziaSetupEnrollPreview')).toBeHidden();
  expect(requests.filter(({ path }) => path.includes('/vpn-setup/'))).toHaveLength(0);
  const applied = requests.find(({ path }) => path.endsWith('/amnezia-provision/apply'));
  expect(applied.body).toMatchObject({ host, port, fingerprint, ...config,
    expected_state: revision, confirm: true });
  expect(applied.body.password).toBe(secret);
  await expect(page.locator('#amneziaSetupPassword')).toHaveValue('');
  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaSetupSubmit').click();
  await expect(page.locator('#amneziaSetupEnrollPreview')).toBeVisible();
  await expect(page.locator('#amneziaSetupInstall')).toBeHidden();
  expect(await page.evaluate(() => JSON.stringify({ local: { ...localStorage },
    session: { ...sessionStorage } }))).not.toContain(secret);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

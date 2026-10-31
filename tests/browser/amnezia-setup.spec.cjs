/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const { test, expect } = require('@playwright/test');

const fingerprint = `SHA256:${'A'.repeat(43)}`;
const containerId = 'a'.repeat(64);
const secret = 'disposable-amnezia-ssh-password';
const missing = { protocol: 1, target: 'awg2', enrolled: false, marker: 'absent',
  other_marker: 'absent', socket_active: false, service_active: false,
  installer_ready: true, installed_current: false, can_arm: false,
  reason: 'NOT_ENROLLED' };
const enrolled = { protocol: 1, target: 'awg2', enrolled: true, marker: 'absent',
  other_marker: 'absent', socket_active: false, service_active: false,
  installer_ready: true, installed_current: false, can_arm: false,
  container_id: containerId, configured_clients: 2, owned_clients: 0 };
const installed = { ...enrolled, installed_current: true, can_arm: true };
const armed = { ...installed, marker: 'valid', socket_active: true, can_arm: false };
const enrollment = { protocol: 1, action: 'enroll_preview', writes: false,
  target: 'awg2', container_id: containerId, image_id: `sha256:${'b'.repeat(64)}`,
  config_sha256: 'c'.repeat(64), table_sha256: 'd'.repeat(64),
  configured_clients: 2, vpn_protocol: 'amneziawg', interface: 'awg0',
  listen_port: 51820, server_subnet: '10.0.0.0/24',
  host_key_fingerprint: fingerprint, reverify_required: true };

test('Amnezia setup reviews and confirms each stage without storing SSH credentials', async ({ page }) => {
  const requests = [];
  let setup = missing;
  await page.route('**/api/v1/browser-ssh/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = route.request().postDataJSON();
    let reply;
    if (path.endsWith('/agent/list')) reply = [];
    else if (path.endsWith('/host-key')) reply = { protocol: 1, port: 22,
      key_type: 'ssh-ed25519', fingerprint };
    else if (path.endsWith('/vpn-setup/preview')) reply = setup;
    else if (path.endsWith('/vpn-setup/enroll-preview')) reply = enrollment;
    else if (path.endsWith('/vpn-setup/enroll')) {
      setup = enrolled;
      reply = { protocol: 1, action: 'enrolled', target: 'awg2',
        enrolled: true, container_id: containerId, configured_clients: 2,
        setup };
    } else if (path.endsWith('/vpn-setup/install')) {
      setup = installed;
      reply = { protocol: 1, action: 'installed', target: 'awg2', setup };
    } else if (path.endsWith('/vpn-setup/arm')) {
      setup = armed;
      reply = { protocol: 1, action: 'armed', target: 'awg2', setup };
    } else throw new Error(`Unexpected gateway route: ${path}`);
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
  await expect(page.locator('#amneziaSetupPanel')).toBeVisible();

  await page.locator('#amneziaSetupInspect').click();
  await expect(page.locator('#amneziaSetupFingerprint')).toHaveText(fingerprint);
  await expect(page.locator('#amneziaSetupSubmit')).toBeDisabled();
  await page.locator('#amneziaSetupTrust').check();
  await page.locator('#amneziaSetupUsername').fill('root');
  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaSetupSubmit').click();
  await expect(page.locator('#amneziaSetupEnrollPreview')).toBeVisible();
  await expect(page.locator('#amneziaSetupPassword')).toHaveValue('');

  // Every subsequent step requires a new SSH secret. A blank form cannot
  // request even the read-only enrollment snapshot.
  await page.locator('#amneziaSetupEnrollPreview').click();
  await expect(page.locator('#amneziaSetupError')).toBeVisible();
  expect(requests.filter(({ path }) => path.endsWith('/enroll-preview'))).toHaveLength(0);
  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaSetupEnrollPreview').click();
  await expect(page.locator('#amneziaSetupEnrollment')).toBeVisible();
  await expect(page.locator('#amneziaSetupEnrollmentSummary')).toContainText('UDP 51820');
  await expect(page.locator('#amneziaSetupPassword')).toHaveValue('');

  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaSetupEnroll').click();
  await expect(page.locator('#amneziaSetupDialog')).toBeVisible();
  await page.locator('#amneziaSetupDialogCancel').click();
  expect(requests.filter(({ path }) => path.endsWith('/vpn-setup/enroll'))).toHaveLength(0);
  await page.locator('#amneziaSetupEnroll').click();
  await page.locator('#amneziaSetupDialogConfirm').click();
  await expect(page.locator('#amneziaSetupInstall')).toBeVisible();
  await expect(page.locator('#amneziaSetupPassword')).toHaveValue('');

  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaSetupInstall').click();
  await expect(page.locator('#amneziaSetupDialog')).toBeVisible();
  await page.locator('#amneziaSetupDialogConfirm').click();
  await expect(page.locator('#amneziaSetupArm')).toBeVisible();
  await expect(page.locator('#amneziaSetupPassword')).toHaveValue('');

  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaSetupArm').click();
  await expect(page.locator('#amneziaSetupDialog')).toBeVisible();
  await expect(page.locator('#amneziaSetupMaintenance')).not.toBeChecked();
  await page.locator('#amneziaSetupDialogConfirm').click();
  await expect(page.locator('#amneziaSetupDialog')).toBeVisible();
  expect(requests.filter(({ path }) => path.endsWith('/vpn-setup/arm'))).toHaveLength(0);
  await page.locator('#amneziaSetupMaintenance').check();
  await page.locator('#amneziaSetupDialogConfirm').click();
  await expect(page.locator('#amneziaSetupDetails')).toContainText('Сокет: работает');
  await expect(page.locator('#amneziaSetupPassword')).toHaveValue('');

  const steps = requests.filter(({ path }) => path.includes('/vpn-setup/'));
  expect(steps.map(({ path }) => path.split('/').at(-1))).toEqual([
    'preview', 'enroll-preview', 'enroll', 'install', 'arm',
  ]);
  for (const { body } of steps) {
    expect(body.password).toBe(secret);
    expect(body.fingerprint).toBe(fingerprint);
    expect(body.target).toBe('awg2');
  }
  expect(steps[2].body.reviewed).toEqual(enrollment);
  expect(steps[2].body.confirm).toBe('ENROLL_EXISTING_CONTAINER');
  expect(steps[3].body.reviewed).toEqual(enrolled);
  expect(steps[3].body.confirm).toBe('INSTALL_AMNEZIA_BROKER');
  expect(steps[4].body.reviewed).toEqual(installed);
  expect(steps[4].body.confirm).toBe('I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG2');
  expect(await page.evaluate(() => JSON.stringify({ local: { ...localStorage },
    session: { ...sessionStorage } }))).not.toContain(secret);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('Amnezia setup on an entered Ubuntu host pins its own key and binds every stage', async ({ page }) => {
  const requests = [];
  const host = 'vpn.example', port = 2202;
  const scope = { scope: 'entered_target', host, port, host_key_fingerprint: fingerprint };
  let setup = { ...missing, ...scope };
  await page.route('**/api/v1/browser-ssh/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = route.request().postDataJSON();
    let reply;
    if (path.endsWith('/agent/list')) reply = [];
    else if (path.endsWith('/target-host-key')) reply = { protocol: 1, scope: 'entered_target',
      host, port, key_type: 'ssh-ed25519', fingerprint, reverify_required: true };
    else if (path.endsWith('/target-status')) reply = { protocol: 1, ...scope, kind: 'managed' };
    else if (path.endsWith('/vpn-setup/preview')) reply = setup;
    else if (path.endsWith('/vpn-setup/enroll-preview')) reply = { ...enrollment, ...scope };
    else if (path.endsWith('/vpn-setup/enroll')) {
      setup = { ...enrolled, ...scope };
      reply = { protocol: 1, action: 'enrolled', target: 'awg2', enrolled: true,
        container_id: containerId, configured_clients: 2, setup, ...scope };
    } else if (path.endsWith('/vpn-setup/install')) {
      setup = { ...installed, ...scope };
      reply = { protocol: 1, action: 'installed', target: 'awg2', setup, ...scope };
    } else if (path.endsWith('/vpn-setup/arm')) {
      setup = { ...armed, ...scope };
      reply = { protocol: 1, action: 'armed', target: 'awg2', setup, ...scope };
    } else throw new Error(`Unexpected gateway route: ${path}`);
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
  await expect(page.locator('#amneziaSetupPanel')).toBeVisible();
  await page.locator('#amneziaSetupScopeRemote').check();
  await expect(page.locator('#amneziaSetupRemoteFields')).toBeVisible();
  await page.locator('#amneziaSetupRemoteHost').fill('VPN.Example');
  await page.locator('#amneziaSetupRemotePort').fill(String(port));
  await page.locator('#amneziaSetupInspect').click();
  await expect(page.locator('#amneziaSetupKeyHost')).toHaveText(host);
  await expect(page.locator('#amneziaSetupFingerprint')).toHaveText(fingerprint);
  await page.locator('#amneziaSetupTrust').check();
  await page.locator('#amneziaSetupUsername').fill('root');
  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaSetupSubmit').click();
  await expect(page.locator('#amneziaSetupEnrollPreview')).toBeVisible();

  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaSetupEnrollPreview').click();
  await expect(page.locator('#amneziaSetupEnrollment')).toBeVisible();
  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaSetupEnroll').click();
  await page.locator('#amneziaSetupDialogConfirm').click();
  await expect(page.locator('#amneziaSetupInstall')).toBeVisible();
  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaSetupInstall').click();
  await page.locator('#amneziaSetupDialogConfirm').click();
  await expect(page.locator('#amneziaSetupArm')).toBeVisible();
  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaSetupArm').click();
  await page.locator('#amneziaSetupMaintenance').check();
  await page.locator('#amneziaSetupDialogConfirm').click();
  await expect(page.locator('#amneziaSetupDetails')).toContainText('Сокет: работает');

  expect(requests.map(({ path }) => path.split('/').at(-1))).toEqual([
    'target-host-key', 'target-status', 'preview', 'enroll-preview', 'enroll', 'install', 'arm',
  ]);
  expect(requests[0].body).toEqual({ host, port });
  for (const { body } of requests.slice(1)) {
    expect(body.host).toBe(host);
    expect(body.port).toBe(port);
    expect(body.fingerprint).toBe(fingerprint);
    expect(body.password).toBe(secret);
  }
  expect(requests[4].body.reviewed).toEqual({ ...enrollment, ...scope });
  expect(requests[5].body.reviewed).toEqual({ ...enrolled, ...scope });
  expect(requests[6].body.reviewed).toEqual({ ...installed, ...scope });
  expect(await page.evaluate(({ host, port }) => localStorage.getItem(
    `sovagrid.target-ssh-host-key:${location.origin}:${host}:${port}`), { host, port })).toBe(fingerprint);
  expect(await page.evaluate(() => JSON.stringify({ local: { ...localStorage },
    session: { ...sessionStorage } }))).not.toContain(secret);
  await page.locator('#amneziaSetupRemoteHost').fill('other.example');
  await expect(page.locator('#amneziaSetupHostKeyReview')).toBeHidden();
  await expect(page.locator('#amneziaSetupResult')).toBeHidden();
  await expect(page.locator('#amneziaSetupSubmit')).toBeDisabled();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('entered Ubuntu host prepares VPN code before Amnezia setup on desktop and phone', async ({ page }) => {
  const host = 'vpn.example', port = 2202;
  const scope = { scope: 'entered_target', host, port, host_key_fingerprint: fingerprint };
  const hashes = { source_manifest_sha256: 'a'.repeat(64), candidate_sha256: 'b'.repeat(64),
    installed_sha256: '0'.repeat(64), state_sha256: '0'.repeat(64) };
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
      ...hashes, expected: hashes, change: 'install', temporary_writes: true,
      activation_writes: false, cleanup_required: false };
    else if (path.endsWith('/vpn-source/apply')) reply = { protocol: 1, ...scope,
      installed: true, changed: true, cleanup_required: false,
      source_manifest_sha256: hashes.source_manifest_sha256,
      candidate_sha256: hashes.candidate_sha256 };
    else if (path.endsWith('/vpn-setup/preview')) reply = { ...missing, ...scope };
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
  await page.locator('#amneziaSetupRemoteHost').fill(host);
  await page.locator('#amneziaSetupRemotePort').fill(String(port));
  await page.locator('#amneziaSetupInspect').click();
  await page.locator('#amneziaSetupTrust').check();
  await page.locator('#amneziaSetupUsername').fill('root');
  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaSourcePreview').click();
  await expect(page.locator('#amneziaSourceReview')).toBeVisible();
  await expect(page.locator('#amneziaSourceApply')).toBeVisible();
  await expect(page.locator('#amneziaSetupPassword')).toHaveValue('');
  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaSourceApply').click();
  await expect(page.locator('#amneziaSetupDialog')).toBeVisible();
  await page.locator('#amneziaSetupDialogCancel').click();
  expect(requests.filter(({ path }) => path.endsWith('/vpn-source/apply'))).toHaveLength(0);
  await page.locator('#amneziaSourceApply').click();
  await page.locator('#amneziaSetupDialogConfirm').click();
  await expect(page.locator('#amneziaSourceNotice')).toContainText('VPN-код подготовлен');
  await expect(page.locator('#amneziaSetupPassword')).toHaveValue('');
  await page.locator('#amneziaSetupPassword').fill(secret);
  await page.locator('#amneziaSetupSubmit').click();
  await expect(page.locator('#amneziaSetupResult')).toBeVisible();
  expect(requests.filter(({ path }) => path.includes('/vpn-source/')).map(({ path }) => path.split('/').at(-1)))
    .toEqual(['preview', 'apply']);
  expect(requests.find(({ path }) => path.endsWith('/vpn-source/apply')).body.expected).toEqual(hashes);
  expect(await page.evaluate(() => JSON.stringify({ local: { ...localStorage },
    session: { ...sessionStorage } }))).not.toContain(secret);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

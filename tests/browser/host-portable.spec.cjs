/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ../../ATTRIBUTION.md. */
const { test, expect } = require('@playwright/test');
const crypto = require('node:crypto');
const fs = require('node:fs');

const id = 'b'.repeat(32);
const prefix = '/api/v1/host-backups';
const archiveId = 'a'.repeat(32);
const sha = (letter) => letter.repeat(64);
const date = '2026-10-31T12:00:00+00:00';
const archive = { id: archiveId, created_at: date, layout: 'full', bytes: 4096, files: 8 };
const operation = { ok: true, protocol: 'sovagrid-host-backup-operation-v1',
  request_id: id, phase: 'complete', archive, error: null, created_at: date };
const receipt = { protocol: 'sovagrid-portable-host-receipt-v1', host_archive_id: archiveId,
  host_archive_sha256: sha('d'), source_manifest_sha256: sha('c'),
  images_sha256: sha('e'), images: { hub: 'sha256:' + sha('1'),
    web: 'sha256:' + sha('2') },
  container_ids: { hub: sha('3'), web: sha('4') },
  exported_configs: { hub: 'sha256:' + sha('1'), web: 'sha256:' + sha('2') },
  rootfs_sha256: { hub: sha('5'), web: sha('6') }, active_units: [], unit_hashes: {} };

test('phone and desktop download a verified portable image with one-use same-origin cookie', async ({ page }) => {
  let grants = 0;
  const grantToken = crypto.randomBytes(16).toString('hex');
  await page.context().route('**/api/v1/host-backups/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const json = (body) => route.fulfill({ status: 200, contentType: 'application/json',
      headers: { 'Cache-Control': 'no-store' }, body: JSON.stringify(body) });
    if (path === prefix + '/plan') return json({ plan: { layout: 'full',
      active_units: [], running_containers: ['hub', 'web'], offline_ready: false },
    manifest_sha256: sha('c') });
    if (path === prefix + '/archives') return json({ archives: [archive] });
    if (path === prefix + '/operations') return json({ operations: [operation] });
    if (path === prefix + '/portable/capabilities')
      return json({ supported: true, download: true });
    if (path === prefix + '/operations/' + id + '/portable')
      return json({ ...operation, image_receipt: receipt });
    if (path === prefix + '/operations/' + id + '/portable/verify')
      return json({ ok: true, request_id: id, archive, images_bytes: 8192, receipt });
    if (path === prefix + '/operations/' + id + '/portable/download-grants/images') {
      expect(request.method()).toBe('POST');
      expect(request.headers().authorization).toMatch(/^Bearer /);
      grants++;
      return route.fulfill({ status: 200, contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store',
          'Set-Cookie': `sg_portable_smoke=${grantToken}; Path=${prefix}/operations/${id}/portable/download/images; HttpOnly; SameSite=Strict; Max-Age=60` },
        body: JSON.stringify({ request_id: id, part: 'images', expires_in_seconds: 60 }) });
    }
    throw new Error('Unexpected host backup route: ' + path);
  });

  await page.goto('/');
  await page.locator('#hubLoginMode').click();
  await page.locator('#hubUrl').fill('http://127.0.0.1:8900');
  await page.locator('#username').fill('owner');
  await page.locator('#password').fill('fixture-owner-passphrase');
  await page.locator('#loginButton').click();
  await expect(page.locator('#appView')).toBeVisible();
  await page.locator('[data-view="settings"]').click();
  await expect(page.locator('#hostBackupPortableCreate')).toBeEnabled();
  await page.locator('#hostBackupOperations').getByRole('button', { name: 'Проверить переносимую копию' }).click();
  await page.locator('#hostBackupActive').getByRole('button',
    { name: 'Проверить архив и образы' }).click();
  await expect(page.locator('#hostBackupPortableFiles')).toBeVisible();
  const images = page.locator('.host-portable-file').filter({ hasText: 'Образы контейнеров' });
  await images.getByRole('button', { name: 'Подготовить скачивание' }).click();
  await expect(images.getByRole('link', { name: 'Скачать' })).toBeVisible();
  const downloadPromise = page.waitForEvent('download');
  await images.getByRole('link', { name: 'Скачать' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('images.tar');
  expect(download.url()).toBe('http://127.0.0.1:8900' + prefix + '/operations/' + id + '/portable/download/images');
  expect(fs.readFileSync(await download.path(), 'utf8')).toBe('disposable-image-archive');
  expect(grants).toBe(1);
  const replay = await page.context().request.get(download.url());
  expect(replay.status()).toBe(403);
});

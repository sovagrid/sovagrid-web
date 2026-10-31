/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const { randomUUID } = require('node:crypto');

const archiveId = 'a'.repeat(32);
const operationId = 'b'.repeat(32);
const manifest = 'c'.repeat(64);
const timestamp = '2026-10-27T12:00:00+00:00';
const archive = { id: archiveId, created_at: timestamp, layout: 'full',
  bytes: 4096, files: 8 };
const plan = { plan: { layout: 'full', active_units: ['sovagrid-vpn-status.timer'],
  running_containers: ['hub', 'web'], offline_ready: false },
  manifest_sha256: manifest };
const operation = (id = operationId, phase = 'accepted') => ({
  ok: true, protocol: 'sovagrid-host-backup-operation-v1', request_id: id,
  phase, archive: phase === 'complete' ? archive : null,
  error: null, created_at: timestamp,
});
const portableReceipt = { protocol: 'sovagrid-portable-host-receipt-v1',
  host_archive_id: archiveId, host_archive_sha256: 'd'.repeat(64),
  source_manifest_sha256: manifest, images_sha256: 'e'.repeat(64),
  images: { hub: 'sha256:' + '1'.repeat(64), web: 'sha256:' + '2'.repeat(64) },
  container_ids: { hub: '3'.repeat(64), web: '4'.repeat(64) },
  exported_configs: { hub: 'sha256:' + '1'.repeat(64), web: 'sha256:' + '2'.repeat(64) },
  rootfs_sha256: { hub: '5'.repeat(64), web: '6'.repeat(64) },
  active_units: [], unit_hashes: {} };
const portableOperation = (id = operationId, phase = 'complete') => ({
  ...operation(id, phase), image_receipt: phase === 'complete' ? portableReceipt : null,
});
const portableVerification = { ok: true, request_id: operationId,
  archive, images_bytes: 8192, receipt: portableReceipt };
const reply = (status, value) => ({ ok: status < 400, status,
  text: async () => JSON.stringify(value) });

function harness(localStore = new Map()) {
  const elements = new Map(), calls = [];
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { textContent: '', hidden: false, disabled: false, open: false,
        children: [], listeners, className: '', style: {}, attributes: {},
        setAttribute(name, value) { this.attributes[name] = value; },
        addEventListener(type, fn) { listeners.set(type, fn); },
        append(...items) { this.children.push(...items); },
        replaceChildren(...items) { this.children = items; },
        showModal() { this.open = true; },
        close() { this.open = false; listeners.get('close')?.({}); },
      });
    }
    return elements.get(id);
  };
  let fetchHook = () => { throw new Error('unexpected fetch'); };
  const context = vm.createContext({ URL, AbortController, TextEncoder, Uint8Array,
    crypto: { randomUUID }, setTimeout, clearTimeout, setInterval: () => 1,
    clearInterval() {}, Date,
    document: { getElementById: element, createElement: () => element(Symbol()),
      querySelectorAll: () => [], addEventListener() {} },
    navigator: {}, location: { protocol: 'file:' },
    localStorage: { getItem: (key) => localStore.get(key) ?? null,
      setItem: (key, value) => localStore.set(key, value),
      removeItem: (key) => localStore.delete(key) },
    fetch: (url, options) => { calls.push({ url, options }); return fetchHook(url, options); },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('host-backups.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  const client = vm.runInContext('hostBackupClient', context);
  Object.assign(state, { token: 'session-1', base: 'https://hub.example',
    user: { id: 'admin', username: 'admin', role: 'admin', enabled: true },
    access: { mode: 'all', revision: 0, unrestricted_admin: true }, view: 'settings' });
  return { context, state, client, localStore, element, calls,
    setFetchHook: (fn) => { fetchHook = fn; } };
}

function descendants(node) {
  return [node, ...node.children.flatMap(descendants)];
}

function metadata(url) {
  if (url.endsWith('/plan')) return reply(200, plan);
  if (url.endsWith('/archives')) return reply(200, { archives: [archive] });
  if (url.endsWith('/operations')) return reply(200, { operations: [] });
  throw new Error('unexpected metadata route ' + url);
}

test('confirmed host snapshot keeps request ID before the one POST', async () => {
  const h = harness();
  let posts = 0, requestId;
  h.setFetchHook((url, options) => {
    if (options.method === 'POST') {
      posts++;
      const body = JSON.parse(options.body);
      requestId = body.request_id;
      assert.match(requestId, /^[0-9a-f]{32}$/);
      assert.equal(body.expected_manifest_sha256, manifest);
      assert.equal(url, 'https://hub.example/api/v1/host-backups/operations');
      assert.equal(JSON.parse(h.localStore.get('sovagrid.host-backup-request.v1:https://hub.example')).request_id, requestId);
      return Promise.resolve(reply(202, operation(requestId)));
    }
    return Promise.resolve(metadata(url));
  });
  await h.context.hostBackupsRefresh(true);
  assert.equal(h.element('hostBackupCreate').disabled, false);
  assert.equal(h.element('hostBackupPortableCreate').disabled, true);
  await h.context.hostBackupPrepareCreate();
  assert.equal(h.element('hostBackupCreateDialog').open, true);
  assert.equal(posts, 0);
  await h.context.hostBackupConfirmCreate();
  assert.equal(posts, 1);
  assert.equal(h.client.activeId, requestId);
  assert.equal(h.element('hostBackupCreateDialog').open, false);
});

test('lost response keeps the ID through reload and never repeats the POST', async () => {
  const store = new Map();
  const h = harness(store);
  let posts = 0, requestId;
  h.setFetchHook((url, options) => {
    if (options.method === 'POST') {
      posts++;
      requestId = JSON.parse(options.body).request_id;
      return Promise.reject(new TypeError('Hub stopped'));
    }
    if (url.endsWith('/operations/' + requestId))
      return Promise.resolve(reply(200, operation(requestId)));
    return Promise.resolve(metadata(url));
  });
  await h.context.hostBackupsRefresh(true);
  await h.context.hostBackupPrepareCreate();
  await h.context.hostBackupConfirmCreate();
  await new Promise(setImmediate);
  assert.equal(posts, 1);
  assert.equal(h.context.hostBackupCanStart(), false);
  assert.equal(h.context.hostBackupReadMarker(), requestId);
  const next = harness(store);
  next.setFetchHook((url) => {
    if (url.endsWith('/operations/' + requestId))
      return Promise.resolve(reply(200, operation(requestId, 'complete')));
    return Promise.resolve(metadata(url));
  });
  await next.context.hostBackupsRefresh(true);
  assert.equal(next.client.active.phase, 'complete');
  assert.equal(next.context.hostBackupReadMarker(), null);
});

test('selected admin and unavailable browser storage cannot start a host snapshot', async () => {
  const h = harness();
  h.state.access = { mode: 'selected', revision: 1, unrestricted_admin: false };
  await h.context.hostBackupsRefresh(true);
  assert.equal(h.calls.length, 0);
  h.state.access = { mode: 'all', revision: 2, unrestricted_admin: true };
  h.setFetchHook((url, options) => {
    assert.notEqual(options.method, 'POST');
    return Promise.resolve(metadata(url));
  });
  await h.context.hostBackupsRefresh(true);
  await h.context.hostBackupPrepareCreate();
  h.context.localStorage.setItem = () => { throw new Error('storage denied'); };
  await h.context.hostBackupConfirmCreate();
  assert.equal(h.element('hostBackupCreateDialog').open, true);
  assert.match(h.element('hostBackupCreateError').textContent, /не сохранил ID/);
});

test('recovery is confirmed and uses the stored operation ID once', async () => {
  const h = harness();
  let recoveryPosts = 0;
  h.setFetchHook((url, options) => {
    if (url.endsWith('/operations/' + operationId + '/recover')) {
      recoveryPosts++;
      assert.equal(options.body, '{}');
      return Promise.resolve(reply(202, operation(operationId, 'recovery_requested')));
    }
    if (url.endsWith('/operations')) return Promise.resolve(reply(200,
      { operations: [operation(operationId, 'recovery_required')] }));
    if (url.endsWith('/operations/' + operationId)) return Promise.resolve(reply(200,
      operation(operationId, 'recovery_required')));
    return Promise.resolve(metadata(url));
  });
  await h.context.hostBackupsRefresh(true);
  await h.context.hostBackupCheck(operationId);
  h.context.hostBackupPrepareRecover(operationId);
  assert.equal(h.element('hostBackupRecoverDialog').open, true);
  assert.equal(recoveryPosts, 0);
  await h.context.hostBackupConfirmRecover();
  assert.equal(recoveryPosts, 1);
  assert.equal(h.context.hostBackupReadMarker(), operationId);
});

test('portable create stores its mode before POST and resumes by ID after a lost reply', async () => {
  const store = new Map(), h = harness(store);
  let createdId, posts = 0;
  h.setFetchHook((url, options) => {
    if (url.endsWith('/portable/capabilities'))
      return Promise.resolve(reply(200, { supported: true, download: true }));
    if (url.endsWith('/portable/operations') && options.method === 'POST') {
      posts++;
      createdId = JSON.parse(options.body).request_id;
      assert.equal(JSON.parse(store.get('sovagrid.host-backup-request.v1:https://hub.example')).mode,
        'portable');
      return Promise.reject(new TypeError('Hub restarted during the snapshot'));
    }
    if (createdId && url.endsWith('/operations/' + createdId + '/portable'))
      return Promise.reject(new TypeError('Hub still offline'));
    return Promise.resolve(metadata(url));
  });
  await h.context.hostBackupsRefresh(true);
  assert.equal(h.element('hostBackupPortableCreate').disabled, false);
  await h.context.hostBackupPrepareCreate('portable');
  assert.match(h.element('hostBackupCreateSummary').textContent, /образы контейнеров/);
  await h.context.hostBackupConfirmCreate();
  await new Promise(setImmediate);
  assert.equal(posts, 1);
  assert.equal(h.context.hostBackupReadMarkerRecord()?.mode, 'portable');
  const resumed = harness(store);
  resumed.setFetchHook((url) => {
    if (url.endsWith('/portable/capabilities'))
      return Promise.resolve(reply(200, { supported: true, download: true }));
    if (url.endsWith('/operations/' + createdId + '/portable'))
      return Promise.resolve(reply(200, portableOperation(createdId)));
    return Promise.resolve(metadata(url));
  });
  await resumed.context.hostBackupsRefresh(true);
  assert.equal(resumed.client.activeId, createdId);
  assert.equal(resumed.client.activePortable, true);
  assert.equal(resumed.client.portableReceipt.host_archive_id, archiveId);
  assert.equal(resumed.context.hostBackupReadMarker(), null);
});

test('verified portable pair gets one same-origin cookie grant and a native download link', async () => {
  const h = harness();
  h.context.location.origin = 'https://hub.example';
  h.setFetchHook((url, options) => {
    if (url.endsWith('/portable/capabilities'))
      return Promise.resolve(reply(200, { supported: true, download: true }));
    if (url.endsWith('/operations/' + operationId + '/portable/verify'))
      return Promise.resolve(reply(200, portableVerification));
    if (url.endsWith('/operations/' + operationId + '/portable'))
      return Promise.resolve(reply(200, portableOperation()));
    if (url.endsWith('/operations/' + operationId + '/portable/download-grants/images')) {
      assert.equal(options.method, 'POST');
      assert.equal(options.body, '{}');
      assert.equal(options.headers.Authorization, 'Bearer session-1');
      return Promise.resolve(reply(200, { request_id: operationId, part: 'images',
        expires_in_seconds: 60 }));
    }
    return Promise.resolve(metadata(url));
  });
  await h.context.hostBackupsRefresh(true);
  await h.context.hostBackupPortableCheck(operationId);
  await h.context.hostBackupPortableVerify(operationId);
  assert.equal(h.client.portableVerified.imagesBytes, 8192);
  await h.context.hostBackupPortablePrepareDownload(operationId, 'images');
  const links = descendants(h.element('hostBackupPortableFiles')).filter((item) =>
    typeof item.href === 'string' && item.href.endsWith('/portable/download/images'));
  assert.equal(links.length, 1);
  assert.equal(links[0].download, 'images.tar');
  assert.equal(links[0].href.includes('session-1'), false);
  assert.equal(h.calls.filter((call) => call.url.endsWith('/portable/download/images')).length, 0);
  links[0].listeners.get('click')();
  assert.equal(h.client.portableGrant, null);
  assert.deepEqual({ ...h.context.hostBackupReadDownloadMarker() }, {
    requestId: operationId, part: 'images', startedAt: h.client.portableDownloadPending.startedAt,
  });
  h.context.hostBackupRender();
  assert.equal(h.element('hostBackupDownloadPending').hidden, false);
  assert.match(h.element('hostBackupDownloadPending').children[1].textContent, /до часа/);
  assert.equal(h.element('hostBackupCreate').disabled, true);
  await h.context.hostBackupPortablePrepareDownload(operationId, 'archive');
  assert.equal(h.calls.filter((call) => call.url.includes('/download-grants/')).length, 1);

  const resumed = harness(h.localStore);
  resumed.context.location.origin = 'https://hub.example';
  resumed.setFetchHook((url) => Promise.resolve(url.endsWith('/portable/capabilities')
    ? reply(200, { supported: true, download: true }) : metadata(url)));
  await resumed.context.hostBackupsRefresh(true);
  assert.equal(resumed.client.portableDownloadPending.part, 'images');
  assert.equal(resumed.element('hostBackupDownloadPending').hidden, false);
  assert.equal(resumed.element('hostBackupPortableCreate').disabled, true);
  const pendingActions = resumed.element('hostBackupDownloadPending').children[2].children;
  pendingActions[1].listeners.get('click')();
  assert.equal(resumed.element('hostBackupDownloadRetryDialog').open, true);
  resumed.element('hostBackupDownloadRetryCancel').listeners.get('click')();
  assert.equal(resumed.context.hostBackupReadDownloadMarker().part, 'images');
  pendingActions[1].listeners.get('click')();
  resumed.element('hostBackupDownloadRetryConfirm').listeners.get('click')();
  assert.equal(resumed.context.hostBackupReadDownloadMarker(), null);
  assert.equal(resumed.element('hostBackupDownloadPending').hidden, true);
  assert.equal(resumed.element('hostBackupPortableCreate').disabled, false);
});

test('native download is canceled if the browser cannot persist its pending state', () => {
  const h = harness();
  h.context.location.origin = 'https://hub.example';
  Object.assign(h.client, { ready: true, activeId: operationId,
    active: operation(operationId, 'complete'), activePortable: true,
    portableReceipt, portableVerified: { requestId: operationId, archive,
      imagesBytes: 8192, receipt: portableReceipt, base: h.state.base, token: h.state.token },
    portableGrant: { requestId: operationId, part: 'images', base: h.state.base,
      token: h.state.token, expiresAt: Date.now() + 60000 } });
  h.context.hostBackupRender();
  const link = descendants(h.element('hostBackupPortableFiles')).find((item) =>
    typeof item.href === 'string' && item.href.endsWith('/portable/download/images'));
  assert.ok(link);
  h.context.localStorage.setItem = () => { throw new Error('storage unavailable'); };
  let canceled = false;
  link.listeners.get('click')({ preventDefault() { canceled = true; } });
  assert.equal(canceled, true);
  assert.equal(h.client.portableDownloadPending, null);
  assert.match(h.element('hostBackupError').textContent, /Не удалось сохранить состояние/);
});

test('remote-origin panel does not issue a cookie grant for another Hub', async () => {
  const h = harness();
  h.context.location.origin = 'https://panel.example';
  h.setFetchHook((url) => {
    if (url.endsWith('/portable/capabilities'))
      return Promise.resolve(reply(200, { supported: true, download: true }));
    if (url.endsWith('/operations/' + operationId + '/portable/verify'))
      return Promise.resolve(reply(200, portableVerification));
    if (url.endsWith('/operations/' + operationId + '/portable'))
      return Promise.resolve(reply(200, portableOperation()));
    return Promise.resolve(metadata(url));
  });
  await h.context.hostBackupsRefresh(true);
  await h.context.hostBackupPortableCheck(operationId);
  await h.context.hostBackupPortableVerify(operationId);
  await h.context.hostBackupPortablePrepareDownload(operationId, 'archive');
  assert.equal(h.calls.some((call) => call.url.includes('/download-grants/')), false);
  const links = descendants(h.element('hostBackupPortableFiles')).filter((item) =>
    typeof item.href === 'string');
  assert.equal(links.length, 1);
  assert.equal(links[0].href, 'https://hub.example/sovagrid/monitoring/');
  assert.match(h.element('hostBackupPortableFiles').children[1].textContent,
    /самого выбранного Hub/);
});

test('changed receipt refuses browser export before any download grant', async () => {
  const h = harness();
  h.context.location.origin = 'https://hub.example';
  h.setFetchHook((url) => {
    if (url.endsWith('/portable/capabilities'))
      return Promise.resolve(reply(200, { supported: true, download: true }));
    if (url.endsWith('/operations/' + operationId + '/portable/verify'))
      return Promise.resolve(reply(200, { ...portableVerification,
        receipt: { ...portableReceipt, images_sha256: 'f'.repeat(64) } }));
    if (url.endsWith('/operations/' + operationId + '/portable'))
      return Promise.resolve(reply(200, portableOperation()));
    return Promise.resolve(metadata(url));
  });
  await h.context.hostBackupsRefresh(true);
  await h.context.hostBackupPortableCheck(operationId);
  await h.context.hostBackupPortableVerify(operationId);
  assert.equal(h.client.portableVerified, null);
  assert.equal(h.element('hostBackupPortableFiles').hidden, true);
  await h.context.hostBackupPortablePrepareDownload(operationId, 'images');
  assert.equal(h.calls.some((call) => call.url.includes('/download-grants/')), false);
  assert.match(h.element('hostBackupError').textContent, /изменились/);
});

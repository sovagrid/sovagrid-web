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
const reply = (status, value) => ({ ok: status < 400, status,
  text: async () => JSON.stringify(value) });

function harness(localStore = new Map()) {
  const elements = new Map(), calls = [];
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { textContent: '', hidden: false, disabled: false, open: false,
        children: [], listeners, className: '',
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

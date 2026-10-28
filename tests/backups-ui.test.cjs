/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const { randomUUID } = require('node:crypto');

const firstId = '11111111-1111-4111-8111-111111111111';
const secondId = '22222222-2222-4222-8222-222222222222';
const requestId = '33333333-3333-4333-8333-333333333333';
const markerKey = 'sovagrid.restore-request.v1:https://hub.example';
const backup = (id = firstId) => ({ id, created_at: 1793000000,
  database_bytes: 24576, telegram_token_included: true, verified: true });
const restored = (phase = 'complete') => ({ ok: phase === 'complete', protocol: 1,
  request_id: requestId, target_id: firstId, phase, safety_id: secondId,
  plan_id: '44444444-4444-4444-8444-444444444444', hub_running: true,
  error: phase === 'complete' ? null : 'RESTORE_INCOMPLETE', created_at: 1793000100 });
const reply = (status, value) => ({ ok: status < 400, status,
  text: async () => JSON.stringify(value) });

function harness(localStore = new Map()) {
  const elements = new Map(), calls = [];
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { value: '', textContent: '', hidden: false, disabled: false,
        open: false, children: [], className: '', listeners,
        addEventListener(type, fn) { listeners.set(type, fn); },
        append(...nodes) { this.children.push(...nodes); },
        replaceChildren(...nodes) { this.children = nodes; },
        setAttribute() {}, showModal() { this.open = true; },
        close() { this.open = false; listeners.get('close')?.({}); },
      });
    }
    return elements.get(id);
  };
  let fetchHook = () => { throw new Error('unexpected fetch'); };
  const context = vm.createContext({ URL, AbortController, TextEncoder, Uint8Array,
    crypto: { randomUUID }, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, createElement: () => element(Symbol()),
      querySelectorAll: () => [], addEventListener() {} },
    navigator: {}, location: { protocol: 'file:' },
    localStorage: { getItem: (key) => localStore.get(key) ?? null,
      setItem: (key, value) => localStore.set(key, value), removeItem: (key) => localStore.delete(key) },
    fetch: (url, options) => { calls.push({ url, options }); return fetchHook(url, options); },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('backups.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('backups-restore.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  const client = vm.runInContext('backupsClient', context);
  const restoreClient = vm.runInContext('restoresClient', context);
  Object.assign(state, { token: 'session-1', base: 'https://hub.example',
    user: { id: 'admin', username: 'admin', role: 'admin', enabled: true },
    access: { mode: 'all', revision: 0, unrestricted_admin: true }, view: 'settings' });
  return { context, state, client, restoreClient, localStore, element, calls,
    setFetchHook: (fn) => { fetchHook = fn; } };
}

test('global admin can review metadata and create one confirmed snapshot', async () => {
  const h = harness();
  let ids = [firstId];
  h.setFetchHook((url, options) => {
    if (options.method === 'POST') {
      assert.equal(url, 'https://hub.example/api/v1/backups');
      assert.equal(options.body, '{}');
      assert.match(options.headers['Idempotency-Key'], /^[0-9a-f-]{36}$/);
      ids = [secondId, firstId];
      return Promise.resolve(reply(201, { backup: backup(secondId) }));
    }
    if (url.endsWith('/api/v1/backups/' + firstId))
      return Promise.resolve(reply(200, { backup: backup(firstId) }));
    return Promise.resolve(reply(200, { ids }));
  });
  await h.context.backupsRefresh();
  assert.equal(h.element('backupsCreate').disabled, false);
  assert.equal(h.element('backupsList').children.length, 1);
  await h.context.backupsVerify(firstId);
  assert.match(h.element('backupsList').children[0].children[1].children[0].textContent, /Проверить/);
  assert.match(h.element('backupsList').children[0].children[0].children[1].textContent,
    /Telegram-токен включён/);
  h.context.backupsPrepareCreate();
  assert.equal(h.element('backupsCreateDialog').open, true);
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 0);
  await h.context.backupsConfirmCreate();
  await new Promise(setImmediate);
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 1);
  assert.ok(h.client.ids.includes(secondId));
  assert.equal(h.element('backupsCreateDialog').open, false);
  assert.equal(JSON.stringify(h.client.details).includes('A'.repeat(30)), false);
});

test('lost transport or broker response refreshes list before explicit same-key retry', async () => {
  for (const firstFailure of [() => Promise.reject(new TypeError('connection lost')),
    () => Promise.resolve(reply(503, { error: 'Backup broker unavailable; result may be uncertain' }))]) {
    const h = harness();
    let posts = 0, keys = [];
    h.setFetchHook((_url, options) => {
      if (options.method === 'POST') {
        posts++; keys.push(options.headers['Idempotency-Key']);
        if (posts === 1) return firstFailure();
        return Promise.resolve(reply(200, { backup: backup(firstId) }));
      }
      return Promise.resolve(reply(200, { ids: posts === 2 ? [firstId] : [] }));
    });
    await h.context.backupsRefresh();
    h.context.backupsPrepareCreate();
    await h.context.backupsConfirmCreate();
    await new Promise(setImmediate);
    assert.equal(posts, 1);
    assert.equal(h.client.listKnown, true);
    assert.equal(h.element('backupsCreate').textContent, 'Проверить создание');
    assert.match(h.element('backupsStatus').textContent, /тот же ключ/);
    h.context.backupsPrepareCreate();
    assert.match(h.element('backupsCreateDescription').textContent, /тот же ключ/);
    await h.context.backupsConfirmCreate();
    await new Promise(setImmediate);
    assert.equal(posts, 2);
    assert.equal(keys[0], keys[1]);
    assert.equal(h.client.uncertainKey, null);
  }
});

test('selected admin and invalid metadata cannot use global backup controls', async () => {
  const h = harness();
  h.state.access = { mode: 'selected', revision: 1, unrestricted_admin: false };
  await h.context.backupsRefresh();
  h.context.backupsPrepareCreate();
  assert.equal(h.calls.length, 0);
  assert.equal(h.element('backupsCreateDialog').open, false);
  h.state.access = { mode: 'all', revision: 2, unrestricted_admin: true };
  h.setFetchHook((url) => url.endsWith(firstId)
    ? Promise.resolve(reply(200, { backup: { ...backup(), database_bytes: -1 } }))
    : Promise.resolve(reply(200, { ids: [firstId] })));
  await h.context.backupsRefresh();
  await h.context.backupsVerify(firstId);
  assert.equal(h.client.details.size, 0);
  assert.match(h.element('backupsError').textContent, /неверное описание/);
  h.context.backupsReset();
  assert.equal(h.client.ids.length, 0);
  assert.equal(h.element('backupsList').children.length, 0);
});

test('confirmed restore sends one request and keeps its UUID after lost response and reload', async () => {
  const localStore = new Map();
  const h = harness(localStore);
  let restorePosts = 0;
  h.setFetchHook((url, options) => {
    if (url.endsWith('/api/v1/backups/restores')) return Promise.resolve(reply(200, { restores: [] }));
    if (url.endsWith('/api/v1/backups/' + firstId)) return Promise.resolve(reply(200, { backup: backup() }));
    if (url.endsWith('/api/v1/backups/restore') && options.method === 'POST') {
      restorePosts++;
      const body = JSON.parse(options.body);
      assert.equal(body.backup_id, firstId);
      assert.match(body.request_id, /^[0-9a-f-]{36}$/);
      return Promise.reject(new TypeError('Hub restarted'));
    }
    if (url.endsWith('/api/v1/backups')) return Promise.resolve(reply(200, { ids: [firstId] }));
    throw new Error('unexpected ' + url);
  });
  await h.context.backupsRefresh();
  await h.context.backupsVerify(firstId);
  await h.context.backupsPrepareRestore(firstId);
  assert.equal(h.element('backupsRestoreDialog').open, true);
  assert.equal(restorePosts, 0);
  await h.context.backupsConfirmRestore();
  await new Promise(setImmediate);
  assert.equal(restorePosts, 1);
  assert.equal(h.element('backupsCreate').disabled, true);
  const marker = JSON.parse(localStore.get(markerKey));
  assert.equal(marker.target_id, firstId);
  assert.equal(marker.request_id, h.restoreClient.activeRequestId);
  assert.match(h.element('backupsRestoreError').textContent, /Не повторяйте/);
  h.restoreClient.activeRequestId = secondId;
  h.restoreClient.active = { ...restored(), request_id: secondId };
  assert.equal(h.context.backupsRestoreCanStart(), false);

  const next = harness(localStore);
  next.setFetchHook((url) => {
    if (url.endsWith('/api/v1/backups/restores'))
      return Promise.resolve(reply(200, { restores: [{ ...restored(), request_id: marker.request_id,
        hub_running: null }] }));
    if (url.endsWith('/api/v1/backups/restores/' + marker.request_id))
      return Promise.resolve(reply(200, { ...restored(), request_id: marker.request_id }));
    if (url.endsWith('/api/v1/backups')) return Promise.resolve(reply(200, { ids: [firstId] }));
    throw new Error('unexpected ' + url);
  });
  await next.context.backupsRestoresRefresh();
  await new Promise(setImmediate);
  assert.equal(next.restoreClient.active?.phase, 'complete');
  assert.equal(next.restoreClient.activeRequestId, marker.request_id);
  assert.equal(localStore.has(markerKey), false);
  assert.equal(next.context.backupsRestoreCanStart(), true);
});

test('denied browser storage blocks restore and recovery before any mutation', async () => {
  const h = harness();
  h.client.ids = [firstId];
  h.client.listKnown = true;
  h.setFetchHook((url) => {
    if (url.endsWith('/api/v1/backups/' + firstId))
      return Promise.resolve(reply(200, { backup: backup() }));
    throw new Error('mutation must not reach the server');
  });
  h.context.localStorage.setItem = () => { throw new Error('storage denied'); };
  await h.context.backupsPrepareRestore(firstId);
  assert.equal(h.element('backupsRestoreDialog').open, true);
  await h.context.backupsConfirmRestore();
  assert.equal(h.element('backupsRestoreDialog').open, true);
  assert.match(h.element('backupsRestoreDialogError').textContent, /не сохранил UUID/);
  h.restoreClient.pending = null;
  h.element('backupsRestoreDialog').close();
  h.restoreClient.activeRequestId = requestId;
  h.restoreClient.active = restored('started');
  h.context.backupsPrepareRecover(requestId);
  assert.equal(h.element('backupsRecoverDialog').open, true);
  await h.context.backupsConfirmRecover();
  assert.equal(h.element('backupsRecoverDialog').open, true);
  assert.match(h.element('backupsRecoverDialogError').textContent, /не сохранил UUID/);
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 0);
});

test('recovery requires a second confirmation and never repeats a lost POST', async () => {
  const h = harness();
  let recoverPosts = 0;
  h.setFetchHook((url, options) => {
    if (url.endsWith('/api/v1/backups/restores'))
      return Promise.resolve(reply(200, { restores: [restored('started')] }));
    if (url.endsWith('/api/v1/backups/restores/' + requestId + '/recover') && options.method === 'POST') {
      recoverPosts++;
      assert.equal(options.body, '{}');
      return Promise.reject(new TypeError('lost response'));
    }
    if (url.endsWith('/api/v1/backups/restores/' + requestId))
      return Promise.resolve(reply(200, restored('started')));
    throw new Error('unexpected ' + url);
  });
  await h.context.backupsRestoresRefresh();
  await h.context.backupsRestoreCheck(requestId);
  h.context.backupsPrepareRecover(requestId);
  assert.equal(h.element('backupsRecoverDialog').open, true);
  assert.equal(recoverPosts, 0);
  await h.context.backupsConfirmRecover();
  assert.equal(recoverPosts, 1);
  assert.match(h.element('backupsRestoreError').textContent, /Не повторяйте/);
  await h.context.backupsRestoreCheck(requestId);
  assert.equal(recoverPosts, 1);
});

test('session revoked during restore keeps the local request ID for a new login', async () => {
  const h = harness();
  let posts = 0;
  h.setFetchHook((url, options) => {
    if (url.endsWith('/api/v1/backups/restores'))
      return Promise.resolve(reply(200, { restores: [] }));
    if (url.endsWith('/api/v1/backups/' + firstId))
      return Promise.resolve(reply(200, { backup: backup() }));
    if (url.endsWith('/api/v1/backups/restore') && options.method === 'POST') {
      posts++;
      return Promise.resolve(reply(401, { error: 'Session revoked' }));
    }
    if (url.endsWith('/api/v1/backups')) return Promise.resolve(reply(200, { ids: [firstId] }));
    throw new Error('unexpected ' + url);
  });
  await h.context.backupsRefresh();
  await h.context.backupsVerify(firstId);
  await h.context.backupsPrepareRestore(firstId);
  await h.context.backupsConfirmRestore();
  assert.equal(posts, 1);
  assert.equal(h.state.token, '');
  assert.match(h.localStore.get(markerKey), /request_id/);
});

test('restore metadata validation and selected-admin gate reject unsafe inputs', async () => {
  const h = harness();
  assert.throws(() => h.context.restoreRecord({ ...restored(), target_id: '../bad' }),
    /неверное состояние/);
  assert.throws(() => h.context.restoreRecord({ ...restored(), ok: false }),
    /неверное состояние/);
  assert.throws(() => h.context.restoreRecord({ ...restored('started'), error: 'X' }),
    /неверное состояние/);
  h.state.access = { mode: 'selected', revision: 1, unrestricted_admin: false };
  h.setFetchHook(() => { throw new Error('must not call API'); });
  await h.context.backupsPrepareRestore(firstId);
  await h.context.backupsRestoresRefresh();
  assert.equal(h.calls.length, 0);
  assert.equal(h.element('backupsRestoreDialog').open, false);
});

test('local restore UUIDs remain separate for different Hub addresses', () => {
  const h = harness();
  h.context.restoreMarkerSave(requestId, firstId);
  h.state.base = 'https://second-hub.example';
  assert.equal(h.context.restoreMarkerRead(), null);
  h.context.restoreMarkerSave(secondId, firstId);
  assert.equal(h.localStore.has(markerKey), true);
  assert.equal(h.localStore.has('sovagrid.restore-request.v1:https://second-hub.example'), true);
  h.state.base = 'https://hub.example';
  assert.equal(h.context.restoreMarkerRead().request_id, requestId);
});

test('two absent status checks plus refreshed history permit only explicit local forget', async () => {
  const h = harness();
  h.context.restoreMarkerSave(requestId, firstId);
  h.setFetchHook((url) => {
    if (url.endsWith('/api/v1/backups/restores'))
      return Promise.resolve(reply(200, { restores: [] }));
    if (url.endsWith('/api/v1/backups/restores/' + requestId))
      return Promise.resolve(reply(404, { error: 'Restore not found' }));
    throw new Error('unexpected ' + url);
  });
  await h.context.backupsRestoresRefresh();
  await new Promise(setImmediate);
  assert.equal(h.restoreClient.absentChecks, 1);
  assert.equal(h.context.backupsRestoreCanStart(), false);
  h.context.backupsPrepareForget();
  assert.equal(h.element('backupsForgetDialog').open, false);
  await h.context.backupsRestoresRefresh();
  await new Promise(setImmediate);
  assert.equal(h.restoreClient.absentChecks, 2);
  assert.equal(h.restoreClient.absentHistoryChecked, true);
  assert.equal(h.localStore.has(markerKey), true);
  h.context.backupsPrepareForget();
  assert.equal(h.element('backupsForgetDialog').open, true);
  h.context.backupsConfirmForget();
  assert.equal(h.localStore.has(markerKey), false);
  assert.equal(h.context.backupsRestoreCanStart(), true);
});

test('offline shell includes only public backup UI assets', () => {
  const shell = fs.readFileSync('sw.js', 'utf8');
  const container = fs.readFileSync('Dockerfile', 'utf8');
  assert.match(shell, /backups\.js\?v=2/);
  assert.match(shell, /backups-restore\.js\?v=1/);
  assert.match(shell, /backups\.css\?v=2/);
  assert.doesNotMatch(shell, /\/api\/v1\/backups/);
  assert.match(container, /backups\.js backups-restore\.js backups\.css/);
});

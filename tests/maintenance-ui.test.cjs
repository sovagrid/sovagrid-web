/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const response = (status, payload) => ({ ok: status >= 200 && status < 300, status,
  text: async () => JSON.stringify(payload) });

function harness(fetchHook = () => { throw new Error('unexpected fetch'); }) {
  const elements = new Map(), calls = [];
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { value: '', textContent: '', className: '', hidden: false, disabled: false,
        open: false, children: [], listeners,
        addEventListener(name, fn) { listeners.set(name, fn); },
        setAttribute() {},
        replaceChildren() { this.children = []; },
        append(...children) { this.children.push(...children); },
        showModal() { this.open = true; },
        close() { this.open = false; listeners.get('close')?.({}); },
      });
    }
    return elements.get(id);
  };
  const context = vm.createContext({
    URL, AbortController, TextEncoder, setTimeout, clearTimeout,
    setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, createElement: () => ({ className: '', textContent: '',
      children: [], append(...children) { this.children.push(...children); } }),
      querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    navigator: {}, location: new URL('https://hub.example'),
    fetch: (url, options) => { calls.push({ url, options }); return fetchHook(url, options); },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('maintenance.js', 'utf8'), context);
  vm.runInContext('refresh = async () => {}', context);
  const state = vm.runInContext('state', context);
  const client = vm.runInContext('maintenanceClient', context);
  state.base = 'https://hub.example'; state.token = 'admin-session';
  state.servers = [{ id: 'server-a', name: 'Alpha', online: true, maintenance: null },
    { id: 'server-b', name: 'Beta', online: true, maintenance: null }];
  state.selectedId = 'server-a'; state.view = 'overview';
  context.maintenanceSelectedServer('server-a');
  element('maintenanceDuration').value = '1800';
  return { context, state, client, element, calls,
    setFetchHook: (hook) => { fetchHook = hook; } };
}

function windowFor(id = 'window-1', overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  return { id, server_id: 'server-a', starts_at: now - 60, ends_at: now + 1800,
    reason: 'Плановое обновление', cancelled_at: null, status: 'active', ...overrides };
}

test('active window and history render as text while incidents remain part of overview', async () => {
  const window = windowFor('window-1', { reason: '<img src=x onerror=alert(1)>' });
  const h = harness((url, options) => {
    assert.equal(url, 'https://hub.example/api/v1/servers/server-a/maintenance');
    assert.equal(options.headers.Authorization, 'Bearer admin-session');
    return Promise.resolve(response(200, { server_id: 'server-a', windows: [window] }));
  });
  await h.context.maintenanceRefresh();
  assert.equal(h.element('maintenanceBadge').textContent, 'Уведомления на паузе');
  assert.equal(h.element('maintenanceActive').hidden, false);
  assert.equal(h.element('maintenanceForm').hidden, true);
  assert.equal(h.element('maintenanceActiveReason').textContent, '<img src=x onerror=alert(1)>');
  assert.equal(h.element('maintenanceHistory').children[0].children[2].textContent, window.reason);
  assert.match(fs.readFileSync('index.html', 'utf8'), /id="eventsList"/);
  assert.match(fs.readFileSync('index.html', 'utf8'), /Инциденты и метрики остаются в панели/);
});

test('start requires a reason and confirms exact server, duration and schema before POST', async () => {
  let created;
  const h = harness((url, options) => {
    if (options.method === 'POST') {
      const data = JSON.parse(options.body);
      created = windowFor('window-created', { starts_at: data.ends_at - 1800,
        ends_at: data.ends_at, reason: data.reason });
      return Promise.resolve(response(201, { window: created }));
    }
    return Promise.resolve(response(200, { server_id: 'server-a', windows: [] }));
  });
  await h.context.maintenanceRefresh();
  h.element('maintenanceReason').value = '  Обновление Ubuntu  ';
  h.context.maintenancePrepareStart({ preventDefault() {} });
  assert.equal(h.element('maintenanceConfirmDialog').open, true);
  assert.match(h.element('maintenanceConfirmServer').textContent, /Alpha · ID: server-a/);
  assert.match(h.element('maintenanceConfirmSummary').textContent, /30 минут.*Обновление Ubuntu/);
  await h.context.maintenanceConfirm();
  const post = h.calls.find((call) => call.options.method === 'POST');
  assert.equal(post.url, 'https://hub.example/api/v1/servers/server-a/maintenance');
  assert.equal(post.options.headers.Authorization, 'Bearer admin-session');
  assert.deepEqual(JSON.parse(post.options.body), { ends_at: created.ends_at, reason: 'Обновление Ubuntu' });
  assert.equal(h.element('maintenanceConfirmDialog').open, false);
  assert.equal(h.element('maintenanceForm').hidden, true);
  assert.equal(h.element('maintenanceReason').value, '');
  assert.equal(h.element('maintenanceMessage').hidden, false);
});

test('bad reason and invalid duration never reach confirmation or Hub', async () => {
  const h = harness(() => Promise.resolve(response(200, { server_id: 'server-a', windows: [] })));
  await h.context.maintenanceRefresh();
  h.element('maintenanceReason').value = '  ';
  h.context.maintenancePrepareStart({ preventDefault() {} });
  assert.match(h.element('maintenanceError').textContent, /Введите причину/);
  h.element('maintenanceReason').value = 'обновление';
  h.element('maintenanceDuration').value = '999';
  h.context.maintenancePrepareStart({ preventDefault() {} });
  assert.match(h.element('maintenanceError').textContent, /Выберите длительность/);
  assert.equal(h.element('maintenanceConfirmDialog').open, false);
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 0);
});

test('end confirmation includes full window ID and never targets a newly selected server', async () => {
  const active = windowFor('window-exact-id');
  const h = harness(() => Promise.resolve(response(200, { server_id: 'server-a', windows: [active] })));
  await h.context.maintenanceRefresh();
  h.context.maintenancePrepareEnd();
  assert.match(h.element('maintenanceConfirmWindow').textContent, /window-exact-id/);
  h.state.selectedId = 'server-b';
  h.context.maintenanceSelectedServer('server-b');
  await h.context.maintenanceConfirm();
  assert.equal(h.calls.filter((call) => call.options.method === 'DELETE').length, 0);
  assert.equal(h.element('maintenanceConfirmDialog').open, false);
  assert.equal(h.client.windows, null);
});

test('cancel sends bound window ID; changed active window blocks DELETE', async () => {
  const active = windowFor();
  const h = harness((url, options) => options.method === 'DELETE'
    ? Promise.resolve(response(200, { window: { ...active, cancelled_at: Math.floor(Date.now() / 1000), status: 'cancelled' } }))
    : Promise.resolve(response(200, { server_id: 'server-a', windows: [active] })));
  await h.context.maintenanceRefresh();
  h.context.maintenancePrepareEnd();
  h.client.windows = [windowFor('another-window')];
  await h.context.maintenanceConfirm();
  assert.equal(h.calls.filter((call) => call.options.method === 'DELETE').length, 0);
  assert.match(h.element('maintenanceConfirmError').textContent, /изменились/);
  h.context.maintenanceCancel();
  h.client.windows = [active];
  h.context.maintenancePrepareEnd();
  await h.context.maintenanceConfirm();
  assert.equal(h.calls.find((call) => call.options.method === 'DELETE').url,
    'https://hub.example/api/v1/servers/server-a/maintenance/window-1');
  assert.equal(h.element('maintenanceForm').hidden, false);
  assert.match(h.element('maintenanceMessage').textContent, /возобновятся/);
});

test('a GET started before POST cannot erase the confirmed window', async () => {
  let resolveOldGet;
  const h = harness((url, options) => options.method === 'POST'
    ? Promise.resolve(response(201, { window: windowFor('new-window', {
      starts_at: JSON.parse(options.body).ends_at - 1800,
      ends_at: JSON.parse(options.body).ends_at,
      reason: JSON.parse(options.body).reason,
    }) }))
    : Promise.resolve(response(200, { server_id: 'server-a', windows: [] })));
  await h.context.maintenanceRefresh();
  h.setFetchHook((url, options) => options.method === 'POST'
    ? Promise.resolve(response(201, { window: windowFor('new-window', {
      starts_at: JSON.parse(options.body).ends_at - 1800,
      ends_at: JSON.parse(options.body).ends_at,
      reason: JSON.parse(options.body).reason,
    }) }))
    : new Promise((done) => { resolveOldGet = done; }));
  const oldGet = h.context.maintenanceRefresh();
  h.element('maintenanceReason').value = 'Проверка гонки';
  h.context.maintenancePrepareStart({ preventDefault() {} });
  await h.context.maintenanceConfirm();
  resolveOldGet(response(200, { server_id: 'server-a', windows: [] }));
  await oldGet;
  assert.equal(h.client.windows[0].id, 'new-window');
  assert.equal(h.element('maintenanceActive').hidden, false);
  assert.equal(h.client.loading, false);
});

test('409 requires refreshed state and a late GET cannot populate a new session', async () => {
  const h = harness((url, options) => options.method === 'POST'
    ? Promise.resolve(response(409, { error: 'active already' }))
    : Promise.resolve(response(200, { server_id: 'server-a', windows: [] })));
  await h.context.maintenanceRefresh();
  h.element('maintenanceReason').value = 'проверка';
  h.context.maintenancePrepareStart({ preventDefault() {} });
  await h.context.maintenanceConfirm();
  assert.match(h.element('maintenanceConfirmError').textContent, /другой вкладке/);
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 1);
  assert.equal(h.element('maintenanceConfirmDialog').open, true);

  let resolve;
  h.setFetchHook(() => new Promise((done) => { resolve = done; }));
  const pending = h.context.maintenanceRefresh();
  h.context.logout(false);
  h.state.token = 'new-session'; h.state.selectedId = 'server-a';
  resolve(response(200, { server_id: 'server-a', windows: [windowFor()] }));
  await pending;
  assert.equal(h.client.windows, null);
  assert.equal(h.element('maintenanceConfirmDialog').open, false);
});

test('container and offline shell include maintenance in system, light and dark panel', () => {
  const html = fs.readFileSync('index.html', 'utf8');
  const shell = fs.readFileSync('sw.js', 'utf8');
  assert.match(fs.readFileSync('Dockerfile', 'utf8'), /maintenance\.js/);
  assert.match(html, /maintenance\.js\?v=2/);
  assert.match(shell, /maintenance\.js\?v=2/);
  assert.match(fs.readFileSync('theme.css', 'utf8'), /\.maintenance-active \{ background: var\(--sg-warn-bg\)/);
  assert.match(fs.readFileSync('styles.css', 'utf8'), /@media\(max-width:600px\)\{\.maintenance-panel/);
});

test('operator sees maintenance history without changing or ending it', async () => {
  const active = windowFor();
  const h = harness(() => Promise.resolve(response(200, { server_id: 'server-a', windows: [active] })));
  h.state.user = { id: 'operator-id', username: 'operator', role: 'operator' };
  await h.context.maintenanceRefresh();
  assert.equal(h.element('maintenanceActive').hidden, false);
  assert.equal(h.element('maintenanceHistory').children.length, 1);
  assert.equal(h.element('maintenanceForm').hidden, true);
  assert.equal(h.element('maintenanceEnd').disabled, true);
  h.context.maintenancePrepareEnd();
  assert.equal(h.element('maintenanceConfirmDialog').open, false);
  await h.context.maintenanceConfirm();
  assert.equal(h.calls.filter(({ options }) => options.method && options.method !== 'GET').length, 0);
});

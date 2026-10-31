/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

function element() {
  const listeners = new Map();
  return { textContent: '', value: '', className: '', children: [], hidden: false,
    disabled: false, listeners, style: {},
    addEventListener(type, callback) { listeners.set(type, callback); },
    setAttribute() {},
    append(...children) { this.children.push(...children); },
    replaceChildren() { this.children = []; this.textContent = ''; },
  };
}

function harness(role = 'admin') {
  const elements = new Map(), paths = [];
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  let fetchHook = () => { throw new Error('unexpected fetch'); };
  const context = vm.createContext({ URL, AbortController, setTimeout, clearTimeout,
    setInterval: () => 1, clearInterval() {},
    document: { getElementById: get, createElement: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {} }, navigator: {}, location: { protocol: 'file:' },
    fetch: (url, options) => { paths.push(new URL(url).pathname); return fetchHook(url, options); },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  context.renderSidebar = () => {};
  context.renderWorkspace = () => {};
  context.renderServer = () => {};
  const state = vm.runInContext('state', context);
  state.base = 'https://hub.example'; state.token = 'test-session'; state.view = 'vpn';
  state.selectedId = 'server-a';
  if (role !== 'admin') {
    state.user = { id: 'viewer-1', username: 'viewer', role, enabled: true, legacy: false };
    state.access = { mode: 'selected', revision: 1, unrestricted_admin: false };
  }
  return { context, get, paths, state, setFetchHook: (hook) => { fetchHook = hook; } };
}

const reply = (status, payload) => ({ ok: status >= 200 && status < 300, status,
  text: async () => JSON.stringify(payload) });
const servers = [{ id: 'server-a', name: 'Alpha', access_role: 'viewer' },
  { id: 'server-b', name: '<img src=x onerror=alert(1)>', access_role: 'viewer' }];
const vpn = (name = 'AWG') => ({ schema_version: 1, source_status: 'ok', collected_at: 9999999999,
  services: [{ name, service: name, state: 'running', health: 'healthy', published_ports: [] }],
  managed: { source_status: 'ok', instances: [{ name: 'office', state: 'active' }] },
  amnezia_details: { source_status: 'ok', services: [] } });
const envelope = (id, freshness = 'ok', data = vpn()) => ({ server_id: id, received_at: 1790000000,
  freshness, vpn: data });
const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; });
  return { resolve, promise }; };
const until = async (predicate) => {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (predicate()) return;
    await new Promise(setImmediate);
  }
  throw new Error('timed out');
};

test('selected Agent inventory uses its own route and Hub receipt time; Hub host is explicit', async () => {
  const h = harness();
  h.setFetchHook((url) => {
    const path = new URL(url).pathname;
    if (path.endsWith('/servers')) return reply(200, { servers });
    if (path.endsWith('/incidents')) return reply(200, { incidents: [] });
    if (path.endsWith('/server-a/vpn')) return reply(200, envelope('server-a', 'stale'));
    if (path === '/api/v1/vpn') return reply(200, { vpn: vpn('Hub VPN') });
    throw new Error(path);
  });
  await h.context.refresh();
  assert.equal(h.state.vpnTargetId, 'server-a');
  assert.ok(h.paths.includes('/api/v1/servers/server-a/vpn'));
  assert.ok(!h.paths.includes('/api/v1/vpn'));
  assert.equal(h.get('vpnSourceLocation').textContent, 'Источник: Alpha');
  assert.equal(h.get('vpnSourceBadge').textContent, 'Данные устарели');
  assert.equal(h.get('managedSourceBadge').textContent, 'Данные устарели');
  assert.equal(h.get('amneziaDetailBadge').textContent, 'Данные устарели');
  assert.equal(h.get('vpnSnapshotTime').textContent,
    `Получено центром: ${h.context.timestamp(1790000000)} · Данные устарели`);
  assert.equal(h.get('vpnServicesList').children[0].children[0].children[0].textContent, 'AWG');

  const select = h.get('vpnTargetServer');
  select.value = '@hub-host';
  select.listeners.get('change')({ target: select });
  await until(() => h.get('vpnSourceLocation').textContent === 'Источник: хост панели (Hub)' &&
    h.get('vpnServicesList').children[0]?.children[0]?.children[0]?.textContent === 'Hub VPN');
  assert.ok(h.paths.includes('/api/v1/vpn'));
});

test('a late old-server reply cannot replace the newly selected server, and names render as text', async () => {
  const h = harness(), old = deferred();
  h.setFetchHook((url) => {
    const path = new URL(url).pathname;
    if (path.endsWith('/servers')) return reply(200, { servers });
    if (path.endsWith('/incidents')) return reply(200, { incidents: [] });
    if (path.endsWith('/server-a/vpn')) return old.promise;
    if (path.endsWith('/server-b/vpn')) return reply(200, envelope('server-b', 'ok', vpn('<script>bad</script>')));
    throw new Error(path);
  });
  const first = h.context.refresh();
  await until(() => h.paths.includes('/api/v1/servers/server-a/vpn'));
  const select = h.get('vpnTargetServer');
  select.value = 'server-b';
  select.listeners.get('change')({ target: select });
  await until(() => h.get('vpnSourceBadge').textContent === 'Данные актуальны' &&
    h.get('vpnSourceLocation').textContent.includes('<img'));
  old.resolve(reply(200, envelope('server-a')));
  await first;
  assert.equal(h.state.vpnTargetId, 'server-b');
  assert.equal(h.get('vpnSourceLocation').textContent, `Источник: ${servers[1].name}`);
  assert.equal(h.get('vpnServicesList').children[0].children[0].children[0].textContent, '<script>bad</script>');
  assert.equal(h.get('vpnServicesList').children.length, 1);
  assert.equal(h.get('vpnSourceBadge').textContent, 'Данные актуальны');
});

test('viewer reads only authorized server inventory; denial and old Hub clear old cards', async () => {
  const h = harness('viewer');
  let mode = 'ok';
  h.setFetchHook((url) => {
    const path = new URL(url).pathname;
    if (path.endsWith('/session')) return reply(200, { user: { id: 'viewer-1', username: 'viewer',
      role: 'viewer', enabled: true } });
    if (path.endsWith('/session/access')) return reply(200, { access: {
      mode: 'selected', revision: 1, unrestricted_admin: false } });
    if (path.endsWith('/servers')) return reply(200, { servers: [servers[0]] });
    if (path.endsWith('/incidents')) return reply(200, { incidents: [] });
    if (path.endsWith('/server-a/vpn')) return mode === 'ok' ? reply(200, envelope('server-a')) :
      reply(mode === 'denied' ? 403 : 404, { error: 'Unavailable' });
    throw new Error(path);
  });
  await h.context.refresh();
  assert.equal(h.get('vpnRunning').textContent, '1');
  assert.equal(h.get('vpnTargetServer').children.length, 1, 'viewer must not get the Hub-host choice');
  assert.ok(!h.paths.includes('/api/v1/vpn'));

  mode = 'denied';
  await h.context.refresh();
  assert.equal(h.get('vpnSourceBadge').textContent, 'Нет доступа');
  assert.equal(h.get('vpnServicesList').children.length, 1);
  assert.equal(h.get('vpnRunning').textContent, '—');
  assert.equal(h.get('globalError').textContent, '');

  mode = 'old-hub';
  await h.context.refresh();
  assert.equal(h.get('vpnSourceBadge').textContent, 'Нужен новый Hub');
  assert.match(h.get('vpnSourceText').textContent, /Обновите Hub/);
  assert.ok(!h.paths.includes('/api/v1/vpn'), 'remote failure must not fall back to the Hub-host snapshot');
});

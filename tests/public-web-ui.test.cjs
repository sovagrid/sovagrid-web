/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const { randomUUID } = require('node:crypto');

const SHA = 'a'.repeat(64), SOURCE = 'b'.repeat(64), NEXT = 'c'.repeat(64);
const config = (overrides = {}) => ({ mode: 'ip', address: '8.8.8.8',
  acme_environment: 'production', panel_path: '/sovagrid/monitoring/',
  root_behavior: 'untouched', ...overrides });
const status = (cfg = null, hash = null) => ({ protocol: 1, ok: true,
  enabled: cfg !== null, config: cfg, expected_state_sha256: hash });
const preview = (cfg, hash = null, changes = true) => ({ protocol: 1, ok: true,
  config: cfg, expected_state_sha256: hash, source_manifest_sha256: SOURCE,
  changed: changes, url: `https://${cfg.address}`, certificate_verified: false });
const applied = (cfg, hash = NEXT) => ({ ...preview(cfg, hash), enabled: true,
  certificate_verified: cfg.acme_environment === 'production' });
const reply = (code, data) => ({ ok: code >= 200 && code < 300, status: code,
  text: async () => JSON.stringify(data) });

class Element {
  constructor() { this.value = ''; this.textContent = ''; this.hidden = false; this.disabled = false;
    this.href = ''; this.open = false; this.listeners = new Map(); }
  addEventListener(name, callback) { this.listeners.set(name, callback); }
  showModal() { this.open = true; }
  close() { this.open = false; }
  replaceChildren() {}
  setAttribute() {}
}

function harness(options = {}) {
  const elements = new Map(), calls = [], timers = [], storage = options.storage || new Map(), navigations = [];
  const address = new URL(options.origin || 'https://hub.example/sovagrid/monitoring/');
  address.assign = (value) => navigations.push(value);
  let fetchHook = () => { throw new Error('unexpected fetch'); };
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const context = vm.createContext({ URL, AbortController,
    crypto: { randomUUID },
    setTimeout: (callback, ms) => { timers.push({ callback, ms, cleared: false }); return timers.length; },
    clearTimeout: (id) => { if (timers[id - 1]) timers[id - 1].cleared = true; },
    setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: (key) => storage.get(key) || null,
      setItem: (key, value) => { if (options.storageDenied) throw Error('denied'); storage.set(key, value); },
      removeItem: (key) => storage.delete(key) },
    navigator: {}, location: address,
    fetch: (url, init) => { calls.push({ url, init }); return fetchHook(url, init); },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('public-web.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  const client = vm.runInContext('publicWebClient', context);
  state.base = address.origin; state.token = 'bearer-secret'; state.view = 'settings';
  state.user = { id: 'admin', username: 'admin', role: 'admin', enabled: true, legacy: false };
  state.access = { mode: 'all', revision: 1, unrestricted_admin: true };
  return { context, state, client, calls, storage, timers, navigations, element,
    setFetchHook: (hook) => { fetchHook = hook; },
    change: (id, value) => { element(id).value = value; element(id).listeners.get('input')(); },
    runRecovery: async () => {
      const timer = timers.find((item) => !item.cleared && item.ms === 0);
      assert.ok(timer); timer.cleared = true; timer.callback();
      for (let i = 0; i < 10; i++) await Promise.resolve();
    },
  };
}

test('new configuration uses untouched root and an existing panel root remains unchanged', async () => {
  const h = harness();
  h.setFetchHook(() => Promise.resolve(reply(200, status())));
  await h.context.publicWebRefresh();
  assert.equal(h.element('publicWebPath').value, '/sovagrid/monitoring/');
  assert.equal(h.element('publicWebRoot').value, 'untouched');
  assert.equal(h.element('publicWebAddress').value, '');
  assert.equal(h.element('publicWebPreview').disabled, false);
  h.setFetchHook(() => Promise.resolve(reply(200, status(config({ root_behavior: 'panel' }), SHA))));
  await h.context.publicWebRefresh({ replace: true });
  assert.equal(h.element('publicWebRoot').value, 'panel');
  assert.match(h.element('publicWebCurrent').textContent, /8\.8\.8\.8/);
  assert.match(h.element('publicWebCurrentLink').href, /^https:\/\/8\.8\.8\.8/);
});

test('preview and apply bind one exact CAS request then relocate without URL credentials', async () => {
  const h = harness();
  h.setFetchHook((url, init) => {
    if (url.endsWith('/public-web') && init.method !== 'POST') return Promise.resolve(reply(200, status()));
    if (url.endsWith('/preview')) return Promise.resolve(reply(200, preview(config({ panel_path: '/ops/panel/' }))));
    if (url.endsWith('/apply')) {
      const data = JSON.parse(init.body);
      assert.equal(h.storage.size, 1, 'recovery record must exist before mutation');
      assert.equal(data.request_id.length, 36);
      assert.equal(data.expected_state_sha256, null);
      assert.equal(data.source_manifest_sha256, SOURCE);
      assert.deepEqual(data.config, config({ panel_path: '/ops/panel/' }));
      return Promise.resolve(reply(200, applied(data.config)));
    }
    throw Error('unexpected route');
  });
  await h.context.publicWebRefresh();
  h.change('publicWebAddress', '8.8.8.8');
  h.change('publicWebPath', '/ops/panel/');
  await h.context.publicWebPreview({ preventDefault() {} });
  assert.equal(h.element('publicWebPreviewCard').hidden, false);
  assert.match(h.element('publicWebPreviewSummary').textContent, /\/ops\/panel\//);
  h.context.publicWebPrepareApply();
  assert.equal(h.element('publicWebApplyDialog').open, true);
  await h.context.publicWebApply();
  assert.deepEqual(h.navigations, ['https://8.8.8.8/ops/panel/']);
  assert.equal(h.storage.size, 0);
  assert.equal(h.calls.filter((call) => call.url.endsWith('/apply')).length, 1);
  assert.equal(h.calls.find((call) => call.url.endsWith('/apply')).init.cache, 'no-store');
  assert.ok(h.calls.every((call) => call.init.headers.Authorization === 'Bearer bearer-secret'));
  assert.ok(h.navigations.every((url) => !url.includes('bearer-secret') && !url.includes('request_id')));
});

test('preview rejects unsafe path before network and an admin may reload after CAS conflict', async () => {
  const h = harness();
  h.setFetchHook(() => Promise.resolve(reply(200, status(config({ root_behavior: 'panel' }), SHA))));
  await h.context.publicWebRefresh();
  h.change('publicWebPath', '/api/secret/');
  await h.context.publicWebPreview({ preventDefault() {} });
  assert.match(h.element('publicWebError').textContent, /Проверьте/);
  assert.equal(h.calls.length, 1);
  h.change('publicWebPath', '/ops/panel/');
  await h.context.publicWebRefresh();
  assert.equal(h.element('publicWebPath').value, '/ops/panel/');
  h.setFetchHook(() => Promise.resolve(reply(200, status(config({ panel_path: '/new/', root_behavior: 'panel' }), NEXT))));
  await h.context.publicWebRefresh();
  assert.equal(h.client.conflict, true);
  assert.equal(h.element('publicWebPreview').disabled, true);
  await h.context.publicWebRefresh({ replace: true });
  assert.equal(h.element('publicWebPath').value, '/new/');
});

test('lost apply reply reconciles committed status and old request ID is never duplicated', async () => {
  const h = harness({ origin: 'http://127.0.0.1:8766/sovagrid/monitoring/' });
  let committed = false;
  h.setFetchHook((url) => {
    if (url.endsWith('/public-web')) return Promise.resolve(reply(200, status(committed ? config() : null, committed ? NEXT : null)));
    if (url.endsWith('/preview')) return Promise.resolve(reply(200, preview(config())));
    if (url.endsWith('/apply')) { committed = true; return Promise.reject(Error('connection closed')); }
    throw Error('unexpected');
  });
  await h.context.publicWebRefresh();
  h.change('publicWebAddress', '8.8.8.8');
  await h.context.publicWebPreview({ preventDefault() {} });
  await h.context.publicWebApply();
  assert.equal(h.storage.size, 1);
  await h.runRecovery();
  assert.equal(h.storage.size, 0);
  assert.deepEqual(h.navigations, []);
  assert.equal(h.calls.filter((call) => call.url.endsWith('/apply')).length, 1);
  assert.match(h.element('publicWebMessage').textContent, /Адрес панели уже открыт/);
});

test('unconfirmed apply keeps the exact request and recovery survives a same-origin reload', async () => {
  const storage = new Map();
  const h = harness({ storage });
  h.setFetchHook((url) => {
    if (url.endsWith('/public-web')) return Promise.resolve(reply(200, status()));
    if (url.endsWith('/preview')) return Promise.resolve(reply(200, preview(config())));
    if (url.endsWith('/apply')) return Promise.reject(Error('connection closed'));
    throw Error('unexpected');
  });
  await h.context.publicWebRefresh();
  h.change('publicWebAddress', '8.8.8.8');
  await h.context.publicWebPreview({ preventDefault() {} });
  await h.context.publicWebApply();
  const first = JSON.parse(h.calls.find((call) => call.url.endsWith('/apply')).init.body);
  assert.equal(storage.size, 1);
  const reloaded = harness({ storage });
  reloaded.setFetchHook((url) => Promise.resolve(url.endsWith('/public-web') ? reply(200, status()) :
    reply(200, applied(config()))));
  await reloaded.context.publicWebRefresh();
  assert.equal(reloaded.client.pending.request_id, first.request_id);
  assert.equal(reloaded.element('publicWebRepeat').hidden, false);
  await reloaded.context.publicWebSendApply(reloaded.client.pending);
  const repeated = JSON.parse(reloaded.calls.find((call) => call.url.endsWith('/apply')).init.body);
  assert.deepEqual(repeated, first);
  assert.equal(storage.size, 0);
});

test('a 409 with unchanged state ends the pending request and requires a fresh preview', async () => {
  const h = harness();
  h.setFetchHook((url) => {
    if (url.endsWith('/public-web')) return Promise.resolve(reply(200, status()));
    if (url.endsWith('/preview')) return Promise.resolve(reply(200, preview(config())));
    if (url.endsWith('/apply')) return Promise.resolve(reply(409, { error: 'State changed' }));
    throw Error('unexpected route');
  });
  await h.context.publicWebRefresh();
  h.change('publicWebAddress', '8.8.8.8');
  await h.context.publicWebPreview({ preventDefault() {} });
  await h.context.publicWebApply();
  await h.runRecovery();
  assert.equal(h.storage.size, 0);
  assert.equal(h.client.pending, null);
  assert.equal(h.element('publicWebPreview').disabled, true);
  assert.match(h.element('publicWebMessage').textContent, /не применил/);
});

test('viewer, cross-origin page and unavailable browser storage cannot apply', async () => {
  const viewer = harness();
  viewer.state.user.role = 'viewer';
  await viewer.context.publicWebRefresh();
  assert.equal(viewer.calls.length, 0);
  viewer.context.publicWebRender();
  assert.equal(viewer.element('publicWebPanel').hidden, true);

  const remote = harness();
  remote.state.base = 'https://other.example';
  await remote.context.publicWebRefresh();
  assert.equal(remote.calls.length, 0);
  assert.equal(remote.element('publicWebPreview').disabled, true);

  const blocked = harness({ storageDenied: true });
  blocked.setFetchHook((url) => Promise.resolve(url.endsWith('/public-web') ? reply(200, status()) :
    reply(200, preview(config()))));
  await blocked.context.publicWebRefresh();
  blocked.change('publicWebAddress', '8.8.8.8');
  await blocked.context.publicWebPreview({ preventDefault() {} });
  await blocked.context.publicWebApply();
  assert.equal(blocked.calls.filter((call) => call.url.endsWith('/apply')).length, 0);
  assert.match(blocked.element('publicWebApplyError').textContent, /ID восстановления/);
});

test('public UI assets are packaged but API and request data remain outside the offline shell', () => {
  const html = fs.readFileSync('index.html', 'utf8');
  const docker = fs.readFileSync('Dockerfile', 'utf8');
  const shell = fs.readFileSync('sw.js', 'utf8');
  assert.match(html, /id="publicWebPanel"[^>]*data-global-admin-only/);
  assert.match(html, /public-web\.js\?v=2/);
  assert.match(html, /public-web\.css\?v=2/);
  assert.match(docker, /COPY[^\n]+public-web\.js/);
  assert.match(docker, /COPY[^\n]+public-web\.css/);
  assert.match(shell, /public-web\.js\?v=2/);
  assert.match(shell, /public-web\.css\?v=2/);
  assert.ok(!shell.includes('/api/v1/public-web'));
});

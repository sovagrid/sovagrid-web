/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const { randomUUID } = require('node:crypto');

const SHA = 'a'.repeat(64), SOURCE = 'b'.repeat(64), NEXT = 'c'.repeat(64);
const cfg = (more = {}) => ({ panel_path: '/sovagrid/monitoring/', root_behavior: 'untouched', ...more });
const localStatus = (value = null, hash = null) => ({ protocol: 1, ok: true,
  enabled: value !== null, config: value, expected_state_sha256: hash });
const publicStatus = (enabled = false) => ({ protocol: 1, ok: true, enabled,
  config: enabled ? { mode: 'ip', address: '8.8.8.8', acme_environment: 'production',
    panel_path: '/ops/panel/', root_behavior: 'panel' } : null,
  expected_state_sha256: enabled ? SHA : null });
const preview = (value, hash = null) => ({ protocol: 1, ok: true, config: value,
  expected_state_sha256: hash, source_manifest_sha256: SOURCE, changed: true,
  url: 'http://127.0.0.1:8766', certificate_verified: false });
const applied = (value) => ({ ...preview(value, NEXT), enabled: true });
const disabled = () => ({ protocol: 1, ok: true, enabled: false, changed: true,
  expected_state_sha256: null });
const reply = (code, data) => ({ ok: code >= 200 && code < 300, status: code,
  text: async () => JSON.stringify(data) });

class Element {
  constructor() { this.value = ''; this.textContent = ''; this.hidden = false; this.disabled = false;
    this.href = ''; this.open = false; this.listeners = new Map(); }
  addEventListener(name, fn) { this.listeners.set(name, fn); }
  showModal() { this.open = true; }
  close() { this.open = false; }
  replaceChildren() {}
  setAttribute() {}
}

function harness(options = {}) {
  const nodes = new Map(), calls = [], timers = [], storage = options.storage || new Map(), navigations = [];
  const location = new URL(options.origin || 'http://127.0.0.1:9876/sovagrid/monitoring/');
  location.assign = (url) => navigations.push(url);
  let fetchHook = () => { throw Error('unexpected request'); };
  const element = (id) => {
    if (!nodes.has(id)) nodes.set(id, new Element());
    return nodes.get(id);
  };
  const context = vm.createContext({ URL, AbortController,
    crypto: { randomUUID },
    setTimeout: (callback, delay) => { timers.push({ callback, delay, cleared: false }); return timers.length; },
    clearTimeout: (id) => { if (timers[id - 1]) timers[id - 1].cleared = true; },
    setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    navigator: {}, location,
    localStorage: { getItem: (key) => storage.get(key) || null,
      setItem: (key, value) => { if (options.storageDenied) throw Error('blocked'); storage.set(key, value); },
      removeItem: (key) => storage.delete(key) },
    fetch: (url, init) => { calls.push({ url: String(url), init }); return fetchHook(String(url), init); },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('public-web.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('local-web.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  const client = vm.runInContext('localWebClient', context);
  state.base = location.origin; state.token = 'private-bearer'; state.view = 'settings';
  state.user = { id: 'admin', username: 'admin', role: 'admin', enabled: true, legacy: false };
  state.access = { mode: 'all', revision: 1, unrestricted_admin: true };
  return { context, state, client, calls, timers, storage, navigations, element,
    setFetchHook: (fn) => { fetchHook = fn; },
    change: (id, value) => { element(id).value = value; element(id).listeners.get('input')(); },
    fireTimer: async (delay) => {
      const timer = timers.find((item) => !item.cleared && item.delay === delay);
      assert.ok(timer, `missing timer ${delay}`); timer.cleared = true; timer.callback();
      for (let i = 0; i < 16; i++) await Promise.resolve();
    },
  };
}

test('new local mode starts with untouched root and legacy 404 discovery only', async () => {
  const h = harness();
  h.setFetchHook((url) => Promise.resolve(url.endsWith('/local-web') ? reply(200, localStatus()) :
    url.endsWith('/public-web') ? reply(200, publicStatus()) : reply(404, { error: 'not found' })));
  await h.context.localWebRefresh();
  for (let i = 0; i < 8; i++) await Promise.resolve();
  assert.equal(h.element('localWebPath').value, '/sovagrid/monitoring/');
  assert.equal(h.element('localWebRoot').value, 'untouched');
  assert.equal(h.element('localWebPreview').disabled, false);
  assert.match(h.element('localWebDiscovery').textContent, /Старый Hub/);
  const discovery = h.calls.find((call) => call.url.endsWith('/panel-location'));
  assert.equal(discovery.init.cache, 'no-store');
  assert.equal(discovery.init.credentials, 'omit');
  assert.equal(discovery.init.headers, undefined);
});

test('503 discovery is never treated as the default path', async () => {
  const h = harness();
  h.setFetchHook((url) => Promise.resolve(url.endsWith('/local-web') ? reply(200, localStatus()) :
    url.endsWith('/public-web') ? reply(200, publicStatus()) : reply(503, { error: 'not ready' })));
  await h.context.localWebRefresh();
  for (let i = 0; i < 8; i++) await Promise.resolve();
  assert.equal(h.client.discoveryPath, null);
  assert.match(h.element('localWebDiscovery').textContent, /ещё определяет/);
});

test('a new path waits through 503 discovery and a legacy 404 cannot confirm a custom path', async () => {
  const h = harness();
  let discovery = 0;
  h.setFetchHook((url) => {
    if (!url.endsWith('/panel-location')) throw Error('unexpected');
    discovery++;
    return Promise.resolve(discovery === 1 ? reply(503, { error: 'not ready' }) :
      reply(200, { panel_path: '/home/control/' }));
  });
  await h.context.localWebDiscoverAndNavigate('/home/control/', true);
  assert.deepEqual(h.navigations, []);
  await h.fireTimer(3500);
  assert.deepEqual(h.navigations, ['http://127.0.0.1:9876/home/control/']);

  const legacy = harness();
  legacy.setFetchHook(() => Promise.resolve(reply(404, { error: 'old Hub' })));
  await legacy.context.localWebDiscoverAndNavigate('/home/control/', true);
  assert.deepEqual(legacy.navigations, []);
  assert.match(legacy.element('localWebMessage').textContent, /другой путь/);
});

test('local preview/apply uses exact CAS and moves this loopback tunnel after discovery', async () => {
  const h = harness();
  const desired = cfg({ panel_path: '/home/control/' });
  h.setFetchHook((url, init) => {
    if (url.endsWith('/local-web')) return Promise.resolve(reply(200, localStatus()));
    if (url.endsWith('/public-web')) return Promise.resolve(reply(200, publicStatus()));
    if (url.endsWith('/preview')) return Promise.resolve(reply(200, preview(desired)));
    if (url.endsWith('/apply')) {
      const body = JSON.parse(init.body);
      assert.equal(h.storage.has('sovagrid.local-web.pending.v1'), true);
      assert.deepEqual(body.config, desired);
      assert.equal(body.source_manifest_sha256, SOURCE);
      assert.equal(body.expected_state_sha256, null);
      assert.equal(body.request_id.length, 36);
      return Promise.resolve(reply(200, applied(desired)));
    }
    if (url.endsWith('/panel-location')) return Promise.resolve(reply(200, { panel_path: desired.panel_path }));
    throw Error('unexpected');
  });
  await h.context.localWebRefresh();
  await h.context.publicWebRefresh();
  assert.equal(h.element('publicWebAddress').value, '');
  assert.equal(h.element('publicWebPreview').disabled, false);
  h.change('localWebPath', desired.panel_path);
  await h.context.localWebPreview({ preventDefault() {} });
  assert.equal(h.element('localWebPreviewCard').hidden, false);
  h.context.localWebPrepareApply();
  assert.equal(h.element('localWebApplyDialog').open, true);
  await h.context.localWebStart('apply');
  for (let i = 0; i < 12; i++) await Promise.resolve();
  assert.deepEqual(h.navigations, ['http://127.0.0.1:9876/home/control/']);
  assert.equal(h.storage.size, 0);
  assert.equal(h.element('publicWebPreview').disabled, true);
  assert.ok(h.navigations.every((url) => !url.includes('private-bearer')));
  assert.equal(h.calls.filter((call) => call.url.endsWith('/apply')).length, 1);
});

test('public HTTPS makes the local form read-only and preserves existing root behavior', async () => {
  const h = harness();
  h.setFetchHook((url) => Promise.resolve(url.endsWith('/local-web')
    ? reply(200, localStatus(cfg({ root_behavior: 'panel' }), SHA))
    : url.endsWith('/public-web') ? reply(200, publicStatus(true))
      : reply(200, { panel_path: '/ops/panel/' })));
  await h.context.localWebRefresh();
  assert.equal(h.element('localWebRoot').value, 'panel');
  assert.equal(h.element('localWebPreview').disabled, true);
  assert.equal(h.element('localWebDisable').hidden, true);
  assert.match(h.element('localWebOwnership').textContent, /публичный HTTPS/);
  await h.context.localWebPreview({ preventDefault() {} });
  assert.equal(h.calls.filter((call) => call.url.endsWith('/preview')).length, 0);
});

test('confirmed local disable keeps path/root as public draft and moves to legacy alias', async () => {
  const h = harness();
  const old = cfg({ panel_path: '/home/control/', root_behavior: 'redirect' });
  h.setFetchHook((url, init) => {
    if (url.endsWith('/local-web')) return Promise.resolve(reply(200, localStatus(old, SHA)));
    if (url.endsWith('/public-web')) return Promise.resolve(reply(200, publicStatus()));
    if (url.endsWith('/disable')) {
      assert.deepEqual(JSON.parse(init.body), { expected_state_sha256: SHA,
        request_id: JSON.parse(init.body).request_id });
      assert.equal(h.storage.has('sovagrid.public-web.local-route-transfer.v1'), true);
      return Promise.resolve(reply(200, disabled()));
    }
    if (url.endsWith('/panel-location')) return Promise.resolve(reply(200, { panel_path: '/sovagrid/monitoring/' }));
    throw Error('unexpected');
  });
  await h.context.localWebRefresh();
  h.context.localWebPrepareDisable();
  assert.equal(h.element('localWebDisableDialog').open, true);
  await h.context.localWebStart('disable');
  for (let i = 0; i < 12; i++) await Promise.resolve();
  assert.deepEqual(h.navigations, []);
  assert.equal(h.storage.has('sovagrid.local-web.pending.v1'), false);
  const transfer = JSON.parse(h.storage.get('sovagrid.public-web.local-route-transfer.v1'));
  assert.equal(transfer.panel_path, '/home/control/');
  assert.equal(transfer.root_behavior, 'redirect');
  assert.equal(h.element('publicWebPath').value, '/home/control/');
  assert.equal(h.element('publicWebRoot').value, 'redirect');
  assert.ok(!JSON.stringify([...h.storage.values()]).includes('private-bearer'));
});

test('lost disable reply retries only the same CAS request ID', async () => {
  const h = harness();
  const old = cfg({ panel_path: '/home/control/', root_behavior: 'panel' });
  let attempts = 0, disabledNow = false;
  h.setFetchHook((url) => {
    if (url.endsWith('/local-web')) return Promise.resolve(reply(200,
      localStatus(disabledNow ? null : old, disabledNow ? null : SHA)));
    if (url.endsWith('/public-web')) return Promise.resolve(reply(200, publicStatus()));
    if (url.endsWith('/disable')) {
      attempts++;
      if (attempts === 1) return Promise.reject(Error('connection lost'));
      disabledNow = true;
      return Promise.resolve(reply(200, disabled()));
    }
    if (url.endsWith('/panel-location')) return Promise.resolve(reply(200,
      { panel_path: '/sovagrid/monitoring/' }));
    throw Error('unexpected');
  });
  await h.context.localWebRefresh();
  await h.context.localWebStart('disable');
  const first = JSON.parse(h.calls.find((call) => call.url.endsWith('/disable')).init.body);
  assert.equal(h.storage.has('sovagrid.local-web.pending.v1'), true);
  await h.fireTimer(0);
  assert.equal(h.client.repeatAllowed, true);
  await h.context.localWebSend(h.client.pending);
  const second = JSON.parse(h.calls.filter((call) => call.url.endsWith('/disable'))[1].init.body);
  assert.deepEqual(second, first);
  assert.equal(h.storage.has('sovagrid.local-web.pending.v1'), false);
  assert.equal(h.storage.has('sovagrid.public-web.local-route-transfer.v1'), true);
});

test('lost apply result keeps one UUID and recovery status confirms destination', async () => {
  const h = harness();
  const desired = cfg({ panel_path: '/home/control/' });
  let changed = false;
  h.setFetchHook((url) => {
    if (url.endsWith('/local-web')) return Promise.resolve(reply(200,
      localStatus(changed ? desired : null, changed ? NEXT : null)));
    if (url.endsWith('/public-web')) return Promise.resolve(reply(200, publicStatus()));
    if (url.endsWith('/preview')) return Promise.resolve(reply(200, preview(desired)));
    if (url.endsWith('/apply')) { changed = true; return Promise.reject(Error('Web restarted')); }
    if (url.endsWith('/panel-location')) return Promise.resolve(reply(200,
      { panel_path: changed ? desired.panel_path : PUBLIC_DEFAULT }));
    throw Error('unexpected');
  });
  const PUBLIC_DEFAULT = '/sovagrid/monitoring/';
  await h.context.localWebRefresh();
  h.change('localWebPath', desired.panel_path);
  await h.context.localWebPreview({ preventDefault() {} });
  await h.context.localWebStart('apply');
  assert.equal(h.storage.has('sovagrid.local-web.pending.v1'), true);
  await h.fireTimer(0);
  for (let i = 0; i < 8; i++) await Promise.resolve();
  assert.equal(h.storage.has('sovagrid.local-web.pending.v1'), false);
  assert.deepEqual(h.navigations, ['http://127.0.0.1:9876/home/control/']);
  assert.equal(h.calls.filter((call) => call.url.endsWith('/apply')).length, 1);
});

test('viewer and HTTPS page cannot alter local route', async () => {
  const viewer = harness();
  viewer.state.user.role = 'viewer';
  await viewer.context.localWebRefresh();
  assert.equal(viewer.calls.length, 0);
  const remote = harness({ origin: 'https://8.8.8.8/sovagrid/monitoring/' });
  remote.setFetchHook((url) => Promise.resolve(url.endsWith('/local-web')
    ? reply(200, localStatus()) : url.endsWith('/public-web')
      ? reply(200, publicStatus(true)) : reply(200, { panel_path: '/ops/panel/' })));
  await remote.context.localWebRefresh();
  assert.equal(remote.element('localWebPreview').disabled, true);
  await remote.context.localWebPreview({ preventDefault() {} });
  assert.equal(remote.calls.filter((call) => call.url.endsWith('/preview')).length, 0);
});

test('local UI shell contains only public assets, not API or operation state', () => {
  const html = fs.readFileSync('index.html', 'utf8');
  const docker = fs.readFileSync('Dockerfile', 'utf8');
  const shell = fs.readFileSync('sw.js', 'utf8');
  assert.match(html, /id="localWebPanel"[^>]*data-global-admin-only/);
  assert.match(html, /local-web\.js\?v=1/);
  assert.match(docker, /COPY[^\n]+local-web\.js/);
  assert.match(shell, /local-web\.js\?v=1/);
  assert.ok(!shell.includes('/api/v1/local-web'));
  assert.ok(!shell.includes('/api/v1/panel-location'));
});

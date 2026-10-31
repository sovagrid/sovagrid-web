/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const key = 'a'.repeat(64), manifest = 'b'.repeat(64), revision = 'c'.repeat(64);
const snapshot = (changes = {}) => ({
  format: 1, channel: 'stable', enabled: false, key_id: null,
  available_keys: { 'sovagrid-2026-10': key }, timer_installed: true,
  timer_enabled: false, timer_active: false, manual_candidate_active: false,
  installed_manifest_sha256: manifest,
  ledger: { format: 1, highest_sequence: 0, highest_version: '0.0.0',
    highest_issued_at: 0, last_seen_at: 0 }, state_revision: revision, ...changes,
});
const reply = (code, value) => ({ ok: code < 400, status: code,
  text: async () => JSON.stringify(value) });

function harness() {
  const elements = new Map(), calls = [];
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { textContent: '', hidden: false, disabled: false,
        checked: false, className: '', listeners,
        addEventListener(type, listener) { listeners.set(type, listener); },
      });
    }
    return elements.get(id);
  };
  let fetchHook = () => { throw Error('unexpected request'); };
  const context = vm.createContext({ URL, AbortController, setTimeout, clearTimeout,
    setInterval: () => 1, clearInterval() {}, Date,
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null }, navigator: {}, location: { protocol: 'file:' },
    fetch: (url, options) => { calls.push({ url, options }); return fetchHook(url, options); },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('updates.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  Object.assign(state, { token: 'test-session', base: 'https://hub.example',
    user: { id: 'admin', username: 'admin', role: 'admin', enabled: true },
    access: { mode: 'all', revision: 0, unrestricted_admin: true }, view: 'settings' });
  return { context, element, state, calls, setFetchHook: (fn) => { fetchHook = fn; } };
}

test('settings show signed-feed state and offer enable only to an unrestricted admin', async () => {
  const h = harness();
  h.setFetchHook(() => Promise.resolve(reply(200, snapshot())));
  await h.context.releaseFeedRefresh(true);
  assert.match(h.element('releaseFeedSummary').textContent, /выключена/);
  assert.equal(h.element('releaseFeedEnable').disabled, false);
  assert.equal(h.element('releaseFeedDisable').disabled, true);
  assert.equal(h.element('releaseFeedFingerprint').textContent, key);
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].url, 'https://hub.example/api/v1/release-feed');
  h.state.access.unrestricted_admin = false;
  h.context.releaseFeedAccessChanged();
  assert.equal(h.element('releaseFeedEnable').disabled, true);
  assert.equal(vm.runInContext('releaseFeedClient.status', h.context), null);
});

test('enable needs a separate review and posts only the captured CAS revision', async () => {
  const h = harness();
  let changed = false;
  h.setFetchHook((url, options) => Promise.resolve(
    options.method === 'POST' ? (changed = true, reply(200, snapshot({ enabled: true,
      key_id: 'sovagrid-2026-10', timer_enabled: true, timer_active: true,
      state_revision: 'd'.repeat(64) }))) : reply(200, snapshot())));
  await h.context.releaseFeedRefresh(true);
  h.element('releaseFeedEnable').listeners.get('click')();
  assert.equal(h.element('releaseFeedReview').hidden, false);
  assert.equal(h.element('releaseFeedApply').disabled, true);
  assert.equal(h.calls.length, 1);
  h.element('releaseFeedConfirm').checked = true;
  h.element('releaseFeedConfirm').listeners.get('change')();
  assert.equal(h.element('releaseFeedApply').disabled, false);
  await h.context.releaseFeedApply();
  assert.equal(changed, true);
  assert.equal(h.calls.length, 2);
  assert.equal(h.calls[1].url, 'https://hub.example/api/v1/release-feed/enable');
  assert.deepEqual(JSON.parse(h.calls[1].options.body), { expected_state: revision });
  assert.equal(h.element('releaseFeedBadge').textContent, 'Включено');
  assert.equal(h.element('releaseFeedDisable').disabled, false);
  assert.equal(h.element('releaseFeedReview').hidden, true);
});

test('stale CAS and Hub-only refusal give precise guidance without retrying POST', async () => {
  for (const code of ['STATE_CHANGED', 'HUB_ONLY_UNSUPPORTED']) {
    const h = harness(); let posts = 0;
    h.setFetchHook((_url, options) => {
      if (options.method === 'POST') { posts++; return Promise.resolve(reply(409, { error: code })); }
      return Promise.resolve(reply(200, snapshot()));
    });
    await h.context.releaseFeedRefresh(true);
    h.context.releaseFeedReview('enable');
    h.element('releaseFeedConfirm').checked = true;
    await h.context.releaseFeedApply();
    assert.equal(posts, 1);
    assert.equal(h.element('releaseFeedReview').hidden, true);
    assert.match(h.element('releaseFeedError').textContent,
      code === 'STATE_CHANGED' ? /изменилось/ : /только Hub/);
    if (code === 'HUB_ONLY_UNSUPPORTED') assert.equal(h.element('releaseFeedEnable').disabled, true);
  }
});

test('missing signed feed is reported honestly and does not claim activation', async () => {
  const h = harness();
  h.setFetchHook((_url, options) => Promise.resolve(options.method === 'POST'
    ? reply(503, { error: 'FEED_UNAVAILABLE' }) : reply(200, snapshot())));
  await h.context.releaseFeedRefresh(true);
  h.context.releaseFeedReview('enable');
  h.element('releaseFeedConfirm').checked = true;
  await h.context.releaseFeedApply();
  await new Promise(setImmediate);
  assert.match(h.element('releaseFeedError').textContent, /Результат операции не подтверждён/);
  assert.equal(h.element('releaseFeedBadge').textContent, 'Выключено');
  assert.equal(h.element('releaseFeedEnable').disabled, false);
});

test('untrusted metadata and missing trust never enable the action', async () => {
  const h = harness();
  h.setFetchHook(() => Promise.resolve(reply(200, snapshot({ available_keys: {} }))));
  await h.context.releaseFeedRefresh(true);
  assert.equal(h.element('releaseFeedEnable').disabled, true);
  assert.match(h.element('releaseFeedNotice').textContent, /Нет доверенного ключа/);
  h.setFetchHook(() => Promise.resolve(reply(200, snapshot({
    available_keys: { '<script>': key },
  }))));
  await h.context.releaseFeedRefresh(true);
  assert.equal(h.element('releaseFeedBadge').textContent, 'Нет данных');
  assert.equal(h.element('releaseFeedEnable').disabled, true);
  assert.match(h.element('releaseFeedError').textContent, /Не удалось проверить/);
  assert.equal(h.calls.filter(({ options }) => options.method === 'POST').length, 0);
});

test('unknown POST result requires a fresh status check before another attempt', async () => {
  const h = harness(); let reads = 0;
  h.setFetchHook((_url, options) => {
    if (options.method === 'POST') return Promise.reject(new Error('offline'));
    reads++;
    return reads === 1 ? Promise.resolve(reply(200, snapshot())) : Promise.reject(new Error('offline'));
  });
  await h.context.releaseFeedRefresh(true);
  h.context.releaseFeedReview('enable');
  h.element('releaseFeedConfirm').checked = true;
  await h.context.releaseFeedApply();
  await new Promise(setImmediate);
  assert.match(h.element('releaseFeedError').textContent, /Результат операции не подтверждён/);
  assert.equal(h.element('releaseFeedEnable').disabled, true);
  assert.equal(h.calls.filter(({ options }) => options.method === 'POST').length, 1);
});

test('logout discards a pending response and panel contains no credential input', async () => {
  const h = harness(); let release;
  h.setFetchHook(() => new Promise((resolve) => { release = resolve; }));
  const pending = h.context.releaseFeedRefresh(true);
  h.context.releaseFeedReset();
  release(reply(200, snapshot()));
  await pending;
  assert.equal(vm.runInContext('releaseFeedClient.status', h.context), null);
  const html = fs.readFileSync('index.html', 'utf8');
  const section = html.match(/<section id="releaseFeedPanel"[\s\S]*?<\/section>/)?.[0];
  assert.ok(section);
  assert.match(section, /data-global-admin-only/);
  assert.doesNotMatch(section, /type="(?:text|password)"/);
  assert.match(fs.readFileSync('sw.js', 'utf8'), /"\/updates\.js\?v=1"/);
  assert.match(fs.readFileSync('Dockerfile', 'utf8'), /updates\.js updates\.css/);
});

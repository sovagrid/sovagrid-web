/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const GRANT = 'A'.repeat(43);

function harness(url, broker = { grant: GRANT }, hub = {
  token: 'private-session',
  user: { id: 'admin-id', username: 'admin', role: 'admin', enabled: true },
}) {
  const location = new URL(url);
  const elements = new Map();
  const storage = new Map();
  const calls = [];
  const removed = [];
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      value: '', hidden: false, disabled: false, textContent: '',
      addEventListener() {}, setAttribute() {}, replaceChildren() {},
    });
    return elements.get(id);
  };
  const context = vm.createContext({
    URL, AbortController, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: {
      getItem: (key) => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value),
      removeItem: (key) => storage.delete(key),
    },
    location, navigator: {},
    history: { state: null, replaceState(_state, _unused, path) { removed.push(path); location.hash = ''; } },
    fetch: async (target, options) => {
      calls.push({ target, options });
      if (String(target).endsWith('/grant')) return { ok: broker !== null, json: async () => broker };
      return { ok: hub !== null, status: hub === null ? 403 : 200,
        text: async () => JSON.stringify(hub ?? { error: 'expired' }) };
    },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  context.refresh = async () => {};
  return { context, calls, removed, element, storage,
    pending: vm.runInContext('sshBootstrapPending', context) };
}

test('SSH handoff clears fragment before network work and enters the local Hub without storing credentials', async () => {
  const h = harness('http://127.0.0.1:49152/#sg-bootstrap=49310');
  assert.deepEqual(h.removed, ['/']);
  assert.equal(h.element('loginButton').disabled, true);
  await h.pending;
  assert.equal(h.calls.length, 2);
  assert.equal(h.calls[0].target, 'http://127.0.0.1:49310/grant');
  assert.equal(h.calls[0].options.credentials, 'omit');
  assert.equal(h.calls[0].options.cache, 'no-store');
  assert.equal(h.calls[0].options.mode, 'cors');
  assert.equal(h.calls[1].target, 'http://127.0.0.1:49152/api/v1/session/ssh-grant');
  assert.equal(h.calls[1].options.method, 'POST');
  assert.equal(h.calls[1].options.body, JSON.stringify({ grant: GRANT }));
  assert.equal(h.element('loginView').hidden, true);
  assert.equal(h.element('appView').hidden, false);
  assert.equal(h.element('sessionIdentity').textContent, 'admin · Администратор');
  assert.equal(h.element('loginButton').disabled, false);
  assert.equal(h.storage.size, 0);
  assert.ok(!JSON.stringify(h.removed).includes(GRANT));
});

test('expired or malformed grants leave the password form usable', async () => {
  for (const broker of [null, { grant: 'short' }, { grant: GRANT, unexpected: 1 }]) {
    const h = harness('http://127.0.0.1:49152/#sg-bootstrap=49310', broker);
    await h.pending;
    assert.equal(h.element('loginView').hidden, false);
    assert.equal(h.element('loginButton').disabled, false);
    assert.match(h.element('loginNotice').textContent, /локальному паролю/);
    assert.equal(h.calls.some((call) => String(call.target).includes('/api/v1/session/ssh-grant')), false);
  }
  const h = harness('http://127.0.0.1:49152/#sg-bootstrap=49310', null);
  await h.pending;
  assert.equal(h.element('hubUrl').value, 'http://127.0.0.1:49152');
  h.element('username').value = 'admin';
  h.element('password').value = 'local-password';
  await h.context.login({ preventDefault() {} });
  assert.equal(h.element('appView').hidden, false);
  assert.equal(h.element('password').value, '');
});

test('hostile origin and invalid port cannot request a local SSH grant', async () => {
  for (const url of [
    'https://panel.example/#sg-bootstrap=49310',
    'http://localhost:49152/#sg-bootstrap=49310',
    'http://127.0.0.1:49152/#sg-bootstrap=0',
    'http://127.0.0.1:49152/#sg-bootstrap=65536',
    'http://127.0.0.1:49152/#sg-bootstrap=49310%26x',
  ]) {
    const h = harness(url);
    await h.pending;
    assert.equal(h.calls.length, 0, url);
    assert.equal(h.removed.length, 1, url);
    assert.equal(h.element('loginButton').disabled, false, url);
  }
});

test('an older Hub without SSH grant redemption keeps manual login available', async () => {
  const h = harness('http://127.0.0.1:49152/#sg-bootstrap=49310', { grant: GRANT }, null);
  await h.pending;
  assert.equal(h.calls.length, 2);
  assert.equal(h.element('loginView').hidden, false);
  assert.equal(h.element('loginButton').disabled, false);
  assert.match(h.element('loginNotice').textContent, /локальному паролю/);
});

test('a native WebView may redeem a validated SSH grant in memory on its loopback panel', async () => {
  const h = harness('http://127.0.0.1:49152/');
  assert.equal(await h.context.sovagridRedeemNativeSSHGrant(GRANT), true);
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].target, 'http://127.0.0.1:49152/api/v1/session/ssh-grant');
  assert.equal(h.calls[0].options.body, JSON.stringify({ grant: GRANT }));
  assert.equal(h.element('appView').hidden, false);
  assert.equal(h.storage.size, 0);
  assert.equal(await h.context.sovagridRedeemNativeSSHGrant(GRANT), false);
  assert.equal(h.calls.length, 1);
});

test('native grants are rejected off loopback or with an invalid value', async () => {
  for (const [origin, grant] of [
    ['https://panel.example/', GRANT], ['http://localhost:49152/', GRANT],
    ['http://127.0.0.1:49152/', 'short'],
  ]) {
    const h = harness(origin);
    assert.equal(await h.context.sovagridRedeemNativeSSHGrant(grant), false);
    assert.equal(h.calls.length, 0);
    assert.equal(h.element('appView').hidden, false);
  }
  const failed = harness('http://127.0.0.1:49152/', { grant: GRANT }, null);
  assert.equal(await failed.context.sovagridRedeemNativeSSHGrant(GRANT), false);
  assert.equal(failed.element('loginButton').disabled, false);
  assert.match(failed.element('loginNotice').textContent, /локальному паролю/);
});

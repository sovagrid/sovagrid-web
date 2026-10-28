/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const FINGERPRINT = `SHA256:${'A'.repeat(43)}`;
const CHANGED = `SHA256:${'B'.repeat(43)}`;
const TOKEN = 't'.repeat(43);
const hostKey = (fingerprint = FINGERPRINT) => ({ protocol: 1, scope: 'entered_target',
  host: 'server.example', port: 22, key_type: 'ssh-ed25519', fingerprint, reverify_required: true });
const status = (kind = 'missing', fingerprint = FINGERPRINT) => ({ protocol: 1, scope: 'entered_target',
  host: 'server.example', port: 22, kind, host_key_fingerprint: fingerprint });
const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };

function harness({ page = 'https://panel.example/sovagrid/monitoring/', base = 'https://panel.example',
  role = 'admin', unrestricted = true, savedPin = null, fingerprint = FINGERPRINT,
  statusReply = status(), hostKeyReply = null, statusError = null } = {}) {
  const elements = new Map(), calls = [], storage = new Map(), documentListeners = new Map();
  const location = new URL(page);
  if (savedPin) storage.set(`sovagrid.target-ssh-host-key:${location.origin}:server.example:22`, savedPin);
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { value: '', textContent: '', hidden: false, disabled: false,
        checked: id === 'serverSetupAuthPassword', files: [], open: false, listeners,
        addEventListener(name, handler) { listeners.set(name, handler); },
        setAttribute(name, value) { this[name] = value; }, focus() {},
        showModal() { this.open = true; },
        close() { this.open = false; listeners.get('close')?.({}); },
        replaceChildren() {}, append() {},
      });
    }
    return elements.get(id);
  };
  const document = { hidden: false, getElementById: element, createElement: () => element(Symbol()),
    querySelectorAll: () => [], addEventListener(name, handler) { documentListeners.set(name, handler); },
    body: { append() {} } };
  const context = vm.createContext({
    URL, AbortController, TextEncoder, TextDecoder, Uint8Array, btoa, atob,
    setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    location, navigator: {}, confirm: () => true,
    document,
    localStorage: { getItem: (key) => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value), removeItem: (key) => storage.delete(key) },
    fetch: async (path, options) => {
      calls.push({ path, options, secretAtFetch: element('serverSetupPassword').value,
        keyAtFetch: element('serverSetupPrivateKey').value,
        phraseAtFetch: element('serverSetupPassphrase').value });
      const probe = path === '/api/v1/browser-ssh/target-host-key';
      const reply = probe ? (hostKeyReply ?? hostKey(fingerprint)) : statusError?.body ?? statusReply;
      return { ok: probe || !statusError, status: probe ? 200 : statusError?.code ?? 200,
        json: async () => reply, text: async () => JSON.stringify(reply) };
    },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  state.base = base; state.token = TOKEN;
  state.user = { username: 'admin', role, enabled: true };
  state.access = { mode: 'all', unrestricted_admin: unrestricted, revision: 1 };
  context.openAddServer();
  element('serverSetupHost').value = 'server.example';
  element('serverSetupPort').value = '22';
  return { context, state, element, calls, storage, document, documentListeners };
}

test('add-server dialog has guided SSH path and separate manual Agent registration', () => {
  const html = fs.readFileSync('index.html', 'utf8');
  const shell = fs.readFileSync('sw.js', 'utf8');
  assert.match(html, /id="serverSetupSshTab"/);
  assert.match(html, /id="serverSetupAgentTab"/);
  assert.match(html, /id="serverSetupTrust"/);
  assert.match(html, /id="addServerForm"/);
  assert.match(html, /Проверить состояние без изменений/);
  assert.doesNotMatch(html, /id="serverSetupInstall"/);
  assert.match(html, /app\.js\?v=47/);
  assert.match(shell, /app\.js\?v=47/);
  assert.match(html, /styles\.css\?v=36/);
  assert.match(shell, /styles\.css\?v=36/);
});

test('manual Agent tab remains available and closing the dialog discards SSH credentials', async () => {
  const h = harness();
  assert.equal(h.element('serverSetupSshPanel').hidden, false);
  h.element('serverSetupAgentTab').listeners.get('click')();
  assert.equal(h.element('serverSetupSshPanel').hidden, true);
  assert.equal(h.element('serverSetupAgentPanel').hidden, false);
  assert.equal(h.element('serverSetupAgentTab')['aria-selected'], 'true');
  assert.equal(typeof h.element('addServerForm').listeners.get('submit'), 'function');
  h.element('serverSetupSshTab').listeners.get('click')();
  await h.context.serverSetupInspect();
  h.element('serverSetupPassword').value = 'temporary';
  h.element('addServerDialog').close();
  assert.equal(h.element('serverSetupPassword').value, '');
  assert.equal(h.element('serverSetupReview').hidden, true);
  assert.equal(h.element('serverSetupHost').value, '');
});

test('hiding the page clears typed SSH secrets while retaining the reviewed public key', async () => {
  const h = harness();
  await h.context.serverSetupInspect();
  h.element('serverSetupPassword').value = 'temporary';
  h.element('serverSetupPassphrase').value = 'phrase';
  h.document.hidden = true;
  h.documentListeners.get('visibilitychange')();
  assert.equal(h.element('serverSetupPassword').value, '');
  assert.equal(h.element('serverSetupPassphrase').value, '');
  assert.equal(h.element('serverSetupFingerprint').textContent, FINGERPRINT);
  assert.equal(h.element('serverSetupReview').hidden, false);
});

test('SSH status requires fingerprint consent and clears password before same-origin request', async () => {
  const h = harness();
  assert.equal(h.element('serverSetupStatusButton').disabled, true);
  await h.context.serverSetupInspect();
  assert.equal(h.calls[0].path, '/api/v1/browser-ssh/target-host-key');
  assert.deepEqual(JSON.parse(h.calls[0].options.body), { host: 'server.example', port: 22 });
  assert.equal(h.calls[0].options.credentials, 'omit');
  assert.equal(h.calls[0].options.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(h.element('serverSetupFingerprint').textContent, FINGERPRINT);
  assert.equal(h.element('serverSetupStatusButton').disabled, true);
  h.element('serverSetupTrust').checked = true;
  h.context.serverSetupRender();
  h.element('serverSetupUsername').value = 'root';
  h.element('serverSetupPassword').value = 'temporary SSH password';
  await h.context.serverSetupStatus({ preventDefault() {} });
  assert.equal(h.calls[1].path, '/api/v1/browser-ssh/target-status');
  assert.equal(h.calls[1].secretAtFetch, '');
  assert.equal(h.calls[1].options.credentials, 'omit');
  assert.deepEqual(JSON.parse(h.calls[1].options.body), { host: 'server.example', port: 22,
    username: 'root', method: 'password', fingerprint: FINGERPRINT,
    password: 'temporary SSH password', private_key: '', passphrase: '' });
  assert.equal(h.element('serverSetupPassword').value, '');
  assert.equal(h.element('serverSetupResult').hidden, false);
  assert.match(h.element('serverSetupResultTitle').textContent, /не обнаружен/);
  assert.deepEqual([...h.storage.entries()],
    [[`sovagrid.target-ssh-host-key:${h.context.location.origin}:server.example:22`, FINGERPRINT]]);
});

test('private-key status clears file and passphrase and labels agent-only result', async () => {
  const h = harness({ statusReply: status('agent_only') });
  await h.context.serverSetupInspect();
  h.element('serverSetupTrust').checked = true;
  h.element('serverSetupAuthPassword').checked = false;
  h.element('serverSetupAuthKey').checked = true;
  h.element('serverSetupUsername').value = 'ubuntu';
  h.element('serverSetupPrivateKey').files = [{ size: 30, text: async () => 'PRIVATE KEY' }];
  h.element('serverSetupPrivateKey').value = '/fake/key';
  h.element('serverSetupPassphrase').value = 'phrase';
  await h.context.serverSetupStatus({ preventDefault() {} });
  assert.deepEqual(JSON.parse(h.calls[1].options.body), { host: 'server.example', port: 22,
    username: 'ubuntu', method: 'private_key', fingerprint: FINGERPRINT,
    password: '', private_key: 'PRIVATE KEY', passphrase: 'phrase' });
  assert.equal(h.calls[1].keyAtFetch, '');
  assert.equal(h.calls[1].phraseAtFetch, '');
  assert.equal(h.element('serverSetupPrivateKey').value, '');
  assert.equal(h.element('serverSetupPassphrase').value, '');
  assert.match(h.element('serverSetupResultTitle').textContent, /Agent/);
});

test('remote Hub, plain remote HTTP and limited admin cannot inspect another server', async () => {
  for (const options of [
    { base: 'https://elsewhere.example' },
    { page: 'http://panel.example/sovagrid/monitoring/', base: 'http://panel.example' },
    { role: 'viewer' }, { unrestricted: false },
  ]) {
    const h = harness(options);
    await h.context.serverSetupInspect();
    assert.equal(h.calls.length, 0);
    assert.equal(h.element('serverSetupInspect').disabled, true);
    assert.equal(h.element('serverSetupStatusButton').disabled, true);
    assert.equal(h.element('serverSetupNotice').hidden, false);
  }
});

test('changed SSH key blocks status until independent replacement consent', async () => {
  const h = harness({ savedPin: FINGERPRINT, fingerprint: CHANGED, statusReply: status('managed', CHANGED) });
  await h.context.serverSetupInspect();
  h.element('serverSetupTrust').checked = true;
  h.context.serverSetupRender();
  assert.equal(h.element('serverSetupStatusButton').disabled, true);
  await h.context.serverSetupStatus({ preventDefault() {} });
  assert.equal(h.calls.length, 1);
  h.element('serverSetupReplaceKey').listeners.get('click')();
  assert.equal(h.element('serverSetupTrust').checked, false);
  h.element('serverSetupTrust').checked = true;
  h.element('serverSetupUsername').value = 'root';
  h.element('serverSetupPassword').value = 'password';
  await h.context.serverSetupStatus({ preventDefault() {} });
  assert.equal(h.calls.length, 2);
  assert.equal(h.storage.get('sovagrid.target-ssh-host-key:https://panel.example:server.example:22'), CHANGED);
  assert.match(h.element('serverSetupResultText').textContent, /не добавил сервер/);
});

test('target change during asynchronous key read drops stale status and clears secrets', async () => {
  const h = harness();
  await h.context.serverSetupInspect();
  const read = deferred();
  h.element('serverSetupTrust').checked = true;
  h.element('serverSetupAuthPassword').checked = false;
  h.element('serverSetupAuthKey').checked = true;
  h.element('serverSetupUsername').value = 'root';
  h.element('serverSetupPrivateKey').files = [{ size: 20, text: () => read.promise }];
  h.element('serverSetupPrivateKey').value = '/fake/key';
  const pending = h.context.serverSetupStatus({ preventDefault() {} });
  h.element('serverSetupHost').value = 'changed.example';
  h.element('serverSetupHost').listeners.get('input')();
  read.resolve('PRIVATE KEY');
  await pending;
  assert.equal(h.calls.length, 1);
  assert.equal(h.element('serverSetupPrivateKey').value, '');
  assert.equal(h.element('serverSetupReview').hidden, true);
  assert.equal(h.element('serverSetupResult').hidden, true);
});

test('malformed status response and unsupported SSH method do not pin or claim enrollment', async () => {
  for (const options of [
    { statusReply: { ...status(), host: 'wrong.example' } },
    { statusError: { code: 422, body: { error: 'UNSUPPORTED_AUTH_METHOD' } } },
  ]) {
    const h = harness(options);
    await h.context.serverSetupInspect();
    h.element('serverSetupTrust').checked = true;
    h.element('serverSetupUsername').value = 'root';
    h.element('serverSetupPassword').value = 'password';
    await h.context.serverSetupStatus({ preventDefault() {} });
    assert.equal(h.element('serverSetupResult').hidden, true);
    assert.equal(h.element('serverSetupError').hidden, false);
    assert.equal(h.storage.size, 0);
    assert.equal(h.element('serverSetupPassword').value, '');
  }
});

test('SSH key change during authentication forces a fresh host-key inspection', async () => {
  const h = harness({ statusError: { code: 409, body: { error: 'HOST_KEY_CHANGED' } } });
  await h.context.serverSetupInspect();
  h.element('serverSetupTrust').checked = true;
  h.element('serverSetupUsername').value = 'root';
  h.element('serverSetupPassword').value = 'password';
  await h.context.serverSetupStatus({ preventDefault() {} });
  assert.equal(h.calls.length, 2);
  assert.equal(h.element('serverSetupReview').hidden, true);
  assert.equal(h.element('serverSetupStatusButton').disabled, true);
  assert.match(h.element('serverSetupError').textContent, /Ключ SSH изменился/);
  assert.equal(h.storage.size, 0);
});

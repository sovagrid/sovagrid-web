/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const FP = `SHA256:${'A'.repeat(43)}`;
const OTHER_FP = `SHA256:${'B'.repeat(43)}`;
const TOKEN = 't'.repeat(43);
const SID = 'session_1234567890';
const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };
async function until(predicate) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (predicate()) return;
    await new Promise(setImmediate);
  }
  assert.fail('direct SSH step did not finish');
}

function harness({ page = 'https://panel.example/sovagrid/monitoring/', base = 'https://panel.example',
  role = 'admin', unrestricted = true, storageAvailable = true,
  openFingerprint = FP, openReply = null, eventsReply = null } = {}) {
  const elements = new Map(), calls = [], terminals = [], storage = new Map();
  const location = new URL(page);
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { value: '', type: 'text', textContent: '', hidden: false, disabled: false,
        checked: id === 'serverSetupAuthPassword', files: [], open: false, listeners, children: [],
        classList: { toggle() {} }, style: {}, dataset: {},
        addEventListener(name, handler) { listeners.set(name, handler); },
        setAttribute(name, value) { this[name] = value; }, focus() {},
        showModal() { this.open = true; },
        close() { this.open = false; listeners.get('close')?.({}); },
        replaceChildren(...children) { this.children = children; },
        append(...children) { this.children.push(...children); },
        getBoundingClientRect() { return { width: 800 }; },
      });
    }
    return elements.get(id);
  };
  const document = { hidden: false, getElementById: element, createElement: () => element(Symbol()),
    querySelectorAll: () => [], addEventListener() {}, body: { append() {} } };
  class Terminal {
    constructor() { this.cols = 80; this.rows = 24; this.writes = []; this.options = {}; terminals.push(this); }
    loadAddon() {} open() {} focus() {} dispose() { this.disposed = true; }
    onData(handler) { this.input = handler; }
    write(bytes) { this.writes.push(Buffer.from(bytes).toString()); }
  }
  class FitAddon { fit() {} }
  let fetchHook = null;
  const context = vm.createContext({ URL, AbortController, TextEncoder, TextDecoder, Uint8Array,
    btoa, atob, Terminal, FitAddon: { FitAddon },
    setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    location, navigator: {}, confirm: () => true, document,
    localStorage: { getItem: (key) => {
      if (!storageAvailable && key.startsWith('sovagrid.target-ssh-host-key:'))
        throw new Error('storage unavailable');
      return storage.get(key) ?? null;
    }, setItem: (key, value) => {
      if (!storageAvailable) throw new Error('storage unavailable');
      storage.set(key, value);
    }, removeItem: (key) => storage.delete(key) },
    fetch: async (path, options) => {
      calls.push({ path, options, passwordAtFetch: element('serverSetupPassword').value,
        keyAtFetch: element('serverSetupPrivateKey').value });
      if (fetchHook) return fetchHook(path, options);
      let reply;
      if (path === '/api/v1/browser-ssh/target-host-key')
        reply = { protocol: 1, scope: 'entered_target', host: 'server.example', port: 22,
          key_type: 'ssh-ed25519', fingerprint: FP, reverify_required: true };
      else if (path.endsWith('/direct-terminal/open'))
        reply = openReply ?? { session_id: SID, next_cursor: 0,
          host_key_fingerprint: openFingerprint, expires_at: 1234567890 };
      else if (path.endsWith('/direct-terminal/events'))
        reply = eventsReply ?? { events: [], next_cursor: 0, closed: false };
      else if (path.endsWith('/direct-terminal/input') || path.endsWith('/direct-terminal/resize'))
        reply = { accepted: true };
      else if (path.endsWith('/direct-terminal/close')) reply = { closed: true };
      else if (path === '/api/v1/browser-ssh/agent/list') reply = [];
      else throw new Error(`unexpected path ${path}`);
      return { ok: true, status: 200, json: async () => reply };
    },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('direct-ssh.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  state.base = base; state.token = TOKEN;
  state.user = { username: 'admin', role, enabled: true };
  state.access = { mode: 'all', unrestricted_admin: unrestricted, revision: 1 };
  context.openAddServer();
  element('serverSetupHost').value = 'server.example';
  element('serverSetupPort').value = '22';
  return { context, state, element, calls, terminals, storage,
    setFetchHook(hook) { fetchHook = hook; } };
}

async function reviewed(h) {
  await h.context.serverSetupInspect();
  h.element('serverSetupTrust').checked = true;
  h.element('serverSetupUsername').value = 'ubuntu';
  h.context.serverSetupRender();
}

test('direct terminal is offered after trusted host-key review and only to an unrestricted admin', async () => {
  const html = fs.readFileSync('index.html', 'utf8');
  const sw = fs.readFileSync('sw.js', 'utf8');
  assert.match(html, /id="serverSetupDirectTerminalButton"/);
  assert.match(html, /id="directSshScreen"/);
  assert.match(html, /direct-ssh\.js\?v=2/);
  assert.match(sw, /direct-ssh\.js\?v=2/);
  assert.match(sw, /direct-ssh\.css\?v=1/);
  const h = harness();
  assert.equal(h.element('serverSetupDirectTerminalButton').disabled, true);
  await reviewed(h);
  assert.equal(h.element('serverSetupDirectTerminalButton').disabled, false);
  h.element('addServerDialog').close();
  for (const settings of [{ role: 'viewer' }, { unrestricted: false },
    { page: 'http://panel.example/sovagrid/monitoring/', base: 'http://panel.example' },
    { base: 'https://elsewhere.example' }]) {
    const denied = harness(settings);
    await reviewed(denied);
    assert.equal(denied.element('serverSetupDirectTerminalButton').disabled, true);
    denied.element('addServerDialog').close();
  }
});

test('password opens a pinned SSH terminal, streams output, sends mobile input, and closes on dialog exit', async () => {
  const h = harness();
  const waiting = deferred();
  let polls = 0;
  h.setFetchHook(async (path) => {
    if (path === '/api/v1/browser-ssh/target-host-key')
      return { ok: true, status: 200, json: async () => ({ protocol: 1, scope: 'entered_target',
        host: 'server.example', port: 22, key_type: 'ssh-ed25519', fingerprint: FP, reverify_required: true }) };
    if (path === '/api/v1/browser-ssh/agent/list') return { ok: true, status: 200, json: async () => [] };
    if (path.endsWith('/direct-terminal/open')) return { ok: true, status: 200,
      json: async () => ({ session_id: SID, next_cursor: 0, host_key_fingerprint: FP }) };
    if (path.endsWith('/direct-terminal/events')) {
      polls++;
      if (polls > 1) return waiting.promise;
      return { ok: true, status: 200, json: async () => ({ events: [{ cursor: 1,
        data: Buffer.from('hello\r\n').toString('base64') }], next_cursor: 1, closed: false }) };
    }
    if (path.endsWith('/direct-terminal/input') || path.endsWith('/direct-terminal/resize'))
      return { ok: true, status: 200, json: async () => ({ accepted: true }) };
    if (path.endsWith('/direct-terminal/close'))
      return { ok: true, status: 200, json: async () => ({ closed: true }) };
    throw new Error(path);
  });
  await reviewed(h);
  h.element('serverSetupPassword').value = 'secret';
  await h.context.directSshOpen();
  await until(() => h.terminals[0].writes.length === 1);
  assert.equal(h.element('serverSetupPassword').value, '');
  assert.equal(h.element('directSshPanel').hidden, false);
  assert.equal(h.element('serverSetupStatusForm').hidden, true);
  const openCall = h.calls.find((call) => call.path.endsWith('/direct-terminal/open'));
  assert.equal(openCall.passwordAtFetch, '');
  assert.deepEqual(JSON.parse(openCall.options.body), { host: 'server.example', port: 22,
    username: 'ubuntu', method: 'password', fingerprint: FP, password: 'secret', private_key: '',
    passphrase: '', cols: 80, rows: 24 });
  assert.equal(openCall.options.credentials, 'omit');
  assert.equal(openCall.options.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(h.terminals[0].writes[0], 'hello\r\n');
  assert.equal(h.storage.get('sovagrid.target-ssh-host-key:https://panel.example:server.example:22'), FP);
  h.element('directSshLine').value = 'ls -la';
  h.context.directSshSendLine({ preventDefault() {} });
  await until(() => h.calls.some((call) => call.path.endsWith('/direct-terminal/input')));
  const input = h.calls.find((call) => call.path.endsWith('/direct-terminal/input'));
  assert.equal(Buffer.from(JSON.parse(input.options.body).data, 'base64').toString(), 'ls -la\r');
  assert.equal(h.element('directSshLine').value, '');
  h.element('addServerDialog').close();
  assert.equal(h.terminals[0].disposed, true);
  assert.ok(h.calls.some((call) => call.path.endsWith('/direct-terminal/close')));
  waiting.resolve({ ok: true, status: 200, json: async () => ({ events: [], next_cursor: 1, closed: true }) });
});

test('mismatched authenticated host key cannot be pinned or shown as connected', async () => {
  const h = harness({ openFingerprint: OTHER_FP });
  await reviewed(h);
  h.element('serverSetupPassword').value = 'secret';
  await h.context.directSshOpen();
  assert.equal(h.element('directSshPanel').hidden, true);
  assert.equal(h.element('serverSetupPassword').value, '');
  assert.equal(h.storage.size, 0);
  assert.match(h.element('serverSetupError').textContent, /неверный ответ/);
  assert.ok(h.calls.some((call) => call.path.endsWith('/direct-terminal/close')));
  h.element('addServerDialog').close();
});

test('keyboard characters are batched before Enter and sent in order', async () => {
  const h = harness({ eventsReply: { events: [], next_cursor: 0, closed: false } });
  await reviewed(h);
  h.element('serverSetupPassword').value = 'secret';
  await h.context.directSshOpen();
  const term = h.terminals[0];
  term.input('a');
  term.input('b');
  term.input('\r');
  await until(() => h.calls.some((call) => call.path.endsWith('/direct-terminal/input')));
  const inputs = h.calls.filter((call) => call.path.endsWith('/direct-terminal/input'));
  assert.equal(inputs.length, 1);
  assert.equal(Buffer.from(JSON.parse(inputs[0].options.body).data, 'base64').toString(), 'ab\r');
  h.element('addServerDialog').close();
});

test('output reconnect resumes from the last cursor without repeating input', async () => {
  const h = harness();
  const cursors = [];
  h.setFetchHook(async (path, options) => {
    if (path === '/api/v1/browser-ssh/agent/list') return { ok: true, status: 200, json: async () => [] };
    if (path === '/api/v1/browser-ssh/target-host-key') return { ok: true, status: 200,
      json: async () => ({ protocol: 1, scope: 'entered_target', host: 'server.example', port: 22,
        key_type: 'ssh-ed25519', fingerprint: FP, reverify_required: true }) };
    if (path.endsWith('/direct-terminal/open')) return { ok: true, status: 200,
      json: async () => ({ session_id: SID, next_cursor: 0, host_key_fingerprint: FP }) };
    if (path.endsWith('/direct-terminal/events')) {
      const cursor = JSON.parse(options.body).cursor;
      cursors.push(cursor);
      if (cursors.length === 2) throw new Error('network unavailable');
      return { ok: true, status: 200, json: async () => cursors.length === 1 ? {
        events: [{ cursor: 1, data: Buffer.from('one').toString('base64') }],
        next_cursor: 1, closed: false } : {
        events: [{ cursor: 2, data: Buffer.from('two').toString('base64') }],
        next_cursor: 2, closed: true, reason: 'REMOTE_CLOSED' } };
    }
    if (path.endsWith('/direct-terminal/close')) return { ok: true, status: 200,
      json: async () => ({ closed: true }) };
    throw new Error(path);
  });
  await reviewed(h);
  h.element('serverSetupPassword').value = 'secret';
  await h.context.directSshOpen();
  await until(() => vm.runInContext('directSSH.phase', h.context) === 'disconnected');
  h.context.directSshReconnect();
  await until(() => vm.runInContext('directSSH.phase', h.context) === 'closed');
  assert.deepEqual(cursors, [0, 1, 1]);
  assert.deepEqual(h.terminals[0].writes, ['one', 'two']);
  assert.equal(h.calls.filter((call) => call.path.endsWith('/direct-terminal/input')).length, 0);
  h.element('addServerDialog').close();
});

test('selected key file is cleared and lost admin access closes the running session', async () => {
  const h = harness({ eventsReply: { events: [], next_cursor: 0, closed: false } });
  await reviewed(h);
  h.element('serverSetupAuthPassword').checked = false;
  h.element('serverSetupAuthKey').checked = true;
  h.element('serverSetupPrivateKey').files = [{ size: 20, text: async () => 'PRIVATE KEY' }];
  h.element('serverSetupPrivateKey').value = '/fake/key';
  h.element('serverSetupPassphrase').value = 'phrase';
  await h.context.directSshOpen();
  const openCall = h.calls.find((call) => call.path.endsWith('/direct-terminal/open'));
  assert.equal(openCall.keyAtFetch, '');
  assert.equal(JSON.parse(openCall.options.body).private_key, 'PRIVATE KEY');
  assert.equal(h.element('serverSetupPrivateKey').value, '');
  assert.equal(h.element('serverSetupPassphrase').value, '');
  h.state.access.unrestricted_admin = false;
  h.context.sovagridDirectSSH.accessChanged();
  assert.equal(h.element('directSshPanel').hidden, true);
  assert.equal(h.element('serverSetupDirectTerminalButton').disabled, true);
  assert.equal(h.terminals[0].disposed, true);
  h.element('addServerDialog').close();
});

test('device-generated SSH key opens the terminal only after download and is cleared afterward', async () => {
  const h = harness({ eventsReply: { events: [], next_cursor: 0, closed: true } });
  const cleared = [];
  h.context.sovagridSSHKeygen = { get: (name) => name === 'setup' ? {
    privateKey: 'GENERATED PRIVATE KEY', revision: 1, downloadRequested: true } : null,
  clear: (name) => cleared.push(name) };
  await reviewed(h);
  h.element('serverSetupAuthPassword').checked = false;
  h.element('serverSetupAuthKey').checked = true;
  await h.context.directSshOpen();
  const open = h.calls.find((call) => call.path.endsWith('/direct-terminal/open'));
  assert.equal(JSON.parse(open.options.body).private_key, 'GENERATED PRIVATE KEY');
  assert.ok(cleared.includes('setup'));
  h.element('addServerDialog').close();
});

test('opening response arriving after logout cannot attach a terminal session', async () => {
  const h = harness();
  const waiting = deferred();
  h.setFetchHook(async (path) => {
    if (path === '/api/v1/browser-ssh/target-host-key')
      return { ok: true, status: 200, json: async () => ({ protocol: 1, scope: 'entered_target',
        host: 'server.example', port: 22, key_type: 'ssh-ed25519', fingerprint: FP, reverify_required: true }) };
    if (path === '/api/v1/browser-ssh/agent/list') return { ok: true, status: 200, json: async () => [] };
    if (path.endsWith('/direct-terminal/open')) return waiting.promise;
    if (path.endsWith('/direct-terminal/close'))
      return { ok: true, status: 200, json: async () => ({ closed: true }) };
    throw new Error(path);
  });
  await reviewed(h);
  h.element('serverSetupPassword').value = 'secret';
  const pending = h.context.directSshOpen();
  await until(() => h.calls.some((call) => call.path.endsWith('/direct-terminal/open')));
  h.context.logout(false);
  waiting.resolve({ ok: true, status: 200, json: async () => ({ session_id: SID,
    next_cursor: 0, host_key_fingerprint: FP }) });
  await pending;
  assert.equal(h.element('directSshPanel').hidden, true);
  assert.equal(h.storage.size, 0);
  assert.equal(h.terminals[0].disposed, true);
  assert.equal(h.element('serverSetupPassword').value, '');
});

test('ProxyJump verifies both host keys, re-enters jump credentials, and opens only the direct terminal', async () => {
  const h = harness();
  const jumpFP = OTHER_FP;
  let waiting = deferred();
  h.setFetchHook(async (path, options) => {
    if (path === '/api/v1/browser-ssh/agent/list') return { ok: true, status: 200, json: async () => [] };
    if (path === '/api/v1/browser-ssh/target-host-key') {
      const body = JSON.parse(options.body);
      if (body.host === 'jump.example') return { ok: true, status: 200, json: async () => ({
        protocol: 1, scope: 'entered_target', host: 'jump.example', port: 22,
        key_type: 'ssh-ed25519', fingerprint: jumpFP, reverify_required: true }) };
      assert.equal(body.host, 'server.example');
      assert.equal(body.jump.host, 'jump.example');
      assert.equal(body.jump.fingerprint, jumpFP);
      return { ok: true, status: 200, json: async () => ({ protocol: 1, scope: 'entered_target',
        host: 'server.example', port: 22, key_type: 'ssh-ed25519', fingerprint: FP,
        jump_host_key_fingerprint: jumpFP, reverify_required: true }) };
    }
    if (path.endsWith('/direct-terminal/open')) return { ok: true, status: 200,
      json: async () => ({ session_id: SID, next_cursor: 0,
        host_key_fingerprint: FP, jump_host_key_fingerprint: jumpFP }) };
    if (path.endsWith('/direct-terminal/events')) return waiting.promise;
    if (path.endsWith('/direct-terminal/resize'))
      return { ok: true, status: 200, json: async () => ({ accepted: true }) };
    if (path.endsWith('/direct-terminal/close'))
      return { ok: true, status: 200, json: async () => ({ closed: true }) };
    throw new Error(path);
  });
  h.element('directSshUseJump').checked = true;
  h.element('directSshUseJump').listeners.get('change')();
  h.element('directSshJumpHost').value = 'jump.example';
  h.element('directSshJumpPort').value = '22';
  assert.equal(h.element('serverSetupInspect').disabled, true);
  await h.context.directSshJumpInspect();
  assert.equal(h.element('directSshJumpFingerprint').textContent, jumpFP);
  h.element('directSshJumpTrust').checked = true;
  h.context.sovagridDirectSSH.render();
  h.element('directSshJumpUsername').value = 'jumpuser';
  h.element('directSshJumpPassword').value = 'jump-first-secret';
  await h.context.serverSetupInspect();
  assert.equal(h.element('serverSetupFingerprint').textContent, FP);
  assert.equal(h.element('directSshJumpPassword').value, '');
  assert.equal(h.storage.get('sovagrid.target-ssh-host-key:https://panel.example:jump.example:22'), jumpFP);
  assert.equal(h.storage.has('sovagrid.target-ssh-host-key:https://panel.example:server.example:22'), false);
  assert.equal(h.element('serverSetupStatusButton').disabled, true);
  assert.equal(h.element('serverSetupInstallPanel').hidden, true);
  h.element('serverSetupTrust').checked = true;
  h.element('serverSetupUsername').value = 'ubuntu';
  h.element('serverSetupPassword').value = 'target-secret';
  h.element('directSshJumpPassword').value = 'jump-second-secret';
  await h.context.directSshOpen();
  const open = h.calls.find((call) => call.path.endsWith('/direct-terminal/open'));
  const body = JSON.parse(open.options.body);
  assert.equal(body.password, 'target-secret');
  assert.equal(body.jump.password, 'jump-second-secret');
  assert.equal(body.jump.fingerprint, jumpFP);
  assert.equal(h.element('serverSetupPassword').value, '');
  assert.equal(h.element('directSshJumpPassword').value, '');
  assert.equal(h.storage.get('sovagrid.target-ssh-host-key:https://panel.example:server.example:22'), FP);
  h.element('addServerDialog').close();
  waiting.resolve({ ok: true, status: 200, json: async () => ({ events: [], next_cursor: 0, closed: true }) });
});

test('ProxyJump Agent setup keeps two pinned keys and separates preview from prepare credentials', async () => {
  const h = harness({ storageAvailable: false });
  const blob = Buffer.from('fixture-public-host-key').toString('base64');
  const jumpFP = OTHER_FP;
  const requestId = '11111111-1111-4111-8111-111111111111';
  h.setFetchHook(async (path, options) => {
    if (path === '/api/v1/browser-ssh/agent/list') return {
      ok: true, status: 200, json: async () => [],
    };
    if (path === '/api/v1/browser-ssh/target-host-key') {
      const body = JSON.parse(options.body);
      return { ok: true, status: 200, json: async () => body.host === 'jump.example' ? {
        protocol: 1, scope: 'entered_target', host: 'jump.example', port: 22,
        key_type: 'ssh-ed25519', fingerprint: jumpFP, host_key_blob: blob,
        reverify_required: true,
      } : {
        protocol: 1, scope: 'entered_target', host: 'server.example', port: 22,
        key_type: 'ssh-ed25519', fingerprint: FP, host_key_blob: blob,
        jump_host_key_fingerprint: jumpFP, reverify_required: true,
      } };
    }
    if (path === '/api/v1/browser-ssh/target-status') return { ok: true, status: 200,
      json: async () => ({ protocol: 1, scope: 'entered_target', host: 'server.example', port: 22,
        host_key_fingerprint: FP, kind: 'missing', jump_host: 'jump.example', jump_port: 22,
        jump_host_key_fingerprint: jumpFP }) };
    if (path === '/api/v1/browser-ssh/target-install-preview') return { ok: true, status: 200,
      json: async () => ({ protocol: 1, action: 'install_preview', writes: false,
        host: 'server.example', port: 22, target_kind: 'missing', hub_route: 'reachable',
        preflight_passed: true, host_key_fingerprint: FP, jump_host: 'jump.example',
        jump_port: 22, jump_host_key_fingerprint: jumpFP }) };
    if (path === '/api/v1/browser-ssh/agent/prepare') return { ok: true, status: 200,
      json: async () => ({ protocol: 1, request_id: requestId, name: 'server.example',
        phase: 'prepared', revision: 1, created_at: 1, updated_at: 2,
        cleanup_required: false, server_id: null, registration_state: null,
        recoverable: true, writes: true, activation_writes: false,
        hub_fingerprint: FP, platform: { ubuntu_version: '24.04', python_version: '3.12',
          systemd_version: '255' }, source_commits: { 'sovagrid-agent': 'a'.repeat(40) } }) };
    throw new Error(path);
  });
  h.element('directSshUseJump').checked = true;
  h.element('directSshUseJump').listeners.get('change')();
  h.element('directSshJumpHost').value = 'jump.example';
  h.element('directSshJumpPort').value = '22';
  await h.context.directSshJumpInspect();
  h.element('directSshJumpTrust').checked = true;
  h.element('directSshJumpUsername').value = 'operator';
  h.element('directSshJumpPassword').value = 'jump-review-secret';
  await h.context.serverSetupInspect();
  h.element('serverSetupTrust').checked = true;
  h.context.serverSetupRender();
  assert.equal(h.element('serverSetupStatusButton').disabled, false);
  h.element('serverSetupUsername').value = 'root';
  h.element('serverSetupPassword').value = 'target-status-secret';
  h.element('directSshJumpPassword').value = 'jump-status-secret';
  await h.context.serverSetupStatus({ preventDefault() {} });
  const statusBody = JSON.parse(h.calls.find((call) => call.path.endsWith('/target-status')).options.body);
  assert.equal(statusBody.password, 'target-status-secret');
  assert.equal(statusBody.jump.password, 'jump-status-secret');
  assert.equal(h.element('serverSetupInstallPanel').hidden, false);
  h.element('serverSetupInstallName').value = 'server.example';
  h.element('serverSetupHubHost').value = '198.51.100.20';
  h.element('serverSetupHubPort').value = '22';
  h.element('serverSetupLocalPort').value = '22023';
  h.element('serverSetupPassword').value = 'target-prepare-secret';
  h.element('directSshJumpPassword').value = 'jump-prepare-secret';
  await h.context.serverSetupPrepare();
  const previewBody = JSON.parse(h.calls.find((call) => call.path.endsWith('/target-install-preview')).options.body);
  const prepareBody = JSON.parse(h.calls.find((call) => call.path.endsWith('/agent/prepare')).options.body);
  assert.equal(previewBody.jump.password, 'jump-prepare-secret');
  assert.equal(previewBody.jump.host_key_blob, undefined);
  assert.equal(previewBody.host_key_blob, undefined);
  assert.equal(prepareBody.password, 'target-prepare-secret');
  assert.equal(prepareBody.jump.password, 'jump-prepare-secret');
  assert.equal(prepareBody.host_key_blob, blob);
  assert.equal(prepareBody.jump.host_key_blob, blob);
  assert.equal(h.element('serverSetupPassword').value, '');
  assert.equal(h.element('directSshJumpPassword').value, '');
});

test('ProxyJump target review rejects a changed jump key and never pins the target', async () => {
  const h = harness();
  h.setFetchHook(async (path, options) => {
    if (path === '/api/v1/browser-ssh/agent/list') return { ok: true, status: 200, json: async () => [] };
    if (path === '/api/v1/browser-ssh/target-host-key') {
      const body = JSON.parse(options.body);
      return { ok: true, status: 200, json: async () => body.host === 'jump.example' ? {
        protocol: 1, scope: 'entered_target', host: 'jump.example', port: 22,
        key_type: 'ssh-ed25519', fingerprint: OTHER_FP, reverify_required: true } : {
        protocol: 1, scope: 'entered_target', host: 'server.example', port: 22,
        key_type: 'ssh-ed25519', fingerprint: FP, jump_host_key_fingerprint: FP,
        reverify_required: true } };
    }
    throw new Error(path);
  });
  h.element('directSshUseJump').checked = true;
  h.element('directSshUseJump').listeners.get('change')();
  h.element('directSshJumpHost').value = 'jump.example';
  h.element('directSshJumpPort').value = '22';
  await h.context.directSshJumpInspect();
  h.element('directSshJumpTrust').checked = true;
  h.element('directSshJumpUsername').value = 'jumpuser';
  h.element('directSshJumpPassword').value = 'secret';
  await h.context.serverSetupInspect();
  assert.equal(h.storage.size, 0);
  assert.equal(h.element('serverSetupReview').hidden, true);
  assert.equal(h.element('serverSetupDirectTerminalButton').disabled, true);
  h.element('addServerDialog').close();
});

test('ProxyJump remains usable in private browsing when host-key storage is unavailable', async () => {
  const h = harness({ storageAvailable: false });
  h.setFetchHook(async (path, options) => {
    if (path === '/api/v1/browser-ssh/agent/list') return { ok: true, status: 200, json: async () => [] };
    if (path === '/api/v1/browser-ssh/target-host-key') {
      const body = JSON.parse(options.body);
      return { ok: true, status: 200, json: async () => body.host === 'jump.example' ? {
        protocol: 1, scope: 'entered_target', host: 'jump.example', port: 22,
        key_type: 'ssh-ed25519', fingerprint: OTHER_FP, reverify_required: true } : {
        protocol: 1, scope: 'entered_target', host: 'server.example', port: 22,
        key_type: 'ssh-ed25519', fingerprint: FP, jump_host_key_fingerprint: OTHER_FP,
        reverify_required: true } };
    }
    if (path.endsWith('/direct-terminal/open')) return { ok: true, status: 200,
      json: async () => ({ session_id: SID, next_cursor: 0,
        host_key_fingerprint: FP, jump_host_key_fingerprint: OTHER_FP }) };
    if (path.endsWith('/direct-terminal/events')) return { ok: true, status: 200,
      json: async () => ({ events: [], next_cursor: 0, closed: true }) };
    if (path.endsWith('/direct-terminal/close')) return { ok: true, status: 200,
      json: async () => ({ closed: true }) };
    throw new Error(path);
  });
  h.element('directSshUseJump').checked = true;
  h.element('directSshUseJump').listeners.get('change')();
  h.element('directSshJumpHost').value = 'jump.example';
  h.element('directSshJumpPort').value = '22';
  await h.context.directSshJumpInspect();
  h.element('directSshJumpTrust').checked = true;
  h.element('directSshJumpUsername').value = 'jumpuser';
  h.element('directSshJumpPassword').value = 'first';
  await h.context.serverSetupInspect();
  h.element('serverSetupTrust').checked = true;
  h.element('serverSetupUsername').value = 'ubuntu';
  h.element('serverSetupPassword').value = 'target';
  h.element('directSshJumpPassword').value = 'second';
  await h.context.directSshOpen();
  assert.ok(h.calls.some((call) => call.path.endsWith('/direct-terminal/open')));
  assert.equal(h.storage.size, 0);
  h.element('addServerDialog').close();
});

/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { randomUUID } = require('node:crypto');
const test = require('node:test');

function harness() {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, {
        textContent: '', value: '', hidden: false, disabled: false, open: false, listeners,
        addEventListener(name, handler) { listeners.set(name, handler); },
        setAttribute() {}, replaceChildren() {},
        showModal() { this.open = true; },
        close() { this.open = false; listeners.get('close')?.({}); },
      });
    }
    return elements.get(id);
  };
  let fetchHook = () => { throw new Error('unexpected fetch'); };
  const context = vm.createContext({
    URL, AbortController, TextEncoder, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    crypto: { randomUUID },
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {} },
    navigator: {}, location: { protocol: 'file:' },
    fetch: (...args) => fetchHook(...args),
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  state.base = 'https://hub.example';
  state.token = 'test-token';
  state.servers = [{ id: 'a', name: 'Server A', online: true, remote_commands_enabled: true }];
  state.selectedId = 'a';
  return { context, state, element, setFetchHook: (hook) => { fetchHook = hook; } };
}

const reply = (status, payload) => ({ ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(payload) });
const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };

test('logout closes one-time token and erases it from the DOM', () => {
  const { context, element } = harness();
  element('agentToken').textContent = 'secret-agent-token';
  element('serverId').textContent = 'server-id';
  element('tokenDialog').showModal();
  element('addServerDialog').showModal();
  context.logout(false);
  assert.equal(element('agentToken').textContent, '');
  assert.equal(element('serverId').textContent, '');
  assert.equal(element('tokenDialog').open, false);
  assert.equal(element('addServerDialog').open, false);
});

test('confirmation rejects a changed server and prevents cancellation during POST', async () => {
  const { context, state, element, setFetchHook } = harness();
  element('commandInput').value = 'uptime';
  context.prepareCommand({ preventDefault() {} });
  assert.match(state.pendingCommandKey, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  state.servers.push({ id: 'b', name: 'Server B', online: true, remote_commands_enabled: true });
  state.selectedId = 'b';
  await context.runCommand();
  assert.match(element('confirmCommandError').textContent, /сервер изменился/);
  state.selectedId = 'a';

  const post = deferred();
  let header;
  setFetchHook((_url, options) => { header = options.headers['Idempotency-Key']; return post.promise; });
  let refreshed = 0;
  context.refresh = async () => { refreshed++; };
  const pending = context.runCommand();
  assert.equal(header, state.pendingCommandKey);
  assert.equal(element('runCommandButton').disabled, true);
  assert.equal(element('cancelCommandButton').disabled, true);
  let prevented = false;
  element('confirmCommandDialog').listeners.get('cancel')({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  element('cancelCommandButton').listeners.get('click')();
  assert.equal(element('confirmCommandDialog').open, true);
  post.resolve(reply(201, { job: { id: 'one' } }));
  await pending;
  assert.equal(refreshed, 1);
  assert.equal(state.pendingCommandKey, null);
  assert.equal(state.commandSubmitting, false);
  assert.equal(element('confirmCommandDialog').open, false);
});

test('ambiguous response refreshes jobs and retry uses the same idempotency key', async () => {
  const { context, state, element, setFetchHook } = harness();
  element('commandInput').value = 'uptime';
  context.prepareCommand({ preventDefault() {} });
  const key = state.pendingCommandKey;
  const sentKeys = [];
  let attempts = 0;
  setFetchHook((_url, options) => {
    sentKeys.push(options.headers['Idempotency-Key']);
    attempts++;
    if (attempts === 1) return Promise.reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
    return Promise.resolve(reply(200, { job: { id: 'same-job' } }));
  });
  let refreshed = 0;
  context.refresh = async () => { refreshed++; };
  await context.runCommand();
  assert.equal(refreshed, 1);
  assert.equal(state.pendingCommandKey, key);
  assert.match(element('confirmCommandError').textContent, /могла попасть в очередь/);
  await context.runCommand();
  assert.deepEqual(sentKeys, [key, key]);
  assert.equal(refreshed, 2);
  assert.equal(state.pendingCommandKey, null);
});

test('old POST response cannot close a new session confirmation', async () => {
  const { context, state, element, setFetchHook } = harness();
  const post = deferred();
  setFetchHook(() => post.promise);
  context.refresh = async () => {};
  element('commandInput').value = 'uptime';
  context.prepareCommand({ preventDefault() {} });
  const old = context.runCommand();
  context.logout(false);
  state.token = 'new-token';
  state.servers = [{ id: 'b', name: 'Server B', online: true, remote_commands_enabled: true }];
  state.selectedId = 'b';
  element('commandInput').value = 'free -h';
  context.prepareCommand({ preventDefault() {} });
  const newKey = state.pendingCommandKey;
  post.resolve(reply(201, { job: { id: 'old-job' } }));
  await old;
  assert.equal(state.pendingCommandKey, newKey);
  assert.equal(state.pendingCommand, 'free -h');
  assert.equal(element('confirmCommandDialog').open, true);
});

/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

function harness(servers, telegram) {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      textContent: '', hidden: false, disabled: false, value: '', className: '',
      style: {}, dataset: {}, children: [],
      replaceChildren() { this.children = []; }, append(...items) { this.children.push(...items); },
      addEventListener() {}, setAttribute() {},
    });
    return elements.get(id);
  };
  const calls = [];
  const fetch = async (url) => {
    calls.push(url);
    const path = new URL(url).pathname;
    const payload = path === '/api/v1/session/ssh-grant' ? { token: 'new-ssh-session' } :
      path === '/api/v1/servers' ? { servers } :
      path === '/api/v1/incidents' ? { incidents: [] } :
        path === '/api/v1/telegram' ? { telegram } : { metrics: [] };
    return { ok: true, status: 200, text: async () => JSON.stringify(payload) };
  };
  const stored = [];
  const context = vm.createContext({
    URL, AbortController, setTimeout, clearTimeout, setInterval() {}, clearInterval() {},
    TextEncoder, TextDecoder, Uint8Array, btoa, atob,
    document: { getElementById: element, createElement: () => element(Symbol()),
      querySelectorAll: () => [], addEventListener() {}, body: { append() {} } },
    localStorage: { getItem() { return null; }, setItem(...args) { stored.push(args); }, removeItem() {} },
    navigator: {}, location: { protocol: 'file:' }, fetch,
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  state.base = 'https://hub.example'; state.token = 'admin-session';
  return { context, state, element, calls, stored };
}

test('new Hub opens a first-run guide and checks Telegram without storing credentials', async () => {
  const h = harness([], { configured: false, connected: false, polling: false });
  await h.context.refresh();
  assert.equal(h.state.view, 'start');
  assert.equal(h.element('startPrimaryButton').dataset.startAction, 'add');
  assert.equal(h.element('startServersBadge').textContent, 'Нет серверов');
  assert.equal(h.element('startTelegramBadge').textContent, 'Не настроен');
  assert.ok(h.calls.includes('https://hub.example/api/v1/telegram'));
  assert.deepEqual(h.stored, []);
});

test('guide describes Hub command permission without promising local Agent access', async () => {
  const h = harness([{ id: 'srv1', name: 'Ubuntu', online: true, last_seen: 1710000000,
    remote_commands_enabled: true, latest: { cpu_percent: 21 } },
  { id: 'srv2', name: 'Target', online: false, last_seen: 1710000000,
    remote_commands_enabled: false, latest: {} }],
  { configured: true, connected: true, polling: true });
  h.state.view = 'start';
  await h.context.refresh();
  assert.equal(h.element('startServersBadge').textContent, '1 на связи');
  assert.match(h.element('startServersText').textContent, /В списке: 2\./);
  assert.equal(h.element('startCommandsBadge').textContent, 'Разрешено в Hub');
  assert.match(h.element('startCommandsText').textContent, /Agent должен разрешать/);
  assert.equal(h.element('startTelegramBadge').textContent, 'На связи');
  assert.equal(h.element('startPrimaryButton').dataset.startAction, 'settings');
});

test('SSH landing selects an enrolled target server and its existing RBAC terminal view', async () => {
  const h = harness([
    { id: 'relay', name: 'Relay', online: true, latest: {} },
    { id: 'target-id', name: 'Target', online: true, latest: {}, remote_commands_enabled: true },
  ], { configured: false, connected: false, polling: false });
  h.context.location = new URL('https://hub.example/');
  h.state.token = '';
  await h.context.sovagridRedeemBrowserSSHGrant('c'.repeat(43), { server: 'Target', commands: true });
  assert.equal(h.state.selectedId, 'target-id');
  assert.equal(h.state.view, 'commands');
  assert.equal(h.element('sshLandingNotice').textContent, '');
  assert.ok(h.calls.includes('https://hub.example/api/v1/session/ssh-grant'));
});

test('unknown or inaccessible SSH landing falls back to an authorized server', async () => {
  const h = harness([
    { id: 'relay', name: 'Relay', online: true, latest: {} },
  ], { configured: false, connected: false, polling: false });
  vm.runInContext('browserSSHLanding = { server: "private-target", commands: true }', h.context);
  await h.context.refresh();
  assert.equal(h.state.selectedId, 'relay');
  assert.equal(h.state.view, 'overview');
  assert.equal(h.element('sshLandingNotice').hidden, false);
  assert.match(h.element('sshLandingNotice').textContent, /не найден среди доступных/);
  assert.ok(h.calls.every((url) => !url.includes('private-target')));
});

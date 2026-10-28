/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const response = (status, body) => ({ ok: status < 400, status,
  text: async () => JSON.stringify(body) });
const basePolicy = { revision: 0, mode: 'all', grants: [] };
const flush = () => new Promise((done) => setImmediate(done));

function harness(fetchHook = () => response(200, { access: basePolicy })) {
  const elements = new Map(), calls = [];
  const make = () => ({ value: '', textContent: '', hidden: false, disabled: false,
    open: false, children: [], dataset: {}, attributes: {}, listeners: new Map(),
    addEventListener(name, handler) { this.listeners.set(name, handler); },
    setAttribute(key, value) { this.attributes[key] = value; },
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
    classList: { toggle() {} }, focus() {},
    showModal() { this.open = true; },
    close() { this.open = false; this.listeners.get('close')?.(); },
  });
  const element = (id) => { if (!elements.has(id)) elements.set(id, make()); return elements.get(id); };
  const nav = ['overview', 'commands', 'files', 'telegram', 'audit', 'vpn'].map((view) => {
    const node = make(); node.dataset.view = view; return node;
  });
  const serverButton = make(), globalButton = make();
  const context = vm.createContext({ URL, AbortController, TextEncoder, Uint8Array,
    setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {}, Intl,
    document: { getElementById: element, createElement: make, addEventListener() {},
      querySelectorAll(selector) {
        return selector === '[data-view]' ? nav :
          selector === '[data-admin-only], [data-command]' ? [serverButton] :
            selector === '[data-global-admin-only]' ? [globalButton] : [];
      } },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    navigator: {}, location: new URL('https://hub.example'),
    fetch: async (url, options) => { calls.push({ url, options }); return fetchHook(url, options); },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('access.js', 'utf8'), context);
  const state = vm.runInContext('state', context), client = vm.runInContext('accessClient', context);
  state.base = 'https://hub.example'; state.token = 'admin-session';
  state.user = { id: 'owner', username: 'owner', role: 'admin', legacy: false };
  state.access = { mode: 'all', revision: 0, unrestricted_admin: true };
  state.servers = [{ id: 'server-a', name: '<img onerror=bad()>', access_role: 'admin', online: true,
    remote_commands_enabled: true }, { id: 'server-b', name: 'Home', access_role: 'admin' }];
  state.selectedId = 'server-a';
  return { context, state, client, element, calls, nav, serverButton, globalButton };
}

test('session access validates shape and selected admin sees only server actions', () => {
  const h = harness();
  for (const payload of [{}, { access: { mode: 'selected', revision: 1, unrestricted_admin: true } },
    { access: { mode: 'all', revision: -1, unrestricted_admin: false } }]) {
    assert.throws(() => h.context.hubSessionAccess(payload), /неверные права/);
  }
  h.state.access = { mode: 'selected', revision: 3, unrestricted_admin: false };
  h.state.servers[1].access_role = 'viewer';
  h.context.applyHubPermissions();
  assert.equal(h.context.hubCanGlobalAdmin(), false);
  assert.equal(h.context.hubCanAdmin(), true);
  assert.equal(h.serverButton.hidden, false);
  assert.equal(h.globalButton.hidden, true);
  assert.equal(h.nav.find((item) => item.dataset.view === 'commands').hidden, false);
  assert.equal(h.nav.find((item) => item.dataset.view === 'telegram').hidden, true);
  assert.equal(h.nav.find((item) => item.dataset.view === 'audit').hidden, false);
  assert.equal(h.context.vpnTargetReady(), false);
  h.state.selectedId = 'server-b'; h.state.view = 'commands';
  h.context.applyHubPermissions();
  assert.equal(h.context.hubCanAdmin(), false);
  assert.equal(h.state.view, 'overview');
  assert.equal(h.serverButton.hidden, true);
  assert.equal(h.nav.find((item) => item.dataset.view === 'commands').hidden, true);
  h.state.vpnTargetId = 'server-a';
  assert.equal(h.context.vpnTargetReady(), true);
});

test('older Hub admin gate preserves viewer and operator monitoring without accepting other denials', async () => {
  for (const role of ['viewer', 'operator']) {
    const h = harness(() => response(403, { error: 'Insufficient role' }));
    const access = await h.context.hubLoadSessionAccess({ role, legacy: false });
    assert.equal(access.mode, 'all');
    assert.equal(access.unrestricted_admin, false);
  }
  const admin = harness(() => response(404, { error: 'Not found' }));
  assert.equal((await admin.context.hubLoadSessionAccess({ role: 'admin', legacy: false })).unrestricted_admin, true);
  for (const [status, message] of [[403, 'Server access denied'], [401, 'Unauthorized']]) {
    const h = harness(() => response(status, { error: message }));
    await assert.rejects(h.context.hubLoadSessionAccess({ role: 'viewer', legacy: false }),
      (error) => error.status === status);
  }
});

test('user grants editor loads, renders names as text and sends one exact CAS update', async () => {
  const calls = [];
  const h = harness((url, options) => {
    calls.push({ url, options });
    if (options.method === 'PATCH') return response(200, { access: { revision: 8, mode: 'selected',
      grants: [{ server_id: 'server-a', role: 'operator' }] } });
    return response(200, { access: { revision: 7, mode: 'selected',
      grants: [{ server_id: 'server-a', role: 'viewer' }] } });
  });
  h.context.accessOpen('user', 'account-1', 'Guest', 'operator'); await flush();
  assert.equal(h.element('accessDialog').open, true);
  assert.equal(h.element('accessMode').value, 'selected');
  const unsafe = h.element('accessServerRows').children.find((row) => row.children[0].textContent.startsWith('<img'));
  assert.equal(h.element('accessServerRows').children.length, 2);
  assert.equal(unsafe.children[0].textContent, '<img onerror=bad()>');
  assert.equal(fs.readFileSync('access.js', 'utf8').includes('.innerHTML'), false);
  h.client.selects.get('server-a').value = 'operator';
  h.element('accessMode').value = 'selected';
  await h.context.accessSave({ preventDefault() {} });
  const writes = calls.filter(({ options }) => options.method === 'PATCH');
  assert.equal(writes.length, 1);
  assert.equal(writes[0].url, 'https://hub.example/api/v1/users/account-1/server-access');
  assert.deepEqual(JSON.parse(writes[0].options.body), { revision: 7, mode: 'selected',
    grants: [{ server_id: 'server-a', role: 'operator' }] });
  assert.equal(h.client.policy.revision, 8);
  assert.match(h.element('accessDialogMessage').textContent, /применены/);
});

test('Telegram grants use exact binding path and a conflict never auto retries', async () => {
  const h = harness((_url, options) => options.method === 'PATCH'
    ? response(409, { error: 'changed' }) : response(200, { access: basePolicy }));
  h.context.accessOpen('telegram', 12345, '@bot-user', 'admin'); await flush();
  h.element('accessMode').value = 'selected';
  h.client.selects.get('server-b').value = 'viewer';
  await h.context.accessSave({ preventDefault() {} });
  const writes = h.calls.filter(({ options }) => options.method === 'PATCH');
  assert.equal(writes.length, 1);
  assert.equal(writes[0].url, 'https://hub.example/api/v1/telegram/bindings/12345/12345/server-access');
  assert.deepEqual(JSON.parse(writes[0].options.body), { revision: 0, mode: 'selected',
    grants: [{ server_id: 'server-b', role: 'viewer' }] });
  assert.match(h.element('accessDialogError').textContent, /другой вкладке/);
  assert.equal(h.element('accessDialog').open, true);
});

test('logout rejects a late access GET and clears the dialog', async () => {
  let resolveGet;
  const h = harness(() => new Promise((resolve) => { resolveGet = resolve; }));
  h.context.accessOpen('user', 'account-1', 'Guest', 'viewer');
  assert.equal(h.element('accessDialog').open, true);
  h.context.logout(false);
  resolveGet(response(200, { access: basePolicy }));
  await flush();
  assert.equal(h.element('accessDialog').open, false);
  assert.equal(h.client.policy, null);
  assert.equal(h.state.token, '');
});

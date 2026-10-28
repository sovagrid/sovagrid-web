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
        textContent: '', value: '', hidden: false, disabled: false, open: false,
        children: [], listeners,
        addEventListener(name, handler) { listeners.set(name, handler); },
        setAttribute() {},
        append(...children) { this.children.push(...children); },
        replaceChildren() { this.children = []; },
        showModal() { this.open = true; },
        close() { this.open = false; listeners.get('close')?.({}); },
      });
    }
    return elements.get(id);
  };
  let fetchHook = () => { throw new Error('unexpected fetch'); };
  const context = vm.createContext({
    URL, AbortController, TextEncoder, setTimeout, clearTimeout,
    setInterval: () => 1, clearInterval() {}, crypto: { randomUUID },
    document: {
      getElementById: element, createElement: () => element(Symbol()),
      querySelectorAll: () => [], addEventListener() {},
    },
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
  context.renderVpnControls();
  return { context, state, element, setFetchHook: (hook) => { fetchHook = hook; } };
}

const reply = (status, payload) => ({
  ok: status >= 200 && status < 300, status,
  text: async () => JSON.stringify(payload),
});

const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};

test('create queues the exact Hub schema on the selected server and polls its job', async () => {
  const { context, state, element, setFetchHook } = harness();
  element('vpnCreateName').value = 'phone-vpn';
  element('vpnCreatePort').value = '51821';
  element('vpnCreateSubnet').value = '10.49.0.0/24';
  element('vpnCreateEndpoint').value = 'vpn.example.com';
  context.prepareVpnCreate({ preventDefault() {} });
  assert.equal(element('vpnActionDialog').open, true);
  assert.match(state.vpnPending.key, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  assert.equal(element('vpnActionServer').textContent, 'Сервер: Server A');

  const post = deferred();
  let sent;
  setFetchHook((url, options) => { sent = { url, options }; return post.promise; });
  const refresh = context.refresh;
  context.refresh = async () => {};
  const submitting = context.submitVpnAction();
  assert.equal(sent.url, 'https://hub.example/api/v1/servers/a/vpn/actions');
  assert.equal(sent.options.method, 'POST');
  assert.equal(sent.options.headers['Idempotency-Key'], state.vpnPending.key);
  assert.deepEqual(JSON.parse(sent.options.body), {
    action: 'create', name: 'phone-vpn', port: 51821,
    subnet: '10.49.0.0/24', endpoint: 'vpn.example.com',
  });
  assert.equal(sent.options.headers['Content-Type'], 'application/json');
  assert.equal(element('vpnActionConfirm').disabled, true);
  assert.equal(element('vpnActionCancel').disabled, true);
  let prevented = false;
  element('vpnActionDialog').listeners.get('cancel')({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  post.resolve(reply(201, { job: { id: 'job-1', state: 'queued' } }));
  await submitting;
  assert.equal(element('vpnActionDialog').open, false);
  assert.equal(state.vpnActionJobId, 'job-1');
  assert.equal(element('vpnActionJobPanel').hidden, false);
  assert.equal(element('vpnCreateName').value, '');

  state.view = 'vpn';
  context.refresh = refresh;
  context.renderSidebar = () => {};
  context.renderWorkspace = () => {};
  context.renderServer = () => {};
  context.renderVpn = () => {};
  const paths = [];
  setFetchHook((url) => {
    paths.push(new URL(url).pathname);
    if (url.endsWith('/servers')) return Promise.resolve(reply(200, { servers: state.servers }));
    if (url.endsWith('/incidents')) return Promise.resolve(reply(200, { incidents: [] }));
    if (url.endsWith('/vpn')) return Promise.resolve(reply(200, { vpn: { source_status: 'ok', services: [] } }));
    if (url.endsWith('/jobs/job-1')) return Promise.resolve(reply(200, {
      job: { id: 'job-1', state: 'succeeded', output: '{"name":"phone-vpn"}' },
    }));
    throw new Error(`unexpected path: ${url}`);
  });
  await context.refresh();
  assert.ok(paths.includes('/api/v1/jobs/job-1'));
  assert.equal(element('vpnActionJobState').textContent, 'Успешно');
  assert.equal(element('vpnActionJobOutput').textContent, '{"name":"phone-vpn"}');
});

test('remove requires exact typed name and rejects a changed target server', async () => {
  const { context, state, element, setFetchHook } = harness();
  state.servers.push({ id: 'b', name: 'Server B', online: true, remote_commands_enabled: true });
  context.prepareVpnAction({ action: 'remove', name: 'phone-vpn', confirm_name: 'phone-vpn' });
  assert.equal(element('vpnRemoveConfirmation').hidden, false);
  assert.equal(element('vpnActionConfirm').disabled, true);

  let posts = 0;
  setFetchHook(() => { posts++; return Promise.resolve(reply(201, { job: { id: 'removed' } })); });
  context.refresh = async () => {};
  element('vpnRemoveName').value = 'wrong';
  await context.submitVpnAction();
  assert.equal(posts, 0);
  assert.match(element('vpnActionError').textContent, /точное имя/);

  element('vpnRemoveName').value = 'phone-vpn';
  state.vpnTargetId = 'b';
  await context.submitVpnAction();
  assert.equal(posts, 0);
  assert.match(element('vpnActionError').textContent, /Сервер изменился/);

  state.vpnTargetId = 'a';
  await context.submitVpnAction();
  assert.equal(posts, 1);
  assert.equal(state.vpnActionJobId, 'removed');
});

test('an ambiguous response keeps the same UUID and exact payload for retry', async () => {
  const { context, state, element, setFetchHook } = harness();
  context.prepareVpnAction({ action: 'add-client', name: 'phone-vpn', client: 'my_iphone' });
  const key = state.vpnPending.key;
  const sent = [];
  setFetchHook((url, options) => {
    sent.push({ url, key: options.headers['Idempotency-Key'], body: options.body });
    if (sent.length === 1) return Promise.reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
    return Promise.resolve(reply(200, { job: { id: 'same-job', state: 'queued' } }));
  });
  let refreshed = 0;
  context.refresh = async () => { refreshed++; };
  await context.submitVpnAction();
  assert.equal(state.vpnPending.key, key);
  assert.equal(element('vpnActionDialog').open, true);
  assert.match(element('vpnActionError').textContent, /могла попасть в очередь/);
  assert.equal(refreshed, 1);
  await context.submitVpnAction();
  assert.equal(refreshed, 2);
  assert.deepEqual(sent.map((item) => item.key), [key, key]);
  assert.equal(sent[0].body, sent[1].body);
  assert.deepEqual(JSON.parse(sent[0].body), {
    action: 'add-client', name: 'phone-vpn', client: 'my_iphone',
  });
  assert.equal(state.vpnPending, null);
  assert.equal(state.vpnActionJobId, 'same-job');
});

test('instance and client forms emit only the activate and revoke-client schemas', async () => {
  const { context, element, setFetchHook } = harness();
  const bodies = [];
  setFetchHook((_url, options) => {
    bodies.push(JSON.parse(options.body));
    return Promise.resolve(reply(201, { job: { id: `job-${bodies.length}` } }));
  });
  context.refresh = async () => {};

  element('vpnInstanceAction').value = 'activate';
  element('vpnInstanceName').value = 'phone-vpn';
  context.prepareVpnInstance({ preventDefault() {} });
  await context.submitVpnAction();

  element('vpnClientAction').value = 'revoke-client';
  element('vpnClientInstance').value = 'phone-vpn';
  element('vpnClientName').value = 'old_iphone';
  context.prepareVpnClient({ preventDefault() {} });
  await context.submitVpnAction();

  assert.deepEqual(bodies, [
    { action: 'activate', name: 'phone-vpn' },
    { action: 'revoke-client', name: 'phone-vpn', client: 'old_iphone' },
  ]);
});

test('managed status cards expose no secrets or unbound action shortcuts', () => {
  const { context, element } = harness();
  context.renderManagedVpn({ source_status: 'ok', instances: [{
    name: 'phone-vpn', interface: 'sg12345678901', port: 51821,
    subnet: '10.49.0.0/24', client_count: 1, state: 'active',
    private_key: 'DO-NOT-RENDER-PRIVATE-KEY',
    client_profiles: ['DO-NOT-RENDER-CLIENT-PROFILE'],
  }] });
  const texts = (node) => [node.textContent, ...node.children.flatMap(texts)].join(' ');
  const displayed = texts(element('managedInstancesList'));
  assert.match(displayed, /phone-vpn/);
  assert.doesNotMatch(displayed, /DO-NOT-RENDER/);
  assert.equal(element('managedInstancesList').children[0].children.length, 3,
    'Hub-host inventory must not offer shortcuts targeting an arbitrary Agent');
});

test('old VPN POST cannot close a new session confirmation', async () => {
  const { context, state, element, setFetchHook } = harness();
  const post = deferred();
  setFetchHook(() => post.promise);
  context.refresh = async () => {};
  context.prepareVpnAction({ action: 'activate', name: 'first-vpn' });
  const old = context.submitVpnAction();
  context.logout(false);
  state.token = 'new-token';
  state.servers = [{ id: 'b', name: 'Server B', online: true, remote_commands_enabled: true }];
  state.selectedId = 'b';
  context.renderVpnControls();
  context.prepareVpnAction({ action: 'activate', name: 'new-vpn' });
  const newKey = state.vpnPending.key;
  post.resolve(reply(201, { job: { id: 'old-job' } }));
  await old;
  assert.equal(state.vpnPending.key, newKey);
  assert.equal(element('vpnActionDialog').open, true);
  assert.equal(state.vpnActionJobId, null);
});

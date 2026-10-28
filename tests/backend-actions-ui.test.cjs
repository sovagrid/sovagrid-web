/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const { randomUUID } = require('node:crypto');

const reply = (status, value) => ({ ok: status < 400, status,
  text: async () => JSON.stringify(value) });

function harness() {
  const elements = new Map(), calls = [];
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { value: '', textContent: '', hidden: false, disabled: false,
        open: false, children: [], listeners, className: '',
        addEventListener(type, fn) { listeners.set(type, fn); },
        append(...nodes) { this.children.push(...nodes); },
        replaceChildren(...nodes) { this.children = nodes; },
        setAttribute() {}, showModal() { this.open = true; },
        close() { this.open = false; listeners.get('close')?.({}); },
      });
    }
    return elements.get(id);
  };
  let fetchHook = () => { throw new Error('unexpected fetch'); };
  const context = vm.createContext({ URL, AbortController, TextEncoder, Uint8Array,
    crypto: { randomUUID }, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, createElement: () => element(Symbol()),
      querySelectorAll: () => [], addEventListener() {} },
    location: { protocol: 'file:' }, navigator: {},
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    fetch: (url, options) => { calls.push({ url, options }); return fetchHook(url, options); },
  });
  for (const file of ['app.js', 'process-inventory.js', 'service-control.js'])
    vm.runInContext(fs.readFileSync(file, 'utf8'), context);
  const state = vm.runInContext('state', context);
  Object.assign(state, { token: 'session-1', base: 'https://hub.example', selectedId: 'server-A',
    servers: [{ id: 'server-A', name: 'Server A', online: true, remote_commands_enabled: true,
      latest: { details: { services: { units: [{ name: 'nginx.service' }] } } } },
    { id: 'server-B', name: 'Server B', online: true, remote_commands_enabled: true }] });
  return { context, state, element, calls, setFetchHook: (fn) => { fetchHook = fn; } };
}

test('process inventory pages use fixed jobs and vanish on server switch', async () => {
  const h = harness();
  h.context.processInventorySelectedServer('server-A');
  const output = (after, rows, next, more) => JSON.stringify({ observed_at: 1793000000,
    after_pid: after, filter: 'python', next_after_pid: next, has_more: more,
    processes: rows });
  let page = 0;
  h.setFetchHook((url, options) => {
    if (options.method === 'POST') {
      const payload = JSON.parse(options.body);
      assert.equal(payload.after_pid, page ? 42 : 0);
      assert.equal(payload.limit, 32);
      assert.equal(payload.filter, 'python');
      return Promise.resolve(reply(201, { job: { id: `job-${page}`, server_id: 'server-A', state: 'queued' } }));
    }
    return Promise.resolve(reply(200, { job: { id: `job-${page}`, server_id: 'server-A',
      state: 'succeeded', transient_output: true, output_expired: false,
      output: page ? output(42, [{ pid: 49, name: 'python-worker', rss_bytes: 8192 }], 49, false)
        : output(0, [{ pid: 42, name: 'python', rss_bytes: 4096 }], 42, true) } }));
  });
  await h.context.processInventoryRequest(0, 'python');
  const client = vm.runInContext('processInventory', h.context);
  assert.equal(client.rows.length, 1);
  assert.equal(h.element('processInventoryMore').hidden, false);
  assert.equal(h.element('processInventoryRows').children[0].children[1].textContent, 'python');
  page = 1;
  await h.context.processInventoryRequest(42, 'python');
  assert.equal(client.rows.length, 2);
  assert.equal(h.element('processInventoryMore').hidden, true);
  h.state.selectedId = 'server-B'; h.context.processInventorySelectedServer('server-B');
  assert.equal(client.rows.length, 0);
  assert.equal(h.element('processInventoryTable').hidden, true);
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 2);
  assert.ok(h.calls.every((call) => !call.url.includes('python')));
});

test('generic job history never prints transient process output', () => {
  const h = harness();
  h.state.jobs = [{ id: 'snapshot-1', server_id: 'server-A', state: 'succeeded',
    created_at: 1793000000, exit_code: 0, transient_output: true,
    output: '{"processes":[{"name":"private-process"}]}' }];
  h.context.renderJobs();
  assert.equal(h.element('jobsList').children.length, 1);
  assert.equal(h.element('jobsList').children[0].children.length, 2);
});

test('service control requires recent status and exact confirmation before mutation', async () => {
  const h = harness(); h.context.serviceControlSelectedServer('server-A');
  h.element('serviceControlUnit').value = 'nginx.service';
  let action = 'status';
  h.setFetchHook((url, options) => {
    if (options.method === 'POST') {
      assert.deepEqual(JSON.parse(options.body), { action, unit: 'nginx.service' });
      return Promise.resolve(reply(201, { job: { id: `${action}-job`, server_id: 'server-A', state: 'queued' } }));
    }
    if (url.includes('/services/control?unit=')) return Promise.resolve(reply(200,
      { control: { source_status: 'ok', unit: 'nginx.service', observed_at: 1793000000,
        load_state: 'loaded', active_state: 'active', sub_state: 'running' } }));
    return Promise.resolve(reply(200,
      { job: { id: `${action}-job`, server_id: 'server-A', state: 'succeeded' } }));
  });
  assert.equal(h.element('serviceControlRestart').disabled, true);
  await h.context.serviceControlQueue({ action: 'status', unit: 'nginx.service' });
  assert.equal(h.element('serviceControlRestart').disabled, false);
  h.context.serviceControlPrepare('restart');
  assert.equal(h.element('serviceControlDialog').open, true);
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 1);
  action = 'restart';
  await h.context.serviceControlConfirm();
  assert.equal(h.element('serviceControlDialog').open, false);
  assert.equal(h.element('serviceControlRestart').disabled, true);
  assert.match(h.element('serviceControlStatus').textContent, /Проверьте состояние/);
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 2);
  h.element('serviceControlUnit').value = 'nginx@.service';
  h.context.serviceControlPrepare('restart');
  assert.equal(h.element('serviceControlDialog').open, false);
});

test('uncertain service mutation closes confirmation and requires a new status', async () => {
  const h = harness(); h.context.serviceControlSelectedServer('server-A');
  h.element('serviceControlUnit').value = 'nginx.service';
  let action = 'status';
  h.setFetchHook((url, options) => {
    if (options.method === 'POST') {
      if (action === 'restart') return Promise.reject(new Error('connection lost'));
      return Promise.resolve(reply(201, { job: { id: 'status-job', server_id: 'server-A' } }));
    }
    if (url.includes('/services/control?unit=')) return Promise.resolve(reply(200,
      { control: { source_status: 'ok', unit: 'nginx.service', observed_at: 1793000000,
        load_state: 'loaded', active_state: 'active', sub_state: 'running' } }));
    return Promise.resolve(reply(200,
      { job: { id: 'status-job', server_id: 'server-A', state: 'succeeded' } }));
  });
  await h.context.serviceControlQueue({ action: 'status', unit: 'nginx.service' });
  h.context.serviceControlPrepare('restart');
  action = 'restart';
  await h.context.serviceControlConfirm();
  const client = vm.runInContext('serviceControl', h.context);
  assert.equal(client.pending, null);
  assert.equal(client.control, null);
  assert.equal(h.element('serviceControlDialog').open, false);
  assert.equal(h.element('serviceControlRestart').disabled, true);
  assert.match(h.element('serviceControlError').textContent, /Проверьте состояние/);
  await h.context.serviceControlConfirm();
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 2);
});

test('protected access and network units remain status-only after a successful check', async () => {
  for (const unit of ['ssh.service', 'sovagrid-agent.service', 'wg-quick@wg0.service',
    'reverse-tunnel.service', 'Docker.service', 'nginx-tunnel.service']) {
    const h = harness(); h.context.serviceControlSelectedServer('server-A');
    h.element('serviceControlUnit').value = unit;
    h.setFetchHook((url, options) => {
      if (options.method === 'POST') {
        assert.deepEqual(JSON.parse(options.body), { action: 'status', unit });
        return Promise.resolve(reply(201, { job: { id: 'status-job', server_id: 'server-A' } }));
      }
      if (url.includes('/services/control?unit=')) return Promise.resolve(reply(200,
        { control: { source_status: 'ok', unit, observed_at: 1793000000,
          load_state: 'loaded', active_state: 'active', sub_state: 'running' } }));
      return Promise.resolve(reply(200,
        { job: { id: 'status-job', server_id: 'server-A', state: 'succeeded' } }));
    });
    await h.context.serviceControlQueue({ action: 'status', unit });
    assert.equal(h.element('serviceControlPolicyHint').hidden, false, unit);
    assert.equal(h.element('serviceControlStart').disabled, true, unit);
    assert.equal(h.element('serviceControlStop').disabled, true, unit);
    assert.equal(h.element('serviceControlRestart').disabled, true, unit);
    h.context.serviceControlPrepare('restart');
    assert.equal(h.element('serviceControlDialog').open, false, unit);
    await h.context.serviceControlQueue({ action: 'restart', unit });
    assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 1, unit);
  }
});

test('administrator role and a still-valid status are rechecked when confirming', async () => {
  const h = harness(); h.context.serviceControlSelectedServer('server-A');
  h.element('serviceControlUnit').value = 'nginx.service';
  h.setFetchHook((url, options) => {
    if (options.method === 'POST') return Promise.resolve(reply(201,
      { job: { id: 'status-job', server_id: 'server-A' } }));
    if (url.includes('/services/control?unit=')) return Promise.resolve(reply(200,
      { control: { source_status: 'ok', unit: 'nginx.service', observed_at: 1793000000,
        load_state: 'loaded', active_state: 'active', sub_state: 'running' } }));
    return Promise.resolve(reply(200,
      { job: { id: 'status-job', server_id: 'server-A', state: 'succeeded' } }));
  });
  await h.context.serviceControlQueue({ action: 'status', unit: 'nginx.service' });
  assert.equal(h.element('serviceControlRestart').disabled, false);
  h.context.serviceControlPrepare('restart');
  assert.equal(h.element('serviceControlDialog').open, true);
  vm.runInContext('serviceControl.control = null', h.context);
  await h.context.serviceControlConfirm();
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 1);
  assert.match(h.element('serviceControlDialogError').textContent, /Проверьте службу заново/);
  h.element('serviceControlDialog').close();
  await h.context.serviceControlQueue({ action: 'status', unit: 'nginx.service' });
  h.context.serviceControlPrepare('restart');
  assert.equal(h.element('serviceControlDialog').open, true);
  h.state.user = { id: 'operator', username: 'operator', role: 'operator', enabled: true };
  await h.context.serviceControlConfirm();
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 2);
  assert.match(h.element('serviceControlDialogError').textContent, /Проверьте службу заново/);
  h.context.serviceControlSelectedServer('server-A');
  assert.equal(h.element('serviceControlCheck').disabled, true);
  assert.equal(h.element('serviceControlRestart').disabled, true);
  await h.context.serviceControlQueue({ action: 'status', unit: 'nginx.service' });
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 2);
});

test('a Hub refusal before queueing is shown as rejected, not an uncertain execution', async () => {
  const h = harness(); h.context.serviceControlSelectedServer('server-A');
  h.element('serviceControlUnit').value = 'nginx.service';
  let action = 'status';
  h.setFetchHook((url, options) => {
    if (options.method === 'POST') {
      if (action === 'restart') return Promise.resolve(reply(403, { error: 'Action denied' }));
      return Promise.resolve(reply(201, { job: { id: 'status-job', server_id: 'server-A' } }));
    }
    if (url.includes('/services/control?unit=')) return Promise.resolve(reply(200,
      { control: { source_status: 'ok', unit: 'nginx.service', observed_at: 1793000000,
        load_state: 'loaded', active_state: 'active', sub_state: 'running' } }));
    return Promise.resolve(reply(200,
      { job: { id: 'status-job', server_id: 'server-A', state: 'succeeded' } }));
  });
  await h.context.serviceControlQueue({ action: 'status', unit: 'nginx.service' });
  h.context.serviceControlPrepare('restart');
  action = 'restart';
  await h.context.serviceControlConfirm();
  assert.match(h.element('serviceControlError').textContent, /отклонил действие до постановки/);
  assert.doesNotMatch(h.element('serviceControlError').textContent, /могло выполниться/);
  assert.equal(h.element('serviceControlRestart').disabled, true);
});

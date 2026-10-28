/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const { randomUUID } = require('node:crypto');

const ID = 'a'.repeat(64);
const MANAGED = 'b'.repeat(64);
const reply = (status, value) => ({ ok: status < 400, status,
  text: async () => JSON.stringify(value) });

function snapshot() {
  return { version: 1, collected_at: Math.floor(Date.now() / 1000), engines: [
    { engine: 'docker', source_status: 'ok', reason: null, truncated: false, containers: [
      { id: ID, name: 'worker', image: 'docker.io/library/worker:1', state: 'running' },
      { id: MANAGED, name: 'sovagrid-hub', image: 'sovagrid-hub:local', state: 'running' },
    ] },
    { engine: 'podman', source_status: 'unavailable', reason: 'no_socket', truncated: false, containers: [] },
  ] };
}

function harness() {
  const elements = new Map(), calls = [], listeners = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      const events = new Map();
      elements.set(id, { value: '', textContent: '', hidden: false, disabled: false,
        open: false, children: [], events, className: '',
        addEventListener(name, fn) { events.set(name, fn); },
        append(...items) { this.children.push(...items); },
        replaceChildren(...items) { this.children = items; },
        setAttribute() {}, showModal() { this.open = true; },
        close() { this.open = false; events.get('close')?.({}); },
      });
    }
    return elements.get(id);
  };
  let fetchHook = () => { throw new Error('unexpected fetch'); };
  const context = vm.createContext({ URL, AbortController, TextEncoder, Uint8Array,
    crypto: { randomUUID }, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { hidden: false, getElementById: element, createElement: () => element(Symbol()),
      querySelectorAll: () => [], addEventListener: (name, fn) => listeners.set(name, fn) },
    location: { protocol: 'file:' }, navigator: {},
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    fetch: (url, options) => { calls.push({ url, options }); return fetchHook(url, options); },
  });
  for (const file of ['app.js', 'container-control.js'])
    vm.runInContext(fs.readFileSync(file, 'utf8'), context);
  const state = vm.runInContext('state', context);
  const server = { id: 'server-1', name: 'Worker host', online: true,
    remote_commands_enabled: true, access_role: 'admin',
    latest: { details: { containers: snapshot() } } };
  Object.assign(state, { token: 'session', base: 'https://hub.example',
    selectedId: server.id, view: 'overview', servers: [server],
    user: { id: 'admin', role: 'admin', enabled: true, legacy: false },
    access: { mode: 'all', revision: 1, unrestricted_admin: true } });
  const render = () => context.containerActionRenderInventory(server.latest.details.containers, server);
  return { context, state, server, element, calls, listeners, render,
    setFetchHook: (fn) => { fetchHook = fn; } };
}

test('admin checks an exact ordinary Docker ID before a confirmed mutation', async () => {
  const h = harness(); h.render();
  assert.equal(h.element('containerActionPanel').hidden, false);
  assert.equal(h.element('containerActionTarget').children.length, 1);
  assert.equal(h.element('containerActionTarget').value, ID);
  assert.equal(h.element('containerActionStop').disabled, true);
  let action = 'status';
  h.setFetchHook((url, options) => {
    if (url.endsWith('/containers/actions')) {
      assert.deepEqual(JSON.parse(options.body), { action, engine: 'docker', id: ID });
      assert.match(options.headers['Idempotency-Key'], /^[0-9a-f-]{36}$/);
      return Promise.resolve(reply(201, { job: { id: randomUUID(), server_id: h.server.id } }));
    }
    if (url.includes('/containers/control?')) return Promise.resolve(reply(200,
      { control: { source_status: 'ok', engine: 'docker', id: ID,
        observed_at: Math.floor(Date.now() / 1000), state: 'running' } }));
    const jobId = url.split('/').pop();
    return Promise.resolve(reply(200, { job: { id: jobId, server_id: h.server.id,
      state: 'succeeded' } }));
  });
  await h.context.containerActionQueue('status', h.context.containerActionTarget());
  assert.equal(h.element('containerActionStop').disabled, false);
  assert.equal(h.element('containerActionStart').disabled, true);
  h.context.containerActionPrepare('stop');
  assert.equal(h.element('containerActionDialog').open, true);
  assert.equal(h.calls.filter((item) => item.options.method === 'POST').length, 1);
  action = 'stop';
  await h.context.containerActionConfirm();
  assert.equal(h.element('containerActionDialog').open, false);
  assert.equal(h.element('containerActionStop').disabled, true);
  assert.match(h.element('containerActionStatus').textContent, /Проверьте состояние заново/);
  assert.equal(h.calls.filter((item) => item.options.method === 'POST').length, 2);
});

test('role loss, protected target and incomplete inventory prevent controls', async () => {
  const h = harness(); h.render();
  h.context.containerActionPrepare('stop');
  assert.equal(h.element('containerActionDialog').open, false);
  h.server.latest.details.containers.engines[0].truncated = true;
  h.render();
  assert.equal(h.element('containerActionTarget').children.length, 0);
  h.server.latest.details.containers.engines[0].truncated = false;
  h.server.access_role = 'viewer';
  h.render();
  assert.equal(h.element('containerActionPanel').hidden, true);
  assert.equal(h.element('containerActionCheck').disabled, true);
  assert.equal(h.calls.length, 0);
});

test('lost mutation reply clears proof and requires another status check', async () => {
  const h = harness(); h.render();
  h.setFetchHook((url, options) => {
    if (url.endsWith('/containers/actions') && JSON.parse(options.body).action === 'stop')
      return Promise.reject(Object.assign(new Error('lost'), { name: 'AbortError' }));
    if (url.endsWith('/containers/actions'))
      return Promise.resolve(reply(201, { job: { id: randomUUID(), server_id: h.server.id } }));
    if (url.includes('/containers/control?')) return Promise.resolve(reply(200,
      { control: { source_status: 'ok', engine: 'docker', id: ID,
        observed_at: Math.floor(Date.now() / 1000), state: 'running' } }));
    return Promise.resolve(reply(200, { job: { id: url.split('/').pop(),
      server_id: h.server.id, state: 'succeeded' } }));
  });
  await h.context.containerActionQueue('status', h.context.containerActionTarget());
  h.context.containerActionPrepare('stop');
  await h.context.containerActionConfirm();
  assert.equal(h.element('containerActionStop').disabled, true);
  assert.match(h.element('containerActionError').textContent, /могло выполниться/);
  h.context.containerActionPrepare('stop');
  assert.equal(h.element('containerActionDialog').open, false);
  assert.equal(h.calls.filter((item) => item.options.method === 'POST').length, 2);
});

test('a changed inventory or hidden tab invalidates an earlier status proof', async () => {
  const h = harness(); h.render();
  h.setFetchHook((url, options) => {
    if (options.method === 'POST') return Promise.resolve(reply(201,
      { job: { id: randomUUID(), server_id: h.server.id } }));
    if (url.includes('/containers/control?')) return Promise.resolve(reply(200,
      { control: { source_status: 'ok', engine: 'docker', id: ID,
        observed_at: Math.floor(Date.now() / 1000), state: 'running' } }));
    return Promise.resolve(reply(200, { job: { id: url.split('/').pop(),
      server_id: h.server.id, state: 'succeeded' } }));
  });
  await h.context.containerActionQueue('status', h.context.containerActionTarget());
  assert.equal(h.element('containerActionStop').disabled, false);
  h.server.latest.details.containers.engines[0].containers[0].state = 'exited';
  h.render();
  assert.equal(h.element('containerActionStop').disabled, true);
  h.context.containerActionPrepare('stop');
  assert.equal(h.element('containerActionDialog').open, false);
  h.context.document.hidden = true;
  h.listeners.get('visibilitychange')();
  assert.equal(h.element('containerActionCheck').disabled, true);
  assert.equal(h.element('containerActionStop').disabled, true);
  assert.equal(h.calls.filter((item) => item.options.method === 'POST').length, 1);
});

test('the container action source ships in the online and PWA shells', () => {
  const html = fs.readFileSync('index.html', 'utf8');
  const shell = fs.readFileSync('sw.js', 'utf8');
  const dockerfile = fs.readFileSync('Dockerfile', 'utf8');
  assert.match(html, /id="containerActionPanel"[^>]+data-admin-only[^>]+hidden/);
  assert.match(html, /container-control\.js\?v=1/);
  assert.match(shell, /container-control\.js\?v=1/);
  assert.match(dockerfile, /container-control\.js/);
});

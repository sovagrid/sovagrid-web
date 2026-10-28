/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const ID = 'a'.repeat(64);
const reply = (status, payload) => ({ ok: status < 400, status,
  text: async () => JSON.stringify(payload) });
const config = (revision = 0, rules = [], source_status = 'ok') => ({
  revision, hold_seconds: 120, rules, source_status,
  observed_at: Math.floor(Date.now() / 1000),
  observations: rules.map(({ name }) => ({ name, status: 'running' })),
});
const rule = (name = 'worker') => ({ name, stopped: true, unhealthy: true, missing: false });

function harness() {
  const elements = new Map(), calls = [];
  const make = () => ({ value: '', checked: false, required: false, hidden: false, disabled: false,
    textContent: '', open: false, children: [], className: '', events: {},
    addEventListener(name, fn) { this.events[name] = fn; }, setAttribute() {},
    append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = items; },
    focus() {}, showModal() { this.open = true; }, close() { this.open = false; this.events.close?.(); } });
  const element = (id) => { if (!elements.has(id)) elements.set(id, make()); return elements.get(id); };
  let hook = () => reply(200, config());
  const context = vm.createContext({ URL, AbortController, TextEncoder, Intl,
    setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    navigator: {}, location: new URL('https://hub.example'),
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    document: { hidden: false, getElementById: element, createElement: make,
      querySelectorAll: () => [], addEventListener() {} },
    fetch: async (url, options) => { calls.push({ url, options }); return hook(url, options); },
  });
  for (const source of ['app.js', 'container-alerts.js'])
    vm.runInContext(fs.readFileSync(source, 'utf8'), context);
  const state = vm.runInContext('state', context);
  const server = { id: 'server-1', online: true, access_role: 'admin', latest: { details: {
    containers: { version: 1, collected_at: Math.floor(Date.now() / 1000), engines: [
      { engine: 'docker', source_status: 'ok', truncated: false,
        containers: [{ id: ID, name: 'worker', image: 'worker:1', state: 'running', health: 'healthy' }] },
      { engine: 'podman', source_status: 'unavailable', truncated: false, containers: [] },
    ] },
  } } };
  Object.assign(state, { token: 'session', base: 'https://hub.example', selectedId: server.id,
    view: 'overview', servers: [server],
    user: { id: 'admin', role: 'admin', enabled: true, legacy: false },
    access: { mode: 'all', revision: 1, unrestricted_admin: true } });
  return { context, state, server, element, calls, setHook: (fn) => { hook = fn; } };
}
const submit = { preventDefault() {} };

test('admin adds an observed Docker name through revision CAS', async () => {
  const h = harness(); await h.context.containerAlertsRefresh();
  assert.equal(h.element('containerAlertsAdd').disabled, false);
  h.context.containerAlertsOpen('create');
  assert.equal(h.element('containerAlertDialog').open, true);
  assert.equal(h.element('containerAlertName').value, 'worker');
  h.setHook((_url, options) => {
    if (options.method === 'PUT') {
      assert.deepEqual(JSON.parse(options.body), { revision: 0, hold_seconds: 120, rules: [rule()] });
      return reply(200, config(1, [rule()]));
    }
    return reply(200, config(1, [rule()]));
  });
  await h.context.containerAlertsSubmit(submit);
  assert.equal(h.element('containerAlertDialog').open, false);
  assert.equal(h.element('containerAlertsCount').textContent, '1');
  assert.equal(h.calls.filter((item) => item.options.method === 'PUT').length, 1);
});

test('viewer sees status but cannot edit; partial source disables new rules', async () => {
  const h = harness(); h.setHook(() => reply(200, config(1, [rule()], 'partial')));
  await h.context.containerAlertsRefresh();
  assert.equal(h.element('containerAlertsAdd').disabled, true);
  h.server.access_role = 'viewer'; h.context.containerAlertsRenderInventory();
  assert.equal(h.element('containerAlertsList').children[0].children.length, 2);
  h.context.containerAlertsOpen('edit', 'worker');
  assert.equal(h.element('containerAlertDialog').open, false);
  assert.equal(h.calls.filter((item) => item.options.method === 'PUT').length, 0);
});

test('lost save reply reconciles with one GET and never repeats PUT', async () => {
  const h = harness(); await h.context.containerAlertsRefresh();
  h.context.containerAlertsOpen('create');
  h.setHook((_url, options) => options.method === 'PUT'
    ? Promise.reject(new Error('connection lost')) : reply(200, config(1, [rule()])));
  await h.context.containerAlertsSubmit(submit);
  assert.equal(h.element('containerAlertDialog').open, false);
  assert.match(h.element('containerAlertsMessage').textContent, /повторным чтением/);
  assert.equal(h.calls.filter((item) => item.options.method === 'PUT').length, 1);
});

test('invalid condition and lost administrator access prevent mutation', async () => {
  const h = harness(); await h.context.containerAlertsRefresh(); h.context.containerAlertsOpen('create');
  h.element('containerAlertStopped').checked = false;
  h.element('containerAlertUnhealthy').checked = false;
  h.element('containerAlertMissing').checked = false;
  await h.context.containerAlertsSubmit(submit);
  assert.match(h.element('containerAlertDialogError').textContent, /хотя бы одно условие/);
  h.server.access_role = 'viewer'; h.context.containerAlertsRenderInventory();
  assert.equal(h.element('containerAlertDialog').open, false);
  assert.equal(h.calls.filter((item) => item.options.method === 'PUT').length, 0);
});

test('container incident shows its authorized subject and never inserts markup', () => {
  const h = harness();
  const incident = { kind: `container:${'a'.repeat(64)}`, subject: '<script>unsafe</script>',
    state: 'firing', opened_at: 100, updated_at: 100 };
  const label = vm.runInContext(`incidentLabel(${JSON.stringify(incident)})`, h.context);
  assert.match(label, /Docker-контейнером «<script>unsafe<\/script>»/);
  assert.equal(fs.readFileSync('container-alerts.js', 'utf8').includes('.innerHTML'), false);
});

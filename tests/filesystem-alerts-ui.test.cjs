/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const reply = (status, payload) => ({ ok: status < 400, status,
  text: async () => JSON.stringify(payload) });
const rule = (mountpoint = '/', metric = 'space', threshold_percent = 90) =>
  ({ mountpoint, metric, threshold_percent });
const config = (revision = 0, rules = [], source_status = 'ok') => ({
  server_id: 'server-1', revision, hold_seconds: 120, rules, source_status,
  observed_at: Math.floor(Date.now() / 1000),
  filesystems: source_status === 'ok' ? [
    { mountpoint: '/', fstype: 'ext4', space_used_percent: 62, inodes_used_percent: 22 },
    { mountpoint: '/data', fstype: 'xfs', space_used_percent: 51, inodes_used_percent: null },
  ] : [],
  observations: rules.map(({ mountpoint, metric }) =>
    ({ mountpoint, metric, status: 'normal', used_percent: 62 })),
});

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
  for (const source of ['app.js', 'filesystem-alerts.js'])
    vm.runInContext(fs.readFileSync(source, 'utf8'), context);
  const state = vm.runInContext('state', context);
  const server = { id: 'server-1', online: true, access_role: 'admin', latest: { details: {} } };
  Object.assign(state, { token: 'session', base: 'https://hub.example', selectedId: server.id,
    view: 'overview', servers: [server],
    user: { id: 'admin', role: 'admin', enabled: true, legacy: false },
    access: { mode: 'all', revision: 1, unrestricted_admin: true } });
  return { context, state, server, element, calls, setHook: (fn) => { hook = fn; } };
}
const submit = { preventDefault() {} };

test('admin chooses only a fresh mountpoint and saves the exact space threshold via CAS', async () => {
  const h = harness(); await h.context.filesystemAlertsRefresh();
  assert.equal(h.element('filesystemAlertsAdd').disabled, false);
  h.context.filesystemAlertsOpen('create');
  assert.equal(h.element('filesystemAlertDialog').open, true);
  assert.equal(h.element('filesystemAlertMountpoint').value, '/');
  assert.equal(h.element('filesystemAlertMetric').value, 'space');
  h.element('filesystemAlertThreshold').value = '83';
  h.setHook((_url, options) => {
    if (options.method === 'PUT') {
      assert.deepEqual(JSON.parse(options.body), { revision: 0, hold_seconds: 120, rules: [rule('/', 'space', 83)] });
      return reply(200, config(1, [rule('/', 'space', 83)]));
    }
    return reply(200, config(1, [rule('/', 'space', 83)]));
  });
  await h.context.filesystemAlertsSubmit(submit);
  assert.equal(h.element('filesystemAlertDialog').open, false);
  assert.equal(h.element('filesystemAlertsCount').textContent, '1');
  assert.equal(h.calls.filter((item) => item.options.method === 'PUT').length, 1);
});

test('viewer reads status but cannot mutate; partial inventory forbids new rules', async () => {
  const h = harness(); h.setHook(() => reply(200, config(2, [rule()], 'partial')));
  await h.context.filesystemAlertsRefresh();
  assert.equal(h.element('filesystemAlertsAdd').disabled, true);
  h.server.access_role = 'viewer'; h.context.filesystemAlertsRenderInventory();
  assert.equal(h.element('filesystemAlertsList').children[0].children.length, 2);
  h.context.filesystemAlertsOpen('edit', 'space\0/');
  assert.equal(h.element('filesystemAlertDialog').open, false);
  assert.equal(h.calls.filter((item) => item.options.method === 'PUT').length, 0);
});

test('missing mountpoint is unknown and never offered as a fresh choice', async () => {
  const h = harness();
  h.setHook(() => reply(200, { ...config(1, [rule('/lost')]),
    filesystems: config().filesystems.filter((row) => row.mountpoint !== '/lost'),
    observations: [{ mountpoint: '/lost', metric: 'space', status: 'unknown', used_percent: null }] }));
  await h.context.filesystemAlertsRefresh();
  assert.match(h.element('filesystemAlertsList').children[0].children[0].children[1].textContent,
    /Нет достоверных данных/);
  h.context.filesystemAlertsOpen('create');
  assert.notEqual(h.element('filesystemAlertMountpoint').value, '/lost');
});

test('lost save reply reconciles once by GET without replaying PUT', async () => {
  const h = harness(); await h.context.filesystemAlertsRefresh();
  h.context.filesystemAlertsOpen('create');
  h.setHook((_url, options) => options.method === 'PUT'
    ? Promise.reject(new Error('connection lost')) : reply(200, config(1, [rule()])));
  await h.context.filesystemAlertsSubmit(submit);
  assert.equal(h.element('filesystemAlertDialog').open, false);
  assert.match(h.element('filesystemAlertsMessage').textContent, /повторным чтением/);
  assert.equal(h.calls.filter((item) => item.options.method === 'PUT').length, 1);
});

test('invalid threshold and lost administrator access prevent mutation', async () => {
  const h = harness(); await h.context.filesystemAlertsRefresh(); h.context.filesystemAlertsOpen('create');
  h.element('filesystemAlertThreshold').value = '0';
  await h.context.filesystemAlertsSubmit(submit);
  assert.match(h.element('filesystemAlertDialogError').textContent, /от 1 до 100/);
  h.server.access_role = 'viewer'; h.context.filesystemAlertsRenderInventory();
  assert.equal(h.element('filesystemAlertDialog').open, false);
  assert.equal(h.calls.filter((item) => item.options.method === 'PUT').length, 0);
});

test('untrusted mountpoint and incident subject are rendered as text', async () => {
  const h = harness();
  const name = '/<script>unsafe</script>';
  h.setHook(() => reply(200, { ...config(1, [rule(name)]),
    observations: [{ mountpoint: name, metric: 'space', status: 'alert', used_percent: 99 }] }));
  await h.context.filesystemAlertsRefresh();
  assert.equal(h.element('filesystemAlertsList').children[0].children[0].children[0].textContent, name);
  assert.match(vm.runInContext('incidentLabel({kind:"filesystem:space:"+"a".repeat(64),subject:"' +
    name + '"})', h.context), /<script>unsafe<\/script>/);
  assert.equal(fs.readFileSync('filesystem-alerts.js', 'utf8').includes('.innerHTML'), false);
});

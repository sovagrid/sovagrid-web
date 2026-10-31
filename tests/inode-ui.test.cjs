/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const response = (status, payload) => ({ ok: status < 400, status, text: async () => JSON.stringify(payload) });
const settings = (values = {}) => ({ threshold_percent: null, hold_seconds: 60, revision: 0, ...values });
const path = 'https://hub.example/api/v1/monitoring/inode-settings';

function harness(hook) {
  const elements = new Map(), calls = [];
  const make = () => ({ value: '', checked: false, required: false, disabled: false, hidden: false,
    textContent: '', className: '', children: [], listeners: new Map(),
    addEventListener(name, fn) { this.listeners.set(name, fn); }, setAttribute() {},
    append(...children) { this.children.push(...children); }, replaceChildren(...children) { this.children = children; } });
  const element = (id) => { if (!elements.has(id)) elements.set(id, make()); return elements.get(id); };
  const context = vm.createContext({ URL, AbortController, setTimeout, clearTimeout,
    setInterval: () => 1, clearInterval() {}, document: { getElementById: element,
      createElement: make, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    navigator: {}, location: new URL('https://hub.example'),
    fetch: async (url, options) => {
      calls.push({ url, options });
      if (hook) return hook(url, options);
      return response(200, { settings: settings() });
    },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('inode.js', 'utf8'), context);
  const state = vm.runInContext('state', context), client = vm.runInContext('inodeClient', context);
  Object.assign(state, { token: 'session-a', base: 'https://hub.example', view: 'settings',
    user: { id: 'owner', username: 'owner', role: 'admin' },
    access: { mode: 'all', revision: 0, unrestricted_admin: true } });
  return { context, state, client, element, calls,
    change(id, value, event = 'input') {
      const field = element(id);
      if (typeof value === 'boolean') field.checked = value;
      else field.value = value;
      field.listeners.get(event)();
    } };
}
const submit = { preventDefault() {} };

test('root inode rule is opt-in and CAS save uses exact typed values', async () => {
  let current = settings();
  const h = harness((url, options) => {
    assert.equal(url, path);
    assert.equal(options.headers.Authorization, 'Bearer session-a');
    if (options.method === 'POST') {
      const body = JSON.parse(options.body);
      assert.deepEqual(body, { threshold_percent: 93.5, hold_seconds: 90, revision: 0 });
      current = settings({ ...body, revision: 1 });
    }
    return response(200, { settings: current });
  });
  await h.context.inodeRefresh();
  assert.equal(h.element('inodeEnabled').checked, false);
  assert.match(h.element('inodeStatus').textContent, /Правило выключено/);
  assert.equal(h.element('inodeFields').hidden, true);
  h.change('inodeEnabled', true, 'change');
  h.change('inodeThreshold', '93.5'); h.change('inodeHold', '90');
  assert.equal(h.element('inodeFields').hidden, false);
  assert.equal(h.element('inodeSave').disabled, false);
  await h.context.inodeSave(submit);
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 1);
  assert.equal(h.client.data.revision, 1);
  assert.equal(h.element('inodeSave').disabled, true);
  assert.match(h.element('inodeStatus').textContent, /порог 93.5%/);
});

test('turning the rule off sends null and keeps the saved hold', async () => {
  let current = settings({ threshold_percent: 91.2, hold_seconds: 300 });
  const h = harness((_url, options) => {
    if (options.method === 'POST') {
      assert.deepEqual(JSON.parse(options.body), { threshold_percent: null, hold_seconds: 300, revision: 0 });
      current = settings({ threshold_percent: null, hold_seconds: 300, revision: 1 });
    }
    return response(200, { settings: current });
  });
  await h.context.inodeRefresh();
  assert.equal(h.element('inodeEnabled').checked, true);
  h.change('inodeEnabled', false, 'change');
  assert.equal(h.element('inodeFields').hidden, true);
  await h.context.inodeSave(submit);
  assert.equal(h.client.data.threshold_percent, null);
});

test('bad percentages and hold periods never reach Hub', async () => {
  const h = harness(() => response(200, { settings: settings() }));
  await h.context.inodeRefresh(); h.change('inodeEnabled', true, 'change');
  for (const value of ['', '0', '-1', '100.1', '1e2', 'NaN']) {
    h.change('inodeThreshold', value); await h.context.inodeSave(submit);
    assert.match(h.element('inodeError').textContent, /Порог inode/);
  }
  h.change('inodeThreshold', '90');
  for (const value of ['29', '86401', '60.5', '']) {
    h.change('inodeHold', value); await h.context.inodeSave(submit);
    assert.match(h.element('inodeError').textContent, /Задержка тревоги inode/);
  }
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 0);
});

test('viewer reads the rule but cannot edit or post', async () => {
  const h = harness((_url, options) => {
    assert.notEqual(options.method, 'POST');
    return response(200, { settings: settings({ threshold_percent: 95 }) });
  });
  h.state.user.role = 'viewer'; h.state.access.unrestricted_admin = false;
  await h.context.inodeRefresh();
  assert.equal(h.element('inodeEnabled').disabled, true);
  assert.equal(h.element('inodeThreshold').disabled, true);
  assert.equal(h.element('inodeSave').hidden, true);
  h.change('inodeThreshold', '80'); await h.context.inodeSave(submit);
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 0);
});

test('changed revision and uncertain POST require a fresh read, never an automatic retry', async () => {
  for (const status of [409, 503]) {
    let current = settings({ threshold_percent: 90 });
    const h = harness((_url, options) => options.method === 'POST'
      ? response(status, { error: 'changed' }) : response(200, { settings: current }));
    await h.context.inodeRefresh(); h.change('inodeThreshold', '95');
    await h.context.inodeSave(submit);
    assert.equal(h.client.conflict, true);
    assert.equal(h.element('inodeThreshold').value, '95');
    assert.equal(h.element('inodeSave').disabled, true);
    await h.context.inodeSave(submit);
    assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 1);
    current = settings({ threshold_percent: 92, revision: 1 });
    await h.context.inodeRefresh({ replace: true });
    assert.equal(h.element('inodeThreshold').value, '92');
    assert.equal(h.client.conflict, false);
  }
});

test('older Hub is unknown rather than off, and late logout response is ignored', async () => {
  const old = harness(() => response(404, { error: 'Not found' }));
  await old.context.inodeRefresh();
  assert.match(old.element('inodeStatus').textContent, /Обновите Hub/);
  assert.equal(old.element('inodeEnabled').disabled, true);
  let resolve;
  const h = harness(() => new Promise((done) => { resolve = done; }));
  const pending = h.context.inodeRefresh();
  h.context.logout(false); h.state.token = 'session-b';
  resolve(response(200, { settings: settings({ threshold_percent: 90 }) }));
  await pending;
  assert.equal(h.client.data, null);
  assert.equal(h.element('inodeEnabled').checked, false);
});

test('missing or contradictory root counters are unknown; closed incidents do not claim recovery', () => {
  const h = harness();
  const valid = { filesystems: [{ mountpoint: '/', inodes_total: 1000, inodes_available: 100,
    inodes_used_percent: 90, used_percent: 50, fstype: 'ext4', available_bytes: 100 }] };
  h.context.renderAdvanced(valid, true);
  assert.match(h.element('rootInodeStatus').textContent, /90% inode/);
  h.context.renderAdvanced(valid, false);
  assert.match(h.element('rootInodeStatus').textContent, /Текущее состояние неизвестно/);
  h.context.renderAdvanced({ filesystems: [{ ...valid.filesystems[0], inodes_total: 0 }] }, true);
  assert.match(h.element('rootInodeStatus').textContent, /неизвестно/);
  h.context.renderAdvanced({ filesystems: [{ ...valid.filesystems[0], inodes_used_percent: 10 }] }, true);
  assert.match(h.element('rootInodeStatus').textContent, /неизвестно/);
  h.context.renderAdvanced({}, true);
  assert.match(h.element('rootInodeStatus').textContent, /неизвестно/);
  const active = { server_id: 's', kind: 'high_root_inodes', state: 'firing',
    current_value: 97.5, threshold: 90, opened_at: 1000, updated_at: 1050 };
  h.state.selectedId = 's'; h.state.incidents = [active];
  h.context.renderIncidents('s'); h.context.renderEvents();
  assert.match(h.element('incidentsList').children[0].children[1].children[1].textContent,
    /Последнее подтверждённое измерение: 97.5% inode занято · порог 90%/);
  active.state = 'resolved'; active.resolved_at = 1100; active.updated_at = 1100;
  h.context.renderIncidents('s'); h.context.renderEvents();
  const closed = h.element('incidentsList').children[0];
  assert.match(closed.className, /inode-closed/);
  assert.match(closed.children[1].children[1].textContent, /^Закрыто:/);
  assert.equal(closed.children[1].children[1].textContent.includes('Восстановлено'), false);
  assert.equal(closed.children[1].children[1].textContent.includes('97.5%'), false);
});

test('inode form is included in the container and scoped offline shell', () => {
  assert.match(fs.readFileSync('Dockerfile', 'utf8'), /monitoring\.js inode\.js/);
  assert.match(fs.readFileSync('index.html', 'utf8'), /inode\.js\?v=1/);
  assert.match(fs.readFileSync('sw.js', 'utf8'), /inode\.js\?v=1/);
  assert.match(fs.readFileSync('sw.js', 'utf8'), /\$\{CACHE_PREFIX\}v86/);
});

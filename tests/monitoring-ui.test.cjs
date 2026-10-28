/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const response = (status, payload) => ({ ok: status >= 200 && status < 300, status,
  text: async () => JSON.stringify(payload) });
const settings = (overrides = {}) => ({ high_cpu: 90, high_memory: 90, high_disk: 90,
  offline_seconds: 120, trigger_minutes: 0, revision: 0, ...overrides });

function harness(fetchHook) {
  const elements = new Map(), calls = [];
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { value: '', textContent: '', hidden: false, disabled: false,
        open: false, listeners,
        addEventListener(name, fn) { listeners.set(name, fn); },
        setAttribute() {}, replaceChildren() {}, close() { this.open = false; },
      });
    }
    return elements.get(id);
  };
  const context = vm.createContext({
    URL, AbortController, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    navigator: {}, location: new URL('https://hub.example'),
    fetch: (url, options) => { calls.push({ url, options }); return fetchHook(url, options); },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('monitoring.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  const client = vm.runInContext('monitoringClient', context);
  state.base = 'https://hub.example'; state.token = 'admin-session'; state.view = 'settings';
  return { context, state, client, element, calls,
    change(id, value) { element(id).value = value; element(id).listeners.get('input')(); } };
}

test('settings are loaded, edited and saved without a restart or console input', async () => {
  let current = settings();
  const h = harness((url, options) => {
    assert.equal(url, 'https://hub.example/api/v1/monitoring/settings');
    assert.equal(options.headers.Authorization, 'Bearer admin-session');
    if (options.method === 'POST') {
      const data = JSON.parse(options.body);
      assert.deepEqual(data, { high_cpu: 85.5, high_memory: 90, high_disk: 90,
        offline_seconds: 180, trigger_minutes: 5, revision: 0 });
      current = settings({ ...data, revision: 1 });
    }
    return Promise.resolve(response(200, { settings: current }));
  });
  await h.context.monitoringRefresh();
  assert.equal(h.element('monitoringCpu').value, '90');
  assert.equal(h.element('monitoringOffline').value, '120');
  assert.equal(h.element('monitoringTrigger').value, '0');
  assert.equal(h.element('monitoringSave').disabled, true);
  h.change('monitoringCpu', '85.5');
  h.change('monitoringOffline', '180');
  h.change('monitoringTrigger', '5');
  assert.equal(h.element('monitoringSave').disabled, false);
  await h.context.monitoringSave({ preventDefault() {} });
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 1);
  assert.equal(h.client.data.revision, 1);
  assert.equal(h.element('monitoringSave').disabled, true);
  assert.match(h.element('monitoringMessage').textContent, /без перезапуска/);
});

test('invalid values stay in the form and never reach the Hub', async () => {
  const h = harness(() => Promise.resolve(response(200, { settings: settings() })));
  await h.context.monitoringRefresh();
  h.change('monitoringCpu', '0');
  await h.context.monitoringSave({ preventDefault() {} });
  assert.match(h.element('monitoringError').textContent, /от 1 до 100/);
  h.change('monitoringCpu', '90');
  h.change('monitoringOffline', '10.5');
  await h.context.monitoringSave({ preventDefault() {} });
  assert.match(h.element('monitoringError').textContent, /целое число секунд/);
  h.change('monitoringOffline', '120');
  h.change('monitoringTrigger', '1.5');
  await h.context.monitoringSave({ preventDefault() {} });
  assert.match(h.element('monitoringError').textContent, /целое число минут/);
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 0);
});

test('periodic refresh preserves unsaved edits and identifies another administrator change', async () => {
  let current = settings();
  const h = harness(() => Promise.resolve(response(200, { settings: current })));
  await h.context.monitoringRefresh();
  h.change('monitoringCpu', '82');
  await h.context.monitoringRefresh();
  assert.equal(h.element('monitoringCpu').value, '82');
  assert.equal(h.element('monitoringSave').disabled, false);
  current = settings({ high_cpu: 94, revision: 1 });
  await h.context.monitoringRefresh();
  assert.equal(h.element('monitoringCpu').value, '82');
  assert.equal(h.element('monitoringSave').disabled, true);
  assert.match(h.element('monitoringError').textContent, /другой вкладке/);
  h.element('monitoringReload').listeners.get('click')();
  await new Promise((done) => setImmediate(done));
  assert.equal(h.element('monitoringCpu').value, '94');
  assert.equal(h.client.conflict, false);
});

test('409 conflict keeps edits and requires loading the saved settings', async () => {
  let current = settings();
  const h = harness((url, options) => options.method === 'POST'
    ? Promise.resolve(response(409, { error: 'changed' }))
    : Promise.resolve(response(200, { settings: current })));
  await h.context.monitoringRefresh();
  h.change('monitoringDisk', '80');
  await h.context.monitoringSave({ preventDefault() {} });
  assert.equal(h.element('monitoringDisk').value, '80');
  assert.equal(h.element('monitoringSave').disabled, true);
  assert.match(h.element('monitoringError').textContent, /Вернуть сохранённое/);
  current = settings({ high_disk: 91, revision: 1 });
  await h.context.monitoringRefresh({ replace: true });
  assert.equal(h.element('monitoringDisk').value, '91');
});

test('logout clears settings and a late response cannot fill a new session', async () => {
  let resolve;
  const h = harness(() => new Promise((done) => { resolve = done; }));
  const pending = h.context.monitoringRefresh();
  h.context.logout(false);
  h.state.token = 'new-session';
  resolve(response(200, { settings: settings() }));
  await pending;
  assert.equal(h.client.data, null);
  assert.equal(h.element('monitoringCpu').value, '');
});

test('monitoring UI script is included in the container and offline shell', () => {
  assert.match(fs.readFileSync('Dockerfile', 'utf8'), /telegram\.js monitoring\.js/);
  assert.match(fs.readFileSync('index.html', 'utf8'), /monitoring\.js\?v=3/);
  assert.match(fs.readFileSync('sw.js', 'utf8'), /monitoring\.js\?v=3/);
});

test('viewer can read thresholds but cannot edit or submit them', async () => {
  const h = harness(() => Promise.resolve(response(200, { settings: settings() })));
  h.state.user = { id: 'read-only', username: 'reader', role: 'viewer' };
  await h.context.monitoringRefresh();
  assert.equal(h.element('monitoringCpu').value, '90');
  assert.equal(h.element('monitoringCpu').disabled, true);
  assert.equal(h.element('monitoringTrigger').disabled, true);
  assert.equal(h.element('monitoringSave').hidden, true);
  h.change('monitoringCpu', '95');
  await h.context.monitoringSave({ preventDefault() {} });
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 0);
});

test('incident history shows explicit recovery time and duration', () => {
  const h = harness(() => Promise.resolve(response(200, { settings: settings() })));
  const recovered = h.context.incidentTimeline({ state: 'resolved', opened_at: 1000,
    updated_at: 1061, resolved_at: 1061 });
  assert.match(recovered, /^Восстановлено:/);
  assert.match(recovered, /начало:/);
  assert.match(recovered, /длилось 1 мин/);
  const active = h.context.incidentTimeline({ state: 'firing', opened_at: 1000,
    updated_at: 1061 });
  assert.match(active, /^Тревога с/);
});

test('cached new panel keeps older Hub settings usable without sending an unknown field', async () => {
  const current = settings(); delete current.trigger_minutes;
  const h = harness((url, options) => {
    if (options.method === 'POST') {
      assert.deepEqual(JSON.parse(options.body), { high_cpu: 88, high_memory: 90,
        high_disk: 90, offline_seconds: 120, revision: 0 });
      return Promise.resolve(response(200, { settings: { ...current, high_cpu: 88, revision: 1 } }));
    }
    return Promise.resolve(response(200, { settings: current }));
  });
  await h.context.monitoringRefresh();
  assert.equal(h.element('monitoringTrigger').disabled, true);
  assert.match(h.element('monitoringTriggerHint').textContent, /Обновите/);
  h.change('monitoringCpu', '88');
  await h.context.monitoringSave({ preventDefault() {} });
  assert.equal(h.client.data.high_cpu, 88);
  assert.equal(h.client.data.revision, 1);
});

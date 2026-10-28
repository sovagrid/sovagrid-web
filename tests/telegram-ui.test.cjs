/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const { randomUUID } = require('node:crypto');

const response = (status, payload) => ({ ok: status >= 200 && status < 300, status,
  text: async () => JSON.stringify(payload) });
const telegram = (overrides = {}) => ({ mode: 'managed', configured: false, polling: false,
  connected: false, last_success_at: null, error: null, bindings: [],
  pending_requests: [], bot_username: null, ...overrides });

function harness() {
  const elements = new Map(), stored = [];
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { textContent: '', value: '', hidden: false, disabled: false,
        open: false, children: [], listeners, className: '', placeholder: '', type: 'password',
        addEventListener(name, fn) { listeners.set(name, fn); },
        setAttribute(name, value) { this[name] = value; }, append(...nodes) { this.children.push(...nodes); },
        focus() { this.focused = true; },
        replaceChildren() { this.children = []; this.textContent = ''; },
        showModal() { this.open = true; },
        close() { this.open = false; listeners.get('close')?.({}); },
      });
    }
    return elements.get(id);
  };
  let fetchHook = () => { throw new Error('unexpected fetch'); };
  const context = vm.createContext({
    URL, AbortController, TextEncoder, TextDecoder, Uint8Array, btoa, atob,
    crypto: { randomUUID }, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, createElement: () => element(Symbol()),
      querySelectorAll: () => [], addEventListener() {}, body: { append() {} } },
    navigator: {}, localStorage: { getItem: () => null,
      setItem(...args) { stored.push(args); }, removeItem() {} },
    location: { protocol: 'file:' }, fetch: (...args) => fetchHook(...args),
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('telegram.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  const client = vm.runInContext('telegramClient', context);
  state.base = 'https://hub.example'; state.token = 'admin-session'; state.view = 'telegram';
  return { context, state, client, element, stored,
    setFetchHook: (fn) => { fetchHook = fn; } };
}

test('managed token is sent once, cleared from DOM, and represented only by a fixed mask', async () => {
  const h = harness();
  const secret = '123456789:AA_TEST_TOKEN_WITHOUT_REAL_CREDENTIAL';
  const calls = [];
  let status = telegram();
  h.setFetchHook((url, options) => {
    calls.push({ url, options });
    assert.equal(options.headers.Authorization, 'Bearer admin-session');
    if (options.method === 'POST') {
      assert.equal(url, 'https://hub.example/api/v1/telegram/token');
      assert.deepEqual(JSON.parse(options.body), { token: secret });
      status = telegram({ configured: true, polling: true, connected: false });
      return Promise.resolve(response(200, { telegram: status }));
    }
    return Promise.resolve(response(200, { telegram: status }));
  });
  await h.context.telegramRefresh();
  h.element('telegramTokenInput').value = secret;
  await h.context.telegramSaveToken({ preventDefault() {} });
  assert.equal(h.element('telegramTokenInput').value, '');
  assert.equal(h.element('telegramTokenState').textContent, 'Сохранён: ••••••••');
  assert.doesNotMatch(h.element('telegramStatusText').textContent +
    h.element('telegramTokenHint').textContent + h.element('telegramTokenState').textContent, /AA_TEST_TOKEN/);
  assert.equal(h.stored.length, 0);
  assert.equal(calls.filter((call) => call.options.method === 'POST').length, 1);
});

test('token setup distinguishes rejected verification from an uncertain response', async () => {
  const h = harness();
  let failure = 'unavailable';
  h.setFetchHook((_url, options) => {
    if (options.method === 'POST') {
      if (failure === 'unavailable') return Promise.resolve(response(503, { error: 'Unavailable' }));
      return Promise.reject(new Error('connection lost'));
    }
    return Promise.resolve(response(200, { telegram: telegram() }));
  });
  await h.context.telegramRefresh();
  h.element('telegramTokenInput').value = '123456789:AA_TEST_TOKEN_WITHOUT_REAL_CREDENTIAL';
  await h.context.telegramSaveToken({ preventDefault() {} });
  assert.match(h.element('telegramTokenError').textContent, /Новый токен не сохранён/);
  failure = 'uncertain';
  h.element('telegramTokenInput').value = '123456789:AA_TEST_TOKEN_WITHOUT_REAL_CREDENTIAL';
  await h.context.telegramSaveToken({ preventDefault() {} });
  assert.match(h.element('telegramTokenError').textContent, /Токен мог сохраниться/);
  assert.equal(h.element('telegramTokenInput').value, '');
});

test('token reveal is explicit and resets to hidden after submit or logout', async () => {
  const h = harness();
  h.setFetchHook(() => Promise.resolve(response(200, { telegram: telegram() })));
  await h.context.telegramRefresh();
  const button = h.element('telegramRevealToken');
  button.listeners.get('click')();
  assert.equal(h.element('telegramTokenInput').type, 'text');
  assert.equal(button['aria-pressed'], 'true');
  h.element('telegramTokenInput').value = 'invalid';
  await h.context.telegramSaveToken({ preventDefault() {} });
  assert.equal(h.element('telegramTokenInput').type, 'password');
  assert.equal(h.element('telegramTokenInput').value, '');
  assert.equal(button['aria-pressed'], 'false');
  assert.equal(h.element('telegramTokenInput').focused, true);
  button.listeners.get('click')();
  h.context.logout(false);
  assert.equal(h.element('telegramTokenInput').type, 'password');
});

test('externally managed token cannot be changed in UI but bindings remain editable', async () => {
  const h = harness();
  h.setFetchHook(() => Promise.resolve(response(200, { telegram: telegram({
    mode: 'managed_externally', configured: true, polling: true, connected: true,
  }) })));
  await h.context.telegramRefresh();
  assert.equal(h.element('telegramTokenInput').disabled, true);
  assert.equal(h.element('telegramSaveToken').disabled, true);
  assert.equal(h.element('telegramRemoveToken').hidden, true);
  assert.equal(h.element('telegramSaveBinding').disabled, false);
  assert.match(h.element('telegramTokenHint').textContent, /настройками службы/);
});

test('private chat role upsert and removal use exact IDs and clear errors', async () => {
  const h = harness();
  const calls = [];
  let bindings = [];
  h.setFetchHook((url, options) => {
    calls.push({ url, options });
    if (options.method === 'POST') {
      const payload = JSON.parse(options.body);
      assert.deepEqual(payload, { user_id: 123456789, chat_id: 123456789, role: 'operator' });
      bindings = [payload];
      return Promise.resolve(response(200, { binding: payload }));
    }
    if (options.method === 'DELETE') {
      assert.equal(url, 'https://hub.example/api/v1/telegram/bindings/123456789/123456789');
      bindings = [];
      return Promise.resolve(response(200, { removed: true }));
    }
    return Promise.resolve(response(200, { telegram: telegram({ bindings }) }));
  });
  await h.context.telegramRefresh();
  h.element('telegramUserId').value = '0';
  await h.context.telegramSaveBinding({ preventDefault() {} });
  assert.match(h.element('telegramBindingError').textContent, /положительный ID/);
  assert.equal(calls.filter((call) => call.options.method === 'POST').length, 0);
  h.element('telegramUserId').value = '123456789';
  h.element('telegramRole').value = 'operator';
  await h.context.telegramSaveBinding({ preventDefault() {} });
  assert.equal(h.element('telegramBindingCount').textContent, '1');
  const row = h.element('telegramBindings').children[0];
  assert.match(row.children[0].children[0].textContent, /Оператор/);
  row.children[1].listeners.get('click')();
  assert.equal(h.element('telegramRemoveBindingDialog').open, true);
  assert.equal(calls.filter((call) => call.options.method === 'DELETE').length, 0);
  await h.context.telegramRemoveBinding();
  assert.equal(h.element('telegramBindingCount').textContent, '0');
  assert.equal(h.element('telegramRemoveBindingDialog').open, false);
});

test('manual admin role requires a review of the exact Telegram ID', async () => {
  const h = harness();
  const calls = [];
  let status = telegram({ configured: true });
  h.setFetchHook((url, options) => {
    if (options.method === 'POST') {
      calls.push(JSON.parse(options.body));
      status = telegram({ configured: true, bindings: [
        { user_id: 123456789, chat_id: 123456789, role: 'admin' },
      ] });
      return Promise.resolve(response(200, { binding: status.bindings[0] }));
    }
    return Promise.resolve(response(200, { telegram: status }));
  });
  await h.context.telegramRefresh();
  h.element('telegramUserId').value = '123456789';
  h.element('telegramRole').value = 'admin';
  await h.context.telegramSaveBinding({ preventDefault() {} });
  assert.equal(h.element('telegramApproveDialog').open, true);
  assert.match(h.element('telegramApproveSummary').textContent, /123456789.*все серверы/);
  assert.equal(calls.length, 0);
  h.element('telegramCancelApprove').listeners.get('click')();
  assert.equal(calls.length, 0);
  await h.context.telegramSaveBinding({ preventDefault() {} });
  h.element('telegramUserId').value = '987654321';
  h.element('telegramConfirmApprove').listeners.get('click')();
  await new Promise((done) => setImmediate(done));
  assert.equal(calls.length, 0);
  assert.match(h.element('telegramApproveError').textContent, /ID или сеанс изменились/);
  h.element('telegramUserId').value = '123456789';
  h.element('telegramRole').value = 'viewer';
  h.element('telegramConfirmApprove').listeners.get('click')();
  await new Promise((done) => setImmediate(done));
  assert.equal(calls.length, 0);
  assert.match(h.element('telegramApproveError').textContent, /Роль изменилась/);
  h.element('telegramRole').value = 'admin';
  h.element('telegramConfirmApprove').listeners.get('click')();
  await new Promise((done) => setImmediate(done));
  assert.deepEqual(calls, [{ user_id: 123456789, chat_id: 123456789, role: 'admin' }]);
  assert.equal(h.element('telegramApproveDialog').open, false);
});

test('pending private chat can be approved by name and role without entering an ID', async () => {
  const h = harness();
  const pending = { user_id: 123456789, chat_id: 123456789, first_name: 'Анна',
    last_name: 'Иванова', username: 'anna_example', requested_at: 1234567890 };
  let status = telegram({ configured: true, bot_username: 'SovaGridBot', pending_requests: [pending] });
  h.setFetchHook((url, options) => {
    if (url.endsWith('/approve')) {
      assert.equal(url, 'https://hub.example/api/v1/telegram/requests/123456789/123456789/approve');
      assert.deepEqual(JSON.parse(options.body), { role: 'operator' });
      status = telegram({ configured: true, bot_username: 'SovaGridBot', bindings: [
        { ...pending, role: 'operator' },
      ] });
    }
    return Promise.resolve(response(200, { telegram: status }));
  });
  await h.context.telegramRefresh();
  assert.equal(h.element('telegramOpenBot').href, 'https://t.me/SovaGridBot');
  assert.equal(h.element('telegramUserId').value, '');
  const row = h.element('telegramRequests').children[0];
  assert.equal(row.children[0].children[0].textContent, 'Анна Иванова');
  const actions = row.children[1];
  const select = actions.children[0];
  select.value = 'operator'; select.listeners.get('change')();
  actions.children[1].listeners.get('click')();
  await new Promise((done) => setImmediate(done));
  assert.equal(h.element('telegramRequestCount').textContent, '0');
  assert.equal(h.element('telegramBindingCount').textContent, '1');
  assert.equal(h.element('telegramUserId').value, '');
});

test('admin pairing requires confirmation and rejection uses a separate action', async () => {
  const h = harness();
  const pending = { user_id: 987654321, chat_id: 987654321, first_name: 'Борис',
    last_name: '', username: null, requested_at: 1234567890 };
  let status = telegram({ configured: true, pending_requests: [pending] });
  const calls = [];
  h.setFetchHook((url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/approve') || url.endsWith('/reject')) status = telegram({ configured: true });
    return Promise.resolve(response(200, { telegram: status }));
  });
  await h.context.telegramRefresh();
  const actions = h.element('telegramRequests').children[0].children[1];
  actions.children[0].value = 'admin';
  actions.children[1].listeners.get('click')();
  assert.equal(h.element('telegramApproveDialog').open, true);
  assert.equal(calls.filter((call) => call.options.method === 'POST').length, 0);
  h.element('telegramCancelApprove').listeners.get('click')();
  assert.equal(h.element('telegramApproveDialog').open, false);
  const retry = h.element('telegramRequests').children[0].children[1];
  retry.children[2].listeners.get('click')();
  await new Promise((done) => setImmediate(done));
  assert.equal(calls.filter((call) => call.url.endsWith('/reject')).length, 1);
  assert.equal(h.element('telegramRequestCount').textContent, '0');
});

test('admin pairing submits only after the confirmation dialog', async () => {
  const h = harness();
  const pending = { user_id: 987654321, chat_id: 987654321, first_name: 'Борис',
    last_name: '', username: null, requested_at: 1234567890 };
  let status = telegram({ configured: true, pending_requests: [pending] }), approved = 0;
  h.setFetchHook((url, options) => {
    if (url.endsWith('/approve')) {
      approved++;
      assert.deepEqual(JSON.parse(options.body), { role: 'admin' });
      status = telegram({ configured: true, bindings: [{ ...pending, role: 'admin' }] });
    }
    return Promise.resolve(response(200, { telegram: status }));
  });
  await h.context.telegramRefresh();
  const actions = h.element('telegramRequests').children[0].children[1];
  actions.children[0].value = 'admin';
  actions.children[1].listeners.get('click')();
  assert.equal(approved, 0);
  assert.match(h.element('telegramApproveSummary').textContent, /Telegram ID 987654321/);
  h.element('telegramConfirmApprove').listeners.get('click')();
  await new Promise((done) => setImmediate(done));
  assert.equal(approved, 1);
  assert.equal(h.element('telegramApproveDialog').open, false);
  assert.equal(h.element('telegramBindingCount').textContent, '1');
});

test('unchanged refresh keeps role selection controls in place', async () => {
  const h = harness();
  const pending = { user_id: 123456789, chat_id: 123456789, first_name: 'Анна',
    last_name: '', username: null, requested_at: 1234567890 };
  h.setFetchHook(() => Promise.resolve(response(200, { telegram: telegram({ pending_requests: [pending] }) })));
  await h.context.telegramRefresh();
  const original = h.element('telegramRequests').children[0];
  const select = original.children[1].children[0];
  select.value = 'operator'; select.listeners.get('change')();
  await h.context.telegramRefresh();
  assert.equal(h.element('telegramRequests').children[0], original);
  assert.equal(select.value, 'operator');
});

test('a stale settings GET cannot overwrite a successful token change', async () => {
  const h = harness();
  let resolveStale, calls = 0;
  h.setFetchHook((url, options) => {
    if (options.method === 'POST') return Promise.resolve(response(200, { telegram: telegram({ configured: true }) }));
    calls++;
    if (calls === 2) return new Promise((resolve) => { resolveStale = resolve; });
    return Promise.resolve(response(200, { telegram: telegram() }));
  });
  await h.context.telegramRefresh();
  const stale = h.context.telegramRefresh();
  h.element('telegramTokenInput').value = '123456789:AA_TEST_TOKEN_WITHOUT_REAL_CREDENTIAL';
  await h.context.telegramSaveToken({ preventDefault() {} });
  resolveStale(response(200, { telegram: telegram() }));
  await stale;
  assert.equal(h.client.data.configured, true);
  assert.equal(h.element('telegramTokenState').textContent, 'Сохранён: ••••••••');
});

test('logout clears typed BotFather token and ignores stale settings response', async () => {
  const h = harness();
  let resolve;
  h.setFetchHook(() => new Promise((done) => { resolve = done; }));
  const pending = h.context.telegramRefresh();
  h.element('telegramTokenInput').value = '123456789:AA_FAKE_TOKEN';
  h.context.logout(false);
  assert.equal(h.element('telegramTokenInput').value, '');
  assert.equal(h.state.token, '');
  resolve(response(200, { telegram: telegram({ configured: true, connected: true }) }));
  await pending;
  assert.equal(h.client.data, null);
  assert.equal(h.element('telegramTokenState').textContent, 'Не настроен');
});

test('container and service worker include Telegram UI script', () => {
  assert.match(fs.readFileSync('Dockerfile', 'utf8'), /COPY[^\n]+telegram\.js/);
  assert.match(fs.readFileSync('index.html', 'utf8'), /telegram\.js\?v=4/);
  assert.match(fs.readFileSync('sw.js', 'utf8'), /telegram\.js\?v=4/);
});


test('durable alert backlog is visible and older Hub responses remain supported', async () => {
  const h = harness();
  h.setFetchHook(() => Promise.resolve(response(200, { telegram: telegram({ pending_incident_notifications: 3 }) })));
  await h.context.telegramRefresh();
  assert.match(h.element('telegramStatusText').textContent, /Уведомлений в очереди: 3/);
  h.setFetchHook(() => Promise.resolve(response(200, { telegram: telegram() })));
  await h.context.telegramRefresh();
  assert.doesNotMatch(h.element('telegramStatusText').textContent, /в очереди/);
  h.context.telegramReset();
  assert.doesNotMatch(h.element('telegramStatusText').textContent, /в очереди/);
});

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
        textContent: '', value: '', hidden: false, disabled: false, open: false, children: [], listeners,
        addEventListener(name, handler) { listeners.set(name, handler); },
        setAttribute() {},
        replaceChildren() { this.children = []; this.value = ''; },
        append(child) { this.children.push(child); if (!this.value) this.value = child.value; },
        showModal() { this.open = true; },
        close() { this.open = false; listeners.get('close')?.({}); },
      });
    }
    return elements.get(id);
  };
  let fetchHook = () => { throw new Error('unexpected fetch'); };
  const timers = new Map();
  let nextTimer = 0;
  const context = vm.createContext({
    URL, AbortController, TextEncoder,
    setTimeout: (callback, delay) => { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
    clearTimeout: (id) => timers.delete(id), setInterval: () => 1, clearInterval() {},
    crypto: { randomUUID },
    document: { getElementById: element, createElement: () => ({ value: '', textContent: '' }), querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    navigator: {}, location: { protocol: 'file:' },
    fetch: (...args) => fetchHook(...args),
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('journal.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  state.base = 'https://hub.example';
  state.token = 'test-token';
  state.servers = [{ id: 'a', name: 'Server A', online: true, remote_commands_enabled: true,
    latest: { details: { journal_units: ['nginx.service', 'ssh.service'] } } }];
  state.selectedId = 'a';
  state.view = 'journal';
  element('journalLines').value = '50';
  return { context, state, element, setFetchHook: (hook) => { fetchHook = hook; },
    fireTimers: (delay) => { for (const [id, timer] of timers) if (timer.delay === delay) {
      timers.delete(id); timer.callback();
    } },
  };
}

const reply = (status, payload) => ({ ok: status >= 200 && status < 300, status,
  text: async () => JSON.stringify(payload) });

test('only advertised exact units appear and disabled access has no action', () => {
  const { context, state, element } = harness();
  context.journalRender();
  assert.deepEqual(element('journalUnit').children.map((option) => option.value), ['nginx.service', 'ssh.service']);
  assert.equal(element('journalPrepare').disabled, false);
  state.servers[0].latest.details.journal_units = [];
  context.journalRender();
  assert.equal(element('journalPrepare').disabled, true);
  assert.equal(element('journalUnit').children.length, 0);
});

test('changing journal unit or line count clears old text without losing selection', () => {
  const { context, element } = harness();
  context.journalRender();
  element('journalOutput').textContent = 'old private log';
  element('journalUnit').value = 'ssh.service';
  element('journalUnit').listeners.get('change')();
  assert.equal(element('journalUnit').value, 'ssh.service');
  assert.equal(element('journalOutput').textContent, '');
  element('journalLines').value = '20';
  element('journalLines').listeners.get('change')();
  assert.equal(element('journalUnit').value, 'ssh.service');
  assert.equal(element('journalLines').value, '20');
  assert.equal(vm.runInContext('JOURNAL_AUTO_INTERVAL_MS', context), 30000);
});

test('confirmation binds server and denies a changed selection before POST', async () => {
  const { context, state, element, setFetchHook } = harness();
  context.journalRender();
  context.journalPrepare();
  assert.equal(element('journalConfirmDialog').open, true);
  assert.match(element('journalConfirmSummary').textContent, /Server A.*nginx.service/);
  state.servers.push({ id: 'b', name: 'Server B', online: true, remote_commands_enabled: true,
    latest: { details: { journal_units: ['nginx.service'] } } });
  state.selectedId = 'b';
  setFetchHook(() => { throw new Error('POST must not run'); });
  await context.journalConfirm();
  assert.match(element('journalConfirmError').textContent, /изменились/);
});

test('ambiguous POST retries with one idempotency key and output remains text', async () => {
  const { context, element, setFetchHook } = harness();
  context.journalRender();
  context.journalPrepare();
  const keys = [];
  let posts = 0;
  const id = randomUUID();
  setFetchHook((url, options) => {
    if (url.endsWith('/journal')) {
      keys.push(options.headers['Idempotency-Key']);
      posts++;
      if (posts === 1) return Promise.reject(Object.assign(new Error('lost'), { name: 'AbortError' }));
      return Promise.resolve(reply(200, { job: { id } }));
    }
    if (url.endsWith(`/jobs/${id}`)) return Promise.resolve(reply(200, { job: {
      id, server_id: 'a', state: 'succeeded', output: '<script>alert(1)</script>\nservice ready',
    } }));
    throw new Error(`unexpected ${url}`);
  });
  await context.journalConfirm();
  assert.match(element('journalConfirmError').textContent, /тот же ключ/);
  assert.equal(element('journalConfirmDialog').open, true);
  await context.journalConfirm();
  assert.equal(posts, 2);
  assert.equal(keys[0], keys[1]);
  assert.equal(element('journalConfirmDialog').open, false);
  assert.equal(element('journalOutput').textContent, '<script>alert(1)</script>\nservice ready');
  context.logout(false);
  assert.equal(element('journalOutput').textContent, '');
});

test('container and offline shell carry the journal script', () => {
  const dockerfile = fs.readFileSync('Dockerfile', 'utf8');
  const html = fs.readFileSync('index.html', 'utf8');
  const shell = fs.readFileSync('sw.js', 'utf8');
  assert.match(dockerfile, /COPY[^\n]*journal\.js/);
  assert.match(html, /journal\.js\?v=2/);
  assert.match(shell, /journal\.js\?v=2/);
});

test('expired transient output asks for a new request', async () => {
  const { context, element, setFetchHook } = harness();
  context.journalRender();
  const id = randomUUID();
  const client = vm.runInContext('journalClient', context);
  client.jobId = id;
  client.jobServerId = 'a';
  setFetchHook(() => Promise.resolve(reply(200, { job: {
    id, server_id: 'a', state: 'succeeded', output: '', transient_output: true, output_expired: true,
  } })));
  await context.journalRefresh();
  assert.match(element('journalOutput').textContent, /Запросите его заново/);
  assert.match(element('journalResultStatus').textContent, /истекло/);
});

test('browser clears journal text from DOM after five minutes', async () => {
  const { context, element, setFetchHook, fireTimers } = harness();
  context.journalRender();
  const id = randomUUID();
  const client = vm.runInContext('journalClient', context);
  client.jobId = id;
  client.jobServerId = 'a';
  setFetchHook(() => Promise.resolve(reply(200, { job: {
    id, server_id: 'a', state: 'succeeded', output: 'sensitive log line', transient_output: true,
  } })));
  await context.journalRefresh();
  assert.equal(element('journalOutput').textContent, 'sensitive log line');
  fireTimers(5 * 60 * 1000);
  assert.match(element('journalOutput').textContent, /Запросите его заново/);
  assert.match(element('journalResultStatus').textContent, /истекло/);
});

test('revoked journal access erases text already shown in this tab', async () => {
  const { context, element, setFetchHook } = harness();
  context.journalRender();
  const client = vm.runInContext('journalClient', context);
  client.jobId = randomUUID();
  client.jobServerId = 'a';
  client.requestUnit = 'nginx.service';
  client.requestLines = 50;
  element('journalOutput').textContent = 'private old line';
  setFetchHook(() => Promise.resolve(reply(403, { error: 'forbidden' })));
  await context.journalRefresh();
  assert.equal(element('journalOutput').textContent, '');
  assert.equal(client.jobId, null);
  assert.match(element('journalError').textContent, /Доступ.*изменился/);
});

test('auto-refresh queues one bounded snapshot at a time and replaces output', async () => {
  const { context, element, setFetchHook } = harness();
  context.journalRender();
  const client = vm.runInContext('journalClient', context);
  client.last = { serverId: 'a', unit: 'nginx.service', lines: 50 };
  client.completed = true;
  context.journalStartAuto();
  assert.ok(client.auto);
  client.auto.nextAt = 0;
  let resolvePost;
  let posts = 0;
  const id = randomUUID();
  setFetchHook((url, options) => {
    if (url.endsWith('/journal')) {
      posts++;
      assert.deepEqual(JSON.parse(options.body), { unit: 'nginx.service', lines: 50 });
      return new Promise((resolve) => { resolvePost = resolve; });
    }
    if (url.endsWith(`/jobs/${id}`)) return Promise.resolve(reply(200, { job: {
      id, server_id: 'a', state: 'succeeded', output: 'new snapshot', transient_output: true,
    } }));
    throw new Error(`unexpected ${url}`);
  });
  const first = context.journalRefresh();
  const second = context.journalRefresh();
  assert.equal(posts, 1);
  resolvePost(reply(201, { job: { id } }));
  await Promise.all([first, second]);
  assert.equal(client.jobId, id);
  assert.equal(client.completed, false);
  await context.journalRefresh();
  assert.equal(element('journalOutput').textContent, 'new snapshot');
  assert.equal(client.completed, true);
  assert.ok(client.auto.nextAt > Date.now());
  assert.equal(posts, 1);
});

test('auto-refresh stops on uncertain POST, access loss, and explicit stop', async () => {
  const { context, state, element, setFetchHook } = harness();
  context.journalRender();
  const client = vm.runInContext('journalClient', context);
  client.last = { serverId: 'a', unit: 'nginx.service', lines: 50 };
  client.completed = true;
  context.journalStartAuto();
  client.auto.nextAt = 0;
  let posts = 0;
  setFetchHook((url) => {
    if (url.endsWith('/journal')) { posts++; return Promise.reject(new Error('lost')); }
    throw new Error(`unexpected ${url}`);
  });
  await context.journalRefresh();
  assert.equal(posts, 1);
  assert.equal(client.auto, null);
  assert.match(element('journalError').textContent, /без повтора/);
  await context.journalRefresh();
  assert.equal(posts, 1);

  context.journalStartAuto();
  assert.ok(client.auto);
  context.journalStopAuto('Остановлено');
  assert.equal(client.auto, null);
  context.journalStartAuto();
  state.servers[0].latest.details.journal_units = [];
  context.journalRender();
  assert.equal(client.auto, null);
});

test('auto-refresh expires after five minutes and server switch clears log text', async () => {
  const { context, state, element, setFetchHook } = harness();
  context.journalRender();
  const client = vm.runInContext('journalClient', context);
  client.last = { serverId: 'a', unit: 'nginx.service', lines: 50 };
  client.completed = true;
  context.journalStartAuto();
  client.auto.startedAt = Date.now() - 5 * 60 * 1000 - 1;
  client.auto.nextAt = 0;
  setFetchHook(() => { throw new Error('expired follow must not POST'); });
  await context.journalRefresh();
  assert.equal(client.auto, null);
  assert.match(element('journalResultStatus').textContent, /Пять минут/);
  element('journalOutput').textContent = 'private log line';
  state.selectedId = 'missing';
  context.journalRender();
  assert.equal(element('journalOutput').textContent, '');
});

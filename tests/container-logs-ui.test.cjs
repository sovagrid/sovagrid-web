/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const { randomUUID } = require('node:crypto');

const ID = 'a'.repeat(64);
const JOB = randomUUID();
class Element {
  constructor() { this.textContent = ''; this.value = ''; this.hidden = false; this.disabled = false;
    this.children = []; this.listeners = new Map(); }
  addEventListener(name, callback) { this.listeners.set(name, callback); }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = items; }
  setAttribute() {}
  focus() {}
}

function harness() {
  const elements = new Map();
  const timers = [];
  const calls = [];
  const storage = [];
  const listeners = new Map();
  let fetchHook = () => { throw new Error('unexpected fetch'); };
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const context = vm.createContext({
    URL, AbortController, TextEncoder,
    crypto: { randomUUID },
    setTimeout: (callback, delay) => { timers.push({ callback, delay }); return timers.length; },
    clearTimeout: (id) => { if (timers[id - 1]) timers[id - 1].cleared = true; },
    setInterval: () => 1, clearInterval() {},
    fetch: (url, options) => { calls.push({ url, options }); return fetchHook(url, options); },
    document: { getElementById: element, createElement: () => new Element(),
      querySelectorAll: () => [], addEventListener: (name, callback) => listeners.set(name, callback) },
    localStorage: { getItem: () => null, setItem: (...args) => storage.push(args), removeItem() {} },
    navigator: {}, location: { protocol: 'file:' },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('container-logs.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  const server = { id: 'server-1', name: 'VPS', online: true, remote_commands_enabled: true,
    access_role: 'admin', latest: { details: { containers: snapshot() } } };
  state.servers = [server]; state.selectedId = server.id; state.view = 'overview';
  state.user = { id: 'u', role: 'admin', enabled: true, legacy: false };
  state.access = { mode: 'all', revision: 1, unrestricted_admin: true };
  state.token = 'private-session'; state.base = 'https://hub.example';
  element('containerLogsLines').value = '50';
  return { context, state, server, element, calls, storage, timers, listeners,
    setFetchHook: (hook) => { fetchHook = hook; },
    render: () => context.containerLogsRender(server.latest.details.containers, server),
    read: () => context.containerLogsRead({ preventDefault() {} }),
  };
}

function snapshot(age = 10) {
  return { version: 1, collected_at: Math.floor(Date.now() / 1000) - age,
    engines: [
      { engine: 'docker', source_status: 'ok', truncated: false, containers: [
        { id: ID, name: '<service>&', image: 'sovagrid-hub:local', state: 'running' },
      ] },
      { engine: 'podman', source_status: 'unavailable', truncated: false, containers: [] },
    ] };
}

const response = (status, body) => ({ ok: status >= 200 && status < 300, status,
  text: async () => JSON.stringify(body) });

test('only a server admin with a complete inventory can request exact container logs', () => {
  const h = harness();
  h.render();
  assert.equal(h.element('containerLogsPanel').hidden, false);
  assert.equal(h.element('containerLogsRead').disabled, false);
  assert.equal(h.element('containerLogsTarget').children.length, 1);
  assert.equal(h.element('containerLogsTarget').children[0].textContent.includes('<service>&'), true);
  h.server.latest.details.containers.engines[0].containers.push({
    id: 'b'.repeat(64), name: 'unmanaged', image: 'example/app:1', state: 'running',
  });
  h.render();
  assert.equal(h.element('containerLogsTarget').children.length, 1);
  h.server.latest.details.containers.engines[0].truncated = true;
  h.render();
  assert.equal(h.element('containerLogsRead').disabled, true);
  h.server.latest.details.containers = snapshot(180);
  h.render();
  // Agent clock skew is possible; Hub uses receipt time for the final freshness check.
  assert.equal(h.element('containerLogsRead').disabled, false);
  h.server.latest.details.containers = snapshot();
  h.server.access_role = 'viewer';
  h.render();
  assert.equal(h.element('containerLogsPanel').hidden, true);
  assert.equal(h.element('containerLogsOutput').textContent, '');
});

test('one-use job displays only bounded transient text and expires from the DOM', async () => {
  const h = harness(); h.render();
  h.setFetchHook((url, options) => {
    if (url.endsWith('/containers/logs')) return Promise.resolve(response(201,
      { job: { id: JOB, server_id: h.server.id } }));
    if (url.endsWith(`/jobs/${JOB}`)) return Promise.resolve(response(200, { job: {
      id: JOB, server_id: h.server.id, state: 'succeeded', output: '<script>token=secret</script>',
      transient_output: true, output_expired: false,
    } }));
    throw new Error('unexpected request');
  });
  await h.read();
  assert.equal(h.calls.length, 2);
  const post = h.calls[0];
  assert.equal(post.options.method, 'POST');
  assert.equal(post.options.cache, 'no-store');
  assert.equal(post.options.headers['Idempotency-Key'].length, 36);
  assert.deepEqual(JSON.parse(post.options.body), { engine: 'docker', id: ID, lines: 50 });
  assert.equal(h.element('containerLogsOutput').textContent, '<script>token=secret</script>');
  assert.equal(h.storage.length, 0);
  const timer = h.timers.find((item) => item.delay === 300000 && !item.cleared);
  assert.ok(timer);
  timer.callback();
  assert.equal(h.element('containerLogsOutput').textContent, '');
  assert.match(h.element('containerLogsResult').textContent, /Время просмотра истекло/);
});

test('lost POST response retries the same idempotency key without new work', async () => {
  const h = harness(); h.render();
  let posts = 0;
  h.setFetchHook((url) => {
    if (url.endsWith('/containers/logs')) {
      posts++;
      if (posts === 1) return Promise.reject(Object.assign(new Error('lost'), { name: 'AbortError' }));
      return Promise.resolve(response(200, { job: { id: JOB, server_id: h.server.id } }));
    }
    return Promise.resolve(response(200, { job: { id: JOB, server_id: h.server.id,
      state: 'succeeded', output: 'ready', transient_output: true, output_expired: false } }));
  });
  await h.read();
  assert.match(h.element('containerLogsError').textContent, /тот же ключ/);
  await h.read();
  assert.equal(h.calls[0].options.headers['Idempotency-Key'], h.calls[1].options.headers['Idempotency-Key']);
  assert.equal(h.element('containerLogsOutput').textContent, 'ready');
});

test('role revocation or server selection change clears private text and ignores late replies', async () => {
  const h = harness(); h.render();
  let resolveJob;
  h.setFetchHook((url) => url.endsWith('/containers/logs')
    ? Promise.resolve(response(201, { job: { id: JOB, server_id: h.server.id } }))
    : new Promise((resolve) => { resolveJob = resolve; }));
  const pending = h.read();
  for (let i = 0; !resolveJob && i < 10; i++) await Promise.resolve();
  assert.equal(typeof resolveJob, 'function');
  h.server.access_role = 'viewer';
  h.context.containerLogsAccessChanged();
  resolveJob(response(200, { job: { id: JOB, server_id: h.server.id, state: 'succeeded',
    output: 'private', transient_output: true, output_expired: false } }));
  await pending;
  assert.equal(h.element('containerLogsOutput').textContent, '');
  assert.equal(h.element('containerLogsRead').disabled, true);
});

test('a hidden tab clears the text and discards an in-flight result', async () => {
  const h = harness(); h.render();
  let resolveJob;
  h.setFetchHook((url) => url.endsWith('/containers/logs')
    ? Promise.resolve(response(201, { job: { id: JOB, server_id: h.server.id } }))
    : new Promise((resolve) => { resolveJob = resolve; }));
  const pending = h.read();
  for (let i = 0; !resolveJob && i < 10; i++) await Promise.resolve();
  h.context.document.hidden = true;
  const callback = h.listeners.get('visibilitychange');
  assert.equal(typeof callback, 'function');
  callback();
  resolveJob(response(200, { job: { id: JOB, server_id: h.server.id, state: 'succeeded',
    output: 'private', transient_output: true, output_expired: false } }));
  await pending;
  assert.equal(h.element('containerLogsOutput').textContent, '');
  h.context.document.hidden = false;
  callback();
  assert.equal(h.element('containerLogsRead').disabled, false);
});

test('permission denial and polling timeout leave controls safe and show an error', async () => {
  const denied = harness(); denied.render();
  denied.setFetchHook(() => Promise.resolve(response(403, { error: 'Access denied' })));
  await denied.read();
  assert.equal(denied.element('containerLogsOutput').textContent, '');
  assert.equal(denied.element('containerLogsRead').disabled, true);
  assert.match(denied.element('containerLogsError').textContent, /Hub отклонил запрос/);

  const timedOut = harness(); timedOut.render();
  let resolveJob;
  timedOut.setFetchHook((url) => url.endsWith('/containers/logs')
    ? Promise.resolve(response(201, { job: { id: JOB, server_id: timedOut.server.id } }))
    : new Promise((resolve, reject) => { resolveJob = () => reject(Object.assign(new Error('late'), { name: 'AbortError' })); }));
  const pending = timedOut.read();
  assert.match(timedOut.element('containerLogsResult').textContent, /Запрашиваем журнал/);
  for (let i = 0; !resolveJob && i < 10; i++) await Promise.resolve();
  resolveJob();
  await pending;
  assert.equal(timedOut.element('containerLogsOutput').textContent, '');
  assert.match(timedOut.element('containerLogsError').textContent, /не ответил вовремя/);
});

test('expired, malformed and failed results never display untrusted output', async () => {
  for (const job of [
    { state: 'succeeded', output: 'secret', transient_output: true, output_expired: true },
    { state: 'succeeded', output: 'secret\u001b[31m', transient_output: true, output_expired: false },
    { state: 'failed', output: 'private error', transient_output: true, output_expired: false },
  ]) {
    const h = harness(); h.render();
    h.setFetchHook((url) => Promise.resolve(url.endsWith('/containers/logs')
      ? response(201, { job: { id: JOB, server_id: h.server.id } })
      : response(200, { job: { id: JOB, server_id: h.server.id, ...job } })));
    await h.read();
    assert.equal(h.element('containerLogsOutput').textContent, '');
    assert.equal(h.element('containerLogsError').hidden, false);
  }
});

test('Web image and offline shell include the public UI while API remains uncached', () => {
  const html = fs.readFileSync('index.html', 'utf8');
  const shell = fs.readFileSync('sw.js', 'utf8');
  const image = fs.readFileSync('Dockerfile', 'utf8');
  assert.match(html, /id="containerLogsPanel"[^>]+data-admin-only[^>]+hidden/);
  assert.match(html, /container-logs\.js\?v=1/);
  assert.match(shell, /container-logs\.js\?v=1/);
  assert.match(image, /COPY[^\n]+container-logs\.js/);
  assert.ok(!shell.includes('/api/v1/servers/'));
});

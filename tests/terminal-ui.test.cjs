/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { randomUUID } = require('node:crypto');
const test = require('node:test');

const response = (status, payload) => ({ ok: status >= 200 && status < 300, status,
  text: async () => JSON.stringify(payload) });
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};
async function until(predicate) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (predicate()) return;
    await new Promise(setImmediate);
  }
  assert.fail('terminal step did not finish');
}

function harness() {
  const elements = new Map(), terminals = [], windowListeners = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { textContent: '', value: '', hidden: false, disabled: false,
        open: false, children: [], listeners, style: {}, dataset: {}, attributes: {},
        addEventListener(name, handler) { listeners.set(name, handler); },
        setAttribute(name, value) { this.attributes[name] = value; },
        append(...children) { for (const child of children) child.parent = this; this.children.push(...children); },
        replaceChildren(...children) { for (const child of this.children) child.parent = null; this.children = []; this.append(...children); },
        remove() { if (this.parent) this.parent.children = this.parent.children.filter((child) => child !== this); this.parent = null; },
        focus() { this.focused = true; },
        querySelector(selector) { return selector.includes('aria-selected') ? this.children.flatMap((item) => item.children).find((child) => child.attributes?.['aria-selected'] === 'true') : null; },
        showModal() { this.open = true; },
        close() { this.open = false; listeners.get('close')?.({}); },
        getBoundingClientRect() { return { width: 720, height: 380 }; },
      });
    }
    return elements.get(id);
  };
  class FakeTerminal {
    constructor(options = {}) { this.cols = 80; this.rows = 24; this.options = options; this.writes = []; this.disposed = false; terminals.push(this); }
    loadAddon(addon) { this.addon = addon; }
    open(screen) { this.screen = screen; }
    onData(callback) { this.input = callback; }
    write(data) { this.writes.push(Buffer.from(data)); }
    focus() { this.focused = true; }
    dispose() { this.disposed = true; }
  }
  class FakeFit { fit() {} }
  let fetchHook = () => { throw new Error('unexpected fetch'); };
  const context = vm.createContext({
    URL, AbortController, TextEncoder, Uint8Array, btoa, atob, crypto: { randomUUID },
    Terminal: FakeTerminal, FitAddon: { FitAddon: FakeFit },
    setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { documentElement: { dataset: { theme: 'dark' } }, getElementById: element, createElement: () => element(Symbol()),
      querySelectorAll: () => [], addEventListener() {}, body: { append() {} } },
    addEventListener: (name, handler) => windowListeners.set(name, handler),
    navigator: {}, localStorage: { getItem: () => null, setItem() {} },
    location: { protocol: 'file:' }, fetch: (...args) => fetchHook(...args),
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  const terminal = vm.runInContext('terminalClient', context);
  state.base = 'https://hub.example'; state.token = 'admin-token'; state.view = 'commands';
  state.servers = [{ id: 'server-A', name: 'Server A', online: true, remote_commands_enabled: true }];
  state.selectedId = 'server-A';
  context.renderTerminalControls();
  return { context, state, terminal, element, terminals,
    emitWindowEvent: (name) => windowListeners.get(name)?.(), setFetchHook: (hook) => { fetchHook = hook; } };
}

test('PTY start, byte output, mobile keys, resize, and close follow the exact HTTP contract', async () => {
  const { context, state, terminal, terminals, setFetchHook, element } = harness();
  const waiting = deferred(), sent = [];
  setFetchHook((url, options) => {
    const parsed = new URL(url);
    sent.push({ path: parsed.pathname + parsed.search, options });
    if (options.method === 'POST' && parsed.pathname.endsWith('/terminal/sessions')) {
      return Promise.resolve(response(201, { session: { id: 'sid-1', server_id: 'server-A', state: 'pending' } }));
    }
    if (parsed.pathname.endsWith('/events') && parsed.search === '?after=0') {
      return Promise.resolve(response(200, { events: [{ seq: 1, type: 'output', data: Buffer.from('prompt$ ').toString('base64url') }],
        next_after: 1, state: 'active', exit_code: null, reason: null }));
    }
    if (parsed.pathname.endsWith('/events')) return waiting.promise;
    if (['/input', '/resize'].some((suffix) => parsed.pathname.endsWith(suffix))) {
      return Promise.resolve(response(202, { accepted: true, next_seq: JSON.parse(options.body).seq }));
    }
    if (options.method === 'DELETE') return Promise.resolve(response(200, { closed: true }));
    throw new Error(`unexpected path ${url}`);
  });
  await context.startTerminal();
  await until(() => terminal.status === 'active' && terminals[0].writes.length === 1);
  assert.equal(sent[0].path, '/api/v1/servers/server-A/terminal/sessions');
  assert.equal(sent[0].options.headers.Authorization, 'Bearer admin-token');
  assert.match(sent[0].options.headers['Idempotency-Key'], /^[0-9a-f]{8}-/);
  assert.deepEqual(JSON.parse(sent[0].options.body), { cols: 80, rows: 24 });
  assert.equal(Buffer.concat(terminals[0].writes).toString(), 'prompt$ ');
  assert.equal(terminal.after, 1);
  terminals[0].input('echo hello\r');
  context.flushTerminalInput();
  await until(() => terminal.nextSeq === 2);
  terminals[0].cols = 90;
  context.fitTerminal();
  await until(() => terminal.nextSeq === 3);
  context.sendTerminalKey('ctrl-c');
  context.flushTerminalInput();
  await until(() => terminal.nextSeq === 4);
  const writes = sent.filter((item) => item.options.method === 'POST' && !item.path.endsWith('/sessions'));
  assert.deepEqual(writes.map((item) => [item.path.slice(item.path.lastIndexOf('/') + 1), JSON.parse(item.options.body).seq]),
    [['input', 1], ['resize', 2], ['input', 3]]);
  assert.equal(Buffer.from(JSON.parse(writes[0].options.body).data, 'base64url').toString(), 'echo hello\r');
  assert.deepEqual(JSON.parse(writes[1].options.body), { seq: 2, cols: 90, rows: 24 });
  assert.equal(Buffer.from(JSON.parse(writes[2].options.body).data, 'base64url').toString('hex'), '03');
  assert.equal(state.jobs.length, 0, 'PTY input/output must not enter generic job history');
  await context.closeTerminal();
  waiting.resolve(response(200, { events: [], next_after: 1, state: 'closed', exit_code: null, reason: 'closed' }));
  assert.equal(sent.at(-1).options.method, 'DELETE');
  assert.equal(terminal.sessionId, null);
  assert.equal(terminals[0].disposed, true);
  assert.equal(element('terminalScreen').children.length, 0);
});

test('phone input sends one explicit line, blocks multiline paste, and clears secrets on close', async () => {
  const { context, terminal, element, setFetchHook } = harness();
  const waiting = deferred(), inputs = [];
  let eventCount = 0;
  setFetchHook((url, options) => {
    if (options.method === 'POST' && url.endsWith('/terminal/sessions')) {
      return Promise.resolve(response(201, { session: { id: 'phone-sid', server_id: 'server-A', state: 'pending' } }));
    }
    if (url.includes('/events?') && ++eventCount === 1) {
      return Promise.resolve(response(200, { events: [], next_after: 0, state: 'active' }));
    }
    if (url.includes('/events?')) return waiting.promise;
    if (url.endsWith('/input')) {
      inputs.push(JSON.parse(options.body));
      return Promise.resolve(response(202, { accepted: true, next_seq: inputs.at(-1).seq }));
    }
    if (options.method === 'DELETE') return Promise.resolve(response(200, { closed: true }));
    throw new Error(`unexpected path ${url}`);
  });
  assert.equal(element('terminalInput').disabled, true);
  await context.startTerminal();
  await until(() => terminal.status === 'active');
  assert.equal(element('terminalInput').disabled, false);
  const input = element('terminalInput');
  input.value = 'pasted secret';
  context.toggleTerminalLineVisibility();
  assert.equal(input.type, 'password');
  context.sendTerminalLine({ preventDefault() {} });
  assert.equal(input.value, '');
  context.flushTerminalInput();
  await until(() => inputs.length === 1);
  assert.equal(Buffer.from(inputs[0].data, 'base64url').toString(), 'pasted secret\r');
  let blocked = false;
  context.rejectMultilineTerminalPaste({ clipboardData: { getData: () => 'first\nsecond' },
    preventDefault() { blocked = true; } });
  assert.equal(blocked, true);
  assert.match(element('terminalInputError').textContent, /одну строку/);
  input.value = 'unsent password';
  await context.closeTerminal();
  waiting.resolve(response(200, { events: [], next_after: 0, state: 'closed' }));
  assert.equal(input.value, '');
  assert.equal(input.type, 'text');
});

test('lost input acknowledgement retries the identical sequence and bytes after reconnect', async () => {
  const { context, terminal, terminals, setFetchHook } = harness();
  const heldPolls = [], inputPosts = [];
  let getCount = 0;
  setFetchHook((url, options) => {
    const parsed = new URL(url);
    if (options.method === 'POST' && parsed.pathname.endsWith('/terminal/sessions')) {
      return Promise.resolve(response(201, { session: { id: 'sid-2', server_id: 'server-A', state: 'pending' } }));
    }
    if (parsed.pathname.endsWith('/events')) {
      getCount++;
      if (getCount === 1) return Promise.resolve(response(200, { events: [], next_after: 0, state: 'active' }));
      if (getCount === 3) return Promise.resolve(response(200, { events: [], next_after: 0, state: 'active' }));
      const held = deferred(); heldPolls.push(held); return held.promise;
    }
    if (parsed.pathname.endsWith('/input')) {
      inputPosts.push(options.body);
      return inputPosts.length === 1 ? Promise.reject(new Error('network interrupted')) :
        Promise.resolve(response(200, { accepted: true, next_seq: 1 }));
    }
    if (options.method === 'DELETE') return Promise.resolve(response(200, { closed: true }));
    throw new Error(`unexpected path ${url}`);
  });
  await context.startTerminal();
  await until(() => terminal.status === 'active' && getCount >= 2);
  terminals[0].input('secret\r');
  context.flushTerminalInput();
  await until(() => terminal.status === 'disconnected');
  assert.equal(terminal.operations.length, 1);
  assert.equal(terminal.operations[0].seq, 1);
  context.reconnectTerminal();
  await until(() => inputPosts.length === 2 && terminal.nextSeq === 2);
  assert.equal(inputPosts[0], inputPosts[1]);
  assert.equal(terminal.after, 0, 'reconnect must resume from the previous acknowledged output cursor');
  await context.closeTerminal();
  for (const held of heldPolls) held.resolve(response(200, { events: [], next_after: 0, state: 'closed' }));
});

test('old terminal start cannot attach a session after logout', async () => {
  const { context, state, terminal, setFetchHook } = harness();
  const started = deferred();
  setFetchHook(() => started.promise);
  const pending = context.startTerminal();
  context.logout(false);
  state.token = 'another-session';
  started.resolve(response(201, { session: { id: 'old-sid', server_id: 'server-A', state: 'active' } }));
  await pending;
  assert.equal(terminal.sessionId, null);
  assert.equal(terminal.status, 'idle');
});

test('a screen resize while start is in flight is sent after session creation', async () => {
  const { context, terminal, terminals, setFetchHook } = harness();
  const started = deferred(), waiting = deferred(), resizes = [];
  setFetchHook((url, options) => {
    if (options.method === 'POST' && url.endsWith('/terminal/sessions')) return started.promise;
    if (url.includes('/events?')) return waiting.promise;
    if (url.endsWith('/resize')) {
      resizes.push(JSON.parse(options.body));
      return Promise.resolve(response(202, { accepted: true, next_seq: resizes.at(-1).seq }));
    }
    if (options.method === 'DELETE') return Promise.resolve(response(200, { closed: true }));
    throw new Error(`unexpected path ${url}`);
  });
  const pending = context.startTerminal();
  terminals[0].cols = 110;
  context.fitTerminal();
  started.resolve(response(201, { session: { id: 'sid-resize', server_id: 'server-A', state: 'pending' } }));
  await pending;
  await until(() => resizes.length === 1);
  assert.deepEqual(resizes[0], { seq: 1, cols: 110, rows: 24 });
  await context.closeTerminal();
  waiting.resolve(response(200, { events: [], next_after: 0, state: 'closed' }));
  assert.equal(terminal.sessionId, null);
});

test('expired output cursor closes the UI session without repeating output', async () => {
  const { context, terminal, setFetchHook, element } = harness();
  setFetchHook((url, options) => {
    if (options.method === 'POST') return Promise.resolve(response(201,
      { session: { id: 'sid-expired', server_id: 'server-A', state: 'pending' } }));
    if (url.includes('/events?')) return Promise.resolve(response(409, { error: 'Terminal output expired' }));
    if (options.method === 'DELETE') return Promise.resolve(response(200, { closed: true }));
    throw new Error(`unexpected path ${url}`);
  });
  await context.startTerminal();
  await until(() => terminal.status === 'closed');
  assert.match(element('terminalTarget').textContent, /Вывод устарел/);
  assert.equal(element('terminalStartButton').hidden, false);
  await context.closeTerminal();
});

test('slow Agent startup points to the local interactive-terminal permission', () => {
  const { context, terminal, element } = harness();
  terminal.serverId = 'server-A';
  terminal.status = 'pending';
  terminal.pendingSince = Date.now() - 31000;
  context.renderTerminalControls();
  assert.match(element('terminalTarget').textContent, /allow_interactive_terminal=true/);
});

test('two server tabs keep output, input and close operations in their own sessions', async () => {
  const { context, state, terminal: first, terminals, element, setFetchHook } = harness();
  state.servers.push({ id: 'server-B', name: 'Server B', online: true, remote_commands_enabled: true });
  const held = new Map(), inputs = [], deletes = [], polls = new Map();
  setFetchHook((url, options) => {
    const parsed = new URL(url), server = parsed.pathname.split('/')[4];
    if (options.method === 'POST' && parsed.pathname.endsWith('/terminal/sessions')) {
      return Promise.resolve(response(201, { session: { id: `sid-${server}`, server_id: server, state: 'pending' } }));
    }
    if (parsed.pathname.endsWith('/events')) {
      const count = (polls.get(server) || 0) + 1; polls.set(server, count);
      if (count === 1) return Promise.resolve(response(200, { events: [{ seq: 1, type: 'output',
        data: Buffer.from(`${server}$ `).toString('base64url') }], next_after: 1, state: 'active' }));
      const wait = deferred(); held.set(server, wait); return wait.promise;
    }
    if (parsed.pathname.endsWith('/input')) {
      inputs.push({ server, body: JSON.parse(options.body) });
      return Promise.resolve(response(202, { accepted: true, next_seq: inputs.at(-1).body.seq }));
    }
    if (options.method === 'DELETE') {
      deletes.push(server); return Promise.resolve(response(200, { closed: true }));
    }
    throw new Error(`unexpected path ${url}`);
  });
  await context.startTerminal();
  await until(() => first.status === 'active' && held.has('server-A'));
  state.selectedId = 'server-B';
  context.addTerminalTab();
  const second = vm.runInContext('terminalClient', context);
  await context.startTerminal();
  await until(() => second.status === 'active' && held.has('server-B'));
  assert.equal(terminals.length, 2);
  assert.equal(Buffer.concat(terminals[0].writes).toString(), 'server-A$ ');
  assert.equal(Buffer.concat(terminals[1].writes).toString(), 'server-B$ ');
  terminals[0].input('hidden input');
  context.queueTerminalInput('pwd\r'); context.flushTerminalInput();
  await until(() => inputs.length === 1);
  assert.equal(inputs[0].server, 'server-B');
  assert.equal(Buffer.from(inputs[0].body.data, 'base64url').toString(), 'pwd\r');
  held.get('server-A').resolve(response(200, { events: [{ seq: 2, type: 'output',
    data: Buffer.from('background').toString('base64url') }], next_after: 2, state: 'active' }));
  await until(() => first.after === 2);
  assert.equal(Buffer.concat(terminals[0].writes).toString(), 'server-A$ background');
  assert.equal(Buffer.concat(terminals[1].writes).toString(), 'server-B$ ');
  assert.match(element('terminalTarget').textContent, /Server B/);
  await context.closeTerminalTab(first);
  assert.deepEqual(deletes, ['server-A']);
  assert.equal(terminals[0].disposed, true);
  assert.equal(terminals[1].disposed, false);
  assert.equal(second.status, 'active');
  assert.equal(element('terminalScreen').children.length, 1);
  assert.equal(vm.runInContext('terminalTabs.items.length', context), 1);
  held.get('server-A').resolve(response(200, { events: [], next_after: 2, state: 'closed' }));
  held.get('server-B').resolve(response(200, { events: [], next_after: 1, state: 'closed' }));
});

test('failed close keeps the session visible for an explicit retry', async () => {
  const { context, terminal, element, setFetchHook } = harness();
  let polls = 0, closes = 0;
  const waiting = deferred();
  setFetchHook((url, options) => {
    if (options.method === 'POST') return Promise.resolve(response(201,
      { session: { id: 'sid-close', server_id: 'server-A', state: 'pending' } }));
    if (url.includes('/events?')) return ++polls === 1
      ? Promise.resolve(response(200, { events: [], next_after: 0, state: 'active' })) : waiting.promise;
    if (options.method === 'DELETE') return ++closes === 1
      ? Promise.reject(new Error('network lost')) : Promise.resolve(response(200, { closed: true }));
    throw new Error(`unexpected path ${url}`);
  });
  await context.startTerminal();
  await until(() => terminal.status === 'active');
  element('terminalInput').value = 'unsent password';
  await context.closeTerminal();
  assert.equal(terminal.sessionId, 'sid-close');
  assert.equal(terminal.status, 'disconnected');
  assert.equal(element('terminalInput').value, '');
  assert.match(element('terminalTarget').textContent, /Повторите закрытие/);
  await context.closeTerminal();
  assert.equal(closes, 2);
  assert.equal(terminal.sessionId, null);
  assert.equal(element('terminalInput').value, '');
  waiting.resolve(response(200, { events: [], next_after: 0, state: 'closed' }));
});

test('late creation response for a closed tab is deleted without attaching to another tab', async () => {
  const { context, state, terminal: first, setFetchHook } = harness();
  state.servers.push({ id: 'server-B', name: 'Server B', online: true, remote_commands_enabled: true });
  const waiting = deferred(), startedB = deferred(), deletes = [];
  setFetchHook((url, options) => {
    const parsed = new URL(url), server = parsed.pathname.split('/')[4];
    if (options.method === 'POST' && parsed.pathname.endsWith('/terminal/sessions')) {
      return server === 'server-B' ? startedB.promise : Promise.resolve(response(201,
        { session: { id: 'sid-A', server_id: 'server-A', state: 'pending' } }));
    }
    if (parsed.pathname.endsWith('/events')) return waiting.promise;
    if (options.method === 'DELETE') { deletes.push(server); return Promise.resolve(response(200, { closed: true })); }
    throw new Error(`unexpected path ${url}`);
  });
  await context.startTerminal();
  state.selectedId = 'server-B'; context.addTerminalTab();
  const second = vm.runInContext('terminalClient', context);
  const pending = context.startTerminal();
  await until(() => second.pendingStart && second.startInFlight);
  await context.closeTerminalTab(second);
  startedB.resolve(response(201, { session: { id: 'sid-B', server_id: 'server-B', state: 'pending' } }));
  await pending;
  await until(() => deletes.includes('server-B'));
  assert.equal(first.sessionId, 'sid-A');
  assert.equal(vm.runInContext('terminalClient', context), first);
  assert.equal(vm.runInContext('terminalTabs.items.length', context), 1);
  waiting.resolve(response(200, { events: [], next_after: 0, state: 'closed' }));
});

test('logout disposes every tab and sends a close for each owned session', async () => {
  const { context, state, terminals, element, setFetchHook } = harness();
  state.servers.push({ id: 'server-B', name: 'Server B', online: true, remote_commands_enabled: true });
  const waiting = deferred(), deletes = [];
  setFetchHook((url, options) => {
    const parsed = new URL(url), server = parsed.pathname.split('/')[4];
    if (options.method === 'POST' && parsed.pathname.endsWith('/terminal/sessions')) return Promise.resolve(response(201,
      { session: { id: `sid-${server}`, server_id: server, state: 'pending' } }));
    if (parsed.pathname.endsWith('/events')) return waiting.promise;
    if (options.method === 'DELETE') { deletes.push(server); return Promise.resolve(response(200, { closed: true })); }
    throw new Error(`unexpected path ${url}`);
  });
  await context.startTerminal();
  state.selectedId = 'server-B'; context.addTerminalTab();
  await context.startTerminal();
  element('terminalInput').value = 'unsubmitted secret';
  context.logout(false);
  assert.deepEqual(deletes.sort(), ['server-A', 'server-B']);
  assert.equal(terminals.every((item) => item.disposed), true);
  assert.equal(element('terminalInput').value, '');
  assert.equal(vm.runInContext('terminalTabs.items.length', context), 1);
  assert.equal(vm.runInContext('terminalClient.sessionId', context), null);
  waiting.resolve(response(200, { events: [], next_after: 0, state: 'closed' }));
});

test('theme changes repaint the live xterm canvas without closing its PTY session', async () => {
  const { context, terminal, terminals, emitWindowEvent, setFetchHook } = harness();
  const waiting = deferred(), deletes = [];
  setFetchHook((url, options) => {
    if (options.method === 'POST' && url.endsWith('/terminal/sessions')) return Promise.resolve(response(201,
      { session: { id: 'sid-theme', server_id: 'server-A', state: 'pending' } }));
    if (url.includes('/events?')) return waiting.promise;
    if (options.method === 'DELETE') { deletes.push(url); return Promise.resolve(response(200, { closed: true })); }
    throw new Error(`unexpected path ${url}`);
  });
  await context.startTerminal();
  assert.equal(terminals[0].options.theme.background, '#07151a');
  context.document.documentElement.dataset.theme = 'light';
  emitWindowEvent('sovagridthemechange');
  assert.equal(terminals[0].options.theme.background, '#eef4f1');
  assert.equal(terminal.sessionId, 'sid-theme');
  assert.equal(terminals[0].disposed, false);
  assert.equal(deletes.length, 0);
  await context.closeTerminal();
  waiting.resolve(response(200, { events: [], next_after: 0, state: 'closed' }));
});

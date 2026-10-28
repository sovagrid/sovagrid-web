/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const { webcrypto } = require('node:crypto');

const admin = { id: 'admin-id', username: 'owner', role: 'admin', enabled: true,
  revision: 0, created_at: 100, updated_at: 100 };
const viewer = { id: 'viewer-id', username: 'guest', role: 'viewer', enabled: true,
  revision: 3, created_at: 110, updated_at: 120 };
const reply = (status, body) => ({ ok: status < 400, status, text: async () => JSON.stringify(body) });
const submit = { preventDefault() {} };

function harness(hook = async () => reply(200, { users: [admin, viewer] })) {
  const elements = new Map();
  const make = () => ({ value: '', type: 'text', textContent: '', hidden: false, disabled: false,
    checked: false, required: false, open: false, children: [], attributes: {}, dataset: {},
    addEventListener() {}, setAttribute(k, v) { this.attributes[k] = v; },
    append(...nodes) { this.children.push(...nodes); }, replaceChildren(...nodes) { this.children = nodes; },
    classList: { toggle() {} }, focus() { this.focused = true; },
    close() { this.open = false; }, showModal() { this.open = true; },
  });
  const element = (id) => { if (!elements.has(id)) elements.set(id, make()); return elements.get(id); };
  const adminElement = make();
  const nav = ['overview', 'commands', 'files', 'telegram', 'vpn', 'settings'].map((view) => {
    const button = make(); button.dataset.view = view; return button;
  });
  const calls = [];
  const context = vm.createContext({ URL, AbortController, TextEncoder, Uint8Array, crypto: webcrypto,
    setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {}, Intl,
    document: { getElementById: element, createElement: make, addEventListener() {},
      querySelectorAll(selector) { return selector === '[data-admin-only], [data-command]' ? [adminElement] : selector === '[data-view]' ? nav : []; } },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    navigator: {}, location: new URL('https://hub.example'),
    fetch: async (url, options) => { calls.push({ url, options }); return hook(url, options); },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('users.js', 'utf8'), context);
  const state = vm.runInContext('state', context), client = vm.runInContext('usersClient', context);
  Object.assign(state, { token: 'session-a', base: 'https://hub.example', user: { ...admin }, view: 'settings' });
  return { context, state, client, element, calls, nav, adminElement };
}

test('user list uses text, describes roles, and new accounts default to viewer', async () => {
  const badName = { ...viewer, username: '<img src=x onerror=alert(1)>' };
  const h = harness(async () => reply(200, { users: [admin, badName] }));
  await h.context.usersRefresh();
  const rows = h.element('usersList').children;
  assert.equal(rows.length, 2);
  assert.equal(rows.find((row) => row.children[0].children[0].textContent === badName.username).children[0].children[1].textContent,
    'Наблюдатель · Доступ открыт');
  h.context.usersOpen('create');
  assert.equal(h.element('userRole').value, 'viewer');
  assert.equal(h.element('userPassword').type, 'password');
  h.context.usersGeneratePassword();
  assert.match(h.element('userPassword').value, /^[A-Za-z0-9_-]{24}$/);
  assert.equal(h.element('userPassword').type, 'text');
  assert.equal(h.element('userGeneratedConfirm').hidden, false);
  assert.equal(fs.readFileSync('users.js', 'utf8').includes('.innerHTML'), false);
});

test('generated password must be saved before creating or resetting an account', async () => {
  const h = harness(); await h.context.usersRefresh(); h.context.usersOpen('create');
  h.element('userUsername').value = 'new-person'; h.context.usersGeneratePassword();
  const before = h.calls.length;
  await h.context.usersSubmit(submit);
  assert.equal(h.calls.length, before);
  assert.match(h.element('userDialogError').textContent, /Сохраните сгенерированный пароль/);
  assert.equal(h.element('userPassword').value.length, 24);
  h.context.usersOpen('password', viewer); h.context.usersGeneratePassword();
  await h.context.usersSubmit(submit);
  assert.equal(h.calls.length, before);
  h.context.usersPasswordEdited();
  assert.equal(h.element('userGeneratedConfirm').hidden, true);
});

test('copy is explicit and a late clipboard result cannot touch another session', async () => {
  const h = harness(); await h.context.usersRefresh(); h.context.usersOpen('create');
  h.context.usersGeneratePassword();
  let resolveCopy, copied;
  h.context.navigator.clipboard = { writeText: (value) => { copied = value; return new Promise((done) => { resolveCopy = done; }); } };
  assert.equal(copied, undefined);
  const pending = h.context.usersCopyPassword();
  assert.equal(copied, h.element('userPassword').value);
  assert.equal(h.element('userPasswordSaved').checked, false);
  h.context.logout(false); h.state.token = 'next-session';
  resolveCopy(); await pending;
  assert.equal(h.element('userPasswordStatus').textContent, '');
  assert.equal(h.element('userPassword').value, '');
});

test('creation clears password before await and sends it only in bearer JSON body', async () => {
  let resolveCreate;
  const h = harness(async (url, options) => options.method === 'POST'
    ? new Promise((resolve) => { resolveCreate = resolve; }) : reply(200, { users: [admin, viewer] }));
  await h.context.usersRefresh(); h.context.usersOpen('create');
  h.element('userUsername').value = 'new-person'; h.element('userPassword').value = 'secret-new-person-password';
  const pending = h.context.usersSubmit(submit);
  assert.equal(h.element('userPassword').value, '');
  assert.equal(h.element('userDialogConfirm').disabled, true);
  assert.equal(h.element('userPassword').disabled, true);
  assert.equal(h.element('userRole').disabled, true);
  const call = h.calls.at(-1);
  assert.equal(call.url, 'https://hub.example/api/v1/users');
  assert.equal(call.options.headers.Authorization, 'Bearer session-a');
  assert.deepEqual(JSON.parse(call.options.body), { username: 'new-person', password: 'secret-new-person-password', role: 'viewer' });
  resolveCreate(reply(201, { user: { ...viewer, id: 'new-id', username: 'new-person', revision: 0 } }));
  await pending;
  assert.equal(h.element('userDialog').open, false);
  assert.equal(h.element('userPassword').disabled, false);
  assert.match(h.element('usersMessage').textContent, /Пользователь создан/);
  assert.equal(h.calls.some((call) => call.url.includes('secret-new-person')), false);
});

test('permission edit binds immutable ID and revision; conflict never silently retries', async () => {
  const h = harness(async (_url, options) => options.method === 'PATCH'
    ? reply(409, { error: 'Revision changed' }) : reply(200, { users: [admin, viewer] }));
  await h.context.usersRefresh(); h.context.usersOpen('access', viewer);
  h.client.rows = [{ ...admin }, { ...viewer, revision: 4 }];
  h.element('userRole').value = 'operator'; h.element('userEnabled').checked = false;
  await h.context.usersSubmit(submit);
  const writes = h.calls.filter(({ options }) => options.method === 'PATCH');
  assert.equal(writes.length, 1);
  assert.equal(writes[0].url, 'https://hub.example/api/v1/users/viewer-id');
  assert.deepEqual(JSON.parse(writes[0].options.body), { revision: 3, role: 'operator', enabled: false });
  assert.match(h.element('userDialogError').textContent, /Запись изменилась/);
  assert.equal(h.element('userDialog').open, true);
});

test('password reset erases input; stale response cannot alter a new session', async () => {
  let resolveReset;
  const h = harness(async (_url, options) => options.method === 'POST'
    ? new Promise((resolve) => { resolveReset = resolve; }) : reply(200, { users: [admin, viewer] }));
  await h.context.usersRefresh(); h.context.usersOpen('password', viewer);
  h.element('userPassword').value = 'reset-person-password';
  const pending = h.context.usersSubmit(submit);
  assert.equal(h.element('userPassword').value, '');
  h.context.logout(false); h.state.token = 'session-b'; h.state.user = { ...admin };
  resolveReset(reply(200, { user: { ...viewer, revision: 4 }, sessions_revoked: true }));
  await pending;
  assert.equal(h.state.token, 'session-b');
  assert.equal(h.client.rows, null);
  assert.equal(h.element('userPassword').disabled, false);
  assert.equal(h.element('usersMessage').textContent, '');
});

test('rejected password reset preserves the selected user and requires fresh password entry', async () => {
  const h = harness(async (_url, options) => options.method === 'POST'
    ? reply(403, { error: 'Denied' }) : reply(200, { users: [admin, viewer] }));
  await h.context.usersRefresh(); h.context.usersOpen('password', viewer);
  h.element('userPassword').value = 'reset-person-password';
  await h.context.usersSubmit(submit);
  assert.equal(h.element('userPassword').value, '');
  assert.equal(h.client.pending.user.id, viewer.id);
  assert.equal(h.element('userDialog').open, true);
  assert.match(h.element('userDialogError').textContent, /Введите пароль заново/);
  assert.equal(h.state.token, 'session-a');
});

test('resetting own password requires a new login without logging out other identities', async () => {
  const h = harness(async (_url, options) => options.method === 'POST'
    ? reply(200, { user: { ...admin, revision: 1 }, sessions_revoked: true }) : reply(200, { users: [admin, viewer] }));
  await h.context.usersRefresh(); h.context.usersOpen('password', admin);
  h.element('userPassword').value = 'reset-owner-password';
  await h.context.usersSubmit(submit);
  assert.equal(h.state.token, '');
  assert.match(h.element('loginNotice').textContent, /Ваш доступ изменён/);
  assert.equal(h.element('userPassword').value, '');
});

test('viewer and operator cannot open privileged views or send user mutations', async () => {
  const h = harness(); await h.context.usersRefresh();
  h.state.user = { ...viewer }; h.state.view = 'commands'; h.context.applyHubPermissions();
  assert.equal(h.state.view, 'overview');
  assert.equal(h.adminElement.hidden, true);
  assert.equal(h.nav.find((button) => button.dataset.view === 'commands').hidden, true);
  assert.equal(h.nav.find((button) => button.dataset.view === 'vpn').hidden, false);
  h.context.setView('commands'); assert.equal(h.state.view, 'overview');
  const before = h.calls.length;
  h.context.usersOpen('delete', admin); await h.context.usersSubmit(submit);
  assert.equal(h.calls.length, before);
  h.state.servers = [{ id: 'vps', online: true, remote_commands_enabled: true }]; h.state.vpnTargetId = 'vps'; h.state.selectedId = 'vps';
  assert.equal(h.context.vpnTargetReady(), false);
  assert.equal(h.context.hubCanAcknowledge(), false);
  h.state.user.role = 'operator';
  assert.equal(h.context.hubCanAcknowledge(), true);
  assert.equal(h.context.hubCanAdmin(), false);
});

test('malformed identity is rejected; singleton legacy Hub remains compatible', () => {
  const h = harness();
  assert.equal(h.context.hubSessionUser({}, 'old-owner').role, 'admin');
  for (const user of [null, {}, { ...admin, role: 'root' }, { ...admin, enabled: false }, { ...admin, id: '' }]) {
    assert.throws(() => h.context.hubSessionUser({ user }), /права доступа/);
  }
});

test('container and offline shell include user administration assets', () => {
  const html = fs.readFileSync('index.html', 'utf8'), docker = fs.readFileSync('Dockerfile', 'utf8');
  const shell = fs.readFileSync('sw.js', 'utf8');
  for (const name of ['users.js', 'users.css']) {
    assert.ok(html.includes(`${name}?v=2`)); assert.ok(shell.includes(`/${name}?v=2`)); assert.ok(docker.includes(name));
  }
  assert.ok(html.includes('access.js?v=1')); assert.ok(shell.includes('/access.js?v=1')); assert.ok(docker.includes('access.js'));
  assert.match(html, /id="userDialog"[^>]*aria-labelledby="userDialogHeading"/);
  assert.match(html, /id="usersHeading"/);
});

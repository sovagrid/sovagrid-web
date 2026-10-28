/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

function harness(fetchHook) {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      value: '', textContent: '', hidden: false, disabled: false, open: false,
      addEventListener() {}, setAttribute() {}, replaceChildren() {}, close() { this.open = false; },
      focus() { this.focused = true; },
    });
    return elements.get(id);
  };
  const calls = [];
  const context = vm.createContext({
    URL, AbortController, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    navigator: {}, location: new URL('https://hub.example'),
    fetch: async (url, options) => { calls.push({ url, options }); return fetchHook(url, options); },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  state.base = 'https://hub.example'; state.token = 'private-session'; state.view = 'settings';
  const fill = (current = 'old-admin-password', next = 'new-admin-password') => {
    element('currentAdminPassword').value = current;
    element('newAdminPassword').value = next;
    element('confirmAdminPassword').value = next;
  };
  return { context, state, element, calls, fill };
}

const response = (status, data) => ({ ok: status < 400, status, text: async () => JSON.stringify(data) });
const submit = { preventDefault() {} };

test('successful password change sends a bearer JSON request, clears fields, and requires login again', async () => {
  const h = harness(async () => response(200, { changed: true, sessions_revoked: true }));
  h.fill();
  await h.context.changeAdminPassword(submit);
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].url, 'https://hub.example/api/v1/admin/password');
  assert.equal(h.calls[0].options.method, 'POST');
  assert.equal(h.calls[0].options.headers.Authorization, 'Bearer private-session');
  assert.equal(h.calls[0].options.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(h.calls[0].options.body), {
    current_password: 'old-admin-password', new_password: 'new-admin-password',
  });
  assert.equal(h.state.token, '');
  assert.equal(h.element('appView').hidden, true);
  assert.equal(h.element('loginView').hidden, false);
  assert.match(h.element('loginNotice').textContent, /Войдите с новым паролем/);
  assert.equal(h.element('loginNotice').hidden, false);
  assert.equal(h.element('password').focused, true);
  for (const id of ['currentAdminPassword', 'newAdminPassword', 'confirmAdminPassword']) {
    assert.equal(h.element(id).value, '');
  }
  assert.equal(h.calls.some(({ url }) => url.includes('password=')), false);
});

test('incorrect current password and retry limit are shown without revealing input or logging out', async () => {
  let status = 403;
  const h = harness(async () => response(status, { error: 'Current password is incorrect' }));
  h.fill();
  await h.context.changeAdminPassword(submit);
  assert.equal(h.state.token, 'private-session');
  assert.match(h.element('settingsPasswordError').textContent, /Текущий пароль неверен/);
  assert.equal(h.element('currentAdminPassword').value, '');
  assert.equal(h.element('newAdminPassword').value, '');
  status = 429;
  h.fill();
  await h.context.changeAdminPassword(submit);
  assert.match(h.element('settingsPasswordError').textContent, /30 секунд/);
  assert.equal(h.element('changePasswordButton').disabled, false);
});

test('mismatch and unsaved file changes prevent the request', async () => {
  const h = harness(async () => { throw Error('should not fetch'); });
  h.fill();
  h.element('confirmAdminPassword').value = 'another-long-password';
  await h.context.changeAdminPassword(submit);
  assert.match(h.element('settingsPasswordError').textContent, /не совпадают/);
  h.context.filesHasUnsavedChanges = () => true;
  h.fill();
  await h.context.changeAdminPassword(submit);
  assert.match(h.element('settingsPasswordError').textContent, /правки файла/);
  assert.equal(h.calls.length, 0);
});

test('late password-change response cannot log out a newer login', async () => {
  let resolve;
  const h = harness(() => new Promise((done) => { resolve = done; }));
  h.fill();
  const pending = h.context.changeAdminPassword(submit);
  h.context.logout(false);
  h.state.token = 'new-session';
  resolve(response(200, { changed: true, sessions_revoked: true }));
  await pending;
  assert.equal(h.state.token, 'new-session');
  assert.equal(h.element('loginNotice').hidden, false);
  assert.equal(h.element('loginNotice').textContent, '');
});

test('multiuser own-password change targets the authenticated session for every role', async () => {
  const h = harness(async () => response(200, { changed: true, sessions_revoked: true }));
  h.state.user = { id: 'viewer-id', username: 'reader', role: 'viewer', legacy: false };
  h.fill();
  await h.context.changeAdminPassword(submit);
  assert.equal(h.calls[0].url, 'https://hub.example/api/v1/session/password');
  assert.equal(h.calls[0].options.headers.Authorization, 'Bearer private-session');
  assert.equal(h.state.token, '');
});

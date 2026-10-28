/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

function harness(saved, origin = 'http://127.0.0.1:49152') {
  const elements = new Map();
  const storage = new Map(saved ? [['sovagrid.hub', saved]] : []);
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      value: '', hidden: false, disabled: false, textContent: '',
      addEventListener() {}, setAttribute() {}, replaceChildren() {},
    });
    return elements.get(id);
  };
  const context = vm.createContext({
    URL, AbortController, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: {
      getItem: (key) => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value),
      removeItem: (key) => storage.delete(key),
    },
    location: new URL(origin), navigator: {},
    fetch: async () => ({ ok: true, text: async () => JSON.stringify({ token: 'session' }) }),
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  context.refresh = async () => {};
  return { context, element, storage };
}

test('a new phone tunnel uses its current port instead of the previous loopback port', async () => {
  const { context, element, storage } = harness('http://127.0.0.1:41000');
  assert.equal(element('hubUrl').value, 'http://127.0.0.1:49152');
  element('username').value = 'admin';
  element('password').value = 'temporary';
  await context.login({ preventDefault() {} });
  assert.equal(element('loginError').textContent, '');
  assert.equal(element('password').value, '');
  assert.equal(storage.has('sovagrid.hub'), false);
});

test('an explicit remote HTTPS Hub address remains available', () => {
  const { element } = harness('https://hub.example');
  assert.equal(element('hubUrl').value, 'https://hub.example');
});

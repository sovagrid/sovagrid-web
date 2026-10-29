/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const { webcrypto, randomUUID } = require('node:crypto');

const FINGERPRINT = `SHA256:${'A'.repeat(43)}`;
const CHANGED = `SHA256:${'B'.repeat(43)}`;
const TOKEN = 't'.repeat(43);
const preview = () => ({ protocol: 1, target: 'awg2', enrolled: false,
  marker: 'absent', other_marker: 'absent', socket_active: false, service_active: false,
  installer_ready: true, installed_current: false, can_arm: true, reason: 'NOT_ENROLLED' });

function harness({ page = 'https://panel.example/sovagrid/monitoring/', base = 'https://panel.example',
  fingerprint = FINGERPRINT, savedPin = null, previewReply = preview() } = {}) {
  const elements = new Map(), calls = [], storage = new Map();
  const location = new URL(page);
  if (savedPin) storage.set(`sovagrid.ssh-host-key:${location.origin}`, savedPin);
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { textContent: '', value: '', hidden: false, disabled: false,
        checked: id === 'amneziaSetupAuthPassword', files: [], open: false, listeners,
        addEventListener(name, fn) { listeners.set(name, fn); },
        replaceChildren() { this.textContent = ''; }, append() {}, close() {},
      });
    }
    return elements.get(id);
  };
  const context = vm.createContext({
    URL, AbortController, TextEncoder, TextDecoder, Uint8Array, File, btoa, atob,
    crypto: { randomUUID, subtle: webcrypto.subtle }, isSecureContext: true,
    setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, createElement: () => element(Symbol()),
      querySelectorAll: () => [], addEventListener() {}, body: { append() {} } },
    location, navigator: { canShare: () => false }, confirm: () => true,
    localStorage: { getItem: (key) => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value), removeItem: (key) => storage.delete(key) },
    fetch: async (path, options) => {
      calls.push({ path, options });
      const reply = path.endsWith('/host-key')
        ? { protocol: 1, port: 22, key_type: 'ssh-ed25519', fingerprint }
        : typeof previewReply === 'function' ? previewReply(path) : previewReply;
      return { ok: !reply.__httpStatus, status: reply.__httpStatus || 200,
        json: async () => reply.__httpStatus ? reply.body : reply };
    },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('amnezia.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  state.base = base; state.token = TOKEN; state.view = 'vpn';
  state.user = { username: 'admin', role: 'admin', enabled: true };
  state.access = { mode: 'all', unrestricted_admin: true, revision: 1 };
  element('amneziaSetupTarget').value = 'awg2';
  element('amneziaSetupAuthPassword').checked = true;
  context.amneziaSetupRender();
  return { context, state, element, calls, storage };
}

test('VPN panel includes local-only read-only SSH preview and fresh PWA assets', () => {
  const html = fs.readFileSync('index.html', 'utf8');
  const styles = fs.readFileSync('styles.css', 'utf8');
  const shell = fs.readFileSync('sw.js', 'utf8');
  assert.match(html, /id="amneziaSetupPanel"[^>]+data-global-admin-only hidden/);
  assert.match(html, /id="amneziaSetupInspect"/);
  assert.match(html, /id="amneziaSetupTrust"/);
  assert.match(html, /id="amneziaSetupPrivateKey"/);
  assert.match(html, /Показать состояние без изменений/);
  assert.doesNotMatch(html, /id="amneziaSetup(?:Host|Port)Input"/);
  assert.match(styles, /#amneziaSetupKeyFields\[hidden\]/);
  assert.match(html, /amnezia\.js\?v=8/);
  assert.match(shell, /amnezia\.js\?v=8/);
  assert.match(html, /styles\.css\?v=39/);
  assert.match(shell, /styles\.css\?v=39/);
});

test('preview requires reviewed host key and clears SSH password before same-origin request', async () => {
  const h = harness();
  assert.equal(h.element('amneziaSetupSubmit').disabled, true);
  await h.context.amneziaSetupInspect();
  assert.equal(h.calls[0].path, '/api/v1/browser-ssh/host-key');
  assert.equal(h.calls[0].options.credentials, 'omit');
  assert.equal(h.element('amneziaSetupFingerprint').textContent, FINGERPRINT);
  assert.equal(h.element('amneziaSetupSubmit').disabled, true);
  h.element('amneziaSetupTrust').checked = true;
  h.context.amneziaSetupRender();
  h.element('amneziaSetupUsername').value = 'root';
  h.element('amneziaSetupPassword').value = 'private SSH password';
  await h.context.amneziaSetupPreview({ preventDefault() {} });
  assert.equal(h.calls[1].path, '/api/v1/browser-ssh/vpn-setup/preview');
  assert.equal(h.calls[1].options.credentials, 'omit');
  assert.equal(h.calls[1].options.headers.Authorization, `Bearer ${TOKEN}`);
  assert.deepEqual(JSON.parse(h.calls[1].options.body), { username: 'root', method: 'password',
    fingerprint: FINGERPRINT, password: 'private SSH password', private_key: '', passphrase: '', target: 'awg2' });
  assert.equal(h.element('amneziaSetupPassword').value, '');
  assert.equal(h.element('amneziaSetupResult').hidden, false);
  assert.match(h.element('amneziaSetupSummary').textContent, /Изменений не выполнено/);
  assert.deepEqual([...h.storage.entries()], [[`sovagrid.ssh-host-key:${h.context.location.origin}`, FINGERPRINT]]);
});

test('remote Hub, plain remote HTTP and limited admin cannot send SSH credentials', async () => {
  for (const options of [
    { base: 'https://other.example' },
    { page: 'http://panel.example/sovagrid/monitoring/', base: 'http://panel.example' },
  ]) {
    const h = harness(options);
    h.element('amneziaSetupUsername').value = 'root';
    h.element('amneziaSetupPassword').value = 'secret';
    await h.context.amneziaSetupInspect();
    await h.context.amneziaSetupPreview({ preventDefault() {} });
    assert.equal(h.calls.length, 0);
    assert.equal(h.element('amneziaSetupSubmit').disabled, true);
  }
  const h = harness();
  h.state.access = { mode: 'selected', unrestricted_admin: false, revision: 2 };
  await h.context.amneziaSetupInspect();
  assert.equal(h.calls.length, 0);
});

test('changed pinned host key needs an independent replacement decision and fresh consent', async () => {
  const h = harness({ fingerprint: CHANGED, savedPin: FINGERPRINT });
  await h.context.amneziaSetupInspect();
  h.element('amneziaSetupTrust').checked = true;
  h.context.amneziaSetupRender();
  assert.equal(h.element('amneziaSetupSubmit').disabled, true);
  assert.equal(h.element('amneziaSetupReplaceKey').hidden, false);
  await h.context.amneziaSetupPreview({ preventDefault() {} });
  assert.equal(h.calls.length, 1);
  h.element('amneziaSetupReplaceKey').listeners.get('click')();
  assert.equal(h.element('amneziaSetupTrust').checked, false);
  h.element('amneziaSetupTrust').checked = true;
  h.context.amneziaSetupRender();
  assert.equal(h.element('amneziaSetupSubmit').disabled, false);
  assert.equal(h.storage.get(`sovagrid.ssh-host-key:${h.context.location.origin}`), FINGERPRINT);
});

test('private key is read only after host-key consent and its file input is cleared before sending', async () => {
  const h = harness();
  await h.context.amneziaSetupInspect();
  h.element('amneziaSetupTrust').checked = true;
  h.element('amneziaSetupUsername').value = 'operator';
  h.element('amneziaSetupAuthKey').checked = true;
  h.element('amneziaSetupAuthPassword').checked = false;
  h.context.amneziaSetupMethodChanged();
  h.element('amneziaSetupPrivateKey').value = 'selected';
  h.element('amneziaSetupPrivateKey').files = [{ size: 32, text: async () => 'private-key-fixture' }];
  h.element('amneziaSetupPassphrase').value = 'private phrase';
  await h.context.amneziaSetupPreview({ preventDefault() {} });
  assert.equal(h.calls.length, 2);
  assert.deepEqual(JSON.parse(h.calls[1].options.body), { username: 'operator', method: 'private_key',
    fingerprint: FINGERPRINT, password: '', private_key: 'private-key-fixture',
    passphrase: 'private phrase', target: 'awg2' });
  assert.equal(h.element('amneziaSetupPrivateKey').value, '');
  assert.equal(h.element('amneziaSetupPassphrase').value, '');
  assert.equal(h.element('amneziaSetupResult').hidden, false);
});

test('key read completing after logout cannot send a preview or keep a private key', async () => {
  const h = harness();
  await h.context.amneziaSetupInspect();
  h.element('amneziaSetupTrust').checked = true;
  h.element('amneziaSetupUsername').value = 'root';
  h.element('amneziaSetupAuthKey').checked = true;
  h.element('amneziaSetupAuthPassword').checked = false;
  h.context.amneziaSetupMethodChanged();
  let release;
  h.element('amneziaSetupPrivateKey').files = [{ size: 100,
    text: () => new Promise((resolve) => { release = resolve; }) }];
  const pending = h.context.amneziaSetupPreview({ preventDefault() {} });
  h.context.amneziaSetupReset();
  release('-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----');
  await pending;
  assert.equal(h.calls.length, 1); // Host-key inspection only.
  assert.equal(h.element('amneziaSetupPrivateKey').value, '');
  assert.equal(h.element('amneziaSetupResult').hidden, true);
});

test('malformed gateway preview is rejected without saving its fingerprint', async () => {
  const h = harness({ previewReply: { protocol: 1, target: 'awg2', enrolled: true } });
  await h.context.amneziaSetupInspect();
  h.element('amneziaSetupTrust').checked = true;
  h.element('amneziaSetupUsername').value = 'root';
  h.element('amneziaSetupPassword').value = 'secret';
  await h.context.amneziaSetupPreview({ preventDefault() {} });
  assert.equal(h.element('amneziaSetupResult').hidden, true);
  assert.equal(h.storage.size, 0);
  assert.equal(h.element('amneziaSetupPassword').value, '');
});

test('failed or malformed repeat enrollment preview invalidates the earlier action card', async () => {
  const enrollment = { protocol: 1, action: 'enroll_preview', writes: false,
    target: 'awg2', container_id: 'a'.repeat(64), image_id: `sha256:${'b'.repeat(64)}`,
    config_sha256: 'c'.repeat(64), table_sha256: 'd'.repeat(64),
    configured_clients: 2, vpn_protocol: 'amneziawg', interface: 'awg0',
    listen_port: 51820, server_subnet: '10.0.0.0/24',
    host_key_fingerprint: FINGERPRINT, reverify_required: true };
  for (const failure of [{ protocol: 1, action: 'enroll_preview' },
    { __httpStatus: 503, body: { error: 'SETUP_UNAVAILABLE' } }]) {
    let previews = 0;
    const h = harness({ previewReply: (path) => {
      if (path.endsWith('/vpn-setup/preview')) return preview();
      if (path.endsWith('/vpn-setup/enroll-preview')) return ++previews === 1 ? enrollment : failure;
      throw new Error(`Unexpected test request: ${path}`);
    } });
    await h.context.amneziaSetupInspect();
    h.element('amneziaSetupTrust').checked = true;
    h.element('amneziaSetupUsername').value = 'root';
    h.element('amneziaSetupPassword').value = 'temporary-ssh-secret';
    await h.context.amneziaSetupPreview({ preventDefault() {} });
    h.element('amneziaSetupPassword').value = 'temporary-ssh-secret';
    await h.context.amneziaSetupAction('enroll-preview');
    assert.equal(h.element('amneziaSetupEnrollment').hidden, false);
    assert.equal(h.element('amneziaSetupEnroll').disabled, false);
    h.element('amneziaSetupPassword').value = 'temporary-ssh-secret';
    await h.context.amneziaSetupAction('enroll-preview');
    assert.equal(previews, 2);
    assert.equal(h.element('amneziaSetupEnrollment').hidden, true);
    assert.equal(h.element('amneziaSetupEnroll').disabled, true);
    assert.equal(h.element('amneziaSetupEnrollmentSummary').textContent, '');
    assert.equal(h.element('amneziaSetupEnrollmentPins').textContent, '');
    assert.equal(h.element('amneziaSetupPassword').value, '');
    assert.equal(h.calls.filter(({ path }) => path.endsWith('/vpn-setup/enroll')).length, 0);
    assert.doesNotMatch(JSON.stringify([...h.storage.entries()]), /temporary-ssh-secret/);
  }
});

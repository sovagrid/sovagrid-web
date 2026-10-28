/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const { webcrypto, randomUUID } = require('node:crypto');

const encoder = new TextEncoder();
const reply = (status, payload) => ({ ok: status >= 200 && status < 300, status,
  text: async () => JSON.stringify(payload) });
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};

function harness({ secure = true, decryptGate = null, origin = null, androidBridge = null, appleBridge = null } = {}) {
  const elements = new Map(), downloads = [], shares = [], saved = [];
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, {
        textContent: '', value: '', hidden: false, disabled: false, open: false, children: [], listeners,
        addEventListener(name, handler) { listeners.set(name, handler); },
        setAttribute() {}, append(...children) { this.children.push(...children); },
        replaceChildren() { this.children = []; }, showModal() { this.open = true; },
        close() { this.open = false; listeners.get('close')?.({}); },
        click() { downloads.push({ url: this.href, filename: this.download }); }, remove() {},
      });
    }
    return elements.get(id);
  };
  class TestUrl extends URL {
    static createObjectURL(file) { saved.push(file); return `blob:test-${saved.length}`; }
    static revokeObjectURL() {}
  }
  let fetchHook = () => { throw new Error('unexpected fetch'); };
  const subtle = decryptGate ? {
    generateKey: (...args) => webcrypto.subtle.generateKey(...args),
    exportKey: (...args) => webcrypto.subtle.exportKey(...args),
    importKey: (...args) => webcrypto.subtle.importKey(...args),
    deriveBits: (...args) => webcrypto.subtle.deriveBits(...args),
    deriveKey: (...args) => webcrypto.subtle.deriveKey(...args),
    decrypt: async (...args) => { decryptGate.started = true; await decryptGate.promise; return webcrypto.subtle.decrypt(...args); },
  } : webcrypto.subtle;
  const context = vm.createContext({
    URL: TestUrl, AbortController, TextEncoder, File, Uint8Array, atob, btoa,
    isSecureContext: secure, crypto: { randomUUID, subtle },
    setTimeout: (fn, ms) => ms === 60000 ? 0 : setTimeout(fn, ms), clearTimeout,
    setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, createElement: () => element(Symbol()),
      querySelectorAll: () => [], addEventListener() {}, body: { append() {} } },
    localStorage: { getItem: () => null, setItem(...args) { saved.push(args); } },
    navigator: { canShare: () => true, share: async (payload) => { shares.push(payload); } },
    location: origin ? new URL(origin) : { protocol: 'file:' },
    sovagridNativeProfile: androidBridge,
    webkit: appleBridge ? { messageHandlers: { sovagridNativeProfile: appleBridge } } : undefined,
    fetch: (...args) => fetchHook(...args),
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  state.base = 'https://hub.example'; state.token = 'session-A';
  state.servers = [{ id: 'server-A', name: 'Server A', online: true, remote_commands_enabled: true }];
  state.selectedId = 'server-A'; state.view = 'vpn';
  context.renderVpnControls();
  element('vpnExportInstance').value = 'phone-vpn';
  element('vpnExportClient').value = 'my-iphone';
  return { context, state, element, downloads, shares, saved,
    setFetchHook: (hook) => { fetchHook = hook; } };
}

async function encryptedEnvelope(publicKey, name, client, content) {
  const peer = await webcrypto.subtle.importKey('raw', Buffer.from(publicKey, 'base64url'),
    { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ephemeral = await webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const shared = await webcrypto.subtle.deriveBits({ name: 'ECDH', public: peer }, ephemeral.privateKey, 256);
  const material = await webcrypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const nonce = webcrypto.getRandomValues(new Uint8Array(12));
  const key = await webcrypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt,
    info: encoder.encode('SovaGrid sealed WireGuard profile v1') }, material,
  { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ciphertext = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce,
    additionalData: encoder.encode(`SovaGrid profile\0${name}\0${client}`), tagLength: 128 },
  key, encoder.encode(content));
  return JSON.stringify({ version: 1,
    ephemeral_public_key: Buffer.from(await webcrypto.subtle.exportKey('raw', ephemeral.publicKey)).toString('base64url'),
    salt: Buffer.from(salt).toString('base64url'), nonce: Buffer.from(nonce).toString('base64url'),
    ciphertext: Buffer.from(ciphertext).toString('base64url') });
}

async function until(predicate) {
  const deadline = performance.now() + 5000;
  while (performance.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.fail('asynchronous UI step did not finish');
}

async function completedProfile(h, content = '[Interface]\nPrivateKey = NATIVE_SECRET\n') {
  const { context, state, element, setFetchHook } = h;
  await context.prepareVpnExport({ preventDefault() {} });
  const pending = state.vpnPending;
  setFetchHook(() => Promise.resolve(reply(201,
    { job: { id: 'native-job', server_id: 'server-A', state: 'queued' } })));
  context.refresh = async () => {};
  await context.submitVpnAction();
  const envelope = await encryptedEnvelope(pending.payload.public_key, pending.payload.name,
    pending.payload.client, content);
  state.vpnActionJob = { id: 'native-job', server_id: 'server-A', state: 'succeeded', output: envelope };
  context.renderVpnActionJob();
  await until(() => element('vpnProfileDownload').hidden === false);
  return content;
}

test('browser sends only a fresh public key, decrypts a real envelope, and downloads only on click', async () => {
  const { context, state, element, setFetchHook, downloads, shares, saved } = harness();
  await context.prepareVpnExport({ preventDefault() {} });
  assert.equal(element('vpnActionDialog').open, true);
  const pending = state.vpnPending;
  assert.deepEqual(Object.keys(pending.payload).sort(), ['action', 'client', 'name', 'public_key']);
  assert.equal(pending.payload.action, 'sealed-export');
  assert.match(pending.payload.public_key, /^[A-Za-z0-9_-]{87}$/);
  assert.equal(vm.runInContext('pendingSealedExport.privateKey.extractable', context), false);
  const posts = [];
  setFetchHook((url, options) => { posts.push({ url, options }); return Promise.resolve(reply(201,
    { job: { id: 'sealed-job', server_id: 'server-A', state: 'queued' } })); });
  context.refresh = async () => {};
  await context.submitVpnAction();
  assert.equal(posts.length, 1);
  assert.equal(posts[0].options.headers['Idempotency-Key'], pending.key);
  assert.equal(posts[0].options.body, JSON.stringify(pending.payload));
  assert.equal(downloads.length, 0);
  const profile = '[Interface]\nPrivateKey = CLIENT_SECRET\n[Peer]\nPublicKey = SERVER_PUBLIC\n';
  const envelope = await encryptedEnvelope(pending.payload.public_key, 'phone-vpn', 'my-iphone', profile);
  state.vpnActionJob = { id: 'sealed-job', server_id: 'server-A', state: 'succeeded', output: envelope };
  context.renderVpnActionJob();
  await until(() => element('vpnProfileDownload').hidden === false);
  assert.equal(element('vpnActionJobOutput').textContent, '');
  assert.equal(downloads.length, 0, 'completion must never start a download');
  assert.equal(vm.runInContext('activeSealedExport.privateKey', context), null);
  state.jobs = [{ ...state.vpnActionJob, server_id: 'server-A' }];
  context.renderJobs();
  const visible = (node) => [node.textContent, ...node.children.flatMap(visible)].join(' ');
  assert.doesNotMatch(visible(element('jobsList')), /ciphertext|CLIENT_SECRET|ephemeral_public_key/);
  assert.doesNotMatch(visible(element('vpnActionJobPanel')), /ciphertext|CLIENT_SECRET|ephemeral_public_key/);
  assert.equal(saved.some((entry) => Array.isArray(entry)), false, 'profile must not be written to localStorage');
  context.downloadVpnProfile();
  assert.equal(downloads.length, 1);
  assert.equal(downloads[0].filename, 'phone-vpn-my-iphone.conf');
  assert.equal(await saved[0].text(), profile);
  await context.shareVpnProfile();
  assert.equal(shares.length, 1);
  assert.equal(await shares[0].files[0].text(), profile);
  context.prepareVpnAction({ action: 'activate', name: 'phone-vpn' });
  element('vpnActionDialog').close();
  context.downloadVpnProfile();
  assert.equal(downloads.length, 2, 'cancelling another confirmation must keep the current file available');
});

test('full-route export is explicit and preserves the native bridge filename', async () => {
  const h = harness();
  h.element('vpnExportRoute').value = 'full';
  await h.context.prepareVpnExport({ preventDefault() {} });
  const pending = h.state.vpnPending;
  assert.equal(pending.payload.route, 'full');
  assert.match(h.element('vpnActionSummary').textContent, /весь трафик/);
  h.setFetchHook(() => Promise.resolve(reply(201,
    { job: { id: 'full-job', server_id: 'server-A', state: 'queued' } })));
  h.context.refresh = async () => {};
  await h.context.submitVpnAction();
  const content = '[Interface]\nPrivateKey = FULL_SECRET\n[Peer]\nAllowedIPs = 0.0.0.0/0, ::/0\n';
  const sealed = await encryptedEnvelope(pending.payload.public_key, pending.payload.name,
    pending.payload.client, content);
  h.state.vpnActionJob = { id: 'full-job', server_id: 'server-A', state: 'succeeded', output: sealed };
  h.context.renderVpnActionJob();
  await until(() => h.element('vpnProfileDownload').hidden === false);
  assert.equal(vm.runInContext('activeSealedExport.file.name', h.context), 'phone-vpn-my-iphone.conf');
  assert.equal(h.element('vpnExportRoute').value, 'split');
});

test('lost browser key hides ciphertext and requires a new export', async () => {
  const { context, state, element } = harness();
  state.vpnActionJobId = 'old-sealed-job';
  state.vpnActionJob = { id: 'old-sealed-job', server_id: 'server-A', state: 'succeeded',
    output: JSON.stringify({ version: 1, ephemeral_public_key: 'abc', salt: 'def', nonce: 'ghi', ciphertext: 'jkl' }) };
  context.renderVpnActionJob();
  assert.equal(element('vpnActionJobOutput').textContent, '');
  assert.equal(element('vpnProfileDownload').hidden, true);
  assert.match(element('vpnProfileStatus').textContent, /Запросите профиль ещё раз/);
  context.downloadVpnProfile();
});

test('uncertain POST reuses one public key and UUID; logout discards a pending decryption', async () => {
  const gate = deferred();
  const { context, state, element, setFetchHook, downloads } = harness({ decryptGate: gate });
  await context.prepareVpnExport({ preventDefault() {} });
  const pending = state.vpnPending;
  const sent = [];
  setFetchHook((_url, options) => {
    sent.push({ key: options.headers['Idempotency-Key'], body: options.body });
    return sent.length === 1 ? Promise.reject(new Error('network failed')) :
      Promise.resolve(reply(200, { job: { id: 'same-job', server_id: 'server-A', state: 'queued' } }));
  });
  context.refresh = async () => {};
  await context.submitVpnAction();
  assert.equal(state.vpnPending.key, pending.key);
  await context.submitVpnAction();
  assert.deepEqual(sent.map((item) => item.key), [pending.key, pending.key]);
  assert.equal(sent[0].body, sent[1].body);
  const envelope = await encryptedEnvelope(pending.payload.public_key, 'phone-vpn', 'my-iphone', '[Interface]\nPrivateKey = TEST\n');
  state.vpnActionJob = { id: 'same-job', server_id: 'server-A', state: 'succeeded', output: envelope };
  context.renderVpnActionJob();
  await until(() => gate.started);
  context.logout(false);
  assert.equal(vm.runInContext('activeSealedExport', context), null);
  gate.resolve();
  await new Promise(setImmediate);
  await new Promise(setImmediate);
  assert.equal(element('vpnProfileDownload').hidden, true);
  assert.equal(downloads.length, 0);
});

for (const platform of ['Android', 'Apple']) {
  test(`${platform} loopback bridge receives a validated profile only after download click`, async () => {
    const messages = [];
    const bridge = { postMessage(value) { messages.push(value); } };
    const h = harness({ origin: 'http://127.0.0.1:8766',
      [platform === 'Android' ? 'androidBridge' : 'appleBridge']: bridge });
    const profile = await completedProfile(h);
    assert.equal(messages.length, 0);
    assert.equal(h.downloads.length, 0);
    await h.context.downloadVpnProfile();
    assert.equal(messages.length, 1);
    assert.equal(h.downloads.length, 0, 'native WebView must not use a blob navigation');
    const payload = JSON.parse(messages[0]);
    assert.deepEqual(Object.keys(payload).sort(), ['data', 'filename', 'version']);
    assert.equal(payload.version, 1);
    assert.equal(payload.filename, 'phone-vpn-my-iphone.conf');
    assert.match(payload.data, /^[A-Za-z0-9_-]+$/);
    assert.equal(Buffer.from(payload.data, 'base64url').toString('base64url'), payload.data);
    assert.equal(Buffer.from(payload.data, 'base64url').toString(), profile);
    assert.match(h.element('vpnProfileStatus').textContent, /Запрос на сохранение/);
  });
}

test('native profile bridge is ignored outside panel loopback origin', async () => {
  const messages = [];
  const h = harness({ origin: 'https://panel.example',
    androidBridge: { postMessage(value) { messages.push(value); } } });
  await completedProfile(h);
  await h.context.downloadVpnProfile();
  assert.equal(messages.length, 0);
  assert.equal(h.downloads.length, 1);
});

test('native profile bridge rejects oversized or renamed files and a stale login', async () => {
  const messages = [];
  const h = harness({ origin: 'http://localhost:8766',
    androidBridge: { postMessage(value) { messages.push(value); } } });
  await completedProfile(h);
  const exportRequest = vm.runInContext('activeSealedExport', h.context);
  const originalFile = exportRequest.file;
  exportRequest.file = new File([Buffer.alloc(16385)], originalFile.name);
  await h.context.downloadVpnProfile();
  assert.equal(messages.length, 0);
  assert.match(h.element('vpnProfileStatus').textContent, /Не удалось открыть/);
  exportRequest.file = originalFile;
  exportRequest.name = '../bad';
  await h.context.downloadVpnProfile();
  assert.equal(messages.length, 0);
  exportRequest.name = 'phone-vpn';
  const gate = deferred();
  exportRequest.file = { name: originalFile.name, size: originalFile.size, arrayBuffer: () => gate.promise };
  const pending = h.context.downloadVpnProfile();
  h.context.logout(false);
  gate.resolve(await originalFile.arrayBuffer());
  await pending;
  assert.equal(messages.length, 0, 'logout must invalidate a pending native save');
});

test('insecure browser context refuses to generate or send a profile key', async () => {
  const { context, element, setFetchHook } = harness({ secure: false });
  setFetchHook(() => { assert.fail('insecure context must not send request'); });
  await context.prepareVpnExport({ preventDefault() {} });
  assert.equal(element('vpnActionDialog').open, false);
  assert.match(element('vpnExportError').textContent, /HTTPS или localhost/);
});

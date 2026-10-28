/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { randomUUID, webcrypto, createHash } = require('node:crypto');
const test = require('node:test');

const response = (status, payload) => ({ ok: status >= 200 && status < 300, status,
  text: async () => JSON.stringify(payload) });

function harness() {
  const elements = new Map();
  const created = [];
  const downloaded = [];
  const revoked = [];
  class TestURL extends URL {
    static createObjectURL() { const value = `blob:test-${downloaded.length + 1}`; downloaded.push(value); return value; }
    static revokeObjectURL(value) { revoked.push(value); }
  }
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { textContent: '', value: '', hidden: false, disabled: false,
        open: false, children: [], listeners, style: {}, dataset: {},
        addEventListener(name, handler) { listeners.set(name, handler); },
        setAttribute() {}, append(...children) { this.children.push(...children); },
        replaceChildren() { this.children = []; },
        click() { this.clicked = true; }, remove() {},
        showModal() { this.open = true; },
        close() { this.open = false; listeners.get('close')?.({}); },
      });
    }
    return elements.get(id);
  };
  let fetchHook = () => { throw new Error('unexpected fetch'); };
  const context = vm.createContext({
    URL: TestURL, Blob, AbortController, TextEncoder, TextDecoder, Uint8Array, btoa, atob,
    crypto: { randomUUID, subtle: webcrypto.subtle },
    setTimeout: (callback, delay) => delay >= 60000 ? 0 : setTimeout(callback, delay),
    clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, createElement: () => { const item = element(Symbol()); created.push(item); return item; },
      querySelectorAll: () => [], addEventListener() {}, body: { append() {} } },
    navigator: {}, localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    location: { protocol: 'file:' }, fetch: (...args) => fetchHook(...args),
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('files.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  const files = vm.runInContext('filesClient', context);
  state.base = 'https://hub.example'; state.token = 'admin-token'; state.view = 'files';
  state.servers = [{ id: 'server-A', name: 'Server A', online: true, remote_commands_enabled: true },
    { id: 'server-B', name: 'Server B', online: true, remote_commands_enabled: true }];
  state.selectedId = 'server-A';
  files.serverId = 'server-A'; files.root = 'workspace'; files.roots = ['workspace']; files.loaded = true;
  return { context, state, files, element, created, downloaded, revoked,
    setFetchHook: (hook) => { fetchHook = hook; } };
}

test('file editor reads, confirms, and writes to the exact server with its ETag', async () => {
  const { context, files, element, setFetchHook } = harness();
  const calls = [];
  let action = '';
  setFetchHook((url, options) => {
    const parsed = new URL(url);
    calls.push({ url: parsed.pathname, options });
    assert.match(parsed.pathname, /^\/api\/v1\/servers\/server-A\/files\/operations/);
    assert.equal(options.headers.Authorization, 'Bearer admin-token');
    if (options.method === 'POST') {
      const body = JSON.parse(options.body);
      action = body.action;
      if (action === 'write') {
        assert.equal(body.etag, 'a'.repeat(64));
        assert.equal(Buffer.from(body.content, 'base64url').toString(), 'edited\n');
      }
      assert.match(options.headers['Idempotency-Key'], /^[0-9a-f-]{36}$/);
      return Promise.resolve(response(201, { operation: { id: randomUUID(), state: 'queued' } }));
    }
    if (action === 'read') return Promise.resolve(response(200, { operation: { state: 'succeeded',
      result: { content: Buffer.from('original\n').toString('base64url'), etag: 'a'.repeat(64), size: 9 } } }));
    if (action === 'write') return Promise.resolve(response(200, { operation: { state: 'succeeded',
      result: { etag: 'b'.repeat(64), size: 7 } } }));
    throw new Error('unexpected action');
  });
  await context.openFile('note.txt');
  assert.equal(element('filesText').value, 'original\n');
  element('filesText').value = 'edited\n';
  context.renderFilesButtons();
  assert.equal(element('filesSave').disabled, false);
  context.prepareFileSave();
  assert.equal(element('filesSaveDialog').open, true);
  assert.equal(calls.filter((call) => call.options.method === 'POST').length, 1);
  await context.confirmFileSave();
  assert.equal(files.etag, 'b'.repeat(64));
  assert.equal(files.originalText, 'edited\n');
  assert.equal(element('filesSaveDialog').open, false);
  assert.equal(calls.filter((call) => call.options.method === 'POST').length, 2);
});

test('ETag conflict preserves unsaved editor content and server switch clears it', async () => {
  const { context, state, files, element, setFetchHook } = harness();
  files.filePath = 'note.txt'; files.etag = 'a'.repeat(64); files.originalText = 'old';
  element('filesText').value = 'unsaved';
  setFetchHook((url, options) => options.method === 'POST'
    ? Promise.resolve(response(201, { operation: { id: randomUUID(), state: 'queued' } }))
    : Promise.resolve(response(200, { operation: { state: 'failed', result: { code: 'conflict' } } })));
  context.prepareFileSave();
  await context.confirmFileSave();
  assert.equal(element('filesText').value, 'unsaved');
  assert.equal(files.etag, 'a'.repeat(64));
  assert.match(element('filesError').textContent, /изменился/);
  state.selectedId = 'server-B';
  context.filesReset();
  assert.equal(element('filesText').value, '');
  assert.equal(files.etag, '');
});

test('uncertain write start retries with the same idempotency key and payload', async () => {
  const { context, files, element, setFetchHook } = harness();
  files.filePath = 'note.txt'; files.etag = 'a'.repeat(64); files.originalText = 'old';
  element('filesText').value = 'new';
  const posts = [];
  setFetchHook((url, options) => {
    if (options.method === 'POST') {
      posts.push({ key: options.headers['Idempotency-Key'], body: options.body });
      if (posts.length === 1) return Promise.reject(new TypeError('lost response'));
      return Promise.resolve(response(200, { operation: { id: randomUUID(), state: 'succeeded' } }));
    }
    return Promise.resolve(response(200, { operation: { state: 'succeeded',
      result: { etag: 'b'.repeat(64), size: 3 } } }));
  });
  context.prepareFileSave();
  await context.confirmFileSave();
  assert.equal(posts.length, 2);
  assert.equal(posts[0].key, posts[1].key);
  assert.equal(posts[0].body, posts[1].body);
  assert.equal(files.originalText, 'new');
});

test('server navigation and manual logout preserve an unsaved file until it is discarded', () => {
  const { context, state, files, element, setFetchHook } = harness();
  files.filePath = 'note.txt'; files.etag = 'a'.repeat(64); files.originalText = 'old';
  element('filesText').value = 'unsaved';
  context.renderSidebar();
  element('serverList').children[1].listeners.get('click')();
  assert.equal(state.selectedId, 'server-A');
  assert.equal(element('filesText').value, 'unsaved');
  assert.match(element('filesError').textContent, /Сначала сохраните/);
  element('logoutButton').listeners.get('click')();
  assert.equal(state.token, 'admin-token');
  assert.equal(element('filesText').value, 'unsaved');
  element('filesDiscard').listeners.get('click')();
  assert.equal(element('filesText').value, 'old');
  setFetchHook(() => Promise.resolve(response(204, {})));
  element('logoutButton').listeners.get('click')();
  assert.equal(state.token, '');
  assert.equal(element('filesText').value, '');
});

test('binary download uses bounded chunks, checks digest, and releases Hub results', async () => {
  const { context, element, created, downloaded, setFetchHook } = harness();
  const raw = Buffer.from(Array.from({ length: 150000 }, (_, index) => index % 256));
  const digest = createHash('sha256').update(raw).digest('hex');
  const etag = 'a'.repeat(64);
  const requests = [];
  let last;
  setFetchHook((url, options) => {
    if (options.method === 'POST') {
      last = JSON.parse(options.body);
      requests.push(last);
      return Promise.resolve(response(201, { operation: { id: randomUUID(), state: 'queued' } }));
    }
    if (options.method === 'DELETE') return Promise.resolve(response(200, { closed: true }));
    const value = last.action === 'binary_info' ? { size: raw.length, etag, sha256: digest } :
      { content: raw.subarray(last.offset, last.offset + 65536).toString('base64url'),
        offset: last.offset, size: Math.min(65536, raw.length - last.offset), etag };
    return Promise.resolve(response(200, { operation: { state: 'succeeded', result: value } }));
  });
  await context.prepareBinaryDownload('archive.bin');
  assert.equal(element('filesTransferDialog').open, true);
  await context.confirmBinaryTransfer();
  assert.deepEqual(requests.map((item) => item.action), ['binary_info', 'binary_chunk', 'binary_chunk', 'binary_chunk']);
  assert.equal(downloaded.length, 1);
  assert.equal(created.find((item) => item.download === 'archive.bin')?.clicked, true);
  assert.match(element('filesTransferStatus').textContent, /проверен/);
});

test('download above 4 MiB uses 64 KiB requests and verifies before saving', async () => {
  const { context, element, downloaded, setFetchHook } = harness();
  const raw = Buffer.alloc(4 * 1024 * 1024 + 256, 0x73);
  const digest = createHash('sha256').update(raw).digest('hex');
  const etag = 'a'.repeat(64);
  const requests = [];
  let last;
  setFetchHook((url, options) => {
    if (options.method === 'POST') {
      last = JSON.parse(options.body);
      requests.push(last);
      return Promise.resolve(response(201, { operation: { id: randomUUID(), state: 'queued' } }));
    }
    if (options.method === 'DELETE') return Promise.resolve(response(200, { closed: true }));
    const value = last.action === 'binary_info' ? { size: raw.length, etag, sha256: digest } :
      { content: raw.subarray(last.offset, last.offset + 65536).toString('base64url'),
        offset: last.offset, size: Math.min(65536, raw.length - last.offset), etag };
    return Promise.resolve(response(200, { operation: { state: 'succeeded', result: value } }));
  });
  await context.prepareBinaryDownload('over-four.bin');
  await context.confirmBinaryTransfer();
  assert.equal(requests[0].action, 'binary_info');
  assert.equal(requests.filter((item) => item.action === 'binary_chunk').length, 65);
  assert.equal(requests.at(-1).offset, 4 * 1024 * 1024);
  assert.equal(downloaded.length, 1);
  assert.match(element('filesTransferStatus').textContent, /проверен/);
});

test('file list enables downloads above 4 MiB and explains the 32 MiB ceiling', () => {
  const { context, files, element } = harness();
  files.lastEntries = [
    { name: 'medium.bin', kind: 'file', size: 4 * 1024 * 1024 + 1 },
    { name: 'too-big.bin', kind: 'file', size: 32 * 1024 * 1024 + 1 },
  ];
  context.renderFilesEntries();
  const rows = element('filesEntries').children;
  assert.equal(rows[0].children[1].disabled, false);
  assert.equal(rows[1].children[1].disabled, true);
  assert.match(rows[1].children[1].title, /32 МБ/);
});

test('download cap and overwrite cap are reported before transfer', async () => {
  const { context, files, element, downloaded, setFetchHook } = harness();
  files.lastEntries = [{ name: 'large.bin', kind: 'file', size: 4 * 1024 * 1024 + 1 }];
  let size = 32 * 1024 * 1024 + 1;
  let last;
  setFetchHook((url, options) => {
    if (options.method === 'POST') {
      last = JSON.parse(options.body);
      return Promise.resolve(response(201, { operation: { id: randomUUID(), state: 'queued' } }));
    }
    return Promise.resolve(response(200, { operation: { state: 'succeeded',
      result: { size, etag: 'a'.repeat(64), sha256: 'b'.repeat(64) } } }));
  });
  await context.prepareBinaryDownload('large.bin');
  assert.equal(element('filesTransferDialog').open, false);
  assert.match(element('filesError').textContent, /сведения о файле/);
  size = 4 * 1024 * 1024 + 1;
  await context.prepareBinaryUpload({ name: 'large.bin', size: 1 });
  assert.equal(element('filesTransferDialog').open, false);
  assert.match(element('filesError').textContent, /заменить существующий файл больше 4 МБ/);
  assert.equal(downloaded.length, 0);
  assert.equal(last.action, 'binary_info');
});

test('repeated downloads keep at most two live browser URLs', async () => {
  const { context, files, downloaded, revoked, setFetchHook } = harness();
  const raw = Buffer.from('safe');
  const digest = createHash('sha256').update(raw).digest('hex');
  let last;
  setFetchHook((url, options) => {
    if (options.method === 'POST') {
      last = JSON.parse(options.body);
      return Promise.resolve(response(201, { operation: { id: randomUUID(), state: 'queued' } }));
    }
    if (options.method === 'DELETE') return Promise.resolve(response(200, { closed: true }));
    const result = last.action === 'binary_info'
      ? { size: raw.length, etag: 'a'.repeat(64), sha256: digest }
      : { content: raw.toString('base64url'), offset: 0, size: raw.length, etag: 'a'.repeat(64) };
    return Promise.resolve(response(200, { operation: { state: 'succeeded', result } }));
  });
  for (let index = 0; index < 3; index++) {
    await context.prepareBinaryDownload(`file-${index}.bin`);
    await context.confirmBinaryTransfer();
  }
  assert.equal(downloaded.length, 3);
  assert.equal(files.downloadUrls.size, 2);
  assert.deepEqual(revoked, [downloaded[0]]);
});

test('binary upload confirms overwrite and sends exact chunks and digest', async () => {
  const { context, files, element, setFetchHook } = harness();
  const raw = Buffer.from(Array.from({ length: 90000 }, (_, index) => (index * 7) % 256));
  const digest = createHash('sha256').update(raw).digest('hex');
  files.lastEntries = [{ name: 'archive.bin', kind: 'file', size: 8 }];
  const file = { name: 'archive.bin', size: raw.length,
    arrayBuffer: async () => raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength) };
  const calls = [];
  let last;
  const uploadId = randomUUID();
  setFetchHook((url, options) => {
    if (options.method === 'POST') {
      last = JSON.parse(options.body);
      calls.push(last);
      return Promise.resolve(response(201, { operation: { id: randomUUID(), state: 'queued' } }));
    }
    if (options.method === 'DELETE') return Promise.resolve(response(200, { closed: true }));
    const item = last.action === 'binary_info' ? { size: 8, sha256: 'b'.repeat(64), etag: 'a'.repeat(64) } :
      last.action === 'upload_begin' ? { upload_id: uploadId, size: raw.length } :
      last.action === 'upload_chunk' ? { received: last.offset + Buffer.from(last.content, 'base64url').length,
        size: raw.length } :
      last.action === 'upload_commit' ? { size: raw.length, sha256: digest, etag: 'c'.repeat(64) } :
      { entries: [{ name: 'archive.bin', kind: 'file', size: raw.length }], truncated: false };
    return Promise.resolve(response(200, { operation: { state: 'succeeded', result: item } }));
  });
  await context.prepareBinaryUpload(file);
  assert.match(element('filesTransferHeading').textContent, /Заменить/);
  await context.confirmBinaryTransfer();
  assert.equal(calls[1].etag, 'a'.repeat(64));
  assert.equal(calls[1].sha256, digest);
  assert.deepEqual(calls.filter((item) => item.action === 'upload_chunk').map((item) => item.offset), [0, 65536]);
  assert.equal(Buffer.concat(calls.filter((item) => item.action === 'upload_chunk')
    .map((item) => Buffer.from(item.content, 'base64url'))).equals(raw), true);
  assert.match(element('filesTransferStatus').textContent, /сохранён/);
});

test('binary download rejects a wrong whole-file digest before browser save', async () => {
  const { context, element, downloaded, setFetchHook } = harness();
  let last;
  setFetchHook((url, options) => {
    if (options.method === 'POST') {
      last = JSON.parse(options.body);
      return Promise.resolve(response(201, { operation: { id: randomUUID(), state: 'queued' } }));
    }
    if (options.method === 'DELETE') return Promise.resolve(response(200, { closed: true }));
    const result = last.action === 'binary_info'
      ? { size: 4, etag: 'a'.repeat(64), sha256: 'b'.repeat(64) }
      : { content: Buffer.from('test').toString('base64url'), offset: 0, size: 4, etag: 'a'.repeat(64) };
    return Promise.resolve(response(200, { operation: { state: 'succeeded', result } }));
  });
  await context.prepareBinaryDownload('bad.bin');
  await context.confirmBinaryTransfer();
  assert.equal(downloaded.length, 0);
  assert.match(element('filesError').textContent, /Контрольная сумма/);
});

test('oversized upload and unsafe name are rejected before the network', async () => {
  const { context, element, setFetchHook } = harness();
  setFetchHook(() => { throw new Error('network should not be called'); });
  await context.prepareBinaryUpload({ name: '../bad.bin', size: 1 });
  assert.match(element('filesError').textContent, /Имя файла/);
  await context.prepareBinaryUpload({ name: 'large.bin', size: 4 * 1024 * 1024 + 1 });
  assert.match(element('filesError').textContent, /4 МБ/);
});

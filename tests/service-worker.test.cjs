/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

function worker(base = '/sovagrid/monitoring/', oldKeys = [
  'sovagrid-shell:%2Fsovagrid%2Fmonitoring%2F:v45', 'sovagrid-shell-v30', 'other-app-cache']) {
  const events = {}, puts = [], removed = [], added = [];
  const cache = { put: async (...args) => { puts.push(args); added.push(args[0]); },
    match: async () => 'own-public-shell' };
  const context = vm.createContext({ URL, Request, Promise,
    fetch: async (request) => ({ status: 200, redirected: false,
      headers: new Headers({ 'Content-Type': new URL(request.url).pathname.endsWith('.js') ? 'text/javascript' :
        new URL(request.url).pathname.endsWith('.css') ? 'text/css' : 'text/html' }),
      clone() { return this; } }),
    self: { location: { origin: 'https://panel.example', href: 'https://panel.example' + base + 'sw.js' },
      clients: { claim: async () => {} }, skipWaiting() {},
      addEventListener(type, callback) { events[type] = callback; } },
    caches: { open: async () => cache, keys: async () => oldKeys,
      delete: async (key) => removed.push(key) } });
  vm.runInContext(fs.readFileSync('sw.js', 'utf8'), context);
  async function event(type, request) {
    let response; const pending = [];
    events[type]({ request, respondWith(value) { response = value; }, waitUntil(value) { pending.push(value); } });
    const value = await response; await Promise.all(pending); return value;
  }
  return { context, puts, removed, added, event };
}

test('service worker precaches only scoped public assets and preserves other paths', async () => {
  const w = worker(); await w.event('install'); await w.event('activate');
  assert.deepEqual(w.removed, ['sovagrid-shell:%2Fsovagrid%2Fmonitoring%2F:v45']);
  for (const request of w.added) {
    assert.equal(request.credentials, 'omit');
    const url = new URL(request.url); assert.equal(url.origin, 'https://panel.example');
    assert.doesNotMatch(url.pathname, /^\/api\//);
    assert.ok(url.pathname.startsWith('/sovagrid/monitoring/'));
    const path = url.pathname.slice('/sovagrid/monitoring/'.length);
    assert.ok(fs.statSync(path || 'index.html').isFile());
  }
  assert.ok(w.added.some((request) => request.url.endsWith('/sovagrid/monitoring/install.js?v=3')));
  assert.ok(w.added.some((request) => request.url.endsWith('/sovagrid/monitoring/host-backups.js?v=3')));
  assert.ok(w.added.some((request) => request.url.endsWith('/sovagrid/monitoring/host-backups.css?v=3')));
  assert.ok(w.added.some((request) => request.url.endsWith('/icons/maskable-512.png')));
});

test('HTML fallback for a missing script aborts installation without caching the broken shell', async () => {
  const w = worker();
  const good = w.context.fetch;
  w.context.fetch = async (request) => {
    const response = await good(request);
    if (new URL(request.url).pathname.endsWith('/filesystem-alerts.js'))
      response.headers.set('Content-Type', 'text/html; charset=utf-8');
    return response;
  };
  await assert.rejects(w.event('install'), /Incomplete SovaGrid app shell/);
  assert.equal(w.added.length, 0);
  assert.deepEqual(w.removed, ['sovagrid-shell:%2Fsovagrid%2Fmonitoring%2F:v88']);
});

test('HTML fallback for a script never replaces the cached JavaScript on refresh', async () => {
  const w = worker();
  w.context.fetch = async () => ({ status: 200, redirected: false,
    headers: new Headers({ 'Content-Type': 'text/html; charset=utf-8' }), clone() { return this; } });
  await w.event('fetch', new Request('https://panel.example/sovagrid/monitoring/filesystem-alerts.js?v=1'));
  assert.equal(w.puts.length, 0);
});

test('API, credentials, unknown URL parameters and private downloads never enter Cache API', async () => {
  const w = worker();
  for (const [method, path, headers] of [['GET', '/api/v1/session'], ['GET', '/api/v1/servers'],
    ['POST', '/api/v1/session'], ['GET', '/sovagrid/monitoring/?token=private-canary'],
    ['GET', '/sovagrid/monitoring/index.html?password=private-canary'],
    ['GET', '/sovagrid/monitoring/profile.conf'],
    ['GET', '/api/v1/host-backups/operations/' + 'a'.repeat(32) + '/portable/download/images'],
    ['GET', '/sovagrid/monitoring/', { Authorization: 'Bearer private-canary' }]]) {
    assert.equal(await w.event('fetch', new Request('https://panel.example' + path, { method, headers })), undefined);
  }
  assert.equal(w.puts.length, 0);
  await w.event('fetch', new Request('https://panel.example/sovagrid/monitoring/install.js?v=3'));
  assert.equal(w.puts.length, 1);
});

test('no-store/private responses are not cached and offline fallback stays in this public shell cache', async () => {
  const w = worker();
  for (const policy of ['no-store', 'private, max-age=0']) {
    w.context.fetch = async () => ({ status: 200, redirected: false, headers: new Headers({ 'Cache-Control': policy }) });
    await w.event('fetch', new Request('https://panel.example/sovagrid/monitoring/'));
  }
  assert.equal(w.puts.length, 0);
  w.context.fetch = async () => { throw Error('offline'); };
  assert.equal(await w.event('fetch', new Request('https://panel.example/sovagrid/monitoring/')), 'own-public-shell');
});

test('root worker cleans only old SovaGrid root caches', async () => {
  const w = worker('/', ['sovagrid-shell-v45', 'sovagrid-shell:%2F:v45',
    'sovagrid-shell:%2Fsovagrid%2Fmonitoring%2F:v45', 'other-app-cache']);
  await w.event('install'); await w.event('activate');
  assert.deepEqual(w.removed, ['sovagrid-shell-v45', 'sovagrid-shell:%2F:v45']);
  assert.ok(w.added.some((request) => request.url === 'https://panel.example/'));
});

test('a custom panel path registers the stable worker and retires only the legacy root worker', async () => {
  const app = fs.readFileSync('app.js', 'utf8');
  const script = app.slice(app.lastIndexOf('if ("serviceWorker" in navigator'));
  const removed = [];
  const legacy = { scope: 'https://panel.example/',
    active: { scriptURL: 'https://panel.example/sw.js' },
    unregister: async () => { removed.push('legacy'); } };
  const unrelated = { scope: 'https://panel.example/',
    active: { scriptURL: 'https://panel.example/unrelated-sw.js' },
    unregister: async () => { removed.push('unrelated'); } };
  const registrations = [];
  vm.runInNewContext(script, { URL, location: new URL('https://panel.example/ops/monitoring/'),
    document: { currentScript: { src: 'https://panel.example/ops/monitoring/app.js?v=44' } },
    navigator: { serviceWorker: {
      register: async (...args) => { registrations.push(args); return {
        active: { scriptURL: 'https://panel.example/sovagrid/monitoring/sw.js', state: 'activated' },
      }; },
      getRegistrations: async () => [legacy, unrelated],
    } },
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(registrations.length, 1);
  assert.equal(registrations[0][0], 'https://panel.example/sovagrid/monitoring/sw.js');
  assert.equal(registrations[0][1].scope, '/sovagrid/monitoring/');
  assert.deepEqual(removed, ['legacy']);
});

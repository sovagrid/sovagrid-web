/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');

const hub = 'a'.repeat(64), old = 'b'.repeat(64), archive = 'c'.repeat(64);
const review = 'd'.repeat(64), baseline = 'e'.repeat(64), enrollment = 'f'.repeat(64);
const requestId = '83b7d1b0-c5f7-4dc4-bb70-5215fc8a8e1f';
const status = (changes = {}) => ({ protocol: 1, hub_only: true,
  current_hub_manifest_sha256: hub, external_agent_manifest_sha256: old,
  idle_endpoint_present: true, live_idle_ack_verified: false, ...changes });
const preview = (changes = {}) => ({ protocol: 1,
  current_hub_manifest_sha256: hub, candidate_manifest_sha256: hub,
  external_agent_manifest_sha256: old, external_agent_preserved: true,
  tunnel_active: true, source_paths_to_change: [{ path: 'sovagrid-agent/sovagrid_agent/agent.py',
    operation: 'replace' }], original_hub_compatibility: 'verified_same_bundle',
  apply_supported: true, apply_blockers: ['EXTERNAL_AGENT_PREFLIGHT_REQUIRED'],
  explicit_review_required: true, ...changes });
const preflight = (changes = {}) => preview({ archive_sha256: archive,
  baseline_sha256: baseline, enrollment_sha256: enrollment, review_sha256: review,
  candidate_agent_file_count: 12,
  metadata_paths_to_change: ['/opt/sovagrid-agent-installer/source-manifest.json',
    '/var/lib/sovagrid-agent-enrollment/state.json', '/var/lib/sovagrid-promotion/baseline.json'],
  live_gates_pending: ['ORIGINAL_HUB_AGENT_UPDATE_LEASE', 'AGENT_IDLE_ACK', 'TRIAL_FD_WATCHDOG'],
  apply_blockers: [], ...changes });
const operation = (phase = 'accepted', changes = {}) => ({ format: 1, request_id: requestId,
  phase, created_at: 1800000000, updated_at: 1800000001,
  error: ['failed', 'uncertain'].includes(phase) ? 'TEST_FAILURE' : null, ...changes });
const reply = (code, value) => ({ ok: code < 400, status: code,
  text: async () => JSON.stringify(value) });

function harness() {
  const elements = new Map(), calls = [];
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { textContent: '', value: '', hidden: false,
        disabled: false, checked: false, className: '', listeners,
        addEventListener(type, listener) { listeners.set(type, listener); } });
    }
    return elements.get(id);
  };
  let fetchHook = (url, options) => {
    if (url.endsWith('/api/v1/external-agent-update')) return reply(200, status());
    if (url.endsWith('/api/v1/external-agent-update/operations')) return reply(200, { operations: [] });
    if (url.endsWith('/preview')) return reply(200, preview());
    if (url.endsWith('/preflight')) return reply(200, preflight());
    if (url.endsWith('/apply')) return reply(200, operation());
    if (url.endsWith(`/operations/${requestId}`)) return reply(200, operation());
    throw Error(`unexpected request ${url} ${options?.method}`);
  };
  const context = vm.createContext({ URL, AbortController, Date,
    setTimeout: () => 1, clearTimeout() {}, setInterval: () => 1, clearInterval() {},
    crypto: { randomUUID: () => requestId },
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null }, navigator: {}, location: { protocol: 'file:' },
    fetch: (url, options) => { calls.push({ url, options }); return Promise.resolve(fetchHook(url, options)); },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('external-agent-update.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  Object.assign(state, { token: 'test-session', base: 'https://hub.example',
    user: { id: 'admin', username: 'admin', role: 'admin', enabled: true },
    access: { mode: 'all', revision: 0, unrestricted_admin: true }, view: 'settings' });
  return { context, element, state, calls, setFetchHook: (fn) => { fetchHook = fn; } };
}

async function flush() { await new Promise(setImmediate); }

async function prepared(h) {
  await h.context.externalAgentUpdateRefresh(true);
  await flush();
  h.element('externalAgentUpdateArchive').value = archive;
  h.element('externalAgentUpdateArchive').listeners.get('input')();
  await h.context.externalAgentUpdatePrepare();
}

test('only unrestricted admin sees current hashes and can prepare an exact CAS review', async () => {
  const h = harness();
  await prepared(h);
  assert.equal(h.element('externalAgentUpdateHubHash').textContent, hub);
  assert.equal(h.element('externalAgentUpdateAgentHash').textContent, old);
  assert.equal(h.element('externalAgentUpdateReview').hidden, false);
  assert.equal(h.element('externalAgentUpdateReviewHash').textContent, review);
  assert.match(h.element('externalAgentUpdateFiles').textContent, /agent\.py/);
  assert.equal(h.element('externalAgentUpdateApply').disabled, true);
  const posts = h.calls.filter(({ options }) => options.method === 'POST');
  assert.equal(posts.length, 2);
  assert.deepEqual(JSON.parse(posts[0].options.body),
    { archive_sha256: archive, current_hub_manifest_sha256: hub });
  assert.deepEqual(JSON.parse(posts[1].options.body),
    { archive_sha256: archive, current_hub_manifest_sha256: hub });
  h.element('externalAgentUpdateConfirm').checked = true;
  h.element('externalAgentUpdateConfirm').listeners.get('change')();
  assert.equal(h.element('externalAgentUpdateApply').disabled, false);
  h.state.access.unrestricted_admin = false;
  h.context.externalAgentUpdateAccessChanged();
  assert.equal(h.element('externalAgentUpdateApply').disabled, true);
  assert.equal(vm.runInContext('externalAgentUpdateClient.plan', h.context), null);
});

test('editing archive or changing installed state invalidates review and confirmation', async () => {
  const h = harness();
  await prepared(h);
  h.element('externalAgentUpdateConfirm').checked = true;
  h.element('externalAgentUpdateArchive').value = '0'.repeat(64);
  h.element('externalAgentUpdateArchive').listeners.get('input')();
  assert.equal(h.element('externalAgentUpdateReview').hidden, true);
  assert.equal(h.element('externalAgentUpdateConfirm').checked, false);
  h.element('externalAgentUpdateArchive').value = archive;
  await h.context.externalAgentUpdatePrepare();
  h.setFetchHook((url) => url.endsWith('/api/v1/external-agent-update')
    ? reply(200, status({ external_agent_manifest_sha256: '0'.repeat(64) }))
    : reply(200, { operations: [] }));
  await h.context.externalAgentUpdateRefresh(true);
  assert.equal(h.element('externalAgentUpdateReview').hidden, true);
  assert.match(h.element('externalAgentUpdateNotice').textContent, /изменилось/);
  assert.equal(h.calls.filter(({ url }) => url.endsWith('/apply')).length, 0);
});

test('malformed Hub preflight cannot enable apply', async () => {
  const h = harness();
  h.setFetchHook((url) => url.endsWith('/api/v1/external-agent-update')
    ? reply(200, status()) : url.endsWith('/api/v1/external-agent-update/operations')
      ? reply(200, { operations: [] }) : url.endsWith('/preview')
        ? reply(200, preview()) : reply(200, preflight({ review_sha256: '<script>' })));
  await prepared(h);
  assert.equal(h.element('externalAgentUpdateReview').hidden, true);
  assert.equal(h.element('externalAgentUpdateApply').disabled, true);
  assert.equal(h.calls.filter(({ url }) => url.endsWith('/apply')).length, 0);
});

test('an already running server operation is recovered from metadata after page load', async () => {
  const h = harness();
  h.setFetchHook((url) => url.endsWith('/api/v1/external-agent-update')
    ? reply(200, status()) : url.endsWith('/api/v1/external-agent-update/operations')
      ? reply(200, { operations: [operation('running')] }) :
        reply(200, operation('running')));
  await h.context.externalAgentUpdateRefresh(true);
  await flush();
  h.element('externalAgentUpdateArchive').value = archive;
  h.element('externalAgentUpdateArchive').listeners.get('input')();
  assert.equal(h.element('externalAgentUpdateOperationId').textContent, requestId);
  assert.equal(h.element('externalAgentUpdatePreflight').disabled, true);
  assert.equal(h.calls.filter(({ options }) => options.method === 'POST').length, 0);
});

test('one confirmed POST reserves UUID and reconciles unknown response through GET', async () => {
  const h = harness();
  let posts = 0, gets = 0;
  h.setFetchHook((url) => {
    if (url.endsWith('/api/v1/external-agent-update')) return reply(200, status());
    if (url.endsWith('/api/v1/external-agent-update/operations')) return reply(200, { operations: [] });
    if (url.endsWith('/preview')) return reply(200, preview());
    if (url.endsWith('/preflight')) return reply(200, preflight());
    if (url.endsWith('/apply')) { posts++; throw Error('offline'); }
    if (url.endsWith(`/operations/${requestId}`)) { gets++; return reply(200, operation('running')); }
    throw Error(`unexpected ${url}`);
  });
  await prepared(h);
  h.element('externalAgentUpdateConfirm').checked = true;
  await h.context.externalAgentUpdateApply();
  assert.equal(posts, 1);
  assert.equal(gets, 1);
  const sent = h.calls.find(({ url }) => url.endsWith('/apply'));
  assert.deepEqual(JSON.parse(sent.options.body), { request_id: requestId,
    archive_sha256: archive, current_hub_manifest_sha256: hub,
    external_agent_manifest_sha256: old, review_sha256: review, confirmed: true });
  assert.equal(h.element('externalAgentUpdateReview').hidden, true);
  assert.equal(h.element('externalAgentUpdateOperationId').textContent, requestId);
  assert.equal(h.element('externalAgentUpdatePreflight').disabled, true);
  assert.equal(h.calls.filter(({ url }) => url.endsWith('/apply')).length, 1);
});

test('completed operation enables a new plan only after fresh status, and recent list is metadata-only', async () => {
  const h = harness();
  h.setFetchHook((url) => url.endsWith('/api/v1/external-agent-update')
    ? reply(200, status({ external_agent_manifest_sha256: hub })) :
      url.endsWith('/api/v1/external-agent-update/operations')
        ? reply(200, { operations: [operation('complete')] }) :
        reply(200, operation('complete')));
  await h.context.externalAgentUpdateRefresh(true);
  await flush();
  assert.match(h.element('externalAgentUpdateHistory').textContent, /Завершена/);
  assert.match(h.element('externalAgentUpdateHistory').textContent, new RegExp(requestId));
  assert.doesNotMatch(h.element('externalAgentUpdateHistory').textContent, new RegExp(archive));
  assert.equal(h.element('externalAgentUpdateBadge').textContent, 'Готов к плану');
});

test('completed request is checked against the installed Agent manifest without another POST', async () => {
  const h = harness(); let applied = false, posts = 0;
  h.setFetchHook((url) => {
    if (url.endsWith('/api/v1/external-agent-update'))
      return reply(200, status(applied ? { external_agent_manifest_sha256: hub } : {}));
    if (url.endsWith('/api/v1/external-agent-update/operations'))
      return reply(200, { operations: [] });
    if (url.endsWith('/preview')) return reply(200, preview());
    if (url.endsWith('/preflight')) return reply(200, preflight());
    if (url.endsWith('/apply')) { posts++; applied = true; return reply(200, operation()); }
    if (url.endsWith(`/operations/${requestId}`)) return reply(200, operation('complete'));
    throw Error(`unexpected ${url}`);
  });
  await prepared(h);
  h.element('externalAgentUpdateConfirm').checked = true;
  await h.context.externalAgentUpdateApply();
  await flush();
  assert.equal(posts, 1);
  assert.match(h.element('externalAgentUpdateNotice').textContent, /манифест совпал/);
  assert.equal(h.element('externalAgentUpdateAgentHash').textContent, hub);
  assert.equal(h.element('externalAgentUpdateReview').hidden, true);
});

test('assets are bundled and no credential input exists in update panel', () => {
  const html = fs.readFileSync('index.html', 'utf8');
  const section = html.match(/<section id="externalAgentUpdatePanel"[\s\S]*?<\/section>/)?.[0];
  assert.ok(section);
  assert.match(section, /data-global-admin-only/);
  assert.doesNotMatch(section, /type="password"/);
  assert.match(html, /external-agent-update\.js\?v=1/);
  assert.match(fs.readFileSync('Dockerfile', 'utf8'), /external-agent-update\.js external-agent-update\.css/);
  const serviceWorker = fs.readFileSync('sw.js', 'utf8');
  assert.match(serviceWorker, /"\/external-agent-update\.js\?v=1"/);
  assert.match(serviceWorker, /"\/external-agent-update\.css\?v=1"/);
});

/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const elements = new Map();
const element = (id) => {
  if (!elements.has(id)) elements.set(id, { textContent: '', hidden: false, disabled: false, addEventListener() {}, setAttribute() {}, append() {}, replaceChildren() {} });
  return elements.get(id);
};
let fetchHook = () => { throw new Error('unexpected fetch'); };
const context = vm.createContext({
  URL, AbortController, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
  document: { getElementById: element, createElement: () => element(), querySelectorAll: () => [], addEventListener() {} },
  localStorage: { getItem: () => null, setItem() {} },
  navigator: {}, location: { protocol: 'file:' },
  fetch: (...args) => fetchHook(...args),
});
vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
const state = vm.runInContext('state', context);
const rendered = [];
context.renderSidebar = () => {};
context.renderServer = () => {};
context.renderHistory = (samples) => rendered.push(samples[0]?.marker ?? 'empty');
const reply = (payload) => ({ ok: true, status: 200, text: async () => JSON.stringify(payload) });
const defer = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };
const until = async (predicate) => { for (let i = 0; i < 100; i++) { if (predicate()) return; await new Promise(setImmediate); } throw new Error('timed out'); };

(async () => {
  state.base = 'https://hub.example'; state.token = 'token'; state.selectedId = 'a';
  const slowHistory = defer(); let oldHistoryRequested = false;
  fetchHook = (url) => {
    if (url.endsWith('/servers')) return Promise.resolve(reply({ servers: [{ id: 'a' }, { id: 'b' }] }));
    if (url.endsWith('/incidents')) return Promise.resolve(reply({ incidents: [] }));
    if (url.includes('/a/metrics')) { oldHistoryRequested = true; return slowHistory.promise; }
    if (url.includes('/b/metrics')) return Promise.resolve(reply({ metrics: [{ marker: 'b' }] }));
    throw new Error(url);
  };
  const older = context.refresh();
  await until(() => oldHistoryRequested);
  state.selectedId = 'b';
  await context.refresh();
  slowHistory.resolve(reply({ metrics: [{ marker: 'a' }] }));
  await older;
  assert.deepEqual(rendered, ['b'], 'stale history must not replace newly selected server history');

  const slowServers = defer(); let oldServersRequested = false;
  state.base = 'https://old.example'; state.token = 'old-token'; state.selectedId = null;
  fetchHook = (url) => {
    if (url === 'https://old.example/api/v1/servers') { oldServersRequested = true; return slowServers.promise; }
    if (url === 'https://new.example/api/v1/servers') return Promise.resolve(reply({ servers: [{ id: 'new' }] }));
    if (url.endsWith('/incidents')) return Promise.resolve(reply({ incidents: [] }));
    if (url.includes('/new/metrics')) return Promise.resolve(reply({ metrics: [{ marker: 'new' }] }));
    throw new Error(url);
  };
  const stale = context.refresh();
  await until(() => oldServersRequested);
  context.logout(false);
  state.base = 'https://new.example'; state.token = 'new-token';
  await context.refresh();
  slowServers.resolve(reply({ servers: [{ id: 'old' }] }));
  await stale;
  assert.equal(state.servers[0].id, 'new', 'stale Hub response must not replace new session state');
  assert.equal(element('refreshButton').disabled, false);

  state.view = 'commands';
  state.selectedId = 'new';
  let jobsRendered = false;
  let metricsRequested = false;
  context.renderJobs = () => { jobsRendered = true; };
  fetchHook = (url) => {
    if (url.endsWith('/servers')) return Promise.resolve(reply({ servers: [{ id: 'new' }] }));
    if (url.endsWith('/incidents')) return Promise.resolve(reply({ incidents: [] }));
    if (url.includes('/new/metrics')) { metricsRequested = true; throw new Error('commands must not depend on metrics'); }
    if (url.endsWith('/jobs')) return Promise.resolve(reply({ jobs: [{ id: 'job-1', server_id: 'new' }] }));
    throw new Error(url);
  };
  const commandsRefresh = context.refresh();
  await until(() => jobsRendered);
  assert.equal(state.jobs[0].id, 'job-1', 'job results should not depend on metrics');
  await commandsRefresh;
  assert.equal(metricsRequested, false);

  state.view = 'audit';
  let auditRendered = false;
  context.renderAudit = () => { auditRendered = true; };
  fetchHook = (url) => {
    if (url.endsWith('/servers')) return Promise.resolve(reply({ servers: [{ id: 'new' }] }));
    if (url.endsWith('/incidents')) return Promise.resolve(reply({ incidents: [] }));
    if (url.includes('/new/metrics')) { metricsRequested = true; throw new Error('audit must not depend on metrics'); }
    if (url.endsWith('/audit')) return Promise.resolve(reply({ events: [{ id: 3 }] }));
    throw new Error(url);
  };
  const auditRefresh = context.refresh();
  await until(() => auditRendered);
  assert.equal(state.audit[0].id, 3, 'audit should not depend on metrics');
  await auditRefresh;
  assert.equal(metricsRequested, false);

  state.view = 'vpn';
  let vpnRendered = null;
  context.renderVpn = (vpn) => { vpnRendered = vpn; };
  fetchHook = (url) => {
    if (url.endsWith('/servers')) return Promise.resolve(reply({ servers: [] }));
    if (url.endsWith('/incidents')) return Promise.resolve(reply({ incidents: [] }));
    if (url.endsWith('/vpn')) return Promise.resolve(reply({ vpn: { source_status: 'stale', services: [{ name: 'amnezia-awg' }] } }));
    throw new Error(url);
  };
  await context.refresh();
  assert.ok(vpnRendered, element('globalError').textContent || 'VPN did not render');
  assert.equal(vpnRendered.source_status, 'stale', 'VPN status should render even with no monitored servers');
  assert.equal(element('emptyState').hidden, true, 'global VPN view should not show add-server prompt');

  fetchHook = (url) => {
    if (url.endsWith('/servers')) return Promise.resolve(reply({ servers: [] }));
    if (url.endsWith('/incidents')) return Promise.resolve(reply({ incidents: [] }));
    if (url.endsWith('/vpn')) return Promise.resolve({ ok: false, status: 503, text: async () => JSON.stringify({ error: 'adapter unavailable' }) });
    throw new Error(url);
  };
  await context.refresh();
  assert.equal(vpnRendered.source_status, 'error', 'failed VPN request must clear stale service cards');
  assert.equal(element('globalError').textContent, 'adapter unavailable');
  console.log('Web refresh race checks passed');
})().catch((error) => { console.error(error); process.exitCode = 1; });

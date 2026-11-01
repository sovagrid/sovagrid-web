/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const SERVER = '11111111-2222-4333-8444-555555555555';
const FP = `SHA256:${'A'.repeat(43)}`;
const OFF = { commands: false, terminal: false, files: false };
const ON = { commands: true, terminal: true, files: true };
const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { resolve, promise }; };
function reply(features, action = 'preview', extra = {}) {
  return { protocol: 1, action, scope: 'entered_target', host: 'agent.example', port: 22,
    host_key_fingerprint: FP, server_id: SERVER, kind: 'agent_only',
    current: action === 'applied' ? (features || OFF) : OFF, desired: features || OFF,
    hub_enabled: action === 'applied' ? features.commands : false, hub_revision: 2,
    source_manifest_sha256: 'b'.repeat(64),
    ...(action === 'preview' ? { can_apply: features !== null, change_required: !!features?.commands,
      recovery_required: false, pending_features: null, review_sha256: features === null ? null : 'c'.repeat(64),
      temporary_writes: true, activation_writes: false } :
      { applied: true, changed: true, fresh_metric_verified: true, cleanup_required: false }), ...extra };
}
function harness({ page = 'https://hub.example/sovagrid/monitoring/', role = 'admin', unrestricted = true, managementReply = null } = {}) {
  const elements = new Map(), calls = [], storage = new Map(), listeners = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      const handlers = new Map();
      elements.set(id, { value: '', textContent: '', files: [], hidden: false, disabled: false, checked: false,
        open: false, children: [], listeners: handlers, dataset: {}, classList: { toggle() {} },
        addEventListener(name, callback) { handlers.set(name, callback); },
        setAttribute() {}, focus() {}, showModal() { this.open = true; },
        close() { this.open = false; handlers.get('close')?.({}); },
        replaceChildren(...children) { this.children = children; }, append(...children) { this.children.push(...children); } });
    }
    return elements.get(id);
  };
  let hook = null;
  const context = vm.createContext({ URL, AbortController, TextEncoder, TextDecoder, Uint8Array, btoa, atob,
    setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {}, location: new URL(page), navigator: {},
    document: { getElementById: element, createElement: () => element(Symbol()),
      querySelectorAll: (selector) => selector === '[data-agent-features-entry]' ? [element('commandAgentFeaturesButton')] : [],
      addEventListener(name, callback) { listeners.set(name, callback); } },
    localStorage: { getItem: (key) => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value), removeItem: (key) => storage.delete(key) },
    fetch: async (path, options) => {
      path = new URL(path, page).pathname;
      if (path === '/api/v1/agent-management') {
        const rows = await (managementReply || {servers:[{id:SERVER,name:'Agent A'}],truncated:false});
        return { ok:true,status:200,text:async()=>JSON.stringify(rows) };
      }
      const body = JSON.parse(options.body); calls.push({ path, body, options });
      if (hook) return hook(path, body);
      return { ok: true, status: 200, json: async () => reply(body.features, path.endsWith('/apply') ? 'applied' : 'preview') };
    },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  state.base = new URL(page).origin; state.token = 't'.repeat(43);
  state.user = { username: 'owner', role, enabled: true };
  state.access = { mode: 'all', unrestricted_admin: unrestricted, revision: 1 };
  state.servers = [{ id: SERVER, name: 'Agent A', online: true, remote_commands_enabled: false }]; state.selectedId = SERVER;
  context.refresh = async () => {};
  vm.runInContext(fs.readFileSync('agent-features.js', 'utf8'), context);
  const trusted = async () => {
    await context.agentFeaturesOpen(SERVER);
    element('serverSetupHost').value = 'agent.example'; element('serverSetupPort').value = '22';
    element('serverSetupUsername').value = 'operator'; element('serverSetupAuthPassword').checked = true;
    element('serverSetupAuthKey').checked = false; element('serverSetupTrust').checked = true;
    element('serverSetupPassword').value = 'temporary-ssh-secret';
    vm.runInContext(`serverSetup.reviewed = { host:'agent.example',port:22,fingerprint:'${FP}' }; serverSetupRender();`, context);
  };
  return { context, state, element, calls, storage, trusted, listeners,
    hook: (callback) => { hook = callback; }, internal: () => vm.runInContext('agentFeatures', context) };
}

test('reading preserves permissions; a fresh explicit plan and confirmation precede Agent and Hub changes', async () => {
  const h = harness(); await h.trusted();
  await h.context.agentFeaturesRequest('preview', null);
  assert.deepEqual(h.calls[0].body.features, null);
  assert.equal(h.element('agentFeaturesOptions').hidden, false);
  assert.equal(h.element('serverSetupPassword').value, 'temporary-ssh-secret');
  h.element('agentFeaturesFiles').checked = true;
  await h.context.agentFeaturesRequest('preview', { ...OFF, files: true });
  assert.equal(h.calls.length, 1);
  assert.match(h.element('agentFeaturesError').textContent, /явно разрешить команды/);
  for (const name of ['Commands', 'Terminal', 'Files']) h.element('agentFeatures' + name).checked = true;
  await h.context.agentFeaturesRequest('preview', ON);
  assert.equal(h.element('agentFeaturesApply').disabled, true);
  assert.match(h.element('agentFeaturesChanges').children.at(-1).textContent, /Допуск команд в Hub.*выключен → включён/);
  await h.context.agentFeaturesRequest('apply', ON);
  assert.equal(h.calls.length, 2);
  h.element('agentFeaturesConfirm').checked = true;
  await h.context.agentFeaturesRequest('apply', ON);
  assert.equal(h.calls.length, 3);
  assert.equal(h.calls[2].body.expected_review_sha256, 'c'.repeat(64));
  assert.equal(h.calls[2].body.confirm, true);
  assert.equal(h.calls[2].body.username, 'operator');
  assert.equal(h.element('serverSetupPassword').value, '');
  assert.equal(h.internal().plan, null);
  assert.match(h.element('agentFeaturesNotice').textContent, /применены/);
  assert.equal(JSON.stringify([...h.storage]).includes('temporary-ssh-secret'), false);
});

test('read and apply remain unavailable to restricted admins and remote plain HTTP', async () => {
  for (const config of [{ role: 'viewer' }, { unrestricted: false }, { page: 'http://public.example/' }]) {
    const h = harness(config); await h.trusted();
    await h.context.agentFeaturesRequest('preview', null);
    assert.equal(h.calls.length, 0);
    assert.equal(h.internal().active, false);
  }
});

test('changed target and old session responses cannot activate a stale plan or overwrite a new secret', async () => {
  const h = harness(); await h.trusted();
  await h.context.agentFeaturesRequest('preview', null);
  const pending = deferred(); h.hook(() => pending.promise);
  for (const name of ['Commands', 'Terminal', 'Files']) h.element('agentFeatures' + name).checked = true;
  const operation = h.context.agentFeaturesRequest('preview', ON);
  await new Promise(setImmediate);
  h.element('serverSetupHost').value = 'other.example'; h.context.serverSetupInvalidate();
  h.element('serverSetupPassword').value = 'new-session-secret';
  pending.resolve({ ok: true, status: 200, json: async () => reply(ON) });
  await operation;
  assert.equal(h.internal().plan, null);
  assert.equal(h.element('agentFeaturesReview').hidden, true);
  assert.equal(h.element('serverSetupPassword').value, 'new-session-secret');
});

test('unknown result fields or mismatched selected Agent never enable apply', async () => {
  for (const extra of [{ password: 'unexpected' }, { server_id: '99999999-2222-4333-8444-555555555555' }, { hub_revision: true }]) {
    const h = harness(); await h.trusted();
    h.hook(() => ({ ok: true, status: 200, json: async () => reply(ON, 'preview', extra) }));
    await h.context.agentFeaturesRequest('preview', ON);
    assert.equal(h.internal().plan, null);
    assert.match(h.element('agentFeaturesError').textContent, /несовместимый ответ/);
  }
});

test('ProxyJump carries separate reviewed keys; a changed relay invalidates the plan', async () => {
  const h = harness(); await h.trusted();
  const jump = { host: 'jump.example', port: 2222, fingerprint: `SHA256:${'J'.repeat(43)}`, host_key_blob: 'QUFBQUFBQUFBQUFB' };
  h.context.sovagridDirectSSH = { jumpEnabled: () => true, reviewedJump: () => jump,
    installJumpCredentials: async () => ({ ...jump, username: 'relay', method: 'password', password: 'relay-secret', private_key: '', passphrase: '' }), render() {}, clearCredentials() {} };
  vm.runInContext(`Object.assign(serverSetup.reviewed,{viaJump:true,jumpHost:'jump.example',jumpPort:2222,jumpFingerprint:'${jump.fingerprint}',host_key_blob:'QkJCQkJCQkJCQkJC'})`, h.context);
  h.hook((_path, body) => ({ ok: true, status: 200, json: async () => reply(body.features, 'preview', {
    jump_host: jump.host, jump_port: jump.port, jump_host_key_fingerprint: jump.fingerprint }) }));
  await h.context.agentFeaturesRequest('preview', ON);
  assert.equal(h.calls[0].body.host_key_blob, 'QkJCQkJCQkJCQkJC');
  assert.equal(h.calls[0].body.jump.host_key_blob, 'QUFBQUFBQUFBQUFB');
  assert.equal(h.calls[0].body.jump.password, 'relay-secret');
  jump.fingerprint = `SHA256:${'K'.repeat(43)}`;
  h.context.agentFeaturesRender();
  assert.equal(h.internal().plan, null);
  assert.equal(h.element('agentFeaturesApply').disabled, true);
});

test('lost apply reply clears consent and requires reading a new state instead of replaying', async () => {
  const h = harness(); await h.trusted();
  for (const name of ['Commands', 'Terminal', 'Files']) h.element('agentFeatures' + name).checked = true;
  await h.context.agentFeaturesRequest('preview', ON);
  h.element('agentFeaturesConfirm').checked = true;
  h.hook(() => { throw Object.assign(new Error('lost'), { name: 'AbortError' }); });
  await h.context.agentFeaturesRequest('apply', ON);
  assert.equal(h.internal().plan, null);
  assert.equal(h.element('agentFeaturesConfirm').checked, false);
  assert.match(h.element('agentFeaturesError').textContent, /сначала проверьте Agent снова/);
  await h.context.agentFeaturesRequest('apply', ON);
  assert.equal(h.calls.filter((call) => call.path.endsWith('/apply')).length, 1);
});

test('closing and losing global authority clear credentials and plans', async () => {
  const h = harness(); await h.trusted();
  await h.context.agentFeaturesRequest('preview', null);
  h.element('addServerDialog').close();
  assert.equal(h.element('serverSetupPassword').value, '');
  assert.equal(h.internal().active, false);
  await h.trusted(); h.state.access.unrestricted_admin = false;
  h.context.agentFeaturesAccessChanged();
  assert.equal(h.element('serverSetupPassword').value, '');
  assert.equal(h.element('addServerDialog').open, false);
  assert.equal(h.internal().plan, null);
});


test('server picker accepts only the complete enrolled-Agent list, never a full Hub from the dashboard', async () => {
  const h = harness({ managementReply: { servers: [], truncated: false } }); await h.trusted();
  await h.context.agentFeaturesRequest('preview', null);
  assert.equal(h.calls.length, 0);
  assert.equal(h.element('agentFeaturesServer').value, '');
  assert.match(h.element('agentFeaturesNotice').textContent, /Отдельных Agent пока нет/);
  const limited = harness({ managementReply: { servers: [{id:SERVER,name:'Agent A'}], truncated:true } });
  await limited.context.agentFeaturesOpen(SERVER);
  assert.equal(limited.internal().servers.length, 0);
  assert.match(limited.element('agentFeaturesError').textContent, /256/);
});

test('typing a target while the enrolled-Agent list loads does not discard the list', async () => {
  const pending = deferred();
  const h = harness({ managementReply: pending.promise });
  const opened = h.context.agentFeaturesOpen(SERVER);
  h.element('serverSetupHost').value = 'agent.example';
  h.context.serverSetupInvalidate();
  pending.resolve({servers:[{id:SERVER,name:'Agent A'}],truncated:false});
  await opened;
  assert.equal(h.internal().servers.length, 1);
  assert.equal(h.element('agentFeaturesServer').value, SERVER);
});

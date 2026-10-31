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
const until = async (predicate) => {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (predicate()) return;
    await new Promise(setImmediate);
  }
  throw new Error('timed out');
};

function harness({ page = 'https://panel.example/sovagrid/monitoring/', base = 'https://panel.example',
  fingerprint = FINGERPRINT, savedPin = null, previewReply = preview(), replies = {} } = {}) {
  const elements = new Map(), calls = [], storage = new Map(), session = new Map();
  const location = new URL(page);
  if (savedPin) storage.set(`sovagrid.ssh-host-key:${location.origin}`, savedPin);
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { textContent: '', value: '', hidden: false, disabled: false,
        checked: id === 'amneziaSetupAuthPassword', files: [], open: false, listeners,
        addEventListener(name, fn) { listeners.set(name, fn); },
        replaceChildren() { this.textContent = ''; }, append() {},
        showModal() { this.open = true; }, close() { this.open = false; listeners.get('close')?.(); },
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
    sessionStorage: { getItem: (key) => session.get(key) ?? null,
      setItem: (key, value) => session.set(key, value), removeItem: (key) => session.delete(key) },
    fetch: async (path, options) => {
      calls.push({ path, options });
      const reply = Object.hasOwn(replies, path)
        ? typeof replies[path] === 'function' ? replies[path](options) : replies[path]
        : path.endsWith('/host-key')
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
  return { context, state, element, calls, storage, session };
}

test('VPN panel includes local and entered-host SSH setup with fresh PWA assets', () => {
  const html = fs.readFileSync('index.html', 'utf8');
  const styles = fs.readFileSync('styles.css', 'utf8');
  const shell = fs.readFileSync('sw.js', 'utf8');
  assert.match(html, /id="amneziaSetupPanel"[^>]+data-global-admin-only hidden/);
  assert.match(html, /id="amneziaSetupInspect"/);
  assert.match(html, /id="amneziaSetupTrust"/);
  assert.match(html, /id="amneziaSetupPrivateKey"/);
  assert.match(html, /id="amneziaSetupScopeRemote"/);
  assert.match(html, /id="amneziaSetupRemoteHost"/);
  assert.match(html, /id="amneziaSetupRemotePort"/);
  assert.match(html, /id="amneziaSourcePreview"/);
  assert.match(html, /id="amneziaSourceApply"/);
  assert.match(html, /id="wgControlPanel"/);
  assert.match(html, /id="wgControlPreview"/);
  assert.match(html, /id="amneziaProvisionPanel"/);
  assert.match(html, /Новая AmneziaWG 3\.1/);
  assert.match(html, /id="amneziaProvisionRoute"/);
  assert.match(html, /VPN-интерфейс и клиентские профили не создаются и не включаются/);
  assert.match(html, /Показать состояние без изменений/);
  assert.doesNotMatch(html, /id="amneziaSetup(?:Host|Port)Input"/);
  assert.match(styles, /#amneziaSetupKeyFields\[hidden\]/);
  assert.match(html, /amnezia\.js\?v=14/);
  assert.match(shell, /amnezia\.js\?v=14/);
  assert.match(html, /styles\.css\?v=45/);
  assert.match(shell, /styles\.css\?v=45/);
});

test('Amnezia installation drift asks for manual review', () => {
  const h = harness();
  assert.match(h.context.amneziaProvisionReason('INSTALLATION_DRIFT'), /ручная проверка сервера/);
});

test('fresh AmneziaWG preview pins SSH and explicit apply creates only reviewed configuration', async () => {
  const host = 'awg.example', port = 2202;
  const scope = { protocol: 1, scope: 'entered_target', host, port,
    host_key_fingerprint: FINGERPRINT };
  const config = { listen_port: 51820, subnet: '10.44.0.0/24', route_mode: 'full' };
  const full = { ...scope, schema_version: 1, action: 'preview', writes: false,
    target: 'awg2', container: 'amnezia-awg2', ...config,
    image_digest: 'sha256:' + 'd'.repeat(64), image_cached: false,
    state_revision: 'a'.repeat(64), can_apply: true };
  const h = harness({ replies: {
    '/api/v1/browser-ssh/target-host-key': { ...scope, key_type: 'ssh-ed25519',
      fingerprint: FINGERPRINT, reverify_required: true },
    '/api/v1/browser-ssh/target-status': { ...scope, kind: 'agent_only' },
    '/api/v1/browser-ssh/amnezia-provision/preview': full,
    '/api/v1/browser-ssh/amnezia-provision/apply': { ...scope, schema_version: 1,
      action: 'installed', target: 'awg2', container: 'amnezia-awg2',
      container_id: 'b'.repeat(64), image_id: 'sha256:' + 'c'.repeat(64),
      ...config, recovery_required: false },
  } });
  h.element('amneziaSetupScopeLocal').checked = false;
  h.element('amneziaSetupScopeRemote').checked = true;
  h.context.amneziaSetupReset();
  h.element('amneziaSetupRemoteHost').value = host;
  h.element('amneziaSetupRemotePort').value = String(port);
  await h.context.amneziaSetupInspect();
  h.element('amneziaSetupTrust').checked = true;
  h.element('amneziaSetupUsername').value = 'root';
  h.element('amneziaProvisionPort').value = String(config.listen_port);
  h.element('amneziaProvisionSubnet').value = config.subnet;
  h.element('amneziaProvisionRoute').value = config.route_mode;
  h.element('amneziaSetupPassword').value = 'disposable-preview-password';
  await h.context.amneziaProvisionPreview();
  assert.deepEqual(h.calls.map((call) => call.path), [
    '/api/v1/browser-ssh/target-host-key', '/api/v1/browser-ssh/target-status',
    '/api/v1/browser-ssh/amnezia-provision/preview',
  ]);
  assert.equal(h.element('amneziaProvisionReview').hidden, false);
  assert.equal(h.element('amneziaProvisionApply').hidden, false);
  assert.equal(h.element('amneziaSetupPassword').value, '');
  assert.match(h.element('amneziaProvisionSummary').textContent, /IPv4 через VPN/);
  h.element('amneziaSetupPassword').value = 'disposable-apply-password';
  h.context.amneziaProvisionConfirm('apply');
  assert.equal(h.element('amneziaProvisionDialog').open, true);
  assert.equal(h.calls.length, 3, 'review and dialog alone must not create a container');
  h.element('amneziaProvisionDialogConfirm').listeners.get('click')();
  await until(() => h.element('amneziaProvisionNotice').textContent.includes('Docker опубликовал'));
  const applied = h.calls.at(-1);
  assert.equal(applied.path, '/api/v1/browser-ssh/amnezia-provision/apply');
  const body = JSON.parse(applied.options.body);
  assert.deepEqual({ listen_port: body.listen_port, subnet: body.subnet, route_mode: body.route_mode }, config);
  assert.equal(body.expected_state, full.state_revision);
  assert.equal(body.confirm, true);
  assert.equal(body.password, 'disposable-apply-password');
  assert.equal(h.element('amneziaSetupPassword').value, '');
  assert.equal(h.session.size, 0);
  assert.doesNotMatch(JSON.stringify([...h.storage, ...h.session]), /disposable-/);
  assert.match(h.element('amneziaProvisionNotice').textContent, /сетевой экран провайдера/);
});

test('AmneziaWG recovery is separate, and changing subnet invalidates reviewed apply', async () => {
  const host = 'awg.example', scope = { protocol: 1, scope: 'entered_target', host, port: 22,
    host_key_fingerprint: FINGERPRINT };
  const config = { listen_port: 51820, subnet: '10.44.0.0/24', route_mode: 'split' };
  let reason = 'UDP_PORT_BUSY';
  const h = harness({ replies: {
    '/api/v1/browser-ssh/target-host-key': { ...scope, key_type: 'ssh-ed25519',
      fingerprint: FINGERPRINT, reverify_required: true },
    '/api/v1/browser-ssh/target-status': { ...scope, kind: 'agent_only' },
    '/api/v1/browser-ssh/amnezia-provision/preview': () => ({ ...scope,
      schema_version: 1, action: 'preview', writes: false, target: 'awg2',
      container: 'amnezia-awg2', ...config, image_digest: 'sha256:' + 'd'.repeat(64),
      image_cached: true, state_revision: 'a'.repeat(64), can_apply: reason === null,
      ...(reason ? { reason } : {}) }),
    '/api/v1/browser-ssh/amnezia-provision/recover': { ...scope,
      schema_version: 1, action: 'recovered', changed: true, installed: false },
  } });
  h.element('amneziaSetupScopeLocal').checked = false;
  h.element('amneziaSetupScopeRemote').checked = true;
  h.context.amneziaSetupReset();
  h.element('amneziaSetupRemoteHost').value = host;
  h.element('amneziaSetupRemotePort').value = '22';
  await h.context.amneziaSetupInspect();
  h.element('amneziaSetupTrust').checked = true;
  h.element('amneziaSetupUsername').value = 'root';
  h.element('amneziaProvisionPort').value = String(config.listen_port);
  h.element('amneziaProvisionSubnet').value = config.subnet;
  h.element('amneziaProvisionRoute').value = config.route_mode;
  h.element('amneziaSetupPassword').value = 'secret';
  await h.context.amneziaProvisionPreview();
  assert.equal(h.element('amneziaProvisionApply').hidden, true);
  assert.equal(h.element('amneziaProvisionRecover').hidden, true);
  assert.match(h.element('amneziaProvisionSummary').textContent, /UDP-порт уже занят/);
  reason = 'RECOVERY_REQUIRED';
  h.element('amneziaSetupPassword').value = 'secret';
  await h.context.amneziaProvisionPreview();
  assert.equal(h.element('amneziaProvisionRecover').hidden, false);
  h.element('amneziaSetupPassword').value = 'fresh';
  h.context.amneziaProvisionConfirm('recover');
  assert.equal(h.element('amneziaProvisionDialog').open, true);
  assert.equal(h.calls.filter((call) => call.path.endsWith('/amnezia-provision/recover')).length, 0);
  h.element('amneziaProvisionDialogConfirm').listeners.get('click')();
  await until(() => h.element('amneziaProvisionNotice').textContent.includes('очищена'));
  const recovered = JSON.parse(h.calls.at(-1).options.body);
  assert.equal(recovered.confirm, true);
  assert.equal(Object.hasOwn(recovered, 'expected_state'), false);
  assert.equal(h.element('amneziaSetupPassword').value, '');
  reason = null;
  h.element('amneziaSetupPassword').value = 'secret';
  await h.context.amneziaProvisionPreview();
  assert.equal(h.element('amneziaProvisionApply').hidden, false);
  h.element('amneziaProvisionSubnet').value = '10.45.0.0/24';
  h.element('amneziaProvisionSubnet').listeners.get('input')();
  assert.equal(h.element('amneziaProvisionApply').hidden, true);
  assert.equal(h.element('amneziaProvisionReview').hidden, true);
});

test('uncertain AmneziaWG apply blocks retry until fresh recovery review', async () => {
  const host = 'awg.example', scope = { protocol: 1, scope: 'entered_target', host, port: 22,
    host_key_fingerprint: FINGERPRINT };
  const config = { listen_port: 51820, subnet: '10.44.0.0/24', route_mode: 'full' };
  let recovery = false;
  const h = harness({ replies: {
    '/api/v1/browser-ssh/target-host-key': { ...scope, key_type: 'ssh-ed25519',
      fingerprint: FINGERPRINT, reverify_required: true },
    '/api/v1/browser-ssh/target-status': { ...scope, kind: 'agent_only' },
    '/api/v1/browser-ssh/amnezia-provision/preview': () => ({ ...scope,
      schema_version: 1, action: 'preview', writes: false, target: 'awg2',
      container: 'amnezia-awg2', ...config, image_digest: 'sha256:' + 'd'.repeat(64),
      image_cached: true, state_revision: 'a'.repeat(64), can_apply: !recovery,
      ...(recovery ? { reason: 'RECOVERY_REQUIRED' } : {}) }),
    '/api/v1/browser-ssh/amnezia-provision/apply': { __httpStatus: 503,
      body: { error: 'APPLY_UNCERTAIN' } },
    '/api/v1/browser-ssh/amnezia-provision/recover': { ...scope, schema_version: 1,
      action: 'recovered', changed: true, installed: true, container_id: 'b'.repeat(64) },
  } });
  h.element('amneziaSetupScopeLocal').checked = false;
  h.element('amneziaSetupScopeRemote').checked = true;
  h.context.amneziaSetupReset();
  h.element('amneziaSetupRemoteHost').value = host;
  h.element('amneziaSetupRemotePort').value = '22';
  await h.context.amneziaSetupInspect();
  h.element('amneziaSetupTrust').checked = true;
  h.element('amneziaSetupUsername').value = 'root';
  h.element('amneziaProvisionPort').value = String(config.listen_port);
  h.element('amneziaProvisionSubnet').value = config.subnet;
  h.element('amneziaProvisionRoute').value = config.route_mode;
  h.element('amneziaSetupPassword').value = 'first';
  await h.context.amneziaProvisionPreview();
  h.element('amneziaSetupPassword').value = 'second';
  h.context.amneziaProvisionConfirm('apply');
  h.element('amneziaProvisionDialogConfirm').listeners.get('click')();
  await until(() => h.element('amneziaProvisionError').textContent.includes('Состояние могло измениться'));
  assert.equal(h.session.size, 1);
  assert.equal(h.element('amneziaProvisionApply').hidden, true);
  recovery = true;
  h.element('amneziaSetupPassword').value = 'third';
  await h.context.amneziaProvisionPreview();
  assert.equal(h.element('amneziaProvisionRecover').hidden, false);
  assert.equal(h.element('amneziaProvisionApply').hidden, true);
  h.element('amneziaSetupPassword').value = 'fourth';
  h.context.amneziaProvisionConfirm('recover');
  h.element('amneziaProvisionDialogConfirm').listeners.get('click')();
  await until(() => h.element('amneziaProvisionNotice').textContent.includes('Контейнер AmneziaWG 3.1'));
  assert.equal(h.session.size, 0);
  assert.equal(h.calls.filter((call) => call.path.endsWith('/amnezia-provision/apply')).length, 1);
  assert.equal(h.element('amneziaSetupPassword').value, '');
});

test('plain WireGuard broker preview uses pinned target and confirmed apply with exact revisions', async () => {
  const host = 'wg.example', port = 2202;
  const scope = { protocol: 1, scope: 'entered_target', host, port,
    host_key_fingerprint: FINGERPRINT };
  const revisions = { state_revision: 'a'.repeat(64), source_revision: 'b'.repeat(64) };
  const snapshot = { ...scope, schema_version: 1, action: 'preview', writes: false,
    ...revisions, installed_current: false, socket_active: false, service_active: false,
    socket_enabled: false, pending_recovery: false, inventory_timer_active: false,
    inventory_timer_enabled: false, inventory_snapshot_present: false,
    missing_dependencies: ['wg'], apparmor_profile_present: false,
    can_apply: true, requires_service_restart: false };
  const h = harness({ replies: {
    '/api/v1/browser-ssh/target-host-key': { ...scope, key_type: 'ssh-ed25519',
      fingerprint: FINGERPRINT, reverify_required: true },
    '/api/v1/browser-ssh/target-status': { ...scope, kind: 'agent_only' },
    '/api/v1/browser-ssh/wg-control/preview': snapshot,
    '/api/v1/browser-ssh/wg-control/apply': { ...scope, action: 'installed',
      socket_active: true, service_active: true, vpn_interface_changed: false,
      inventory_timer_active: true, inventory_snapshot_present: true,
      source_revision: revisions.source_revision },
  } });
  h.element('amneziaSetupScopeLocal').checked = false;
  h.element('amneziaSetupScopeRemote').checked = true;
  h.context.amneziaSetupReset();
  h.element('amneziaSetupRemoteHost').value = host;
  h.element('amneziaSetupRemotePort').value = String(port);
  await h.context.amneziaSetupInspect();
  h.element('amneziaSetupTrust').checked = true;
  h.element('amneziaSetupUsername').value = 'root';
  h.element('amneziaSetupPassword').value = 'one-use-password';
  await h.context.wgControlPreview();
  assert.deepEqual(h.calls.map((call) => call.path), [
    '/api/v1/browser-ssh/target-host-key', '/api/v1/browser-ssh/target-status',
    '/api/v1/browser-ssh/wg-control/preview',
  ]);
  assert.equal(h.element('wgControlReview').hidden, false);
  assert.equal(h.element('wgControlApply').hidden, false);
  assert.equal(h.element('wgControlRecover').hidden, true);
  assert.equal(h.element('amneziaSetupPassword').value, '');
  assert.match(h.element('wgControlDetails').textContent, /Недостающие пакеты: wg/);
  h.element('amneziaSetupPassword').value = 'fresh-password';
  h.context.wgControlConfirm('apply');
  assert.equal(h.element('wgControlDialog').open, true);
  assert.equal(h.calls.length, 3, 'review alone must not install');
  h.element('wgControlDialogConfirm').listeners.get('click')();
  await until(() => h.element('wgControlNotice').textContent.includes('Брокер, сокет'));
  const applied = h.calls.at(-1);
  assert.equal(applied.path, '/api/v1/browser-ssh/wg-control/apply');
  const body = JSON.parse(applied.options.body);
  assert.deepEqual(body.expected, revisions);
  assert.equal(body.confirm, true);
  assert.equal(body.password, 'fresh-password');
  assert.equal(h.element('amneziaSetupPassword').value, '');
  assert.match(h.element('wgControlNotice').textContent, /VPN-интерфейс не включён/);
  assert.equal(h.session.size, 0);
});

test('degraded WireGuard preview blocks apply and reviewed recovery requires confirmation', async () => {
  const host = 'wg.example', scope = { protocol: 1, scope: 'entered_target', host, port: 22,
    host_key_fingerprint: FINGERPRINT };
  let reason = 'SOURCE_NOT_PREPARED';
  const h = harness({ replies: {
    '/api/v1/browser-ssh/target-host-key': { ...scope, key_type: 'ssh-ed25519',
      fingerprint: FINGERPRINT, reverify_required: true },
    '/api/v1/browser-ssh/target-status': { ...scope, kind: 'agent_only' },
    '/api/v1/browser-ssh/wg-control/preview': () => ({ ...scope, schema_version: 1,
      action: 'preview', writes: false, can_apply: false,
      pending_recovery: reason === 'RECOVERY_REQUIRED', reason }),
    '/api/v1/browser-ssh/wg-control/recover': { ...scope, action: 'recovered', changed: true },
  } });
  h.element('amneziaSetupScopeLocal').checked = false;
  h.element('amneziaSetupScopeRemote').checked = true;
  h.context.amneziaSetupReset();
  h.element('amneziaSetupRemoteHost').value = host;
  h.element('amneziaSetupRemotePort').value = '22';
  await h.context.amneziaSetupInspect();
  h.element('amneziaSetupTrust').checked = true;
  h.element('amneziaSetupUsername').value = 'root';
  h.element('amneziaSetupPassword').value = 'secret';
  await h.context.wgControlPreview();
  assert.equal(h.element('wgControlApply').hidden, true);
  assert.equal(h.element('wgControlRecover').hidden, true);
  assert.match(h.element('wgControlSummary').textContent, /подготовьте VPN-код/);
  reason = 'RECOVERY_REQUIRED';
  h.element('amneziaSetupPassword').value = 'secret';
  await h.context.wgControlPreview();
  assert.equal(h.element('wgControlRecover').hidden, false);
  h.element('amneziaSetupPassword').value = 'new-secret';
  h.context.wgControlConfirm('recover');
  assert.equal(h.element('wgControlDialog').open, true);
  h.element('wgControlDialogConfirm').listeners.get('click')();
  await until(() => h.element('wgControlNotice').textContent.includes('Восстановление завершено'));
  const body = JSON.parse(h.calls.at(-1).options.body);
  assert.equal(body.confirm, true);
  assert.equal(Object.hasOwn(body, 'expected'), false);
  assert.equal(h.element('amneziaSetupPassword').value, '');
});

test('uncertain WireGuard apply retains recovery warning and invalidates reviewed revisions', async () => {
  const host = 'wg.example', scope = { protocol: 1, scope: 'entered_target', host, port: 22,
    host_key_fingerprint: FINGERPRINT };
  const h = harness({ replies: {
    '/api/v1/browser-ssh/target-host-key': { ...scope, key_type: 'ssh-ed25519',
      fingerprint: FINGERPRINT, reverify_required: true },
    '/api/v1/browser-ssh/target-status': { ...scope, kind: 'agent_only' },
    '/api/v1/browser-ssh/wg-control/preview': { ...scope, schema_version: 1,
      action: 'preview', writes: false, state_revision: 'a'.repeat(64),
      source_revision: 'b'.repeat(64), installed_current: false, socket_active: false,
      service_active: false, socket_enabled: false, pending_recovery: false,
      inventory_timer_active: false, inventory_timer_enabled: false,
      inventory_snapshot_present: false, missing_dependencies: [],
      apparmor_profile_present: true, can_apply: true, requires_service_restart: false },
    '/api/v1/browser-ssh/wg-control/apply': { __httpStatus: 503,
      body: { error: 'APPLY_UNCERTAIN' } },
  } });
  h.element('amneziaSetupScopeLocal').checked = false;
  h.element('amneziaSetupScopeRemote').checked = true;
  h.context.amneziaSetupReset();
  h.element('amneziaSetupRemoteHost').value = host;
  h.element('amneziaSetupRemotePort').value = '22';
  await h.context.amneziaSetupInspect();
  h.element('amneziaSetupTrust').checked = true;
  h.element('amneziaSetupUsername').value = 'root';
  h.element('amneziaSetupPassword').value = 'secret';
  await h.context.wgControlPreview();
  h.element('amneziaSetupPassword').value = 'fresh';
  h.context.wgControlConfirm('apply');
  h.element('wgControlDialogConfirm').listeners.get('click')();
  await until(() => h.element('wgControlError').textContent.includes('Действие могло выполниться'));
  assert.equal(h.element('wgControlApply').hidden, true);
  assert.equal(h.session.size, 1, 'uncertain outcome remains visible across reload in this tab');
  h.element('amneziaSetupPassword').value = 'fresh-again';
  await h.context.wgControlPreview();
  assert.equal(h.session.size, 0, 'a verified new preview resolves the uncertainty marker');
  assert.equal(h.element('wgControlApply').hidden, false);
});

test('changing the SSH endpoint invalidates WireGuard review before any write', async () => {
  const host = 'wg.example', scope = { protocol: 1, scope: 'entered_target', host, port: 22,
    host_key_fingerprint: FINGERPRINT };
  const h = harness({ replies: {
    '/api/v1/browser-ssh/target-host-key': { ...scope, key_type: 'ssh-ed25519',
      fingerprint: FINGERPRINT, reverify_required: true },
    '/api/v1/browser-ssh/target-status': { ...scope, kind: 'agent_only' },
    '/api/v1/browser-ssh/wg-control/preview': { ...scope, schema_version: 1,
      action: 'preview', writes: false, state_revision: 'a'.repeat(64),
      source_revision: 'b'.repeat(64), installed_current: false, socket_active: false,
      service_active: false, socket_enabled: false, pending_recovery: false,
      inventory_timer_active: false, inventory_timer_enabled: false,
      inventory_snapshot_present: false, missing_dependencies: [],
      apparmor_profile_present: true, can_apply: true, requires_service_restart: false },
  } });
  h.element('amneziaSetupScopeLocal').checked = false;
  h.element('amneziaSetupScopeRemote').checked = true;
  h.context.amneziaSetupReset();
  h.element('amneziaSetupRemoteHost').value = host;
  h.element('amneziaSetupRemotePort').value = '22';
  await h.context.amneziaSetupInspect();
  h.element('amneziaSetupTrust').checked = true;
  h.element('amneziaSetupUsername').value = 'root';
  h.element('amneziaSetupPassword').value = 'secret';
  await h.context.wgControlPreview();
  assert.equal(h.element('wgControlApply').hidden, false);
  h.element('amneziaSetupRemoteHost').value = 'other.example';
  h.element('amneziaSetupRemoteHost').listeners.get('input')();
  assert.equal(h.element('wgControlApply').hidden, true);
  assert.equal(h.element('wgControlReview').hidden, true);
  h.context.wgControlConfirm('apply');
  assert.equal(h.element('wgControlDialog').open, false);
  assert.equal(h.calls.filter((call) => call.path.endsWith('/wg-control/apply')).length, 0);
});

test('entered host prepares verified VPN code through preview and separate confirmation', async () => {
  const host = 'vpn.example', port = 2202;
  const scope = { protocol: 1, scope: 'entered_target', host, port,
    host_key_fingerprint: FINGERPRINT };
  const hashes = { source_manifest_sha256: 'a'.repeat(64), candidate_sha256: 'b'.repeat(64),
    installed_sha256: '0'.repeat(64), state_sha256: '0'.repeat(64) };
  const h = harness({ replies: {
    '/api/v1/browser-ssh/target-host-key': { ...scope, key_type: 'ssh-ed25519',
      fingerprint: FINGERPRINT, reverify_required: true },
    '/api/v1/browser-ssh/target-status': { ...scope, kind: 'agent_only' },
    '/api/v1/browser-ssh/vpn-source/preview': { ...scope, ...hashes, expected: hashes,
      change: 'install', temporary_writes: true, activation_writes: false,
      cleanup_required: false },
    '/api/v1/browser-ssh/vpn-source/apply': { ...scope, installed: true, changed: true,
      cleanup_required: false, source_manifest_sha256: hashes.source_manifest_sha256,
      candidate_sha256: hashes.candidate_sha256 },
  } });
  h.element('amneziaSetupScopeLocal').checked = false;
  h.element('amneziaSetupScopeRemote').checked = true;
  h.context.amneziaSetupReset();
  h.element('amneziaSetupRemoteHost').value = host;
  h.element('amneziaSetupRemotePort').value = String(port);
  await h.context.amneziaSetupInspect();
  h.element('amneziaSetupTrust').checked = true;
  h.element('amneziaSetupUsername').value = 'root';
  h.element('amneziaSetupPassword').value = 'one-use-password';
  await h.context.amneziaSourcePreview();
  assert.deepEqual(h.calls.map((call) => call.path), [
    '/api/v1/browser-ssh/target-host-key',
    '/api/v1/browser-ssh/target-status',
    '/api/v1/browser-ssh/vpn-source/preview',
  ]);
  assert.equal(h.element('amneziaSourceReview').hidden, false);
  assert.equal(h.element('amneziaSourceApply').hidden, false);
  assert.equal(h.element('amneziaSourceDigest').textContent, hashes.candidate_sha256);
  assert.equal(h.element('amneziaSetupPassword').value, '');
  h.element('amneziaSetupPassword').value = 'second-use-password';
  await h.context.amneziaSourceAction('apply');
  const applied = h.calls.at(-1);
  assert.equal(applied.path, '/api/v1/browser-ssh/vpn-source/apply');
  assert.equal(JSON.parse(applied.options.body).password, 'second-use-password');
  assert.deepEqual(JSON.parse(applied.options.body).expected, hashes);
  assert.match(h.element('amneziaSourceNotice').textContent, /VPN-код подготовлен/);
  assert.equal(h.element('amneziaSourceApply').hidden, true);
  assert.equal(h.element('amneziaSetupPassword').value, '');
  h.element('amneziaSetupRemoteHost').value = 'other.example';
  h.element('amneziaSetupRemoteHost').listeners.get('input')();
  assert.equal(h.element('amneziaSourceNotice').textContent, '');
  assert.equal(h.element('amneziaSourcePreview').disabled, true);
});

test('VPN source preview exposes only reviewed recovery and never reuses a stale endpoint', async () => {
  const host = 'vpn.example', port = 22;
  const scope = { protocol: 1, scope: 'entered_target', host, port,
    host_key_fingerprint: FINGERPRINT };
  const hashes = { source_manifest_sha256: 'a'.repeat(64), candidate_sha256: 'b'.repeat(64),
    installed_sha256: 'b'.repeat(64), state_sha256: 'c'.repeat(64) };
  const h = harness({ replies: {
    '/api/v1/browser-ssh/target-host-key': { ...scope, key_type: 'ssh-ed25519',
      fingerprint: FINGERPRINT, reverify_required: true },
    '/api/v1/browser-ssh/target-status': { ...scope, kind: 'agent_only' },
    '/api/v1/browser-ssh/vpn-source/preview': { ...scope, ...hashes, expected: hashes,
      change: 'current', temporary_writes: true, activation_writes: false,
      cleanup_required: true },
    '/api/v1/browser-ssh/vpn-source/recover': { ...scope, recovered: true },
  } });
  h.element('amneziaSetupScopeLocal').checked = false;
  h.element('amneziaSetupScopeRemote').checked = true;
  h.context.amneziaSetupReset();
  h.element('amneziaSetupRemoteHost').value = host;
  h.element('amneziaSetupRemotePort').value = String(port);
  await h.context.amneziaSetupInspect();
  h.element('amneziaSetupTrust').checked = true;
  h.element('amneziaSetupUsername').value = 'root';
  h.element('amneziaSetupPassword').value = 'temporary-password';
  await h.context.amneziaSourcePreview();
  assert.equal(h.element('amneziaSourceApply').hidden, true);
  assert.equal(h.element('amneziaSourceRecover').hidden, false);
  h.element('amneziaSetupPassword').value = 'fresh-password';
  await h.context.amneziaSourceAction('recover');
  assert.equal(h.calls.at(-1).path, '/api/v1/browser-ssh/vpn-source/recover');
  assert.equal(JSON.parse(h.calls.at(-1).options.body).password, 'fresh-password');
  assert.equal(JSON.parse(h.calls.at(-1).options.body).expected, undefined);
  assert.match(h.element('amneziaSourceNotice').textContent, /Очистка завершена/);
  h.element('amneziaSetupRemoteHost').value = 'other.example';
  h.element('amneziaSetupRemoteHost').listeners.get('input')();
  assert.equal(h.element('amneziaSourceNotice').textContent, '');
  assert.equal(h.element('amneziaSourceRecover').hidden, true);
});

test('interrupted VPN source staging offers recovery after a failed preview', async () => {
  const host = 'vpn.example', port = 22;
  const scope = { protocol: 1, scope: 'entered_target', host, port,
    host_key_fingerprint: FINGERPRINT };
  const h = harness({ replies: {
    '/api/v1/browser-ssh/target-host-key': { ...scope, key_type: 'ssh-ed25519',
      fingerprint: FINGERPRINT, reverify_required: true },
    '/api/v1/browser-ssh/target-status': { ...scope, kind: 'agent_only' },
    '/api/v1/browser-ssh/vpn-source/preview': { __httpStatus: 409,
      body: { error: 'STAGE_CLEANUP_REQUIRED' } },
    '/api/v1/browser-ssh/vpn-source/recover': { ...scope, recovered: true },
  } });
  h.element('amneziaSetupScopeLocal').checked = false;
  h.element('amneziaSetupScopeRemote').checked = true;
  h.context.amneziaSetupReset();
  h.element('amneziaSetupRemoteHost').value = host;
  h.element('amneziaSetupRemotePort').value = String(port);
  await h.context.amneziaSetupInspect();
  h.element('amneziaSetupTrust').checked = true;
  h.element('amneziaSetupUsername').value = 'root';
  h.element('amneziaSetupPassword').value = 'temporary-password';
  await h.context.amneziaSourcePreview();
  assert.equal(h.element('amneziaSourceRecover').hidden, false);
  assert.equal(h.element('amneziaSourceApply').hidden, true);
  h.element('amneziaSetupPassword').value = 'fresh-password';
  await h.context.amneziaSourceAction('recover');
  assert.equal(h.calls.at(-1).path, '/api/v1/browser-ssh/vpn-source/recover');
  assert.match(h.element('amneziaSourceNotice').textContent, /Очистка завершена/);
});

test('entered Ubuntu host needs its own pinned SSH key and status before VPN preview', async () => {
  const host = 'vpn.example', port = 2202;
  const scoped = { scope: 'entered_target', host, port, host_key_fingerprint: FINGERPRINT };
  const h = harness({ replies: {
    '/api/v1/browser-ssh/target-host-key': { protocol: 1, scope: 'entered_target',
      host, port, key_type: 'ssh-ed25519', fingerprint: FINGERPRINT,
      reverify_required: true },
    '/api/v1/browser-ssh/target-status': { protocol: 1, ...scoped, kind: 'managed' },
    '/api/v1/browser-ssh/vpn-setup/preview': { ...preview(), ...scoped },
  } });
  h.element('amneziaSetupScopeLocal').checked = false;
  h.element('amneziaSetupScopeRemote').checked = true;
  h.context.amneziaSetupReset();
  h.element('amneziaSetupRemoteHost').value = 'VPN.Example';
  h.element('amneziaSetupRemotePort').value = String(port);
  await h.context.amneziaSetupInspect();
  assert.equal(h.calls[0].path, '/api/v1/browser-ssh/target-host-key');
  assert.deepEqual(JSON.parse(h.calls[0].options.body), { host, port });
  assert.equal(h.calls[0].options.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(h.element('amneziaSetupKeyHost').textContent, host);
  assert.equal(h.element('amneziaSetupSubmit').disabled, true);
  h.element('amneziaSetupTrust').checked = true;
  h.element('amneziaSetupUsername').value = 'root';
  h.element('amneziaSetupPassword').value = 'temporary-remote-password';
  await h.context.amneziaSetupPreview({ preventDefault() {} });
  assert.equal(h.calls[1].path, '/api/v1/browser-ssh/target-status');
  assert.equal(h.calls[2].path, '/api/v1/browser-ssh/vpn-setup/preview');
  assert.deepEqual(JSON.parse(h.calls[1].options.body), { host, port, username: 'root',
    method: 'password', fingerprint: FINGERPRINT, password: 'temporary-remote-password',
    private_key: '', passphrase: '' });
  assert.equal(JSON.parse(h.calls[2].options.body).host, host);
  assert.equal(h.element('amneziaSetupPassword').value, '');
  assert.equal(h.element('amneziaSetupResult').hidden, false);
  assert.equal(h.storage.get(`sovagrid.target-ssh-host-key:${h.context.location.origin}:${host}:${port}`),
    FINGERPRINT);
  h.element('amneziaSetupRemoteHost').value = 'other.example';
  h.element('amneziaSetupRemoteHost').listeners.get('input')();
  assert.equal(h.element('amneziaSetupResult').hidden, true);
  assert.equal(h.element('amneziaSetupSubmit').disabled, true);
  assert.equal(h.element('amneziaSetupHostKeyReview').hidden, true);
  assert.equal(h.calls.length, 3);
});

test('entered host without SovaGrid Agent cannot reach VPN preview or save a pin', async () => {
  const host = 'bare.example', port = 22;
  const h = harness({ replies: {
    '/api/v1/browser-ssh/target-host-key': { protocol: 1, scope: 'entered_target',
      host, port, key_type: 'ssh-ed25519', fingerprint: FINGERPRINT,
      reverify_required: true },
    '/api/v1/browser-ssh/target-status': { protocol: 1, scope: 'entered_target',
      host, port, host_key_fingerprint: FINGERPRINT, kind: 'missing' },
  } });
  h.element('amneziaSetupScopeLocal').checked = false;
  h.element('amneziaSetupScopeRemote').checked = true;
  h.context.amneziaSetupReset();
  h.element('amneziaSetupRemoteHost').value = host;
  h.element('amneziaSetupRemotePort').value = String(port);
  await h.context.amneziaSetupInspect();
  h.element('amneziaSetupTrust').checked = true;
  h.element('amneziaSetupUsername').value = 'root';
  h.element('amneziaSetupPassword').value = 'temporary-remote-password';
  await h.context.amneziaSetupPreview({ preventDefault() {} });
  assert.deepEqual(h.calls.map(({ path }) => path.split('/').at(-1)), ['target-host-key', 'target-status']);
  assert.equal(h.element('amneziaSetupResult').hidden, true);
  assert.equal(h.storage.size, 0);
  assert.equal(h.element('amneziaSetupPassword').value, '');
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

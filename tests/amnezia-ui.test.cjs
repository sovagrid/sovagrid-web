/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const { webcrypto, randomUUID } = require('node:crypto');

const response = (status, payload) => ({ ok: status >= 200 && status < 300, status,
  text: async () => JSON.stringify(payload) });
const control = (source_status = 'ok') => ({ source_status, target: 'awg2', observed_at: Date.now() / 1000,
  enrolled: source_status === 'ok', recovery_required: false,
  owned_clients: source_status === 'ok' ? ['first-phone'] : [] });
const settingsPreview = () => ({
  target: 'awg2', container_id: 'a'.repeat(64), image_id: `sha256:${'b'.repeat(64)}`,
  config_sha256: 'c'.repeat(64), table_sha256: 'd'.repeat(64), generation: 2,
  protocol: 'amneziawg', interface: 'awg0', listen_port: 49289,
  server_address: '10.44.0.1', server_subnet: '10.44.0.0/24',
  configured_clients: 3, managed_clients: 1, external_clients: 2,
  awg_parameters: { Jc: '4', Jmin: '10', Jmax: '50', S1: '24', S2: '24', S3: '24', S4: '24',
    H1: '1', H2: '2', H3: '3', H4: '4' },
  awg_parameters_runtime_verified: false, header_protection_key_present: true,
  awg3_required_parameters_present: true, apply_supported: false,
  apply_blockers: ['CLIENT_PROFILES_REQUIRE_REISSUE', 'PORT_REQUIRES_CONTAINER_NETWORK_MIGRATION'],
});
const settingsPlan = (patch = { Jc: '5' }) => {
  const preview = settingsPreview();
  return { target: 'awg2', container_id: preview.container_id, image_id: preview.image_id,
    generation: preview.generation, config_sha256: preview.config_sha256,
    table_sha256: preview.table_sha256, proposed_config_sha256: 'e'.repeat(64),
    current_awg_parameters: preview.awg_parameters,
    proposed_awg_parameters: { ...preview.awg_parameters, ...patch },
    changed_fields: Object.keys(patch).sort(), configured_clients: preview.configured_clients,
    apply_supported: false,
    apply_blockers: ['CLIENT_PROFILES_REQUIRE_REISSUE'] };
};
const emptySettingsPreview = () => ({ ...settingsPreview(), configured_clients: 0,
  managed_clients: 0, external_clients: 0 });
const emptySettingsPlan = () => ({ ...settingsPlan(), configured_clients: 0,
  apply_supported: true, apply_blockers: [] });
const settingsIntent = () => ({ target: 'awg2', action: 'settings_intent',
  confirmation_id: Buffer.alloc(32, 7).toString('base64url'),
  expires_at: Math.floor(Date.now() / 1000) + 300,
  generation: 2, config_sha256: 'c'.repeat(64), proposed_config_sha256: 'e'.repeat(64),
  changed_fields: ['Jc'], configured_clients: 0 });

async function readyEmptySettingsFlow({ refreshPreview = true } = {}) {
  const h = harness(), posts = [], jobs = new Map();
  const outputs = { 'settings-preview': emptySettingsPreview(),
    'settings-plan': emptySettingsPlan(), 'settings-intent': settingsIntent(),
    'settings-apply': { target: 'awg2', action: 'settings_updated',
      generation: 3, config_sha256: 'e'.repeat(64), cleanup_required: false } };
  const http = (url, options = {}) => {
    if (url.endsWith('/amnezia/control')) return Promise.resolve(response(200, { control: control() }));
    if (options.method === 'POST') {
      const payload = JSON.parse(options.body), id = `job-${posts.length + 1}`;
      posts.push({ payload, key: options.headers['Idempotency-Key'] });
      jobs.set(id, payload.action);
      if (payload.action === 'settings-apply' && refreshPreview) outputs['settings-preview'] = {
        ...emptySettingsPreview(), generation: 3, config_sha256: 'e'.repeat(64) };
      return Promise.resolve(response(201, { job: { id, server_id: 'server-A', state: 'queued' } }));
    }
    const id = url.split('/').pop(), action = jobs.get(id);
    assert.ok(action, `unexpected job ${id}`);
    return Promise.resolve(response(200, { job: { id, server_id: 'server-A',
      state: 'succeeded', exit_code: 0, output: JSON.stringify(outputs[action]) } }));
  };
  h.setFetchHook(http);
  h.context.renderVpnControls();
  await until(() => h.amnezia.control?.source_status === 'ok');
  await h.context.amneziaSettingsPreview();
  await until(() => h.amnezia.settingsPreview?.configured_clients === 0);
  h.element('amneziaPlanJc').value = '5';
  await h.context.amneziaPlanSubmit({ preventDefault() {} });
  await until(() => h.amnezia.settingsPlan?.apply_supported === true);
  return { h, posts, jobs, outputs, http };
}

function harness() {
  const elements = new Map(), downloads = [], files = [], storageWrites = [];
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { textContent: '', value: '', hidden: false, disabled: false,
        open: false, children: [], listeners, className: '',
        addEventListener(name, fn) { listeners.set(name, fn); },
        setAttribute() {}, append(...nodes) { this.children.push(...nodes); },
        replaceChildren() { this.children = []; this.textContent = ''; },
        showModal() { this.open = true; },
        close() { this.open = false; listeners.get('close')?.({}); },
        click() { downloads.push({ url: this.href, filename: this.download }); }, remove() {},
      });
    }
    return elements.get(id);
  };
  class TestUrl extends URL {
    static createObjectURL(file) { files.push(file); return `blob:profile-${files.length}`; }
    static revokeObjectURL() {}
  }
  let fetchHook = () => { throw new Error('unexpected request'); };
  const context = vm.createContext({
    URL: TestUrl, AbortController, TextEncoder, TextDecoder, Uint8Array, File, btoa, atob,
    crypto: { randomUUID, subtle: webcrypto.subtle }, isSecureContext: true,
    setTimeout: (fn, ms) => ms === 60000 ? 0 : setTimeout(fn, ms), clearTimeout,
    setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, createElement: () => element(Symbol()),
      querySelectorAll: () => [], addEventListener() {}, body: { append() {} } },
    navigator: { canShare: () => false },
    localStorage: { getItem: () => null, setItem(key, value) { storageWrites.push([key, value]); }, removeItem() {} },
    location: { protocol: 'file:' }, fetch: (...args) => fetchHook(...args),
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('amnezia.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  const amnezia = vm.runInContext('amneziaClient', context);
  state.base = 'https://hub.example'; state.token = 'session-A'; state.view = 'vpn';
  state.servers = [{ id: 'server-A', name: 'Server A', online: true, remote_commands_enabled: true },
    { id: 'server-B', name: 'Server B', online: true, remote_commands_enabled: true }];
  state.selectedId = 'server-A';
  return { context, state, amnezia, element, elements, downloads, files, storageWrites,
    setFetchHook: (fn) => { fetchHook = fn; } };
}

async function until(predicate) {
  const deadline = performance.now() + 5000;
  while (performance.now() < deadline) {
    if (predicate()) return;
    // WebCrypto runs on a worker pool. A fixed count of event-loop turns
    // can expire before that worker runs on a shared Linux CI runner.
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.fail('UI did not reach expected state');
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

async function envelope(recipient, text, target = 'awg2') {
  const publicKey = await webcrypto.subtle.importKey('raw', Buffer.from(recipient, 'base64url'),
    { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ephemeral = await webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const secret = await webcrypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, ephemeral.privateKey, 256);
  const material = await webcrypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const nonce = webcrypto.getRandomValues(new Uint8Array(12));
  const key = await webcrypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt,
    info: new TextEncoder().encode('SovaGrid sealed WireGuard profile v1') }, material,
  { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ciphertext = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce,
    additionalData: new TextEncoder().encode(`SovaGrid profile\0${target}\0phone_1`), tagLength: 128 },
  key, new TextEncoder().encode(text));
  return { version: 1,
    ephemeral_public_key: Buffer.from(await webcrypto.subtle.exportKey('raw', ephemeral.publicKey)).toString('base64url'),
    salt: Buffer.from(salt).toString('base64url'), nonce: Buffer.from(nonce).toString('base64url'),
    ciphertext: Buffer.from(ciphertext).toString('base64url') };
}

test('dormant broker disables mutations while exact status check remains available', async () => {
  const h = harness();
  const posts = [];
  h.setFetchHook((url, options) => {
    if (url.endsWith('/amnezia/control')) return Promise.resolve(response(200, { control: control('unavailable') }));
    if (options.method === 'POST') {
      posts.push({ url, options });
      return Promise.resolve(response(201, { job: { id: 'status-job', server_id: 'server-A', state: 'queued' } }));
    }
    return Promise.resolve(response(200, { job: { id: 'status-job', server_id: 'server-A', state: 'failed' } }));
  });
  h.context.renderVpnControls();
  await until(() => h.amnezia.control?.source_status === 'unavailable');
  assert.equal(h.element('amneziaAddButton').disabled, true);
  assert.equal(h.element('amneziaExportButton').disabled, true);
  assert.equal(h.element('amneziaRevokeButton').disabled, true);
  assert.equal(h.element('amneziaSettingsPreview').disabled, true);
  assert.equal(h.element('amneziaCheck').disabled, false);
  await h.context.amneziaCheck();
  await until(() => h.amnezia.job?.state === 'failed');
  assert.equal(posts.length, 1);
  assert.equal(posts[0].url, 'https://hub.example/api/v1/servers/server-A/amnezia/actions');
  assert.deepEqual(JSON.parse(posts[0].options.body), { action: 'status', target: 'awg2' });
  assert.match(posts[0].options.headers['Idempotency-Key'], /^[0-9a-f-]{36}$/);
});

test('settings preview shows bounded server values and keeps digests in technical details', async () => {
  const h = harness();
  const posts = [];
  h.setFetchHook((url, options = {}) => {
    if (url.endsWith('/amnezia/control')) return Promise.resolve(response(200, { control: control() }));
    if (options.method === 'POST') {
      posts.push(JSON.parse(options.body));
      return Promise.resolve(response(201, { job: { id: 'preview-job', server_id: 'server-A', state: 'queued' } }));
    }
    return Promise.resolve(response(200, { job: { id: 'preview-job', server_id: 'server-A',
      state: 'succeeded', exit_code: 0, output: JSON.stringify(settingsPreview()) } }));
  });
  h.context.renderVpnControls();
  await until(() => h.amnezia.control?.source_status === 'ok');
  assert.equal(h.element('amneziaSettingsPreview').disabled, false);
  await h.context.amneziaSettingsPreview();
  await until(() => h.amnezia.settingsPreview?.listen_port === 49289);
  assert.deepEqual(posts, [{ action: 'settings-preview', target: 'awg2' }]);
  assert.equal(h.element('amneziaSettingsCard').hidden, false);
  assert.match(h.element('amneziaSettingsValues').textContent, /Порт: 49289\/UDP/);
  assert.match(h.element('amneziaSettingsValues').textContent, /Клиенты: 3 всего · 1 SovaGrid · 2 внешних/);
  assert.match(h.element('amneziaSettingsValues').textContent, /Jc=4/);
  assert.doesNotMatch(h.element('amneziaSettingsValues').textContent, /sha256|PrivateKey/);
  assert.match(h.element('amneziaSettingsDigests').textContent, /SHA-256 конфигурации: c{64}/);
  assert.match(h.element('amneziaSettingsState').textContent, /только для просмотра.*перевыпуска/);
  h.element('amneziaTarget').value = 'wireguard';
  h.context.amneziaTargetChanged();
  assert.equal(h.amnezia.settingsPreview, null);
  assert.equal(h.element('amneziaSettingsCard').hidden, true);
});

test('settings preview rejects secret, malformed, and oversized job output', async () => {
  const h = harness();
  let output = JSON.stringify({ ...settingsPreview(), private_key: 'secret' });
  let number = 0;
  h.setFetchHook((url, options = {}) => {
    if (url.endsWith('/amnezia/control')) return Promise.resolve(response(200, { control: control() }));
    if (options.method === 'POST') {
      number++;
      return Promise.resolve(response(201, { job: { id: `preview-${number}`, server_id: 'server-A', state: 'queued' } }));
    }
    return Promise.resolve(response(200, { job: { id: `preview-${number}`, server_id: 'server-A',
      state: 'succeeded', exit_code: 0, output } }));
  });
  h.context.renderVpnControls();
  await until(() => h.amnezia.control?.source_status === 'ok');
  for (const invalid of [output, 'PrivateKey = secret',
    JSON.stringify({ ...settingsPreview(), server_subnet: '10.45.0.0/24' }),
    JSON.stringify(settingsPreview()) + ' '.repeat(4096)]) {
    output = invalid;
    await h.context.amneziaSettingsPreview();
    await until(() => h.amnezia.job?.state === 'succeeded' && h.amnezia.settingsPreviewError);
    assert.equal(h.amnezia.settingsPreview, null);
    assert.doesNotMatch(h.element('amneziaSettingsCard').textContent +
      h.element('amneziaSettingsState').textContent + h.element('amneziaSettingsValues').textContent,
    /PrivateKey|secret/);
    assert.equal(h.element('amneziaSettingsDetails').hidden, true);
  }
});

test('AWG3 proposal sends only changed fields with snapshot CAS and shows read-only plan', async () => {
  const h = harness();
  const posts = [];
  h.setFetchHook((url, options = {}) => {
    if (url.endsWith('/amnezia/control')) return Promise.resolve(response(200, { control: control() }));
    if (options.method === 'POST') {
      const payload = JSON.parse(options.body);
      posts.push({ payload, key: options.headers['Idempotency-Key'] });
      return Promise.resolve(response(201, { job: { id: payload.action, server_id: 'server-A', state: 'queued' } }));
    }
    const plan = url.endsWith('/jobs/settings-plan');
    return Promise.resolve(response(200, { job: { id: plan ? 'settings-plan' : 'settings-preview',
      server_id: 'server-A', state: 'succeeded', exit_code: 0,
      output: JSON.stringify(plan ? settingsPlan() : settingsPreview()) } }));
  });
  h.context.renderVpnControls();
  await until(() => h.amnezia.control?.source_status === 'ok');
  assert.equal(h.element('amneziaPlanSection').hidden, true);
  await h.context.amneziaSettingsPreview();
  await until(() => h.amnezia.settingsPreview?.target === 'awg2');
  assert.equal(h.element('amneziaPlanSection').hidden, false);
  assert.equal(h.element('amneziaPlanJc').value, '4');
  assert.equal(h.element('amneziaPlanH4').value, '4');
  h.element('amneziaPlanJc').value = '5';
  await h.context.amneziaPlanSubmit({ preventDefault() {} });
  await until(() => h.amnezia.settingsPlan?.proposed_awg_parameters?.Jc === '5');
  assert.equal(posts.length, 2);
  assert.deepEqual(posts[1].payload, { action: 'settings-plan', target: 'awg2',
    expected_config_sha256: 'c'.repeat(64), expected_generation: 2, parameters: { Jc: '5' } });
  assert.match(posts[1].key, /^[0-9a-f-]{36}$/);
  assert.equal(h.element('amneziaPlanResult').hidden, false);
  assert.match(h.element('amneziaPlanSummary').textContent, /Изменятся: Jc: 4 → 5.*не изменены/);
  assert.match(h.element('amneziaPlanBlockers').textContent, /Применение недоступно.*профили/);
  assert.doesNotMatch(h.element('amneziaPlanSummary').textContent, /PrivateKey|HeaderProtectionKey/);
  assert.equal(h.element('amneziaPlanPrepareApply').hidden, true);
  h.element('amneziaPlanH1').value = '10';
  h.element('amneziaPlanH1').listeners.get('input')({});
  assert.equal(h.amnezia.settingsPlan, null, 'an edited input invalidates the computed plan');
  assert.equal(h.amnezia.planRequest, null);
  assert.equal(h.element('amneziaPlanResult').hidden, true);
  h.element('amneziaTarget').value = 'wireguard';
  h.context.amneziaTargetChanged();
  assert.equal(h.element('amneziaPlanSection').hidden, true);
  assert.equal(h.amnezia.settingsPlan, null);
});

test('AWG3 proposal rejects invalid values and untrusted plan output', async () => {
  const h = harness();
  let planOutput = JSON.stringify({ ...settingsPlan(), private_key: 'secret' });
  let jobs = 0;
  const posts = [];
  h.setFetchHook((url, options = {}) => {
    if (url.endsWith('/amnezia/control')) return Promise.resolve(response(200, { control: control() }));
    if (options.method === 'POST') {
      const payload = JSON.parse(options.body);
      posts.push(payload);
      return Promise.resolve(response(201, { job: { id: payload.action === 'settings-plan'
        ? `plan-${++jobs}` : 'preview', server_id: 'server-A', state: 'queued' } }));
    }
    const plan = url.includes('/jobs/plan-');
    return Promise.resolve(response(200, { job: { id: plan ? `plan-${jobs}` : 'preview',
      server_id: 'server-A', state: 'succeeded', exit_code: 0,
      output: plan ? planOutput : JSON.stringify(settingsPreview()) } }));
  });
  h.context.renderVpnControls();
  await until(() => h.amnezia.control?.source_status === 'ok');
  await h.context.amneziaSettingsPreview();
  await until(() => h.amnezia.settingsPreview?.target === 'awg2');
  for (const [name, value] of [['S1', '11'], ['Jc', '01'], ['Jmin', '99'], ['H1', '20-1']]) {
    h.context.amneziaPlanReset();
    h.element('amneziaPlan' + name).value = value;
    await h.context.amneziaPlanSubmit({ preventDefault() {} });
    assert.equal(posts.length, 1);
    assert.equal(h.element('amneziaPlanError').hidden, false);
  }
  h.context.amneziaPlanReset();
  h.element('amneziaPlanJc').value = '5';
  for (const invalid of [planOutput,
    JSON.stringify({ ...settingsPlan(), apply_supported: true }),
    JSON.stringify({ ...settingsPlan(), changed_fields: ['S1'] }),
    JSON.stringify({ ...settingsPlan(), config_sha256: 'f'.repeat(64) })]) {
    planOutput = invalid;
    await h.context.amneziaPlanSubmit({ preventDefault() {} });
    await until(() => h.amnezia.jobId === `plan-${jobs}` && h.amnezia.job?.state === 'succeeded' &&
      h.amnezia.settingsPlanError);
    assert.equal(h.amnezia.settingsPlan, null);
    assert.equal(h.element('amneziaPlanResult').hidden, true);
    assert.doesNotMatch(h.element('amneziaPlanError').textContent, /secret|PrivateKey/);
  }
});

test('lost AWG3 plan reply retries exact payload and key, then ignores an old server response', async () => {
  const h = harness();
  const sent = [], late = deferred();
  let loseFirst = true;
  h.setFetchHook((url, options = {}) => {
    if (url.endsWith('/amnezia/control')) return Promise.resolve(response(200, { control: control() }));
    if (options.method === 'POST') {
      const payload = JSON.parse(options.body);
      if (payload.action === 'settings-preview')
        return Promise.resolve(response(201, { job: { id: 'preview', server_id: 'server-A', state: 'queued' } }));
      sent.push({ key: options.headers['Idempotency-Key'], body: options.body });
      if (loseFirst) { loseFirst = false; return Promise.reject(new TypeError('lost response')); }
      return late.promise;
    }
    return Promise.resolve(response(200, { job: { id: 'preview', server_id: 'server-A',
      state: 'succeeded', exit_code: 0, output: JSON.stringify(settingsPreview()) } }));
  });
  h.context.renderVpnControls();
  await until(() => h.amnezia.control?.source_status === 'ok');
  await h.context.amneziaSettingsPreview();
  await until(() => h.amnezia.settingsPreview?.target === 'awg2');
  h.element('amneziaPlanJc').value = '5';
  await h.context.amneziaPlanSubmit({ preventDefault() {} });
  assert.equal(h.amnezia.planPending?.payload.action, 'settings-plan');
  assert.equal(h.element('amneziaPlanJc').disabled, true);
  assert.match(h.element('amneziaPlanError').textContent, /Ответ потерян/);
  h.element('amneziaPlanJc').listeners.get('input')({});
  assert.equal(h.amnezia.planPending?.payload.action, 'settings-plan', 'disabled input cannot replace retry state');
  const retry = h.context.amneziaPlanSubmit({ preventDefault() {} });
  await until(() => sent.length === 2);
  assert.equal(sent[0].key, sent[1].key);
  assert.equal(sent[0].body, sent[1].body);
  h.state.vpnTargetId = 'server-B';
  h.context.amneziaTargetChanged();
  late.resolve(response(201, { job: { id: 'old-plan', server_id: 'server-A', state: 'queued' } }));
  await retry;
  assert.equal(h.amnezia.settingsPlan, null);
  assert.equal(h.amnezia.planPending, null);
  assert.equal(h.element('amneziaPlanSection').hidden, true);
});

test('zero-client AWG3 apply requires intent result and explicit confirmation', async () => {
  const { h, posts, outputs } = await readyEmptySettingsFlow();
  assert.equal(h.element('amneziaPlanPrepareApply').hidden, false);
  assert.equal(h.element('amneziaPlanPrepareApply').disabled, false);
  assert.match(h.element('amneziaPlanBlockers').textContent, /Изменение AWG3.*Connect/);
  await h.context.amneziaPrepareSettingsApply();
  await until(() => h.amnezia.pending?.kind === 'settings-apply');
  assert.deepEqual(posts.map((post) => post.payload.action),
    ['settings-preview', 'settings-plan', 'settings-intent']);
  assert.deepEqual(posts[2].payload, { action: 'settings-intent', target: 'awg2',
    expected_config_sha256: 'c'.repeat(64), expected_generation: 2,
    expected_proposed_config_sha256: 'e'.repeat(64), parameters: { Jc: '5' } });
  assert.equal(h.element('amneziaDialog').open, true);
  assert.match(h.element('amneziaDialogServer').textContent, /Server A/);
  assert.match(h.element('amneziaDialogSummary').textContent, /Jc: 4 → 5.*Клиентов: 0/);
  assert.equal(h.element('amneziaDialogConfirm').textContent, 'Применить настройки');
  const handle = outputs['settings-intent'].confirmation_id;
  assert.equal(handle.length, 43);
  assert.equal(h.amnezia.job.output, '', 'intent output must not be retained as job state');
  assert.ok([...h.elements.values()].every((node) => !String(node.textContent).includes(handle)),
    'one-time handle must not be rendered');
  assert.ok(h.storageWrites.every((entry) => !JSON.stringify(entry).includes(handle)),
    'one-time handle must not enter localStorage');
  await h.context.amneziaConfirm();
  await until(() => h.amnezia.settingsApplyOutcome === 'applied' &&
    h.amnezia.settingsPreview?.config_sha256 === 'e'.repeat(64));
  assert.deepEqual(posts.map((post) => post.payload.action),
    ['settings-preview', 'settings-plan', 'settings-intent', 'settings-apply', 'settings-preview']);
  assert.deepEqual(posts[3].payload, { action: 'settings-apply', target: 'awg2',
    expected_config_sha256: 'c'.repeat(64), expected_generation: 2,
    expected_proposed_config_sha256: 'e'.repeat(64), parameters: { Jc: '5' },
    confirmation_id: handle });
  assert.equal(h.amnezia.pending, null);
  assert.equal(h.amnezia.intentRequest, null);
  assert.equal(h.amnezia.applyRequest, null);
  assert.equal(h.amnezia.intentExpiryTimer, null);
  assert.match(h.element('amneziaSettingsState').textContent, /Для изменения числовых параметров AWG3/);
});

test('AWG3 apply rejects stale plan, wrong intent result, and non-admin role', async () => {
  const stale = await readyEmptySettingsFlow();
  stale.h.element('amneziaPlanJc').value = '6';
  stale.h.element('amneziaPlanJc').listeners.get('input')({});
  await stale.h.context.amneziaPrepareSettingsApply();
  assert.equal(stale.h.amnezia.settingsPlan, null);
  assert.equal(stale.posts.length, 2);
  const role = await readyEmptySettingsFlow();
  role.h.state.user = { id: 'viewer', username: 'viewer', role: 'viewer', legacy: false };
  role.h.state.access = { mode: 'all', revision: 1, unrestricted_admin: false };
  role.h.context.renderAmneziaControl();
  assert.equal(role.h.element('amneziaPlanPrepareApply').disabled, true);
  await role.h.context.amneziaPrepareSettingsApply();
  assert.equal(role.posts.length, 2);
  for (const invalid of [
    { confirmation_id: '!'.repeat(43) },
    { config_sha256: 'f'.repeat(64) },
    { changed_fields: ['S1'] },
  ]) {
    const flow = await readyEmptySettingsFlow();
    flow.outputs['settings-intent'] = { ...settingsIntent(), ...invalid };
    await flow.h.context.amneziaPrepareSettingsApply();
    await until(() => flow.h.amnezia.jobAction === 'settings-intent' &&
      flow.h.amnezia.job?.state === 'succeeded' && !flow.h.amnezia.intentRequest);
    assert.equal(flow.h.amnezia.pending, null);
    assert.equal(flow.h.element('amneziaDialog').open, false);
    assert.match(flow.h.element('amneziaPlanError').textContent, /не прошло проверку/);
    assert.equal(flow.posts.length, 3);
  }
});

test('AWG3 handle is cleared on cancellation, expiry, target/server change, and logout', async () => {
  for (const action of ['cancel', 'expiry', 'target', 'server', 'logout']) {
    const { h, posts } = await readyEmptySettingsFlow();
    await h.context.amneziaPrepareSettingsApply();
    await until(() => h.amnezia.pending?.kind === 'settings-apply');
    if (action === 'cancel') h.element('amneziaDialogCancel').listeners.get('click')({});
    if (action === 'expiry') {
      h.amnezia.pending.receivedAt = Date.now() - 240001;
      await h.context.amneziaConfirm();
      assert.match(h.element('amneziaPlanError').textContent, /истекло/);
    }
    if (action === 'target') {
      h.element('amneziaTarget').value = 'wireguard';
      h.context.amneziaTargetChanged();
    }
    if (action === 'server') {
      h.state.vpnTargetId = 'server-B';
      h.context.amneziaTargetChanged();
    }
    if (action === 'logout') h.context.amneziaReset();
    assert.equal(h.amnezia.pending, null, action);
    assert.equal(h.amnezia.intentRequest, null, action);
    assert.equal(h.amnezia.intentExpiryTimer, null, action);
    assert.ok(!JSON.stringify(h.amnezia).includes(settingsIntent().confirmation_id),
      'intent handle must not survive in client state');
    assert.equal(h.element('amneziaDialog').open, false, action);
    assert.equal(posts.length, 3, action);
  }
});

test('AWG3 apply treats mismatched result as unknown and does not retry', async () => {
  const { h, posts, outputs } = await readyEmptySettingsFlow();
  outputs['settings-apply'] = { ...outputs['settings-apply'], config_sha256: 'f'.repeat(64) };
  await h.context.amneziaPrepareSettingsApply();
  await until(() => h.amnezia.pending?.kind === 'settings-apply');
  await h.context.amneziaConfirm();
  await until(() => h.amnezia.settingsApplyOutcome === 'uncertain' &&
    h.amnezia.settingsPreview?.generation === 3);
  assert.equal(posts.filter((post) => post.payload.action === 'settings-apply').length, 1);
  assert.match(h.element('amneziaSettingsState').textContent, /Состояние изменения неизвестно/);
  assert.doesNotMatch(h.element('amneziaProfileStatus').textContent, /Настройки AWG3 применены/);
});

test('AWG3 apply treats a stale refreshed snapshot as unknown', async () => {
  const { h, posts } = await readyEmptySettingsFlow({ refreshPreview: false });
  await h.context.amneziaPrepareSettingsApply();
  await until(() => h.amnezia.pending?.kind === 'settings-apply');
  await h.context.amneziaConfirm();
  await until(() => h.amnezia.settingsApplyOutcome === 'uncertain' &&
    h.amnezia.jobAction === 'settings-preview' && h.amnezia.job?.state === 'succeeded');
  assert.equal(posts.filter((post) => post.payload.action === 'settings-apply').length, 1);
  assert.match(h.element('amneziaSettingsState').textContent, /Состояние изменения неизвестно/);
  assert.doesNotMatch(h.element('amneziaProfileStatus').textContent, /Настройки AWG3 применены/);
});

test('lost AWG3 apply POST clears the handle and never automatically repeats', async () => {
  const { h, posts, http } = await readyEmptySettingsFlow();
  await h.context.amneziaPrepareSettingsApply();
  await until(() => h.amnezia.pending?.kind === 'settings-apply');
  h.setFetchHook((url, options = {}) => {
    if (options.method === 'POST' && JSON.parse(options.body).action === 'settings-apply') {
      posts.push({ payload: JSON.parse(options.body), key: options.headers['Idempotency-Key'] });
      return Promise.reject(new TypeError('lost apply response'));
    }
    return http(url, options);
  });
  await h.context.amneziaConfirm();
  assert.equal(h.amnezia.settingsApplyOutcome, 'uncertain');
  assert.equal(h.amnezia.pending, null);
  assert.equal(h.amnezia.intentExpiryTimer, null);
  assert.equal(h.element('amneziaDialog').open, false);
  assert.equal(posts.filter((post) => post.payload.action === 'settings-apply').length, 1);
  assert.match(h.element('amneziaError').textContent, /Состояние изменения неизвестно/);
  await h.context.amneziaConfirm();
  assert.equal(posts.filter((post) => post.payload.action === 'settings-apply').length, 1);
});

test('add-profile confirms exact target, decrypts nested AWG3 envelope, downloads only on click', async () => {
  const h = harness();
  h.setFetchHook((url) => {
    assert.ok(url.endsWith('/amnezia/control'));
    return Promise.resolve(response(200, { control: control() }));
  });
  h.context.renderVpnControls();
  await until(() => h.amnezia.control?.source_status === 'ok');
  h.element('amneziaAddClient').value = 'phone_1';
  h.element('amneziaAddAddressMode').value = 'manual';
  h.context.amneziaAddAddressModeChange();
  h.element('amneziaAddAddress').value = '10.0.0.42';
  h.element('amneziaAddEndpoint').value = 'vpn.example.org';
  h.element('amneziaAddRoute').value = 'split';
  h.context.amneziaAdd({ preventDefault() {} });
  await until(() => h.element('amneziaDialog').open);
  const pending = h.amnezia.pending;
  assert.deepEqual(Object.keys(pending.payload).sort(),
    ['action', 'address', 'client', 'endpoint_host', 'public_key', 'route', 'target']);
  assert.equal(pending.privateKey.extractable, false);
  assert.equal(pending.payload.target, 'awg2');
  assert.equal(pending.payload.address, '10.0.0.42');
  assert.equal(h.downloads.length, 0);
  const text = '[Interface]\nPrivateKey = CLIENT_SECRET\n[Peer]\nPublicKey = SERVER_PUBLIC\n';
  const sealed = await envelope(pending.payload.public_key, text);
  const posts = [];
  h.setFetchHook((url, options) => {
    if (url.endsWith('/amnezia/control')) return Promise.resolve(response(200, { control: control() }));
    if (options.method === 'POST') {
      posts.push({ url, options });
      return Promise.resolve(response(201, { job: { id: 'add-job', server_id: 'server-A', state: 'queued' } }));
    }
    return Promise.resolve(response(200, { job: { id: 'add-job', server_id: 'server-A', state: 'succeeded',
      output: JSON.stringify({ target: 'awg2', action: 'added', client: 'phone_1',
        profile_format: 'awg3-conf', configured_clients: 2, cleanup_required: false,
        sealed_profile: sealed }) } }));
  });
  await h.context.amneziaConfirm();
  await until(() => h.amnezia.profile?.status === 'ready');
  assert.equal(posts.length, 1);
  assert.equal(posts[0].options.body, JSON.stringify(pending.payload));
  assert.equal(posts[0].options.headers['Idempotency-Key'], pending.key);
  assert.equal(h.downloads.length, 0);
  assert.equal(h.amnezia.profile.privateKey, null);
  assert.doesNotMatch(h.element('amneziaJobPanel').textContent + h.element('amneziaProfileStatus').textContent,
    /CLIENT_SECRET|ciphertext|PrivateKey/);
  const nativeMessages = [];
  h.context.location = new URL('http://127.0.0.1:8766');
  h.context.sovagridNativeProfile = { postMessage(value) { nativeMessages.push(value); } };
  await h.context.amneziaDownload();
  assert.equal(h.downloads.length, 0, 'native app receives bytes instead of a blob navigation');
  assert.equal(nativeMessages.length, 1);
  assert.equal(JSON.parse(nativeMessages[0]).filename, 'amnezia-awg2-phone_1.conf');
  assert.equal(Buffer.from(JSON.parse(nativeMessages[0]).data, 'base64url').toString(), text);
  h.context.location = { protocol: 'file:' };
  await h.context.amneziaDownload();
  assert.equal(h.downloads.length, 1);
  assert.equal(h.downloads[0].filename, 'amnezia-awg2-phone_1.conf');
  assert.equal(await h.files[0].text(), text);
  h.setFetchHook((url, options) => {
    if (url.endsWith('/amnezia/control')) return Promise.resolve(response(200, { control: control() }));
    if (options.method === 'POST') return Promise.resolve(response(201,
      { job: { id: 'check-job', server_id: 'server-A', state: 'queued' } }));
    return Promise.resolve(response(200, { job: { id: 'check-job', server_id: 'server-A', state: 'succeeded',
      output: JSON.stringify({ target: 'awg2', enrolled: true, recovery_required: false,
        owned_clients: ['first-phone', 'phone_1'] }) } }));
  });
  await h.context.amneziaCheck();
  await until(() => h.amnezia.job?.state === 'succeeded' && h.amnezia.jobId === 'check-job');
  assert.equal(h.amnezia.profile.status, 'ready', 'status refresh must not discard a prepared profile');
  await h.context.amneziaDownload();
  assert.equal(h.downloads.length, 2);
});

test('revoke requires exact typed name and rejects a changed server', async () => {
  const h = harness();
  const posts = [];
  h.setFetchHook((url, options) => {
    if (url.endsWith('/amnezia/control')) return Promise.resolve(response(200, { control: control() }));
    if (options.method === 'POST') posts.push(options);
    return Promise.resolve(response(200, {}));
  });
  h.context.renderVpnControls();
  await until(() => h.amnezia.control?.source_status === 'ok');
  h.element('amneziaRevokeClient').value = 'first-phone';
  h.context.amneziaRevoke({ preventDefault() {} });
  assert.equal(h.element('amneziaDialogConfirm').disabled, true);
  h.element('amneziaRevokeName').value = 'wrong';
  await h.context.amneziaConfirm();
  assert.equal(posts.length, 0);
  h.element('amneziaRevokeName').value = 'first-phone';
  h.state.vpnTargetId = 'server-B';
  await h.context.amneziaConfirm();
  assert.equal(posts.length, 0);
  assert.match(h.element('amneziaDialogError').textContent, /Сервер/);
});

test('late old status response cannot re-enable Amnezia mutations', async () => {
  const h = harness();
  const old = deferred();
  let loads = 0;
  h.setFetchHook((url) => {
    assert.ok(url.endsWith('/amnezia/control'));
    loads++;
    return loads === 1 ? old.promise : Promise.resolve(response(200, { control: control('unavailable') }));
  });
  h.context.renderVpnControls();
  await h.context.amneziaLoadControl();
  old.resolve(response(200, { control: control() }));
  await until(() => h.amnezia.control?.source_status === 'unavailable');
  assert.equal(h.element('amneziaAddButton').disabled, true);
});

test('uncertain POST retains the same Amnezia payload and idempotency key', async () => {
  const h = harness();
  h.setFetchHook((url) => {
    assert.ok(url.endsWith('/amnezia/control'));
    return Promise.resolve(response(200, { control: control() }));
  });
  h.context.renderVpnControls();
  await until(() => h.amnezia.control?.source_status === 'ok');
  h.element('amneziaRevokeClient').value = 'first-phone';
  h.context.amneziaRevoke({ preventDefault() {} });
  h.element('amneziaRevokeName').value = 'first-phone';
  const sent = [];
  h.setFetchHook((_url, options) => {
    if (options.method === 'POST') {
      sent.push({ key: options.headers['Idempotency-Key'], body: options.body });
      return sent.length === 1 ? Promise.reject(new TypeError('lost response')) :
        Promise.resolve(response(200, { job: { id: 'revoke-job', server_id: 'server-A', state: 'succeeded' } }));
    }
    return Promise.resolve(response(200, { job: { id: 'revoke-job', server_id: 'server-A', state: 'succeeded' } }));
  });
  await h.context.amneziaConfirm();
  assert.equal(h.amnezia.pending.payload.action, 'revoke');
  await h.context.amneziaConfirm();
  assert.equal(sent.length, 2);
  assert.equal(sent[0].key, sent[1].key);
  assert.equal(sent[0].body, sent[1].body);
});

test('Amnezia profile selects a free IPv4 automatically unless manual mode is chosen', async () => {
  const h = harness();
  h.setFetchHook((url) => {
    assert.ok(url.endsWith('/amnezia/control'));
    return Promise.resolve(response(200, { control: control() }));
  });
  h.context.renderVpnControls();
  await until(() => h.amnezia.control?.source_status === 'ok');
  h.element('amneziaAddClient').value = 'phone_auto';
  h.element('amneziaAddEndpoint').value = 'vpn.example.org';
  h.element('amneziaAddRoute').value = 'split';
  assert.equal(h.element('amneziaAddManualAddress').hidden, true);
  assert.equal(h.element('amneziaAddAddress').required, false);
  h.context.amneziaAdd({ preventDefault() {} });
  await until(() => h.element('amneziaDialog').open);
  assert.equal(h.amnezia.pending.payload.address, 'auto');
  assert.match(h.element('amneziaDialogSummary').textContent, /IPv4 автоматически/);
  h.element('amneziaAddAddressMode').value = 'manual';
  h.context.amneziaAddAddressModeChange();
  assert.equal(h.element('amneziaAddManualAddress').hidden, false);
  assert.equal(h.element('amneziaAddAddress').required, true);
});

test('container image includes Amnezia script and service worker caches its version', () => {
  assert.match(fs.readFileSync('Dockerfile', 'utf8'), /COPY index\.html app\.js .*amnezia\.js/);
  assert.match(fs.readFileSync('index.html', 'utf8'), /amnezia\.js\?v=16/);
  assert.match(fs.readFileSync('sw.js', 'utf8'), /amnezia\.js\?v=16/);
});

test('WireGuard container selection binds status, action, and profile AAD to target', async () => {
  const h = harness();
  h.element('amneziaTarget').value = 'wireguard';
  h.setFetchHook((url) => {
    assert.match(url, /amnezia\/control\?target=wireguard$/);
    return Promise.resolve(response(200, { control: { ...control(), target: 'wireguard' } }));
  });
  h.context.renderVpnControls();
  await until(() => h.amnezia.control?.target === 'wireguard');
  h.element('amneziaAddClient').value = 'phone_1';
  h.element('amneziaAddAddressMode').value = 'manual';
  h.context.amneziaAddAddressModeChange();
  h.element('amneziaAddAddress').value = '10.0.0.42';
  h.element('amneziaAddEndpoint').value = 'vpn.example.org';
  h.element('amneziaAddRoute').value = 'full';
  h.context.amneziaAdd({ preventDefault() {} });
  await until(() => h.element('amneziaDialog').open);
  const pending = h.amnezia.pending;
  assert.equal(pending.payload.target, 'wireguard');
  assert.equal(pending.payload.route, 'full');
  const profile = '[Interface]\nPrivateKey = WG_CLIENT\n[Peer]\nPublicKey = WG_SERVER\n';
  const sealed = await envelope(pending.payload.public_key, profile, 'wireguard');
  h.setFetchHook((url, options) => {
    if (url.endsWith('/amnezia/control?target=wireguard'))
      return Promise.resolve(response(200, { control: { ...control(), target: 'wireguard' } }));
    if (options.method === 'POST') return Promise.resolve(response(201,
      { job: { id: 'wg-job', server_id: 'server-A', state: 'queued' } }));
    return Promise.resolve(response(200, { job: { id: 'wg-job', server_id: 'server-A', state: 'succeeded',
      output: JSON.stringify({ target: 'wireguard', action: 'added', client: 'phone_1',
        profile_format: 'wg-conf', configured_clients: 1, cleanup_required: false,
        sealed_profile: sealed }) } }));
  });
  await h.context.amneziaConfirm();
  await until(() => h.amnezia.profile?.status === 'ready');
  assert.equal(h.amnezia.profile.file.name, 'amnezia-wireguard-phone_1.conf');
  assert.equal(await h.amnezia.profile.file.text(), profile);
  h.element('amneziaTarget').value = 'awg2';
  h.context.amneziaTargetChanged();
  assert.equal(h.amnezia.profile, null);
  assert.equal(h.element('amneziaDownload').hidden, true);
});

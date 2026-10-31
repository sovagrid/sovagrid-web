/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ../ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const { createHash, webcrypto } = require('node:crypto');

function hostKey(seed) {
  const type = Buffer.from('ssh-ed25519');
  const raw = Buffer.concat([Buffer.from([0, 0, 0, type.length]), type,
    Buffer.from([0, 0, 0, 32]), Buffer.alloc(32, seed)]);
  return { blob: raw.toString('base64'),
    fingerprint: 'SHA256:' + createHash('sha256').update(raw).digest('base64').replace(/=+$/, '') };
}
const JUMP_KEY = hostKey(1), TARGET_KEY = hostKey(2);
const PIN = JUMP_KEY.fingerprint, TARGET_PIN = TARGET_KEY.fingerprint;

function element(value = '') {
  return { value, textContent: '', hidden: false, disabled: false, checked: false,
    files: [], listeners: {}, addEventListener(type, callback) { this.listeners[type] = callback; } };
}

test('VPN jump panel verifies both keys and one read-only status, then clears input secrets', async () => {
  const nodes = new Map();
  const initial = { vpnJumpHost: 'gateway.example', vpnJumpPort: '22', vpnJumpUser: 'operator',
    vpnJumpMethod: 'password', vpnJumpTargetHost: '127.0.0.1', vpnJumpTargetPort: '22022',
    vpnJumpTargetUser: 'root', vpnJumpTargetMethod: 'password' };
  const get = (id) => {
    if (!nodes.has(id)) nodes.set(id, element(initial[id] ?? ''));
    return nodes.get(id);
  };
  const saved = new Map(), calls = [];
  const context = vm.createContext({
    AbortController, TextEncoder, URL, setTimeout, clearTimeout,
    document: { getElementById: get, addEventListener() {}, hidden: false },
    crypto: webcrypto, atob, btoa,
    serverSetupHostKeyBlobValid: (value) => typeof value === 'string' &&
      value.length >= 12 && value.length <= 10924 && /^[A-Za-z0-9+/]+={0,2}$/.test(value),
    location: { origin: 'https://panel.example' },
    localStorage: { getItem: (key) => saved.get(key) ?? null,
      setItem: (key, value) => saved.set(key, value) },
    state: { token: 't'.repeat(43) },
    amneziaSetupAllowed: () => true,
    fetch: async (path, request) => {
      const body = JSON.parse(request.body);
      calls.push({ path, body });
      if (path.endsWith('/target-host-key') && !body.jump)
        return { ok: true, json: async () => ({ protocol: 1, scope: 'entered_target',
          host: 'gateway.example', port: 22, key_type: 'ssh-ed25519', fingerprint: PIN,
          host_key_blob: JUMP_KEY.blob,
          reverify_required: true }) };
      if (path.endsWith('/target-host-key')) {
        assert.equal(body.jump.password, 'jump-secret');
        return { ok: true, json: async () => ({ protocol: 1, scope: 'entered_target',
          host: '127.0.0.1', port: 22022, key_type: 'ssh-ed25519', fingerprint: TARGET_PIN,
          host_key_blob: TARGET_KEY.blob,
          jump_host: 'gateway.example', jump_port: 22, jump_host_key_fingerprint: PIN,
          reverify_required: true }) };
      }
      assert.equal(path, '/api/v1/browser-ssh/target-status');
      assert.equal(body.jump.password, 'jump-secret');
      assert.equal(body.password, 'target-secret');
      return { ok: true, json: async () => ({ protocol: 1, scope: 'entered_target',
        host: '127.0.0.1', port: 22022, kind: 'agent_only', host_key_fingerprint: TARGET_PIN,
        jump_host: 'gateway.example', jump_port: 22, jump_host_key_fingerprint: PIN }) };
    },
  });
  vm.runInContext(fs.readFileSync('vpn-jump.js', 'utf8'), context);
  await get('vpnJumpInspect').listeners.click();
  assert.equal(get('vpnJumpFingerprint').textContent, PIN);
  assert.equal(get('vpnJumpInspectTarget').disabled, true);
  assert.equal(context.vpnJumpRoutePins({ host: '127.0.0.1', port: 22022 }), null);
  get('vpnJumpTrust').checked = true;
  get('vpnJumpTrust').listeners.change();
  get('vpnJumpPassword').value = 'jump-secret';
  await get('vpnJumpInspectTarget').listeners.click();
  assert.equal(get('vpnJumpTargetFingerprint').textContent, TARGET_PIN);
  assert.equal(get('vpnJumpPassword').value, '');
  assert.equal(context.vpnJumpRoutePins({ host: '127.0.0.1', port: 22022 }), null);
  get('vpnJumpTargetTrust').checked = true;
  get('vpnJumpTargetTrust').listeners.change();
  assert.equal(get('vpnJumpStatus').disabled, false);
  get('vpnJumpPassword').value = 'jump-secret';
  get('vpnJumpTargetPassword').value = 'target-secret';
  await get('vpnJumpStatus').listeners.click();
  assert.match(get('vpnJumpResult').textContent, /Agent отвечает/);
  assert.equal(get('vpnJumpPassword').value, '');
  assert.equal(get('vpnJumpTargetPassword').value, '');
  assert.equal(calls.length, 3);
  assert.equal(saved.size, 2);
  assert.doesNotMatch([...saved].join(' '), /secret/);
  const pins = context.vpnJumpRoutePins({ host: '127.0.0.1', port: 22022 }, TARGET_PIN);
  assert.equal(pins.jump.host_key_blob, JUMP_KEY.blob);
  assert.equal(pins.target.host_key_blob, TARGET_KEY.blob);
  get('vpnJumpPassword').value = 'jump-secret';
  const route = await context.vpnJumpRouteCredentials({ host: '127.0.0.1', port: 22022 }, TARGET_PIN);
  assert.equal(route.jump.password, 'jump-secret');
  assert.equal(route.host_key_blob, TARGET_KEY.blob);
  const state = vm.runInContext('vpnJump', context);
  state.targetKeyBlob = JUMP_KEY.blob;
  await assert.rejects(() => context.vpnJumpRouteCredentials(
    { host: '127.0.0.1', port: 22022 }, TARGET_PIN), /HOST_KEY_CHANGED/);
  state.targetKeyBlob = TARGET_KEY.blob;
  get('vpnJumpPassword').value = 'pending-secret';
  context.vpnJumpReset();
  assert.equal(get('vpnJumpPassword').value, '');
  assert.equal(get('vpnJumpTrust').checked, false);
  assert.equal(get('vpnJumpTargetTrust').checked, false);
  assert.equal(get('vpnJumpStatus').disabled, true);
  get('vpnJumpHost').value = '2001:0db8:0000:0000:0000:0000:0000:0001';
  assert.equal(context.vpnJumpEndpoint('vpnJump').host, '2001:db8::1');
});

/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

function harness({ secure = true, crypto = webcrypto } = {}) {
  const elements = new Map(), clipboard = [], downloads = [], pageEvents = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, { value: '', textContent: '', checked: false, hidden: true,
        disabled: false, files: [], listeners,
        addEventListener(kind, listener) { listeners.set(kind, listener); },
        dispatchEvent(event) { listeners.get(event.type)?.(event); },
        focus() {}, select() {},
      });
    }
    return elements.get(id);
  };
  const context = vm.createContext({
    crypto, btoa, TextEncoder, Uint8Array, Blob,
    isSecureContext: secure, Event: class { constructor(type) { this.type = type; } },
    document: { getElementById: element,
      createElement: () => ({ click() { downloads.push(this.download); }, remove() {} }),
      body: { append() {} } },
    navigator: { clipboard: { writeText: async (value) => clipboard.push(value) } },
    URL: { createObjectURL: () => 'blob:test', revokeObjectURL() {} },
    setTimeout() {}, confirm: () => true,
    addEventListener(kind, listener) { pageEvents.set(kind, listener); },
  });
  vm.runInContext(fs.readFileSync('ssh-keygen.js', 'utf8'), context);
  const click = async (id) => {
    const handler = element(id).listeners.get('click');
    assert.ok(handler, `${id} has a click handler`);
    await handler();
  };
  return { context, element, clipboard, downloads, pageEvents, click };
}

test('generated keys are visible and usable in both SSH forms only while this page holds them', async () => {
  const h = harness();
  await h.click('sshGenerateKey');
  const publicKey = h.element('sshGeneratedPublicKey').value;
  assert.match(publicKey, /^ssh-ed25519 [A-Za-z0-9+/=]+ sovagrid-browser$/);
  assert.equal(h.element('sshGeneratedKeyPanel').hidden, false);
  assert.equal(h.element('sshUseGeneratedKey').checked, true);
  assert.equal(h.element('sshPassphrase').disabled, true);
  assert.equal(h.element('sshAuthKey').checked, true);
  assert.equal(h.context.sovagridSSHKeygen.get('login').downloadRequested, false);
  assert.match(h.context.sovagridSSHKeygen.get('login').privateKey,
    /^-----BEGIN OPENSSH PRIVATE KEY-----\n/);
  await h.click('sshCopyPublicKey');
  assert.deepEqual(h.clipboard, [publicKey]);
  await h.click('sshDownloadPrivateKey');
  assert.deepEqual(h.downloads, ['sovagrid_ssh_ed25519']);
  assert.equal(h.context.sovagridSSHKeygen.get('login').downloadRequested, true);
  const revision = h.context.sovagridSSHKeygen.get('login').revision;
  assert.equal(h.context.sovagridSSHKeygen.clear('login', revision + 1), false);
  assert.ok(h.context.sovagridSSHKeygen.get('login'));
  h.context.sovagridSSHKeygen.setBusy('login', true);
  assert.equal(h.element('sshGenerateKey').disabled, true);
  const savedKey = h.context.sovagridSSHKeygen.get('login').privateKey;
  await h.click('sshGenerateKey');
  assert.equal(h.context.sovagridSSHKeygen.get('login').privateKey, savedKey);
  h.context.sovagridSSHKeygen.setBusy('login', false);
  assert.equal(h.element('sshGenerateKey').disabled, false);
  h.element('sshPrivateKey').files = [{ size: 1 }];
  h.element('sshPrivateKey').listeners.get('change')();
  assert.equal(h.context.sovagridSSHKeygen.get('login'), null);
  assert.equal(h.element('sshPassphrase').disabled, false);
  h.element('sshUseGeneratedKey').checked = true;
  h.element('sshUseGeneratedKey').listeners.get('change')();
  assert.ok(h.context.sovagridSSHKeygen.get('login'));
  assert.equal(h.element('sshPassphrase').disabled, true);

  await h.click('serverSetupGenerateKey');
  assert.notEqual(h.element('serverSetupGeneratedPublicKey').value, publicKey);
  h.context.sovagridSSHKeygen.setBusy('setup', true);
  assert.equal(h.element('serverSetupGenerateKey').disabled, true);
  h.context.sovagridSSHKeygen.setBusy('setup', false);
  h.context.sovagridSSHKeygen.clear('setup');
  assert.equal(h.context.sovagridSSHKeygen.get('setup'), null);
  assert.equal(h.element('serverSetupGeneratedKeyPanel').hidden, true);
  assert.ok(h.context.sovagridSSHKeygen.get('login'));
  h.pageEvents.get('pagehide')();
  assert.equal(h.context.sovagridSSHKeygen.get('login'), null);
  assert.equal(h.element('sshGeneratedPublicKey').value, '');
});

test('unsupported crypto never claims a key was created or sent to a server', async () => {
  const h = harness({ secure: false });
  await h.click('sshGenerateKey');
  assert.equal(h.context.sovagridSSHKeygen.get('login'), null);
  assert.match(h.element('sshGeneratedKeyMessage').textContent, /не поддерживает/);
  assert.equal(h.element('sshGeneratedKeyPanel').hidden, true);
});

test('an in-flight generation cannot replace a key after an SSH request becomes busy', async () => {
  const pair = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  let release;
  const crypto = { subtle: {
    generateKey: () => new Promise((resolve) => { release = resolve; }),
    exportKey: (format, key) => webcrypto.subtle.exportKey(format, key),
  }, getRandomValues: (array) => webcrypto.getRandomValues(array) };
  const h = harness({ crypto });
  const generating = h.click('sshGenerateKey');
  assert.equal(h.element('sshGenerateKey').disabled, true);
  h.context.sovagridSSHKeygen.setBusy('login', true);
  release(pair);
  await generating;
  assert.equal(h.context.sovagridSSHKeygen.get('login'), null);
  assert.equal(h.element('sshGeneratedPublicKey').value, '');
  assert.equal(h.element('sshGenerateKey').disabled, true);
  h.context.sovagridSSHKeygen.setBusy('login', false);
  assert.equal(h.element('sshGenerateKey').disabled, false);
});

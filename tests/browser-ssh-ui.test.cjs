/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const FINGERPRINT = `SHA256:${'A'.repeat(43)}`;
const CHANGED = `SHA256:${'B'.repeat(43)}`;
const GRANT = 'c'.repeat(43);

function harness({ fingerprint = FINGERPRINT, savedPin = null, responseStatus = 200,
  url = 'https://relay.example/', loginDelay = null } = {}) {
  const elements = new Map();
  const storage = new Map(savedPin ? [[`sovagrid.ssh-host-key:https://relay.example`, savedPin]] : []);
  const calls = [];
  const redeemed = [];
  const landings = [];
  const element = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      elements.set(id, {
        value: '', hidden: id === 'sshKeyFields', checked: id === 'sshAuthPassword',
        disabled: id === 'sshConnectButton', textContent: '', files: [],
        listeners, addEventListener(name, listener) { listeners.set(name, listener); },
        setAttribute(name, value) { this[name] = value; }, focus() {},
      });
    }
    return elements.get(id);
  };
  const context = vm.createContext({
    URL, AbortController, setTimeout, clearTimeout,
    document: { getElementById: element },
    location: new URL(url),
    localStorage: {
      getItem: (key) => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value),
      removeItem: (key) => storage.delete(key),
    },
    fetch: async (path, options) => {
      calls.push({ path, options });
      if (path.endsWith('/login') && loginDelay) await loginDelay;
      const value = path.endsWith('/host-key')
        ? { protocol: 1, port: 22, key_type: 'ssh-ed25519', fingerprint }
        : { protocol: 1, grant: GRANT };
      return { ok: responseStatus === 200, status: responseStatus, json: async () => value };
    },
    sovagridRedeemBrowserSSHGrant: async (grant, landing) => { redeemed.push(grant); landings.push(landing); },
    confirm: () => true,
  });
  vm.runInContext(fs.readFileSync('browser-ssh.js', 'utf8'), context);
  const dispatch = async (id, name, event = {}) => {
    const handler = element(id).listeners.get(name);
    assert.ok(handler, `${id}: ${name}`);
    handler({ preventDefault() {}, ...event });
    await new Promise((resolve) => setImmediate(resolve));
  };
  return { context, element, storage, calls, redeemed, landings, dispatch };
}

test('SSH is the visible first option and the panel login remains reachable', async () => {
  const html = fs.readFileSync('index.html', 'utf8');
  const css = fs.readFileSync('styles.css', 'utf8');
  const image = fs.readFileSync('Dockerfile', 'utf8');
  const shell = fs.readFileSync('sw.js', 'utf8');
  const caddy = fs.readFileSync('deploy/Caddyfile.container', 'utf8');
  assert.match(html, /id="sshLoginMode"[^>]+aria-selected="true"/);
  assert.match(html, /id="hubLoginView"[^>]+hidden/);
  assert.match(html, /browser-ssh\.js\?v=4/);
  assert.match(image, /COPY[^\n]*browser-ssh\.js/);
  assert.match(shell, /browser-ssh\.js\?v=4/);
  assert.match(html, /theme\.css\?v=6/);
  assert.match(shell, /theme\.css\?v=6/);
  assert.ok(caddy.indexOf('@browser_ssh path /api/v1/browser-ssh/*') < caddy.indexOf('@api path /api/*'));
  assert.match(caddy, /reverse_proxy ssh-gateway:8768/);
  assert.match(caddy, /header_up X-SovaGrid-Client-IP \{remote_host\}/);
  assert.match(css, /#sshPasswordFields\[hidden\].*display:none/);
  assert.match(html, /id="sshAuthPassword"[^>]+checked/);
  assert.match(html, /id="sshAuthKey"[^>]+private_key/);
  const h = harness();
  await h.dispatch('hubLoginMode', 'click');
  assert.equal(h.element('hubLoginView').hidden, false);
  assert.equal(h.element('browserSshView').hidden, true);
});

test('password login requires inspected host key and stores only the public fingerprint', async () => {
  const h = harness();
  h.element('sshUsername').value = 'root';
  await h.dispatch('sshAuthPassword', 'change');
  assert.equal(h.element('sshPasswordFields').hidden, false);
  assert.equal(h.element('sshKeyFields').hidden, true);
  assert.equal(h.element('sshConnectButton').disabled, true);
  await h.dispatch('sshInspectHost', 'click');
  assert.equal(h.calls[0].path, '/api/v1/browser-ssh/host-key');
  assert.equal(h.calls[0].options.credentials, 'omit');
  assert.equal(h.element('sshHostFingerprint').textContent, FINGERPRINT);
  assert.equal(h.element('sshConnectButton').disabled, true);
  h.element('sshTrustHost').checked = true;
  await h.dispatch('sshTrustHost', 'change');
  h.element('sshPassword').value = 'private SSH password';
  await h.dispatch('browserSshForm', 'submit');
  assert.equal(h.calls[1].path, '/api/v1/browser-ssh/login');
  assert.equal(JSON.parse(h.calls[1].options.body).password, 'private SSH password');
  assert.equal(h.element('sshPassword').value, '');
  assert.deepEqual(h.redeemed, [GRANT]);
  assert.deepEqual([...h.storage.entries()], [[`sovagrid.ssh-host-key:https://relay.example`, FINGERPRINT]]);
});

test('Target landing is selected only after a relay SSH grant and is never a gateway destination', async () => {
  const h = harness();
  h.element('sshUsername').value = 'root';
  h.element('sshOpenServer').value = ' Target ';
  h.element('sshOpenCommands').checked = true;
  await h.dispatch('sshInspectHost', 'click');
  h.element('sshTrustHost').checked = true;
  h.element('sshPassword').value = 'secret';
  await h.dispatch('browserSshForm', 'submit');
  assert.deepEqual(h.redeemed, [GRANT]);
  assert.equal(h.landings[0].server, 'Target');
  assert.equal(h.landings[0].commands, true);
  assert.equal(Object.hasOwn(JSON.parse(h.calls[1].options.body), 'server'), false);
  assert.equal(h.calls[1].path, '/api/v1/browser-ssh/login');
});

test('changed host key blocks login until explicit replacement and fresh confirmation', async () => {
  const h = harness({ fingerprint: CHANGED, savedPin: FINGERPRINT });
  h.element('sshUsername').value = 'root';
  h.element('sshPassword').value = 'secret';
  await h.dispatch('sshInspectHost', 'click');
  assert.equal(h.element('sshConnectButton').disabled, true);
  assert.equal(h.element('sshReplaceHostKey').hidden, false);
  assert.match(h.element('sshLoginError').textContent, /не совпадает/);
  await h.dispatch('browserSshForm', 'submit');
  assert.equal(h.calls.length, 1);
  await h.dispatch('sshReplaceHostKey', 'click');
  assert.equal(h.storage.get('sovagrid.ssh-host-key:https://relay.example'), FINGERPRINT);
  assert.equal(h.element('sshTrustHost').checked, false);
  h.element('sshTrustHost').checked = true;
  await h.dispatch('sshTrustHost', 'change');
  await h.dispatch('browserSshForm', 'submit');
  assert.equal(h.calls.length, 2);
  assert.equal(h.storage.get('sovagrid.ssh-host-key:https://relay.example'), CHANGED);
});

test('private key and passphrase come from file picker and clear before network request', async () => {
  const h = harness();
  h.element('sshUsername').value = 'root';
  h.element('sshAuthPassword').checked = false;
  h.element('sshAuthKey').checked = true;
  await h.dispatch('sshAuthKey', 'change');
  await h.dispatch('sshInspectHost', 'click');
  h.element('sshTrustHost').checked = true;
  await h.dispatch('sshTrustHost', 'change');
  h.element('sshPrivateKey').files = [{ size: 48, text: async () => '-----BEGIN PRIVATE KEY-----\nsecret' }];
  h.element('sshPrivateKey').value = 'selected file';
  h.element('sshPassphrase').value = 'passphrase';
  await h.dispatch('browserSshForm', 'submit');
  const payload = JSON.parse(h.calls[1].options.body);
  assert.equal(payload.method, 'private_key');
  assert.equal(payload.private_key, '-----BEGIN PRIVATE KEY-----\nsecret');
  assert.equal(payload.passphrase, 'passphrase');
  assert.equal(h.element('sshPrivateKey').value, '');
  assert.equal(h.element('sshPassphrase').value, '');
  assert.deepEqual(h.redeemed, [GRANT]);
});

test('generated SSH key signs in without a file or passphrase', async () => {
  const h = harness();
  const privateKey = '-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----\n';
  const cleared = [];
  h.context.sovagridSSHKeygen = {
    get: (name) => name === 'login' ? { privateKey, revision: 7, downloadRequested: true } : null,
    clear: (name, revision) => { cleared.push([name, revision]); },
  };
  h.element('sshUsername').value = 'root';
  h.element('sshAuthPassword').checked = false;
  h.element('sshAuthKey').checked = true;
  await h.dispatch('sshAuthKey', 'change');
  await h.dispatch('sshInspectHost', 'click');
  h.element('sshTrustHost').checked = true;
  await h.dispatch('sshTrustHost', 'change');
  h.element('sshPassphrase').value = 'ignored for an unencrypted generated key';
  await h.dispatch('browserSshForm', 'submit');
  const payload = JSON.parse(h.calls[1].options.body);
  assert.equal(payload.method, 'private_key');
  assert.equal(payload.private_key, privateKey);
  assert.equal(payload.passphrase, '');
  assert.equal(h.element('sshPassphrase').value, '');
  assert.deepEqual(h.redeemed, [GRANT]);
  assert.deepEqual(cleared, [['login', 7]]);
});

test('generated key requires a private download before SSH login', async () => {
  const h = harness();
  h.context.sovagridSSHKeygen = { get: () => ({ privateKey: 'key', revision: 1,
    downloadRequested: false }) };
  h.element('sshUsername').value = 'root';
  h.element('sshAuthPassword').checked = false;
  h.element('sshAuthKey').checked = true;
  await h.dispatch('sshAuthKey', 'change');
  await h.dispatch('sshInspectHost', 'click');
  h.element('sshTrustHost').checked = true;
  await h.dispatch('browserSshForm', 'submit');
  assert.equal(h.calls.length, 1);
  assert.match(h.element('sshLoginError').textContent, /Скачать приватный/);
});

test('in-flight SSH login clears only its key revision after the response', async () => {
  let releaseLogin;
  const loginDelay = new Promise((resolve) => { releaseLogin = resolve; });
  const h = harness({ loginDelay });
  let current = { privateKey: 'old key', revision: 4, downloadRequested: true };
  const busyStates = [], clearRevisions = [];
  const keygen = {
    get: () => current,
    setBusy: (name, busy) => { busyStates.push([name, busy]); },
    clear: (name, revision) => {
      clearRevisions.push([name, revision]);
      if (current?.revision === revision) current = null;
    },
  };
  h.element('sshUsername').value = 'root';
  h.element('sshAuthPassword').checked = false;
  h.element('sshAuthKey').checked = true;
  await h.dispatch('sshAuthKey', 'change');
  await h.dispatch('sshInspectHost', 'click');
  h.context.sovagridSSHKeygen = keygen;
  h.element('sshTrustHost').checked = true;
  await h.dispatch('browserSshForm', 'submit');
  assert.equal(h.calls[1].path, '/api/v1/browser-ssh/login');
  assert.deepEqual(busyStates, [['login', true]]);
  current = { privateKey: 'new key', revision: 5, downloadRequested: false };
  releaseLogin();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(clearRevisions, [['login', 4]]);
  assert.equal(current.privateKey, 'new key');
  assert.deepEqual(busyStates, [['login', true], ['login', false]]);
});

test('old server explains unavailable gateway and keeps Hub login usable', async () => {
  const h = harness({ responseStatus: 404 });
  await h.dispatch('sshInspectHost', 'click');
  assert.match(h.element('sshLoginError').textContent, /SSH-вход через сайт ещё не включён/);
  await h.dispatch('hubLoginMode', 'click');
  assert.equal(h.element('hubLoginView').hidden, false);
});

test('plain HTTP on a remote IP never reads a key or posts SSH credentials', async () => {
  const h = harness({ url: 'http://8.8.8.8/' });
  assert.equal(h.element('sshInspectHost').disabled, true);
  assert.equal(h.element('sshConnectButton').disabled, true);
  assert.match(h.element('sshLoginError').textContent, /HTTPS/);
  h.element('sshUsername').value = 'root';
  h.element('sshPrivateKey').files = [{ size: 20, text() { throw new Error('must not read'); } }];
  await h.dispatch('sshInspectHost', 'click');
  await h.dispatch('browserSshForm', 'submit');
  assert.equal(h.calls.length, 0);
  assert.deepEqual(h.redeemed, []);
  await h.dispatch('hubLoginMode', 'click');
  assert.equal(h.element('hubLoginView').hidden, false);
});

test('file read cannot race a new host-key inspection or an unchecked trust box', async () => {
  const h = harness();
  h.element('sshUsername').value = 'root';
  h.element('sshAuthPassword').checked = false;
  h.element('sshAuthKey').checked = true;
  await h.dispatch('sshAuthKey', 'change');
  await h.dispatch('sshInspectHost', 'click');
  h.element('sshTrustHost').checked = true;
  await h.dispatch('sshTrustHost', 'change');
  let finishRead;
  h.element('sshPrivateKey').files = [{ size: 20, text: () => new Promise((resolve) => { finishRead = resolve; }) }];
  await h.dispatch('browserSshForm', 'submit');
  assert.equal(h.element('sshInspectHost').disabled, true);
  await h.dispatch('sshInspectHost', 'click');
  assert.equal(h.calls.length, 1, 'a concurrent inspection was blocked');
  h.element('sshTrustHost').checked = false;
  finishRead('-----BEGIN PRIVATE KEY-----\nsecret');
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.calls.length, 1, 'the key was not posted after trust changed');
  assert.match(h.element('sshLoginError').textContent, /изменились/);
  assert.equal(h.storage.size, 0);
});

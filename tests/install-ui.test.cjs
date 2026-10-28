/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

function harness({ secure = true, url = 'https://panel.example/', agent = 'Chrome/140 Safari/537.36',
  platform = 'Linux', touch = 0, standalone = false } = {}) {
  const elements = new Map(), events = new Map();
  function element(id) {
    if (!elements.has(id)) elements.set(id, { textContent: '', hidden: false, disabled: false, children: [], handlers: {},
      addEventListener(type, callback) { this.handlers[type] = callback; },
      replaceChildren(...items) { this.children = items; }, showModal() { this.open = true; }, close() { this.open = false; } });
    return elements.get(id);
  }
  const buttons = [element('loginInstall'), element('topInstall')];
  const mode = { matches: standalone, addEventListener(_type, callback) { this.change = callback; } };
  const window = { isSecureContext: secure, matchMedia: () => mode,
    addEventListener(type, callback) { events.set(type, callback); } };
  const navigator = { userAgent: agent, platform, maxTouchPoints: touch };
  const context = vm.createContext({ URL, window, navigator, location: new URL(url),
    document: { getElementById: element, createElement: () => element(Symbol()), querySelectorAll: () => buttons },
    fetch() { throw Error('installation must not access APIs'); },
    localStorage: { setItem() { throw Error('installation must not persist'); } } });
  vm.runInContext(fs.readFileSync('install.js', 'utf8'), context);
  return { element, buttons, mode, navigator, events,
    emit(type, value = {}) { return events.get(type)?.(value); },
    open() { buttons[0].handlers.click(); }, click() { return element('installConfirm').handlers.click(); } };
}

test('installation is available before login, never auto-prompts, and consumes each event once', async () => {
  const h = harness(); let prompts = 0, prevented = 0;
  assert.equal(h.buttons.length, 2);
  h.emit('beforeinstallprompt', { preventDefault() { prevented++; },
    prompt() { prompts++; return Promise.resolve(); }, userChoice: Promise.resolve({ outcome: 'dismissed' }) });
  assert.equal(prevented, 1); assert.equal(prompts, 0);
  h.open(); assert.equal(h.element('installDialog').open, true); assert.equal(prompts, 0);
  const pending = h.click(); assert.equal(prompts, 1); assert.equal(h.element('installConfirm').disabled, true);
  await pending; await h.click(); assert.equal(prompts, 1);
  assert.match(h.element('installStatus').textContent, /отменена/);
  assert.equal(h.element('installConfirm').hidden, true);
  assert.equal(h.buttons[0].textContent, 'Сделать приложением');
});

test('accepted request waits for browser completion; late choice cannot undo appinstalled', async () => {
  const h = harness(); let resolve;
  const choice = new Promise((done) => { resolve = done; });
  h.emit('beforeinstallprompt', { preventDefault() {}, prompt() { return Promise.resolve(); }, userChoice: choice });
  const pending = h.click(); h.emit('appinstalled'); resolve({ outcome: 'dismissed' }); await pending;
  assert.equal(h.buttons[0].textContent, 'Приложение SovaGrid');
  assert.match(h.element('installTitle').textContent, /добавлен/);
  assert.equal(h.element('installConfirm').hidden, true);
  const second = harness();
  second.emit('beforeinstallprompt', { preventDefault() {}, prompt() { return Promise.resolve({ outcome: 'accepted' }); } });
  await second.click(); assert.match(second.element('installStatus').textContent, /Браузер принял запрос/);
  assert.equal(second.buttons[0].textContent, 'Сделать приложением');
});

test('standalone mode and iOS standalone detection replace installation with truthful current state', () => {
  const h = harness({ standalone: true }); h.open();
  assert.match(h.element('installTitle').textContent, /уже открыт/);
  assert.equal(h.element('installGuide').hidden, true);
  assert.equal(h.element('installConfirm').hidden, true);
  const ios = harness(); ios.navigator.standalone = true; ios.emit('pageshow');
  assert.match(ios.element('installTitle').textContent, /уже открыт/);
});

test('iPhone and iPad provide Safari steps rather than pretending to open an OS install dialog', () => {
  for (const device of [{ agent: 'Mozilla/5.0 (iPhone) Version/27 Mobile Safari/604.1', platform: 'iPhone' },
    { agent: 'Mozilla/5.0 (Macintosh) Version/27 Safari/605.1', platform: 'MacIntel', touch: 5 }]) {
    const h = harness(device); h.open();
    assert.match(h.element('installGuideTitle').textContent, /iPhone или iPad/);
    assert.match(h.element('installSteps').children.map((item) => item.textContent).join(' '), /Поделиться.*На экран Домой.*веб-приложение/);
    assert.equal(h.element('installConfirm').hidden, true);
    assert.match(h.element('installHelp').href, /^https:\/\/support\.apple\.com\//);
  }
  const other = harness({ agent: 'iPhone CriOS/140 Mobile Safari/604.1', platform: 'iPhone' });
  assert.match(other.element('installGuideIntro').textContent, /Откройте этот адрес в Safari/);
});

test('Safari Mac, unknown browsers and insecure origins get useful bounded guidance', () => {
  const mac = harness({ agent: 'Macintosh Version/27 Safari/605.1', platform: 'MacIntel' });
  assert.match(mac.element('installGuideTitle').textContent, /Dock/);
  const unknown = harness({ agent: 'UnknownBrowser', platform: '' });
  assert.match(unknown.element('installSteps').children[1].textContent, /Chrome или Edge/);
  const unsafe = harness({ secure: false, url: 'http://192.0.2.40/?password=private-canary#token' });
  let called = false;
  unsafe.emit('beforeinstallprompt', { preventDefault() { called = true; }, prompt() { called = true; } });
  assert.equal(called, false); assert.equal(unsafe.element('installSecureHint').hidden, false);
  assert.equal(unsafe.element('installOrigin').textContent, 'http://192.0.2.40/sovagrid/monitoring/');
  assert.doesNotMatch(unsafe.element('installOrigin').textContent, /canary|password|token/);
  assert.equal(unsafe.element('installConfirm').hidden, true);
});

test('loopback keeps its exact port and explains that the PWA does not create an SSH tunnel', () => {
  const h = harness({ url: 'http://127.0.0.1:8766/?private-canary' });
  assert.equal(h.element('installOrigin').textContent, 'http://127.0.0.1:8766/sovagrid/monitoring/');
  assert.match(h.element('installConnection').textContent, /том же порту.*само SSH-соединение не создаёт/);
  assert.equal(h.element('installSecureHint').hidden, true);
});

test('a custom panel path offers the permanent PWA launch route without URL secrets', () => {
  const h = harness({ url: 'https://panel.example/admin/ops/?password=private-canary#token' });
  assert.equal(h.element('installOrigin').textContent, 'https://panel.example/sovagrid/monitoring/');
  assert.equal(h.element('installStableLink').href, 'https://panel.example/sovagrid/monitoring/');
  assert.equal(h.element('installStableLink').hidden, false);
  assert.match(fs.readFileSync('index.html', 'utf8'), /id="installStableHint"[^>]*>[^<]*постоянный адрес/);
  assert.doesNotMatch(h.element('installOrigin').textContent, /private-canary|password|token/);
  const stable = harness({ url: 'https://panel.example/sovagrid/monitoring/' });
  assert.equal(stable.element('installStableLink').hidden, true);
});

test('prompt failure uses a fixed helpful message and a new browser event can enable retry', async () => {
  const h = harness();
  h.emit('beforeinstallprompt', { preventDefault() {}, prompt() { throw Error('private-canary'); } });
  await h.click(); assert.doesNotMatch(h.element('installStatus').textContent, /private-canary/);
  assert.match(h.element('installStatus').textContent, /через его меню/);
  h.emit('beforeinstallprompt', { preventDefault() {}, prompt() {} });
  assert.equal(h.element('installConfirm').hidden, false);
});

test('manifest and icons launch from the permanent route across custom panel paths', () => {
  const manifest = JSON.parse(fs.readFileSync('manifest.webmanifest', 'utf8'));
  assert.equal(manifest.id, '/');
  assert.equal(manifest.start_url, '/sovagrid/monitoring/');
  assert.equal(manifest.scope, '/');
  assert.equal(new URL(manifest.start_url, 'https://host.test/ops/monitoring/manifest.webmanifest').pathname,
    '/sovagrid/monitoring/');
  assert.equal(new URL(manifest.scope, 'https://host.test/ops/monitoring/manifest.webmanifest').pathname, '/');
  assert.equal(manifest.display, 'standalone');
  for (const size of [192, 512]) for (const purpose of ['any', 'maskable']) {
    const icon = manifest.icons.find((entry) => entry.sizes === `${size}x${size}` && entry.purpose === purpose);
    assert.equal(icon.type, 'image/png');
    assert.ok(icon.src.startsWith('/sovagrid/monitoring/icons/'));
    const png = fs.readFileSync(icon.src.slice('/sovagrid/monitoring/'.length));
    assert.equal(png.subarray(1, 4).toString(), 'PNG');
    assert.equal(png.readUInt32BE(16), size); assert.equal(png.readUInt32BE(20), size);
  }
  const apple = fs.readFileSync('icons/apple-touch-icon.png');
  assert.equal(apple.readUInt32BE(16), 180); assert.equal(apple.readUInt32BE(20), 180);
  const html = fs.readFileSync('index.html', 'utf8');
  assert.match(html, /rel="apple-touch-icon"[^>]+\/sovagrid\/monitoring\/icons\/apple-touch-icon.png/);
  assert.equal((html.match(/data-install-open/g) || []).length, 2);
  assert.match(fs.readFileSync('Dockerfile', 'utf8'), /COPY install.js install.css/);
});

/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

class Element {
  constructor() { this.textContent = ''; this.className = ''; this.children = []; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  addEventListener() {}
  setAttribute() {}
}

function harness() {
  const elements = new Map();
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const context = vm.createContext({
    URL, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: get, createElement: () => new Element(), querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    navigator: {}, location: new URL('https://hub.example'),
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  return { render: (data, online = true) => context.renderContainers(data, { online }), get };
}

function snapshot(age = 10) {
  return { version: 1, collected_at: Math.floor(Date.now() / 1000) - age, engines: [
    { engine: 'docker', source_status: 'ok', reason: null, truncated: false, containers: [
      { id: 'a'.repeat(64), name: '<img src=x onerror=alert(1)>', image: 'registry.example/api:1',
        state: 'running', health: 'healthy', restarts: 2, cpu_percent: 1.5, memory_bytes: 2048 },
    ] },
    { engine: 'podman', source_status: 'unavailable', reason: 'no_socket', truncated: false, containers: [] },
  ] };
}

test('mobile inventory renders safe text, resource usage and source access state', () => {
  const h = harness();
  h.render(snapshot());
  assert.equal(h.get('containersCount').textContent, '1');
  assert.match(h.get('containersFreshness').textContent, /Актуальный снимок.*UTC/);
  const [docker, podman] = h.get('containersList').children;
  const card = docker.children[1].children[0];
  assert.equal(card.children[0].children[0].textContent, '<img src=x onerror=alert(1)>');
  assert.match(card.children[3].textContent, /CPU 1.5% · RAM 2.0 КБ/);
  assert.match(podman.children[1].textContent, /Локальный сокет недоступен/);
  assert.ok(fs.readFileSync('index.html', 'utf8').includes('id="containersList"'));
  assert.match(fs.readFileSync('styles.css', 'utf8'), /@media\(max-width:760px\)\{\.container-engines\{grid-template-columns:1fr/);
});

test('offline or old snapshots are clearly marked stale; absent feature is explained', () => {
  const h = harness();
  h.render(snapshot(180));
  assert.match(h.get('containersFreshness').textContent, /Устаревший снимок · 3 мин назад/);
  h.render(snapshot(), false);
  assert.match(h.get('containersFreshness').textContent, /Устаревший снимок/);
  h.render(null);
  assert.match(h.get('containersFreshness').textContent, /не включён/);
  assert.equal(h.get('containersCount').textContent, '—');
});

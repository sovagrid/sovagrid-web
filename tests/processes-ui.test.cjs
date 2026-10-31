/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

class Element {
  constructor() { this.textContent = ''; this.hidden = false; this.children = []; }
  addEventListener() {}
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = [...items]; }
}

function harness() {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const context = vm.createContext({
    URL, AbortController, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, createElement: () => new Element(), querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null }, navigator: {}, location: { protocol: 'file:' },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  return { context, element };
}

test('top processes show bounded RSS rows without HTML interpolation', () => {
  const h = harness();
  h.context.renderTopProcesses([
    { pid: 101, name: 'python3', rss_bytes: 409600 },
    { pid: 7, name: 'sshd', rss_bytes: 81920 },
  ], { online: true });
  assert.equal(h.element('topProcessesTable').hidden, false);
  assert.equal(h.element('topProcessesRows').children.length, 2);
  assert.deepEqual(h.element('topProcessesRows').children[0].children.map((cell) => cell.textContent),
    ['101', 'python3', '400 КБ']);
  assert.match(h.element('topProcessesStatus').textContent, /2 процесса/);

  h.context.renderTopProcesses([{ pid: 101, name: '<img src=x>', rss_bytes: 1 }], { online: true });
  assert.equal(h.element('topProcessesTable').hidden, true);
  assert.equal(h.element('topProcessesRows').children.length, 0);
  assert.match(h.element('topProcessesStatus').textContent, /некорректные данные/);
});

test('empty, unsupported and offline states remove stale process rows', () => {
  const h = harness();
  h.context.renderTopProcesses([{ pid: 1, name: 'init', rss_bytes: 1024 }], { online: true });
  h.context.renderTopProcesses([], { online: true });
  assert.equal(h.element('topProcessesTable').hidden, true);
  assert.equal(h.element('topProcessesRows').children.length, 0);
  assert.match(h.element('topProcessesStatus').textContent, /Нет процессов/);

  h.context.renderTopProcesses(undefined, { online: true });
  assert.match(h.element('topProcessesStatus').textContent, /пока не передал/);
  h.context.renderTopProcesses([{ pid: 1, name: 'init', rss_bytes: 1024 }], { online: false, last_seen: 10 });
  assert.equal(h.element('topProcessesTable').hidden, true);
  assert.match(h.element('topProcessesStatus').textContent, /не отвечает/);
});

test('process table and new asset versions are included in the offline shell', () => {
  const html = fs.readFileSync('index.html', 'utf8');
  const shell = fs.readFileSync('sw.js', 'utf8');
  assert.match(html, /id="topProcessesTable"[^>]*hidden/);
  assert.match(html, /styles\.css\?v=42/);
  assert.match(html, /app\.js\?v=50/);
  assert.match(shell, /sovagrid-shell:\$\{encodeURIComponent\(BASE\)\}:/);
  assert.match(shell, /\$\{CACHE_PREFIX\}v73/);
  assert.match(html, /checks\.js\?v=5/);
  assert.match(shell, /checks\.js\?v=5/);
  assert.match(shell, /styles\.css\?v=42/);
  assert.match(shell, /app\.js\?v=50/);
  assert.match(shell, /container-alerts\.js\?v=1/);
  assert.match(shell, /journal\.js\?v=2/);
});

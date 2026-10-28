/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

class Element {
  constructor() { this.textContent = ''; this.children = []; this.className = ''; }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = items; }
  setAttribute() {}
  addEventListener() {}
}

test('check incidents use the saved safe name in overview and event list', () => {
  const elements = new Map();
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const context = vm.createContext({
    URL, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: get, createElement: () => new Element(),
      querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    navigator: {}, location: new URL('https://hub.example'),
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  const incident = { id: 'one', server_id: 'server', kind: 'check:sample',
    subject: '<img src=x onerror=alert(1)>', state: 'resolved',
    opened_at: 1_000_000, resolved_at: 1_000_120, updated_at: 1_000_120 };
  context.sample = incident;
  vm.runInContext('state.selectedId = "server"; state.incidents = [sample]; renderIncidents("server"); renderEvents()', context);
  assert.equal(get('incidentsList').children[0].children[1].children[0].textContent,
    'Недоступность проверки «<img src=x onerror=alert(1)>»');
  assert.equal(get('eventsList').children[0].children[1].children[0].textContent,
    'Недоступность проверки «<img src=x onerror=alert(1)>»');
  assert.equal(get('incidentCount').textContent, '0');
  assert.equal(get('eventsCount').textContent, '0');
  assert.equal(vm.runInContext('incidentLabel({kind: "check:sample"})', context),
    'Недоступность проверки');
});
test('TLS incidents show days and threshold without percent or stale recovery value', () => {
  const elements = new Map();
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const context = vm.createContext({
    URL, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: get, createElement: () => new Element(),
      querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    navigator: {}, location: new URL('https://hub.example'),
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  const incidents = [{ id: 'one', server_id: 'server', kind: 'tls:sample',
    subject: '<img src=x onerror=alert(1)>', state: 'firing', current_value: -2.25, threshold: 14,
    opened_at: 1_000_000, updated_at: 1_000_120 },
  { id: 'two', server_id: 'server', kind: 'tls:sample', subject: 'Renewed', state: 'resolved',
    current_value: 1.1, threshold: 14, opened_at: 1_000_000, resolved_at: 1_000_120, updated_at: 1_000_120 }];
  context.sample = incidents;
  vm.runInContext('state.selectedId = "server"; state.incidents = sample; renderIncidents("server"); renderEvents()', context);
  for (const list of ['incidentsList', 'eventsList']) {
    const active = get(list).children[0].children[1];
    assert.equal(active.children[0].textContent, 'Истекает HTTPS-сертификат проверки «<img src=x onerror=alert(1)>»');
    assert.match(active.children[1].textContent, /Сертификат просрочен на 2\.3 дн\. · порог 14 дн\./);
    assert.equal(active.children[1].textContent.includes('%'), false);
    assert.equal(get(list).children[1].children[1].children[1].textContent.includes('До истечения'), false);
  }
  assert.equal(vm.runInContext('incidentLabel({kind: "tls:sample"})', context), 'Истекает HTTPS-сертификат проверки');
});

/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

function element() {
  return {
    textContent: '', className: '', hidden: false, children: [],
    addEventListener() {}, setAttribute() {},
    append(...children) { this.children.push(...children); },
    replaceChildren() { this.children = []; },
  };
}

test('VPN view labels stale data and clears old services when the source fails', () => {
  const elements = new Map();
  const get = (id) => { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); };
  const context = vm.createContext({
    URL, AbortController, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: get, createElement: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {} }, navigator: {}, location: { protocol: 'file:' },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  context.renderVpn({ source_status: 'stale', collected_at: 1790000000, services: [{
    name: 'amnezia-awg', service: 'AmneziaWG', state: 'running', health: 'healthy',
    published_ports: [{ port: 51820, protocol: 'udp' }],
  }] });
  assert.equal(get('vpnSourceBadge').textContent, 'Данные устарели');
  assert.match(get('vpnSourceText').textContent, /могло измениться/);
  assert.equal(get('vpnRunning').textContent, '1');
  assert.equal(get('vpnServicesList').children[0].children[0].children[0].textContent, 'AmneziaWG');
  assert.equal(get('vpnServicesList').children[0].children[2].children[1].children[1].textContent, '51820/udp');

  context.renderVpn({ source_status: 'error', collected_at: 1790000000, services: [] });
  assert.equal(get('vpnSourceBadge').textContent, 'Ошибка сбора');
  assert.equal(get('vpnTotal').textContent, '—');
  assert.equal(get('vpnServicesList').children.length, 1);
  assert.equal(get('vpnServicesList').children[0].textContent, 'Список сервисов пока недоступен');

  context.renderVpn({ source_status: 'unavailable', collected_at: null, services: [] });
  assert.equal(get('vpnSourceBadge').textContent, 'Нет данных');
  assert.match(get('vpnSourceText').textContent, /ещё не настроен/);

  context.renderVpn({ source_status: 'loading' });
  assert.equal(get('vpnSourceBadge').textContent, 'Обновляем...');
});

test('managed WireGuard and Amnezia status render independently', () => {
  const elements = new Map();
  const get = (id) => { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); };
  const context = vm.createContext({
    URL, AbortController, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: get, createElement: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {} }, navigator: {}, location: { protocol: 'file:' },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  const instance = { name: 'phone-vpn', interface: 'sg12345678901', port: 51821,
    subnet: '10.49.0.0/24', client_count: 2, state: 'active' };
  context.renderVpn({ source_status: 'error', services: [],
    managed: { source_status: 'ok', instances: [instance] } });
  assert.equal(get('vpnSourceBadge').textContent, 'Ошибка сбора');
  assert.equal(get('managedSourceBadge').textContent, 'Данные актуальны');
  assert.equal(get('managedActive').textContent, '1');
  assert.equal(get('managedInstancesList').children[0].children[0].children[0].textContent, 'phone-vpn');
  assert.equal(get('managedInstancesList').children[0].children[2].children[2].children[1].textContent, '2');

  context.renderVpn({ source_status: 'ok', services: [{
    name: 'amnezia-awg', service: 'AmneziaWG', state: 'running', health: 'healthy',
    published_ports: [],
  }], managed: { source_status: 'ok', instances: [{
    name: 'phone-vpn', interface: 'sg12345678901', port: null,
    subnet: null, client_count: null, state: 'error',
  }] } });
  assert.equal(get('vpnRunning').textContent, '1');
  assert.equal(get('managedError').textContent, '1');
  assert.equal(get('managedInstancesList').children[0].children[2].children[0].children[1].textContent, '—');

  context.renderVpn({ source_status: 'ok', services: [],
    managed: { source_status: 'error', instances: [] } });
  assert.equal(get('managedSourceBadge').textContent, 'Ошибка сбора');
  assert.equal(get('managedCount').textContent, '—');
  assert.equal(get('vpnSourceBadge').textContent, 'Данные актуальны');
});

test('Amnezia protocol details expose interface failure and aggregate traffic only', () => {
  const elements = new Map();
  const get = (id) => { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); };
  const context = vm.createContext({
    URL, AbortController, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: get, createElement: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {} }, navigator: {}, location: { protocol: 'file:' },
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  context.renderVpn({ source_status: 'ok', services: [], amnezia_details: {
    source_status: 'ok', services: [
      { name: 'amnezia-awg2', status: 'ready', configured_clients: 2, runtime_clients: 2,
        active_last_3m: 1, latest_handshake_at: 1790000000,
        received_bytes: 1048576, sent_bytes: 1024 },
      { name: 'amnezia-wireguard', status: 'interface_down', configured_clients: 1,
        runtime_clients: 0 },
      { name: 'amnezia-xray', status: 'ready', configured_clients: 1,
        runtime_clients: null, api_enabled: false, stats_enabled: false },
    ],
  } });
  assert.equal(get('amneziaDetailBadge').textContent, 'Данные актуальны');
  const cards = get('amneziaDetailList').children;
  assert.equal(cards.length, 3);
  assert.equal(cards[1].children[0].children[1].textContent, 'Интерфейс отключён');
  assert.equal(cards[0].children[1].children[4].children[1].textContent, '1.0 МБ');
  const visible = (node) => [node.textContent, ...node.children.flatMap(visible)].join(' ');
  assert.doesNotMatch(visible(get('amneziaDetailList')), /PrivateKey|UUID|PublicKey|10\.0\./);
  context.renderVpn({ source_status: 'ok', services: [], amnezia_details: { source_status: 'error', services: [] } });
  assert.equal(get('amneziaDetailList').children.length, 1);
  assert.equal(get('amneziaDetailBadge').textContent, 'Ошибка сбора');
});

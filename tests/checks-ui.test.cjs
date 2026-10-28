/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const { webcrypto } = require('node:crypto');
const id = '27e9f965-7a73-47de-ab39-5e250c83c488';
const definition = { id, name: '<img onerror=alert(1)>', kind: 'http', enabled: true,
  interval_seconds: 60, timeout_seconds: 5, url: 'https://service.example/health' };
const result = { observed_at: 100, received_at: 101, status: 'up', latency_ms: 21,
  http_status: 200, tls_expires_at: 200, error_code: null };
const summary = () => ({ server_id: 'a', revision: 7, worker_seen_at: 100,
  checks: [{ ...definition, latest: { ...result }, state: 'stale' }] });
const reply = (status, payload) => ({ ok: status < 400, status, text: async () => JSON.stringify(payload) });
function harness(hook) {
  const elements = new Map(), calls = [];
  const make = () => ({ value: '', checked: false, required: false, hidden: false, disabled: false,
    textContent: '', open: false, children: [], dataset: {}, attributes: {}, addEventListener() {},
    setAttribute(k, v) { this.attributes[k] = v; }, append(...v) { this.children.push(...v); },
    replaceChildren(...v) { this.children = v; }, focus() {}, showModal() { this.open = true; }, close() { this.open = false; } });
  const element = (id) => { if (!elements.has(id)) elements.set(id, make()); return elements.get(id); };
  const context = vm.createContext({ URL, AbortController, TextEncoder, atob, btoa, crypto: webcrypto, setTimeout, clearTimeout,
    setInterval: () => 1, clearInterval() {}, Intl, navigator: {}, location: new URL('https://hub.example'),
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    document: { getElementById: element, createElement: make, querySelectorAll: () => [], addEventListener() {} },
    fetch: async (url, options) => {
      calls.push({ url, options });
      if (hook) { const value = await hook(url, options); if (value) return value; }
      return reply(200, url.endsWith('/config') ? { server_id: 'a', revision: 7, checks: [{ ...definition }] } : summary());
    } });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('checks.js', 'utf8'), context);
  const state = vm.runInContext('state', context), client = vm.runInContext('checksClient', context);
  Object.assign(state, { token: 'session-a', base: 'https://hub.example', selectedId: 'a',
    servers: [{ id: 'a', access_role: 'admin' }], user: { role: 'admin' } });
  return { context, state, client, element, calls };
}
const submit = { preventDefault() {} };
const fakeFile = (content) => {
  const bytes = Uint8Array.from(content);
  return { size: bytes.length, arrayBuffer: async () => bytes.buffer };
};

test('results use text, show stale/TLS dates and never render a target', async () => {
  const h = harness(); await h.context.checksRefresh();
  const row = h.element('checksList').children[0];
  assert.equal(row.children[0].textContent, definition.name);
  assert.equal(row.children[1].children[0].textContent, 'Данные устарели');
  assert.match(row.children[3].textContent, /Сертификат действителен до/);
  assert.equal(JSON.stringify(row).includes(definition.url), false);
  assert.equal(fs.readFileSync('checks.js', 'utf8').includes('.innerHTML'), false);
});
test('new HTTP check submits exact CAS list and public typed fields in JSON body', async () => {
  const h = harness(); await h.context.checksRefresh(); await h.context.checksOpen('create');
  h.element('checkName').value = 'My site'; h.element('checkUrl').value = 'https://example.com/health';
  await h.context.checksSubmit(submit);
  const call = h.calls.find((x) => x.options.method === 'POST');
  assert.equal(call.url, 'https://hub.example/api/v1/servers/a/checks/config');
  const body = JSON.parse(call.options.body);
  assert.equal(body.revision, 7); assert.equal(body.checks.length, 2);
  assert.match(body.checks[1].id, /^[a-f0-9-]{36}$/);
  assert.equal(body.checks[1].url, 'https://example.com/health');
  assert.equal(Object.hasOwn(body.checks[1], 'tls_alert_days'), false);
  assert.equal(h.element('checkDialog').open, false); assert.equal(h.element('checkUrl').value, '');
});
test('HTTPS alert is opt-in, bounded and sent as an integer with the check', async () => {
  const h = harness(); await h.context.checksRefresh(); await h.context.checksOpen('create');
  h.element('checkName').value = 'Certificate';
  assert.equal(h.element('checkTlsAlertField').hidden, true);
  h.element('checkUrl').value = 'https://example.com/health'; h.context.checksTlsControls();
  assert.equal(h.element('checkTlsAlertField').hidden, false);
  h.element('checkTlsAlertEnabled').checked = true; h.context.checksTlsControls();
  assert.equal(h.element('checkTlsAlertDays').required, true);
  for (const invalid of ['', '0', '91', '1.5', ' 14']) {
    h.element('checkTlsAlertDays').value = invalid;
    await h.context.checksSubmit(submit);
    assert.match(h.element('checkDialogError').textContent, /1 до 90/);
  }
  assert.equal(h.calls.filter((x) => x.options.method === 'POST').length, 0);
  h.element('checkTlsAlertDays').value = '30'; await h.context.checksSubmit(submit);
  const body = JSON.parse(h.calls.find((x) => x.options.method === 'POST').options.body);
  assert.equal(body.checks[1].tls_alert_days, 30);
  assert.equal(body.checks[0].url, definition.url);
  assert.equal(Object.hasOwn(body.checks[0], 'tls_alert_days'), false);
});
test('admin can choose a PEM CA file and save canonical DER for one HTTPS check', async () => {
  const h = harness(); await h.context.checksRefresh(); await h.context.checksOpen('create');
  h.element('checkName').value = 'Target service'; h.element('checkUrl').value = 'https://target.example/health';
  h.context.checksTlsControls();
  const der = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]);
  const pem = `-----BEGIN CERTIFICATE-----\n${der.toString('base64')}\n-----END CERTIFICATE-----\n`;
  h.element('checkCaFile').files = [fakeFile(Buffer.from(pem))];
  await h.context.checksCaSelected();
  assert.equal(h.element('checkCaField').hidden, false);
  assert.match(h.element('checkCaStatus').textContent, /Новый CA выбран/);
  assert.equal(h.element('checkCaClear').disabled, false);
  await h.context.checksSubmit(submit);
  const rows = JSON.parse(h.calls.find((call) => call.options.method === 'POST').options.body).checks;
  assert.equal(rows[1].ca_cert_der_b64, der.toString('base64'));
  assert.equal(Object.hasOwn(rows[0], 'ca_cert_der_b64'), false);
  assert.equal(JSON.stringify(h.element('checksList')).includes(der.toString('base64')), false);
  assert.equal(h.element('checkCaFile').value, '');
});
test('existing HTTPS CA is shown privately and explicit removal sends null', async () => {
  const encoded = Buffer.from([0x30, 0x00]).toString('base64');
  const configured = { ...definition, ca_cert_der_b64: encoded };
  const h = harness((url) => url.endsWith('/config') ? reply(200, { server_id: 'a', revision: 7, checks: [configured] }) : null);
  await h.context.checksRefresh(); await h.context.checksOpen('edit', id);
  assert.match(h.element('checkCaStatus').textContent, /уже настроен/);
  assert.equal(JSON.stringify(h.element('checksList')).includes(encoded), false);
  h.context.checksCaClear();
  assert.match(h.element('checkCaStatus').textContent, /будет удалён/);
  await h.context.checksSubmit(submit);
  const row = JSON.parse(h.calls.find((call) => call.options.method === 'POST').options.body).checks[0];
  assert.equal(row.ca_cert_der_b64, null);
});
test('bad, multiple and oversized certificate files block saving until a valid selection', async () => {
  const h = harness(); await h.context.checksRefresh(); await h.context.checksOpen('create');
  h.element('checkName').value = 'CA service'; h.element('checkUrl').value = 'https://target.example/';
  h.context.checksTlsControls();
  for (const content of [
    '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----',
    '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----',
    Buffer.alloc(1537, 48), Buffer.alloc(4097, 48),
  ]) {
    h.element('checkCaFile').files = [fakeFile(Buffer.from(content))];
    await h.context.checksCaSelected();
    assert.equal(h.element('checkConfirm').disabled, true);
    await h.context.checksSubmit(submit);
    assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 0);
  }
  h.element('checkCaFile').files = [fakeFile(Buffer.from([0x30, 0x00]))];
  await h.context.checksCaSelected();
  assert.equal(h.element('checkConfirm').disabled, false);
  await h.context.checksSubmit(submit);
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 1);
});
test('a rejected CA file can be cleared without closing the new-check form', async () => {
  const h = harness(); await h.context.checksRefresh(); await h.context.checksOpen('create');
  h.element('checkName').value = 'Target service'; h.element('checkUrl').value = 'https://target.example/';
  h.context.checksTlsControls();
  h.element('checkCaFile').files = [fakeFile(Buffer.from('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----'))];
  await h.context.checksCaSelected();
  assert.equal(h.element('checkConfirm').disabled, true);
  assert.equal(h.element('checkCaClear').disabled, false);
  assert.equal(h.element('checkCaClear').textContent, 'Сбросить неверный файл');
  h.context.checksCaClear();
  assert.equal(h.element('checkDialog').open, true);
  assert.equal(h.element('checkConfirm').disabled, false);
  assert.equal(h.element('checkDialogError').hidden, true);
  await h.context.checksSubmit(submit);
  const row = JSON.parse(h.calls.find((call) => call.options.method === 'POST').options.body).checks[1];
  assert.equal(Object.hasOwn(row, 'ca_cert_der_b64'), false);
});
test('clearing a rejected replacement keeps the previously configured CA', async () => {
  const encoded = Buffer.from([0x30, 0x00]).toString('base64');
  const configured = { ...definition, ca_cert_der_b64: encoded };
  const h = harness((url) => url.endsWith('/config') ? reply(200, { server_id: 'a', revision: 7, checks: [configured] }) : null);
  await h.context.checksRefresh(); await h.context.checksOpen('edit', id);
  h.element('checkCaFile').files = [fakeFile(Buffer.from('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----'))];
  await h.context.checksCaSelected();
  h.context.checksCaClear();
  assert.match(h.element('checkCaStatus').textContent, /уже настроен/);
  await h.context.checksSubmit(submit);
  const row = JSON.parse(h.calls.find((call) => call.options.method === 'POST').options.body).checks[0];
  assert.equal(row.ca_cert_der_b64, encoded);
});
test('changing an HTTPS check to HTTP or TCP never sends its previous CA', async () => {
  const configured = { ...definition, ca_cert_der_b64: Buffer.from([0x30, 0x00]).toString('base64') };
  for (const kind of ['http', 'tcp']) {
    const h = harness((url) => url.endsWith('/config') ? reply(200, { server_id: 'a', revision: 7, checks: [configured] }) : null);
    await h.context.checksRefresh(); await h.context.checksOpen('edit', id);
    if (kind === 'http') h.element('checkUrl').value = 'http://service.example/health';
    else { h.element('checkKind').value = 'tcp'; h.context.checksKindChanged();
      h.element('checkHost').value = 'service.example'; h.element('checkPort').value = '443'; }
    h.context.checksTlsControls();
    assert.equal(h.element('checkCaField').hidden, true);
    await h.context.checksSubmit(submit);
    const row = JSON.parse(h.calls.find((call) => call.options.method === 'POST').options.body).checks[0];
    assert.equal(Object.hasOwn(row, 'ca_cert_der_b64'), false);
  }
});
test('a delayed CA file read cannot change a new server or dialog', async () => {
  let finish;
  const h = harness(); await h.context.checksRefresh(); await h.context.checksOpen('create');
  h.element('checkName').value = 'Delayed'; h.element('checkUrl').value = 'https://target.example/';
  h.context.checksTlsControls();
  h.element('checkCaFile').files = [{ size: 2, arrayBuffer: () => new Promise((resolve) => { finish = resolve; }) }];
  const reading = h.context.checksCaSelected();
  assert.equal(h.element('checkConfirm').disabled, true);
  h.state.selectedId = 'b'; h.context.checksSelectedServer('b');
  finish(Uint8Array.from([0x30, 0x00]).buffer); await reading;
  assert.equal(h.client.pending, null);
  assert.equal(h.element('checkCaStatus').textContent, 'Используется системное доверие.');
  assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 0);
});
test('editing HTTPS alert sends explicit null to disable; HTTP/TCP cannot inherit it', async () => {
  const configured = { ...definition, tls_alert_days: 30 };
  const h = harness((url) => url.endsWith('/config') ? reply(200, { server_id: 'a', revision: 7, checks: [configured] }) :
    url.endsWith('/checks') ? reply(200, { ...summary(), checks: [{ ...summary().checks[0], tls_alert_days: 30 }] }) : null);
  await h.context.checksRefresh(); await h.context.checksOpen('edit', id);
  assert.equal(h.element('checkTlsAlertEnabled').checked, true);
  assert.equal(h.element('checkTlsAlertDays').value, '30');
  h.element('checkTlsAlertEnabled').checked = false; h.context.checksTlsControls();
  assert.equal(h.element('checkTlsAlertDays').disabled, true);
  await h.context.checksSubmit(submit);
  const first = JSON.parse(h.calls.find((x) => x.options.method === 'POST').options.body).checks[0];
  assert.equal(first.tls_alert_days, null);

  const changed = harness((url) => url.endsWith('/config') ? reply(200, { server_id: 'a', revision: 7, checks: [configured] }) : null);
  await changed.context.checksRefresh(); await changed.context.checksOpen('edit', id);
  changed.element('checkUrl').value = 'http://example.com/health'; changed.context.checksTlsControls();
  assert.equal(changed.element('checkTlsAlertField').hidden, true);
  await changed.context.checksSubmit(submit);
  const second = JSON.parse(changed.calls.find((x) => x.options.method === 'POST').options.body).checks[0];
  assert.equal(Object.hasOwn(second, 'tls_alert_days'), false);
});
test('certificate date keeps a 14-day visual warning even with notifications off', async () => {
  const now = Math.floor(Date.now() / 1000);
  const h = harness((url) => url.endsWith('/checks') ? reply(200, { ...summary(),
    checks: [{ ...summary().checks[0], tls_alert_days: null,
      latest: { ...result, tls_expires_at: now + 7 * 86400 } }] }) : null);
  await h.context.checksRefresh();
  const tls = h.element('checksList').children[0].children[3];
  assert.equal(tls.className, 'check-tls-warning');
  assert.match(tls.textContent, /Оповещение выключено/);
  assert.match(tls.textContent, /Требуется обновление сертификата/);
  assert.equal(tls.textContent.includes('%'), false);
});
test('invalid URL/password/query and bad intervals never cause a mutation', async () => {
  const h = harness(); await h.context.checksRefresh(); await h.context.checksOpen('create');
  h.element('checkName').value = 'Bad site';
  for (const url of ['https://a:b@example.com', 'https://example.com/?', 'https://example.com/#', 'file:///tmp/a', 'https://exa\\mple.com']) {
    h.element('checkUrl').value = url; await h.context.checksSubmit(submit);
  }
  h.element('checkUrl').value = 'https://example.com'; h.element('checkInterval').value = '59';
  await h.context.checksSubmit(submit);
  assert.equal(h.calls.filter((x) => x.options.method === 'POST').length, 0);
  assert.equal(h.element('checkDialog').open, true);
});
test('TCP mode excludes stale URL and delete cannot leave the next form optional', async () => {
  const h = harness(); await h.context.checksRefresh(); await h.context.checksOpen('delete', id);
  assert.equal(h.element('checkName').required, false); h.context.checksClose();
  await h.context.checksOpen('edit', id); assert.equal(h.element('checkName').required, true);
  h.element('checkKind').value = 'tcp'; h.context.checksKindChanged();
  h.element('checkHost').value = '127.0.0.1'; h.element('checkPort').value = '22';
  await h.context.checksSubmit(submit);
  const body = JSON.parse(h.calls.find((x) => x.options.method === 'POST').options.body);
  assert.equal(body.checks[0].kind, 'tcp'); assert.equal(body.checks[0].port, 22);
  assert.equal(Object.hasOwn(body.checks[0], 'url'), false);
});
test('DNS mode submits A/AAAA targets without stale HTTP or TCP fields', async () => {
  const h = harness(); await h.context.checksRefresh(); await h.context.checksOpen('create');
  h.element('checkName').value = 'DNS from home';
  h.element('checkKind').value = 'dns'; h.context.checksKindChanged();
  assert.equal(h.element('checkDnsFields').hidden, false);
  assert.equal(h.element('checkUrlField').hidden, true);
  assert.equal(h.element('checkTcpFields').hidden, true);
  assert.equal(h.element('checkExpectedIp').placeholder, '203.0.113.10');
  assert.equal(h.element('checkExpectedIp').inputMode, 'decimal');
  h.element('checkDnsHost').value = 'example.test';
  h.element('checkRecordType').value = 'AAAA'; h.context.checksDnsTypeChanged();
  assert.equal(h.element('checkExpectedIp').placeholder, '2001:db8::1');
  assert.equal(h.element('checkExpectedIp').inputMode, 'text');
  h.element('checkExpectedIp').value = '2001:db8::7';
  await h.context.checksSubmit(submit);
  const row = JSON.parse(h.calls.find((x) => x.options.method === 'POST').options.body).checks[1];
  assert.equal(row.kind, 'dns'); assert.equal(row.host, 'example.test');
  assert.equal(row.record_type, 'AAAA'); assert.equal(row.expected_ip, '2001:db8::7');
  assert.equal(Object.hasOwn(row, 'url'), false); assert.equal(Object.hasOwn(row, 'port'), false);
  assert.equal(h.element('checkExpectedIp').value, '');
});
test('DNS rejects malformed host and mismatched expected address before saving', async () => {
  const h = harness(); await h.context.checksRefresh(); await h.context.checksOpen('create');
  h.element('checkKind').value = 'dns'; h.context.checksKindChanged(); h.element('checkName').value = 'DNS';
  for (const [host, type, expected] of [
    ['127.0.0.1', 'A', ''], ['bad host', 'A', ''], ['example.test', 'A', '2001:db8::1'],
    ['example.test', 'AAAA', '203.0.113.5'], ['example..test', 'A', '']]) {
    h.element('checkDnsHost').value = host; h.element('checkRecordType').value = type;
    h.element('checkExpectedIp').value = expected; await h.context.checksSubmit(submit);
  }
  assert.equal(h.calls.filter((x) => x.options.method === 'POST').length, 0);
});
test('DNS viewer sees typed status without the queried name or expected address', async () => {
  const h = harness((url) => url.endsWith('/checks') ? reply(200, { server_id: 'a', revision: 8, worker_seen_at: 100,
    checks: [{ id, name: 'Resolver', kind: 'dns', enabled: true, interval_seconds: 60,
      timeout_seconds: 5, state: 'down', latest: { ...result, http_status: null,
        tls_expires_at: null, status: 'down', error_code: 'dns_mismatch' } }] }) : null);
  h.state.user.role = 'viewer'; await h.context.checksRefresh();
  const rendered = JSON.stringify(h.element('checksList'));
  assert.match(rendered, /DNS/); assert.match(rendered, /DNS вернул другой адрес/);
  assert.equal(rendered.includes('example.test'), false);
});
test('viewer may read history but has no mutation controls or target config access', async () => {
  const h = harness((url) => url.includes('/history') ? reply(200, { server_id: 'a', check_id: id, results: [result] }) : null);
  h.state.user.role = 'viewer'; await h.context.checksRefresh();
  const actions = h.element('checksList').children[0].children.find((x) => x.className === 'checks-actions');
  assert.equal(actions.children.length, 0); assert.equal(h.element('checksAdd').disabled, true);
  await h.context.checksOpen('edit', id); await h.context.checksRun(id);
  const list = h.element('history'); await h.context.checksHistory(id, list);
  assert.equal(list.children.length, 1);
  assert.equal(h.calls.some((x) => x.url.endsWith('/config') || x.options.method === 'POST'), false);
});
test('late old-server config, summary and history cannot repopulate new selection', async () => {
  for (const kind of ['summary', 'config', 'history']) {
    let resolve; let block = false;
    const h = harness((url) => block && (kind === 'config' ? url.endsWith('/config') : kind === 'history' ? url.includes('/history') : !url.endsWith('/config'))
      ? new Promise((done) => { resolve = done; }) : null);
    await h.context.checksRefresh(); block = true;
    const list = h.element('oldHistory');
    const pending = kind === 'config' ? h.context.checksOpen('edit', id) : kind === 'history' ? h.context.checksHistory(id, list) : h.context.checksRefresh();
    h.state.selectedId = 'b'; h.context.checksSelectedServer('b');
    resolve(reply(200, kind === 'config' ? { server_id: 'a', revision: 7, checks: [definition] } : kind === 'history' ? { server_id: 'a', check_id: id, results: [result] } : summary()));
    await pending;
    assert.equal(h.client.data, null); assert.equal(h.client.pending, null);
    assert.equal(h.element('checkDialog').open, false); assert.equal(list.children.length, 0);
  }
});
test('CAS and uncertain saves require reopening instead of retrying an old snapshot', async () => {
  for (const status of [409, 503]) {
    const h = harness((url, options) => options.method === 'POST' ? reply(status, { error: 'unavailable' }) : null);
    await h.context.checksRefresh(); await h.context.checksOpen('edit', id);
    h.element('checkName').value = 'Edited'; await h.context.checksSubmit(submit);
    assert.equal(h.element('checkName').value, 'Edited'); assert.equal(h.element('checkConfirm').disabled, true);
    await h.context.checksSubmit(submit);
    assert.equal(h.calls.filter((x) => x.options.method === 'POST').length, 1);
    assert.match(h.element('checkDialogError').textContent, /Закройте окно/);
  }
});
test('history captured before a target edit cannot return to the new target cache', async () => {
  let resolve;
  const h = harness((url) => url.includes('/history') ? new Promise((done) => { resolve = done; }) : null);
  await h.context.checksRefresh();
  const list = h.element('oldHistory');
  const history = h.context.checksHistory(id, list);
  await h.context.checksOpen('edit', id);
  h.element('checkUrl').value = 'https://different.example/health';
  await h.context.checksSubmit(submit);
  resolve(reply(200, { server_id: 'a', check_id: id, results: [result] }));
  await history;
  assert.equal(h.client.histories.has(id), false);
  assert.equal(list.children.length, 0);
});
test('null history entry is rejected before caching and cannot break the next refresh', async () => {
  const h = harness((url) => url.includes('/history') ? reply(200, { server_id: 'a', check_id: id, results: [null] }) : null);
  await h.context.checksRefresh();
  const list = h.element('history'); await h.context.checksHistory(id, list);
  assert.equal(h.client.histories.has(id), false);
  assert.match(list.children[0].textContent, /Неверная запись истории/);
  assert.doesNotThrow(() => h.context.checksRender());
});
test('a failed summary invalidates history even when the next configuration revision changes', async () => {
  let status = 200, revision = 7;
  const h = harness((url) => url.includes('/history') ? reply(200, { server_id: 'a', check_id: id, results: [result] })
    : reply(status, status === 200 ? { ...summary(), revision } : { error: 'unavailable' }));
  await h.context.checksRefresh(); await h.context.checksHistory(id, h.element('history'));
  assert.equal(h.client.histories.has(id), true);
  const epoch = h.client.historyEpoch;
  status = 503; await h.context.checksRefresh();
  assert.equal(h.client.data, null); assert.equal(h.client.histories.has(id), false);
  assert.ok(h.client.historyEpoch > epoch);
  status = 200; revision = 8; await h.context.checksRefresh();
  assert.equal(h.client.data.revision, 8); assert.equal(h.client.histories.has(id), false);
});
test('manual run binds current revision; old Hub is explained without breaking overview', async () => {
  const h = harness(); await h.context.checksRefresh(); await h.context.checksRun(id);
  const call = h.calls.find((x) => x.options.method === 'POST');
  assert.equal(call.url, `https://hub.example/api/v1/servers/a/checks/${id}/run`);
  assert.equal(JSON.parse(call.options.body).revision, 7);
  const old = harness(() => reply(404, { error: 'Not found' })); await old.context.checksRefresh();
  assert.match(old.element('checksError').textContent, /Обновите Hub/); assert.equal(old.element('checksAdd').disabled, true);
});
test('container and offline shell include both check assets', () => {
  for (const file of ['index.html', 'sw.js', 'Dockerfile']) {
    const content = fs.readFileSync(file, 'utf8'); assert.match(content, /checks\.js/); assert.match(content, /checks\.css/);
  }
});

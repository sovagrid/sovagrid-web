/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

function harness() {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      value: '', hidden: false, textContent: '',
      addEventListener() {}, replaceChildren() {}, setAttribute() {},
    });
    return elements.get(id);
  };
  const context = vm.createContext({
    URL, AbortController, setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    location: new URL('http://127.0.0.1:8766/'), navigator: {},
  });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  return { render: (clock, online = true) => context.renderClock(clock, online), element };
}

test('clock panel shows UTC and warns for unsynchronized 165-second RTC difference', () => {
  const h = harness();
  h.render({ system_utc_epoch: 1800000000, timezone: 'Etc/UTC', ntp_synchronized: false,
    rtc_local_time: false, rtc_utc_epoch: 1800000165, rtc_offset_seconds: 165 });
  assert.equal(h.element('clockUtcValue').textContent, '2027-01-15 08:00:00 UTC');
  assert.equal(h.element('clockSyncValue').textContent, 'Нет синхронизации');
  assert.equal(h.element('clockZoneValue').textContent, 'Etc/UTC');
  assert.equal(h.element('clockRtcOffsetValue').textContent, '+165 с · RTC впереди');
  assert.equal(h.element('clockWarning').hidden, false);
  assert.match(h.element('clockWarning').textContent, /NTP.*RTC.*165/);
});

test('missing RTC is unknown and a synchronized clock clears a previous warning', () => {
  const h = harness();
  h.render({ system_utc_epoch: 1800000000, ntp_synchronized: false });
  assert.equal(h.element('clockWarning').hidden, false);
  h.render({ system_utc_epoch: 1800000000, timezone: 'UTC', ntp_synchronized: true,
    rtc_offset_seconds: null });
  assert.equal(h.element('clockSyncValue').textContent, 'Синхронизировано');
  assert.equal(h.element('clockRtcOffsetValue').textContent, 'Недоступно');
  assert.equal(h.element('clockWarning').hidden, true);
  assert.equal(h.element('clockWarning').textContent, '');
  h.render(null);
  assert.equal(h.element('clockUtcValue').textContent, '—');
  assert.equal(h.element('clockSyncValue').textContent, 'Неизвестно');
});

test('stale report is labeled and timezone is added only as text', () => {
  const h = harness();
  h.render({ system_utc_epoch: 1800000000, timezone: '<img src=x>', ntp_synchronized: false,
    rtc_offset_seconds: -30 }, false);
  assert.equal(h.element('clockZoneValue').textContent, '—');
  assert.equal(h.element('clockRtcOffsetValue').textContent, '−30 с · RTC позади');
  assert.match(h.element('clockWarning').textContent, /По последнему отчёту/);
  assert.ok(fs.readFileSync('index.html', 'utf8').includes('id="clockWarning"'));
});

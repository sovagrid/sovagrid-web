/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

function themeHarness(saved = null, dark = true) {
  const listeners = new Map(), mediaListeners = new Map(), events = [], writes = [];
  const selects = [{ value: '' }, { value: '' }, { value: '' }];
  const meta = { 'theme-color': { value: '', setAttribute(_name, value) { this.value = value; } },
    'color-scheme': { value: '', setAttribute(_name, value) { this.value = value; } } };
  const media = { matches: dark, addEventListener(name, listener) { mediaListeners.set(name, listener); } };
  class CustomEvent { constructor(type, options) { this.type = type; this.detail = options.detail; } }
  const document = { documentElement: { dataset: {} },
    querySelector(selector) { return meta[selector.match(/name="([^"]+)"/)?.[1]] || null; },
    querySelectorAll(selector) { return selector === '[data-theme-select]' ? selects : []; },
    addEventListener(name, listener) { listeners.set(name, listener); } };
  const context = vm.createContext({ document, CustomEvent,
    localStorage: { getItem: () => saved, setItem: (key, value) => writes.push([key, value]) },
    matchMedia: () => media, addEventListener() {}, dispatchEvent: (event) => events.push(event) });
  vm.runInContext(fs.readFileSync('theme.js', 'utf8'), context);
  listeners.get('DOMContentLoaded')();
  return { context, document, selects, meta, media, events, writes,
    choose: (value) => listeners.get('change')({ target: { value, matches: (selector) => selector === '[data-theme-select]' } }),
    systemDark: (value) => { media.matches = value; mediaListeners.get('change')(); } };
}

test('saved theme is restored on load and selector changes synchronize every control', () => {
  const h = themeHarness('light', true);
  assert.equal(h.document.documentElement.dataset.theme, 'light');
  assert.deepEqual(h.selects.map((item) => item.value), ['light', 'light', 'light']);
  assert.equal(h.meta['theme-color'].value, '#f3f7f5');
  h.choose('dark');
  assert.deepEqual(h.writes, [['sovagrid.theme', 'dark']]);
  assert.deepEqual(h.selects.map((item) => item.value), ['dark', 'dark', 'dark']);
  assert.equal(h.meta['color-scheme'].value, 'dark');
});

test('system choice follows live OS light and dark changes without a reload', () => {
  const h = themeHarness('system', true);
  assert.equal(h.document.documentElement.dataset.theme, 'dark');
  h.systemDark(false);
  assert.equal(h.document.documentElement.dataset.theme, 'light');
  assert.equal(h.document.documentElement.dataset.themeChoice, 'system');
  assert.equal(h.events.at(-1).detail.resolved, 'light');
  h.choose('dark');
  h.systemDark(false);
  assert.equal(h.document.documentElement.dataset.theme, 'dark');
  assert.equal(h.writes.length, 1, 'OS changes should not rewrite a saved preference');
});

test('unexpected stored value falls back to system and CSS keeps the native media query', () => {
  const h = themeHarness('unexpected', false);
  assert.equal(h.document.documentElement.dataset.themeChoice, 'system');
  assert.equal(h.document.documentElement.dataset.theme, 'light');
  assert.match(fs.readFileSync('theme.css', 'utf8'), /@media \(prefers-color-scheme: light\)[\s\S]*?:root\[data-theme-choice="system"\] \{ color-scheme: light; \}/);
});

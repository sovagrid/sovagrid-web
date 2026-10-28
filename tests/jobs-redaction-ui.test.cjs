/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

function harness(jobs) {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, { textContent: '', hidden: false, disabled: false,
      children: [], addEventListener() {}, setAttribute() {},
      append(...nodes) { this.children.push(...nodes); },
      replaceChildren(...nodes) { this.children = nodes; } });
    return elements.get(id);
  };
  const reply = (value) => ({ ok: true, status: 200, text: async () => JSON.stringify(value) });
  const context = vm.createContext({ URL, AbortController, setTimeout, clearTimeout,
    setInterval: () => 1, clearInterval() {},
    document: { getElementById: element, createElement: () => element(Symbol()),
      querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    navigator: {}, location: { protocol: 'file:' },
    fetch: (url) => {
      if (url.endsWith('/servers')) return Promise.resolve(reply({ servers: [{ id: 'server-A', name: 'A' }] }));
      if (url.endsWith('/incidents')) return Promise.resolve(reply({ incidents: [] }));
      if (url.endsWith('/jobs')) return Promise.resolve(reply({ jobs }));
      throw new Error(`unexpected request: ${url}`);
    } });
  vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);
  const state = vm.runInContext('state', context);
  Object.assign(state, { base: 'https://hub.example', token: 'session-A',
    selectedId: 'server-A', view: 'commands', firstLoad: false });
  context.renderSidebar = () => {};
  context.renderWorkspace = () => {};
  context.renderServer = () => {};
  const visible = (node) => [node.textContent, ...node.children.map(visible)].join(' ');
  return { context, state, element, visible };
}

test('generic jobs refresh redacts AWG3 intent before state and DOM', async () => {
  const handle = Buffer.alloc(32, 7).toString('base64url');
  const h = harness([
    { id: 'intent-job', server_id: 'server-A', state: 'succeeded',
      created_at: 1793000000, exit_code: 0,
      output: JSON.stringify({ target: 'awg2', action: 'settings_intent', confirmation_id: handle }) },
    { id: 'normal-job', server_id: 'server-A', state: 'succeeded',
      created_at: 1793000001, exit_code: 0, output: 'ordinary result' },
  ]);
  await h.context.refresh();
  assert.equal(h.state.jobs.length, 2);
  assert.equal(h.state.jobs[0].output, null);
  assert.equal(h.state.jobs[0].awg_settings_redacted, true);
  assert.equal(h.state.jobs[1].output, 'ordinary result');
  assert.ok(!JSON.stringify(h.state.jobs).includes(handle));
  assert.ok(!h.visible(h.element('jobsList')).includes(handle));
  assert.match(h.visible(h.element('jobsList')), /ordinary result/);
});

test('future apply commands and malformed intent output stay private in generic history', async () => {
  const handle = Buffer.alloc(32, 9).toString('base64url');
  const jobs = [
    { id: 'apply-job', server_id: 'server-A', state: 'succeeded',
      created_at: 1793000000, exit_code: 0,
      command: `settings-apply --confirmation-id ${handle}`, output: handle },
    { id: 'intent-malformed', server_id: 'server-A', state: 'succeeded',
      created_at: 1793000001, exit_code: 0,
      command: 'settings-intent', output: `malformed response ${handle}` },
  ];
  const h = harness(jobs);
  await h.context.refresh();
  assert.equal(h.state.jobs.length, 2);
  assert.ok(h.state.jobs.every((job) => job.awg_settings_redacted && job.output === null));
  assert.ok(!JSON.stringify(h.state.jobs).includes(handle));
  assert.ok(!h.visible(h.element('jobsList')).includes(handle));
  h.state.jobs = jobs;
  h.context.renderJobs();
  assert.ok(!h.visible(h.element('jobsList')).includes(handle),
    'the DOM guard also covers direct jobs state assignments');
});

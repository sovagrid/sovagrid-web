/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ../ATTRIBUTION.md. */
const assert = require("node:assert/strict");
const { createHash, webcrypto } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

const ID = "b".repeat(32), OP = "c".repeat(32), FP = "SHA256:" + "A".repeat(43);
class Element {
  constructor() { this.value = ""; this.checked = false; this.hidden = false; this.disabled = false;
    this.textContent = ""; this.open = false; this.listeners = {}; this.children = []; }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  showModal() { this.open = true; }
  close() { this.open = false; this.listeners.close?.(); }
}
function setup() {
  const elements = new Map(), storage = new Map(), calls = [], slices = [], released = [];
  const get = (id) => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  const raw = { host_manifest: Buffer.from("{}\n"), host: Buffer.alloc(4194304 + 17, 0x5a),
    images_manifest: Buffer.from("{}\n"), images: Buffer.from([0, 10, 255, 13, 10]) };
  raw.receipt = Buffer.from(JSON.stringify({ protocol: "sovagrid-portable-host-receipt-v2", host_archive_id: ID,
    host_archive_sha256: createHash("sha256").update(raw.host).digest("hex"),
    images_sha256: createHash("sha256").update(raw.images).digest("hex") }));
  const names = { host_manifest: `${ID}.manifest.json`, host: `${ID}.tar.gz`,
    images_manifest: "manifest.json", images: "images.tar", receipt: "receipt.json" };
  const virtualFiles = () => Object.entries(raw).map(([part, data]) => ({ name: names[part], size: data.length,
    slice(start, end) { slices.push({ part, start, end });
      return { arrayBuffer: async () => Uint8Array.from(data.subarray(start, end)).buffer }; },
    release() { released.push(part); } }));
  let uploaded = null, statusReply = null;
  const fetchImpl = async (url, options) => {
    const action = url.split("/").at(-1); calls.push(action);
    if (action === "status" && statusReply) return statusReply();
    let value;
    if (action === "import-init") {
      const request = JSON.parse(options.body);
      if (!uploaded) uploaded = { protocol: "sovagrid-web-restore-v1", source_id: request.source_id,
        archive_id: request.archive_id, max_chunk_bytes: 4194304, pending_chunk: null, complete: false,
        artifacts: Object.fromEntries(Object.entries(request.artifacts).map(([key, item]) =>
          [key, { ...item, received: 0, complete: false }])) };
      assert.equal(request.source_id, uploaded.source_id);
      value = uploaded;
    } else if (action === "import-chunk") {
      const metadata = JSON.parse(decodeURIComponent(options.headers["X-SovaGrid-Restore-Meta"]));
      const body = Buffer.from(options.body);
      assert.ok(body.length <= 4194304);
      assert.equal(metadata.sha256, createHash("sha256").update(body).digest("hex"));
      assert.deepEqual(body, raw[metadata.part].subarray(metadata.offset, metadata.offset + metadata.length));
      const item = uploaded.artifacts[metadata.part];
      assert.equal(item.received, metadata.offset); item.received += body.length; item.complete = item.received === item.bytes;
      uploaded.complete = Object.values(uploaded.artifacts).every((item) => item.complete);
      value = uploaded;
    } else throw new Error("unexpected route " + action);
    return { ok: true, text: async () => JSON.stringify(value) };
  };
  const window = { addEventListener() {} };
  const context = vm.createContext({ console, window, crypto: webcrypto, Uint8Array, ArrayBuffer,
    TextEncoder, TextDecoder, AbortController, setTimeout, clearTimeout, setInterval: () => 0,
    location: { origin: "https://panel.example.com", protocol: "https:" },
    state: { base: "https://panel.example.com", token: "t".repeat(43), user: { role: "admin" },
      access: { unrestricted_admin: true }, view: "settings" },
    serverSetupAllowed: () => true, $: get, bytes: (value) => String(value), confirm: () => false,
    fetch: (...args) => fetchImpl(...args), request: async () => {},
    localStorage: { getItem: (key) => storage.get(key) || null, setItem: (key, value) => storage.set(key, value),
      removeItem: (key) => storage.delete(key) },
    document: { createElement: () => new Element() } });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../host-restore.js"), "utf8"), context);
  get("hostRestoreDialog").open = true;
  vm.runInContext("hostRestore.openedView = 'settings'", context);
  for (const prefix of ["hostRestoreTarget", "hostRestoreJump"]) {
    get(prefix + "Method").value = "password"; get(prefix + "Port").value = "22";
    get(prefix + "Host").value = "server.example.com"; get(prefix + "Username").value = "root";
  }
  return { context, get, calls, storage, slices, released, virtualFiles,
    setStatus(callback) { statusReply = callback; },
    run: (source) => vm.runInContext(source, context),
    choose(files) { context.selectedFiles = files; return vm.runInContext("hostRestoreChooseFiles(selectedFiles)", context); } };
}

test("plain virtual files stream a backup larger than ordinary native upload limit in bounded slices", async () => {
  const app = setup();
  await app.choose([]);
  assert.equal(app.get("hostRestoreError").hidden, false);
  await app.choose(app.virtualFiles());
  assert.equal(app.run("hostRestore.upload.complete"), true);
  assert.equal(app.run("hostRestore.source.kind"), "upload");
  assert.equal(app.run("hostRestore.files"), null);
  assert.ok(app.slices.every(({ start, end }) => end - start <= 4194304));
  assert.equal(app.calls.filter((name) => name === "import-chunk").length, 6);
  assert.equal(app.released.length, 5);
  assert.equal(app.get("hostRestoreError").hidden, true);
  const stored = [...app.storage.values()].join(" ");
  assert.doesNotMatch(stored, /password|private_key|PRIVATE KEY/);
  app.run("hostRestoreReset()");
});

test("late poll of an old operation cannot replace a newly selected uploaded source", async () => {
  const app = setup();
  let resolve;
  app.setStatus(() => new Promise((done) => { resolve = done; }));
  app.run(`hostRestore.active = { operation_id: '${OP}' }`);
  const poll = app.run("hostRestorePoll()");
  await app.choose(app.virtualFiles());
  resolve({ ok: true, text: async () => JSON.stringify({ protocol: "sovagrid-web-restore-v1", operation_id: OP }) });
  await poll;
  assert.equal(app.run("hostRestore.active"), null);
  assert.equal(app.run("hostRestore.source.kind"), "upload");
  app.run("hostRestoreReset()");
});

test("reselecting files for an older selected operation preserves its source and operation IDs", async () => {
  const app = setup();
  const source = "f".repeat(32);
  app.run(`hostRestore.source = { kind:'upload',id:'${source}' };
    hostRestore.active = { operation_id:'${OP}',archive_id:'${ID}',source:hostRestore.source,
      route:{ username:'root',host:'server.example.com',port:22 },phase:'resume_required' };
    hostRestoreUploadMarker({ source_id:'${"e".repeat(32)}',archive_id:'${"d".repeat(32)}' });`);
  await app.choose(app.virtualFiles());
  assert.equal(app.run("hostRestore.source.id"), source);
  assert.equal(app.run("hostRestore.active.operation_id"), OP);
  assert.equal(app.run("hostRestore.active.target"), null);
  assert.equal(app.run("hostRestore.upload.complete"), true);
  app.run("hostRestoreReset()");
});

test("key-file completion after logout/close cannot put a private key back into the hidden form", async () => {
  const app = setup();
  let resolve;
  const file = { size: 20, slice() { return { arrayBuffer: () => new Promise((done) => { resolve = done; }) }; } };
  const completion = app.get("hostRestoreTargetKeyFile").listeners.change({ target: { files: [file] } });
  app.run("hostRestoreReset()");
  resolve(new TextEncoder().encode("private-key-contents").buffer);
  await completion;
  assert.equal(app.get("hostRestoreTargetPrivateKey").value, "");
});

test("closing the wizard clears the displayed trust proof together with the SSH pin", () => {
  const app = setup();
  app.get("hostRestoreTargetTrust").checked = app.get("hostRestoreJumpTrust").checked = true;
  app.get("hostRestoreTargetFingerprint").textContent = app.get("hostRestoreJumpFingerprint").textContent = FP;
  app.run(`hostRestore.targetPin = { fingerprint:'${FP}' }; hostRestore.jumpPin = { fingerprint:'${FP}' }; hostRestoreReset()`);
  for (const prefix of ["hostRestoreTarget", "hostRestoreJump"]) {
    assert.equal(app.get(prefix + "Trust").checked, false);
    assert.equal(app.get(prefix + "Fingerprint").textContent, "");
  }
  assert.equal(app.run("hostRestore.targetPin"), null);
  assert.equal(app.run("hostRestore.jumpPin"), null);
});

test("native picker completion after closing and reopening releases grants without selecting an old source", async () => {
  const app = setup();
  let resolve;
  app.context.window.sovagridNativeRestore = { pickFiles: () => new Promise((done) => { resolve = done; }) };
  const completion = app.get("hostRestoreNativePick").listeners.click();
  app.run("hostRestoreReset(); hostRestore.openedView = 'settings'");
  app.get("hostRestoreDialog").open = true;
  resolve(app.virtualFiles());
  await completion;
  assert.deepEqual(app.calls, []);
  assert.equal(app.released.length, 5);
  app.run("hostRestoreReset()");
});

test("separate rejected confirmation emits no privileged start request", async () => {
  const app = setup();
  app.get("hostRestoreTargetTrust").checked = true;
  app.get("hostRestoreTargetPassword").value = "memory-only-password";
  app.run(`hostRestore.targetPin = { host:'server.example.com',port:22,fingerprint:'${FP}' };
    hostRestore.active = { operation_id:'${OP}', expected_revision:'${"e".repeat(64)}',
      route:{host:'server.example.com',port:22,username:'root',fingerprint:'${FP}'},
      target:{ apply_available:true,apply_review_sha256:'${"d".repeat(64)}' } };`);
  await app.run("hostRestoreControl('start')");
  assert.deepEqual(app.calls, []);
  app.run("hostRestoreReset()");
});

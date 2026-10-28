/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ../../ATTRIBUTION.md. */
"use strict";

import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import test from "node:test";
import ssh2 from "ssh2";
import { createHandler, hostKey, inspectHostKey, inspectTargetHostKey, issueGrant,
  previewAmneziaSetup, probeTargetStatus, requireUnrestrictedAdmin, safeAmneziaPreview,
  validateAmneziaPreview, validateLogin, validateTargetHostKey, validateTargetStatus } from "../server.js";

function wireKey() {
  const type = Buffer.from("ssh-ed25519");
  const key = Buffer.alloc(32, 0x2a);
  const result = Buffer.alloc(4 + type.length + 4 + key.length);
  result.writeUInt32BE(type.length, 0);
  type.copy(result, 4);
  result.writeUInt32BE(key.length, 4 + type.length);
  key.copy(result, 8 + type.length);
  return result;
}

const KEY = wireKey();
const FINGERPRINT = "SHA256:" + createHash("sha256").update(KEY).digest("base64").replace(/=+$/, "");
const GRANT = "a".repeat(43);
const TOKEN = "t".repeat(43);
const PREVIEW = { schema_version: 1, action: "preview", writes: false,
  selected_target: "awg2", marker: "absent", other_marker: "absent",
  socket_active: false, service_active: false, installer_ready: true,
  installed_current: false, can_arm: false,
  target: { ready: false, reason: "AWG2 is not enrolled" } };

function previewInput(overrides = {}) {
  return { username: "root", method: "password", fingerprint: FINGERPRINT,
    password: "server-secret", private_key: "", passphrase: "", target: "awg2", ...overrides };
}

function statusInput(overrides = {}) {
  return { host: "REMOTE.example", port: 22022, username: "root", method: "password",
    fingerprint: FINGERPRINT, password: "server-secret", private_key: "", passphrase: "", ...overrides };
}

test("real SSH handshake checks the host key before any password is sent", async () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" } });
  let passwordAuthentications = 0;
  let commands = 0;
  let statusCommands = 0;
  const server = new ssh2.Server({ hostKeys: [privateKey] }, (client) => {
    client.on("error", () => {}); // A rejected host key closes KEX by design.
    client.on("authentication", (ctx) => {
      if (ctx.method === "password") passwordAuthentications++;
      if (ctx.method === "password" && ctx.username === "root" && ctx.password === "secret") ctx.accept();
      else ctx.reject();
    }).on("ready", () => {
      client.on("session", (accept) => {
        const session = accept();
        session.on("exec", (accept, _reject, info) => {
          const channel = accept();
          if (info.command.endsWith(" ssh-grant")) {
            commands++;
            channel.write(JSON.stringify({ protocol: 1, grant: GRANT,
              expires_at: Math.floor(Date.now() / 1000) + 60, username: "admin" }));
            channel.exit(0);
            channel.end();
          } else {
            statusCommands++;
            assert.match(info.command, /^sh -c '/);
            let script = "";
            channel.on("data", (chunk) => { script += chunk.toString("utf8"); });
            channel.on("end", () => {
              assert.match(script, /SOVAGRID_SSH_STATUS_V1/);
              channel.write("SG_STATUS_V1:missing\n");
              channel.exit(0);
              channel.end();
            });
          }
        });
      });
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const clientFactory = () => {
    const client = new ssh2.Client();
    const result = {
      on(event, callback) { client.on(event, callback); return result; },
      end() { client.end(); },
      exec(...args) { client.exec(...args); },
      connect(options) {
        client.connect({ ...options, host: "127.0.0.1", port: server.address().port });
      },
    };
    return result;
  };
  try {
    const key = await inspectHostKey({ clientFactory });
    assert.match(key.fingerprint, /^SHA256:/);
    assert.equal(passwordAuthentications, 0);
    const targetKey = await inspectTargetHostKey({ host: "remote.example", port: 22022 },
      { clientFactory });
    assert.equal(targetKey.fingerprint, key.fingerprint);
    assert.equal(targetKey.scope, "entered_target");
    assert.equal(targetKey.reverify_required, true);
    assert.equal(passwordAuthentications, 0);
    const raw = { username: "root", method: "password", fingerprint: "SHA256:" + "B".repeat(43),
      password: "secret", private_key: "", passphrase: "" };
    await assert.rejects(issueGrant(raw, { clientFactory }), /HOST_KEY_CHANGED/);
    assert.equal(passwordAuthentications, 0);
    await assert.rejects(probeTargetStatus(statusInput({ fingerprint: raw.fingerprint,
      password: "secret" }), { clientFactory }), /HOST_KEY_CHANGED/);
    assert.equal(passwordAuthentications, 0);
    assert.equal(statusCommands, 0);
    const result = await issueGrant({ ...raw, fingerprint: key.fingerprint }, { clientFactory });
    assert.equal(result.grant, GRANT);
    const status = await probeTargetStatus(statusInput({ fingerprint: key.fingerprint,
      password: "secret" }), { clientFactory });
    assert.equal(status.kind, "missing");
    assert.equal(status.host_key_fingerprint, key.fingerprint);
    assert.equal(passwordAuthentications, 2);
    assert.equal(commands, 1);
    assert.equal(statusCommands, 1);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

function fakeClient(operations, { key = KEY, output, code = 0 } = {}) {
  const client = new EventEmitter();
  client.end = () => { operations.ended = true; };
  client.connect = (config) => {
    operations.config = config;
    queueMicrotask(() => {
      const trusted = config.hostVerifier(key);
      if (trusted) client.emit("ready");
      else client.emit("error", new Error("rejected"));
    });
  };
  client.exec = (command, options, callback) => {
    operations.command = command;
    operations.options = options;
    const stream = new EventEmitter();
    stream.stderr = new EventEmitter();
    const send = () => {
      stream.emit("data", Buffer.from(output ?? JSON.stringify({
        protocol: 1, grant: GRANT, expires_at: Math.floor(Date.now() / 1000) + 60,
        username: "admin",
      })));
      stream.emit("close", code, null);
    };
    stream.end = (script) => { operations.script = script; queueMicrotask(send); };
    callback(null, stream);
    if (!command.startsWith("sh -c '")) queueMicrotask(send);
  };
  return client;
}

test("host key is inspected without any SSH authentication", async () => {
  const operations = {};
  const result = await inspectHostKey({ clientFactory: () => fakeClient(operations) });
  assert.deepEqual(result, { protocol: 1, port: 22, key_type: "ssh-ed25519",
    fingerprint: FINGERPRINT });
  assert.equal(operations.config.host, "172.30.253.1");
  assert.equal(operations.config.username, "sovagrid-probe");
  assert.equal(operations.config.password, undefined);
  assert.equal(operations.command, undefined);
  assert.equal(operations.ended, true);
  assert.throws(() => hostKey(Buffer.alloc(0)), /Invalid SSH host key/);
});

test("entered target host key accepts an explicit IP or hostname but no URL or credentials", async () => {
  assert.deepEqual(validateTargetHostKey({ host: "EXAMPLE.org", port: 22022 }),
    { host: "example.org", port: 22022 });
  assert.deepEqual(validateTargetHostKey({ host: "198.51.100.7", port: 22 }),
    { host: "198.51.100.7", port: 22 });
  assert.deepEqual(validateTargetHostKey({ host: "2001:db8::1", port: 22 }),
    { host: "2001:db8::1", port: 22 });
  for (const host of ["", " example.org", "example.org ", "https://example.org", "user@example.org",
    "example.org:22", "example..org", "-example.org", "example.org/", "[2001:db8::1]",
    "fe80::1%eth0", "127.1", "2130706433", "a\n.example.org", "я.example.org",
    "a".repeat(64) + ".example.org"]) {
    assert.throws(() => validateTargetHostKey({ host, port: 22 }), /INVALID_INPUT/, host);
  }
  for (const port of [0, -1, 65536, "22", 22.5, null]) {
    assert.throws(() => validateTargetHostKey({ host: "example.org", port }), /INVALID_INPUT/);
  }
  assert.throws(() => validateTargetHostKey({ host: "example.org", port: 22,
    password: "secret" }), /INVALID_INPUT/);
  const operations = {};
  const result = await inspectTargetHostKey({ host: "REMOTE.example", port: 22022 },
    { clientFactory: () => fakeClient(operations) });
  assert.deepEqual(result, { protocol: 1, scope: "entered_target", host: "remote.example",
    port: 22022, key_type: "ssh-ed25519", fingerprint: FINGERPRINT,
    reverify_required: true });
  assert.equal(operations.config.host, "remote.example");
  assert.equal(operations.config.port, 22022);
  assert.equal(operations.config.username, "sovagrid-probe");
  assert.equal(operations.config.password, undefined);
  assert.equal(operations.config.privateKey, undefined);
  assert.equal(operations.config.tryKeyboard, false);
  assert.equal(operations.command, undefined);
  assert.equal(operations.ended, true);
});

test("entered target host-key probe times out without trying authentication", async () => {
  const operations = {};
  const client = new EventEmitter();
  client.connect = (config) => { operations.config = config; };
  client.end = () => { operations.ended = true; };
  await assert.rejects(inspectTargetHostKey({ host: "remote.example", port: 22 },
    { clientFactory: () => client, timeoutMs: 10 }), /SSH_UNAVAILABLE/);
  assert.equal(operations.config.password, undefined);
  assert.equal(operations.ended, true);
});

test("target status accepts only explicit SSH credentials and a pinned target", () => {
  assert.deepEqual(validateTargetStatus(statusInput()), statusInput({ host: "remote.example" }));
  for (const invalid of [
    { host: "https://remote.example" }, { host: "user@remote.example" }, { port: "22" },
    { username: "root; id" }, { fingerprint: "SHA256:invalid" },
    { method: "password", password: "" }, { method: "private_key", private_key: "" },
    { extra: "id" },
  ]) assert.throws(() => validateTargetStatus(statusInput(invalid)), /INVALID_INPUT/);
  assert.throws(() => validateTargetStatus(statusInput({ method: "keyboard_interactive" })),
    /UNSUPPORTED_AUTH_METHOD/);
  assert.throws(() => validateTargetStatus(statusInput({ method: "two_factor" })),
    /UNSUPPORTED_AUTH_METHOD/);
});

test("target status runs only the fixed read-only inventory after host-key verification", async () => {
  const operations = {};
  const raw = statusInput();
  const result = await probeTargetStatus(raw, { clientFactory: () => fakeClient(operations,
    { output: "SG_STATUS_V1:agent_only\n" }) });
  assert.deepEqual(result, { protocol: 1, scope: "entered_target", host: "remote.example",
    port: 22022, kind: "agent_only", host_key_fingerprint: FINGERPRINT });
  assert.equal(operations.config.host, "remote.example");
  assert.equal(operations.config.port, 22022);
  assert.equal(operations.config.password, "server-secret");
  assert.equal(operations.config.tryKeyboard, false);
  assert.match(operations.command, /^sh -c '/);
  assert.doesNotMatch(operations.command, /remote\.example|server-secret|22022/);
  assert.match(operations.script, /SOVAGRID_SSH_STATUS_V1/);
  assert.match(operations.script, /'missing'/);
  assert.deepEqual(operations.options, { pty: false });
  assert.equal(raw.password, "");
  assert.equal(operations.ended, true);

  const keyOps = {};
  const keyInput = statusInput({ method: "private_key", password: "",
    private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n", passphrase: "phrase" });
  await probeTargetStatus(keyInput, { clientFactory: () => fakeClient(keyOps,
    { output: "SG_STATUS_V1:managed\n" }) });
  assert.equal(keyOps.config.privateKey.every((byte) => byte === 0), true);
  assert.equal(keyInput.private_key, "");
  assert.equal(keyInput.passphrase, "");
});

test("target status maps untrusted output to a coarse kind and rejects a changed key", async () => {
  for (const output of ["SG_STATUS_V1:missing\nextra", "root:x:0:0", "SG_STATUS_V1:missing\nSG_STATUS_V1:managed\n"]) {
    const operations = {};
    const result = await probeTargetStatus(statusInput(), { clientFactory: () => fakeClient(operations,
      { output }) });
    assert.equal(result.kind, "unknown");
    assert.doesNotMatch(JSON.stringify(result), /root:x|extra/);
  }
  const failed = await probeTargetStatus(statusInput(), { clientFactory: () => fakeClient({},
    { output: "SG_STATUS_V1:missing\n", code: 2 }) });
  assert.equal(failed.kind, "unknown");
  const tooLarge = {};
  await assert.rejects(probeTargetStatus(statusInput(), { clientFactory: () => fakeClient(tooLarge,
    { output: "x".repeat(513) }) }), /STATUS_UNAVAILABLE/);
  assert.equal(tooLarge.ended, true);
  const changed = {};
  const raw = statusInput({ fingerprint: "SHA256:" + "B".repeat(43) });
  await assert.rejects(probeTargetStatus(raw, { clientFactory: () => fakeClient(changed,
    { output: "SG_STATUS_V1:missing\n" }) }), /HOST_KEY_CHANGED/);
  assert.equal(changed.command, undefined);
  assert.equal(changed.ended, true);
  assert.equal(raw.password, "");
});

test("target status bounds a stalled SSH command and clears its credentials", async () => {
  const operations = {};
  const client = new EventEmitter();
  client.connect = (config) => {
    operations.config = config;
    queueMicrotask(() => {
      assert.equal(config.hostVerifier(KEY), true);
      client.emit("ready");
    });
  };
  client.exec = (_command, _options, callback) => {
    const stream = new EventEmitter();
    stream.stderr = new EventEmitter();
    stream.end = () => {};
    stream.close = () => { operations.channelClosed = true; };
    callback(null, stream);
  };
  client.end = () => { operations.ended = true; };
  const raw = statusInput();
  await assert.rejects(probeTargetStatus(raw, { clientFactory: () => client, timeoutMs: 10 }),
    /STATUS_UNAVAILABLE/);
  assert.equal(operations.channelClosed, true);
  assert.equal(operations.ended, true);
  assert.equal(raw.password, "");
});

test("correctly pinned password SSH grants only the fixed local Hub command", async () => {
  const operations = {};
  const result = await issueGrant({ username: "root", method: "password", fingerprint: FINGERPRINT,
    password: "server-secret", private_key: "", passphrase: "" },
  { clientFactory: () => fakeClient(operations) });
  assert.equal(result.grant, GRANT);
  assert.equal(operations.config.port, 22);
  assert.equal(operations.config.password, "server-secret");
  assert.equal(operations.config.tryKeyboard, true);
  assert.match(operations.command, /^\/usr\/bin\/docker compose /);
  assert.match(operations.command, / ssh-grant$/);
  assert.deepEqual(operations.options, { pty: false });
  assert.equal(operations.ended, true);
});

test("key SSH supports a passphrase and sudo, and rejects a changed host key", async () => {
  const operations = {};
  const raw = { username: "operator", method: "private_key", fingerprint: FINGERPRINT,
    password: "", private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n", passphrase: "key-password" };
  await issueGrant(raw, { clientFactory: () => fakeClient(operations) });
  assert.match(operations.command, /^\/usr\/bin\/sudo -n -- \/usr\/bin\/docker compose /);
  assert.equal(operations.config.passphrase, "key-password");
  assert.equal(operations.config.privateKey.every((byte) => byte === 0), true);
  const changed = { ...raw, fingerprint: "SHA256:" + "A".repeat(43) };
  const rejected = {};
  await assert.rejects(issueGrant(changed, { clientFactory: () => fakeClient(rejected) }),
    /HOST_KEY_CHANGED/);
  assert.equal(rejected.command, undefined);
  assert.equal(rejected.ended, true);
});

test("invalid credentials and fabricated grants do not issue a session", async () => {
  assert.throws(() => validateLogin({ username: "root; echo x" }), /INVALID_INPUT/);
  const raw = { username: "root", method: "password", fingerprint: FINGERPRINT,
    password: "secret", private_key: "", passphrase: "" };
  const operations = {};
  await assert.rejects(issueGrant(raw, { clientFactory: () => fakeClient(operations,
    { output: JSON.stringify({ protocol: 1, grant: "bad", expires_at: 0, username: "admin" }) }) }),
  /GRANT_UNAVAILABLE/);
  assert.equal(operations.ended, true);
});

async function call(handler, { path = "/api/v1/browser-ssh/host-key", payload = {},
  chunks, headers = {} } = {}) {
  const request = Readable.from(chunks ?? [Buffer.from(JSON.stringify(payload))]);
  request.method = "POST";
  request.url = path;
  request.headers = { host: "example.com", origin: "https://example.com",
    "x-forwarded-proto": "https", "x-sovagrid-client-ip": "203.0.113.17",
    "content-type": "application/json", ...headers };
  request.setTimeout = () => {};
  const result = {};
  const response = { writeHead(status, responseHeaders) {
    result.status = status;
    result.headers = responseHeaders;
  }, end(body) { result.body = JSON.parse(body); }, destroyed: false };
  await handler(request, response);
  return result;
}

test("pre-auth HTTP route refuses cross-site origins and limits credential attempts", async () => {
  let logins = 0;
  const handler = createHandler({ inspect: async () => ({ protocol: 1, fingerprint: FINGERPRINT,
    key_type: "ssh-ed25519", port: 22 }), login: async () => { logins++; throw new Error("AUTH_FAILED"); } });
  const crossSite = await call(handler, { headers: { origin: "https://attacker.example" } });
  assert.equal(crossSite.status, 404);
  assert.equal(logins, 0);
  const header = await call(handler);
  assert.equal(header.status, 200);
  assert.equal(header.headers["Cache-Control"], "no-store");
  for (let attempt = 0; attempt < 5; attempt++) {
    assert.equal((await call(handler, { path: "/api/v1/browser-ssh/login" })).status, 401);
  }
  assert.equal((await call(handler, { path: "/api/v1/browser-ssh/login" })).status, 429);
  assert.equal(logins, 5);
});

test("updater's loopback probe receives the SSH host key without credentials", async () => {
  let inspected = 0;
  const handler = createHandler({ inspect: async () => {
    inspected++;
    return { protocol: 1, port: 22, key_type: "ssh-ed25519", fingerprint: FINGERPRINT };
  }, login: async () => { throw new Error("must not authenticate"); } });
  const result = await call(handler, { headers: {
    host: "127.0.0.1:8766", origin: "http://127.0.0.1:8766",
    "x-forwarded-proto": "http", "x-sovagrid-client-ip": "127.0.0.1",
  } });
  assert.equal(result.status, 200);
  assert.deepEqual(result.body, { protocol: 1, port: 22,
    key_type: "ssh-ed25519", fingerprint: FINGERPRINT });
  assert.equal(inspected, 1);
});

test("Amnezia setup preview validates the exact SSH input and returns only safe fields", async () => {
  assert.deepEqual(validateAmneziaPreview(previewInput()).target, "awg2");
  assert.throws(() => validateAmneziaPreview(previewInput({ target: "awg2; id" })), /INVALID_INPUT/);
  assert.throws(() => validateAmneziaPreview(previewInput({ extra: "command" })), /INVALID_INPUT/);
  assert.throws(() => validateAmneziaPreview(previewInput({ username: "root; id" })), /INVALID_INPUT/);
  const summary = safeAmneziaPreview(JSON.stringify({ ...PREVIEW,
    secret: "must-not-appear", target: { ready: true, container_id: "a".repeat(64),
      configured_clients: 2, owned_clients: ["private-client"], private_key: "must-not-appear" } }), "awg2");
  assert.equal(summary.container_id, "a".repeat(64));
  assert.equal(summary.configured_clients, 2);
  assert.equal(summary.owned_clients, 1);
  assert.doesNotMatch(JSON.stringify(summary), /private-client|private_key|must-not-appear/);
  assert.deepEqual(safeAmneziaPreview(JSON.stringify(PREVIEW), "awg2").reason, "NOT_ENROLLED");
  assert.throws(() => safeAmneziaPreview("{", "awg2"), /SETUP_UNAVAILABLE/);
  assert.throws(() => safeAmneziaPreview(JSON.stringify(PREVIEW), "wireguard"), /SETUP_UNAVAILABLE/);
});

test("Amnezia setup preview runs one fixed local root command after a pinned host-key check", async () => {
  const operations = {};
  const result = await previewAmneziaSetup(previewInput(), { clientFactory: () => fakeClient(operations,
    { output: JSON.stringify(PREVIEW) }) });
  assert.equal(result.reason, "NOT_ENROLLED");
  assert.equal(operations.config.host, "172.30.253.1");
  assert.equal(operations.config.password, "server-secret");
  assert.equal(operations.command,
    "/usr/bin/python3 -I /opt/sovagrid-src/sovagrid-vpn/deploy/install-amnezia-control.py preview --target awg2");
  assert.deepEqual(operations.options, { pty: false });
  assert.equal(operations.ended, true);
  const keyOps = {};
  const keyInput = previewInput({ username: "operator", method: "private_key", password: "",
    private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n", passphrase: "phrase",
    target: "wireguard" });
  await previewAmneziaSetup(keyInput, { clientFactory: () => fakeClient(keyOps,
    { output: JSON.stringify({ ...PREVIEW, selected_target: "wireguard",
      target: { ready: false, reason: "WireGuard is not enrolled" } }) }) });
  assert.equal(keyOps.command,
    "/usr/bin/sudo -n -- /usr/bin/python3 -I /opt/sovagrid-src/sovagrid-vpn/deploy/install-amnezia-control.py preview --target wireguard");
  assert.equal(keyOps.config.privateKey.every((byte) => byte === 0), true);
  assert.equal(keyOps.ended, true);
  const changed = {};
  await assert.rejects(previewAmneziaSetup(previewInput({ fingerprint: "SHA256:" + "B".repeat(43) }),
    { clientFactory: () => fakeClient(changed, { output: JSON.stringify(PREVIEW) }) }), /HOST_KEY_CHANGED/);
  assert.equal(changed.command, undefined);
});

test("Amnezia setup preview refuses malformed or failed root output", async () => {
  const malformed = {};
  await assert.rejects(previewAmneziaSetup(previewInput(), { clientFactory: () => fakeClient(malformed,
    { output: JSON.stringify({ ...PREVIEW, writes: true }) }) }), /SETUP_UNAVAILABLE/);
  const failed = {};
  await assert.rejects(previewAmneziaSetup(previewInput(), { clientFactory: () => fakeClient(failed,
    { output: JSON.stringify(PREVIEW), code: 2 }) }), /SETUP_UNAVAILABLE/);
  assert.equal(failed.ended, true);
});

test("Amnezia setup preview handles 128 maximum-length client names without exposing them", async () => {
  const names = Array.from({ length: 128 }, (_, index) =>
    `a${String(index).padStart(3, "0")}${"x".repeat(28)}`);
  const output = JSON.stringify({ ...PREVIEW, target: { ready: true,
    container_id: "a".repeat(64), configured_clients: 128, owned_clients: names } });
  assert.ok(Buffer.byteLength(output) > 4096);
  assert.ok(Buffer.byteLength(output) < 16 * 1024);
  const operations = {};
  const summary = await previewAmneziaSetup(previewInput(), {
    clientFactory: () => fakeClient(operations, { output }),
  });
  assert.equal(summary.configured_clients, 128);
  assert.equal(summary.owned_clients, 128);
  assert.doesNotMatch(JSON.stringify(summary), /a000x/);
  assert.equal(operations.ended, true);
  await assert.rejects(previewAmneziaSetup(previewInput(), {
    clientFactory: () => fakeClient({}, { output: output + " ".repeat(16 * 1024) }),
  }), /SETUP_UNAVAILABLE/);
});

test("gateway clears already read SSH secrets when a request body exceeds the limit", async () => {
  const first = Buffer.alloc(32 * 1024, "s");
  const oversized = Buffer.alloc(40 * 1024, "p");
  const handler = createHandler({ login: async () => { throw new Error("must not authenticate"); } });
  const result = await call(handler, { path: "/api/v1/browser-ssh/login",
    chunks: [first, oversized] });
  assert.equal(result.status, 400);
  assert.equal(first.every((byte) => byte === 0), true);
  assert.equal(oversized.every((byte) => byte === 0), true);
});

test("gateway clears already read SSH secrets when the request stream aborts", async () => {
  const first = Buffer.from("partial-ssh-password");
  const chunks = (async function* () {
    yield first;
    throw new Error("request stream aborted");
  })();
  const handler = createHandler({ login: async () => { throw new Error("must not authenticate"); } });
  const result = await call(handler, { path: "/api/v1/browser-ssh/login", chunks });
  assert.equal(result.status, 503);
  assert.equal(first.every((byte) => byte === 0), true);
});

test("Hub access proof must be a fresh unrestricted administrator session", async () => {
  let calls = 0;
  const fetchImpl = async (url, options) => {
    calls++;
    assert.equal(url, "http://hub:8765/api/v1/session/access");
    assert.equal(options.headers.Authorization, "Bearer " + TOKEN);
    assert.equal(options.redirect, "error");
    return { status: 200, headers: { get: () => null },
      text: async () => JSON.stringify({ access: { mode: "all", revision: 0,
        unrestricted_admin: true } }) };
  };
  await requireUnrestrictedAdmin("Bearer " + TOKEN, { fetchImpl });
  assert.equal(calls, 1);
  await assert.rejects(requireUnrestrictedAdmin("Bearer bad", { fetchImpl }), /AUTH_REQUIRED/);
  assert.equal(calls, 1);
  await assert.rejects(requireUnrestrictedAdmin("Bearer " + TOKEN, {
    fetchImpl: async () => ({ status: 200, headers: { get: () => null },
      text: async () => JSON.stringify({ access: { mode: "selected", revision: 1,
        unrestricted_admin: false } }) }),
  }), /ADMIN_FORBIDDEN/);
  await assert.rejects(requireUnrestrictedAdmin("Bearer " + TOKEN, {
    fetchImpl: async () => ({ status: 401 }),
  }), /AUTH_REQUIRED/);
  await assert.rejects(requireUnrestrictedAdmin("Bearer " + TOKEN, {
    fetchImpl: async () => ({ status: 200, headers: { get: () => null },
      text: async () => JSON.stringify({ access: { unrestricted_admin: true } }) }),
  }), /HUB_UNAVAILABLE/);
});

test("Amnezia HTTP preview denies missing role and cross-origin before SSH", async () => {
  let adminChecks = 0;
  let previews = 0;
  let parsedCredentials;
  const handler = createHandler({ admin: async (authorization) => {
    adminChecks++;
    if (authorization !== "Bearer " + TOKEN) throw new Error("AUTH_REQUIRED");
  }, preview: async (value) => {
    previews++;
    assert.deepEqual(value, previewInput());
    parsedCredentials = value;
    return safeAmneziaPreview(JSON.stringify(PREVIEW), "awg2");
  } });
  const path = "/api/v1/browser-ssh/vpn-setup/preview";
  assert.equal((await call(handler, { path, payload: previewInput(),
    headers: { origin: "https://attacker.example", authorization: "Bearer " + TOKEN } })).status, 404);
  assert.equal((await call(handler, { path, payload: previewInput(), headers: {
    host: "example.com", origin: "http://example.com", "x-forwarded-proto": "http",
    authorization: "Bearer " + TOKEN,
  } })).status, 404);
  assert.equal(adminChecks, 0);
  assert.equal((await call(handler, { path, payload: previewInput() })).status, 401);
  assert.equal(previews, 0);
  const restricted = createHandler({ admin: async () => { throw new Error("ADMIN_FORBIDDEN"); },
    preview: async () => { throw new Error("must not reach SSH"); } });
  assert.equal((await call(restricted, { path, payload: previewInput(),
    headers: { authorization: "Bearer " + TOKEN } })).status, 403);
  const result = await call(handler, { path, payload: previewInput(),
    headers: { authorization: "Bearer " + TOKEN } });
  assert.equal(result.status, 200);
  assert.equal(result.body.reason, "NOT_ENROLLED");
  assert.equal(previews, 1);
  assert.equal(parsedCredentials.password, "");
  assert.equal(parsedCredentials.private_key, "");
  assert.equal(parsedCredentials.passphrase, "");
});

test("entered target host-key route requires unrestricted admin and a safe origin", async () => {
  const path = "/api/v1/browser-ssh/target-host-key";
  let inspected = 0;
  let adminChecks = 0;
  const handler = createHandler({ admin: async (authorization) => {
    adminChecks++;
    if (authorization !== "Bearer " + TOKEN) throw new Error("AUTH_REQUIRED");
  }, inspectTarget: async (target) => {
    inspected++;
    assert.deepEqual(target, { host: "remote.example", port: 22022 });
    return { protocol: 1, scope: "entered_target", host: target.host, port: target.port,
      key_type: "ssh-ed25519", fingerprint: FINGERPRINT, reverify_required: true };
  }, login: async () => { throw new Error("must not authenticate"); } });
  const payload = { host: "remote.example", port: 22022 };
  assert.equal((await call(handler, { path, payload, headers: {
    origin: "https://attacker.example", authorization: "Bearer " + TOKEN,
  } })).status, 404);
  assert.equal((await call(handler, { path, payload, headers: {
    host: "example.com", origin: "http://example.com", "x-forwarded-proto": "http",
    authorization: "Bearer " + TOKEN,
  } })).status, 404);
  assert.equal(adminChecks, 0);
  assert.equal((await call(handler, { path, payload })).status, 401);
  assert.equal(inspected, 0);
  const restricted = createHandler({ admin: async () => { throw new Error("ADMIN_FORBIDDEN"); },
    inspectTarget: async () => { throw new Error("must not reach SSH"); } });
  assert.equal((await call(restricted, { path, payload,
    headers: { authorization: "Bearer " + TOKEN } })).status, 403);
  assert.equal((await call(handler, { path, payload: { ...payload, password: "secret" },
    headers: { authorization: "Bearer " + TOKEN } })).status, 400);
  assert.equal(inspected, 0);
  const result = await call(handler, { path, payload,
    headers: { authorization: "Bearer " + TOKEN } });
  assert.equal(result.status, 200);
  assert.equal(result.body.fingerprint, FINGERPRINT);
  assert.equal(result.body.reverify_required, true);
  assert.equal(inspected, 1);
});

test("target status route requires admin, a same-origin secure request and exact SSH input", async () => {
  const path = "/api/v1/browser-ssh/target-status";
  let checks = 0;
  let probes = 0;
  let parsed;
  const handler = createHandler({ admin: async (authorization) => {
    checks++;
    if (authorization !== "Bearer " + TOKEN) throw new Error("AUTH_REQUIRED");
  }, targetStatus: async (value) => {
    probes++;
    parsed = value;
    return { protocol: 1, scope: "entered_target", host: value.host, port: value.port,
      kind: "missing", host_key_fingerprint: value.fingerprint };
  } });
  const payload = statusInput();
  assert.equal((await call(handler, { path, payload, headers: {
    origin: "https://attacker.example", authorization: "Bearer " + TOKEN,
  } })).status, 404);
  assert.equal((await call(handler, { path, payload, headers: {
    host: "example.com", origin: "http://example.com", "x-forwarded-proto": "http",
    authorization: "Bearer " + TOKEN,
  } })).status, 404);
  assert.equal(checks, 0);
  assert.equal((await call(handler, { path, payload })).status, 401);
  assert.equal(probes, 0);
  const restricted = createHandler({ admin: async () => { throw new Error("ADMIN_FORBIDDEN"); },
    targetStatus: async () => { throw new Error("must not authenticate"); } });
  assert.equal((await call(restricted, { path, payload,
    headers: { authorization: "Bearer " + TOKEN } })).status, 403);
  assert.equal((await call(handler, { path, payload: statusInput({ method: "two_factor" }),
    headers: { authorization: "Bearer " + TOKEN } })).status, 422);
  assert.equal((await call(handler, { path, payload: statusInput({ host: "ssh://remote.example" }),
    headers: { authorization: "Bearer " + TOKEN } })).status, 400);
  assert.equal(probes, 0);
  const success = await call(handler, { path, payload,
    headers: { authorization: "Bearer " + TOKEN } });
  assert.equal(success.status, 200);
  assert.equal(success.body.kind, "missing");
  assert.equal(success.body.host, "remote.example");
  assert.equal(probes, 1);
  assert.equal(parsed.password, "");

  const changed = createHandler({ admin: async () => {},
    targetStatus: async () => { throw new Error("HOST_KEY_CHANGED"); } });
  const changedResponse = await call(changed, { path, payload: statusInput(),
    headers: { authorization: "Bearer " + TOKEN } });
  assert.equal(changedResponse.status, 409);
  assert.deepEqual(changedResponse.body, { error: "HOST_KEY_CHANGED" });

  const loopback = await call(handler, { path, payload: statusInput(), headers: {
    host: "127.0.0.1:8766", origin: "http://127.0.0.1:8766",
    "x-forwarded-proto": "http", "x-sovagrid-client-ip": "127.0.0.1",
    authorization: "Bearer " + TOKEN,
  } });
  assert.equal(loopback.status, 200);
});

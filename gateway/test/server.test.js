/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ../../ATTRIBUTION.md. */
"use strict";

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import ssh2 from "ssh2";
import { agentTimeoutMs, createHandler, hostKey, inspectHostKey, inspectTargetHostKey, issueGrant,
  previewAmneziaSetup, previewTargetInstall, probeTargetStatus, proxyAgent, requireUnrestrictedAdmin,
  safeAgentResult, validateAgentPayload,
  safeAmneziaPreview, validateAmneziaPreview, validateLogin, validateTargetHostKey,
  validateTargetInstallPreview, validateTargetStatus } from "../server.js";

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

test("target inventory supports one keyboard-interactive password after host-key verification", async () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" } });
  let challenges = 0;
  const server = new ssh2.Server({ hostKeys: [privateKey] }, (client) => {
    client.on("error", () => {});
    client.on("authentication", (ctx) => {
      if (ctx.method !== "keyboard-interactive") { ctx.reject(["keyboard-interactive"]); return; }
      challenges++;
      ctx.prompt([{ prompt: "Password: ", echo: false }], (answers) => {
        if (ctx.username === "root" && answers.length === 1 && answers[0] === "secret") ctx.accept();
        else ctx.reject();
      });
    }).on("ready", () => client.on("session", (accept) => {
      const session = accept();
      session.on("exec", (accept, _reject, info) => {
        assert.match(info.command, /^sh -c '/);
        const channel = accept();
        channel.on("data", () => {});
        channel.on("end", () => {
          channel.write("SG_STATUS_V1:missing\n");
          channel.exit(0);
          channel.end();
        });
      });
    }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const clientFactory = () => {
    const client = new ssh2.Client();
    return {
      on(event, callback) { client.on(event, callback); return this; },
      end() { client.end(); },
      exec(...args) { client.exec(...args); },
      connect(options) { client.connect({ ...options, host: "127.0.0.1", port: server.address().port }); },
    };
  };
  try {
    const key = await inspectHostKey({ clientFactory });
    assert.equal(challenges, 0);
    await assert.rejects(probeTargetStatus(statusInput({ fingerprint: "SHA256:" + "B".repeat(43),
      password: "secret" }), { clientFactory }), /HOST_KEY_CHANGED/);
    assert.equal(challenges, 0);
    const input = statusInput({ fingerprint: key.fingerprint, password: "secret" });
    const result = await probeTargetStatus(input, { clientFactory });
    assert.equal(result.kind, "missing");
    assert.equal(challenges, 1);
    assert.equal(input.password, "");
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

function fakeJump(operations, { key = KEY } = {}) {
  const client = fakeClient(operations, { key });
  const channel = { destroyed: false, destroy() { this.destroyed = true; } };
  client.forwardOut = (sourceHost, sourcePort, destinationHost, destinationPort, callback) => {
    operations.forward = { sourceHost, sourcePort, destinationHost, destinationPort };
    callback(null, channel);
  };
  return { client, channel };
}

test("one-hop target probe pins the jump and target independently without target authentication", async () => {
  const jump = statusInput({ host: "JUMP.example", port: 2222, username: "operator",
    password: "jump-secret" });
  const raw = { host: "127.0.0.1", port: 22022, jump };
  const jumpOps = {}, targetOps = {};
  const forward = fakeJump(jumpOps);
  const result = await inspectTargetHostKey(raw, {
    jumpClientFactory: () => forward.client,
    clientFactory: () => fakeClient(targetOps),
  });
  assert.equal(result.host, "127.0.0.1");
  assert.equal(result.jump_host, "jump.example");
  assert.equal(result.jump_port, 2222);
  assert.equal(result.jump_host_key_fingerprint, FINGERPRINT);
  assert.deepEqual(jumpOps.forward, { sourceHost: "127.0.0.1", sourcePort: 0,
    destinationHost: "127.0.0.1", destinationPort: 22022 });
  assert.equal(targetOps.config.sock, forward.channel);
  assert.equal(targetOps.config.password, undefined);
  assert.equal(targetOps.config.username, "sovagrid-probe");
  assert.equal(forward.channel.destroyed, true);
  assert.equal(jump.password, "");
  assert.equal(jumpOps.ended, true);
  const changedJump = fakeJump({}, { key: Buffer.from(KEY).fill(0x31, 8 + "ssh-ed25519".length) });
  await assert.rejects(inspectTargetHostKey({ host: "127.0.0.1", port: 22022,
    jump: statusInput({ host: "jump.example", port: 2222 }) }, {
    jumpClientFactory: () => changedJump.client,
    clientFactory: () => { throw new Error("target must not be contacted"); },
  }), /HOST_KEY_CHANGED/);
});

test("one-hop target status runs only the fixed inventory through both pinned SSH sessions", async () => {
  const raw = statusInput({ host: "127.0.0.1", port: 22022,
    jump: statusInput({ host: "jump.example", port: 2222, username: "operator",
      password: "jump-secret" }) });
  const jumpOps = {}, targetOps = {};
  const forward = fakeJump(jumpOps);
  const result = await probeTargetStatus(raw, {
    jumpClientFactory: () => forward.client,
    clientFactory: () => fakeClient(targetOps, { output: "SG_STATUS_V1:agent_only\n" }),
  });
  assert.equal(result.kind, "agent_only");
  assert.deepEqual([result.jump_host, result.jump_port, result.jump_host_key_fingerprint],
    ["jump.example", 2222, FINGERPRINT]);
  assert.equal(targetOps.config.sock, forward.channel);
  assert.match(targetOps.script, /SOVAGRID_SSH_STATUS_V1/);
  assert.equal(raw.password, "");
  assert.equal(raw.jump.password, "");
  assert.equal(forward.channel.destroyed, true);
  const invalid = statusInput({ jump: { ...statusInput(), extra: "unsafe" } });
  assert.throws(() => validateTargetHostKey({ host: "remote.example", port: 22,
    jump: invalid.jump }), /INVALID_INPUT/);
  assert.throws(() => probeTargetStatus(invalid), /INVALID_INPUT/);
  assert.equal(invalid.password, "");
  assert.equal(invalid.jump.password, "");
});

test("real one-hop SSH handshake reaches a target through a pinned direct-tcpip channel", async () => {
  const makeKey = () => generateKeyPairSync("rsa", { modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" } }).privateKey;
  let targetAuth = 0, forwarded = 0;
  const targetServer = new ssh2.Server({ hostKeys: [makeKey()] }, (client) => {
    client.on("error", () => {});
    client.on("authentication", (ctx) => {
      if (ctx.method === "password") targetAuth++;
      if (ctx.method === "password" && ctx.username === "root" && ctx.password === "target-secret") ctx.accept();
      else ctx.reject();
    }).on("ready", () => client.on("session", (accept) => {
      const session = accept();
      session.on("exec", (accept, _reject, info) => {
        assert.match(info.command, /^sh -c '/);
        const channel = accept();
        channel.on("data", () => {});
        channel.on("end", () => {
          channel.write("SG_STATUS_V1:agent_only\n");
          channel.exit(0);
          channel.end();
        });
      });
    }));
  });
  await new Promise((resolve) => targetServer.listen(0, "127.0.0.1", resolve));
  const jumpServer = new ssh2.Server({ hostKeys: [makeKey()] }, (client) => {
    client.on("error", () => {});
    client.on("authentication", (ctx) => {
      if (ctx.method === "password" && ctx.username === "operator" && ctx.password === "jump-secret") ctx.accept();
      else ctx.reject();
    }).on("ready", () => client.on("tcpip", (accept, reject, info) => {
      if (info.destIP !== "127.0.0.1" || info.destPort !== targetServer.address().port) {
        reject(); return;
      }
      forwarded++;
      const upstream = net.connect({ host: "127.0.0.1", port: targetServer.address().port });
      upstream.once("connect", () => { const channel = accept(); channel.pipe(upstream).pipe(channel); });
      upstream.once("error", () => { reject(); upstream.destroy(); });
    }));
  });
  await new Promise((resolve) => jumpServer.listen(0, "127.0.0.1", resolve));
  try {
    const jumpAddress = { host: "127.0.0.1", port: jumpServer.address().port };
    const targetAddress = { host: "127.0.0.1", port: targetServer.address().port };
    const jumpKey = await inspectTargetHostKey(jumpAddress);
    const jump = { ...jumpAddress, username: "operator", method: "password",
      fingerprint: jumpKey.fingerprint, password: "jump-secret", private_key: "", passphrase: "" };
    const targetKey = await inspectTargetHostKey({ ...targetAddress, jump });
    assert.equal(targetAuth, 0);
    assert.equal(targetKey.jump_host_key_fingerprint, jumpKey.fingerprint);
    const result = await probeTargetStatus({ ...targetAddress, username: "root", method: "password",
      fingerprint: targetKey.fingerprint, password: "target-secret", private_key: "", passphrase: "",
      jump: { ...jump, password: "jump-secret" } });
    assert.equal(result.kind, "agent_only");
    assert.equal(targetAuth, 1);
    assert.equal(forwarded, 2);
  } finally {
    await new Promise((resolve) => jumpServer.close(resolve));
    await new Promise((resolve) => targetServer.close(resolve));
  }
});

test("one-hop HTTP probes require Hub admin and erase both SSH credentials", async () => {
  const jump = statusInput({ host: "jump.example", port: 2222, password: "jump-secret" });
  let inspected, probed;
  const handler = createHandler({ admin: async (authorization) => {
    if (authorization !== "Bearer " + TOKEN) throw new Error("AUTH_REQUIRED");
  }, inspectTarget: async (value) => {
    inspected = value;
    assert.equal(value.jump.password, "jump-secret");
    return { protocol: 1, scope: "entered_target", host: value.host, port: value.port,
      key_type: "ssh-ed25519", fingerprint: FINGERPRINT, reverify_required: true,
      jump_host: value.jump.host, jump_port: value.jump.port,
      jump_host_key_fingerprint: value.jump.fingerprint };
  }, targetStatus: async (value) => { probed = value; return { protocol: 1, scope: "entered_target",
    host: value.host, port: value.port, kind: "agent_only",
    host_key_fingerprint: value.fingerprint, jump_host: value.jump.host,
    jump_port: value.jump.port, jump_host_key_fingerprint: value.jump.fingerprint }; } });
  const probe = { host: "127.0.0.1", port: 22022, jump };
  assert.equal((await call(handler, { path: "/api/v1/browser-ssh/target-host-key", payload: probe })).status, 401);
  const found = await call(handler, { path: "/api/v1/browser-ssh/target-host-key", payload: probe,
    headers: { authorization: "Bearer " + TOKEN } });
  assert.equal(found.status, 200);
  assert.equal(found.body.jump_host_key_fingerprint, FINGERPRINT);
  assert.equal(inspected.jump.password, "");
  const status = statusInput({ host: "127.0.0.1", port: 22022,
    jump: statusInput({ host: "jump.example", port: 2222, password: "jump-secret" }) });
  const reply = await call(handler, { path: "/api/v1/browser-ssh/target-status", payload: status,
    headers: { authorization: "Bearer " + TOKEN } });
  assert.equal(reply.status, 200);
  assert.equal(reply.body.kind, "agent_only");
  assert.equal(reply.body.jump_host, "jump.example");
  assert.equal(probed.password, "");
  assert.equal(probed.jump.password, "");
});

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
  assert.equal(operations.config.tryKeyboard, true);
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

function installPreviewInput(overrides = {}) {
  return { ...statusInput(), name: "Second Ubuntu", hub_host: "198.51.100.20",
    hub_port: 22, local_port: 22023, ...overrides };
}

test("install preview accepts only a pinned target and a routable Hub IP", () => {
  const value = validateTargetInstallPreview(installPreviewInput());
  assert.equal(value.host, "remote.example");
  assert.equal(value.name, "Second Ubuntu");
  assert.deepEqual(value.hub_endpoint, { host: "198.51.100.20", port: 22, local_port: 22023 });
  assert.equal(validateTargetInstallPreview(installPreviewInput({ hub_host: "2001:db8::2" }))
    .hub_endpoint.host, "2001:db8::2");
  for (const invalid of [
    { hub_host: "localhost" }, { hub_host: "127.0.0.1" }, { hub_host: "0.0.0.0" },
    { hub_host: "224.0.0.1" }, { hub_host: "::1" }, { hub_host: "::" },
    { hub_host: "ff02::1" }, { hub_host: "::ffff:127.0.0.1" },
    { hub_host: "fe80::1%eth0" }, { name: "\nNew" }, { name: " New" },
    { name: "New\u00a0server" }, { name: "PRIVATE KEY" },
    { name: "" }, { hub_port: 0 }, { local_port: 1023 }, { local_port: 65536 },
    { extra: "unexpected" },
  ]) assert.throws(() => validateTargetInstallPreview(installPreviewInput(invalid)), /INVALID_INPUT/);
});

test("install preview checks target ownership and Hub route with fixed read-only SSH commands", async () => {
  const operations = [{}, {}];
  let count = 0;
  const raw = installPreviewInput();
  const result = await previewTargetInstall(raw, { clientFactory: () => fakeClient(operations[count],
    { output: count++ === 0 ? "SG_STATUS_V1:missing\n" : "SG_HUB_ROUTE_V1:reachable\n" }) });
  assert.equal(result.action, "install_preview");
  assert.equal(result.writes, false);
  assert.equal(result.target_kind, "missing");
  assert.equal(result.hub_route, "reachable");
  assert.equal(result.preflight_passed, true);
  assert.equal(result.source_verification_required, true);
  assert.equal(result.reverify_required, true);
  assert.equal(result.host_key_fingerprint, FINGERPRINT);
  assert.equal(count, 2);
  assert.match(operations[0].command, /^sh -c '/);
  assert.match(operations[0].script, /SOVAGRID_SSH_STATUS_V1/);
  assert.match(operations[1].command, /^python3 -I -c '/);
  assert.doesNotMatch(operations[1].command, /198\.51\.100\.20|server-secret/);
  assert.equal(operations[1].script, JSON.stringify({ host: "198.51.100.20", port: 22 }));
  if (process.platform !== "win32") {
    const local = spawnSync("sh", ["-c", operations[1].command], {
      input: JSON.stringify({ host: "127.0.0.1", port: 1 }), timeout: 6000,
      encoding: "utf8", maxBuffer: 1024,
    });
    assert.equal(local.status, 0, local.stderr);
    assert.equal(local.stdout, "SG_HUB_ROUTE_V1:unreachable\n");
  }
  assert.equal(operations[0].config.hostVerifier(KEY), true);
  assert.equal(operations[1].config.hostVerifier(KEY), true);
  assert.equal(raw.password, "");
  assert.equal(operations[0].ended, true);
  assert.equal(operations[1].ended, true);

  const blocked = installPreviewInput();
  const conflict = await previewTargetInstall(blocked, { clientFactory: () => fakeClient({},
    { output: "SG_STATUS_V1:conflict\n" }) });
  assert.equal(conflict.preflight_passed, false);
  assert.equal(conflict.hub_route, "not_checked");
  assert.equal(blocked.password, "");
  const unreachable = await previewTargetInstall(installPreviewInput(), { clientFactory: () =>
    fakeClient({}, { output: count++ % 2 === 0 ? "SG_STATUS_V1:missing\n" :
      "SG_HUB_ROUTE_V1:unreachable\n" }) });
  assert.equal(unreachable.preflight_passed, false);
  assert.equal(unreachable.hub_route, "unreachable");
});

test("install preview never answers repeated or multi-prompt SSH challenges", async () => {
  const answers = [];
  const client = new EventEmitter();
  client.connect = (options) => {
    assert.equal(options.tryKeyboard, true);
    assert.equal(options.hostVerifier(KEY), true);
    queueMicrotask(() => {
      client.emit("keyboard-interactive", "", "", "", [{ prompt: "Verification code: ", echo: false }],
        (value) => answers.push(value));
      client.emit("keyboard-interactive", "", "", "", [{ prompt: "Пароль: ", echo: false }],
        (value) => answers.push(value));
      client.emit("keyboard-interactive", "", "", "", [{ prompt: "Password: ", echo: false }],
        (value) => answers.push(value));
      client.emit("keyboard-interactive", "", "", "", [{ prompt: "Password: ", echo: false },
        { prompt: "OTP: ", echo: false }],
        (value) => answers.push(value));
      client.emit("ready");
    });
  };
  client.exec = (_command, _options, callback) => {
    const channel = new EventEmitter();
    channel.stderr = new EventEmitter();
    channel.end = () => queueMicrotask(() => {
      channel.emit("data", Buffer.from("SG_STATUS_V1:conflict\n"));
      channel.emit("close", 0, null);
    });
    callback(null, channel);
  };
  client.end = () => {};
  const raw = installPreviewInput();
  const result = await previewTargetInstall(raw, { clientFactory: () => client });
  assert.equal(result.target_kind, "conflict");
  assert.deepEqual(answers, [[], ["server-secret"], [], []]);
  assert.equal(raw.password, "");
});

test("install preview fails closed if the SSH host key changes before the Hub route check", async () => {
  let calls = 0;
  const raw = installPreviewInput();
  const changedKey = Buffer.from(KEY);
  changedKey[changedKey.length - 1] ^= 1;
  await assert.rejects(previewTargetInstall(raw, { clientFactory: () => {
    const step = calls++;
    return fakeClient({}, { key: step === 0 ? KEY : changedKey,
      output: step === 0 ? "SG_STATUS_V1:missing\n" : "SG_HUB_ROUTE_V1:reachable\n" });
  } }), /HOST_KEY_CHANGED/);
  assert.equal(calls, 2);
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

test("install preview route requires unrestricted admin and clears every SSH secret", async () => {
  const path = "/api/v1/browser-ssh/target-install-preview";
  let checks = 0;
  let previews = 0;
  let passed;
  const handler = createHandler({ admin: async (authorization) => {
    checks++;
    if (authorization !== "Bearer " + TOKEN) throw new Error("AUTH_REQUIRED");
  }, installPreview: async (value) => {
    previews++;
    passed = value;
    assert.equal(value.password, "server-secret");
    return { protocol: 1, action: "install_preview", writes: false, preflight_passed: true };
  } });
  const payload = installPreviewInput();
  assert.equal((await call(handler, { path, payload, headers: {
    origin: "https://attacker.example", authorization: "Bearer " + TOKEN,
  } })).status, 404);
  assert.equal((await call(handler, { path, payload, headers: {
    host: "example.com", origin: "http://example.com", "x-forwarded-proto": "http",
    authorization: "Bearer " + TOKEN,
  } })).status, 404);
  assert.equal(checks, 0);
  assert.equal((await call(handler, { path, payload })).status, 401);
  assert.equal(previews, 0);
  const restricted = createHandler({ admin: async () => { throw new Error("ADMIN_FORBIDDEN"); },
    installPreview: async () => { throw new Error("must not reach SSH"); } });
  assert.equal((await call(restricted, { path, payload,
    headers: { authorization: "Bearer " + TOKEN } })).status, 403);
  const result = await call(handler, { path, payload,
    headers: { authorization: "Bearer " + TOKEN } });
  assert.equal(result.status, 200);
  assert.equal(result.body.writes, false);
  assert.equal(previews, 1);
  assert.equal(passed.password, "");
  assert.equal(passed.private_key, "");
  assert.equal(passed.passphrase, "");
  const loopback = await call(handler, { path, payload: installPreviewInput(), headers: {
    host: "[::1]:8766", origin: "http://[::1]:8766",
    "x-forwarded-proto": "http", "x-sovagrid-client-ip": "::1",
    authorization: "Bearer " + TOKEN,
  } });
  assert.equal(loopback.status, 200);
});

const REQUEST_ID = "00000000-0000-4000-8000-000000000001";
const SOURCE_COMMITS = Object.fromEntries(["sovagrid-blueprint", "sovagrid-hub", "sovagrid-web",
  "sovagrid-agent", "sovagrid-vpn"].map((name) => [name, "a".repeat(40)]));
const AGENT_RECORD = { protocol: 1, request_id: REQUEST_ID, name: "Second Ubuntu",
  phase: "prepared", revision: 1, created_at: 1793000000, updated_at: 1793000000,
  cleanup_required: false, server_id: null, registration_state: null, recoverable: true };

test("Agent enrollment validates each exact action body and strips private worker fields", () => {
  const prepare = validateAgentPayload("prepare", installPreviewInput());
  assert.deepEqual(prepare, { ...installPreviewInput(), host: "remote.example" });
  assert.deepEqual(validateAgentPayload("resume", { ...statusInput(), request_id: REQUEST_ID }),
    { ...statusInput(), host: "remote.example", request_id: REQUEST_ID });
  assert.deepEqual(validateAgentPayload("apply", { request_id: REQUEST_ID, expected_revision: 2 }),
    { request_id: REQUEST_ID, expected_revision: 2 });
  assert.deepEqual(validateAgentPayload("interrupt", {}), {});
  assert.deepEqual(validateAgentPayload("list", {}), {});
  for (const [action, body] of [
    ["prepare", { ...installPreviewInput(), command: "id" }],
    ["prepare", installPreviewInput({ hub_host: "127.0.0.1" })],
    ["resume", { ...statusInput(), request_id: REQUEST_ID, name: "unexpected" }],
    ["apply", { request_id: REQUEST_ID, expected_revision: "2" }],
    ["cleanup", { request_id: "../secret", expected_revision: 1 }],
    ["status", { request_id: REQUEST_ID, token: "secret" }],
    ["list", { host: "example.org" }],
  ]) assert.throws(() => validateAgentPayload(action, body), /INVALID_INPUT/);
  const reviewed = safeAgentResult("prepare", { ...AGENT_RECORD, writes: true,
    activation_writes: false,
    hub_fingerprint: FINGERPRINT,
    platform: { ubuntu_version: "24.04", python_version: "3.12", systemd_version: "255",
      private_key: "never-return" }, source_commits: SOURCE_COMMITS,
    secret: "never-return" });
  assert.equal(reviewed.request_id, REQUEST_ID);
  assert.equal(reviewed.writes, true);
  assert.equal(reviewed.activation_writes, false);
  assert.doesNotMatch(JSON.stringify(reviewed), /never-return|private_key|secret/);
  assert.deepEqual(safeAgentResult("list", [{ ...AGENT_RECORD, password: "never-return" }]), [AGENT_RECORD]);
  assert.throws(() => safeAgentResult("prepare", { ...AGENT_RECORD, writes: false,
    activation_writes: false,
    hub_fingerprint: FINGERPRINT, platform: {}, source_commits: SOURCE_COMMITS }), /INSTALLER_UNAVAILABLE/);
});

test("Agent HTTP routes require a fresh unrestricted session and never expose submitted secrets", async () => {
  const path = "/api/v1/browser-ssh/agent/prepare";
  let checked = 0;
  let forwarded = 0;
  let selected;
  const handler = createHandler({ admin: async (authorization) => {
    checked++;
    if (authorization !== "Bearer " + TOKEN) throw new Error("AUTH_REQUIRED");
  }, agent: async (action, payload, token) => {
    forwarded++;
    assert.equal(action, "prepare");
    assert.equal(token, TOKEN);
    assert.equal(payload.password, "server-secret");
    selected = payload;
    return AGENT_RECORD;
  } });
  assert.equal((await call(handler, { path, payload: installPreviewInput(), headers: {
    origin: "https://attacker.example", authorization: "Bearer " + TOKEN } })).status, 404);
  assert.equal(checked, 0);
  assert.equal((await call(handler, { path, payload: installPreviewInput() })).status, 401);
  assert.equal(forwarded, 0);
  const result = await call(handler, { path, payload: installPreviewInput(),
    headers: { authorization: "Bearer " + TOKEN } });
  assert.equal(result.status, 200);
  assert.equal(result.body.request_id, REQUEST_ID);
  assert.equal(forwarded, 1);
  assert.equal(selected.password, "");
  assert.equal(selected.private_key, "");
  assert.equal(selected.passphrase, "");
  const read = await call(createHandler({ admin: async () => {},
    agent: async (action, payload, token) => {
      assert.equal(action, "list");
      assert.deepEqual(payload, {});
      assert.equal(token, TOKEN);
      return [AGENT_RECORD];
    } }), { path: "/api/v1/browser-ssh/agent/list", payload: {},
    headers: { authorization: "Bearer " + TOKEN } });
  assert.equal(read.status, 200);
  assert.deepEqual(read.body, [AGENT_RECORD]);
  const uncertain = new Error("PREPARE_UNCERTAIN");
  uncertain.requestId = REQUEST_ID;
  const error = await call(createHandler({ admin: async () => {}, agent: async () => { throw uncertain; } }),
    { path, payload: installPreviewInput(), headers: { authorization: "Bearer " + TOKEN } });
  assert.equal(error.status, 503);
  assert.deepEqual(error.body, { error: "PREPARE_UNCERTAIN", request_id: REQUEST_ID });
});

test("VPN source setup accepts only pinned SSH credentials and the exact reviewed revision", async () => {
  const login = statusInput({ host: "remote.example" });
  const hashes = { source_manifest_sha256: "a".repeat(64), installed_sha256: "0".repeat(64),
    state_sha256: "0".repeat(64), candidate_sha256: "b".repeat(64) };
  assert.equal(validateAgentPayload("vpn-source-preview", login).host, "remote.example");
  assert.deepEqual(validateAgentPayload("vpn-source-apply", { ...login, expected: hashes }).expected, hashes);
  assert.throws(() => validateAgentPayload("vpn-source-apply", { ...login,
    expected: { ...hashes, candidate_sha256: "bad" } }), /INVALID_INPUT/);
  assert.throws(() => validateAgentPayload("vpn-source-apply", { ...login,
    expected: { ...hashes, password: "unexpected" } }), /INVALID_INPUT/);
  const preview = safeAgentResult("vpn-source-preview", { protocol: 1,
    scope: "entered_target", host: "remote.example", port: 22022,
    host_key_fingerprint: FINGERPRINT, ...hashes, expected: hashes,
    change: "install", temporary_writes: true, activation_writes: false,
    cleanup_required: false, private_key: "must-not-leak" });
  assert.equal(preview.private_key, undefined);
  assert.deepEqual(preview.expected, hashes);
  assert.throws(() => safeAgentResult("vpn-source-preview", { ...preview,
    expected: { ...hashes, state_sha256: "c".repeat(64) } }), /INSTALLER_UNAVAILABLE/);
});

test("VPN source route enforces admin, origin and credential clearing", async () => {
  let forwarded = 0;
  let selected;
  const handler = createHandler({ admin: async (authorization) => {
    if (authorization !== "Bearer " + TOKEN) throw new Error("AUTH_REQUIRED");
  }, agent: async (action, payload, token) => {
    forwarded++;
    assert.equal(action, "vpn-source-preview");
    assert.equal(token, TOKEN);
    assert.equal(payload.password, "server-secret");
    selected = payload;
    return { protocol: 1, scope: "entered_target", host: "remote.example", port: 22022,
      host_key_fingerprint: FINGERPRINT, source_manifest_sha256: "a".repeat(64),
      candidate_sha256: "b".repeat(64), installed_sha256: "0".repeat(64),
      state_sha256: "0".repeat(64), change: "install", temporary_writes: true,
      activation_writes: false, cleanup_required: false };
  } });
  const path = "/api/v1/browser-ssh/vpn-source/preview";
  const payload = statusInput({ host: "remote.example" });
  assert.equal((await call(handler, { path, payload, headers: {
    origin: "https://attacker.example", authorization: "Bearer " + TOKEN } })).status, 404);
  assert.equal((await call(handler, { path, payload })).status, 401);
  assert.equal(forwarded, 0);
  const result = await call(handler, { path, payload,
    headers: { authorization: "Bearer " + TOKEN } });
  assert.equal(result.status, 200);
  assert.equal(result.body.change, "install");
  assert.equal(forwarded, 1);
  assert.equal(selected.password, "");
  assert.equal(selected.private_key, "");
  assert.equal(selected.passphrase, "");
});

test("WireGuard broker accepts exact pinned payloads and sanitizes fixed results", () => {
  const login = statusInput({ host: "remote.example" });
  const expected = { state_revision: "a".repeat(64), source_revision: "b".repeat(64) };
  assert.equal(validateAgentPayload("wg-control-preview", login).host, "remote.example");
  assert.deepEqual(validateAgentPayload("wg-control-apply", { ...login, expected, confirm: true }).expected,
    expected);
  assert.deepEqual(validateAgentPayload("wg-control-recover", { ...login, confirm: true }).confirm, true);
  for (const bad of [
    { ...login, expected, confirm: false },
    { ...login, expected: { ...expected, state_revision: "A".repeat(64) }, confirm: true },
    { ...login, expected: { ...expected, command: "whoami" }, confirm: true },
  ]) assert.throws(() => validateAgentPayload("wg-control-apply", bad), /INVALID_INPUT/);
  assert.throws(() => validateAgentPayload("wg-control-recover", { ...login, confirm: "true" }), /INVALID_INPUT/);
  assert.throws(() => validateAgentPayload("wg-control-preview", { ...login, command: "whoami" }), /INVALID_INPUT/);

  const scope = { protocol: 1, scope: "entered_target", host: "remote.example", port: 22022,
    host_key_fingerprint: FINGERPRINT };
  const preview = { ...scope, schema_version: 1, action: "preview", writes: false,
    ...expected, installed_current: false, socket_active: false, service_active: false,
    socket_enabled: false, pending_recovery: false, inventory_timer_active: false,
    inventory_timer_enabled: false, inventory_snapshot_present: false,
    missing_dependencies: ["wg", "python3-cryptography"], apparmor_profile_present: false,
    can_apply: true, requires_service_restart: false };
  assert.deepEqual(safeAgentResult("wg-control-preview", preview), preview);
  assert.throws(() => safeAgentResult("wg-control-preview", { ...preview, private_key: "secret" }),
    /INSTALLER_UNAVAILABLE/);
  assert.throws(() => safeAgentResult("wg-control-preview", { ...preview,
    missing_dependencies: ["curl"] }), /INSTALLER_UNAVAILABLE/);
  assert.deepEqual(safeAgentResult("wg-control-preview", { ...scope, schema_version: 1,
    action: "preview", writes: false, can_apply: false, pending_recovery: true,
    reason: "RECOVERY_REQUIRED" }).reason, "RECOVERY_REQUIRED");
  assert.throws(() => safeAgentResult("wg-control-preview", { ...scope, schema_version: 1,
    action: "preview", writes: false, can_apply: false, pending_recovery: false,
    reason: "target says password=secret" }), /INSTALLER_UNAVAILABLE/);
  const installed = { ...scope, action: "installed", socket_active: true, service_active: true,
    vpn_interface_changed: false, inventory_timer_active: true, inventory_snapshot_present: true,
    source_revision: expected.source_revision };
  assert.deepEqual(safeAgentResult("wg-control-apply", installed), installed);
  assert.throws(() => safeAgentResult("wg-control-apply", { ...installed,
    vpn_interface_changed: true }), /INSTALLER_UNAVAILABLE/);
  assert.deepEqual(safeAgentResult("wg-control-recover", { ...scope,
    action: "recovered", changed: true }).changed, true);
  assert.equal(agentTimeoutMs("wg-control-preview"), 120000);
  assert.equal(agentTimeoutMs("wg-control-apply"), 720000);
  assert.equal(agentTimeoutMs("wg-control-recover"), 450000);
});

test("WireGuard broker route checks admin and origin, then wipes SSH credentials", async () => {
  const login = statusInput({ host: "remote.example" });
  const expected = { state_revision: "a".repeat(64), source_revision: "b".repeat(64) };
  let forwarded = 0, selected;
  const handler = createHandler({ admin: async (authorization) => {
    if (authorization !== "Bearer " + TOKEN) throw new Error("AUTH_REQUIRED");
  }, agent: async (action, payload, token) => {
    forwarded++;
    assert.equal(action, "wg-control-apply");
    assert.equal(token, TOKEN);
    assert.deepEqual(payload.expected, expected);
    assert.equal(payload.confirm, true);
    assert.equal(payload.password, "server-secret");
    selected = payload;
    return { protocol: 1, scope: "entered_target", host: "remote.example", port: 22022,
      host_key_fingerprint: FINGERPRINT, action: "installed", socket_active: true,
      service_active: true, vpn_interface_changed: false, inventory_timer_active: true,
      inventory_snapshot_present: true, source_revision: expected.source_revision };
  } });
  const path = "/api/v1/browser-ssh/wg-control/apply", payload = { ...login, expected, confirm: true };
  assert.equal((await call(handler, { path, payload, headers: {
    origin: "https://attacker.example", authorization: "Bearer " + TOKEN } })).status, 404);
  assert.equal((await call(handler, { path, payload })).status, 401);
  assert.equal(forwarded, 0);
  const result = await call(handler, { path, payload, headers: { authorization: "Bearer " + TOKEN } });
  assert.equal(result.status, 200);
  assert.equal(result.body.vpn_interface_changed, false);
  assert.equal(forwarded, 1);
  assert.equal(selected.password, "");
  assert.equal(selected.private_key, "");
  assert.equal(selected.passphrase, "");
});

test("AmneziaWG provision accepts only pinned SSH, canonical private /24 and confirmed CAS", () => {
  const login = statusInput({ host: "remote.example" });
  const config = { listen_port: 51820, subnet: "10.44.0.0/24", route_mode: "full" };
  const state = "a".repeat(64);
  assert.deepEqual(validateAgentPayload("amnezia-provision-preview", { ...login, ...config }),
    { ...login, ...config });
  assert.deepEqual(validateAgentPayload("amnezia-provision-apply", {
    ...login, ...config, expected_state: state, confirm: true }),
  { ...login, ...config, expected_state: state, confirm: true });
  assert.deepEqual(validateAgentPayload("amnezia-provision-recover", { ...login, confirm: true }),
    { ...login, confirm: true });
  for (const bad of [
    { ...config, listen_port: "51820" }, { ...config, listen_port: 0 },
    { ...config, subnet: "10.44.0.1/24" }, { ...config, subnet: "010.44.0.0/24" },
    { ...config, subnet: "100.64.0.0/24" }, { ...config, route_mode: "all" },
    { ...config, command: "id" },
  ]) assert.throws(() => validateAgentPayload("amnezia-provision-preview", { ...login, ...bad }),
    /INVALID_INPUT/);
  for (const bad of [
    { expected_state: "A".repeat(64), confirm: true },
    { expected_state: state, confirm: false },
  ]) assert.throws(() => validateAgentPayload("amnezia-provision-apply", { ...login, ...config, ...bad }),
    /INVALID_INPUT/);
  assert.throws(() => validateAgentPayload("amnezia-provision-recover", { ...login,
    confirm: "true" }), /INVALID_INPUT/);
});

test("AmneziaWG provision result is bounded to fixed fields and timeouts include SSH preflight", () => {
  const scope = { protocol: 1, scope: "entered_target", host: "remote.example", port: 22022,
    host_key_fingerprint: FINGERPRINT };
  const config = { listen_port: 51820, subnet: "10.44.0.0/24", route_mode: "full" };
  const full = { ...scope, schema_version: 1, action: "preview", writes: false,
    target: "awg2", container: "amnezia-awg2", ...config,
    image_digest: "sha256:" + "b".repeat(64), image_cached: false,
    state_revision: "a".repeat(64), can_apply: true };
  assert.deepEqual(safeAgentResult("amnezia-provision-preview", full), full);
  assert.throws(() => safeAgentResult("amnezia-provision-preview", { ...full,
    private_key: "secret" }), /INSTALLER_UNAVAILABLE/);
  assert.throws(() => safeAgentResult("amnezia-provision-preview", { ...full,
    reason: "password=secret" }), /INSTALLER_UNAVAILABLE/);
  const blocked = { ...full, can_apply: false, reason: "UDP_PORT_BUSY" };
  assert.deepEqual(safeAgentResult("amnezia-provision-preview", blocked), blocked);
  assert.deepEqual(safeAgentResult("amnezia-provision-preview", { ...blocked,
    reason: "INSTALLATION_DRIFT" }).reason, "INSTALLATION_DRIFT");
  const degraded = { ...scope, schema_version: 1, action: "preview", writes: false,
    target: "awg2", container: "amnezia-awg2", can_apply: false, reason: "DOCKER_UNAVAILABLE" };
  assert.deepEqual(safeAgentResult("amnezia-provision-preview", degraded), degraded);
  assert.deepEqual(safeAgentResult("amnezia-provision-preview", { ...degraded,
    reason: "SOURCE_UNTRUSTED" }).reason, "SOURCE_UNTRUSTED");
  assert.deepEqual(safeAgentResult("amnezia-provision-preview", { ...degraded,
    reason: "SOURCE_BUSY" }).reason, "SOURCE_BUSY");
  assert.throws(() => safeAgentResult("amnezia-provision-preview", { ...degraded,
    state_revision: "a".repeat(64) }), /INSTALLER_UNAVAILABLE/);
  const installed = { ...scope, schema_version: 1, action: "installed", target: "awg2",
    container: "amnezia-awg2", container_id: "c".repeat(64), image_id: "sha256:" + "d".repeat(64),
    ...config, recovery_required: false };
  assert.deepEqual(safeAgentResult("amnezia-provision-apply", installed), installed);
  assert.throws(() => safeAgentResult("amnezia-provision-apply", { ...installed,
    recovery_required: true }), /INSTALLER_UNAVAILABLE/);
  assert.deepEqual(safeAgentResult("amnezia-provision-recover", { ...scope, schema_version: 1,
    action: "recovered", changed: true, installed: false }).installed, false);
  assert.equal(agentTimeoutMs("amnezia-provision-preview"), 120000);
  assert.equal(agentTimeoutMs("amnezia-provision-apply"), 480000);
  assert.equal(agentTimeoutMs("amnezia-provision-recover"), 180000);
});

test("AmneziaWG provision route checks admin and origin, then wipes SSH credentials", async () => {
  const login = statusInput({ host: "remote.example" });
  const config = { listen_port: 51820, subnet: "10.44.0.0/24", route_mode: "full" };
  let forwarded = 0, selected;
  const handler = createHandler({ admin: async (authorization) => {
    if (authorization !== "Bearer " + TOKEN) throw new Error("AUTH_REQUIRED");
  }, agent: async (action, payload, token) => {
    forwarded++;
    assert.equal(action, "amnezia-provision-apply");
    assert.equal(token, TOKEN);
    assert.equal(payload.expected_state, "a".repeat(64));
    assert.equal(payload.confirm, true);
    assert.equal(payload.password, "server-secret");
    selected = payload;
    return { protocol: 1, scope: "entered_target", host: "remote.example", port: 22022,
      host_key_fingerprint: FINGERPRINT, schema_version: 1, action: "installed", target: "awg2",
      container: "amnezia-awg2", container_id: "c".repeat(64), image_id: "sha256:" + "d".repeat(64),
      ...config, recovery_required: false };
  } });
  const path = "/api/v1/browser-ssh/amnezia-provision/apply";
  const payload = { ...login, ...config, expected_state: "a".repeat(64), confirm: true };
  assert.equal((await call(handler, { path, payload, headers: {
    origin: "https://attacker.example", authorization: "Bearer " + TOKEN } })).status, 404);
  assert.equal((await call(handler, { path, payload })).status, 401);
  assert.equal(forwarded, 0);
  const result = await call(handler, { path, payload, headers: { authorization: "Bearer " + TOKEN } });
  assert.equal(result.status, 200);
  assert.equal(result.body.route_mode, "full");
  assert.equal(forwarded, 1);
  assert.equal(selected.password, "");
  assert.equal(selected.private_key, "");
  assert.equal(selected.passphrase, "");
});

test("Agent socket proxy sends one bounded request and accepts only a safe reply", async () => {
  const directory = mkdtempSync(join(tmpdir(), "sovagrid-agent-proxy-"));
  const socketPath = join(directory, "control.sock");
  const seen = [];
  const server = net.createServer((socket) => {
    let raw = "";
    socket.on("data", (chunk) => { raw += chunk.toString("utf8"); });
    socket.on("end", () => {
      const request = JSON.parse(raw.trim());
      seen.push(request);
      socket.end(JSON.stringify(request.action === "apply" ?
        { ok: false, error: "APPLY_UNCERTAIN", request_id: REQUEST_ID } :
        request.action === "wg-control-preview" ?
          { ok: true, result: { protocol: 1, scope: "entered_target", host: "other.example",
            port: 22022, host_key_fingerprint: FINGERPRINT, schema_version: 1,
            action: "preview", writes: false, can_apply: false, pending_recovery: false,
            reason: "SOURCE_NOT_PREPARED" } } :
        request.action === "amnezia-provision-preview" ?
          { ok: true, result: { protocol: 1, scope: "entered_target", host: "other.example",
            port: 22022, host_key_fingerprint: FINGERPRINT, schema_version: 1,
            action: "preview", writes: false, target: "awg2", container: "amnezia-awg2",
            can_apply: false, reason: "SOURCE_NOT_PREPARED" } } :
          { ok: true, result: { ...AGENT_RECORD, private_key: "must-not-appear" } }) + "\n");
    });
  });
  try {
    await new Promise((resolve) => server.listen(socketPath, resolve));
    const result = await proxyAgent("status", { request_id: REQUEST_ID }, TOKEN,
      { socketPath, timeoutMs: 1000 });
    assert.deepEqual(result, AGENT_RECORD);
    assert.deepEqual(seen, [{ action: "status", session_token: TOKEN,
      payload: { request_id: REQUEST_ID } }]);
    assert.doesNotMatch(JSON.stringify(result), /must-not-appear/);
    await assert.rejects(proxyAgent("apply", { request_id: REQUEST_ID,
      expected_revision: 1 }, TOKEN, { socketPath, timeoutMs: 1000 }), (error) => {
      assert.equal(error.message, "APPLY_UNCERTAIN");
      assert.equal(error.requestId, REQUEST_ID);
      return true;
    });
    await assert.rejects(proxyAgent("wg-control-preview", validateAgentPayload("wg-control-preview",
      statusInput({ host: "remote.example" })), TOKEN, { socketPath, timeoutMs: 1000 }),
    /INSTALLER_UNAVAILABLE/, "a valid reply from another SSH endpoint must be rejected");
    await assert.rejects(proxyAgent("amnezia-provision-preview",
      validateAgentPayload("amnezia-provision-preview", {
        ...statusInput({ host: "remote.example" }), listen_port: 51820,
        subnet: "10.44.0.0/24", route_mode: "full" }), TOKEN,
    { socketPath, timeoutMs: 1000 }), /INSTALLER_UNAVAILABLE/,
    "provision status from another SSH endpoint must be rejected");
  } finally {
    await new Promise((resolve) => server.close(resolve));
    rmSync(directory, { recursive: true, force: true });
  }
});

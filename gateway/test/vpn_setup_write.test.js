/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ../../ATTRIBUTION.md. */
"use strict";

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import test from "node:test";
import { createHandler, enrollAmneziaSetup, mutateAmneziaSetup,
  previewAmneziaEnrollment, previewAmneziaSetup, safeAmneziaEnrollmentPreview,
  safeAmneziaPreview, validateAmneziaEnrollment, validateAmneziaPreview,
  validateAmneziaSetupAction } from "../server.js";

function wireKey() {
  const type = Buffer.from("ssh-ed25519");
  const result = Buffer.alloc(4 + type.length + 4 + 32);
  result.writeUInt32BE(type.length, 0);
  type.copy(result, 4);
  result.writeUInt32BE(32, 4 + type.length);
  result.fill(0x2a, 8 + type.length);
  return result;
}

const KEY = wireKey();
const FINGERPRINT = "SHA256:" + createHash("sha256").update(KEY).digest("base64").replace(/=+$/, "");
const TOKEN = "t".repeat(43);
const CID = "a".repeat(64);
const ENROLL_RAW = { target: "awg2", container_id: CID, image_id: "sha256:" + "b".repeat(64),
  config_sha256: "c".repeat(64), table_sha256: "d".repeat(64),
  configured_clients: 2, protocol: "amneziawg", interface: "awg0",
  listen_port: 51820, server_subnet: "10.0.0.0/24" };
const SETUP_RAW = { schema_version: 1, action: "preview", writes: false,
  selected_target: "awg2", marker: "absent", other_marker: "absent",
  socket_active: false, service_active: false, installer_ready: true,
  installed_current: false, can_arm: false,
  target: { ready: true, container_id: CID, configured_clients: 2,
    owned_clients: ["a", "b"] } };

function credentials(overrides = {}) {
  return { username: "root", method: "password", fingerprint: FINGERPRINT,
    password: "test-password", private_key: "", passphrase: "", target: "awg2", ...overrides };
}

function clients(replies, commands, key = KEY) {
  return () => {
    const client = new EventEmitter();
    client.end = () => {};
    client.connect = (config) => {
      commands.push({ kind: "connect", host: config.host, port: config.port,
        username: config.username, hasPassword: config.password === "test-password" });
      queueMicrotask(() => {
        if (config.hostVerifier(key)) client.emit("ready");
        else client.emit("error", new Error("rejected"));
      });
    };
    client.exec = (command, options, callback) => {
      commands.push({ kind: "exec", command, options });
      const response = replies.shift();
      assert.ok(response, "unexpected SSH command");
      const stream = new EventEmitter();
      stream.stderr = new EventEmitter();
      callback(null, stream);
      queueMicrotask(() => {
        stream.emit("data", Buffer.from(JSON.stringify(response)));
        stream.emit("close", 0, null);
      });
    };
    return client;
  };
}

test("enrollment preview exposes only exact public CAS pins and verifies SSH identity", async () => {
  const review = safeAmneziaEnrollmentPreview(JSON.stringify({ ...ENROLL_RAW }), "awg2", FINGERPRINT);
  assert.equal(review.protocol, 1);
  assert.equal(review.vpn_protocol, "amneziawg");
  assert.equal(review.container_id, CID);
  assert.equal(review.host_key_fingerprint, FINGERPRINT);
  assert.equal(review.writes, false);
  for (const raw of [{ ...ENROLL_RAW, private_key: "secret" },
    { ...ENROLL_RAW, server_subnet: "10.0.0.1/24" },
    { ...ENROLL_RAW, image_id: "bad" }]) {
    assert.throws(() => safeAmneziaEnrollmentPreview(JSON.stringify(raw), "awg2", FINGERPRINT),
      /SETUP_UNAVAILABLE/);
  }
  const input = credentials();
  const commands = [];
  const result = await previewAmneziaEnrollment(input,
    { clientFactory: clients([ENROLL_RAW], commands) });
  assert.deepEqual(result, review);
  assert.equal(commands[0].host, "172.30.253.1");
  assert.equal(commands[0].hasPassword, true);
  assert.equal(commands[1].command,
    "cd /opt/sovagrid-vpn && /usr/bin/python3 -B -E -S -m sovagrid_vpn.amnezia_admin enroll-preview awg2");
  assert.deepEqual(commands[1].options, { pty: false });
  assert.equal(input.password, "");
  const changed = [];
  await assert.rejects(previewAmneziaEnrollment(credentials({ fingerprint: "SHA256:" + "B".repeat(43) }),
    { clientFactory: clients([], changed) }), /HOST_KEY_CHANGED/);
  assert.equal(changed.some((item) => item.kind === "exec"), false);
});

test("enroll rechecks every reviewed pin and executes only the fixed root CLI", async () => {
  const reviewed = safeAmneziaEnrollmentPreview(JSON.stringify(ENROLL_RAW), "awg2", FINGERPRINT);
  const input = { ...credentials(), reviewed, confirm: "ENROLL_EXISTING_CONTAINER" };
  let adminChecks = 0;
  const commands = [];
  const result = await enrollAmneziaSetup(input, {
    clientFactory: clients([ENROLL_RAW,
      { target: "awg2", enrolled: true, configured_clients: 2 }, SETUP_RAW], commands),
    recheckAdmin: async () => { adminChecks++; },
  });
  assert.equal(adminChecks, 1);
  assert.equal(result.action, "enrolled");
  assert.equal(result.container_id, CID);
  assert.equal(input.password, "");
  assert.equal(commands.filter((item) => item.kind === "exec").length, 3);
  assert.equal(commands.filter((item) => item.kind === "connect")
    .every((item) => item.hasPassword), true);
  assert.equal(commands[3].command,
    "cd /opt/sovagrid-vpn && /usr/bin/python3 -B -E -S -m sovagrid_vpn.amnezia_admin enroll awg2" +
    " --confirm-container-id " + CID + " --confirm-image-id sha256:" + "b".repeat(64) +
    " --confirm-config-sha256 " + "c".repeat(64) +
    " --confirm-table-sha256 " + "d".repeat(64));
  assert.match(commands[5].command, /install-amnezia-control.py preview --target awg2$/);
  const stale = [];
  await assert.rejects(enrollAmneziaSetup({ ...credentials(), reviewed,
    confirm: "ENROLL_EXISTING_CONTAINER" }, {
    clientFactory: clients([{ ...ENROLL_RAW, table_sha256: "e".repeat(64) }], stale),
    recheckAdmin: async () => { throw new Error("unexpected admin recheck"); },
  }), /SETUP_CHANGED/);
  assert.equal(stale.filter((item) => item.kind === "exec").length, 1);
});

test("enroll and arm reject missing confirmation and unsafe reviewed state", () => {
  const reviewed = safeAmneziaEnrollmentPreview(JSON.stringify(ENROLL_RAW), "awg2", FINGERPRINT);
  assert.throws(() => validateAmneziaEnrollment({ ...credentials(), reviewed,
    confirm: "wrong" }), /INVALID_INPUT/);
  assert.throws(() => validateAmneziaEnrollment({ ...credentials(), reviewed: { ...reviewed,
    host_key_fingerprint: "SHA256:" + "B".repeat(43) },
    confirm: "ENROLL_EXISTING_CONTAINER" }), /INVALID_INPUT/);
  const setup = safeAmneziaPreview(JSON.stringify(SETUP_RAW), "awg2");
  assert.throws(() => validateAmneziaSetupAction({ ...credentials(), reviewed: setup,
    confirm: "wrong" }, "install"), /INVALID_INPUT/);
  assert.throws(() => validateAmneziaSetupAction({ ...credentials(), reviewed: setup,
    confirm: "I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG2" }, "arm"), /INVALID_INPUT/);
});

test("install and arm reverify state, require confirmation and verify the final state", async () => {
  const setup = safeAmneziaPreview(JSON.stringify(SETUP_RAW), "awg2");
  const installedRaw = { ...SETUP_RAW, installed_current: true, can_arm: true };
  const installed = safeAmneziaPreview(JSON.stringify(installedRaw), "awg2");
  const armedRaw = { ...installedRaw, marker: "valid", socket_active: true, can_arm: false };
  const commands = [];
  let adminChecks = 0;
  const installInput = { ...credentials(), reviewed: setup,
    confirm: "INSTALL_AMNEZIA_BROKER" };
  const install = await mutateAmneziaSetup(installInput, "install", {
    clientFactory: clients([SETUP_RAW,
      { action: "installed", socket_active: false, marker: "absent", target_changed: false },
      installedRaw], commands),
    recheckAdmin: async () => { adminChecks++; },
  });
  assert.equal(install.action, "installed");
  assert.equal(install.setup.installed_current, true);
  assert.equal(adminChecks, 1);
  assert.equal(installInput.password, "");
  assert.equal(commands.filter((item) => item.kind === "connect")
    .every((item) => item.hasPassword), true);
  assert.equal(commands.filter((item) => item.kind === "exec")[1].command,
    "/usr/bin/python3 -I /opt/sovagrid-src/sovagrid-vpn/deploy/install-amnezia-control.py install");
  const armCommands = [];
  const armInput = { ...credentials(), reviewed: installed,
    confirm: "I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG2" };
  const arm = await mutateAmneziaSetup(armInput, "arm", {
    clientFactory: clients([installedRaw,
      { action: "armed", socket_active: true, marker: "valid",
        selected_target: "awg2", target_changed: false }, armedRaw], armCommands),
    recheckAdmin: async () => { adminChecks++; },
  });
  assert.equal(arm.action, "armed");
  assert.equal(arm.setup.marker, "valid");
  assert.equal(adminChecks, 2);
  assert.equal(armInput.password, "");
  assert.equal(armCommands.filter((item) => item.kind === "connect")
    .every((item) => item.hasPassword), true);
  assert.match(armCommands.filter((item) => item.kind === "exec")[1].command,
    /arm --target awg2 --confirm-container-id a{64} --confirm-maintenance-window I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG2$/);
});

test("install fails closed on a changed snapshot and reports an uncertain write", async () => {
  const reviewed = safeAmneziaPreview(JSON.stringify(SETUP_RAW), "awg2");
  const staleCommands = [];
  await assert.rejects(mutateAmneziaSetup({ ...credentials(), reviewed,
    confirm: "INSTALL_AMNEZIA_BROKER" }, "install", {
    clientFactory: clients([{ ...SETUP_RAW, target: { ...SETUP_RAW.target,
      configured_clients: 3 } }], staleCommands),
  }), /SETUP_CHANGED/);
  assert.equal(staleCommands.filter((item) => item.kind === "exec").length, 1);
  const uncertainCommands = [];
  const input = { ...credentials(), reviewed, confirm: "INSTALL_AMNEZIA_BROKER" };
  await assert.rejects(mutateAmneziaSetup(input, "install", {
    clientFactory: clients([SETUP_RAW, { action: "installed", extra: "unsafe" }], uncertainCommands),
  }), /SETUP_UNCERTAIN/);
  assert.equal(input.password, "");
  assert.equal(uncertainCommands.filter((item) => item.kind === "exec").length, 2);
});

test("WireGuard enrollment accepts its own exact protocol and sudo command", async () => {
  const wireguard = { ...ENROLL_RAW, target: "wireguard", protocol: "wireguard",
    interface: "wg0" };
  const input = credentials({ target: "wireguard", username: "operator" });
  const commands = [];
  const result = await previewAmneziaEnrollment(input,
    { clientFactory: clients([wireguard], commands) });
  assert.equal(result.vpn_protocol, "wireguard");
  assert.equal(commands[1].command,
    "cd /opt/sovagrid-vpn && /usr/bin/sudo -n -- /usr/bin/python3 -B -E -S -m sovagrid_vpn.amnezia_admin enroll-preview wireguard");
});

test("remote Amnezia preview pins a separate entered SSH host and preserves local requests", async () => {
  const remote = credentials({ host: "VPN.Example", port: 2202 });
  assert.equal(validateAmneziaPreview(remote).endpoint.host, "vpn.example");
  assert.throws(() => validateAmneziaPreview(credentials({ host: "vpn.example" })), /INVALID_INPUT/);
  assert.throws(() => validateAmneziaPreview(credentials({ host: "https:\/\/vpn.example", port: 22 })),
    /INVALID_INPUT/);
  const commands = [];
  const result = await previewAmneziaSetup(remote,
    { clientFactory: clients([SETUP_RAW], commands) });
  assert.deepEqual({ scope: result.scope, host: result.host, port: result.port,
    fingerprint: result.host_key_fingerprint },
  { scope: "entered_target", host: "vpn.example", port: 2202, fingerprint: FINGERPRINT });
  assert.equal(commands[0].host, "vpn.example");
  assert.equal(commands[0].port, 2202);
  assert.equal(commands[1].command,
    "/usr/bin/python3 -I /opt/sovagrid-src/sovagrid-vpn/deploy/install-amnezia-control.py preview --target awg2");
  assert.equal(remote.password, "");

  const mismatchCommands = [];
  const mismatched = credentials({ host: "vpn.example", port: 2202,
    fingerprint: "SHA256:" + "B".repeat(43) });
  await assert.rejects(previewAmneziaSetup(mismatched,
    { clientFactory: clients([], mismatchCommands) }), /HOST_KEY_CHANGED/);
  assert.equal(mismatched.password, "");
  assert.equal(mismatchCommands.some((item) => item.kind === "exec"), false);
  const local = await previewAmneziaSetup(credentials(),
    { clientFactory: clients([SETUP_RAW], []) });
  assert.equal(Object.hasOwn(local, "host"), false);
  assert.equal(Object.hasOwn(local, "scope"), false);
});

test("remote enrollment and broker mutation bind reviewed host, port and key across all SSH steps", async () => {
  const endpoint = { host: "vpn.example", port: 2202 };
  const reviewInput = credentials({ ...endpoint });
  const reviewedCommands = [];
  const reviewed = await previewAmneziaEnrollment(reviewInput,
    { clientFactory: clients([ENROLL_RAW], reviewedCommands) });
  assert.equal(reviewed.scope, "entered_target");
  assert.equal(reviewed.host, endpoint.host);
  assert.equal(reviewed.port, endpoint.port);
  assert.equal(reviewed.host_key_fingerprint, FINGERPRINT);
  assert.equal(reviewInput.password, "");
  assert.throws(() => validateAmneziaEnrollment({ ...credentials({ host: "other.example", port: 2202 }),
    reviewed, confirm: "ENROLL_EXISTING_CONTAINER" }), /INVALID_INPUT/);
  assert.throws(() => validateAmneziaEnrollment({ ...credentials({ host: endpoint.host, port: 2203 }),
    reviewed, confirm: "ENROLL_EXISTING_CONTAINER" }), /INVALID_INPUT/);
  assert.throws(() => validateAmneziaEnrollment({ ...credentials(endpoint),
    reviewed: { ...reviewed, host_key_fingerprint: "SHA256:" + "B".repeat(43) },
    confirm: "ENROLL_EXISTING_CONTAINER" }), /INVALID_INPUT/);
  const enrollCommands = [];
  const enrolled = await enrollAmneziaSetup({ ...credentials(endpoint), reviewed,
    confirm: "ENROLL_EXISTING_CONTAINER" }, {
    clientFactory: clients([ENROLL_RAW,
      { target: "awg2", enrolled: true, configured_clients: 2 }, SETUP_RAW], enrollCommands),
  });
  assert.equal(enrolled.setup.host, endpoint.host);
  assert.equal(enrolled.setup.port, endpoint.port);
  assert.equal(enrollCommands.filter((item) => item.kind === "connect").length, 3);
  assert.equal(enrollCommands.filter((item) => item.kind === "connect")
    .every((item) => item.host === endpoint.host && item.port === endpoint.port), true);

  const setup = enrolled.setup;
  assert.throws(() => validateAmneziaSetupAction({ ...credentials({ host: "other.example", port: 2202 }),
    reviewed: setup, confirm: "INSTALL_AMNEZIA_BROKER" }, "install"), /INVALID_INPUT/);
  const installedRaw = { ...SETUP_RAW, installed_current: true, can_arm: true };
  const installCommands = [];
  const installed = await mutateAmneziaSetup({ ...credentials(endpoint), reviewed: setup,
    confirm: "INSTALL_AMNEZIA_BROKER" }, "install", {
    clientFactory: clients([SETUP_RAW,
      { action: "installed", socket_active: false, marker: "absent", target_changed: false },
      installedRaw], installCommands),
  });
  assert.equal(installed.setup.scope, "entered_target");
  assert.equal(installCommands.filter((item) => item.kind === "connect")
    .every((item) => item.host === endpoint.host && item.port === endpoint.port), true);
  const armedRaw = { ...installedRaw, marker: "valid", socket_active: true, can_arm: false };
  const armCommands = [];
  const armed = await mutateAmneziaSetup({ ...credentials(endpoint), reviewed: installed.setup,
    confirm: "I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG2" }, "arm", {
    clientFactory: clients([installedRaw,
      { action: "armed", socket_active: true, marker: "valid", selected_target: "awg2",
        target_changed: false }, armedRaw], armCommands),
  });
  assert.equal(armed.setup.host, endpoint.host);
  assert.equal(armCommands.filter((item) => item.kind === "connect")
    .every((item) => item.host === endpoint.host && item.port === endpoint.port), true);
});

async function call(handler, path, payload, headers = {}) {
  const request = Readable.from([Buffer.from(JSON.stringify(payload))]);
  request.method = "POST";
  request.url = path;
  request.headers = { host: "example.com", origin: "https://example.com",
    "x-forwarded-proto": "https", "x-sovagrid-client-ip": "203.0.113.42",
    "content-type": "application/json", authorization: "Bearer " + TOKEN, ...headers };
  const result = {};
  const response = { destroyed: false, writeHead(status) { result.status = status; },
    end(body) { result.body = JSON.parse(body); } };
  await handler(request, response);
  return result;
}

test("write routes require same-origin unrestricted admin and recheck immediately before mutation", async () => {
  let checks = 0;
  let writes = 0;
  const handler = createHandler({ admin: async (authorization) => {
    checks++;
    if (authorization !== "Bearer " + TOKEN) throw new Error("AUTH_REQUIRED");
  },
    enrollPreview: async () => ({ protocol: 1 }),
    enroll: async (value, options) => {
      await options.recheckAdmin();
      writes++;
      assert.equal(value.password, "test-password");
      return { protocol: 1, action: "enrolled" };
    } });
  const path = "/api/v1/browser-ssh/vpn-setup/enroll";
  const input = { ...credentials(), reviewed: {}, confirm: "ENROLL_EXISTING_CONTAINER" };
  assert.equal((await call(handler, path, input,
    { origin: "https://attacker.example" })).status, 404);
  assert.equal(checks, 0);
  assert.equal((await call(handler, path, input,
    { authorization: "" })).status, 401);
  assert.equal((await call(handler, path, input)).status, 200);
  assert.equal(writes, 1);
  assert.equal(checks, 3);
  const restricted = createHandler({ admin: async () => { throw new Error("ADMIN_FORBIDDEN"); },
    enroll: async () => { throw new Error("unexpected write"); } });
  assert.equal((await call(restricted, path, input)).status, 403);
});

test("HTTP setup routes map stale and uncertain results without returning SSH secrets", async () => {
  const actions = [];
  const parsed = [];
  const handler = createHandler({ admin: async () => {},
    enrollPreview: async (value) => { parsed.push(value);
      return { protocol: 1, action: "enroll_preview" }; },
    vpnMutate: async (value, action, options) => {
      parsed.push(value);
      actions.push(action);
      await options.recheckAdmin();
      assert.equal(value.password, "test-password");
      throw new Error(action === "install" ? "SETUP_CHANGED" : "SETUP_UNCERTAIN");
    } });
  const prefix = "/api/v1/browser-ssh/vpn-setup/";
  const previewInput = credentials();
  assert.equal((await call(handler, prefix + "enroll-preview", previewInput)).status, 200);
  const staleInput = credentials();
  const stale = await call(handler, prefix + "install", staleInput);
  assert.equal(stale.status, 409);
  assert.deepEqual(stale.body, { error: "SETUP_CHANGED" });
  const uncertainInput = credentials();
  const uncertain = await call(handler, prefix + "arm", uncertainInput);
  assert.equal(uncertain.status, 503);
  assert.deepEqual(uncertain.body, { error: "SETUP_UNCERTAIN" });
  assert.equal(parsed.every((value) => value.password === ""), true);
  assert.deepEqual(actions, ["install", "arm"]);
});

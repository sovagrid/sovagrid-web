/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ../../ATTRIBUTION.md. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { createHandler, proxyRestore, safeRestoreResult, validateRestorePayload } from "../server.js";

const ID = "a".repeat(32), OP = "b".repeat(32), TOKEN = "t".repeat(43);
const FP = "SHA256:" + "A".repeat(43);
const META = Object.fromEntries(["host_manifest", "host", "images_manifest", "images", "receipt"]
  .map((part) => [part, { bytes: 1, sha256: "c".repeat(64) }]));
const route = { host: "server.example.com", port: 22, username: "root", fingerprint: FP };
const login = { ...route, method: "password", password: "ephemeral-password", private_key: "", passphrase: "" };
function imported() {
  return { protocol: "sovagrid-web-restore-v1", source_id: ID, archive_id: OP,
    max_chunk_bytes: 4194304, pending_chunk: null, complete: false,
    artifacts: Object.fromEntries(Object.entries(META).map(([key, item]) =>
      [key, { ...item, received: 0, complete: false }])) };
}
function state() {
  return { protocol: "sovagrid-web-restore-v1", operation_id: OP, created_at: 1800000000,
    archive_id: ID, source: { kind: "upload", id: ID }, route, phase: "review", worker_active: false,
    progress: "План готов", target: { protocol: "sovagrid-portable-restore-target-v1", operation_id: OP,
      archive_id: ID, request_sha256: "f".repeat(64), phase: "review", registered: true,
      backend_supported: true, target_ready: true, apply_available: true,
      blockers: [], apply_review_sha256: "d".repeat(64) }, error: null, expected_revision: "e".repeat(64) };
}
function request(action, value, { raw = null, origin = "https://panel.example.com" } = {}) {
  const req = Readable.from([raw || Buffer.from(JSON.stringify(value))]);
  req.method = "POST"; req.url = `/api/v1/browser-ssh/restore/${action}`;
  req.headers = { host: "panel.example.com", origin, "x-forwarded-proto": "https",
    "x-sovagrid-client-ip": "192.0.2.15", authorization: `Bearer ${TOKEN}`,
    "content-type": raw ? "application/octet-stream" : "application/json",
    ...(raw ? { "x-sovagrid-restore-meta": encodeURIComponent(JSON.stringify(value)) } : {}) };
  return req;
}
function response() {
  return { status: null, value: null, destroyed: false,
    writeHead(code) { this.status = code; }, end(raw) { this.value = JSON.parse(raw); } };
}

test("restore route schema accepts pinned credentials and only fixed operation fields", () => {
  const selected = validateRestorePayload("start", { ...login, operation_id: OP, expected_revision: "c".repeat(64),
    apply_review_sha256: "d".repeat(64), confirm: true });
  assert.equal(selected.fingerprint, FP);
  for (const changed of [{ ...selected, path: "/root/elsewhere" }, { ...selected, confirm: false },
    { ...selected, operation_id: "../bad" }, { ...selected, apply_review_sha256: "not-a-digest" }])
    assert.throws(() => validateRestorePayload("start", changed), /INVALID_INPUT/);
  assert.throws(() => validateRestorePayload("import-init", { source_id: ID, archive_id: OP,
    artifacts: { ...META, host: { bytes: true, sha256: "a".repeat(64) } } }), /INVALID_INPUT/);
});

test("bounded result projection refuses credential fields and contradictory apply readiness", () => {
  assert.equal(safeRestoreResult("status", state()).operation_id, OP);
  assert.throws(() => safeRestoreResult("status", { ...state(), password: "leak" }), /INSTALLER_UNAVAILABLE/);
  const changed = state(); changed.target.blockers = ["TARGET_NOT_CLEAN"];
  assert.throws(() => safeRestoreResult("status", changed), /INSTALLER_UNAVAILABLE/);
  const bad = imported(); bad.artifacts.host.received = true;
  assert.throws(() => safeRestoreResult("import-status", bad), /INSTALLER_UNAVAILABLE/);
  for (const invalid of [{ policy: { password: "leak" } }, { private_key: "leak" },
    { target_free_bytes: true }, { target_empty: "yes" }]) {
    const reply = state(); reply.target.preview = invalid;
    assert.throws(() => safeRestoreResult("status", reply), /INSTALLER_UNAVAILABLE/);
  }
});

test("all restore mutations require same-origin current unrestricted admin before dispatch", async () => {
  let called = 0, checked = 0;
  const handler = createHandler({ admin: async () => { checked++; },
    restore: async () => { called++; return state(); } });
  const res = response();
  await handler(request("prepare", { ...login, operation_id: OP, source: { kind: "backup", id: ID } }), res);
  assert.equal(res.status, 200); assert.equal(called, 1); assert.equal(checked, 2);
  const forbidden = response();
  await handler(request("status", { operation_id: OP }, { origin: "https://other.example.com" }), forbidden);
  assert.equal(forbidden.status, 404); assert.equal(called, 1);
  let attempts = 0;
  const revoked = createHandler({ admin: async () => { if (++attempts === 2) throw new Error("ADMIN_FORBIDDEN"); },
    restore: async () => { called++; return state(); } });
  const denied = response();
  await revoked(request("start", { ...login, operation_id: OP, expected_revision: "e".repeat(64),
    apply_review_sha256: "d".repeat(64), confirm: true }), denied);
  assert.equal(denied.status, 403); assert.equal(called, 1);
});

test("4MiB binary upload crosses HTTP as raw bounded bytes, never giant JSON", async () => {
  const payload = Buffer.alloc(4194304); for (let i = 0; i < payload.length; i++) payload[i] = i % 256;
  const expected = createHash("sha256").update(payload).digest("hex");
  let calls = 0;
  const handler = createHandler({ admin: async () => {}, restore: async (action, meta, token, { binary }) => {
    calls++; assert.equal(action, "import-chunk"); assert.equal(token, TOKEN);
    assert.equal(meta.sha256, expected); assert.equal(createHash("sha256").update(binary).digest("hex"), expected);
    return imported();
  } });
  const res = response();
  await handler(request("import-chunk", { source_id: ID, part: "host", offset: 0, length: payload.length, sha256: expected },
    { raw: payload }), res);
  assert.equal(res.status, 200); assert.equal(calls, 1);
  const wrong = response();
  await handler(request("import-chunk", { source_id: ID, part: "host", offset: 0, length: 2, sha256: expected },
    { raw: Buffer.alloc(3) }), wrong);
  assert.equal(wrong.status, 400); assert.equal(calls, 1);
});

test("actual Unix socket keeps the JSON header separate from arbitrary binary newlines", async (t) => {
  const directory = mkdtempSync(join(tmpdir(), "sg-restore-proxy-")), path = join(directory, "s");
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const raw = Buffer.from([0, 10, 255, 13, 123, 34, 10]);
  const sha = createHash("sha256").update(raw).digest("hex");
  const metadata = { source_id: ID, part: "host", offset: 0, length: raw.length, sha256: sha };
  const server = net.createServer((socket) => {
    let received = Buffer.alloc(0);
    socket.on("data", (part) => { received = Buffer.concat([received, part]); });
    socket.on("end", () => {
      const newline = received.indexOf(10), header = JSON.parse(received.subarray(0, newline).toString());
      assert.equal(header.action, "restore-import-chunk"); assert.equal(header.session_token, TOKEN);
      assert.deepEqual(received.subarray(newline + 1), raw);
      socket.end(JSON.stringify({ ok: true, result: imported() }) + "\n");
    });
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(path, resolve); });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  assert.equal((await proxyRestore("import-chunk", metadata, TOKEN, { socketPath: path, binary: raw })).source_id, ID);
});

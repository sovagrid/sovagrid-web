/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ../ATTRIBUTION.md. */
"use strict";

import { createHash, timingSafeEqual } from "node:crypto";
import http from "node:http";
import net from "node:net";
import { fileURLToPath } from "node:url";
import ssh2 from "ssh2";

const { Client } = ssh2;
const TARGET = "172.30.253.1"; // Fixed Docker bridge gateway: this Ubuntu host only.
const PORT = Number(process.env.SOVAGRID_HOST_SSH_PORT || "22");
const GRANT_COMMAND = "/usr/bin/docker compose --env-file /etc/sovagrid/deploy.env -f /opt/sovagrid-src/sovagrid-blueprint/deploy/compose.yaml run --rm --no-deps -T --entrypoint python3 hub -m sovagrid_hub --db /data/hub.sqlite ssh-grant";
const AMNEZIA_PREVIEW_COMMAND = "/usr/bin/python3 -I /opt/sovagrid-src/sovagrid-vpn/deploy/install-amnezia-control.py preview --target ";
// Fixed, read-only inventory. No user input is interpolated into the command or script.
// Keep the classification in step with sovagrid-connect/server_status.py.
const STATUS_COMMAND = "sh -c 'if ! command -v python3 >/dev/null 2>&1; then printf \"SG_STATUS_V1:unsupported\\n\"; exit 0; fi; if [ \"$(id -u)\" = 0 ]; then exec python3 -I -; fi; if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then exec sudo -n python3 -I -; fi; printf \"SG_STATUS_V1:unknown\\n\"'";
const STATUS_SCRIPT = String.raw`# SOVAGRID_SSH_STATUS_V1
import os
from pathlib import Path
import shutil
import stat
import subprocess

def node(path):
    try:
        return Path(path).lstat()
    except FileNotFoundError:
        return None

def present(path):
    return node(path) is not None

def regular(path):
    info = node(path)
    return info is not None and stat.S_ISREG(info.st_mode) and info.st_uid == 0

def directory(path):
    info = node(path)
    return info is not None and stat.S_ISDIR(info.st_mode) and info.st_uid == 0

def result(kind):
    print('SG_STATUS_V1:' + kind, flush=True)
    raise SystemExit(0)

try:
    if os.geteuid() != 0:
        result('unknown')
    release = Path('/etc/os-release')
    if not release.is_file():
        result('unsupported')
    raw = release.read_text(encoding='utf-8')[:8192]
    values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line and not line.startswith('#'))
    if values.get('ID', '').strip('"\'') != 'ubuntu':
        result('unsupported')
    full = directory('/opt/sovagrid-src') and regular('/opt/sovagrid-src/sovagrid-bundle.json') and \
        regular('/var/lib/sovagrid/.managed-by-run-sh')
    if full:
        result('managed')
    agent = regular('/opt/sovagrid-agent-installer/source-manifest.json') and \
        regular('/etc/systemd/system/sovagrid-agent.service') and \
        directory('/var/lib/sovagrid-agent-enrollment')
    if agent and not any(present(path) for path in (
        '/opt/sovagrid-src', '/etc/sovagrid-hub', '/var/lib/sovagrid',
        '/etc/sovagrid/.agent-unit-managed-by-run-sh',
    )):
        result('agent_only')
    reserved = (
        '/opt/sovagrid-src', '/opt/sovagrid-agent', '/opt/sovagrid-agent-installer',
        '/opt/sovagrid-vpn', '/etc/sovagrid', '/etc/sovagrid-hub',
        '/etc/sovagrid-agent-tunnel', '/etc/sovagrid-agent-tunnel-public',
        '/var/lib/sovagrid', '/var/lib/sovagrid-agent',
        '/var/lib/sovagrid-agent-enrollment', '/var/lib/sovagrid-hub-tunnels',
        '/var/lib/sovagrid-first-install',
    )
    if any(present(path) for path in reserved):
        result('conflict')
    for base in ('/etc/systemd/system', '/run/systemd/system', '/usr/local/lib/systemd/system'):
        path = Path(base)
        if path.is_dir() and any(entry.name.startswith('sovagrid-') for entry in path.iterdir()):
            result('conflict')
    if shutil.which('docker'):
        scan = subprocess.run(
            ['docker', 'ps', '-a', '--filter', 'label=com.docker.compose.project=sovagrid',
             '--format', '{{.ID}}'], capture_output=True, timeout=8, check=False,
        )
        if scan.returncode != 0:
            result('unknown')
        if scan.stdout.strip():
            result('conflict')
    result('missing')
except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
    result('unknown')
`;
const HUB_ACCESS_URL = "http://hub:8765/api/v1/session/access";
const MAX_BODY = 70 * 1024;
const MAX_OUTPUT = 4096;
const MAX_STATUS_OUTPUT = 512;
// The installer can list 128 owned clients, each with a 32-character name.
const MAX_AMNEZIA_PREVIEW_OUTPUT = 16 * 1024;
const FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{43}$/;
const USERNAME = /^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/;
const GRANT = /^[A-Za-z0-9_-]{43}$/;
const BEARER = /^Bearer ([A-Za-z0-9_-]{43})$/;

if (!Number.isSafeInteger(PORT) || PORT < 1 || PORT > 65535) {
  throw new Error("Invalid fixed host SSH port");
}

export function hostKey(key) {
  if (!Buffer.isBuffer(key) || key.length < 8 || key.length > 8192) {
    throw new Error("Invalid SSH host key");
  }
  const length = key.readUInt32BE(0);
  if (length < 4 || length > 96 || 4 + length > key.length) {
    throw new Error("Invalid SSH host key type");
  }
  const type = key.subarray(4, 4 + length).toString("ascii");
  if (!/^[A-Za-z0-9@._-]+$/.test(type)) throw new Error("Invalid SSH host key type");
  return { key_type: type, fingerprint: "SHA256:" + createHash("sha256").update(key).digest("base64").replace(/=+$/, "") };
}

function sameFingerprint(actual, expected) {
  if (!FINGERPRINT.test(expected)) return false;
  return timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
}

export function validateLogin(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !["username", "method", "fingerprint", "password", "private_key", "passphrase"].every((key) =>
        Object.hasOwn(value, key)) || Object.keys(value).length !== 6 ||
      typeof value.username !== "string" || !USERNAME.test(value.username) ||
      typeof value.fingerprint !== "string" || !FINGERPRINT.test(value.fingerprint) ||
      !["password", "private_key"].includes(value.method) ||
      typeof value.password !== "string" || typeof value.private_key !== "string" ||
      typeof value.passphrase !== "string") {
    throw new Error("INVALID_INPUT");
  }
  if (value.method === "password") {
    if (!value.password || value.password.length > 1024 || value.private_key || value.passphrase) {
      throw new Error("INVALID_INPUT");
    }
  } else if (!value.private_key || Buffer.byteLength(value.private_key, "utf8") > 65536 ||
             value.password || value.passphrase.length > 1024) {
    throw new Error("INVALID_INPUT");
  }
  return value;
}

export function validateAmneziaPreview(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== 7 ||
      !["username", "method", "fingerprint", "password", "private_key", "passphrase", "target"]
        .every((key) => Object.hasOwn(value, key)) ||
      !["awg2", "wireguard"].includes(value.target)) {
    throw new Error("INVALID_INPUT");
  }
  const login = Object.fromEntries(["username", "method", "fingerprint", "password", "private_key", "passphrase"]
    .map((key) => [key, value[key]]));
  validateLogin(login);
  return { login, target: value.target };
}

export function validateTargetHostKey(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== 2 || !Object.hasOwn(value, "host") ||
      !Object.hasOwn(value, "port") || typeof value.host !== "string" ||
      !Number.isSafeInteger(value.port) || value.port < 1 || value.port > 65535) {
    throw new Error("INVALID_INPUT");
  }
  const host = value.host;
  if (!host || host.length > 253 || host !== host.trim() || host.includes("%") ||
      host.includes("[") || host.includes("]")) {
    throw new Error("INVALID_INPUT");
  }
  if (net.isIP(host) === 0) {
    // A hostname is an ASCII DNS name or a single-label local name. A
    // numeric-only string is ambiguous in resolver APIs and must be an IP.
    const labels = host.split(".");
    if (/^[0-9.]+$/.test(host) || labels.some((label) => label.length < 1 ||
        label.length > 63 || !/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label))) {
      throw new Error("INVALID_INPUT");
    }
  }
  return { host: host.toLowerCase(), port: value.port };
}

export function validateTargetStatus(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== 8 ||
      !["host", "port", "username", "method", "fingerprint", "password", "private_key", "passphrase"]
        .every((key) => Object.hasOwn(value, key))) {
    throw new Error("INVALID_INPUT");
  }
  const target = validateTargetHostKey({ host: value.host, port: value.port });
  if (typeof value.method === "string" && !["password", "private_key"].includes(value.method)) {
    throw new Error("UNSUPPORTED_AUTH_METHOD");
  }
  const login = Object.fromEntries(["username", "method", "fingerprint", "password", "private_key", "passphrase"]
    .map((key) => [key, value[key]]));
  validateLogin(login);
  return { ...target, ...login };
}

export async function requireUnrestrictedAdmin(authorization, { fetchImpl = fetch } = {}) {
  if (typeof authorization !== "string" || !BEARER.test(authorization)) {
    throw new Error("AUTH_REQUIRED");
  }
  let reply;
  try {
    reply = await fetchImpl(HUB_ACCESS_URL, { method: "GET", headers: { Authorization: authorization },
      cache: "no-store", redirect: "error", signal: AbortSignal.timeout(3000) });
  } catch { throw new Error("HUB_UNAVAILABLE"); }
  if (reply.status === 401) throw new Error("AUTH_REQUIRED");
  if (reply.status === 403) throw new Error("ADMIN_FORBIDDEN");
  if (reply.status !== 200) throw new Error("HUB_UNAVAILABLE");
  let access;
  try {
    const contentLength = Number(reply.headers.get("content-length"));
    if (Number.isFinite(contentLength) && contentLength > 2048) throw new Error("large response");
    const raw = await reply.text();
    if (Buffer.byteLength(raw, "utf8") > 2048) throw new Error("large response");
    access = JSON.parse(raw)?.access;
  } catch { throw new Error("HUB_UNAVAILABLE"); }
  if (!access || typeof access !== "object" || Array.isArray(access) ||
      !["all", "selected"].includes(access.mode) ||
      typeof access.unrestricted_admin !== "boolean" ||
      !Number.isSafeInteger(access.revision) || access.revision < 0) {
    throw new Error("HUB_UNAVAILABLE");
  }
  if (access.mode !== "all" || access.unrestricted_admin !== true) {
    throw new Error("ADMIN_FORBIDDEN");
  }
}

export function safeAmneziaPreview(raw, expectedTarget) {
  let value;
  try { value = JSON.parse(raw); }
  catch { throw new Error("SETUP_UNAVAILABLE"); }
  const target = value?.target;
  const marker = ["absent", "valid", "unsafe"];
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      value.schema_version !== 1 || value.action !== "preview" || value.writes !== false ||
      value.selected_target !== expectedTarget || !marker.includes(value.marker) ||
      !marker.includes(value.other_marker) ||
      ["socket_active", "service_active", "installer_ready", "installed_current", "can_arm"]
        .some((key) => typeof value[key] !== "boolean") ||
      !target || typeof target !== "object" || Array.isArray(target) ||
      typeof target.ready !== "boolean") {
    throw new Error("SETUP_UNAVAILABLE");
  }
  const result = { protocol: 1, target: expectedTarget, enrolled: target.ready,
    marker: value.marker, other_marker: value.other_marker,
    socket_active: value.socket_active, service_active: value.service_active,
    installer_ready: value.installer_ready, installed_current: value.installed_current,
    can_arm: value.can_arm };
  if (target.ready) {
    if (typeof target.container_id !== "string" || !/^[a-f0-9]{64}$/.test(target.container_id) ||
        !Number.isSafeInteger(target.configured_clients) || target.configured_clients < 0 ||
        !Array.isArray(target.owned_clients) || target.owned_clients.length > target.configured_clients) {
      throw new Error("SETUP_UNAVAILABLE");
    }
    result.container_id = target.container_id;
    result.configured_clients = target.configured_clients;
    result.owned_clients = target.owned_clients.length;
  } else {
    result.reason = target.reason === (expectedTarget === "awg2" ? "AWG2" : "WireGuard") + " is not enrolled"
      ? "NOT_ENROLLED" : "UNAVAILABLE";
  }
  return result;
}

function inspectSSHHostKey(host, port, { clientFactory = () => new Client(), timeoutMs = 8000 } = {}) {
  return new Promise((resolve, reject) => {
    const client = clientFactory();
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      queueMicrotask(() => client.end());
      if (error) reject(error);
      else resolve(value);
    };
    const timer = setTimeout(() => finish(new Error("SSH_UNAVAILABLE")), timeoutMs);
    client.on("error", () => finish(new Error("SSH_UNAVAILABLE")));
    client.on("close", () => finish(new Error("SSH_UNAVAILABLE")));
    try {
      client.connect({ host, port, username: "sovagrid-probe",
        readyTimeout: Math.min(timeoutMs, 7000), tryKeyboard: false,
        hostVerifier: (key) => {
          try { finish(null, { protocol: 1, port, ...hostKey(key) }); }
          catch { finish(new Error("SSH_UNAVAILABLE")); }
          return false; // Inspection never authenticates.
        },
      });
    } catch { finish(new Error("SSH_UNAVAILABLE")); }
  });
}

export function inspectHostKey(options = {}) {
  return inspectSSHHostKey(TARGET, PORT, options);
}

export async function inspectTargetHostKey(raw, options = {}) {
  const target = validateTargetHostKey(raw);
  const key = await inspectSSHHostKey(target.host, target.port, options);
  // The key belongs to this one probe only. Every future SSH authentication
  // must repeat host-key verification against the user's chosen fingerprint.
  return { ...key, scope: "entered_target", host: target.host, reverify_required: true };
}

function clearCredentials(value) {
  if (!value || typeof value !== "object") return;
  for (const key of ["password", "private_key", "passphrase"]) {
    if (Object.hasOwn(value, key)) value[key] = "";
  }
}

function targetStatusKind(output, code, signal) {
  if (code !== 0 || signal) return "unknown";
  const match = /^SG_STATUS_V1:(managed|agent_only|missing|conflict|unsupported|unknown)\n?$/.exec(
    output.toString("utf8"));
  return match?.[1] ?? "unknown";
}

export function probeTargetStatus(raw, { clientFactory = () => new Client(), timeoutMs = 20000 } = {}) {
  let value;
  try { value = validateTargetStatus(raw); }
  catch (error) { clearCredentials(raw); throw error; }
  return new Promise((resolve, reject) => {
    const privateKey = value.method === "private_key" ? Buffer.from(value.private_key, "utf8") : null;
    let client;
    try { client = clientFactory(); }
    catch {
      privateKey?.fill(0);
      clearCredentials(value);
      clearCredentials(raw);
      reject(new Error("SSH_UNAVAILABLE"));
      return;
    }
    let settled = false;
    let keyChanged = false;
    let keyVerified = false;
    let authenticated = false;
    let stream;
    const output = Buffer.alloc(MAX_STATUS_OUTPUT);
    let outputBytes = 0;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { stream?.close?.(); } catch { /* Closing an already closed channel is harmless. */ }
      try { client.end(); } catch { /* Other cleanup must still run. */ }
      if (error) {
        try { client.destroy?.(); } catch { /* A stalled socket must not block cleanup. */ }
      }
      privateKey?.fill(0);
      output.fill(0);
      clearCredentials(value);
      clearCredentials(raw);
      if (error) reject(error);
      else resolve(result);
    };
    const timer = setTimeout(() => finish(new Error(authenticated ? "STATUS_UNAVAILABLE" : "SSH_UNAVAILABLE")), timeoutMs);
    client.on("error", () => finish(new Error(keyChanged ? "HOST_KEY_CHANGED" :
      authenticated ? "STATUS_UNAVAILABLE" : keyVerified ? "AUTH_FAILED" : "SSH_UNAVAILABLE")));
    client.on("close", () => finish(new Error(keyChanged ? "HOST_KEY_CHANGED" :
      authenticated ? "STATUS_UNAVAILABLE" : keyVerified ? "AUTH_FAILED" : "SSH_UNAVAILABLE")));
    client.on("ready", () => {
      authenticated = true;
      try { client.exec(STATUS_COMMAND, { pty: false }, (error, channel) => {
        if (settled) { channel?.close?.(); return; }
        if (error || !channel) { finish(new Error("STATUS_UNAVAILABLE")); return; }
        stream = channel;
        let stderrBytes = 0;
        stream.stderr.on("data", (chunk) => {
          stderrBytes += Buffer.byteLength(chunk);
          if (stderrBytes > 1024) finish(new Error("STATUS_UNAVAILABLE"));
        });
        stream.on("data", (chunk) => {
          if (settled) return;
          const piece = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          if (outputBytes + piece.length > MAX_STATUS_OUTPUT) {
            finish(new Error("STATUS_UNAVAILABLE"));
          } else {
            piece.copy(output, outputBytes);
            outputBytes += piece.length;
          }
        });
        stream.on("error", () => finish(new Error("STATUS_UNAVAILABLE")));
        stream.on("close", (code, signal) => {
          if (settled) return;
          finish(null, { protocol: 1, scope: "entered_target", host: value.host, port: value.port,
            kind: targetStatusKind(output.subarray(0, outputBytes), code, signal),
            host_key_fingerprint: value.fingerprint });
        });
        try { stream.end(STATUS_SCRIPT); }
        catch { finish(new Error("STATUS_UNAVAILABLE")); }
      }); }
      catch { finish(new Error("STATUS_UNAVAILABLE")); }
    });
    try {
      client.connect({ host: value.host, port: value.port, username: value.username,
        readyTimeout: Math.min(timeoutMs, 10000), tryKeyboard: false,
        ...(value.method === "password" ? { password: value.password } :
          { privateKey, passphrase: value.passphrase || undefined }),
        hostVerifier: (key) => {
          try {
            if (sameFingerprint(hostKey(key).fingerprint, value.fingerprint)) {
              keyVerified = true;
              return true;
            }
          } catch { /* Reject malformed host key. */ }
          keyChanged = true;
          return false;
        },
      });
    } catch { finish(new Error("SSH_UNAVAILABLE")); }
  });
}

export function issueGrant(raw, { clientFactory = () => new Client(), timeoutMs = 60000 } = {}) {
  const value = validateLogin(raw);
  return new Promise((resolve, reject) => {
    const client = clientFactory();
    const privateKey = value.method === "private_key" ? Buffer.from(value.private_key, "utf8") : null;
    let settled = false;
    let keyChanged = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      client.end();
      privateKey?.fill(0);
      if (error) reject(error);
      else resolve(result);
    };
    const timer = setTimeout(() => finish(new Error("SSH_UNAVAILABLE")), timeoutMs);
    client.on("error", () => finish(new Error(keyChanged ? "HOST_KEY_CHANGED" : "AUTH_FAILED")));
    client.on("close", () => finish(new Error(keyChanged ? "HOST_KEY_CHANGED" : "AUTH_FAILED")));
    if (value.method === "password") {
      client.on("keyboard-interactive", (_name, _instructions, _language, prompts, done) => {
        const oneSecretPrompt = prompts.length === 1 && prompts[0].echo === false;
        done(oneSecretPrompt ? [value.password] : []);
      });
    }
    client.on("ready", () => {
      const command = value.username === "root" ? GRANT_COMMAND : "/usr/bin/sudo -n -- " + GRANT_COMMAND;
      client.exec(command, { pty: false }, (error, stream) => {
        if (settled) { stream?.close?.(); return; }
        if (error) { finish(new Error("GRANT_UNAVAILABLE")); return; }
        let output = Buffer.alloc(0);
        let tooLarge = false;
        let stderrBytes = 0;
        stream.stderr.on("data", (chunk) => {
          stderrBytes += chunk.length;
          if (stderrBytes > 1024) {
            tooLarge = true;
            stream.close?.();
            finish(new Error("GRANT_UNAVAILABLE"));
          }
        });
        stream.on("data", (chunk) => {
          if (tooLarge) return;
          if (output.length + chunk.length > MAX_OUTPUT) {
            tooLarge = true;
            stream.close?.();
            finish(new Error("GRANT_UNAVAILABLE"));
          } else output = Buffer.concat([output, chunk]);
        });
        stream.on("close", (code, signal) => {
          if (settled) return;
          if (tooLarge || code !== 0 || signal) { finish(new Error("GRANT_UNAVAILABLE")); return; }
          try {
            const grant = JSON.parse(output.toString("utf8"));
            if (!grant || Object.keys(grant).sort().join(",") !==
                "expires_at,grant,protocol,username" || grant.protocol !== 1 ||
                typeof grant.grant !== "string" || !GRANT.test(grant.grant) ||
                !Number.isSafeInteger(grant.expires_at) || grant.expires_at <= Date.now() / 1000 ||
                typeof grant.username !== "string" || !USERNAME.test(grant.username)) {
              throw new Error("Invalid grant");
            }
            finish(null, { protocol: 1, grant: grant.grant, expires_at: grant.expires_at });
          } catch { finish(new Error("GRANT_UNAVAILABLE")); }
        });
      });
    });
    try {
      client.connect({ host: TARGET, port: PORT, username: value.username,
        readyTimeout: Math.min(timeoutMs, 10000), tryKeyboard: value.method === "password",
        ...(value.method === "password" ? { password: value.password } :
          { privateKey, passphrase: value.passphrase || undefined }),
        hostVerifier: (key) => {
          try {
            const actual = hostKey(key).fingerprint;
            if (sameFingerprint(actual, value.fingerprint)) return true;
          } catch { /* Reject malformed host key. */ }
          keyChanged = true;
          return false;
        },
      });
    } catch { finish(new Error("SSH_UNAVAILABLE")); }
  });
}

export function previewAmneziaSetup(raw, { clientFactory = () => new Client(), timeoutMs = 60000 } = {}) {
  const { login: value, target } = validateAmneziaPreview(raw);
  return new Promise((resolve, reject) => {
    const client = clientFactory();
    const privateKey = value.method === "private_key" ? Buffer.from(value.private_key, "utf8") : null;
    let settled = false;
    let keyChanged = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      client.end();
      privateKey?.fill(0);
      value.password = "";
      value.private_key = "";
      value.passphrase = "";
      if (error) reject(error);
      else resolve(result);
    };
    const timer = setTimeout(() => finish(new Error("SSH_UNAVAILABLE")), timeoutMs);
    client.on("error", () => finish(new Error(keyChanged ? "HOST_KEY_CHANGED" : "AUTH_FAILED")));
    client.on("close", () => finish(new Error(keyChanged ? "HOST_KEY_CHANGED" : "AUTH_FAILED")));
    if (value.method === "password") {
      client.on("keyboard-interactive", (_name, _instructions, _language, prompts, done) => {
        done(prompts.length === 1 && prompts[0].echo === false ? [value.password] : []);
      });
    }
    client.on("ready", () => {
      const exact = AMNEZIA_PREVIEW_COMMAND + target;
      const command = value.username === "root" ? exact : "/usr/bin/sudo -n -- " + exact;
      client.exec(command, { pty: false }, (error, stream) => {
        if (settled) { stream?.close?.(); return; }
        if (error) { finish(new Error("SETUP_UNAVAILABLE")); return; }
        let output = Buffer.alloc(0);
        let stderrBytes = 0;
        stream.stderr.on("data", (chunk) => {
          stderrBytes += chunk.length;
          if (stderrBytes > 1024) {
            stream.close?.();
            finish(new Error("SETUP_UNAVAILABLE"));
          }
        });
        stream.on("data", (chunk) => {
          if (settled) return;
          if (output.length + chunk.length > MAX_AMNEZIA_PREVIEW_OUTPUT) {
            stream.close?.();
            finish(new Error("SETUP_UNAVAILABLE"));
          } else output = Buffer.concat([output, chunk]);
        });
        stream.on("close", (code, signal) => {
          if (settled) return;
          if (code !== 0 || signal) { finish(new Error("SETUP_UNAVAILABLE")); return; }
          try { finish(null, safeAmneziaPreview(output.toString("utf8"), target)); }
          catch { finish(new Error("SETUP_UNAVAILABLE")); }
        });
      });
    });
    try {
      client.connect({ host: TARGET, port: PORT, username: value.username,
        readyTimeout: Math.min(timeoutMs, 10000), tryKeyboard: value.method === "password",
        ...(value.method === "password" ? { password: value.password } :
          { privateKey, passphrase: value.passphrase || undefined }),
        hostVerifier: (key) => {
          try {
            if (sameFingerprint(hostKey(key).fingerprint, value.fingerprint)) return true;
          } catch { /* Reject malformed host key. */ }
          keyChanged = true;
          return false;
        },
      });
    } catch { finish(new Error("SSH_UNAVAILABLE")); }
  });
}

class WindowLimit {
  constructor(limit, seconds) {
    this.limit = limit;
    this.windowMs = seconds * 1000;
    this.entries = new Map();
  }
  take(ip) {
    const now = Date.now();
    for (const [key, record] of this.entries) {
      if (record.until <= now) this.entries.delete(key);
    }
    if (this.entries.size > 4096) {
      this.entries.delete(this.entries.keys().next().value);
    }
    const record = this.entries.get(ip);
    if (record && record.count >= this.limit && record.until > now) return false;
    this.entries.set(ip, { count: (record?.until > now ? record.count : 0) + 1,
      until: record?.until > now ? record.until : now + this.windowMs });
    return true;
  }
}

function json(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
    "Content-Length": Buffer.byteLength(body) });
  res.end(body);
}

async function body(req) {
  if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(req.headers["content-type"] || "")) {
    throw new Error("INVALID_INPUT");
  }
  const length = Number(req.headers["content-length"]);
  if (req.headers["content-length"] !== undefined &&
      (!Number.isSafeInteger(length) || length < 0 || length > MAX_BODY)) {
    throw new Error("INVALID_INPUT");
  }
  const chunks = [];
  let total = 0;
  let raw;
  try {
    for await (const chunk of req) {
      chunks.push(chunk);
      total += chunk.length;
      if (total > MAX_BODY) throw new Error("INVALID_INPUT");
    }
    raw = Buffer.concat(chunks);
    try { return JSON.parse(raw.toString("utf8")); }
    catch { throw new Error("INVALID_INPUT"); }
  }
  finally {
    raw?.fill(0);
    for (const chunk of chunks) chunk.fill(0);
  }
}

export function createHandler({ inspect = inspectHostKey, inspectTarget = inspectTargetHostKey,
  targetStatus = probeTargetStatus, login = issueGrant,
  preview = previewAmneziaSetup, admin = requireUnrestrictedAdmin } = {}) {
  const probes = new WindowLimit(20, 60);
  const attempts = new WindowLimit(5, 60);
  let active = 0;
  return async (req, res) => {
    if (req.method === "GET" && req.url === "/healthz") {
      json(res, 200, { ok: true });
      return;
    }
    const origin = req.headers.origin;
    const host = req.headers.host;
    const proto = req.headers["x-forwarded-proto"];
    const address = req.headers["x-sovagrid-client-ip"];
    const isPreview = req.url === "/api/v1/browser-ssh/vpn-setup/preview";
    const isTargetProbe = req.url === "/api/v1/browser-ssh/target-host-key";
    const isTargetStatus = req.url === "/api/v1/browser-ssh/target-status";
    const isAdminRoute = isPreview || isTargetProbe || isTargetStatus;
    if (req.method !== "POST" || !["/api/v1/browser-ssh/host-key", "/api/v1/browser-ssh/login",
        "/api/v1/browser-ssh/vpn-setup/preview", "/api/v1/browser-ssh/target-host-key",
        "/api/v1/browser-ssh/target-status"].includes(req.url) ||
        typeof host !== "string" || !/^[-.A-Za-z0-9:[\]]+(?::[0-9]{1,5})?$/.test(host) ||
        !["http", "https"].includes(proto) || origin !== proto + "://" + host ||
        typeof address !== "string" || net.isIP(address) === 0 ||
        (isAdminRoute && proto !== "https" && !/^(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]{1,5})?$/.test(host))) {
      json(res, 404, { error: "NOT_FOUND" });
      return;
    }
    const isProbe = req.url === "/api/v1/browser-ssh/host-key" || isTargetProbe;
    if (!(isProbe ? probes : attempts).take(address)) {
      json(res, 429, { error: "RATE_LIMIT" });
      return;
    }
    if (active >= 8) {
      json(res, 503, { error: "BUSY" });
      return;
    }
    active++;
    const bodyTimer = setTimeout(() => req.destroy(), 10000);
    try {
      if (isAdminRoute) await admin(req.headers.authorization);
      const value = await body(req);
      clearTimeout(bodyTimer);
      try {
        if (isTargetProbe) {
          json(res, 200, await inspectTarget(validateTargetHostKey(value)));
        } else if (isTargetStatus) {
          const selected = validateTargetStatus(value);
          try { json(res, 200, await targetStatus(selected)); }
          finally { clearCredentials(selected); }
        } else if (isProbe) {
          if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length) {
            throw new Error("INVALID_INPUT");
          }
          json(res, 200, await inspect());
        } else if (isPreview) {
          json(res, 200, await preview(value));
        } else {
          json(res, 200, await login(value));
        }
      } finally {
        clearCredentials(value);
      }
    } catch (error) {
      if (res.destroyed) return;
      const code = ["INVALID_INPUT", "SSH_UNAVAILABLE", "HOST_KEY_CHANGED", "AUTH_FAILED",
        "GRANT_UNAVAILABLE", "AUTH_REQUIRED", "ADMIN_FORBIDDEN", "HUB_UNAVAILABLE",
        "SETUP_UNAVAILABLE", "STATUS_UNAVAILABLE", "UNSUPPORTED_AUTH_METHOD"]
        .includes(error?.message) ? error.message : "SSH_UNAVAILABLE";
      json(res, code === "INVALID_INPUT" ? 400 : code === "HOST_KEY_CHANGED" ? 409 :
        code === "UNSUPPORTED_AUTH_METHOD" ? 422 :
        ["AUTH_FAILED", "AUTH_REQUIRED"].includes(code) ? 401 :
          code === "ADMIN_FORBIDDEN" ? 403 : 503, { error: code });
    } finally { clearTimeout(bodyTimer); active--; }
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const server = http.createServer(createHandler());
  server.headersTimeout = 10000;
  server.requestTimeout = 15000;
  server.maxConnections = 32;
  server.listen(8768, "0.0.0.0");
}

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
const AMNEZIA_CONTROL_COMMAND = "/usr/bin/python3 -I /opt/sovagrid-src/sovagrid-vpn/deploy/install-amnezia-control.py ";
const AMNEZIA_ADMIN_COMMAND = "/usr/bin/python3 -B -E -S -m sovagrid_vpn.amnezia_admin ";
const AMNEZIA_CONFIRM = Object.freeze({ awg2: "I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG2",
  wireguard: "I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_WIREGUARD" });
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
// A read-only route probe runs on the entered Ubuntu server. The destination is
// JSON on stdin; it is never interpolated into a remote command or Python code.
const HUB_ROUTE_COMMAND = String.raw`python3 -I -c 'import json, socket, sys
try:
    endpoint = json.load(sys.stdin)
    if (type(endpoint) is not dict or set(endpoint) != {"host", "port"} or
            type(endpoint["host"]) is not str or type(endpoint["port"]) is not int):
        raise ValueError("bad endpoint")
    with socket.create_connection((endpoint["host"], endpoint["port"]), timeout=4):
        print("SG_HUB_ROUTE_V1:reachable")
except (OSError, ValueError, TypeError):
    print("SG_HUB_ROUTE_V1:unreachable")
'`;
const HUB_ACCESS_URL = "http://hub:8765/api/v1/session/access";
const AGENT_SOCKET = "/run/sovagrid-web-agent/control.sock";
const MAX_BODY = 70 * 1024;
const MAX_AGENT_REPLY = 32 * 1024;
const MAX_OUTPUT = 4096;
const MAX_STATUS_OUTPUT = 512;
// The installer can list 128 owned clients, each with a 32-character name.
const MAX_AMNEZIA_PREVIEW_OUTPUT = 16 * 1024;
const FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{43}$/;
const HEX_SHA = /^[0-9a-f]{64}$/;
const IMAGE_SHA = /^sha256:[0-9a-f]{64}$/;
const USERNAME = /^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/;
const GRANT = /^[A-Za-z0-9_-]{43}$/;
const BEARER = /^Bearer ([A-Za-z0-9_-]{43})$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const AGENT_ACTIONS = new Set(["prepare", "apply", "resume", "cleanup", "interrupt", "status", "list",
  "vpn-source-preview", "vpn-source-apply", "vpn-source-recover",
  "wg-control-preview", "wg-control-apply", "wg-control-recover"]);
const AGENT_ERRORS = new Set(["AUTH_REQUIRED", "ADMIN_FORBIDDEN", "HUB_UNAVAILABLE", "BUSY", "INVALID_INPUT", "INVALID_REQUEST_ID",
  "INVALID_REVISION", "INVALID_FINGERPRINT", "INVALID_TARGET", "HOST_KEY_MISMATCH", "NOT_FOUND",
  "STALE_REVISION", "RESUME_REQUIRED", "RECOVERY_REQUIRED", "ALREADY_ACTIVE", "TARGET_CHANGED",
  "PREPARE_UNCERTAIN", "APPLY_UNCERTAIN", "RESUME_UNCERTAIN", "CLEANUP_UNCERTAIN",
  "ARCHIVE_UNSAFE", "ARCHIVE_FULL",
  "SSH_UNAVAILABLE", "SOURCE_UNTRUSTED", "RUNTIME_UNAVAILABLE", "INVALID_JOURNAL",
  "INSTALLER_UNAVAILABLE", "ROOT_REQUIRED", "JOURNAL_UNAVAILABLE", "UNSAFE_LOCK",
  "INVALID_REQUEST", "SOURCE_CHANGED", "STATE_CONFLICT", "OWNERSHIP_CONFLICT",
  "STALE_PREVIEW", "CONTROL_ACTIVE", "OPERATION_FAILED", "INTERNAL_ERROR",
  "STAGE_CLEANUP_REQUIRED", "RESPONSE_TOO_LARGE", "SOURCE_NOT_PREPARED",
  "AGENT_UNAVAILABLE", "DEPENDENCIES_UNAVAILABLE", "RECOVERY_UNCERTAIN"]);
const WG_DEPENDENCIES = new Set(["wg", "wg-quick", "ip", "python3-cryptography", "apparmor_parser"]);
const WG_REASONS = new Set(["SOURCE_NOT_PREPARED", "SOURCE_CHANGED", "AGENT_UNAVAILABLE",
  "DEPENDENCIES_UNAVAILABLE", "RECOVERY_REQUIRED", "CONTROL_ACTIVE", "BUSY",
  "OPERATION_FAILED", "ROOT_REQUIRED", "SSH_UNAVAILABLE", "STALE_PREVIEW"]);

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
  const fields = ["username", "method", "fingerprint", "password", "private_key", "passphrase", "target"];
  const remote = value && typeof value === "object" && !Array.isArray(value) &&
    (Object.hasOwn(value, "host") || Object.hasOwn(value, "port"));
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !exactFields(value, remote ? [...fields, "host", "port"] : fields) ||
      !["awg2", "wireguard"].includes(value.target)) {
    throw new Error("INVALID_INPUT");
  }
  const login = Object.fromEntries(fields.slice(0, 6)
    .map((key) => [key, value[key]]));
  validateLogin(login);
  return { login, target: value.target,
    ...(remote ? { endpoint: validateTargetHostKey({ host: value.host, port: value.port }) } : {}) };
}

function canonicalSubnet(value) {
  if (typeof value !== "string" || value.length > 32) return false;
  const match = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d|[12]\d|3[0-2])$/.exec(value);
  if (!match || net.isIP(match[1]) !== 4 || match[1].split(".").some((part) =>
    String(Number(part)) !== part)) return false;
  const prefix = Number(match[2]);
  const address = match[1].split(".").reduce((number, octet) => (number * 256 + Number(octet)) >>> 0, 0);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (address & mask) >>> 0 === address;
}

const ENROLL_PREVIEW_FIELDS = ["protocol", "action", "writes", "target", "container_id",
  "image_id", "config_sha256", "table_sha256", "configured_clients", "vpn_protocol",
  "interface", "listen_port", "server_subnet", "host_key_fingerprint", "reverify_required"];
const REMOTE_REVIEW_FIELDS = ["scope", "host", "port"];

function amneziaIdentity(value, selected) {
  if (!selected.endpoint) return value;
  return { ...value, scope: "entered_target", host: selected.endpoint.host,
    port: selected.endpoint.port, host_key_fingerprint: selected.login.fingerprint };
}

function exactAmneziaIdentity(reviewed, selected) {
  return !selected.endpoint || (reviewed.scope === "entered_target" &&
    reviewed.host === selected.endpoint.host && reviewed.port === selected.endpoint.port &&
    reviewed.host_key_fingerprint === selected.login.fingerprint);
}

export function safeAmneziaEnrollmentPreview(raw, target, fingerprint, endpoint = null) {
  let value;
  try { value = JSON.parse(raw); } catch { throw new Error("SETUP_UNAVAILABLE"); }
  const identity = target === "awg2" ? ["amneziawg", "awg0"] : ["wireguard", "wg0"];
  const fields = ["target", "container_id", "image_id", "config_sha256", "table_sha256",
    "configured_clients", "protocol", "interface", "listen_port", "server_subnet"];
  if (!exactFields(value, fields) || value.target !== target || !HEX_SHA.test(value.container_id) ||
      !IMAGE_SHA.test(value.image_id) || !HEX_SHA.test(value.config_sha256) ||
      !HEX_SHA.test(value.table_sha256) || !Number.isSafeInteger(value.configured_clients) ||
      value.configured_clients < 0 || value.configured_clients > 4096 ||
      value.protocol !== identity[0] || value.interface !== identity[1] ||
      !Number.isSafeInteger(value.listen_port) || value.listen_port < 1 ||
      value.listen_port > 65535 || !canonicalSubnet(value.server_subnet) ||
      !FINGERPRINT.test(fingerprint)) throw new Error("SETUP_UNAVAILABLE");
  return { protocol: 1, action: "enroll_preview", writes: false, target,
    container_id: value.container_id, image_id: value.image_id,
    config_sha256: value.config_sha256, table_sha256: value.table_sha256,
    configured_clients: value.configured_clients, vpn_protocol: value.protocol,
    interface: value.interface, listen_port: value.listen_port,
    server_subnet: value.server_subnet, host_key_fingerprint: fingerprint,
    reverify_required: true,
    ...(endpoint ? { scope: "entered_target", host: endpoint.host, port: endpoint.port } : {}) };
}

function validateEnrollmentReview(value, selected) {
  const { target, login, endpoint } = selected;
  if (!exactFields(value, endpoint ? [...ENROLL_PREVIEW_FIELDS, ...REMOTE_REVIEW_FIELDS] :
      ENROLL_PREVIEW_FIELDS) || value.protocol !== 1 ||
      value.action !== "enroll_preview" || value.writes !== false ||
      value.reverify_required !== true || value.target !== target ||
      value.host_key_fingerprint !== login.fingerprint || !exactAmneziaIdentity(value, selected) ||
      !HEX_SHA.test(value.container_id) ||
      !IMAGE_SHA.test(value.image_id) || !HEX_SHA.test(value.config_sha256) ||
      !HEX_SHA.test(value.table_sha256) || !Number.isSafeInteger(value.configured_clients) ||
      value.configured_clients < 0 || value.configured_clients > 4096 ||
      value.vpn_protocol !== (target === "awg2" ? "amneziawg" : "wireguard") ||
      value.interface !== (target === "awg2" ? "awg0" : "wg0") ||
      !Number.isSafeInteger(value.listen_port) || value.listen_port < 1 ||
      value.listen_port > 65535 || !canonicalSubnet(value.server_subnet)) {
    throw new Error("INVALID_INPUT");
  }
  return value;
}

export function validateAmneziaEnrollment(value) {
  const fields = ["username", "method", "fingerprint", "password", "private_key", "passphrase", "target"];
  const remote = value && typeof value === "object" && !Array.isArray(value) &&
    (Object.hasOwn(value, "host") || Object.hasOwn(value, "port"));
  const connectionFields = remote ? [...fields, "host", "port"] : fields;
  if (!exactFields(value, [...connectionFields, "reviewed", "confirm"]) ||
      value.confirm !== "ENROLL_EXISTING_CONTAINER") {
    throw new Error("INVALID_INPUT");
  }
  const selected = validateAmneziaPreview(Object.fromEntries(connectionFields
    .map((key) => [key, value[key]])));
  return { ...selected, reviewed: validateEnrollmentReview(value.reviewed, selected) };
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

export function validateTargetInstallPreview(value) {
  const fields = ["host", "port", "username", "method", "fingerprint", "password",
    "private_key", "passphrase", "name", "hub_host", "hub_port", "local_port"];
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some((key) => !Object.hasOwn(value, key))) {
    throw new Error("INVALID_INPUT");
  }
  const target = validateTargetStatus(Object.fromEntries(fields.slice(0, 8).map((key) => [key, value[key]])));
  if (typeof value.name !== "string" || value.name.length < 1 || value.name.length > 80 ||
      value.name !== value.name.trim() || value.name.includes("PRIVATE KEY") ||
      [...value.name].some((char) => char !== " " && /[\p{C}\p{Z}]/u.test(char))) {
    throw new Error("INVALID_INPUT");
  }
  const hubHost = value.hub_host;
  const version = typeof hubHost === "string" ? net.isIP(hubHost) : 0;
  if (!version || hubHost !== hubHost.trim() || hubHost.includes("%") || hubHost.length > 45 ||
      !Number.isSafeInteger(value.hub_port) || value.hub_port < 1 || value.hub_port > 65535 ||
      !Number.isSafeInteger(value.local_port) || value.local_port < 1024 || value.local_port > 65535) {
    throw new Error("INVALID_INPUT");
  }
  let normalizedHubHost = hubHost;
  if (version === 4) {
    const first = Number(hubHost.split(".")[0]);
    if (first === 0 || first === 127 || first >= 224) throw new Error("INVALID_INPUT");
  } else {
    try { normalizedHubHost = new URL("http://[" + hubHost + "]/").hostname.slice(1, -1); }
    catch { throw new Error("INVALID_INPUT"); }
    if (normalizedHubHost === "::" || normalizedHubHost === "::1" ||
        /^ff[0-9a-f]{2}(?=:|$)/.test(normalizedHubHost) ||
        normalizedHubHost.startsWith("::ffff:")) throw new Error("INVALID_INPUT");
  }
  return { ...target, name: value.name,
    hub_endpoint: { host: normalizedHubHost, port: value.hub_port, local_port: value.local_port } };
}

function exactFields(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === fields.length && fields.every((key) => Object.hasOwn(value, key));
}

export function validateAgentPayload(action, value) {
  if (!AGENT_ACTIONS.has(action)) throw new Error("INVALID_INPUT");
  if (action.startsWith("wg-control-")) {
    const credentialFields = ["host", "port", "username", "method", "fingerprint",
      "password", "private_key", "passphrase"];
    const fields = action === "wg-control-apply" ? [...credentialFields, "expected", "confirm"] :
      action === "wg-control-recover" ? [...credentialFields, "confirm"] : credentialFields;
    if (!exactFields(value, fields)) throw new Error("INVALID_INPUT");
    const target = validateTargetStatus(Object.fromEntries(credentialFields.map((key) => [key, value[key]])));
    if (action === "wg-control-preview") return target;
    if (value.confirm !== true) throw new Error("INVALID_INPUT");
    if (action === "wg-control-recover") return { ...target, confirm: true };
    if (!exactFields(value.expected, ["state_revision", "source_revision"]) ||
        !["state_revision", "source_revision"].every((key) =>
          typeof value.expected[key] === "string" && HEX_SHA.test(value.expected[key]))) {
      throw new Error("INVALID_INPUT");
    }
    return { ...target, expected: { state_revision: value.expected.state_revision,
      source_revision: value.expected.source_revision }, confirm: true };
  }
  if (action.startsWith("vpn-source-")) {
    const credentialFields = ["host", "port", "username", "method", "fingerprint",
      "password", "private_key", "passphrase"];
    const fields = action === "vpn-source-apply" ? [...credentialFields, "expected"] : credentialFields;
    if (!exactFields(value, fields)) throw new Error("INVALID_INPUT");
    const target = validateTargetStatus(Object.fromEntries(credentialFields.map((key) => [key, value[key]])));
    if (action !== "vpn-source-apply") return target;
    const expectedFields = ["source_manifest_sha256", "installed_sha256", "state_sha256", "candidate_sha256"];
    if (!exactFields(value.expected, expectedFields) ||
        expectedFields.some((key) => typeof value.expected[key] !== "string" || !HEX_SHA.test(value.expected[key]))) {
      throw new Error("INVALID_INPUT");
    }
    return { ...target, expected: Object.fromEntries(expectedFields.map((key) => [key, value.expected[key]])) };
  }
  if (action === "prepare") {
    const selected = validateTargetInstallPreview(value);
    return { host: selected.host, port: selected.port, username: selected.username,
      method: selected.method, fingerprint: selected.fingerprint,
      password: selected.password, private_key: selected.private_key, passphrase: selected.passphrase,
      name: selected.name, hub_host: selected.hub_endpoint.host,
      hub_port: selected.hub_endpoint.port, local_port: selected.hub_endpoint.local_port };
  }
  if (action === "resume") {
    const fields = ["request_id", "host", "port", "username", "method", "fingerprint",
      "password", "private_key", "passphrase"];
    if (!exactFields(value, fields) || typeof value.request_id !== "string" ||
        !UUID.test(value.request_id)) throw new Error("INVALID_INPUT");
    const target = validateTargetStatus(Object.fromEntries(fields.slice(1).map((key) => [key, value[key]])));
    return { request_id: value.request_id, ...target };
  }
  if (action === "apply" || action === "cleanup") {
    if (!exactFields(value, ["request_id", "expected_revision"]) ||
        typeof value.request_id !== "string" || !UUID.test(value.request_id) ||
        !Number.isSafeInteger(value.expected_revision) || value.expected_revision < 1) {
      throw new Error("INVALID_INPUT");
    }
    return { request_id: value.request_id, expected_revision: value.expected_revision };
  }
  if (action === "status" || action === "interrupt") {
    if (action === "interrupt" && exactFields(value, [])) return {};
    if (!exactFields(value, ["request_id"]) ||
        typeof value.request_id !== "string" || !UUID.test(value.request_id)) {
      throw new Error("INVALID_INPUT");
    }
    return { request_id: value.request_id };
  }
  if (!exactFields(value, [])) throw new Error("INVALID_INPUT");
  return {};
}

function safeAgentRecord(value) {
  const phases = ["prepared", "transport_ready", "registered", "active"];
  if (!value || typeof value !== "object" || Array.isArray(value) || value.protocol !== 1 ||
      typeof value.request_id !== "string" || !UUID.test(value.request_id) ||
      typeof value.name !== "string" || !value.name || value.name.length > 80 ||
      !phases.includes(value.phase) || !Number.isSafeInteger(value.revision) || value.revision < 1 ||
      !Number.isSafeInteger(value.created_at) || value.created_at < 1 ||
      !Number.isSafeInteger(value.updated_at) || value.updated_at < value.created_at ||
      typeof value.cleanup_required !== "boolean" || typeof value.recoverable !== "boolean" ||
      value.server_id !== null && (typeof value.server_id !== "string" || !UUID.test(value.server_id)) ||
      value.registration_state !== null && !["pending", "active", "cancelled"].includes(value.registration_state)) {
    throw new Error("INSTALLER_UNAVAILABLE");
  }
  return { protocol: 1, request_id: value.request_id, name: value.name, phase: value.phase,
    revision: value.revision, created_at: value.created_at, updated_at: value.updated_at,
    cleanup_required: value.cleanup_required, server_id: value.server_id,
    registration_state: value.registration_state, recoverable: value.recoverable };
}

function safeVpnSourceResult(action, value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      value.protocol !== 1 || value.scope !== "entered_target" ||
      typeof value.host !== "string" || !Number.isSafeInteger(value.port) ||
      value.port < 1 || value.port > 65535 ||
      typeof value.host_key_fingerprint !== "string" ||
      !FINGERPRINT.test(value.host_key_fingerprint)) throw new Error("INSTALLER_UNAVAILABLE");
  const endpoint = validateTargetHostKey({ host: value.host, port: value.port });
  if (endpoint.host !== value.host) throw new Error("INSTALLER_UNAVAILABLE");
  const base = { protocol: 1, scope: "entered_target", host: value.host,
    port: value.port, host_key_fingerprint: value.host_key_fingerprint };
  if (action === "vpn-source-preview") {
    const hashes = ["source_manifest_sha256", "candidate_sha256", "installed_sha256", "state_sha256"];
    if (hashes.some((key) => typeof value[key] !== "string" || !HEX_SHA.test(value[key])) ||
        !exactFields(value.expected, hashes) ||
        hashes.some((key) => value.expected[key] !== value[key]) ||
        !["install", "update", "current"].includes(value.change) ||
        value.temporary_writes !== true || value.activation_writes !== false ||
        typeof value.cleanup_required !== "boolean") throw new Error("INSTALLER_UNAVAILABLE");
    return { ...base, ...Object.fromEntries(hashes.map((key) => [key, value[key]])),
      expected: Object.fromEntries(hashes.map((key) => [key, value[key]])),
      change: value.change, temporary_writes: true, activation_writes: false,
      cleanup_required: value.cleanup_required };
  }
  if (action === "vpn-source-apply") {
    if (value.installed !== true || typeof value.changed !== "boolean" ||
        typeof value.cleanup_required !== "boolean" ||
        typeof value.source_manifest_sha256 !== "string" || !HEX_SHA.test(value.source_manifest_sha256) ||
        typeof value.candidate_sha256 !== "string" || !HEX_SHA.test(value.candidate_sha256)) {
      throw new Error("INSTALLER_UNAVAILABLE");
    }
    return { ...base, installed: true, changed: value.changed,
      cleanup_required: value.cleanup_required,
      source_manifest_sha256: value.source_manifest_sha256,
      candidate_sha256: value.candidate_sha256 };
  }
  if (value.recovered !== true && value.recovered !== false) throw new Error("INSTALLER_UNAVAILABLE");
  return { ...base, recovered: value.recovered };
}

function safeWgControlResult(action, value) {
  const baseFields = ["protocol", "scope", "host", "port", "host_key_fingerprint"];
  if (!value || typeof value !== "object" || Array.isArray(value) || value.protocol !== 1 ||
      value.scope !== "entered_target" || typeof value.host !== "string" ||
      !Number.isSafeInteger(value.port) || value.port < 1 || value.port > 65535 ||
      typeof value.host_key_fingerprint !== "string" || !FINGERPRINT.test(value.host_key_fingerprint)) {
    throw new Error("INSTALLER_UNAVAILABLE");
  }
  const endpoint = validateTargetHostKey({ host: value.host, port: value.port });
  if (endpoint.host !== value.host) throw new Error("INSTALLER_UNAVAILABLE");
  const base = { protocol: 1, scope: "entered_target", host: value.host,
    port: value.port, host_key_fingerprint: value.host_key_fingerprint };
  if (action === "wg-control-preview") {
    const fullFields = ["schema_version", "action", "writes", "state_revision", "source_revision",
      "installed_current", "socket_active", "service_active", "socket_enabled", "pending_recovery",
      "inventory_timer_active", "inventory_timer_enabled", "inventory_snapshot_present",
      "missing_dependencies", "apparmor_profile_present", "can_apply", "requires_service_restart"];
    const full = exactFields(value, [...baseFields, ...fullFields]) ||
      exactFields(value, [...baseFields, ...fullFields, "reason"]);
    if (value.schema_version !== 1 || value.action !== "preview" || value.writes !== false) {
      throw new Error("INSTALLER_UNAVAILABLE");
    }
    if (full) {
      const booleanFields = ["installed_current", "socket_active", "service_active", "socket_enabled",
        "pending_recovery", "inventory_timer_active", "inventory_timer_enabled",
        "inventory_snapshot_present", "apparmor_profile_present", "can_apply", "requires_service_restart"];
      if (!["state_revision", "source_revision"].every((key) => typeof value[key] === "string" && HEX_SHA.test(value[key])) ||
          booleanFields.some((key) => typeof value[key] !== "boolean") ||
          !Array.isArray(value.missing_dependencies) || value.missing_dependencies.length > WG_DEPENDENCIES.size ||
          new Set(value.missing_dependencies).size !== value.missing_dependencies.length ||
          value.missing_dependencies.some((name) => !WG_DEPENDENCIES.has(name)) ||
          (Object.hasOwn(value, "reason") ?
            !["RECOVERY_REQUIRED", "CONTROL_ACTIVE"].includes(value.reason) || value.can_apply !== false :
            value.can_apply !== true)) throw new Error("INSTALLER_UNAVAILABLE");
      return { ...base, ...Object.fromEntries(fullFields.map((key) => [key, value[key]])),
        ...(Object.hasOwn(value, "reason") ? { reason: value.reason } : {}) };
    }
    if (!exactFields(value, [...baseFields, "schema_version", "action", "writes",
          "can_apply", "pending_recovery", "reason"]) || value.can_apply !== false ||
        typeof value.pending_recovery !== "boolean" || !WG_REASONS.has(value.reason)) {
      throw new Error("INSTALLER_UNAVAILABLE");
    }
    return { ...base, schema_version: 1, action: "preview", writes: false,
      can_apply: false, pending_recovery: value.pending_recovery, reason: value.reason };
  }
  if (action === "wg-control-apply") {
    if (!exactFields(value, [...baseFields, "action", "socket_active", "service_active",
          "vpn_interface_changed", "inventory_timer_active", "inventory_snapshot_present", "source_revision"]) ||
        value.action !== "installed" || value.socket_active !== true || value.service_active !== true ||
        value.vpn_interface_changed !== false || value.inventory_timer_active !== true ||
        value.inventory_snapshot_present !== true || typeof value.source_revision !== "string" ||
        !HEX_SHA.test(value.source_revision)) throw new Error("INSTALLER_UNAVAILABLE");
    return { ...base, action: "installed", socket_active: true, service_active: true,
      vpn_interface_changed: false, inventory_timer_active: true, inventory_snapshot_present: true,
      source_revision: value.source_revision };
  }
  if (!exactFields(value, [...baseFields, "action", "changed"]) ||
      value.action !== "recovered" || typeof value.changed !== "boolean") {
    throw new Error("INSTALLER_UNAVAILABLE");
  }
  return { ...base, action: "recovered", changed: value.changed };
}

export function safeAgentResult(action, value) {
  if (action.startsWith("wg-control-")) return safeWgControlResult(action, value);
  if (action.startsWith("vpn-source-")) return safeVpnSourceResult(action, value);
  if (action === "list") {
    if (!Array.isArray(value) || value.length > 256) throw new Error("INSTALLER_UNAVAILABLE");
    return value.map(safeAgentRecord);
  }
  if (action === "interrupt") {
    if (!value || value.protocol !== 1 || value.cancel_requested !== true ||
        value.request_id !== null && (typeof value.request_id !== "string" || !UUID.test(value.request_id))) {
      throw new Error("INSTALLER_UNAVAILABLE");
    }
    return { protocol: 1, request_id: value.request_id, cancel_requested: true };
  }
  if (action === "cleanup" && value?.removed === true) {
    if (value.protocol !== 1 || typeof value.request_id !== "string" || !UUID.test(value.request_id) ||
        value.active !== false) throw new Error("INSTALLER_UNAVAILABLE");
    return { protocol: 1, request_id: value.request_id, removed: true, active: false };
  }
  const record = safeAgentRecord(value);
  if (action === "prepare" || action === "resume") {
    if (value.writes !== true || value.activation_writes !== false ||
        typeof value.hub_fingerprint !== "string" ||
        !FINGERPRINT.test(value.hub_fingerprint) || !value.platform ||
        typeof value.platform !== "object" || Array.isArray(value.platform) ||
        !["ubuntu_version", "python_version", "systemd_version"].every((key) =>
          typeof value.platform[key] === "string" && value.platform[key].length <= 64) ||
        !value.source_commits || typeof value.source_commits !== "object" ||
        Array.isArray(value.source_commits)) throw new Error("INSTALLER_UNAVAILABLE");
    const components = ["sovagrid-blueprint", "sovagrid-hub", "sovagrid-web",
      "sovagrid-agent", "sovagrid-vpn"];
    if (Object.keys(value.source_commits).length !== components.length ||
        components.some((key) => !/^[0-9a-f]{40}$/.test(value.source_commits[key]))) {
      throw new Error("INSTALLER_UNAVAILABLE");
    }
    return { ...record, writes: true, activation_writes: false,
      hub_fingerprint: value.hub_fingerprint,
      platform: Object.fromEntries(["ubuntu_version", "python_version", "systemd_version"]
        .map((key) => [key, value.platform[key]])),
      source_commits: Object.fromEntries(components.map((key) => [key, value.source_commits[key]])) };
  }
  if (action === "cleanup") {
    if (value.removed !== false || value.active !== true) throw new Error("INSTALLER_UNAVAILABLE");
    return { ...record, removed: false, active: true };
  }
  return record;
}

export function agentTimeoutMs(action) {
  if (action === "wg-control-preview") return 120000;
  if (action === "wg-control-apply") return 720000;
  if (action === "wg-control-recover") return 450000;
  return ["status", "list", "interrupt"].includes(action) ? 10000 : 720000;
}

export function proxyAgent(action, payload, token, { socketPath = AGENT_SOCKET,
  timeoutMs = agentTimeoutMs(action) } = {}) {
  if (!AGENT_ACTIONS.has(action) || typeof token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
    throw new Error("AUTH_REQUIRED");
  }
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath });
    const request = Buffer.from(JSON.stringify({ action, session_token: token, payload }) + "\n", "utf8");
    let output = Buffer.alloc(0);
    let settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      request.fill(0);
      output.fill(0);
      socket.destroy();
      if (error) reject(error);
      else resolve(result);
    };
    socket.setTimeout(timeoutMs, () => finish(new Error("INSTALLER_UNAVAILABLE")));
    socket.on("error", () => finish(new Error("INSTALLER_UNAVAILABLE")));
    socket.on("close", () => finish(new Error("INSTALLER_UNAVAILABLE")));
    socket.on("connect", () => socket.end(request));
    socket.on("data", (chunk) => {
      if (settled) return;
      if (output.length + chunk.length > MAX_AGENT_REPLY) {
        finish(new Error("INSTALLER_UNAVAILABLE"));
        return;
      }
      output = Buffer.concat([output, chunk]);
      const newline = output.indexOf(0x0a);
      if (newline === -1) return;
      if (newline !== output.length - 1) {
        finish(new Error("INSTALLER_UNAVAILABLE"));
        return;
      }
      try {
        const response = JSON.parse(output.subarray(0, newline).toString("utf8"));
        if (!response || typeof response !== "object" || Array.isArray(response)) throw new Error();
        if (response.ok === true && Object.keys(response).length === 2 && Object.hasOwn(response, "result")) {
          const result = safeAgentResult(action, response.result);
          if ((action.startsWith("vpn-source-") || action.startsWith("wg-control-")) &&
              (result.host !== payload.host || result.port !== payload.port ||
               result.host_key_fingerprint !== payload.fingerprint)) {
            throw new Error("INSTALLER_UNAVAILABLE");
          }
          finish(null, result);
        } else if (response.ok === false && typeof response.error === "string" &&
                   AGENT_ERRORS.has(response.error) &&
                   Object.keys(response).every((key) => ["ok", "error", "request_id"].includes(key)) &&
                   (response.request_id === undefined ||
                     typeof response.request_id === "string" && UUID.test(response.request_id))) {
          const error = new Error(response.error);
          if (response.request_id !== undefined) error.requestId = response.request_id;
          finish(error);
        } else throw new Error();
      } catch (error) {
        finish(error?.message === "INSTALLER_UNAVAILABLE" ? error : new Error("INSTALLER_UNAVAILABLE"));
      }
    });
  });
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

function passwordChallenge(prompt) {
  if (typeof prompt !== "string" || prompt.length > 200 || /[\u0000-\u001f\u007f]/.test(prompt)) return false;
  if (/(?:otp|one[- ]time|verification|security\s+code|2fa|two[- ]factor|authenticator|token|\bpin\b|passphrase|код|однораз|токен|пин)/iu.test(prompt)) {
    return false;
  }
  return /\bpassword\b|пароль/iu.test(prompt);
}

function targetStatusKind(output, code, signal) {
  if (code !== 0 || signal) return "unknown";
  const match = /^SG_STATUS_V1:(managed|agent_only|missing|conflict|unsupported|unknown)\n?$/.exec(
    output.toString("utf8"));
  return match?.[1] ?? "unknown";
}

function probeTargetReadOnly(raw, { clientFactory = () => new Client(), timeoutMs = 20000 } = {},
  { command, input, failureCode, parse }) {
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
    let keyboardAnswered = false;
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
    const timer = setTimeout(() => finish(new Error(authenticated ? failureCode : "SSH_UNAVAILABLE")), timeoutMs);
    client.on("error", () => finish(new Error(keyChanged ? "HOST_KEY_CHANGED" :
      authenticated ? failureCode : keyVerified ? "AUTH_FAILED" : "SSH_UNAVAILABLE")));
    client.on("close", () => finish(new Error(keyChanged ? "HOST_KEY_CHANGED" :
      authenticated ? failureCode : keyVerified ? "AUTH_FAILED" : "SSH_UNAVAILABLE")));
    if (value.method === "password") {
      client.on("keyboard-interactive", (_name, _instructions, _language, prompts, done) => {
        // Some Ubuntu SSH servers offer password only through keyboard-interactive.
        // Never answer a second-factor, echoed, or multi-question challenge.
        const oneSecretPrompt = !keyboardAnswered && Array.isArray(prompts) && prompts.length === 1 &&
          prompts[0]?.echo === false && passwordChallenge(prompts[0].prompt);
        if (oneSecretPrompt) keyboardAnswered = true;
        done(oneSecretPrompt ? [value.password] : []);
      });
    }
    client.on("ready", () => {
      authenticated = true;
      try { client.exec(command, { pty: false }, (error, channel) => {
        if (settled) { channel?.close?.(); return; }
        if (error || !channel) { finish(new Error(failureCode)); return; }
        stream = channel;
        let stderrBytes = 0;
        stream.stderr.on("data", (chunk) => {
          stderrBytes += Buffer.byteLength(chunk);
          if (stderrBytes > 1024) finish(new Error(failureCode));
        });
        stream.on("data", (chunk) => {
          if (settled) return;
          const piece = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          if (outputBytes + piece.length > MAX_STATUS_OUTPUT) {
            finish(new Error(failureCode));
          } else {
            piece.copy(output, outputBytes);
            outputBytes += piece.length;
          }
        });
        stream.on("error", () => finish(new Error(failureCode)));
        stream.on("close", (code, signal) => {
          if (settled) return;
          try { finish(null, parse(output.subarray(0, outputBytes), code, signal, value)); }
          catch { finish(new Error(failureCode)); }
        });
        try { stream.end(input); }
        catch { finish(new Error(failureCode)); }
      }); }
      catch { finish(new Error(failureCode)); }
    });
    try {
      client.connect({ host: value.host, port: value.port, username: value.username,
        readyTimeout: Math.min(timeoutMs, 10000), tryKeyboard: value.method === "password",
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

export function probeTargetStatus(raw, options = {}) {
  return probeTargetReadOnly(raw, options, { command: STATUS_COMMAND, input: STATUS_SCRIPT,
    failureCode: "STATUS_UNAVAILABLE", parse: (output, code, signal, value) =>
      ({ protocol: 1, scope: "entered_target", host: value.host, port: value.port,
        kind: targetStatusKind(output, code, signal), host_key_fingerprint: value.fingerprint }) });
}

function probeTargetHubRoute(raw, endpoint, options = {}) {
  return probeTargetReadOnly(raw, options, { command: HUB_ROUTE_COMMAND,
    input: JSON.stringify({ host: endpoint.host, port: endpoint.port }),
    failureCode: "ROUTE_UNAVAILABLE", parse: (output, code, signal) => {
      if (code !== 0 || signal) throw new Error("ROUTE_UNAVAILABLE");
      const match = /^SG_HUB_ROUTE_V1:(reachable|unreachable)\n?$/.exec(output.toString("utf8"));
      if (!match) throw new Error("ROUTE_UNAVAILABLE");
      return match[1];
    } });
}

export async function previewTargetInstall(raw, { status = probeTargetStatus,
  route = probeTargetHubRoute, clientFactory = () => new Client(), timeoutMs = 20000 } = {}) {
  let selected;
  try { selected = validateTargetInstallPreview(raw); }
  catch (error) { clearCredentials(raw); throw error; }
  const target = Object.fromEntries(["host", "port", "username", "method", "fingerprint", "password",
    "private_key", "passphrase"].map((key) => [key, selected[key]]));
  const routeTarget = { ...target };
  try {
    const inventory = await status(target, { clientFactory, timeoutMs });
    if (!inventory || inventory.protocol !== 1 || inventory.scope !== "entered_target" ||
        inventory.host !== selected.host || inventory.port !== selected.port ||
        inventory.host_key_fingerprint !== selected.fingerprint ||
        !["managed", "agent_only", "missing", "conflict", "unsupported", "unknown"].includes(inventory.kind)) {
      throw new Error("STATUS_UNAVAILABLE");
    }
    if (inventory.kind !== "missing") {
      return { protocol: 1, action: "install_preview", writes: false, scope: "entered_target",
        host: selected.host, port: selected.port, name: selected.name,
        hub_endpoint: selected.hub_endpoint, target_kind: inventory.kind,
        hub_route: "not_checked", preflight_passed: false,
        source_verification_required: true, reverify_required: true,
        host_key_fingerprint: selected.fingerprint };
    }
    const hubRoute = await route(routeTarget, selected.hub_endpoint,
      { clientFactory, timeoutMs: Math.min(timeoutMs, 12000) });
    if (!["reachable", "unreachable"].includes(hubRoute)) throw new Error("ROUTE_UNAVAILABLE");
    return { protocol: 1, action: "install_preview", writes: false, scope: "entered_target",
      host: selected.host, port: selected.port, name: selected.name,
      hub_endpoint: selected.hub_endpoint, target_kind: inventory.kind,
      hub_route: hubRoute, preflight_passed: hubRoute === "reachable",
      source_verification_required: true, reverify_required: true,
      host_key_fingerprint: selected.fingerprint };
  } finally {
    clearCredentials(target); clearCredentials(routeTarget); clearCredentials(selected); clearCredentials(raw);
  }
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

export async function previewAmneziaSetup(raw, options = {}) {
  let selected;
  try {
    selected = validateAmneziaPreview(raw);
    const login = { ...selected.login };
    const exact = (login.username === "root" ? "" : "/usr/bin/sudo -n -- ") +
      AMNEZIA_PREVIEW_COMMAND + selected.target;
    return await executeFixedAmnezia(login, exact,
      (output) => amneziaIdentity(safeAmneziaPreview(output, selected.target), selected),
      { ...options, endpoint: selected.endpoint });
  } finally {
    clearCredentials(selected?.login); clearCredentials(raw);
  }
}

function executeFixedAmnezia(login, exact, parse, { clientFactory = () => new Client(),
  timeoutMs = 60000, mutation = false, endpoint = null } = {}) {
  validateLogin(login);
  return new Promise((resolve, reject) => {
    const privateKey = login.method === "private_key" ? Buffer.from(login.private_key, "utf8") : null;
    let client;
    try { client = clientFactory(); }
    catch {
      privateKey?.fill(0); clearCredentials(login);
      reject(new Error("SSH_UNAVAILABLE")); return;
    }
    const output = Buffer.alloc(MAX_AMNEZIA_PREVIEW_OUTPUT);
    let bytes = 0;
    let settled = false;
    let keyChanged = false;
    let keyVerified = false;
    let authenticated = false;
    let commandStarted = false;
    let keyboardAnswered = false;
    let stream;
    const failure = () => commandStarted && mutation ? "SETUP_UNCERTAIN" :
      authenticated ? "SETUP_UNAVAILABLE" : keyVerified ? "AUTH_FAILED" : "SSH_UNAVAILABLE";
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { stream?.close?.(); } catch { /* The channel may already have closed. */ }
      try { client.end(); } catch { /* A broken SSH socket must not retain secrets. */ }
      if (error) try { client.destroy?.(); } catch { /* Best effort. */ }
      privateKey?.fill(0); output.fill(0); clearCredentials(login);
      if (error) reject(error); else resolve(result);
    };
    const timer = setTimeout(() => finish(new Error(failure())), timeoutMs);
    client.on("error", () => finish(new Error(keyChanged ? "HOST_KEY_CHANGED" : failure())));
    client.on("close", () => finish(new Error(keyChanged ? "HOST_KEY_CHANGED" : failure())));
    if (login.method === "password") {
      client.on("keyboard-interactive", (_name, _instructions, _language, prompts, done) => {
        const accepted = !keyboardAnswered && Array.isArray(prompts) && prompts.length === 1 &&
          prompts[0]?.echo === false && passwordChallenge(prompts[0].prompt);
        if (accepted) keyboardAnswered = true;
        done(accepted ? [login.password] : []);
      });
    }
    client.on("ready", () => {
      authenticated = true;
      try { client.exec(exact, { pty: false }, (error, channel) => {
        if (settled) { channel?.close?.(); return; }
        if (error || !channel) { finish(new Error("SETUP_UNAVAILABLE")); return; }
        stream = channel;
        commandStarted = true;
        let stderrBytes = 0;
        stream.stderr.on("data", (chunk) => {
          stderrBytes += Buffer.byteLength(chunk);
          if (stderrBytes > 1024) finish(new Error(failure()));
        });
        stream.on("data", (chunk) => {
          if (settled) return;
          const piece = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          if (bytes + piece.length > output.length) finish(new Error(failure()));
          else { piece.copy(output, bytes); bytes += piece.length; }
        });
        stream.on("error", () => finish(new Error(failure())));
        stream.on("close", (code, signal) => {
          if (settled) return;
          if (code !== 0 || signal) { finish(new Error(failure())); return; }
          try { finish(null, parse(output.subarray(0, bytes).toString("utf8"))); }
          catch { finish(new Error(failure())); }
        });
      }); } catch { finish(new Error("SETUP_UNAVAILABLE")); }
    });
    try {
      client.connect({ host: endpoint?.host ?? TARGET, port: endpoint?.port ?? PORT,
        username: login.username,
        readyTimeout: Math.min(timeoutMs, 10000), tryKeyboard: login.method === "password",
        ...(login.method === "password" ? { password: login.password } :
          { privateKey, passphrase: login.passphrase || undefined }),
        hostVerifier: (key) => {
          try {
            if (sameFingerprint(hostKey(key).fingerprint, login.fingerprint)) {
              keyVerified = true; return true;
            }
          } catch { /* Reject malformed host key. */ }
          keyChanged = true; return false;
        },
      });
    } catch { finish(new Error("SSH_UNAVAILABLE")); }
  });
}

function amneziaLogin(selected) {
  return { ...selected.login };
}

function adminCommand(username, action, target, pins = null) {
  // Every interpolated byte is validated as an enum or lowercase SHA-256 hex.
  const prefix = "cd /opt/sovagrid-vpn && " +
    (username === "root" ? "" : "/usr/bin/sudo -n -- ") + AMNEZIA_ADMIN_COMMAND;
  if (action === "enroll-preview") return prefix + "enroll-preview " + target;
  if (action === "enroll") return prefix + "enroll " + target +
    " --confirm-container-id " + pins.container_id +
    " --confirm-image-id " + pins.image_id +
    " --confirm-config-sha256 " + pins.config_sha256 +
    " --confirm-table-sha256 " + pins.table_sha256;
  throw new Error("INVALID_INPUT");
}

async function enrollmentPreview(selected, options) {
  // adminCommand includes its own fixed sudo prefix after the fixed cd.
  const login = amneziaLogin(selected);
  return executeFixedAmnezia(login, adminCommand(login.username, "enroll-preview", selected.target),
    (raw) => safeAmneziaEnrollmentPreview(raw, selected.target, login.fingerprint, selected.endpoint),
    { ...options, endpoint: selected.endpoint });
}

export async function previewAmneziaEnrollment(raw, options = {}) {
  let selected;
  try {
    selected = validateAmneziaPreview(raw);
    return await enrollmentPreview(selected, options);
  } finally {
    clearCredentials(selected?.login); clearCredentials(raw);
  }
}

function safeEnrollmentResult(raw, reviewed) {
  let value;
  try { value = JSON.parse(raw); } catch { throw new Error("SETUP_UNCERTAIN"); }
  if (!exactFields(value, ["target", "enrolled", "configured_clients"]) ||
      value.target !== reviewed.target || value.enrolled !== true ||
      value.configured_clients !== reviewed.configured_clients) throw new Error("SETUP_UNCERTAIN");
  return value;
}

export async function enrollAmneziaSetup(raw, { recheckAdmin = async () => {}, ...options } = {}) {
  let selected;
  try {
    selected = validateAmneziaEnrollment(raw);
    const fresh = await enrollmentPreview(selected, options);
    if ([...ENROLL_PREVIEW_FIELDS, ...(selected.endpoint ? REMOTE_REVIEW_FIELDS : [])]
      .some((key) => fresh[key] !== selected.reviewed[key])) {
      throw new Error("SETUP_CHANGED");
    }
    await recheckAdmin();
    const login = amneziaLogin(selected);
    await executeFixedAmnezia(login, adminCommand(login.username, "enroll", selected.target,
      selected.reviewed), (output) => safeEnrollmentResult(output, selected.reviewed),
    { ...options, timeoutMs: options.timeoutMs ?? 120000, mutation: true,
      endpoint: selected.endpoint });
    const statusInput = { ...selected.login, target: selected.target,
      ...(selected.endpoint ?? {}) };
    let after;
    try { after = await previewAmneziaSetup(statusInput, options); }
    catch { throw new Error("SETUP_UNCERTAIN"); }
    finally { clearCredentials(statusInput); }
    if (!after.enrolled || after.container_id !== selected.reviewed.container_id ||
        !exactAmneziaIdentity(after, selected)) {
      throw new Error("SETUP_UNCERTAIN");
    }
    return amneziaIdentity({ protocol: 1, action: "enrolled", target: selected.target, enrolled: true,
      container_id: after.container_id, configured_clients: after.configured_clients,
      setup: after }, selected);
  } finally {
    clearCredentials(selected?.login); clearCredentials(raw);
  }
}

const SETUP_REVIEW_FIELDS = ["protocol", "target", "enrolled", "marker", "other_marker",
  "socket_active", "service_active", "installer_ready", "installed_current", "can_arm",
  "container_id", "configured_clients", "owned_clients"];

export function validateAmneziaSetupAction(raw, action) {
  const fields = ["username", "method", "fingerprint", "password", "private_key", "passphrase", "target"];
  const remote = raw && typeof raw === "object" && !Array.isArray(raw) &&
    (Object.hasOwn(raw, "host") || Object.hasOwn(raw, "port"));
  const connectionFields = remote ? [...fields, "host", "port"] : fields;
  if (!["install", "arm"].includes(action) ||
      !exactFields(raw, [...connectionFields, "reviewed", "confirm"])) {
    throw new Error("INVALID_INPUT");
  }
  const selected = validateAmneziaPreview(Object.fromEntries(connectionFields
    .map((key) => [key, raw[key]])));
  const value = raw.reviewed;
  if (raw.confirm !== (action === "install" ? "INSTALL_AMNEZIA_BROKER" :
      AMNEZIA_CONFIRM[selected.target]) ||
      !exactFields(value, selected.endpoint ? [...SETUP_REVIEW_FIELDS,
        ...REMOTE_REVIEW_FIELDS, "host_key_fingerprint"] : SETUP_REVIEW_FIELDS) ||
      !exactAmneziaIdentity(value, selected) ||
      value.protocol !== 1 || value.target !== selected.target || value.enrolled !== true ||
      !HEX_SHA.test(value.container_id) || !["absent", "valid", "unsafe"].includes(value.marker) ||
      !["absent", "valid", "unsafe"].includes(value.other_marker) ||
      ["socket_active", "service_active", "installer_ready", "installed_current", "can_arm"]
        .some((key) => typeof value[key] !== "boolean") ||
      !Number.isSafeInteger(value.configured_clients) || value.configured_clients < 0 ||
      value.configured_clients > 100000 || !Number.isSafeInteger(value.owned_clients) ||
      value.owned_clients < 0 || value.owned_clients > value.configured_clients ||
      (action === "install" && (!value.installer_ready || value.installed_current ||
        value.marker !== "absent" || value.other_marker !== "absent" ||
        value.socket_active || value.service_active)) ||
      (action === "arm" && (!value.can_arm || !value.installed_current ||
        value.marker !== "absent"))) {
    throw new Error("INVALID_INPUT");
  }
  return { ...selected, reviewed: value };
}

function setupReadInput(selected) {
  return { ...selected.login, target: selected.target, ...(selected.endpoint ?? {}) };
}

async function setupPreview(selected, options) {
  const input = setupReadInput(selected);
  try { return await previewAmneziaSetup(input, options); }
  finally { clearCredentials(input); }
}

function sameSetupReview(current, reviewed, selected) {
  return [...SETUP_REVIEW_FIELDS, ...(selected.endpoint ? [...REMOTE_REVIEW_FIELDS,
    "host_key_fingerprint"] : [])].every((key) => current[key] === reviewed[key]);
}

function safeControlResult(raw, action, target) {
  let value;
  try { value = JSON.parse(raw); } catch { throw new Error("SETUP_UNCERTAIN"); }
  if (action === "install" && exactFields(value,
    ["action", "socket_active", "marker", "target_changed"]) &&
      value.action === "installed" && value.socket_active === false &&
      value.marker === "absent" && value.target_changed === false) return value;
  if (action === "arm" && exactFields(value,
    ["action", "socket_active", "marker", "selected_target", "target_changed"]) &&
      value.action === "armed" && value.socket_active === true &&
      value.marker === "valid" && value.selected_target === target &&
      value.target_changed === false) return value;
  throw new Error("SETUP_UNCERTAIN");
}

export async function mutateAmneziaSetup(raw, action,
  { recheckAdmin = async () => {}, ...options } = {}) {
  let selected;
  try {
    selected = validateAmneziaSetupAction(raw, action);
    const fresh = await setupPreview(selected, options);
    if (!sameSetupReview(fresh, selected.reviewed, selected)) throw new Error("SETUP_CHANGED");
    await recheckAdmin();
    const suffix = action === "install" ? "install" : "arm --target " + selected.target +
      " --confirm-container-id " + selected.reviewed.container_id +
      " --confirm-maintenance-window " + AMNEZIA_CONFIRM[selected.target];
    const login = amneziaLogin(selected);
    const exact = (login.username === "root" ? "" : "/usr/bin/sudo -n -- ") +
      AMNEZIA_CONTROL_COMMAND + suffix;
    await executeFixedAmnezia(login, exact,
      (output) => safeControlResult(output, action, selected.target),
      { ...options, timeoutMs: options.timeoutMs ?? 150000, mutation: true,
        endpoint: selected.endpoint });
    let after;
    try { after = await setupPreview(selected, options); }
    catch { throw new Error("SETUP_UNCERTAIN"); }
    if (!exactAmneziaIdentity(after, selected) ||
        after.container_id !== selected.reviewed.container_id ||
        (action === "install" && !after.installed_current) ||
        (action === "arm" && (after.marker !== "valid" || !after.socket_active ||
          !after.enrolled))) {
      throw new Error("SETUP_UNCERTAIN");
    }
    return amneziaIdentity({ protocol: 1, action: action === "install" ? "installed" : "armed",
      target: selected.target, setup: after }, selected);
  } finally {
    clearCredentials(selected?.login); clearCredentials(raw);
  }
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
  preview = previewAmneziaSetup, enrollPreview = previewAmneziaEnrollment,
  enroll = enrollAmneziaSetup, vpnMutate = mutateAmneziaSetup,
  installPreview = previewTargetInstall,
  agent = proxyAgent, admin = requireUnrestrictedAdmin } = {}) {
  const probes = new WindowLimit(20, 60);
  const reads = new WindowLimit(60, 60);
  const attempts = new WindowLimit(5, 60);
  const stages = new WindowLimit(5, 60);
  const wgStages = new WindowLimit(8, 60);
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
    const vpnAction = /^\/api\/v1\/browser-ssh\/vpn-setup\/(preview|enroll-preview|enroll|install|arm)$/.exec(req.url || "")?.[1];
    const isTargetProbe = req.url === "/api/v1/browser-ssh/target-host-key";
    const isTargetStatus = req.url === "/api/v1/browser-ssh/target-status";
    const isInstallPreview = req.url === "/api/v1/browser-ssh/target-install-preview";
    const agentAction = /^\/api\/v1\/browser-ssh\/agent\/(prepare|apply|resume|cleanup|interrupt|status|list)$/.exec(req.url || "")?.[1];
    const vpnSourceAction = /^\/api\/v1\/browser-ssh\/vpn-source\/(preview|apply|recover)$/.exec(req.url || "")?.[1];
    const wgControlAction = /^\/api\/v1\/browser-ssh\/wg-control\/(preview|apply|recover)$/.exec(req.url || "")?.[1];
    const isAdminRoute = Boolean(vpnAction) || isTargetProbe || isTargetStatus || isInstallPreview ||
      Boolean(agentAction) || Boolean(vpnSourceAction) || Boolean(wgControlAction);
    if (req.method !== "POST" || (!["/api/v1/browser-ssh/host-key", "/api/v1/browser-ssh/login",
        "/api/v1/browser-ssh/target-host-key", "/api/v1/browser-ssh/target-status",
        "/api/v1/browser-ssh/target-install-preview"].includes(req.url) && !agentAction && !vpnAction && !vpnSourceAction && !wgControlAction) ||
        typeof host !== "string" || !/^[-.A-Za-z0-9:[\]]+(?::[0-9]{1,5})?$/.test(host) ||
        !["http", "https"].includes(proto) || origin !== proto + "://" + host ||
        typeof address !== "string" || net.isIP(address) === 0 ||
        (isAdminRoute && proto !== "https" && !/^(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]{1,5})?$/.test(host))) {
      json(res, 404, { error: "NOT_FOUND" });
      return;
    }
    const isProbe = req.url === "/api/v1/browser-ssh/host-key" || isTargetProbe;
    const isAgentRead = ["status", "list", "interrupt"].includes(agentAction);
    if (!(isProbe ? probes : wgControlAction ? wgStages : vpnSourceAction ? stages : isAgentRead ||
          ["preview", "enroll-preview"].includes(vpnAction) ? reads : attempts)
      .take(address)) {
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
        if (agentAction || vpnSourceAction || wgControlAction) {
          const token = BEARER.exec(req.headers.authorization || "")?.[1];
          if (!token) throw new Error("AUTH_REQUIRED");
          const action = agentAction || (vpnSourceAction ? `vpn-source-${vpnSourceAction}` : `wg-control-${wgControlAction}`);
          const selected = validateAgentPayload(action, value);
          try { json(res, 200, await agent(action, selected, token)); }
          finally { clearCredentials(selected); }
        } else if (isTargetProbe) {
          json(res, 200, await inspectTarget(validateTargetHostKey(value)));
        } else if (isTargetStatus) {
          const selected = validateTargetStatus(value);
          try { json(res, 200, await targetStatus(selected)); }
          finally { clearCredentials(selected); }
        } else if (isInstallPreview) {
          json(res, 200, await installPreview(value));
        } else if (isProbe) {
          if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length) {
            throw new Error("INVALID_INPUT");
          }
          json(res, 200, await inspect());
        } else if (vpnAction === "preview") {
          json(res, 200, await preview(value));
        } else if (vpnAction === "enroll-preview") {
          json(res, 200, await enrollPreview(value));
        } else if (vpnAction === "enroll") {
          json(res, 200, await enroll(value,
            { recheckAdmin: () => admin(req.headers.authorization) }));
        } else if (vpnAction === "install" || vpnAction === "arm") {
          json(res, 200, await vpnMutate(value, vpnAction,
            { recheckAdmin: () => admin(req.headers.authorization) }));
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
        "SETUP_UNAVAILABLE", "SETUP_CHANGED", "SETUP_UNCERTAIN", "STATUS_UNAVAILABLE",
        "ROUTE_UNAVAILABLE", "UNSUPPORTED_AUTH_METHOD",
        ...AGENT_ERRORS]
        .includes(error?.message) ? error.message : "SSH_UNAVAILABLE";
      const status = code === "INVALID_INPUT" || code.startsWith("INVALID_") &&
        code !== "INVALID_JOURNAL" ? 400 :
        ["HOST_KEY_CHANGED", "HOST_KEY_MISMATCH", "SETUP_CHANGED", "STALE_REVISION", "RESUME_REQUIRED",
          "RECOVERY_REQUIRED", "ALREADY_ACTIVE", "TARGET_CHANGED", "BUSY", "SOURCE_CHANGED",
          "STATE_CONFLICT", "OWNERSHIP_CONFLICT", "STALE_PREVIEW", "CONTROL_ACTIVE",
          "STAGE_CLEANUP_REQUIRED", "UNSAFE_LOCK"].includes(code) ? 409 :
        code === "NOT_FOUND" ? 404 :
        ["UNSUPPORTED_AUTH_METHOD", "ROOT_REQUIRED", "SOURCE_NOT_PREPARED",
          "AGENT_UNAVAILABLE", "DEPENDENCIES_UNAVAILABLE"].includes(code) ? 422 :
        ["AUTH_FAILED", "AUTH_REQUIRED"].includes(code) ? 401 :
          code === "ADMIN_FORBIDDEN" ? 403 : 503;
      json(res, status, error?.requestId && UUID.test(error.requestId) ?
        { error: code, request_id: error.requestId } : { error: code });
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

/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// This panel verifies a two-hop SSH route without installing or changing VPN.
// Only host-key fingerprints are kept locally; credentials remain in this tab.
const vpnJump = { generation: 0, busy: false, jump: null, target: null,
  jumpFingerprint: null, targetFingerprint: null, controller: null };
const vpnJumpEl = (id) => document.getElementById(id);
const VPN_JUMP_FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{43}$/;
const VPN_JUMP_USER = /^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/;

function vpnJumpEndpoint(prefix) {
  const host = vpnJumpEl(prefix + "Host").value.trim().toLowerCase();
  const rawPort = vpnJumpEl(prefix + "Port").value;
  if (!host || host.length > 253 || !/^[A-Za-z0-9.:-]+$/.test(host) || host.includes("..") ||
      !/^[0-9]{1,5}$/.test(rawPort)) throw new Error("INVALID_INPUT");
  const port = Number(rawPort);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("INVALID_INPUT");
  return { host, port };
}

function vpnJumpSameEndpoint(prefix, saved) {
  try {
    const current = vpnJumpEndpoint(prefix);
    return saved?.host === current.host && saved?.port === current.port;
  } catch { return false; }
}

function vpnJumpPinName(kind, jump, target = null) {
  return `sovagrid.${kind}-ssh-host-key:${location.origin}:${jump.host}:${jump.port}` +
    (target ? `:${target.host}:${target.port}` : "");
}

function vpnJumpStoredPin(kind, jump, target = null) {
  try { return localStorage.getItem(vpnJumpPinName(kind, jump, target)); }
  catch { return null; }
}

function vpnJumpSavePin(kind, fingerprint, jump, target = null) {
  try { localStorage.setItem(vpnJumpPinName(kind, jump, target), fingerprint); }
  catch { /* Storage can be unavailable in private browsing. */ }
}

function vpnJumpClearSecrets() {
  for (const id of ["vpnJumpPassword", "vpnJumpKey", "vpnJumpPassphrase",
    "vpnJumpTargetPassword", "vpnJumpTargetKey", "vpnJumpTargetPassphrase"]) {
    vpnJumpEl(id).value = "";
  }
}

function vpnJumpError(message = "") {
  const element = vpnJumpEl("vpnJumpError");
  element.textContent = message;
  element.hidden = !message;
}

function vpnJumpExplain(error) {
  if (error?.message === "AUTH_REQUIRED") return "Войдите в Hub снова.";
  if (error?.message === "ADMIN_FORBIDDEN") return "Нужен администратор Hub с полным доступом.";
  if (error?.message === "HOST_KEY_CHANGED") return "Один из SSH-ключей изменился. Сверьте оба отпечатка заново.";
  if (error?.message === "AUTH_FAILED") return "Промежуточный или целевой сервер не принял SSH-данные.";
  if (error?.message === "SSH_TIMEOUT") return "SSH-сервер не ответил вовремя.";
  if (error?.message === "INVALID_INPUT") return "Проверьте адреса, порты и SSH-данные обоих серверов.";
  if (error?.message === "KEY_READ_FAILED") return "Не удалось прочитать выбранный файл ключа.";
  if (error?.message === "STATUS_UNAVAILABLE") return "Состояние сервера не удалось прочитать через SSH.";
  return "Маршрут через промежуточный хост недоступен. Проверьте адреса и SSH-доступ.";
}

function vpnJumpAllowed() {
  return typeof amneziaSetupAllowed === "function" && amneziaSetupAllowed();
}

function vpnJumpRender() {
  const trustedJump = vpnJumpSameEndpoint("vpnJump", vpnJump.jump) &&
    VPN_JUMP_FINGERPRINT.test(vpnJump.jumpFingerprint || "") && vpnJumpEl("vpnJumpTrust").checked;
  const trustedTarget = trustedJump && vpnJumpSameEndpoint("vpnJumpTarget", vpnJump.target) &&
    VPN_JUMP_FINGERPRINT.test(vpnJump.targetFingerprint || "") && vpnJumpEl("vpnJumpTargetTrust").checked;
  vpnJumpEl("vpnJumpInspect").disabled = vpnJump.busy;
  vpnJumpEl("vpnJumpInspectTarget").disabled = vpnJump.busy || !trustedJump;
  vpnJumpEl("vpnJumpStatus").disabled = vpnJump.busy || !trustedTarget;
  for (const prefix of ["vpnJump", "vpnJumpTarget"]) {
    const key = vpnJumpEl(prefix + "Method").value === "private_key";
    vpnJumpEl(prefix + "PasswordField").hidden = key;
    vpnJumpEl(prefix + "KeyFields").hidden = !key;
  }
}

function vpnJumpInvalidate(kind) {
  vpnJump.generation++;
  vpnJump.controller?.abort();
  vpnJump.controller = null;
  vpnJumpEl("vpnJumpResult").textContent = "";
  vpnJumpError();
  if (kind === "jump") {
    vpnJump.jump = null;
    vpnJump.jumpFingerprint = null;
    vpnJumpEl("vpnJumpReview").hidden = true;
    vpnJumpEl("vpnJumpTrust").checked = false;
  }
  vpnJump.target = null;
  vpnJump.targetFingerprint = null;
  vpnJumpEl("vpnJumpTargetReview").hidden = true;
  vpnJumpEl("vpnJumpTargetTrust").checked = false;
  vpnJumpClearSecrets();
  vpnJumpRender();
}

function vpnJumpReset() {
  vpnJumpInvalidate("jump");
  vpnJump.busy = false;
  vpnJumpRender();
}
globalThis.vpnJumpReset = vpnJumpReset;
globalThis.addEventListener?.("pagehide", vpnJumpReset);

async function vpnJumpAPI(path, payload, token, timeoutMs = 30000) {
  const controller = new AbortController();
  vpnJump.controller = controller;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, { method: "POST", credentials: "omit", cache: "no-store",
      redirect: "error", referrerPolicy: "no-referrer",
      headers: { "Content-Type": "application/json", Accept: "application/json",
        Authorization: `Bearer ${token}` },
      body: JSON.stringify(payload), signal: controller.signal });
    const value = await response.json();
    if (!response.ok) throw new Error(typeof value?.error === "string" ? value.error : "SSH_UNAVAILABLE");
    return value;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("SSH_TIMEOUT");
    throw error;
  } finally {
    clearTimeout(timer);
    if (vpnJump.controller === controller) vpnJump.controller = null;
  }
}

async function vpnJumpCredential(prefix, fingerprint) {
  const username = vpnJumpEl(prefix + "User").value.trim();
  const method = vpnJumpEl(prefix + "Method").value;
  if (!VPN_JUMP_USER.test(username) || !VPN_JUMP_FINGERPRINT.test(fingerprint || "") ||
      !["password", "private_key"].includes(method)) throw new Error("INVALID_INPUT");
  let password = "", private_key = "", passphrase = "";
  if (method === "password") password = vpnJumpEl(prefix + "Password").value;
  else {
    const file = vpnJumpEl(prefix + "Key").files?.[0];
    if (!file || file.size < 1 || file.size > 32768) throw new Error("INVALID_INPUT");
    try { private_key = await file.text(); } catch { throw new Error("KEY_READ_FAILED"); }
    passphrase = vpnJumpEl(prefix + "Passphrase").value;
  }
  if ((method === "password" && (!password || password.length > 1024)) ||
      (method === "private_key" && (!private_key || new TextEncoder().encode(private_key).length > 32768)) ||
      passphrase.length > 1024) throw new Error("INVALID_INPUT");
  return { username, method, fingerprint, password, private_key, passphrase };
}

async function vpnJumpInspectJump() {
  if (vpnJump.busy || !vpnJumpAllowed()) return;
  const generation = ++vpnJump.generation, token = state.token;
  vpnJump.busy = true; vpnJumpRender(); vpnJumpError();
  try {
    const endpoint = vpnJumpEndpoint("vpnJump");
    const reply = await vpnJumpAPI("/api/v1/browser-ssh/target-host-key", endpoint, token);
    if (generation !== vpnJump.generation || token !== state.token || !vpnJumpSameEndpoint("vpnJump", endpoint)) return;
    if (reply?.protocol !== 1 || reply.scope !== "entered_target" || reply.host !== endpoint.host ||
        reply.port !== endpoint.port || reply.reverify_required !== true ||
        !VPN_JUMP_FINGERPRINT.test(reply.fingerprint)) throw new Error("INVALID_INPUT");
    vpnJump.jump = endpoint;
    vpnJump.jumpFingerprint = reply.fingerprint;
    vpnJump.target = null; vpnJump.targetFingerprint = null;
    vpnJumpEl("vpnJumpTargetReview").hidden = true;
    vpnJumpEl("vpnJumpTargetTrust").checked = false;
    vpnJumpEl("vpnJumpFingerprint").textContent = reply.fingerprint;
    vpnJumpEl("vpnJumpReview").hidden = false;
    vpnJumpEl("vpnJumpTrust").checked = vpnJumpStoredPin("jump", endpoint) === reply.fingerprint;
  } catch (error) { if (generation === vpnJump.generation) vpnJumpError(vpnJumpExplain(error)); }
  finally { vpnJumpClearSecrets(); vpnJump.busy = false; vpnJumpRender(); }
}

async function vpnJumpInspectTarget() {
  if (vpnJump.busy || !vpnJumpAllowed() || !vpnJumpEl("vpnJumpTrust").checked ||
      !vpnJumpSameEndpoint("vpnJump", vpnJump.jump)) return;
  const generation = ++vpnJump.generation, token = state.token, jump = vpnJump.jump;
  const jumpFingerprint = vpnJump.jumpFingerprint;
  vpnJump.busy = true; vpnJumpRender(); vpnJumpError();
  try {
    const target = vpnJumpEndpoint("vpnJumpTarget");
    const jumpLogin = await vpnJumpCredential("vpnJump", jumpFingerprint);
    if (generation !== vpnJump.generation || token !== state.token ||
        !vpnJumpSameEndpoint("vpnJump", jump) || !vpnJumpSameEndpoint("vpnJumpTarget", target) ||
        !vpnJumpEl("vpnJumpTrust").checked) return;
    vpnJumpClearSecrets();
    const reply = await vpnJumpAPI("/api/v1/browser-ssh/target-host-key",
      { ...target, jump: { ...jump, ...jumpLogin } }, token);
    if (generation !== vpnJump.generation || token !== state.token ||
        !vpnJumpSameEndpoint("vpnJump", jump) || !vpnJumpSameEndpoint("vpnJumpTarget", target)) return;
    if (reply?.protocol !== 1 || reply.scope !== "entered_target" || reply.host !== target.host ||
        reply.port !== target.port || reply.jump_host !== jump.host || reply.jump_port !== jump.port ||
        reply.jump_host_key_fingerprint !== jumpFingerprint || reply.reverify_required !== true ||
        !VPN_JUMP_FINGERPRINT.test(reply.fingerprint)) throw new Error("INVALID_INPUT");
    vpnJump.target = target;
    vpnJump.targetFingerprint = reply.fingerprint;
    vpnJumpEl("vpnJumpTargetFingerprint").textContent = reply.fingerprint;
    vpnJumpEl("vpnJumpTargetReview").hidden = false;
    vpnJumpEl("vpnJumpTargetTrust").checked =
      vpnJumpStoredPin("jump-target", jump, target) === reply.fingerprint;
  } catch (error) { if (generation === vpnJump.generation) vpnJumpError(vpnJumpExplain(error)); }
  finally { vpnJumpClearSecrets(); vpnJump.busy = false; vpnJumpRender(); }
}

async function vpnJumpCheckStatus() {
  if (vpnJump.busy || !vpnJumpAllowed() || !vpnJumpEl("vpnJumpTrust").checked ||
      !vpnJumpEl("vpnJumpTargetTrust").checked ||
      !vpnJumpSameEndpoint("vpnJump", vpnJump.jump) ||
      !vpnJumpSameEndpoint("vpnJumpTarget", vpnJump.target)) return;
  const generation = ++vpnJump.generation, token = state.token;
  const jump = vpnJump.jump, target = vpnJump.target;
  const jumpFingerprint = vpnJump.jumpFingerprint, targetFingerprint = vpnJump.targetFingerprint;
  vpnJump.busy = true; vpnJumpRender(); vpnJumpError();
  try {
    const jumpLogin = await vpnJumpCredential("vpnJump", jumpFingerprint);
    const targetLogin = await vpnJumpCredential("vpnJumpTarget", targetFingerprint);
    if (generation !== vpnJump.generation || token !== state.token ||
        !vpnJumpSameEndpoint("vpnJump", jump) || !vpnJumpSameEndpoint("vpnJumpTarget", target) ||
        !vpnJumpEl("vpnJumpTrust").checked || !vpnJumpEl("vpnJumpTargetTrust").checked) return;
    vpnJumpClearSecrets();
    const reply = await vpnJumpAPI("/api/v1/browser-ssh/target-status",
      { ...target, ...targetLogin, jump: { ...jump, ...jumpLogin } }, token);
    if (generation !== vpnJump.generation || token !== state.token ||
        !vpnJumpSameEndpoint("vpnJump", jump) || !vpnJumpSameEndpoint("vpnJumpTarget", target)) return;
    if (reply?.protocol !== 1 || reply.scope !== "entered_target" ||
        reply.host !== target.host || reply.port !== target.port ||
        reply.host_key_fingerprint !== targetFingerprint ||
        reply.jump_host !== jump.host || reply.jump_port !== jump.port ||
        reply.jump_host_key_fingerprint !== jumpFingerprint ||
        !["managed", "agent_only", "missing", "conflict", "unsupported", "unknown"].includes(reply.kind))
      throw new Error("INVALID_INPUT");
    vpnJumpSavePin("jump", jumpFingerprint, jump);
    vpnJumpSavePin("jump-target", targetFingerprint, jump, target);
    const labels = { managed: "Hub и Agent отвечают", agent_only: "Agent отвечает",
      missing: "SovaGrid пока не установлен", conflict: "Найдены конфликтующие файлы",
      unsupported: "Нужна Ubuntu", unknown: "Состояние не распознано" };
    vpnJumpEl("vpnJumpResult").textContent = `Связь через промежуточный хост подтверждена. ${labels[reply.kind]}.`;
  } catch (error) { if (generation === vpnJump.generation) vpnJumpError(vpnJumpExplain(error)); }
  finally { vpnJumpClearSecrets(); vpnJump.busy = false; vpnJumpRender(); }
}

vpnJumpEl("vpnJumpInspect").addEventListener("click", vpnJumpInspectJump);
vpnJumpEl("vpnJumpInspectTarget").addEventListener("click", vpnJumpInspectTarget);
vpnJumpEl("vpnJumpStatus").addEventListener("click", vpnJumpCheckStatus);
for (const id of ["vpnJumpHost", "vpnJumpPort", "vpnJumpUser", "vpnJumpMethod"]) {
  vpnJumpEl(id).addEventListener("change", () => vpnJumpInvalidate("jump"));
}
for (const id of ["vpnJumpTargetHost", "vpnJumpTargetPort", "vpnJumpTargetUser", "vpnJumpTargetMethod"]) {
  vpnJumpEl(id).addEventListener("change", () => vpnJumpInvalidate("target"));
}
vpnJumpEl("vpnJumpTrust").addEventListener("change", () => vpnJumpRender());
vpnJumpEl("vpnJumpTargetTrust").addEventListener("change", () => vpnJumpRender());
vpnJumpRender();

/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// Direct SSH runs only in this tab. No command, credential, or terminal output is
// written to browser storage. The gateway owns the actual SSH connection.
const directSSH = { generation: 0, phase: "idle", session: null, term: null, fit: null,
  input: [], inputBytes: 0, draining: false, inputTimer: null, controllers: new Set(), resizeTimer: null,
  resizeObserver: null, pollTimer: null, pollWake: null, hiddenSnapshot: null,
  jump: { reviewed: null, changedPin: false }, error: "", status: "", opening: false };
const directSshKeys = { escape: "\x1b", tab: "\t", "ctrl-c": "\x03", "ctrl-d": "\x04",
  up: "\x1b[A", down: "\x1b[B", enter: "\r" };
const directSshClosedReasons = { REMOTE_CLOSED: "SSH-сеанс завершён на сервере.",
  OUTPUT_LIMIT: "Лимит вывода достигнут. Откройте новую сессию.",
  IDLE_TIMEOUT: "Сеанс закрыт после периода бездействия.",
  LIFETIME_LIMIT: "Сеанс достиг максимальной продолжительности.",
  SSH_DISCONNECTED: "Соединение SSH прервано." };
const directSshSessionIdPattern = /^[A-Za-z0-9_-]{12,128}$/;

function directSshActive() { return directSSH.phase !== "idle"; }
function directSshJumpEnabled() { return $("directSshUseJump").checked; }
function directSshJumpTarget() {
  const host = $("directSshJumpHost").value.trim().toLowerCase();
  const rawPort = $("directSshJumpPort").value;
  if (!host || host.length > 253 || !/^[A-Za-z0-9.:-]+$/.test(host) || host.includes("..") ||
      !/^[0-9]{1,5}$/.test(rawPort)) throw new Error("Укажите корректный адрес и порт промежуточного хоста.");
  const port = Number(rawPort);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535)
    throw new Error("Порт промежуточного хоста должен быть от 1 до 65535.");
  return { host, port };
}
function directSshJumpError(message) {
  $("directSshJumpError").textContent = message;
  $("directSshJumpError").hidden = !message;
}
function directSshJumpClearSecrets() {
  $("directSshJumpPassword").value = "";
  $("directSshJumpPrivateKey").value = "";
  $("directSshJumpPassphrase").value = "";
}
function directSshJumpInvalidate() {
  directSSH.jump.reviewed = null;
  directSSH.jump.changedPin = false;
  $("directSshJumpTrust").checked = false;
  directSshJumpClearSecrets();
  directSshJumpError("");
  serverSetupInvalidate();
}
function directSshJumpClear() {
  directSSH.jump.reviewed = null;
  directSSH.jump.changedPin = false;
  $("directSshUseJump").checked = false;
  $("directSshJumpHost").value = "";
  $("directSshJumpPort").value = "22";
  $("directSshJumpUsername").value = "";
  $("directSshJumpAuthPassword").checked = true;
  $("directSshJumpAuthKey").checked = false;
  $("directSshJumpTrust").checked = false;
  directSshJumpClearSecrets();
  directSshJumpError("");
}
function directSshCurrent(session) {
  return directSSH.session === session && directSSH.generation === session.generation &&
    directSSH.phase === "active" && state.token === session.token &&
    serverSetupAllowed() && $("addServerDialog").open && serverSetup.mode === "ssh" &&
    serverSetup.seq === session.setupSeq && state.view === session.view &&
    serverSetup.reviewed?.host === session.host && serverSetup.reviewed?.port === session.port &&
    serverSetup.reviewed?.fingerprint === session.fingerprint;
}
function directSshError(message) {
  directSSH.error = message;
  const node = $("directSshError");
  node.textContent = message;
  node.hidden = !message;
}
function directSshExplain(error) {
  if (error?.message === "DIRECT_SESSION_NOT_FOUND") return "SSH-сеанс больше не найден на шлюзе. Откройте новый.";
  if (error?.message === "DIRECT_SESSION_CLOSED") return "SSH-сеанс уже закрыт. Откройте новый.";
  if (error?.message === "DIRECT_CURSOR_EXPIRED")
    return "Часть вывода уже удалена из памяти шлюза. Откройте новый сеанс.";
  if (error?.message === "INVALID_RESPONSE") return "SSH-шлюз вернул неверный ответ.";
  if (error?.message === "SSH_TIMEOUT") return "SSH-шлюз не ответил вовремя.";
  if (error?.message === "RATE_LIMIT") return "Превышен лимит запросов. Подождите и продолжите вывод.";
  if (["AUTH_REQUIRED", "ADMIN_FORBIDDEN", "HOST_KEY_CHANGED"].includes(error?.message))
    return serverSetupExplain(error);
  return "Связь с SSH-шлюзом прервалась. Проверьте сеть и попробуйте продолжить вывод.";
}
function directSshTerminalGone(error) {
  return ["DIRECT_SESSION_NOT_FOUND", "DIRECT_SESSION_CLOSED", "DIRECT_CURSOR_EXPIRED"]
    .includes(error?.message);
}
function directSshRender() {
  const allowed = serverSetupAllowed();
  if (directSshActive() && !allowed) directSshReset({ render: false });
  const active = directSshActive();
  const opening = directSSH.phase === "opening";
  const connected = directSSH.phase === "active" && directSSH.session !== null;
  const button = $("serverSetupDirectTerminalButton");
  button.disabled = active || serverSetup.busy || Boolean(serverSetup.job) || !allowed ||
    !serverSetup.reviewed || serverSetup.changedPin || !$("serverSetupTrust").checked ||
    (directSshJumpEnabled() && (!directSSH.jump.reviewed || directSSH.jump.changedPin ||
      !$("directSshJumpTrust").checked));
  button.textContent = opening ? "Подключаемся…" : "2. Открыть SSH-терминал";
  const jump = directSshJumpEnabled();
  const jumpReviewed = directSSH.jump.reviewed;
  $("directSshJumpToggle").hidden = active;
  $("directSshJumpPanel").hidden = active || !jump;
  $("directSshJumpReview").hidden = !jumpReviewed;
  $("directSshJumpCredentials").hidden = !jumpReviewed || directSSH.jump.changedPin ||
    !$("directSshJumpTrust").checked;
  $("directSshJumpChangedKey").hidden = !directSSH.jump.changedPin;
  $("directSshJumpReplaceKey").hidden = !directSSH.jump.changedPin;
  $("directSshJumpPasswordFields").hidden = $("directSshJumpAuthKey").checked;
  $("directSshJumpKeyFields").hidden = !$("directSshJumpAuthKey").checked;
  $("directSshJumpInspect").disabled = active || serverSetup.busy || !allowed;
  $("serverSetupInspect").disabled ||= jump && (!jumpReviewed || directSSH.jump.changedPin ||
    !$("directSshJumpTrust").checked);
  $("serverSetupInspect").textContent = jump ? "1. Проверить ключ целевого сервера через ProxyJump" : "1. Проверить SSH-ключ";
  if (jump) {
    const ready = Boolean(directSshReviewedJump() && serverSetup.reviewed?.viaJump &&
      serverSetup.reviewed.jumpHost === jumpReviewed?.host &&
      serverSetup.reviewed.jumpPort === jumpReviewed?.port &&
      serverSetup.reviewed.jumpFingerprint === jumpReviewed?.fingerprint);
    $("serverSetupStatusButton").disabled ||= !ready;
    $("serverSetupPrepareButton").disabled ||= !ready;
    $("serverSetupInstallPanel").hidden ||= !ready;
  } else if (serverSetup.reviewed?.viaJump) {
    $("serverSetupStatusButton").disabled = true;
    $("serverSetupInstallPanel").hidden = true;
  }
  for (const id of ["directSshUseJump", "directSshJumpHost", "directSshJumpPort",
    "directSshJumpUsername", "directSshJumpAuthPassword", "directSshJumpAuthKey", "directSshJumpPassword",
    "directSshJumpPrivateKey", "directSshJumpPassphrase", "directSshJumpTrust"])
    $(id).disabled = active || serverSetup.busy;
  $("directSshPanel").hidden = !active;
  $("addServerDialog").classList?.toggle("direct-ssh-active", active);
  if (active) {
    for (const id of ["serverSetupRecovery", "serverSetupNotice", "serverSetupInspect", "serverSetupReview",
      "serverSetupStatusForm", "serverSetupResult", "serverSetupInstallPanel", "serverSetupJobReview",
      "serverSetupInterruptButton"]) $(id).hidden = true;
    $("serverSetupTarget").hidden = true;
  } else if (directSSH.hiddenSnapshot) {
    for (const [id, hidden] of Object.entries(directSSH.hiddenSnapshot)) $(id).hidden = hidden;
    directSSH.hiddenSnapshot = null;
  }
  $("directSshStatus").textContent = directSSH.status || (opening ? "Подключаемся по SSH…" : "");
  $("directSshClose").textContent = connected || opening || directSSH.phase === "disconnected" ? "Отключиться" : "Вернуться к настройке";
  $("directSshReconnect").hidden = directSSH.phase !== "disconnected";
  $("directSshReconnect").disabled = !allowed;
  for (const id of ["directSshLine", "directSshLineVisibility", "directSshLineSend"])
    $(id).disabled = !connected;
  document.querySelectorAll("[data-direct-ssh-key]").forEach((button) => { button.disabled = !connected; });
  if (!active) {
    $("directSshLine").value = "";
    $("directSshLine").type = "text";
    $("directSshLineVisibility").textContent = "Скрыть";
    $("directSshLineVisibility").setAttribute("aria-pressed", "false");
    $("directSshLineVisibility").setAttribute("aria-label", "Скрыть ввод");
    $("directSshLineError").hidden = true;
    $("directSshLineError").textContent = "";
    directSshError("");
  }
}
function directSshAccessChanged() {
  if (directSshActive() && !serverSetupAllowed()) directSshReset();
  else directSshRender();
}
function directSshCloseRemote(session) {
  if (!session || !serverSetupAllowed() || state.token !== session.token) return;
  // Closing is best effort during pagehide/logout; expiry on the gateway is the fallback.
  void fetch("/api/v1/browser-ssh/direct-terminal/close", { method: "POST", credentials: "omit",
    cache: "no-store", keepalive: true, redirect: "error", referrerPolicy: "no-referrer",
    headers: { "Content-Type": "application/json", Accept: "application/json",
      Authorization: `Bearer ${session.token}` },
    body: JSON.stringify({ session_id: session.id }) }).catch(() => {});
}
function directSshReset({ render = true } = {}) {
  const session = directSSH.session;
  const wasActive = directSshActive();
  directSSH.generation++;
  directSSH.phase = "idle";
  directSSH.session = null;
  directSSH.opening = false;
  directSSH.status = "";
  for (const bytes of directSSH.input) bytes.fill(0);
  directSSH.input = [];
  directSSH.inputBytes = 0;
  directSSH.draining = false;
  for (const controller of directSSH.controllers) controller.abort();
  directSSH.controllers.clear();
  if (directSSH.pollTimer) clearTimeout(directSSH.pollTimer);
  directSSH.pollWake?.();
  if (directSSH.inputTimer) clearTimeout(directSSH.inputTimer);
  if (directSSH.resizeTimer) clearTimeout(directSSH.resizeTimer);
  directSSH.pollTimer = directSSH.inputTimer = directSSH.resizeTimer = null;
  directSSH.pollWake = null;
  directSSH.resizeObserver?.disconnect();
  directSSH.resizeObserver = null;
  directSSH.term?.dispose();
  directSSH.term = directSSH.fit = null;
  $("directSshScreen").replaceChildren();
  $("directSshLine").value = "";
  if (wasActive) {
    serverSetupClearSecrets();
    directSshJumpClearSecrets();
    globalThis.sovagridSSHKeygen?.clear?.("setup");
  }
  if (directSSH.hiddenSnapshot) {
    for (const [id, hidden] of Object.entries(directSSH.hiddenSnapshot)) $(id).hidden = hidden;
    directSSH.hiddenSnapshot = null;
  }
  if (serverSetup.phase === "terminal") { serverSetup.phase = null; serverSetup.busy = false; }
  directSshCloseRemote(session);
  if (render) serverSetupRender();
}
async function directSshPost(path, value, session, timeoutMs = 16000) {
  if (!directSshCurrent(session)) throw new Error("STALE_REQUEST");
  const controller = new AbortController();
  directSSH.controllers.add(controller);
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`/api/v1/browser-ssh/direct-terminal/${path}`, {
      method: "POST", credentials: "omit", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer",
      headers: { "Content-Type": "application/json", Accept: "application/json",
        Authorization: `Bearer ${session.token}` },
      body: JSON.stringify(value), signal: controller.signal });
    let payload;
    try { payload = await response.json(); } catch { throw new Error("INVALID_RESPONSE"); }
    if (!response.ok) {
      const failure = new Error(typeof payload?.error === "string" ? payload.error : "SSH_UNAVAILABLE");
      failure.status = response.status;
      throw failure;
    }
    return payload;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("SSH_TIMEOUT");
    throw error;
  } finally {
    clearTimeout(timer);
    directSSH.controllers.delete(controller);
  }
}
function directSshBytes(data) {
  if (typeof data !== "string" || data.length > 90000 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(data))
    throw new Error("INVALID_RESPONSE");
  const raw = atob(data);
  if (raw.length > 65536) throw new Error("INVALID_RESPONSE");
  return Uint8Array.from(raw, (char) => char.charCodeAt(0));
}
function directSshBase64(bytes) {
  let raw = "";
  for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw);
}
function directSshOpenScreen() {
  if (typeof Terminal !== "function" || !globalThis.FitAddon?.FitAddon)
    throw new Error("Компонент терминала не загрузился. Обновите страницу.");
  const term = new Terminal({ cursorBlink: true, scrollback: 2000, convertEol: false,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", fontSize: 13,
    theme: terminalPalette() });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open($("directSshScreen"));
  term.onData((data) => { void directSshSend(data); });
  directSSH.term = term;
  directSSH.fit = fit;
  if (globalThis.ResizeObserver) {
    directSSH.resizeObserver = new ResizeObserver(() => {
      if (directSSH.resizeTimer) clearTimeout(directSSH.resizeTimer);
      directSSH.resizeTimer = setTimeout(directSshFit, 120);
    });
    directSSH.resizeObserver.observe($("directSshScreen"));
  }
  directSshFit();
  globalThis.requestAnimationFrame?.(directSshFit);
}
function directSshFit() {
  if (!directSSH.term || $("directSshPanel").hidden ||
      $("directSshScreen").getBoundingClientRect?.().width === 0) return;
  try { directSSH.fit.fit(); } catch { return; }
  const cols = Math.max(20, Math.min(300, directSSH.term.cols || 80));
  const rows = Math.max(10, Math.min(120, directSSH.term.rows || 24));
  const session = directSSH.session;
  if (!session || !directSshCurrent(session) || (session.cols === cols && session.rows === rows)) return;
  session.cols = cols;
  session.rows = rows;
  void directSshPost("resize", { session_id: session.id, cols, rows }, session).catch((error) => {
    if (directSshCurrent(session)) directSshError(serverSetupExplain(error));
  });
}
function directSshValidateOpen(reply, reviewed, jump = null) {
  return reply && directSshSessionIdPattern.test(reply.session_id || "") && reply.next_cursor === 0 &&
    reply.host_key_fingerprint === reviewed.fingerprint &&
    (!jump || reply.jump_host_key_fingerprint === jump.fingerprint) &&
    (reply.expires_at === undefined || typeof reply.expires_at === "string" ||
      Number.isSafeInteger(reply.expires_at));
}
function directSshHostKeyReplyValid(reply, target) {
  return reply?.protocol === 1 && reply.scope === "entered_target" && reply.reverify_required === true &&
    reply.host === target.host && reply.port === target.port &&
    typeof reply.key_type === "string" && /^[A-Za-z0-9@._-]{4,96}$/.test(reply.key_type) &&
    typeof reply.fingerprint === "string" && serverSetupFingerprintPattern.test(reply.fingerprint) &&
    (!Object.hasOwn(reply, "host_key_blob") || serverSetupHostKeyBlobValid(reply.host_key_blob));
}
async function directSshJumpInspect() {
  if (!directSshJumpEnabled() || directSshActive() || !serverSetupAllowed() ||
      serverSetup.busy || !$("addServerDialog").open) return;
  let target;
  try { target = directSshJumpTarget(); }
  catch (error) { directSshJumpError(error.message); return; }
  directSSH.jump.reviewed = null;
  directSSH.jump.changedPin = false;
  $("directSshJumpTrust").checked = false;
  serverSetupInvalidate();
  const seq = serverSetup.seq;
  const token = state.token;
  serverSetup.busy = true;
  serverSetup.phase = "jump_inspect";
  directSshJumpError("");
  serverSetupRender();
  try {
    const reply = await serverSetupApi("/api/v1/browser-ssh/target-host-key", target, 12000, seq);
    if (seq !== serverSetup.seq || token !== state.token || !serverSetupAllowed() ||
        !$("addServerDialog").open || !directSshJumpEnabled()) return;
    if (!directSshHostKeyReplyValid(reply, target)) throw new Error("INVALID_RESPONSE");
    directSSH.jump.reviewed = { ...target, fingerprint: reply.fingerprint,
      host_key_blob: reply.host_key_blob };
    $("directSshJumpReviewedHost").textContent = target.host.includes(":") ?
      `[${target.host}]:${target.port}` : `${target.host}:${target.port}`;
    $("directSshJumpFingerprint").textContent = reply.fingerprint;
    $("directSshJumpKeyType").textContent = `Алгоритм: ${reply.key_type}`;
    directSSH.jump.changedPin = Boolean(serverSetupPin(target.host, target.port) &&
      serverSetupPin(target.host, target.port) !== reply.fingerprint);
    if (directSSH.jump.changedPin)
      directSshJumpError("Закреплённый ключ промежуточного хоста изменился. Сверьте новый отпечаток независимо.");
  } catch (error) {
    if (seq === serverSetup.seq) directSshJumpError(serverSetupExplain(error));
  } finally {
    if (seq === serverSetup.seq) { serverSetup.busy = false; serverSetup.phase = null; serverSetupRender(); }
  }
}
async function directSshJumpCredentials(seq, reviewed) {
  const target = directSshJumpTarget();
  if (target.host !== reviewed?.host || target.port !== reviewed.port ||
      !$("directSshJumpTrust").checked || directSSH.jump.changedPin) throw new Error("STALE_REQUEST");
  const username = $("directSshJumpUsername").value.trim();
  const method = $("directSshJumpAuthKey").checked ? "private_key" : "password";
  if (!serverSetupUsernamePattern.test(username)) throw new Error("INVALID_USERNAME");
  const file = method === "private_key" ? $("directSshJumpPrivateKey").files?.[0] : null;
  if (method === "private_key" && (!file || file.size < 1 || file.size > 65536))
    throw new Error("KEY_INVALID");
  let password = "", private_key = "", passphrase = "";
  try {
    if (method === "private_key") {
      try { private_key = await file.text(); } catch { throw new Error("FILE_READ_FAILED"); }
      passphrase = $("directSshJumpPassphrase").value;
    } else password = $("directSshJumpPassword").value;
    if (seq !== serverSetup.seq || !serverSetupAllowed() || !$("addServerDialog").open ||
        !directSshJumpEnabled() || directSSH.jump.reviewed?.fingerprint !== reviewed.fingerprint ||
        $("directSshJumpUsername").value.trim() !== username ||
        ($("directSshJumpAuthKey").checked ? "private_key" : "password") !== method ||
        (file && $("directSshJumpPrivateKey").files?.[0] !== file)) throw new Error("STALE_REQUEST");
    if (method === "password" && (!password || password.length > 1024)) throw new Error("PASSWORD_INVALID");
    if (passphrase.length > 1024) throw new Error("PASSPHRASE_INVALID");
    return { host: reviewed.host, port: reviewed.port, username, method,
      fingerprint: reviewed.fingerprint, password, private_key, passphrase };
  } finally {
    directSshJumpClearSecrets();
    password = private_key = passphrase = "";
  }
}

function directSshReviewedJump() {
  const reviewed = directSSH.jump.reviewed;
  const saved = reviewed ? serverSetupPin(reviewed.host, reviewed.port) : null;
  if (!directSshJumpEnabled() || !reviewed || directSSH.jump.changedPin ||
      !$("directSshJumpTrust").checked || !serverSetupHostKeyBlobValid(reviewed.host_key_blob) ||
      (saved && saved !== reviewed.fingerprint)) return null;
  try {
    const target = directSshJumpTarget();
    if (target.host !== reviewed.host || target.port !== reviewed.port) return null;
  } catch { return null; }
  return { ...reviewed };
}

async function directSshInstallJumpCredentials(seq, reviewed) {
  const current = directSshReviewedJump();
  if (!current || current.host !== reviewed?.host || current.port !== reviewed.port ||
      current.fingerprint !== reviewed.fingerprint ||
      current.host_key_blob !== reviewed.host_key_blob) throw new Error("STALE_REQUEST");
  const credentials = await directSshJumpCredentials(seq, current);
  return { ...credentials, host_key_blob: current.host_key_blob };
}
async function directSshInspectTargetViaJump() {
  if (!directSshJumpEnabled() || directSshActive() || serverSetup.busy || !serverSetupAllowed() ||
      !directSSH.jump.reviewed || directSSH.jump.changedPin || !$("directSshJumpTrust").checked) return;
  const jump = { ...directSSH.jump.reviewed };
  let target;
  try { target = serverSetupTarget(); }
  catch (error) { serverSetupError(error.message); return; }
  if (target.host === jump.host && target.port === jump.port) {
    serverSetupError("Укажите разные адреса для целевого и промежуточного серверов."); return;
  }
  const jumpPin = serverSetupPin(jump.host, jump.port);
  serverSetupInvalidate();
  const seq = serverSetup.seq;
  const token = state.token;
  serverSetup.busy = true;
  serverSetup.phase = "inspect";
  serverSetupClearError();
  serverSetupRender();
  try {
    const jumpCredentials = await directSshJumpCredentials(seq, jump);
    if (token !== state.token || serverSetupPin(jump.host, jump.port) !== jumpPin)
      throw new Error("STALE_REQUEST");
    const reply = await serverSetupApi("/api/v1/browser-ssh/target-host-key",
      { ...target, jump: jumpCredentials }, 30000, seq);
    if (seq !== serverSetup.seq || token !== state.token || !serverSetupAllowed() ||
        !$("addServerDialog").open || !directSshJumpEnabled()) return;
    if (!directSshHostKeyReplyValid(reply, target) ||
        reply.jump_host_key_fingerprint !== jump.fingerprint) throw new Error("INVALID_RESPONSE");
    serverSetupSavePin(jump.host, jump.port, jump.fingerprint);
    serverSetup.reviewed = { ...target, fingerprint: reply.fingerprint,
      host_key_blob: reply.host_key_blob, viaJump: true,
      jumpHost: jump.host, jumpPort: jump.port, jumpFingerprint: jump.fingerprint };
    $("serverSetupReviewedHost").textContent = target.host.includes(":") ?
      `[${target.host}]:${target.port}` : `${target.host}:${target.port}`;
    $("serverSetupFingerprint").textContent = reply.fingerprint;
    $("serverSetupKeyType").textContent = `Алгоритм: ${reply.key_type}; через ${jump.host}`;
    serverSetup.changedPin = Boolean(serverSetupPin(target.host, target.port) &&
      serverSetupPin(target.host, target.port) !== reply.fingerprint);
    if (serverSetup.changedPin)
      serverSetupError("Закреплённый ключ целевого хоста изменился. Сверьте его независимо.");
  } catch (error) {
    if (seq === serverSetup.seq) serverSetupError(
      error.message === "FILE_READ_FAILED" ? "Не удалось прочитать ключ промежуточного хоста." :
      error.message === "KEY_INVALID" ? "Выберите ключ промежуточного хоста размером до 64 КиБ." :
      error.message === "INVALID_USERNAME" ? "Введите пользователя SSH промежуточного хоста." :
      error.message === "PASSWORD_INVALID" ? "Введите пароль промежуточного хоста длиной до 1024 символов." :
      error.message === "PASSPHRASE_INVALID" ? "Парольная фраза промежуточного хоста слишком длинная." :
      serverSetupExplain(error));
  } finally {
    directSshJumpClearSecrets();
    if (seq === serverSetup.seq) { serverSetup.busy = false; serverSetup.phase = null; serverSetupRender(); }
  }
}
async function directSshOpen() {
  if (directSshActive() || serverSetup.busy || serverSetup.job || !serverSetupAllowed() ||
      !serverSetup.reviewed || serverSetup.changedPin || !$("serverSetupTrust").checked ||
      !$("addServerDialog").open || serverSetup.mode !== "ssh") return;
  const reviewed = { ...serverSetup.reviewed };
  const useJump = directSshJumpEnabled();
  const jump = useJump ? { ...directSSH.jump.reviewed } : null;
  const jumpPin = useJump && jump?.host ? serverSetupPin(jump.host, jump.port) : null;
  if (useJump && (!jump?.fingerprint || directSSH.jump.changedPin ||
      !$("directSshJumpTrust").checked || !reviewed.viaJump ||
      reviewed.jumpHost !== jump.host || reviewed.jumpPort !== jump.port ||
      reviewed.jumpFingerprint !== jump.fingerprint ||
      (jumpPin && jumpPin !== jump.fingerprint))) {
    serverSetupError("Сначала проверьте ключ целевого сервера через промежуточный хост."); return;
  }
  if (!useJump && reviewed.viaJump) {
    serverSetupError("Способ подключения изменился. Сверьте ключ сервера заново."); return;
  }
  let target;
  try { target = serverSetupTarget(); }
  catch (error) { serverSetupError(error.message); return; }
  if (target.host !== reviewed.host || target.port !== reviewed.port) {
    serverSetupInvalidate(); serverSetupError("Адрес или порт изменились. Сверьте SSH-ключ заново."); return;
  }
  const username = $("serverSetupUsername").value.trim();
  const method = $("serverSetupAuthKey").checked ? "private_key" : "password";
  if (!serverSetupUsernamePattern.test(username)) {
    serverSetupError("Введите корректное имя пользователя SSH."); return;
  }
  const generated = method === "private_key" ? globalThis.sovagridSSHKeygen?.get("setup") : null;
  if (generated && !generated.downloadRequested) {
    serverSetupError("Сначала скачайте созданный приватный ключ и добавьте публичный на сервер."); return;
  }
  const file = method === "private_key" && !generated ? $("serverSetupPrivateKey").files?.[0] : null;
  if (method === "private_key" && !generated && (!file || file.size < 1 || file.size > 65536)) {
    serverSetupError("Выберите приватный ключ размером до 64 КиБ."); return;
  }
  const pin = serverSetupPin(reviewed.host, reviewed.port);
  const seq = ++serverSetup.seq;
  const generation = ++directSSH.generation;
  const token = state.token;
  directSSH.phase = "opening";
  directSSH.hiddenSnapshot = Object.fromEntries(["serverSetupTarget", "serverSetupInspect",
    "serverSetupRecovery", "serverSetupResult"].map((id) => [id, $(id).hidden]));
  directSSH.opening = true;
  directSSH.status = "Подключаемся к SSH-серверу…";
  serverSetup.busy = true;
  serverSetup.phase = "terminal";
  serverSetupClearError();
  $("directSshTarget").textContent = `${username}@${reviewed.host.includes(":") ? `[${reviewed.host}]` : reviewed.host}:${reviewed.port}`;
  serverSetupRender();
  let password = "", private_key = "", passphrase = "";
  try {
    directSshOpenScreen();
    if (method === "private_key") {
      if (generated) private_key = generated.privateKey;
      else {
        try { private_key = await file.text(); } catch { throw new Error("FILE_READ_FAILED"); }
        passphrase = $("serverSetupPassphrase").value;
      }
    } else password = $("serverSetupPassword").value;
    if (generation !== directSSH.generation || seq !== serverSetup.seq || token !== state.token ||
        !serverSetupAllowed() || !$("addServerDialog").open || serverSetup.mode !== "ssh" ||
        serverSetupPin(reviewed.host, reviewed.port) !== pin ||
        !$("serverSetupTrust").checked || serverSetup.changedPin) throw new Error("STALE_REQUEST");
    if (method === "password" && (!password || password.length > 1024)) throw new Error("PASSWORD_INVALID");
    if (passphrase.length > 1024) throw new Error("PASSPHRASE_INVALID");
    serverSetupClearSecrets();
    const jumpCredentials = useJump ? await directSshJumpCredentials(seq, jump) : null;
    if (generation !== directSSH.generation || seq !== serverSetup.seq || token !== state.token ||
        serverSetupPin(reviewed.host, reviewed.port) !== pin ||
        (useJump && serverSetupPin(jump.host, jump.port) !== jumpPin))
      throw new Error("STALE_REQUEST");
    const payload = { host: reviewed.host, port: reviewed.port, username, method,
      fingerprint: reviewed.fingerprint, password, private_key, passphrase,
      cols: Math.max(20, Math.min(300, directSSH.term?.cols || 80)),
      rows: Math.max(10, Math.min(120, directSSH.term?.rows || 24)) };
    if (jumpCredentials) payload.jump = jumpCredentials;
    password = private_key = passphrase = "";
    const reply = await serverSetupApi("/api/v1/browser-ssh/direct-terminal/open", payload, 30000, seq);
    if (generation !== directSSH.generation || seq !== serverSetup.seq || token !== state.token ||
        !serverSetupAllowed() || !$("addServerDialog").open) {
      if (directSshSessionIdPattern.test(reply?.session_id || ""))
        directSshCloseRemote({ id: reply.session_id, token });
      return;
    }
    if (!directSshValidateOpen(reply, reviewed, jump)) {
      if (directSshSessionIdPattern.test(reply?.session_id || ""))
        directSshCloseRemote({ id: reply.session_id, token });
      throw new Error("INVALID_RESPONSE");
    }
    serverSetupSavePin(reviewed.host, reviewed.port, reviewed.fingerprint);
    if (jump) serverSetupSavePin(jump.host, jump.port, jump.fingerprint);
    globalThis.sovagridSSHKeygen?.clear?.("setup");
    directSSH.session = { id: reply.session_id, token, generation, setupSeq: seq,
      host: reviewed.host, port: reviewed.port, fingerprint: reviewed.fingerprint,
      view: state.view, cursor: 0, cols: payload.cols, rows: payload.rows };
    directSSH.phase = "active";
    directSSH.status = "Соединение установлено. Ввод доступен в терминале или через поле ниже.";
    directSSH.opening = false;
    serverSetup.busy = false;
    serverSetup.phase = null;
    serverSetupRender();
    directSshFit();
    directSSH.term?.focus?.();
    void directSshPoll(directSSH.session);
  } catch (error) {
    if (generation === directSSH.generation) {
      const message = error.message === "FILE_READ_FAILED" ? "Не удалось прочитать приватный ключ." :
        error.message === "PASSWORD_INVALID" ? "Введите пароль SSH длиной до 1024 символов." :
        error.message === "PASSPHRASE_INVALID" ? "Парольная фраза слишком длинная." :
        error.message === "STALE_REQUEST" ? "Параметры SSH изменились. Сверьте ключ заново." :
        error.message === "INVALID_RESPONSE" ? "SSH-шлюз вернул неверный ответ. Соединение не открыто." :
        error.message.startsWith("Компонент терминала") ? error.message : serverSetupExplain(error);
      directSshReset({ render: false });
      serverSetupError(message);
      serverSetupRender();
    }
  } finally {
    password = private_key = passphrase = "";
    directSshJumpClearSecrets();
    if (generation === directSSH.generation) serverSetupClearSecrets();
  }
}
async function directSshPoll(session) {
  while (directSshCurrent(session)) {
    try {
      const reply = await directSshPost("events", { session_id: session.id, cursor: session.cursor }, session, 26000);
      if (!directSshCurrent(session)) return;
      if (!Array.isArray(reply?.events) ||
          !Number.isSafeInteger(reply.next_cursor) || reply.next_cursor < session.cursor ||
          typeof reply.closed !== "boolean") throw new Error("INVALID_RESPONSE");
      let previous = session.cursor;
      for (const event of reply.events) {
        if (!Number.isSafeInteger(event?.cursor) || event.cursor <= previous ||
            event.cursor > reply.next_cursor) throw new Error("INVALID_RESPONSE");
        const bytes = directSshBytes(event.data);
        directSSH.term?.write(bytes);
        previous = event.cursor;
      }
      session.cursor = reply.next_cursor;
      if (reply.closed) {
        directSSH.phase = "closed";
        directSSH.status = directSshClosedReasons[reply.reason] || "SSH-сеанс завершён.";
        directSSH.session = null;
        directSshCloseRemote(session);
        directSshRender();
        return;
      }
      if (!reply.events.length) await new Promise((resolve) => {
        const wake = () => { directSSH.pollWake = null; directSSH.pollTimer = null; resolve(); };
        directSSH.pollWake = wake;
        directSSH.pollTimer = setTimeout(wake, 900);
      });
    } catch (error) {
      if (!directSshCurrent(session)) return;
      if (directSshTerminalGone(error)) {
        directSSH.phase = "closed";
        directSSH.session = null;
        directSSH.status = directSshExplain(error);
        directSshCloseRemote(session);
      } else {
        directSSH.phase = "disconnected";
        directSSH.status = "Связь с SSH-шлюзом прервалась. Вывод можно продолжить без повторной отправки команд.";
        directSshError(directSshExplain(error));
      }
      directSshRender();
      return;
    }
  }
}
function directSshReconnect() {
  const session = directSSH.session;
  if (!session || directSSH.phase !== "disconnected" || !serverSetupAllowed()) return;
  directSSH.phase = "active";
  directSSH.status = "Восстанавливаем вывод SSH-сеанса…";
  directSshError("");
  directSshRender();
  void directSshPoll(session);
}
async function directSshSend(data) {
  const session = directSSH.session;
  if (!session || !directSshCurrent(session)) return;
  const bytes = new TextEncoder().encode(data);
  if (!bytes.length) return;
  if (bytes.length > 4096 || directSSH.inputBytes + bytes.length > 16384) {
    directSshError("Ввод слишком длинный. Отправляйте не более 4 КиБ за раз."); return;
  }
  directSSH.input.push(bytes);
  directSSH.inputBytes += bytes.length;
  // A browser terminal emits one callback per key. Coalesce ordinary typing
  // to avoid one HTTP request per character, while Enter/interrupt stay prompt.
  if (/[\x00-\x1f\x7f]/.test(data)) {
    if (directSSH.inputTimer) clearTimeout(directSSH.inputTimer);
    directSSH.inputTimer = null;
    void directSshDrain(session);
  } else if (!directSSH.draining && !directSSH.inputTimer) {
    directSSH.inputTimer = setTimeout(() => {
      directSSH.inputTimer = null;
      void directSshDrain(session);
    }, 100);
  }
}
async function directSshDrain(session) {
  if (directSSH.draining) return;
  if (directSSH.inputTimer) clearTimeout(directSSH.inputTimer);
  directSSH.inputTimer = null;
  directSSH.draining = true;
  try {
    while (directSSH.input.length && directSshCurrent(session)) {
      const chunks = [];
      let length = 0;
      for (const bytes of directSSH.input) {
        if (length + bytes.length > 4096) break;
        chunks.push(bytes);
        length += bytes.length;
      }
      const combined = new Uint8Array(length);
      let offset = 0;
      for (const bytes of chunks) { combined.set(bytes, offset); offset += bytes.length; }
      let reply;
      try {
        reply = await directSshPost("input", { session_id: session.id,
          data: directSshBase64(combined) }, session);
      } finally { combined.fill(0); }
      if (!directSshCurrent(session)) return;
      if (reply?.accepted !== true) throw new Error("INVALID_RESPONSE");
      directSSH.input.splice(0, chunks.length);
      directSSH.inputBytes -= length;
      for (const bytes of chunks) bytes.fill(0);
    }
  } catch (error) {
    if (directSshCurrent(session)) {
      for (const bytes of directSSH.input) bytes.fill(0);
      directSSH.input = [];
      directSSH.inputBytes = 0;
      if (directSshTerminalGone(error)) {
        directSSH.phase = "closed";
        directSSH.session = null;
        directSSH.status = directSshExplain(error);
        directSshCloseRemote(session);
      } else {
        directSSH.phase = "disconnected";
        directSSH.status = "Подтверждение ввода потеряно. После восстановления проверьте экран перед повтором команды.";
        directSshError(directSshExplain(error));
      }
      directSshRender();
    }
  } finally { directSSH.draining = false; }
}
function directSshSendLine(event) {
  event.preventDefault();
  const input = $("directSshLine");
  const value = input.value;
  input.value = "";
  if (/[\r\n]/.test(value)) {
    $("directSshLineError").textContent = "Вставьте одну строку. Для нескольких команд используйте терминал.";
    $("directSshLineError").hidden = false;
    return;
  }
  $("directSshLineError").hidden = true;
  $("directSshLineError").textContent = "";
  if (directSSH.phase === "active") void directSshSend(`${value}\r`);
}
function directSshToggleVisibility() {
  const input = $("directSshLine");
  input.type = input.type === "password" ? "text" : "password";
  const hidden = input.type === "password";
  $("directSshLineVisibility").textContent = hidden ? "Показать" : "Скрыть";
  $("directSshLineVisibility").setAttribute("aria-pressed", String(hidden));
  $("directSshLineVisibility").setAttribute("aria-label", hidden ? "Показать ввод" : "Скрыть ввод");
  input.focus();
}

$("serverSetupDirectTerminalButton").addEventListener("click", () => { void directSshOpen(); });
$("directSshUseJump").addEventListener("change", directSshJumpInvalidate);
$("directSshJumpHost").addEventListener("input", directSshJumpInvalidate);
$("directSshJumpPort").addEventListener("input", directSshJumpInvalidate);
$("directSshJumpInspect").addEventListener("click", () => { void directSshJumpInspect(); });
$("directSshJumpTrust").addEventListener("change", directSshRender);
$("directSshJumpReplaceKey").addEventListener("click", () => {
  if (!directSSH.jump.reviewed || !directSSH.jump.changedPin || !globalThis.confirm?.(
    "Вы независимо сверили новый SSH-отпечаток промежуточного хоста?")) return;
  directSSH.jump.changedPin = false;
  $("directSshJumpTrust").checked = false;
  directSshJumpError("");
  directSshRender();
});
$("directSshJumpUsername").addEventListener("input", directSshRender);
$("directSshJumpAuthPassword").addEventListener("change", () => { directSshJumpClearSecrets(); directSshRender(); });
$("directSshJumpAuthKey").addEventListener("change", () => { directSshJumpClearSecrets(); directSshRender(); });
document.addEventListener("visibilitychange", () => { if (document.hidden) directSshJumpClearSecrets(); });
$("directSshClose").addEventListener("click", () => directSshReset());
$("directSshReconnect").addEventListener("click", directSshReconnect);
$("directSshLineForm").addEventListener("submit", directSshSendLine);
$("directSshLineVisibility").addEventListener("click", directSshToggleVisibility);
document.querySelectorAll("[data-direct-ssh-key]").forEach((button) => button.addEventListener("click", () => {
  if (Object.hasOwn(directSshKeys, button.dataset.directSshKey))
    void directSshSend(directSshKeys[button.dataset.directSshKey]);
}));
globalThis.addEventListener?.("resize", directSshFit);
globalThis.addEventListener?.("sovagridthemechange", () => {
  if (directSSH.term?.options) directSSH.term.options.theme = terminalPalette();
});
globalThis.sovagridDirectSSH = { render: directSshRender, reset: directSshReset,
  accessChanged: directSshAccessChanged, jumpEnabled: directSshJumpEnabled,
  inspectTargetViaJump: directSshInspectTargetViaJump, clearJump: directSshJumpClear,
  reviewedJump: directSshReviewedJump, installJumpCredentials: directSshInstallJumpCredentials };

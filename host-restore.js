/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

const HOST_RESTORE_PARTS = Object.freeze({ host_manifest: "Описание архива", host: "Архив сервера",
  images_manifest: "Описание образов", images: "Образы Docker", receipt: "Квитанция" });
const HOST_RESTORE_LIMITS = Object.freeze({ host_manifest: 65536, host: 8 * 1024 ** 3,
  images_manifest: 4096, images: 8 * 1024 ** 3, receipt: 8192 });
const HOST_RESTORE_PHASES = Object.freeze({ preparing: "Передача и проверка копии", review: "План готов",
  resume_required: "Подготовку нужно продолжить", receiving: "Передача", ready: "Копия проверена",
  accepted: "Принято сервером", starting: "Запуск", applying: "Восстановление",
  committed: "Восстановлено и проверено", rolled_back: "Цель возвращена к прежнему состоянию",
  recovering: "Безопасный откат", recovery_required: "Нужна проверка восстановления",
  retry_required: "Нужно закончить подготовку новой попытки", uncertain: "Ответ не подтверждён" });
const HOST_RESTORE_BLOCKERS = Object.freeze({ APPLY_NOT_IMPLEMENTED: "Полное применение ещё не включено в выбранном выпуске.",
  PUBLIC_ENDPOINT_MISMATCH: "Публичный адрес из копии не принадлежит цели. Его перенос в этом мастере пока не поддерживается.",
  TARGET_NOT_CLEAN: "На цели уже есть данные SovaGrid.", TARGET_NOT_EMPTY: "Цель уже содержит данные SovaGrid.",
  RESTORE_DISK_SPACE: "На цели недостаточно свободного места.",
  RESTORE_ROUTING_STATE_UNSUPPORTED: "Перенос включённой VPN-маршрутизации из этой копии пока не поддерживается.",
  RESTORE_LAYOUT_UNSUPPORTED: "Схема установки в копии пока не поддерживается.",
  RESTORE_IDENTITY_EXISTS: "На цели заняты служебные учётные записи из копии.",
  RECEIPT_V1_UNSUPPORTED: "Нужна переносимая копия формата v2.",
  RESTORE_RUNTIME_STATE_PRESENT: "На цели уже есть рабочие данные восстанавливаемой службы." });
const hostRestore = { generation: 0, source: null, upload: null, files: null, active: null, history: [],
  targetPin: null, jumpPin: null, busy: false, timer: null, controllers: new Set(), keyReads: new Map(), openedView: null };

function hostRestoreAllowed() { return typeof serverSetupAllowed === "function" && serverSetupAllowed(); }
function hostRestoreContext() { return { generation: hostRestore.generation, token: state.token, base: state.base }; }
function hostRestoreCurrent(context) {
  return hostRestore.generation === context.generation && state.token === context.token && state.base === context.base &&
    $("hostRestoreDialog").open && hostRestoreAllowed() && state.view === hostRestore.openedView;
}
function hostRestoreId() {
  const raw = new Uint8Array(16); crypto.getRandomValues(raw);
  return [...raw].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
function hostRestoreMarker(value) {
  try {
    const key = `sovagrid.host-restore.v1:${state.base}`;
    if (value) localStorage.setItem(key, value); else return localStorage.getItem(key);
  } catch { /* Server history remains available when browser storage is disabled. */ }
  return null;
}
function hostRestoreUploadMarker(value) {
  try {
    const key = `sovagrid.host-restore-import.v1:${state.base}`;
    if (value === null) localStorage.removeItem(key);
    else if (value !== undefined) localStorage.setItem(key, JSON.stringify(value));
    else {
      const raw = localStorage.getItem(key);
      if (!raw || raw.length > 4096) return null;
      const saved = JSON.parse(raw);
      return /^[0-9a-f]{32}$/.test(saved?.source_id) && /^[0-9a-f]{32}$/.test(saved?.archive_id) ? saved : null;
    }
  } catch {}
  return null;
}
function hostRestoreError(error) {
  const code = typeof error === "string" ? error : error?.message;
  const messages = { AUTH_REQUIRED: "Войдите в Hub заново.", ADMIN_FORBIDDEN: "Нужен администратор с доступом ко всем серверам.",
    SOURCE_CHANGED: "Файлы или выбранная копия изменились. Проверьте источник перед продолжением.",
    SOURCE_INCOMPLETE: "Нужно заново выбрать и загрузить все пять файлов копии.",
    SOURCE_UNSUPPORTED: "Нужна полная переносимая копия формата v2.",
    SOURCE_UNAVAILABLE: "Исходная копия недоступна. Можно импортировать её пять файлов с устройства.",
    TARGET_CHANGED: "Адрес, пользователь или SSH-ключ отличается от сохранённой операции.",
    STALE_REVISION: "Состояние изменилось. Проверьте сервер и получите новый план.",
    RESTORE_RESPONSE_UNCERTAIN: "Ответ потерян. Сначала проверьте сохранённую операцию; применение не повторяется автоматически.",
    RESTORE_PREPARE_FAILED: "Подготовка остановилась. Проверьте SSH-доступ, root/sudo и доступность Ubuntu, затем продолжите эту операцию.",
    RESUME_REQUIRED: "Сначала проверьте сохранённую операцию на целевом сервере.",
    INSUFFICIENT_SPACE: "На Hub недостаточно места для импортируемой копии.",
    ARCHIVE_FULL: "Достигнут лимит сохранённых импортов или операций. Удалите ненужную импортированную копию.",
    RUNTIME_UNAVAILABLE: "Обновите серверную часть Hub: мастер восстановления ещё недоступен.",
    BUSY: "Сейчас выполняется другой шаг. Дождитесь его окончания.",
    HOST_KEY_CHANGED: "SSH-ключ изменился. Сверьте новый отпечаток независимо от этой панели." };
  return messages[code] || (code === "STALE_REQUEST" ? "" :
    "Не удалось подтвердить запрос. Проверьте сохранённое состояние перед повтором.");
}
function hostRestoreShowError(error) {
  const text = hostRestoreError(error);
  $("hostRestoreError").textContent = text; $("hostRestoreError").hidden = !text;
}
async function hostRestoreRequest(action, payload, context, { binary = null, timeout = 600000 } = {}) {
  if (!hostRestoreCurrent(context)) throw new Error("STALE_REQUEST");
  const controller = new AbortController(); hostRestore.controllers.add(controller);
  const timer = setTimeout(() => controller.abort(), timeout);
  const headers = { Accept: "application/json", Authorization: `Bearer ${context.token}` };
  let body;
  if (binary !== null) {
    headers["Content-Type"] = "application/octet-stream";
    headers["X-SovaGrid-Restore-Meta"] = encodeURIComponent(JSON.stringify(payload)); body = binary;
  } else { headers["Content-Type"] = "application/json"; body = JSON.stringify(payload); }
  try {
    const reply = await fetch(`${context.base}/api/v1/browser-ssh/restore/${action}`, {
      method: "POST", headers, body, cache: "no-store", credentials: "omit", redirect: "error",
      referrerPolicy: "no-referrer", signal: controller.signal });
    const raw = await reply.text();
    if (raw.length > 32768) throw new Error("INVALID_RESPONSE");
    let value; try { value = JSON.parse(raw); } catch { throw new Error("INVALID_RESPONSE"); }
    if (!reply.ok) throw new Error(value.error || "REQUEST_FAILED");
    if (!hostRestoreCurrent(context)) throw new Error("STALE_REQUEST");
    if (value?.protocol !== "sovagrid-web-restore-v1") throw new Error("INVALID_RESPONSE");
    return value;
  } finally { clearTimeout(timer); hostRestore.controllers.delete(controller); }
}

function hostRestoreReleaseSelected(files) {
  for (const file of files) {
    try { Promise.resolve(file.release?.()).catch(() => {}); } catch {}
  }
}
function hostRestoreReleaseFiles() {
  hostRestoreReleaseSelected(Object.values(hostRestore.files || {}));
  hostRestore.files = null;
  $("hostRestoreFiles").value = "";
}
function hostRestoreClearSecrets() {
  for (const prefix of ["hostRestoreTarget", "hostRestoreJump"])
    for (const field of ["Password", "PrivateKey", "Passphrase", "KeyFile"]) $(prefix + field).value = "";
}
function hostRestoreInvalidateWork() {
  hostRestore.generation++;
  for (const controller of hostRestore.controllers) controller.abort();
  hostRestore.controllers.clear(); clearTimeout(hostRestore.timer); hostRestore.timer = null;
}
function hostRestoreReset() {
  hostRestore.generation++;
  for (const controller of hostRestore.controllers) controller.abort();
  hostRestore.controllers.clear(); clearTimeout(hostRestore.timer); hostRestore.timer = null;
  hostRestoreReleaseFiles(); hostRestoreClearSecrets();
  hostRestore.busy = false; hostRestore.targetPin = hostRestore.jumpPin = null;
  for (const prefix of ["hostRestoreTarget", "hostRestoreJump"]) {
    $(prefix + "Trust").checked = false;
    $(prefix + "Fingerprint").textContent = "";
  }
  if ($("hostRestoreDialog").open) $("hostRestoreDialog").close();
}
globalThis.hostRestoreReset = hostRestoreReset;

function hostRestoreEndpoint(prefix) {
  const host = $(prefix + "Host").value.trim().toLowerCase();
  const port = Number($(prefix + "Port").value);
  if (!host || host.length > 253 || !/^[a-z0-9.:-]+$/.test(host) ||
      !Number.isInteger(port) || port < 1 || port > 65535) throw new Error("INVALID_INPUT");
  return { host, port };
}
function hostRestoreLogin(prefix, pin) {
  const endpoint = hostRestoreEndpoint(prefix);
  if (!pin || pin.host !== endpoint.host || pin.port !== endpoint.port || !$(prefix + "Trust").checked)
    throw new Error("TARGET_CHANGED");
  const method = $(prefix + "Method").value;
  const username = $(prefix + "Username").value.trim();
  if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/.test(username)) throw new Error("INVALID_INPUT");
  const password = method === "password" ? $(prefix + "Password").value : "";
  const private_key = method === "private_key" ? $(prefix + "PrivateKey").value : "";
  const passphrase = method === "private_key" ? $(prefix + "Passphrase").value : "";
  if ((method === "password" && (!password || new TextEncoder().encode(password).length > 1024)) ||
      (method === "private_key" && (!private_key || new TextEncoder().encode(private_key).length > 65536 ||
        new TextEncoder().encode(passphrase).length > 1024))) throw new Error("INVALID_INPUT");
  return { ...endpoint, username, method, password, private_key, passphrase, fingerprint: pin.fingerprint };
}
function hostRestoreCredentials() {
  const selected = hostRestoreLogin("hostRestoreTarget", hostRestore.targetPin);
  if ($("hostRestoreUseJump").checked) {
    const jump = hostRestoreLogin("hostRestoreJump", hostRestore.jumpPin);
    if (!hostRestore.targetPin?.viaJump || hostRestore.targetPin.jumpFingerprint !== jump.fingerprint)
      throw new Error("TARGET_CHANGED");
    selected.host_key_blob = hostRestore.targetPin.host_key_blob;
    selected.jump = { ...jump, host_key_blob: hostRestore.jumpPin.host_key_blob };
  } else if (hostRestore.targetPin?.viaJump) throw new Error("TARGET_CHANGED");
  return selected;
}
function hostRestoreSameRoute(active, login) {
  if (!active) return true;
  const equal = (left, right) => ["host", "port", "username", "fingerprint"].every((key) => left[key] === right[key]);
  return equal(active.route, login) && Boolean(active.route.jump) === Boolean(login.jump) &&
    (!login.jump || equal(active.route.jump, login.jump));
}
function hostRestorePinChanged(prefix) {
  if (prefix === "hostRestoreJump") hostRestore.jumpPin = null;
  hostRestore.targetPin = null;
  $("hostRestoreTargetTrust").checked = false;
  if (prefix === "hostRestoreJump") $("hostRestoreJumpTrust").checked = false;
  for (const selected of prefix === "hostRestoreJump" ? [prefix, "hostRestoreTarget"] : [prefix])
    for (const field of ["Password", "PrivateKey", "Passphrase", "KeyFile"]) $(selected + field).value = "";
  hostRestoreRender();
}
async function hostRestoreProbe(prefix) {
  const context = hostRestoreContext();
  if (hostRestore.busy || !hostRestoreCurrent(context)) return;
  hostRestore.busy = true; hostRestoreRender(); hostRestoreShowError("STALE_REQUEST");
  try {
    const endpoint = hostRestoreEndpoint(prefix);
    const payload = { ...endpoint };
    if (prefix === "hostRestoreTarget" && $("hostRestoreUseJump").checked)
      payload.jump = hostRestoreLogin("hostRestoreJump", hostRestore.jumpPin);
    const reply = await request("/api/v1/browser-ssh/target-host-key", { method: "POST",
      body: JSON.stringify(payload), timeoutMs: 45000 });
    if (!hostRestoreCurrent(context)) return;
    const current = hostRestoreEndpoint(prefix);
    if (current.host !== endpoint.host || current.port !== endpoint.port) return;
    if (reply.scope !== "entered_target" || reply.host !== endpoint.host ||
        typeof reply.fingerprint !== "string" || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(reply.fingerprint) ||
        typeof reply.host_key_blob !== "string") throw new Error("INVALID_RESPONSE");
    const pin = { ...endpoint, fingerprint: reply.fingerprint, host_key_blob: reply.host_key_blob,
      viaJump: Boolean(payload.jump), ...(payload.jump ? { jumpFingerprint: payload.jump.fingerprint } : {}) };
    if (payload.jump && reply.jump_host_key_fingerprint !== payload.jump.fingerprint) throw new Error("TARGET_CHANGED");
    if (prefix === "hostRestoreJump") hostRestore.jumpPin = pin; else hostRestore.targetPin = pin;
    $(prefix + "Fingerprint").textContent = `${endpoint.host}:${endpoint.port} · ${pin.fingerprint}`;
    $(prefix + "Trust").checked = false;
  } catch (error) { if (hostRestoreCurrent(context)) hostRestoreShowError(error); }
  finally { if (hostRestoreCurrent(context)) { hostRestore.busy = false; hostRestoreRender(); } }
}

function hostRestoreFillRoute(operation) {
  const target = operation.route;
  for (const [prefix, value] of [["hostRestoreTarget", target], ["hostRestoreJump", target.jump]]) {
    if (!value) continue;
    $(prefix + "Host").value = value.host; $(prefix + "Port").value = String(value.port);
    $(prefix + "Username").value = value.username;
    $(prefix + "Fingerprint").textContent = `Сохранённый отпечаток: ${value.fingerprint}. Получите ключ и сверьте его заново.`;
    $(prefix + "Trust").checked = false;
  }
  $("hostRestoreUseJump").checked = Boolean(target.jump);
  $("hostRestoreJumpFields").hidden = !target.jump;
  hostRestore.targetPin = hostRestore.jumpPin = null;
}
function hostRestoreRender() {
  const active = hostRestore.active, target = active?.target;
  $("hostRestoreSource").textContent = hostRestore.source ?
    `Источник: ${hostRestore.source.kind === "backup" ? "проверенная копия на Hub" : "импорт с устройства"} · ${active?.archive_id || hostRestore.upload?.archive_id || hostRestore.source.id}` :
    "Выберите пять файлов переносимой копии или откройте мастер у проверенной копии на Hub.";
  $("hostRestoreNativePick").hidden = typeof window.sovagridNativeRestore?.pickFiles !== "function";
  $("hostRestoreJumpFields").hidden = !$("hostRestoreUseJump").checked;
  for (const prefix of ["hostRestoreTarget", "hostRestoreJump"]) {
    const key = $(prefix + "Method").value === "private_key";
    $(prefix + "PasswordFields").hidden = key; $(prefix + "KeyFields").hidden = !key;
  }
  const busy = hostRestore.busy || active?.worker_active;
  let login = false; try { login = hostRestoreSameRoute(active, hostRestoreCredentials()); } catch {}
  $("hostRestorePrepare").disabled = !hostRestoreAllowed() || !hostRestore.source || busy || !login ||
    hostRestore.source.kind === "upload" && hostRestore.upload?.complete !== true ||
    Boolean(target && ["committed", "recovery_required", "rolled_back", "retry_required"].includes(target.phase));
  $("hostRestoreInspect").disabled = !active || hostRestore.busy || active.worker_active || !login;
  $("hostRestorePreview").disabled = !active || busy || !login || target?.registered !== true ||
    !["ready", "review"].includes(target.phase);
  $("hostRestoreHistory").disabled = Boolean(busy);
  $("hostRestoreOpenOperation").disabled = Boolean(busy);
  $("hostRestoreApply").disabled = !active || busy || !login || active.phase !== "review" ||
    !target?.apply_available || typeof target.apply_review_sha256 !== "string";
  $("hostRestoreRecover").disabled = !active || busy || !login ||
    [undefined, "receiving", "ready", "review", "committed", "rolled_back"].includes(target?.phase);
  $("hostRestoreRetry").disabled = !active || busy || !login || !target?.retry_available;
  $("hostRestoreImportDelete").disabled = hostRestore.busy || hostRestore.source?.kind !== "upload" || active?.worker_active;
  $("hostRestoreStatus").textContent = active ?
    `${HOST_RESTORE_PHASES[active.phase] || "Состояние получено"} · ${active.operation_id}` : "Подготовьте сервер, чтобы увидеть точный план.";
  const lines = [];
  if (active) {
    lines.push(`Цель: ${active.route.username}@${active.route.host}:${active.route.port}`);
    if (active.route.jump) lines.push(`Через: ${active.route.jump.host}:${active.route.jump.port}`);
    lines.push(active.progress || "");
    if (active.error) lines.push(hostRestoreError(active.error));
    if (target) {
      for (const [key, label] of [["target_free_bytes", "Свободно"], ["required_free_bytes", "Требуется"]])
        if (Number.isSafeInteger(target.preview?.[key])) lines.push(`${label}: ${bytes(target.preview[key])}`);
      for (const code of target.blockers || []) lines.push(HOST_RESTORE_BLOCKERS[code] || `Проверка: ${code}`);
      if (target.apply_available) lines.push("Ожидающие команды и подтверждения Telegram из копии будут отменены.",
        "VPN-конфигурация восстановится с выключенными интерфейсами. Публичный адрес автоматически не заменяется.",
        "После подтверждения на целевом сервере запустятся код и службы из выбранной доверенной копии.");
      if (target.worker_active) lines.push("Сервер выполняет операцию самостоятельно. Можно закрыть панель и проверить этот ID позже.");
      if (target.phase === "recovery_required") lines.push("Данные сохранены. Повторное применение закрыто; доступна отдельная проверка безопасного отката.");
    }
  }
  $("hostRestoreSummary").textContent = lines.filter(Boolean).join("\n");
}

async function hostRestoreHistory() {
  const context = hostRestoreContext();
  try {
    const value = await hostRestoreRequest("list", {}, context, { timeout: 15000 });
    hostRestore.history = value.operations;
    const select = $("hostRestoreHistory"); select.replaceChildren();
    const placeholder = document.createElement("option"); placeholder.value = ""; placeholder.textContent = "Новая операция"; select.append(placeholder);
    for (const item of value.operations) {
      const option = document.createElement("option"); option.value = item.operation_id;
      option.textContent = `${item.route.host} · ${HOST_RESTORE_PHASES[item.phase] || item.phase} · ${item.operation_id.slice(0, 10)}`;
      select.append(option);
    }
    const saved = hostRestoreMarker();
    if (!hostRestore.active && !hostRestore.source && value.operations.some((item) => item.operation_id === saved)) {
      select.value = saved; await hostRestoreSelect(saved);
    }
  } catch (error) { if (hostRestoreCurrent(context)) hostRestoreShowError(error); }
}
async function hostRestoreSelect(operation) {
  if (!operation || hostRestore.busy) return;
  hostRestoreInvalidateWork(); hostRestoreReleaseFiles();
  hostRestore.active = null; hostRestore.busy = true; hostRestoreRender();
  const context = hostRestoreContext();
  try {
    const value = await hostRestoreRequest("status", { operation_id: operation }, context, { timeout: 15000 });
    hostRestore.active = value; hostRestore.source = value.source; hostRestore.upload = null;
    if (value.source.kind === "upload") {
      try { hostRestore.upload = await hostRestoreRequest("import-status", { source_id: value.source.id }, context, { timeout: 15000 }); }
      catch (error) { if (!hostRestoreCurrent(context)) throw error; hostRestoreShowError(error); }
    }
    hostRestoreClearSecrets(); hostRestoreFillRoute(value); hostRestoreMarker(operation); hostRestoreRender();
    if (value.worker_active) hostRestoreSchedule();
  } catch (error) { if (hostRestoreCurrent(context)) hostRestoreShowError(error); }
  finally { if (hostRestoreCurrent(context)) { hostRestore.busy = false; hostRestoreRender(); } }
}
function hostRestoreSchedule() {
  clearTimeout(hostRestore.timer);
  hostRestore.timer = setTimeout(() => { void hostRestorePoll(); }, 2500);
}
async function hostRestorePoll() {
  if (!hostRestore.active || hostRestore.busy) { if (hostRestore.active) hostRestoreSchedule(); return; }
  const context = hostRestoreContext(); if (!hostRestoreCurrent(context)) return;
  try {
    const value = await hostRestoreRequest("status", { operation_id: hostRestore.active.operation_id }, context, { timeout: 15000 });
    hostRestore.active = value; hostRestoreRender();
    if (value.worker_active) hostRestoreSchedule();
    else if (value.target?.worker_active) {
      let login; try { login = hostRestoreCredentials(); } catch {}
      if (login) { await hostRestoreControl("inspect", false); if (hostRestore.active?.target?.worker_active) hostRestoreSchedule(); }
    }
  } catch (error) { if (hostRestoreCurrent(context)) { hostRestoreShowError(error); hostRestoreSchedule(); } }
}
async function hostRestorePrepare() {
  if (hostRestore.busy || !hostRestore.source) return;
  const context = hostRestoreContext(); let login;
  try { login = hostRestoreCredentials(); } catch (error) { hostRestoreShowError(error); return; }
  if (!confirm(`Подготовить ${login.username}@${login.host}:${login.port}?\nБудут доставлены проверенный исполнитель и выбранная копия. Недостающие зависимости Ubuntu установятся автоматически. Применение потребует отдельного подтверждения после проверки.`)) return;
  const operation = hostRestore.active?.operation_id || hostRestoreId(); hostRestoreMarker(operation);
  hostRestore.busy = true; hostRestoreRender();
  try {
    const result = await hostRestoreRequest("prepare", { ...login, operation_id: operation, source: hostRestore.source }, context);
    hostRestore.active = result; hostRestoreRender(); hostRestoreSchedule();
  } catch (error) {
    if (hostRestoreCurrent(context)) { hostRestoreShowError(error); hostRestore.busy = false; try { await hostRestoreSelect(operation); } catch {} }
  } finally { if (hostRestoreCurrent(context)) { hostRestore.busy = false; hostRestoreRender(); } }
}
async function hostRestoreControl(action, ask = true) {
  const active = hostRestore.active;
  if (!active || hostRestore.busy || active.worker_active) return;
  const context = hostRestoreContext(); let login;
  try { login = hostRestoreCredentials(); } catch (error) { hostRestoreShowError(error); return; }
  const prompts = { start: `Восстановить ${active.route.username}@${active.route.host}:${active.route.port}?\n${$("hostRestoreSummary").textContent}`,
    recover: "Проверить и завершить безопасный откат? Изменённые работающей системой данные сохранятся; неоднозначное состояние остановит автоматический откат.",
    retry: "Сохранить историю полностью отменённой попытки и подготовить новый план? Повторное применение снова потребует подтверждения." };
  if (ask && prompts[action] && !confirm(prompts[action])) return;
  const payload = { ...login, operation_id: active.operation_id };
  if (["start", "recover", "retry"].includes(action)) {
    Object.assign(payload, { expected_revision: active.expected_revision, confirm: true });
    if (action === "start") payload.apply_review_sha256 = active.target?.apply_review_sha256;
    if (action === "retry") payload.terminal_sha256 = active.target?.terminal_sha256;
  }
  hostRestore.busy = true; hostRestoreRender();
  try {
    hostRestore.active = await hostRestoreRequest(action, payload, context);
    hostRestoreRender();
    if (hostRestore.active.worker_active || hostRestore.active.target?.worker_active) hostRestoreSchedule();
  } catch (error) { if (hostRestoreCurrent(context)) { hostRestoreShowError(error); hostRestore.active = { ...active, phase: "uncertain", target: null }; } }
  finally { if (hostRestoreCurrent(context)) { hostRestore.busy = false; hostRestoreRender(); } }
}

async function hostRestoreHash(raw) {
  if (!crypto.subtle) throw new Error("INVALID_INPUT");
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", raw))].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
async function hostRestoreReadSmall(file, limit) {
  if (!file || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > limit) throw new Error("SOURCE_UNSUPPORTED");
  return new Uint8Array(await file.slice(0, file.size).arrayBuffer());
}
async function hostRestoreChooseFiles(selected) {
  const all = Array.from(selected || []);
  if (hostRestore.busy || !hostRestoreCurrent(hostRestoreContext())) {
    hostRestoreReleaseSelected(all);
    return;
  }
  const previous = { active: hostRestore.active, source: hostRestore.source || hostRestore.active?.source, upload: hostRestore.upload };
  hostRestoreInvalidateWork(); hostRestoreReleaseFiles();
  hostRestore.active = hostRestore.source = hostRestore.upload = null;
  hostRestoreShowError("STALE_REQUEST");
  const context = hostRestoreContext();
  if (all.length !== 5 || new Set(all.map((file) => file.name)).size !== 5) {
    hostRestoreReleaseSelected(all); hostRestoreShowError("SOURCE_INCOMPLETE"); return;
  }
  hostRestore.busy = true; hostRestoreRender();
  try {
    const receiptFile = all.find((file) => file.name === "receipt.json");
    const receiptRaw = await hostRestoreReadSmall(receiptFile, 8192);
    const receipt = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(receiptRaw));
    if (receipt.protocol !== "sovagrid-portable-host-receipt-v2" || !/^[0-9a-f]{32}$/.test(receipt.host_archive_id) ||
        !/^[0-9a-f]{64}$/.test(receipt.host_archive_sha256) || !/^[0-9a-f]{64}$/.test(receipt.images_sha256)) throw new Error("SOURCE_UNSUPPORTED");
    const archive = receipt.host_archive_id;
    const filenames = { host_manifest: `${archive}.manifest.json`, host: `${archive}.tar.gz`,
      images_manifest: "manifest.json", images: "images.tar", receipt: "receipt.json" };
    const files = Object.fromEntries(Object.entries(filenames).map(([part, name]) => [part, all.find((file) => file.name === name)]));
    const metadata = {};
    for (const part of Object.keys(HOST_RESTORE_PARTS)) {
      const file = files[part];
      if (!file || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > HOST_RESTORE_LIMITS[part]) throw new Error("SOURCE_UNSUPPORTED");
      const sha = part === "host" ? receipt.host_archive_sha256 : part === "images" ? receipt.images_sha256 :
        await hostRestoreHash(await hostRestoreReadSmall(file, HOST_RESTORE_LIMITS[part]));
      metadata[part] = { bytes: file.size, sha256: sha };
    }
    if (Object.values(metadata).reduce((total, item) => total + item.bytes, 0) > 16 * 1024 ** 3)
      throw new Error("SOURCE_UNSUPPORTED");
    if (!hostRestoreCurrent(context)) throw new Error("STALE_REQUEST");
    const saved = hostRestoreUploadMarker();
    const sourceId = previous.source?.kind === "upload" &&
      (previous.active?.archive_id === archive || previous.upload?.archive_id === archive) ? previous.source.id :
      saved?.archive_id === archive ? saved.source_id : hostRestoreId();
    const value = await hostRestoreRequest("import-init", { source_id: sourceId, archive_id: archive, artifacts: metadata }, context);
    hostRestoreUploadMarker({ source_id: sourceId, archive_id: archive });
    hostRestore.files = files; hostRestore.upload = value; hostRestore.source = { kind: "upload", id: sourceId };
    hostRestore.active = previous.active?.source?.kind === "upload" && previous.active.source.id === sourceId &&
      previous.active.archive_id === archive ? { ...previous.active, phase: "resume_required", target: null } : null;
    await hostRestoreUpload(context);
  } catch (error) {
    if (!hostRestore.files) hostRestoreReleaseSelected(all);
    if (hostRestoreCurrent(context)) hostRestoreShowError(error);
  } finally { if (hostRestoreCurrent(context)) { hostRestore.busy = false; hostRestoreRender(); } }
}
async function hostRestoreUpload(context) {
  for (const part of Object.keys(HOST_RESTORE_PARTS)) {
    while (!hostRestore.upload.artifacts[part].complete) {
      if (!hostRestoreCurrent(context)) throw new Error("STALE_REQUEST");
      const offset = hostRestore.upload.artifacts[part].received;
      const pending = hostRestore.upload.pending_chunk;
      const length = pending ? pending.length : Math.min(4 * 1024 ** 2, hostRestore.files[part].size - offset);
      if (pending && (pending.part !== part || pending.offset !== offset)) throw new Error("SOURCE_CHANGED");
      const raw = await hostRestore.files[part].slice(offset, offset + length).arrayBuffer();
      if (raw.byteLength !== length) throw new Error("SOURCE_CHANGED");
      const sha = await hostRestoreHash(raw);
      if (pending && pending.sha256 !== sha) throw new Error("SOURCE_CHANGED");
      $("hostRestoreStatus").textContent = `Загрузка ${HOST_RESTORE_PARTS[part]}: ${bytes(offset + length)} / ${bytes(hostRestore.files[part].size)}`;
      hostRestore.upload = await hostRestoreRequest("import-chunk", { source_id: hostRestore.upload.source_id,
        part, offset, length, sha256: sha }, context, { binary: raw });
    }
  }
  if (!hostRestore.upload.complete) throw new Error("SOURCE_INCOMPLETE");
  hostRestoreReleaseFiles();
}
async function hostRestoreImportDelete() {
  if (hostRestore.source?.kind !== "upload" || hostRestore.busy ||
      !confirm("Удалить импортированную копию с Hub? Для продолжения незавершённой передачи понадобится снова выбрать те же пять файлов. История операции и данные на целевом сервере сохранятся.")) return;
  const context = hostRestoreContext(); hostRestore.busy = true; hostRestoreRender();
  try {
    await hostRestoreRequest("import-delete", { source_id: hostRestore.source.id, confirm: true }, context);
    hostRestoreUploadMarker(null);
    hostRestore.source = hostRestore.upload = null; hostRestoreReleaseFiles();
  } catch (error) { if (hostRestoreCurrent(context)) hostRestoreShowError(error); }
  finally { if (hostRestoreCurrent(context)) { hostRestore.busy = false; hostRestoreRender(); } }
}
async function hostRestoreOpen(source = null) {
  if (!hostRestoreAllowed() || $("hostRestoreDialog").open) return;
  hostRestoreReset(); hostRestore.source = source; hostRestore.upload = hostRestore.active = null;
  hostRestore.openedView = state.view;
  $("hostRestoreDialog").showModal(); hostRestoreRender(); hostRestoreShowError("STALE_REQUEST");
  await hostRestoreHistory();
  const saved = hostRestoreUploadMarker();
  if (!hostRestore.source && saved) {
    const context = hostRestoreContext();
    try {
      hostRestore.upload = await hostRestoreRequest("import-status", { source_id: saved.source_id }, context, { timeout: 15000 });
      hostRestore.source = { kind: "upload", id: saved.source_id }; hostRestoreRender();
      if (!hostRestore.upload.complete) $("hostRestoreStatus").textContent = "Выберите те же пять файлов, чтобы продолжить прерванную загрузку.";
    } catch (error) { if (hostRestoreCurrent(context)) hostRestoreShowError(error); }
  }
}
globalThis.hostRestoreOpen = hostRestoreOpen;

$("hostRestoreOpenImport").addEventListener("click", () => { void hostRestoreOpen(); });
$("hostRestoreClose").addEventListener("click", hostRestoreReset);
$("hostRestoreDialog").addEventListener("close", () => {
  hostRestoreClearSecrets(); hostRestoreReleaseFiles();
  for (const controller of hostRestore.controllers) controller.abort();
  clearTimeout(hostRestore.timer); hostRestore.generation++;
});
$("hostRestoreHistory").addEventListener("change", (event) => {
  if (event.target.value) void hostRestoreSelect(event.target.value);
  else { hostRestoreInvalidateWork(); hostRestore.active = null; hostRestore.targetPin = hostRestore.jumpPin = null; hostRestoreClearSecrets(); hostRestoreRender(); }
});
$("hostRestoreOpenOperation").addEventListener("click", () => {
  const operation = $("hostRestoreOperationId").value.trim();
  if (/^[0-9a-f]{32}$/.test(operation)) void hostRestoreSelect(operation);
  else hostRestoreShowError("INVALID_INPUT");
});
$("hostRestoreFiles").addEventListener("change", (event) => { void hostRestoreChooseFiles(event.target.files); });
$("hostRestoreNativePick").addEventListener("click", async () => {
  const context = hostRestoreContext();
  try {
    const selected = await window.sovagridNativeRestore.pickFiles();
    if (!hostRestoreCurrent(context)) {
      hostRestoreReleaseSelected(selected || []);
      return;
    }
    await hostRestoreChooseFiles(selected);
  } catch (error) { if (hostRestoreCurrent(context)) hostRestoreShowError(error); }
});
window.addEventListener("sovagrid-native-restore-ready", hostRestoreRender);
$("hostRestorePrepare").addEventListener("click", () => { void hostRestorePrepare(); });
$("hostRestoreInspect").addEventListener("click", () => { void hostRestoreControl("inspect", false); });
$("hostRestorePreview").addEventListener("click", () => { void hostRestoreControl("preview", false); });
$("hostRestoreApply").addEventListener("click", () => { void hostRestoreControl("start"); });
$("hostRestoreRecover").addEventListener("click", () => { void hostRestoreControl("recover"); });
$("hostRestoreRetry").addEventListener("click", () => { void hostRestoreControl("retry"); });
$("hostRestoreImportDelete").addEventListener("click", () => { void hostRestoreImportDelete(); });
$("hostRestoreUseJump").addEventListener("change", () => { hostRestorePinChanged("hostRestoreJump"); hostRestoreRender(); });
for (const prefix of ["hostRestoreTarget", "hostRestoreJump"]) {
  $(prefix + "Probe").addEventListener("click", () => { void hostRestoreProbe(prefix); });
  for (const field of ["Host", "Port"]) $(prefix + field).addEventListener("input", () => hostRestorePinChanged(prefix));
  for (const field of ["Username", "Method", "Password", "PrivateKey", "Passphrase", "Trust"])
    $(prefix + field).addEventListener("input", hostRestoreRender);
  $(prefix + "Method").addEventListener("change", hostRestoreRender);
  $(prefix + "KeyFile").addEventListener("change", async (event) => {
    const context = hostRestoreContext();
    const read = Symbol(); hostRestore.keyReads.set(prefix, read);
    const username = $(prefix + "Username").value, method = $(prefix + "Method").value;
    let endpoint;
    try { endpoint = hostRestoreEndpoint(prefix); } catch { return; }
    let raw;
    try {
      raw = await hostRestoreReadSmall(event.target.files?.[0], 65536);
      const current = hostRestoreEndpoint(prefix);
      if (!hostRestoreCurrent(context) || hostRestore.keyReads.get(prefix) !== read ||
          current.host !== endpoint.host || current.port !== endpoint.port ||
          username !== $(prefix + "Username").value || method !== $(prefix + "Method").value) return;
      $(prefix + "PrivateKey").value = new TextDecoder("utf-8", { fatal: true }).decode(raw); hostRestoreRender();
    } catch (error) { if (hostRestoreCurrent(context)) hostRestoreShowError(error); }
    finally { raw?.fill(0); }
  });
}
window.addEventListener("pagehide", hostRestoreReset);
setInterval(() => {
  if ($("hostRestoreDialog").open && (!hostRestoreAllowed() || state.view !== hostRestore.openedView)) hostRestoreReset();
}, 500);

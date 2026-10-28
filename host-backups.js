/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// The Hub and Web containers stop during a host snapshot. Keep only its
// request ID in browser storage; the root journal is the source of truth.
const HOST_BACKUP_MARKER = "sovagrid.host-backup-request.v1:";
const HOST_BACKUP_ID = /^[0-9a-f]{32}$/;
const HOST_BACKUP_SHA = /^[0-9a-f]{64}$/;
const HOST_BACKUP_ERROR = /^[A-Z][A-Z0-9_]{1,63}$/;
const HOST_BACKUP_PHASES = Object.freeze({
  accepted: "Принято", stopping: "Останавливаем службы",
  archiving: "Создаём архив", restarting: "Запускаем службы",
  complete: "Копия создана", recovery_requested: "Исправление запрошено",
  recovered: "Службы восстановлены", failed: "Операция завершилась с ошибкой",
  recovery_required: "Нужно восстановить службы",
});
const HOST_BACKUP_FINAL = new Set(["complete", "recovered", "failed"]);
const hostBackupClient = {
  generation: 0, loading: false, checking: null, starting: false, recovering: false,
  plan: null, manifest: null, archives: [], operations: [], activeId: null,
  active: null, pending: null, pendingRecover: null, lastRefresh: 0,
  ready: false, uncertain: false,
};

function hostBackupCurrent(generation, token, base) {
  return hostBackupClient.generation === generation && state.token === token &&
    state.base === base && Boolean(token) && hubCanGlobalAdmin();
}

function hostBackupMarkerKey() { return HOST_BACKUP_MARKER + state.base; }

function hostBackupReadMarker() {
  try {
    const value = JSON.parse(localStorage.getItem(hostBackupMarkerKey()) || "null");
    return value && Object.keys(value).length === 2 && value.base === state.base &&
      HOST_BACKUP_ID.test(value.request_id) ? value.request_id : null;
  } catch { return null; }
}

function hostBackupSaveMarker(requestId) {
  try {
    localStorage.setItem(hostBackupMarkerKey(),
      JSON.stringify({ base: state.base, request_id: requestId }));
    return hostBackupReadMarker() === requestId;
  } catch { return false; }
}

function hostBackupClearMarker(requestId) {
  try {
    if (hostBackupReadMarker() === requestId) localStorage.removeItem(hostBackupMarkerKey());
  } catch { /* The server record remains available without local storage. */ }
}

function hostBackupDate(value) {
  const stamp = Date.parse(value);
  if (typeof value !== "string" || value.length > 40 || !Number.isFinite(stamp) ||
      stamp < 0 || !/(?:Z|\+00:00)$/.test(value))
    throw new Error("Hub вернул неверную дату копии.");
  return new Date(stamp).toLocaleString("ru-RU", { timeZone: "UTC" }) + " UTC";
}

function hostBackupArchive(value, expectedId = null) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== 5 || !HOST_BACKUP_ID.test(value.id) ||
      (expectedId !== null && value.id !== expectedId) ||
      !["full", "hub-only"].includes(value.layout) ||
      !Number.isSafeInteger(value.bytes) || value.bytes < 1 ||
      value.bytes > 8 * 1024 ** 3 || !Number.isSafeInteger(value.files) ||
      value.files < 1 || value.files > 20000)
    throw new Error("Hub вернул неверное описание архива.");
  hostBackupDate(value.created_at);
  return value;
}

function hostBackupOperation(value, expectedId = null) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== 7 || value.ok !== true ||
      value.protocol !== "sovagrid-host-backup-operation-v1" ||
      !HOST_BACKUP_ID.test(value.request_id) ||
      (expectedId !== null && value.request_id !== expectedId) ||
      !Object.hasOwn(HOST_BACKUP_PHASES, value.phase) ||
      (value.archive !== null && !hostBackupArchive(value.archive)) ||
      (value.error !== null && (typeof value.error !== "string" ||
        !HOST_BACKUP_ERROR.test(value.error))))
    throw new Error("Hub вернул неверное состояние копирования хоста.");
  hostBackupDate(value.created_at);
  return value;
}

function hostBackupPlan(value) {
  const plan = value?.plan;
  if (!plan || typeof plan !== "object" || Array.isArray(plan) ||
      !["full", "hub-only"].includes(plan.layout) ||
      !Array.isArray(plan.active_units) || plan.active_units.length > 32 ||
      plan.active_units.some((unit) => typeof unit !== "string" ||
        !/^sovagrid-[A-Za-z0-9_.@-]{1,96}\.(?:service|socket|timer)$/.test(unit)) ||
      !Array.isArray(plan.running_containers) || plan.running_containers.length > 2 ||
      plan.running_containers.some((item) => !["hub", "web"].includes(item)) ||
      new Set(plan.running_containers).size !== plan.running_containers.length ||
      typeof plan.offline_ready !== "boolean" ||
      !HOST_BACKUP_SHA.test(value.manifest_sha256))
    throw new Error("Hub вернул неверный план копирования хоста.");
  return { plan, manifest: value.manifest_sha256 };
}

function hostBackupSetActive(record) {
  hostBackupClient.activeId = record.request_id;
  hostBackupClient.active = record;
  hostBackupClient.uncertain = false;
  if (HOST_BACKUP_FINAL.has(record.phase)) hostBackupClearMarker(record.request_id);
}

function hostBackupCanStart() {
  const client = hostBackupClient;
  return hubCanGlobalAdmin() && Boolean(state.token) && client.ready && client.plan &&
    client.manifest && !client.loading && !client.starting && !client.recovering &&
    !client.pending && !hostBackupReadMarker() &&
    !client.operations.some((item) => !HOST_BACKUP_FINAL.has(item.phase));
}

function hostBackupRender() {
  const client = hostBackupClient;
  const ready = hubCanGlobalAdmin() && Boolean(state.token);
  $("hostBackupReload").disabled = !ready || client.loading || client.starting || client.recovering;
  $("hostBackupCreate").disabled = !hostBackupCanStart();
  $("hostBackupCount").textContent = client.ready ? String(client.archives.length) : "—";
  $("hostBackupPlan").textContent = client.plan
    ? `${client.plan.layout === "full" ? "Полный узел" : "Только Hub"} · ${client.plan.active_units.length} служб · ${client.plan.running_containers.length} контейнера(ов). При создании архивируются настройки и данные этого узла.`
    : "План ещё не получен.";
  const active = $("hostBackupActive"); active.replaceChildren();
  active.hidden = !client.activeId;
  if (client.activeId) {
    const title = document.createElement("strong");
    title.textContent = client.active ? `${HOST_BACKUP_PHASES[client.active.phase]} · ${client.activeId}`
      : `Запрос ${client.activeId}: ожидаем подтверждение сервера`;
    const info = document.createElement("p");
    info.textContent = client.active
      ? [`Начало: ${hostBackupDate(client.active.created_at)}`,
        client.active.archive ? `Архив: ${client.active.archive.id} · ${bytes(client.active.archive.bytes)}` : null,
        client.active.error ? `Код: ${client.active.error}` : null].filter(Boolean).join(" · ")
      : "После восстановления связи проверьте этот ID. Не запускайте повторно копирование.";
    const actions = document.createElement("div"); actions.className = "backup-card-actions";
    const check = document.createElement("button"); check.type = "button";
    check.className = "secondary-button"; check.textContent = "Проверить состояние";
    check.disabled = !ready || Boolean(client.checking) || client.starting || client.recovering;
    check.addEventListener("click", () => { void hostBackupCheck(client.activeId); });
    actions.append(check);
    if (client.active && !HOST_BACKUP_FINAL.has(client.active.phase)) {
      const recover = document.createElement("button"); recover.type = "button";
      recover.className = "secondary-button"; recover.textContent = "Восстановить службы…";
      recover.disabled = !ready || Boolean(client.checking) || client.starting || client.recovering;
      recover.addEventListener("click", () => hostBackupPrepareRecover(client.activeId));
      actions.append(recover);
    }
    active.append(title, info, actions);
  }
  const archives = $("hostBackupArchives"); archives.replaceChildren();
  if (client.ready && !client.archives.length) {
    const empty = document.createElement("p"); empty.className = "no-incidents";
    empty.textContent = "Архивов хоста пока нет."; archives.append(empty);
  }
  for (const item of client.archives) {
    const card = document.createElement("article"); card.className = "backup-card";
    const content = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = `${hostBackupDate(item.created_at)} · ${item.layout === "full" ? "полный узел" : "Hub"}`;
    const info = document.createElement("p");
    info.textContent = `${bytes(item.bytes)} · ${item.files} файлов · ID ${item.id}`;
    const action = document.createElement("button"); action.type = "button";
    action.className = "secondary-button";
    action.textContent = client.checking === item.id ? "Проверяем…" : "Проверить целостность";
    action.disabled = !ready || Boolean(client.checking) || client.starting || client.recovering;
    action.addEventListener("click", () => { void hostBackupVerify(item.id); });
    content.append(title, info); card.append(content, action); archives.append(card);
  }
  const operations = $("hostBackupOperations"); operations.replaceChildren();
  for (const item of client.operations.slice(0, 20)) {
    const card = document.createElement("article"); card.className = "backup-card";
    const content = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = `${HOST_BACKUP_PHASES[item.phase]} · ${hostBackupDate(item.created_at)}`;
    const info = document.createElement("p");
    info.textContent = `Запрос ${item.request_id}${item.error ? " · код " + item.error : ""}`;
    const action = document.createElement("button"); action.type = "button";
    action.className = "secondary-button"; action.textContent = "Состояние";
    action.disabled = !ready || Boolean(client.checking) || client.starting || client.recovering;
    action.addEventListener("click", () => { void hostBackupCheck(item.request_id); });
    content.append(title, info); card.append(content, action); operations.append(card);
  }
}

function hostBackupsReset() {
  hostBackupClient.generation++;
  Object.assign(hostBackupClient, { loading: false, checking: null, starting: false,
    recovering: false, plan: null, manifest: null, archives: [], operations: [],
    activeId: null, active: null, pending: null, pendingRecover: null,
    lastRefresh: 0, ready: false, uncertain: false });
  if ($("hostBackupCreateDialog").open) $("hostBackupCreateDialog").close();
  if ($("hostBackupRecoverDialog").open) $("hostBackupRecoverDialog").close();
  $("hostBackupStatus").textContent = "Откройте настройки, чтобы проверить копии хоста.";
  clearError($("hostBackupError"));
  hostBackupRender();
}
globalThis.hostBackupsReset = hostBackupsReset;

async function hostBackupsRefresh(force = false) {
  if (!state.token || !hubCanGlobalAdmin() || hostBackupClient.loading ||
      hostBackupClient.starting || hostBackupClient.recovering) return;
  const client = hostBackupClient;
  const interval = hostBackupReadMarker() || client.operations.some((item) =>
    !HOST_BACKUP_FINAL.has(item.phase)) ? 15000 : 45000;
  if (!force && Date.now() - client.lastRefresh < interval) return;
  const generation = client.generation, token = state.token, base = state.base;
  client.loading = true; client.lastRefresh = Date.now();
  const marker = hostBackupReadMarker();
  if (marker && !client.activeId) client.activeId = marker;
  hostBackupRender();
  const [planResult, archivesResult, operationsResult] = await Promise.allSettled([
    request("/api/v1/host-backups/plan", { timeoutMs: 20000 }),
    request("/api/v1/host-backups/archives", { timeoutMs: 20000 }),
    request("/api/v1/host-backups/operations", { timeoutMs: 20000 }),
  ]);
  if (!hostBackupCurrent(generation, token, base)) return;
  const errors = [];
  if (planResult.status === "fulfilled") {
    try {
      const parsed = hostBackupPlan(planResult.value);
      client.plan = parsed.plan; client.manifest = parsed.manifest;
    } catch (error) { client.plan = null; client.manifest = null; errors.push(error.message); }
  } else {
    client.plan = null; client.manifest = null;
    errors.push(planResult.reason?.status === 404 ? "Обновите Hub для копий хоста." :
      "План хоста недоступен.");
  }
  if (archivesResult.status === "fulfilled") {
    try {
      const items = archivesResult.value?.archives;
      if (!Array.isArray(items) || items.length > 100) throw new Error("Неверный список архивов.");
      const parsed = items.map((item) => hostBackupArchive(item));
      if (new Set(parsed.map((item) => item.id)).size !== parsed.length)
        throw new Error("Повторяющиеся архивы.");
      client.archives = parsed;
    } catch (error) { client.archives = []; errors.push(error.message); }
  } else { client.archives = []; errors.push("Список архивов недоступен."); }
  if (operationsResult.status === "fulfilled") {
    try {
      const items = operationsResult.value?.operations;
      if (!Array.isArray(items) || items.length > 100)
        throw new Error("Неверная история операций.");
      const parsed = items.map((item) => hostBackupOperation(item));
      if (new Set(parsed.map((item) => item.request_id)).size !== parsed.length)
        throw new Error("Повторяющиеся операции.");
      client.operations = parsed;
      const selected = parsed.find((item) => item.request_id === (marker || client.activeId));
      if (selected) hostBackupSetActive(selected);
    } catch (error) { client.operations = []; errors.push(error.message); }
  } else { client.operations = []; errors.push("История операций недоступна."); }
  client.ready = errors.length === 0;
  client.loading = false;
  if (marker && !client.operations.some((item) => item.request_id === marker)) {
    try {
      const record = hostBackupOperation(await request(
        `/api/v1/host-backups/operations/${marker}`, { timeoutMs: 20000 }), marker);
      if (!hostBackupCurrent(generation, token, base)) return;
      hostBackupSetActive(record);
    } catch {
      if (hostBackupCurrent(generation, token, base)) client.uncertain = true;
    }
  }
  if (!hostBackupCurrent(generation, token, base)) return;
  $("hostBackupStatus").textContent = client.uncertain
    ? `Запрос ${client.activeId || marker} сохранён. Hub мог перезапуститься; проверьте состояние после входа.`
    : `Архивов: ${client.archives.length}. Запросов: ${client.operations.length}.`;
  if (errors.length) showError($("hostBackupError"), errors.join(" "));
  else clearError($("hostBackupError"));
  hostBackupRender();
}
globalThis.hostBackupsRefresh = hostBackupsRefresh;

async function hostBackupCheck(requestId) {
  if (!HOST_BACKUP_ID.test(requestId) || !state.token || !hubCanGlobalAdmin() ||
      hostBackupClient.checking || hostBackupClient.starting || hostBackupClient.recovering) return;
  const client = hostBackupClient, generation = client.generation,
    token = state.token, base = state.base;
  client.activeId = requestId; client.checking = requestId; hostBackupRender();
  try {
    const record = hostBackupOperation(await request(
      `/api/v1/host-backups/operations/${requestId}`, { timeoutMs: 30000 }), requestId);
    if (!hostBackupCurrent(generation, token, base)) return;
    hostBackupSetActive(record);
    $("hostBackupStatus").textContent = `Запрос ${requestId}: ${HOST_BACKUP_PHASES[record.phase]}.`;
    clearError($("hostBackupError"));
  } catch {
    if (hostBackupCurrent(generation, token, base)) {
      client.uncertain = true;
      showError($("hostBackupError"), `Состояние запроса ${requestId} пока недоступно. Не запускайте повторное копирование. При остановленном Hub используйте Connect по SSH.`);
    }
  } finally {
    if (hostBackupCurrent(generation, token, base)) { client.checking = null; hostBackupRender(); }
  }
}

async function hostBackupVerify(archiveId) {
  if (!HOST_BACKUP_ID.test(archiveId) || !hostBackupClient.archives.some((item) =>
    item.id === archiveId) || !state.token || !hubCanGlobalAdmin() ||
      hostBackupClient.checking || hostBackupClient.starting || hostBackupClient.recovering) return;
  const client = hostBackupClient, generation = client.generation,
    token = state.token, base = state.base;
  client.checking = archiveId; hostBackupRender();
  $("hostBackupStatus").textContent = "Проверяем архив; это может занять несколько минут…";
  try {
    const result = await request(
      `/api/v1/host-backups/archives/${archiveId}/verify`, { timeoutMs: 360000 });
    if (!hostBackupCurrent(generation, token, base)) return;
    if (result?.verified !== true) throw new Error("Проверка архива не подтверждена.");
    const archive = hostBackupArchive(result.archive, archiveId);
    $("hostBackupStatus").textContent = `Архив ${archive.id} проверен: ${bytes(archive.bytes)}, ${archive.files} файлов.`;
    clearError($("hostBackupError"));
  } catch (error) {
    if (hostBackupCurrent(generation, token, base))
      showError($("hostBackupError"), error.message || "Архив не удалось проверить.");
  } finally {
    if (hostBackupCurrent(generation, token, base)) { client.checking = null; hostBackupRender(); }
  }
}

async function hostBackupPrepareCreate() {
  if (!hostBackupCanStart()) return;
  const client = hostBackupClient, generation = client.generation,
    token = state.token, base = state.base;
  client.loading = true; hostBackupRender();
  try {
    const fresh = hostBackupPlan(await request(
      "/api/v1/host-backups/plan", { timeoutMs: 20000 }));
    if (!hostBackupCurrent(generation, token, base)) return;
    if (fresh.manifest !== client.manifest || fresh.plan.layout !== client.plan.layout)
      throw new Error("Состояние хоста изменилось. Обновите план и подтвердите заново.");
    const requestId = crypto.randomUUID().replaceAll("-", "");
    if (!HOST_BACKUP_ID.test(requestId)) throw new Error("Не удалось создать ID запроса.");
    client.pending = { requestId, manifest: fresh.manifest, plan: fresh.plan,
      generation, token, base };
    $("hostBackupCreateSummary").textContent =
      `Режим: ${fresh.plan.layout === "full" ? "полный узел" : "только Hub"}\n` +
      `Активных служб: ${fresh.plan.active_units.length}; контейнеров: ${fresh.plan.running_containers.length}.\n` +
      `Службы и панель временно остановятся. ID запроса: ${requestId}.`;
    clearError($("hostBackupCreateError"));
    $("hostBackupCreateDialog").showModal();
  } catch (error) {
    if (hostBackupCurrent(generation, token, base))
      showError($("hostBackupError"), error.message || "Не удалось проверить план.");
  } finally {
    if (hostBackupCurrent(generation, token, base)) { client.loading = false; hostBackupRender(); }
  }
}

async function hostBackupConfirmCreate() {
  const client = hostBackupClient, pending = client.pending;
  if (!pending || !hostBackupCurrent(pending.generation, pending.token, pending.base) ||
      client.starting || client.recovering || hostBackupReadMarker() ||
      client.operations.some((item) => !HOST_BACKUP_FINAL.has(item.phase))) return;
  if (!hostBackupSaveMarker(pending.requestId)) {
    showError($("hostBackupCreateError"),
      "Браузер не сохранил ID запроса. Разрешите хранение данных для сайта или создайте копию через Connect.");
    return;
  }
  client.pending = null; $("hostBackupCreateDialog").close();
  client.starting = true; client.activeId = pending.requestId; client.active = null;
  client.uncertain = true; hostBackupRender();
  $("hostBackupStatus").textContent = "Создание копии запущено. Панель временно потеряет связь; ID запроса сохранён.";
  try {
    const record = hostBackupOperation(await request("/api/v1/host-backups/operations", {
      method: "POST", body: JSON.stringify({ request_id: pending.requestId,
        expected_manifest_sha256: pending.manifest }), timeoutMs: 30000,
    }), pending.requestId);
    if (!hostBackupCurrent(pending.generation, pending.token, pending.base)) return;
    hostBackupSetActive(record);
  } catch {
    if (hostBackupCurrent(pending.generation, pending.token, pending.base))
      showError($("hostBackupError"), `Ответ на запрос ${pending.requestId} потерян или отклонён. Не запускайте копирование повторно; проверьте сохранённый ID после восстановления связи.`);
  } finally {
    if (hostBackupCurrent(pending.generation, pending.token, pending.base)) {
      client.starting = false; hostBackupRender();
      void hostBackupsRefresh(true);
    }
  }
}

function hostBackupPrepareRecover(requestId) {
  const client = hostBackupClient, active = client.active;
  if (!active || active.request_id !== requestId || HOST_BACKUP_FINAL.has(active.phase) ||
      !state.token || !hubCanGlobalAdmin() || client.starting || client.recovering) return;
  client.pendingRecover = requestId;
  $("hostBackupRecoverSummary").textContent = `Запрос: ${requestId}\nСостояние: ${HOST_BACKUP_PHASES[active.phase]}.\nИсправление восстановит ранее запущенные службы и не создаст архив повторно.`;
  clearError($("hostBackupRecoverError"));
  $("hostBackupRecoverDialog").showModal();
}

async function hostBackupConfirmRecover() {
  const client = hostBackupClient, requestId = client.pendingRecover;
  if (!requestId || !HOST_BACKUP_ID.test(requestId) || !state.token ||
      !hubCanGlobalAdmin() || client.starting || client.recovering) return;
  if (!hostBackupSaveMarker(requestId)) {
    showError($("hostBackupRecoverError"), "Браузер не сохранил ID. Исправьте сбой через Connect по SSH.");
    return;
  }
  client.pendingRecover = null; $("hostBackupRecoverDialog").close();
  const generation = client.generation, token = state.token, base = state.base;
  client.recovering = true; client.uncertain = true; hostBackupRender();
  try {
    const record = hostBackupOperation(await request(
      `/api/v1/host-backups/operations/${requestId}/recover`,
      { method: "POST", body: "{}", timeoutMs: 30000 }), requestId);
    if (!hostBackupCurrent(generation, token, base)) return;
    hostBackupSetActive(record);
    $("hostBackupStatus").textContent = `Запрос ${requestId}: ${HOST_BACKUP_PHASES[record.phase]}.`;
  } catch {
    if (hostBackupCurrent(generation, token, base))
      showError($("hostBackupError"), `Ответ исправления по запросу ${requestId} потерян или отклонён. Проверьте статус; при остановленном Hub используйте Connect по SSH.`);
  } finally {
    if (hostBackupCurrent(generation, token, base)) {
      client.recovering = false; hostBackupRender(); void hostBackupsRefresh(true);
    }
  }
}

$("hostBackupReload").addEventListener("click", () => { void hostBackupsRefresh(true); });
$("hostBackupCreate").addEventListener("click", () => { void hostBackupPrepareCreate(); });
$("hostBackupCreateConfirm").addEventListener("click", () => { void hostBackupConfirmCreate(); });
$("hostBackupCreateCancel").addEventListener("click", () => $("hostBackupCreateDialog").close());
$("hostBackupCreateDialog").addEventListener("close", () => { hostBackupClient.pending = null; hostBackupRender(); });
$("hostBackupRecoverConfirm").addEventListener("click", () => { void hostBackupConfirmRecover(); });
$("hostBackupRecoverCancel").addEventListener("click", () => $("hostBackupRecoverDialog").close());
$("hostBackupRecoverDialog").addEventListener("close", () => { hostBackupClient.pendingRecover = null; });

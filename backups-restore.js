/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// Restoration runs in a root broker while the Hub container is stopped. A
// browser may lose the POST response and its login session. Only the request
// UUID is kept locally; all authoritative state remains in the host journal.
const RESTORE_MARKER = "sovagrid.restore-request.v1:";
const RESTORE_PHASES = Object.freeze({
  pending: "Ожидает запуска", stopping: "Останавливаем Hub",
  stopped: "Hub остановлен", planning: "Создаём страховочную копию",
  planned: "План готов", applying: "Восстанавливаем данные",
  applied: "Данные восстановлены", starting: "Запускаем Hub",
  started: "Проверяем Hub", finalizing: "Завершаем восстановление",
  complete: "Завершено", failed_recovered: "Прежние данные возвращены",
  recovery_required: "Требуется исправление",
});
const RESTORE_TERMINAL = new Set(["complete", "failed_recovered"]);
const RESTORE_ERROR = /^[A-Z][A-Z0-9_]{2,63}$/;
const restoresClient = { generation: 0, listKnown: false, records: [], visible: 20,
  loading: false, checking: null, submitting: false, recovering: false,
  activeRequestId: null, active: null, pending: null, pendingRecover: null,
  uncertain: false, absentChecks: 0, absentHistoryChecked: false, lastLoadedAt: 0 };

function restoresCurrent(generation, token, base) {
  return restoresClient.generation === generation && backupsCurrent(backupsClient.generation, token, base);
}

function restoreMarkerKey() { return RESTORE_MARKER + state.base; }

function restoreMarkerRead() {
  try {
    const value = JSON.parse(localStorage.getItem(restoreMarkerKey()) || "null");
    if (!value || Object.keys(value).length !== 3 ||
        value.base !== state.base || !BACKUP_UUID.test(value.request_id) ||
        !BACKUP_UUID.test(value.target_id)) return null;
    return value;
  } catch { return null; }
}

function restoreMarkerSave(requestId, targetId) {
  try {
    localStorage.setItem(restoreMarkerKey(), JSON.stringify({ base: state.base,
      request_id: requestId, target_id: targetId }));
    const saved = restoreMarkerRead();
    return saved?.request_id === requestId && saved?.target_id === targetId;
  } catch { return false; }
}

function restoreMarkerClear(requestId) {
  try {
    const marker = restoreMarkerRead();
    if (marker?.request_id === requestId) localStorage.removeItem(restoreMarkerKey());
  } catch { /* Browser storage may be unavailable. */ }
}

function restoreRecord(value, expectedId = null, expectedTarget = null) {
  const keys = ["ok", "protocol", "request_id", "target_id", "phase", "safety_id",
    "plan_id", "hub_running", "error", "created_at"];
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key)) ||
      typeof value.ok !== "boolean" || value.protocol !== 1 ||
      !BACKUP_UUID.test(value.request_id) || !BACKUP_UUID.test(value.target_id) ||
      (expectedId !== null && value.request_id !== expectedId) ||
      (expectedTarget !== null && value.target_id !== expectedTarget) ||
      !Object.hasOwn(RESTORE_PHASES, value.phase) || value.ok !== (value.phase === "complete") ||
      (value.safety_id !== null && !BACKUP_UUID.test(value.safety_id)) ||
      (value.plan_id !== null && !BACKUP_UUID.test(value.plan_id)) ||
      (value.hub_running !== null && typeof value.hub_running !== "boolean") ||
      (value.error !== null && (typeof value.error !== "string" || !RESTORE_ERROR.test(value.error))) ||
      (value.phase === "complete" ? value.error !== null : value.error === null) ||
      !Number.isSafeInteger(value.created_at) || value.created_at < 1 ||
      value.created_at > 253402300799) {
    throw new Error("Hub вернул неверное состояние восстановления.");
  }
  return value;
}

function restoreUtc(seconds) { return new Date(seconds * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC"; }

function restoreCanStart() {
  if (restoresClient.submitting || restoresClient.recovering || restoresClient.pending ||
      restoresClient.pendingRecover) return false;
  const marker = restoreMarkerRead();
  if (marker && (restoresClient.active?.request_id !== marker.request_id ||
      !RESTORE_TERMINAL.has(restoresClient.active.phase) ||
      restoresClient.active.hub_running !== true)) return false;
  if (!restoresClient.activeRequestId) return true;
  return Boolean(restoresClient.active && RESTORE_TERMINAL.has(restoresClient.active.phase) &&
    restoresClient.active.hub_running === true);
}
globalThis.backupsRestoreCanStart = restoreCanStart;

function restoreSetActive(record) {
  const marker = restoreMarkerRead();
  if (marker && marker.request_id === record.request_id && marker.target_id !== record.target_id)
    throw new Error("Сервер ответил о другой резервной копии. Проверьте его вручную.");
  restoresClient.activeRequestId = record.request_id;
  restoresClient.active = record;
  restoresClient.uncertain = false;
  restoresClient.absentChecks = 0;
  restoresClient.absentHistoryChecked = false;
  if (RESTORE_TERMINAL.has(record.phase) && record.hub_running === true)
    restoreMarkerClear(record.request_id);
  restoreRender();
}

function restoreRender() {
  const client = restoresClient;
  const ready = hubCanGlobalAdmin() && Boolean(state.token);
  $("backupsRestoresReload").disabled = !ready || client.loading || client.submitting || client.recovering;
  $("backupsRestoresMore").hidden = !client.listKnown || client.records.length <= client.visible;
  $("backupsRestoresMore").disabled = !ready || client.loading;
  const active = $("backupsRestoreActive"); active.replaceChildren();
  active.hidden = !client.activeRequestId;
  if (client.activeRequestId) {
    const title = document.createElement("strong");
    title.textContent = client.active ? `Запрос: ${client.active.request_id}` :
      `Ожидаем ответ по запросу: ${client.activeRequestId}`;
    active.append(title);
    const lines = document.createElement("p");
    const result = client.active;
    lines.textContent = result
      ? [`Состояние: ${RESTORE_PHASES[result.phase]}`,
        `Копия: ${result.target_id}`, `Начало: ${restoreUtc(result.created_at)}`,
        `Hub: ${result.hub_running === true ? "работает" : result.hub_running === false ? "остановлен" : "не подтверждено"}`,
        result.safety_id ? `Страховочная копия: ${result.safety_id}` : null,
        result.plan_id ? `План: ${result.plan_id}` : null,
        result.error ? `Код ошибки: ${result.error}` : null].filter(Boolean).join("\n")
      : "Проверьте сохранённый запрос после восстановления связи и входа в Hub.";
    active.append(lines);
    const actions = document.createElement("div"); actions.className = "backups-restore-actions";
    const check = document.createElement("button"); check.type = "button";
    check.className = "secondary-button"; check.textContent = client.checking === client.activeRequestId
      ? "Проверяем…" : "Проверить состояние";
    check.disabled = !ready || Boolean(client.checking) || client.submitting || client.recovering;
    check.addEventListener("click", () => { void backupsRestoreCheck(client.activeRequestId); });
    actions.append(check);
    const copy = document.createElement("button"); copy.type = "button";
    copy.className = "secondary-button"; copy.textContent = "Копировать UUID";
    copy.addEventListener("click", async () => {
      const copyId = client.activeRequestId;
      const generation = client.generation, token = state.token, base = state.base;
      try {
        await navigator.clipboard.writeText(copyId);
        if (restoresCurrent(generation, token, base) && client.activeRequestId === copyId)
          $("backupsRestoreStatus").textContent = "UUID запроса скопирован для проверки в SovaGrid Connect.";
      } catch {
        if (restoresCurrent(generation, token, base) && client.activeRequestId === copyId)
          showError($("backupsRestoreError"), "Не удалось скопировать UUID. Его можно выделить в карточке запроса.");
      }
    });
    actions.append(copy);
    if (result && !RESTORE_TERMINAL.has(result.phase) && result.hub_running !== false) {
      const recover = document.createElement("button"); recover.type = "button";
      recover.className = "secondary-button"; recover.textContent = "Исправить сбой…";
      recover.disabled = !ready || Boolean(client.checking) || client.submitting || client.recovering;
      recover.addEventListener("click", () => backupsPrepareRecover(result.request_id));
      actions.append(recover);
    }
    if (restoreMarkerRead()?.request_id === client.activeRequestId &&
        client.absentChecks >= 2 && client.absentHistoryChecked && client.listKnown &&
        !client.records.some((item) => item.request_id === client.activeRequestId)) {
      const forget = document.createElement("button"); forget.type = "button";
      forget.className = "secondary-button"; forget.textContent = "Убрать локальную запись…";
      forget.disabled = !ready || Boolean(client.checking) || client.submitting || client.recovering;
      forget.addEventListener("click", backupsPrepareForget);
      actions.append(forget);
    }
    active.append(actions);
    if (result?.hub_running === false || client.uncertain) {
      const note = document.createElement("p"); note.className = "field-help";
      note.textContent = "Если Hub не отвечает, откройте этот сервер через SovaGrid Connect по SSH и проверьте тот же UUID запроса.";
      active.append(note);
    }
  }
  const list = $("backupsRestoreList"); list.replaceChildren();
  if (!client.listKnown) { backupsRender(); return; }
  if (!client.records.length) {
    const empty = document.createElement("p"); empty.className = "no-incidents";
    empty.textContent = "Восстановлений пока нет."; list.append(empty);
  }
  for (const record of client.records.slice(0, client.visible)) {
    const card = document.createElement("article"); card.className = "backup-card";
    const content = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = `${RESTORE_PHASES[record.phase]} · ${restoreUtc(record.created_at)}`;
    const info = document.createElement("p");
    info.textContent = `Копия ${record.target_id.slice(0, 8)} · запрос ${record.request_id}`;
    content.append(title, info);
    const button = document.createElement("button"); button.type = "button";
    button.className = "secondary-button"; button.textContent = "Состояние";
    button.disabled = !ready || Boolean(client.checking) || client.submitting || client.recovering;
    button.addEventListener("click", () => { void backupsRestoreCheck(record.request_id); });
    card.append(content, button); list.append(card);
  }
  backupsRender();
}

function backupsRestoreReset() {
  restoresClient.generation++;
  Object.assign(restoresClient, { listKnown: false, records: [], visible: 20,
    loading: false, checking: null, submitting: false, recovering: false,
    activeRequestId: null, active: null, pending: null, pendingRecover: null,
    uncertain: false, absentChecks: 0, absentHistoryChecked: false, lastLoadedAt: 0 });
  if ($("backupsRestoreDialog").open) $("backupsRestoreDialog").close();
  if ($("backupsRecoverDialog").open) $("backupsRecoverDialog").close();
  if ($("backupsForgetDialog").open) $("backupsForgetDialog").close();
  $("backupsRestoreStatus").textContent = "История восстановлений хранится на сервере.";
  clearError($("backupsRestoreError"));
  clearError($("backupsRestoreDialogError"));
  clearError($("backupsRecoverDialogError"));
  restoreRender();
}
globalThis.backupsRestoreReset = backupsRestoreReset;

async function backupsRestoresRefresh() {
  if (!state.token || !hubCanGlobalAdmin() || restoresClient.loading || restoresClient.submitting ||
      restoresClient.recovering) return;
  const generation = restoresClient.generation, token = state.token, base = state.base;
  const marker = restoreMarkerRead();
  if (marker && !restoresClient.activeRequestId) restoresClient.activeRequestId = marker.request_id;
  restoresClient.loading = true; restoresClient.lastLoadedAt = Date.now(); restoreRender();
  let inspectRequest = null;
  try {
    const result = await request("/api/v1/backups/restores", { timeoutMs: 20000 });
    if (!restoresCurrent(generation, token, base)) return;
    const records = result?.restores;
    if (!result || Object.keys(result).length !== 1 || !Array.isArray(records) ||
        records.length > 100) throw new Error("Hub вернул неверную историю восстановлений.");
    const parsed = records.map((item) => restoreRecord(item));
    if (new Set(parsed.map((item) => item.request_id)).size !== parsed.length)
      throw new Error("Hub вернул повторяющиеся восстановления.");
    restoresClient.records = parsed; restoresClient.listKnown = true;
    if (marker && restoresClient.absentChecks > 0 &&
        !parsed.some((item) => item.request_id === marker.request_id))
      restoresClient.absentHistoryChecked = true;
    const current = parsed.find((item) => item.request_id === restoresClient.activeRequestId);
    if (current) restoreSetActive(current);
    if (marker) inspectRequest = marker.request_id;
    if (!restoresClient.uncertain) {
      $("backupsRestoreStatus").textContent = `Запросов в истории: ${parsed.length}. Выберите запрос для проверки.`;
      clearError($("backupsRestoreError"));
    }
  } catch (error) {
    if (!restoresCurrent(generation, token, base)) return;
    restoresClient.listKnown = false;
    showError($("backupsRestoreError"), error.status === 404
      ? "История восстановлений появится после обновления Hub."
      : "Не удалось прочитать историю. Если Hub не отвечает, используйте SovaGrid Connect по SSH.");
  } finally {
    if (restoresCurrent(generation, token, base)) {
      restoresClient.loading = false; restoreRender();
      if (inspectRequest) void backupsRestoreCheck(inspectRequest);
    }
  }
}
globalThis.backupsRestoresRefresh = backupsRestoresRefresh;

function backupsRestoresMaybeRefresh() {
  const interval = restoresClient.activeRequestId && !restoreCanStart() ? 10000 : 45000;
  if (Date.now() - restoresClient.lastLoadedAt >= interval) void backupsRestoresRefresh();
}
globalThis.backupsRestoresMaybeRefresh = backupsRestoresMaybeRefresh;

async function backupsRestoreCheck(requestId) {
  if (!BACKUP_UUID.test(requestId) || !state.token || !hubCanGlobalAdmin() ||
      restoresClient.checking || restoresClient.submitting || restoresClient.recovering) return;
  const generation = restoresClient.generation, token = state.token, base = state.base;
  if (restoresClient.activeRequestId !== requestId) {
    restoresClient.absentChecks = 0;
    restoresClient.absentHistoryChecked = false;
  }
  restoresClient.activeRequestId = requestId;
  restoresClient.checking = requestId;
  $("backupsRestoreStatus").textContent = "Проверяем сохранённый запрос на сервере…";
  restoreRender();
  try {
    const result = restoreRecord(await request(`/api/v1/backups/restores/${requestId}`,
      { timeoutMs: 30000 }), requestId);
    if (!restoresCurrent(generation, token, base)) return;
    restoreSetActive(result);
    $("backupsRestoreStatus").textContent = result.phase === "complete"
      ? "Hub запущен. Войдите заново, если сеанс был сброшен."
      : result.phase === "failed_recovered"
        ? "Прежние данные возвращены; проверьте состояние Hub."
        : "Восстановление не завершено. При остановленном Hub откройте SovaGrid Connect по SSH.";
    clearError($("backupsRestoreError"));
  } catch (error) {
    if (!restoresCurrent(generation, token, base)) return;
    restoresClient.uncertain = true;
    if (error.status === 404) restoresClient.absentChecks++;
    showError($("backupsRestoreError"), error.status === 404
      ? "Запрос пока не найден. Повторите проверку истории и состояния; не начинайте второе восстановление по одному ответу 404."
      : "Состояние пока недоступно. Не повторяйте восстановление. Если Hub остановлен, откройте его через SovaGrid Connect по SSH.");
  } finally {
    if (restoresCurrent(generation, token, base)) { restoresClient.checking = null; restoreRender(); }
  }
}
globalThis.backupsRestoreCheck = backupsRestoreCheck;

function backupsPrepareForget() {
  const id = restoresClient.activeRequestId;
  if (!id || restoreMarkerRead()?.request_id !== id || restoresClient.absentChecks < 2 ||
      !restoresClient.absentHistoryChecked ||
      !restoresClient.listKnown || restoresClient.records.some((item) => item.request_id === id) ||
      !state.token || !hubCanGlobalAdmin()) return;
  $("backupsForgetSummary").textContent = `Запрос ${id} не найден после повторной проверки состояния и истории.`;
  $("backupsForgetDialog").showModal();
}

function backupsConfirmForget() {
  const id = restoresClient.activeRequestId;
  if (!id || restoreMarkerRead()?.request_id !== id || restoresClient.absentChecks < 2 ||
      !restoresClient.absentHistoryChecked ||
      !restoresClient.listKnown || restoresClient.records.some((item) => item.request_id === id) ||
      !state.token || !hubCanGlobalAdmin()) return;
  restoreMarkerClear(id);
  restoresClient.activeRequestId = null; restoresClient.active = null;
  restoresClient.absentChecks = 0; restoresClient.absentHistoryChecked = false;
  restoresClient.uncertain = false;
  $("backupsForgetDialog").close();
  $("backupsRestoreStatus").textContent = "Локальная запись убрана. Серверный журнал не изменён; перед новым восстановлением снова проверьте копию.";
  clearError($("backupsRestoreError"));
  restoreRender();
}

async function backupsPrepareRestore(id) {
  if (!BACKUP_UUID.test(id) || !backupsClient.ids.includes(id) || !backupsClient.listKnown ||
      !state.token || !hubCanGlobalAdmin() || !restoreCanStart() ||
      backupsClient.checking || backupsClient.creating) return;
  const generation = restoresClient.generation, token = state.token, base = state.base;
  backupsClient.checking = id; backupsRender();
  $("backupsRestoreStatus").textContent = "Повторно проверяем копию перед подтверждением…";
  try {
    const detail = backupsDetail(await request(`/api/v1/backups/${id}`,
      { timeoutMs: 600000 }), id);
    if (!restoresCurrent(generation, token, base) || !backupsClient.ids.includes(id) ||
        !restoreCanStart()) return;
    backupsClient.details.set(id, detail);
    const requestId = crypto.randomUUID();
    if (!BACKUP_UUID.test(requestId)) throw new Error("Не удалось создать UUID запроса.");
    restoresClient.pending = { requestId, detail, generation, token, base };
    $("backupsRestoreSummary").textContent = `Копия: ${id}\nСоздана: ${restoreUtc(detail.created_at)}\nБаза: ${bytes(detail.database_bytes)}. Восстановленные сеансы и ожидающие команды будут сброшены.`;
    clearError($("backupsRestoreDialogError"));
    $("backupsRestoreDialog").showModal();
  } catch (error) {
    if (restoresCurrent(generation, token, base)) showError($("backupsRestoreError"),
      error.message || "Не удалось проверить копию перед восстановлением.");
  } finally {
    if (restoresCurrent(generation, token, base)) { backupsClient.checking = null; backupsRender(); }
  }
}
globalThis.backupsPrepareRestore = backupsPrepareRestore;

async function backupsConfirmRestore() {
  const pending = restoresClient.pending;
  if (!pending || !restoresCurrent(pending.generation, pending.token, pending.base) ||
      !backupsClient.ids.includes(pending.detail.id) || !backupsClient.listKnown ||
      restoresClient.submitting || restoresClient.recovering) return;
  if (!restoreMarkerSave(pending.requestId, pending.detail.id)) {
    showError($("backupsRestoreDialogError"),
      "Браузер не сохранил UUID запроса. Разрешите хранение данных для этого сайта или восстановите копию через SovaGrid Connect.");
    return;
  }
  restoresClient.pending = null;
  $("backupsRestoreDialog").close();
  restoresClient.submitting = true;
  restoresClient.activeRequestId = pending.requestId;
  restoresClient.active = null;
  restoresClient.uncertain = true;
  $("backupsRestoreStatus").textContent = "Hub может перезапуститься и разорвать соединение. UUID запроса сохранён на этом устройстве.";
  restoreRender();
  try {
    const result = restoreRecord(await request("/api/v1/backups/restore", {
      method: "POST", body: JSON.stringify({ backup_id: pending.detail.id,
        request_id: pending.requestId }), timeoutMs: 1800000,
    }), pending.requestId, pending.detail.id);
    if (!restoresCurrent(pending.generation, pending.token, pending.base)) return;
    restoreSetActive(result);
    $("backupsRestoreStatus").textContent = result.phase === "complete"
      ? "Hub запущен. Войдите в панель заново, если сеанс был сброшен."
      : "Сервер сохранил состояние запроса. Проверьте его после восстановления связи.";
  } catch (error) {
    if (!restoresCurrent(pending.generation, pending.token, pending.base)) return;
    restoresClient.uncertain = true;
    showError($("backupsRestoreError"),
      `Ответ восстановления потерян или отклонён. Запрос ${pending.requestId} сохранён. Не повторяйте действие; проверьте состояние после нового входа. Если Hub остановлен, используйте SovaGrid Connect по SSH.`);
  } finally {
    if (restoresCurrent(pending.generation, pending.token, pending.base)) {
      restoresClient.submitting = false; restoreRender();
      void backupsRestoresRefresh();
    }
  }
}

function backupsPrepareRecover(requestId) {
  const result = restoresClient.active;
  if (!result || result.request_id !== requestId || RESTORE_TERMINAL.has(result.phase) ||
      result.hub_running === false || !state.token || !hubCanGlobalAdmin() ||
      restoresClient.submitting || restoresClient.recovering) return;
  restoresClient.pendingRecover = requestId;
  $("backupsRecoverSummary").textContent = `Запрос: ${requestId}\nКопия: ${result.target_id}\nСостояние: ${RESTORE_PHASES[result.phase]}.`;
  clearError($("backupsRecoverDialogError"));
  $("backupsRecoverDialog").showModal();
}

async function backupsConfirmRecover() {
  const requestId = restoresClient.pendingRecover;
  if (!requestId || !BACKUP_UUID.test(requestId) || !state.token || !hubCanGlobalAdmin() ||
      restoresClient.submitting || restoresClient.recovering) return;
  const targetId = restoresClient.active?.request_id === requestId
    ? restoresClient.active.target_id : null;
  if (!targetId || !restoreMarkerSave(requestId, targetId)) {
    showError($("backupsRecoverDialogError"),
      "Браузер не сохранил UUID запроса. Разрешите хранение данных для этого сайта или исправьте сбой через SovaGrid Connect.");
    return;
  }
  restoresClient.pendingRecover = null;
  $("backupsRecoverDialog").close();
  const generation = restoresClient.generation, token = state.token, base = state.base;
  restoresClient.recovering = true; restoresClient.uncertain = true;
  restoreRender();
  try {
    const result = restoreRecord(await request(`/api/v1/backups/restores/${requestId}/recover`, {
      method: "POST", body: "{}", timeoutMs: 1800000,
    }), requestId);
    if (!restoresCurrent(generation, token, base)) return;
    restoreSetActive(result);
    $("backupsRestoreStatus").textContent = result.phase === "complete"
      ? "Hub запущен. Войдите в панель заново, если сеанс был сброшен."
      : "Исправление завершилось с сохранённым состоянием; проверьте запрос.";
  } catch (error) {
    if (!restoresCurrent(generation, token, base)) return;
    restoresClient.uncertain = true;
    showError($("backupsRestoreError"),
      `Ответ исправления по запросу ${requestId} потерян или отклонён. Не повторяйте действие; проверьте состояние. Если Hub остановлен, используйте SovaGrid Connect по SSH.`);
  } finally {
    if (restoresCurrent(generation, token, base)) { restoresClient.recovering = false; restoreRender(); }
  }
}

$("backupsRestoresReload").addEventListener("click", () => { void backupsRestoresRefresh(); });
$("backupsRestoresMore").addEventListener("click", () => {
  restoresClient.visible = Math.min(restoresClient.visible + 20, restoresClient.records.length);
  restoreRender();
});
$("backupsRestoreCancel").addEventListener("click", () => $("backupsRestoreDialog").close());
$("backupsRestoreConfirm").addEventListener("click", () => { void backupsConfirmRestore(); });
$("backupsRestoreDialog").addEventListener("close", () => { restoresClient.pending = null; restoreRender(); });
$("backupsRecoverCancel").addEventListener("click", () => $("backupsRecoverDialog").close());
$("backupsRecoverConfirm").addEventListener("click", () => { void backupsConfirmRecover(); });
$("backupsRecoverDialog").addEventListener("close", () => { restoresClient.pendingRecover = null; restoreRender(); });
$("backupsForgetCancel").addEventListener("click", () => $("backupsForgetDialog").close());
$("backupsForgetConfirm").addEventListener("click", backupsConfirmForget);

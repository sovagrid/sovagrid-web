/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

const maintenanceClient = { generation: 0, refreshSeq: 0, serverId: null,
  windows: null, busy: false, loading: false, pending: null };
const MAINTENANCE_DURATIONS = { 1800: "30 минут", 7200: "2 часа", 86400: "1 день" };

function maintenanceServer() {
  return state.servers.find((server) => String(server.id) === String(state.selectedId)) || null;
}

function maintenanceCurrent(generation, token, base, serverId) {
  return maintenanceClient.generation === generation && state.token === token &&
    state.base === base && Boolean(token) && String(state.selectedId) === String(serverId) &&
    String(maintenanceClient.serverId) === String(serverId);
}

function maintenanceActive() {
  if (maintenanceClient.windows) {
    return maintenanceClient.windows.find((window) => window.status === "active") || null;
  }
  return maintenanceServer()?.maintenance || null;
}

function maintenanceDate(seconds) {
  const date = new Date(seconds * 1000);
  return new Intl.DateTimeFormat("ru", { day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit" }).format(date);
}

function maintenanceSelectedServer(serverId) {
  if (String(maintenanceClient.serverId) === String(serverId)) return;
  maintenanceClient.generation++;
  maintenanceClient.refreshSeq++;
  maintenanceClient.serverId = serverId;
  maintenanceClient.windows = null;
  maintenanceClient.busy = false;
  maintenanceClient.loading = false;
  maintenanceClient.pending = null;
  if ($("maintenanceConfirmDialog").open) $("maintenanceConfirmDialog").close();
  $("maintenanceReason").value = "";
  clearError($("maintenanceError"));
  clearError($("maintenanceConfirmError"));
  $("maintenanceMessage").textContent = "";
  $("maintenanceMessage").hidden = true;
  maintenanceRender();
}
globalThis.maintenanceSelectedServer = maintenanceSelectedServer;

function maintenanceReset() {
  maintenanceSelectedServer(null);
  maintenanceClient.generation++;
  maintenanceClient.refreshSeq++;
  maintenanceClient.windows = null;
  maintenanceClient.pending = null;
  maintenanceClient.busy = false;
  maintenanceClient.loading = false;
  if ($("maintenanceConfirmDialog").open) $("maintenanceConfirmDialog").close();
  $("maintenanceReason").value = "";
  clearError($("maintenanceError"));
  clearError($("maintenanceConfirmError"));
  $("maintenanceMessage").textContent = "";
  $("maintenanceMessage").hidden = true;
  maintenanceRender();
}
globalThis.maintenanceReset = maintenanceReset;

function maintenanceHistoryRender() {
  const list = $("maintenanceHistory");
  list.replaceChildren();
  if (!maintenanceClient.windows) {
    const item = document.createElement("p");
    item.className = "field-help";
    item.textContent = maintenanceClient.loading ? "Загружаем историю…" : "История пока недоступна.";
    list.append(item);
    return;
  }
  if (!maintenanceClient.windows.length) {
    const item = document.createElement("p");
    item.className = "field-help";
    item.textContent = "Окон обслуживания ещё не было.";
    list.append(item);
    return;
  }
  for (const window of maintenanceClient.windows.slice(0, 8)) {
    const row = document.createElement("div");
    row.className = "maintenance-history-row";
    const heading = document.createElement("strong");
    heading.textContent = window.status === "active" ? "Идёт сейчас" :
      window.status === "cancelled" ? "Завершено досрочно" : "Завершено";
    const dates = document.createElement("span");
    dates.textContent = `${maintenanceDate(window.starts_at)} — ${maintenanceDate(window.ends_at)}`;
    const reason = document.createElement("p");
    reason.textContent = window.reason;
    row.append(heading, dates, reason);
    list.append(row);
  }
}

function maintenanceRender(server = maintenanceServer()) {
  const active = maintenanceActive();
  const readOnly = globalThis.hubCanAdmin?.() === false;
  $("maintenanceBadge").textContent = active ? "Уведомления на паузе" : "Не активно";
  $("maintenanceBadge").className = `status-badge ${active ? "waiting" : ""}`.trim();
  $("maintenanceActive").hidden = !active;
  $("maintenanceForm").hidden = readOnly || Boolean(active);
  $("maintenanceActiveUntil").textContent = active ? `До ${maintenanceDate(active.ends_at)}` : "";
  $("maintenanceActiveReason").textContent = active?.reason || "";
  $("maintenanceActiveId").textContent = active ? `ID окна: ${active.id}` : "";
  $("maintenanceStart").disabled = readOnly || maintenanceClient.busy || maintenanceClient.windows === null || !server || Boolean(active);
  $("maintenanceEnd").disabled = readOnly || maintenanceClient.busy || maintenanceClient.windows === null || !active;
  $("maintenanceStart").textContent = maintenanceClient.busy ? "Выполняем…" : "Начать обслуживание";
  $("maintenanceEnd").textContent = maintenanceClient.busy ? "Выполняем…" : "Завершить досрочно";
  maintenanceHistoryRender();
}
globalThis.maintenanceRender = maintenanceRender;

function maintenanceValidateWindow(window, serverId) {
  if (!window || typeof window !== "object" || typeof window.id !== "string" || !window.id ||
      String(window.server_id) !== String(serverId) || !Number.isSafeInteger(window.starts_at) ||
      !Number.isSafeInteger(window.ends_at) || window.ends_at <= window.starts_at ||
      typeof window.reason !== "string" || !["active", "ended", "cancelled"].includes(window.status)) {
    throw new Error("Центр мониторинга вернул неверное окно обслуживания.");
  }
  return window;
}

async function maintenanceRefresh() {
  if (!state.token || state.selectedId === null || maintenanceClient.busy) return;
  maintenanceSelectedServer(state.selectedId);
  const generation = maintenanceClient.generation, token = state.token, base = state.base;
  const serverId = maintenanceClient.serverId, seq = ++maintenanceClient.refreshSeq;
  maintenanceClient.loading = true;
  maintenanceRender();
  try {
    const payload = await request(`/api/v1/servers/${encodeURIComponent(serverId)}/maintenance`);
    if (!maintenanceCurrent(generation, token, base, serverId) || seq !== maintenanceClient.refreshSeq) return;
    if (String(payload?.server_id) !== String(serverId) || !Array.isArray(payload.windows))
      throw new Error("Центр мониторинга вернул неверную историю обслуживания.");
    maintenanceClient.windows = payload.windows.map((window) => maintenanceValidateWindow(window, serverId));
    clearError($("maintenanceError"));
  } catch (error) {
    if (maintenanceCurrent(generation, token, base, serverId) && seq === maintenanceClient.refreshSeq)
      showError($("maintenanceError"), error.message || "Не удалось загрузить окна обслуживания.");
  } finally {
    if (maintenanceCurrent(generation, token, base, serverId) && seq === maintenanceClient.refreshSeq) {
      maintenanceClient.loading = false;
      maintenanceRender();
    }
  }
}
globalThis.maintenanceRefresh = maintenanceRefresh;

function maintenanceReason() {
  const reason = $("maintenanceReason").value.trim();
  if (!reason || [...reason].length > 200 || [...reason].some((character) =>
      character !== " " && /[\p{C}\p{Z}]/u.test(character)) ||
      new TextEncoder().encode(reason).length > 512) {
    throw new Error("Введите причину без переносов строки: от 1 до 200 символов.");
  }
  return reason;
}

function maintenanceOpen(pending) {
  if (globalThis.hubCanAdmin?.() === false) return;
  maintenanceClient.pending = pending;
  clearError($("maintenanceConfirmError"));
  $("maintenanceConfirmHeading").textContent = pending.action === "start"
    ? "Начать обслуживание?" : "Завершить обслуживание?";
  $("maintenanceConfirmServer").textContent = `Сервер: ${pending.serverName} · ID: ${pending.serverId}`;
  $("maintenanceConfirmSummary").textContent = pending.action === "start"
    ? `Срок: ${MAINTENANCE_DURATIONS[pending.duration]}, до ${maintenanceDate(pending.endsAt)}. Причина: ${pending.reason}`
    : `Активное окно до ${maintenanceDate(pending.endsAt)}. Причина: ${pending.reason}`;
  $("maintenanceConfirmWindow").textContent = pending.action === "end" ? `ID окна: ${pending.windowId}` : "";
  $("maintenanceConfirm").textContent = pending.action === "start" ? "Начать обслуживание" : "Завершить окно";
  $("maintenanceConfirmDialog").showModal();
}

function maintenancePrepareStart(event) {
  event.preventDefault();
  if (!state.token || maintenanceClient.busy || maintenanceClient.windows === null) return;
  clearError($("maintenanceError"));
  const server = maintenanceServer();
  if (!server || maintenanceActive()) {
    showError($("maintenanceError"), "Выберите сервер без активного окна обслуживания."); return;
  }
  let reason;
  try { reason = maintenanceReason(); }
  catch (error) { showError($("maintenanceError"), error.message); return; }
  const duration = Number($("maintenanceDuration").value);
  if (!Object.hasOwn(MAINTENANCE_DURATIONS, duration)) {
    showError($("maintenanceError"), "Выберите длительность 30 минут, 2 часа или 1 день."); return;
  }
  maintenanceOpen({ action: "start", serverId: String(server.id), serverName: String(server.name || `Сервер ${server.id}`),
    duration, reason, endsAt: Math.floor(Date.now() / 1000) + duration,
    generation: maintenanceClient.generation, token: state.token, base: state.base });
}

function maintenancePrepareEnd() {
  if (!state.token || maintenanceClient.busy || maintenanceClient.windows === null) return;
  clearError($("maintenanceError"));
  const server = maintenanceServer(), active = maintenanceActive();
  if (!server || !active) {
    showError($("maintenanceError"), "Активное окно уже завершено. Обновите страницу."); return;
  }
  maintenanceOpen({ action: "end", serverId: String(server.id), serverName: String(server.name || `Сервер ${server.id}`),
    windowId: active.id, reason: active.reason, endsAt: active.ends_at,
    generation: maintenanceClient.generation, token: state.token, base: state.base });
}

function maintenanceCancel() {
  if (maintenanceClient.busy) return;
  maintenanceClient.pending = null;
  if ($("maintenanceConfirmDialog").open) $("maintenanceConfirmDialog").close();
}

async function maintenanceConfirm() {
  if (globalThis.hubCanAdmin?.() === false) return;
  const pending = maintenanceClient.pending;
  if (!pending || maintenanceClient.busy) return;
  const current = () => maintenanceCurrent(pending.generation, pending.token, pending.base, pending.serverId);
  const server = maintenanceServer(), active = maintenanceActive();
  if (!current() || !server || String(server.name || `Сервер ${server.id}`) !== pending.serverName ||
      (pending.action === "start" ? Boolean(active) : active?.id !== pending.windowId)) {
    showError($("maintenanceConfirmError"), "Сервер или окно изменились. Закройте подтверждение и проверьте состояние снова.");
    return;
  }
  if (pending.action === "start" && pending.endsAt - Math.floor(Date.now() / 1000) < 60) {
    showError($("maintenanceConfirmError"), "Время подтверждения истекло. Закройте окно и выберите срок снова.");
    return;
  }
  maintenanceClient.busy = true;
  // Invalidate a GET started before the mutation so it cannot overwrite the
  // confirmed response with an older window list.
  maintenanceClient.refreshSeq++;
  maintenanceClient.loading = false;
  $("maintenanceConfirm").disabled = true;
  $("maintenanceCancel").disabled = true;
  maintenanceRender();
  let succeeded = false;
  try {
    const path = `/api/v1/servers/${encodeURIComponent(pending.serverId)}/maintenance`;
    const payload = await request(pending.action === "start" ? path : `${path}/${encodeURIComponent(pending.windowId)}`,
      pending.action === "start" ? { method: "POST", body: JSON.stringify({ ends_at: pending.endsAt, reason: pending.reason }) }
        : { method: "DELETE" });
    if (!current()) return;
    const window = maintenanceValidateWindow(payload?.window, pending.serverId);
    if (pending.action === "start" ? window.status !== "active" || window.ends_at !== pending.endsAt ||
        window.reason !== pending.reason : window.id !== pending.windowId || window.status !== "cancelled") {
      throw new Error("Центр мониторинга вернул неполный ответ. Проверьте историю обслуживания.");
    }
    maintenanceClient.windows = [window, ...(maintenanceClient.windows || []).filter((item) => item.id !== window.id)];
    maintenanceClient.pending = null;
    $("maintenanceConfirmDialog").close();
    $("maintenanceReason").value = "";
    clearError($("maintenanceError"));
    $("maintenanceMessage").textContent = pending.action === "start"
      ? "Окно обслуживания началось. Инциденты остаются видимыми."
      : "Окно завершено. Уведомления по действующим инцидентам возобновятся.";
    $("maintenanceMessage").hidden = false;
    succeeded = true;
  } catch (error) {
    if (current()) {
      const message = error.status === 409
        ? "Окно изменилось в другой вкладке. Проверьте состояние и подтвердите действие заново."
        : error.status === 400
          ? "Центр мониторинга отклонил срок или причину. Проверьте часы устройства и попробуйте снова."
        : error.message || "Не удалось изменить окно обслуживания.";
      showError($("maintenanceConfirmError"), message);
      showError($("maintenanceError"), message);
    }
  } finally {
    if (current()) {
      maintenanceClient.busy = false;
      $("maintenanceConfirm").disabled = false;
      $("maintenanceCancel").disabled = false;
      maintenanceRender();
      // A failed response may hide an action that actually succeeded. A fresh
      // GET also resolves another administrator's 409 without a blind retry.
      void refresh();
    }
  }
  return succeeded;
}

$("maintenanceForm").addEventListener("submit", maintenancePrepareStart);
$("maintenanceEnd").addEventListener("click", maintenancePrepareEnd);
$("maintenanceCancel").addEventListener("click", maintenanceCancel);
$("maintenanceConfirm").addEventListener("click", maintenanceConfirm);
$("maintenanceConfirmDialog").addEventListener("cancel", (event) => {
  if (maintenanceClient.busy) event.preventDefault();
  else maintenanceClient.pending = null;
});
$("maintenanceConfirmDialog").addEventListener("close", () => {
  if (!maintenanceClient.busy) maintenanceClient.pending = null;
});

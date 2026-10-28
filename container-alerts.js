/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

const containerAlerts = { generation: 0, seq: 0, serverId: null, data: null,
  busy: false, loading: false, pending: null };
const CONTAINER_ALERT_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$/;
const CONTAINER_ALERT_STATUSES = {
  running: "Работает", stopped: "Остановлен", unhealthy: "Ошибка healthcheck", missing: "Не найден",
  unknown: "Нет достоверных данных",
};
const CONTAINER_ALERT_SOURCES = {
  ok: "Полный снимок Docker", stale: "Снимок Docker устарел",
  partial: "Список Docker неполный", unavailable: "Docker недоступен",
};

function containerAlertsServer() {
  return state.servers.find((item) => String(item.id) === String(containerAlerts.serverId));
}
function containerAlertsContext() {
  const generation = containerAlerts.generation, sid = containerAlerts.serverId;
  const token = state.token, base = state.base;
  return () => Boolean(token) && token === state.token && base === state.base &&
    generation === containerAlerts.generation && String(sid) === String(containerAlerts.serverId) &&
    String(sid) === String(state.selectedId);
}
function containerAlertsPath() {
  return `/api/v1/servers/${encodeURIComponent(containerAlerts.serverId)}/containers/alerts`;
}
function containerAlertsValidate(payload) {
  if (!payload || !Number.isSafeInteger(payload.revision) || payload.revision < 0 ||
      !Number.isInteger(payload.hold_seconds) || payload.hold_seconds < 0 || payload.hold_seconds > 86400 ||
      !Array.isArray(payload.rules) || payload.rules.length > 12 ||
      !Object.hasOwn(CONTAINER_ALERT_SOURCES, payload.source_status) ||
      !(payload.observed_at === null || Number.isSafeInteger(payload.observed_at) && payload.observed_at > 0) ||
      !Array.isArray(payload.observations) || payload.observations.length > 12)
    throw new Error("Hub вернул неверные правила Docker-оповещений.");
  const names = new Set();
  for (const row of payload.rules) {
    if (!row || typeof row.name !== "string" || !CONTAINER_ALERT_NAME.test(row.name) || names.has(row.name) ||
        typeof row.stopped !== "boolean" || typeof row.unhealthy !== "boolean" || typeof row.missing !== "boolean" ||
        !(row.stopped || row.unhealthy || row.missing))
      throw new Error("Hub вернул неверное правило Docker-оповещения.");
    names.add(row.name);
  }
  const observed = new Set();
  for (const row of payload.observations) {
    if (!row || !names.has(row.name) || observed.has(row.name) ||
        !Object.hasOwn(CONTAINER_ALERT_STATUSES, row.status))
      throw new Error("Hub вернул неверное состояние Docker-контейнера.");
    observed.add(row.name);
  }
  return payload;
}
function containerAlertsAvailable() {
  const server = containerAlertsServer(), snapshot = server?.latest?.details?.containers;
  if (!server?.online || containerAlerts.data?.source_status !== "ok" || snapshot?.version !== 1 ||
      !Array.isArray(snapshot.engines) || snapshot.engines[0]?.engine !== "docker" ||
      snapshot.engines[0].source_status !== "ok" || snapshot.engines[0].truncated !== false ||
      !Array.isArray(snapshot.engines[0].containers)) return [];
  return [...new Set(snapshot.engines[0].containers.map((item) => item?.name)
    .filter((name) => typeof name === "string" && CONTAINER_ALERT_NAME.test(name)))].sort();
}
function containerAlertsReset() {
  containerAlerts.generation++; containerAlerts.seq++;
  Object.assign(containerAlerts, { serverId: null, data: null, busy: false, loading: false, pending: null });
  if ($("containerAlertDialog").open) $("containerAlertDialog").close();
  clearError($("containerAlertsError")); clearError($("containerAlertDialogError"));
  $("containerAlertsMessage").hidden = true;
  $("containerAlertsMessage").textContent = "";
  containerAlertsRender();
}
globalThis.containerAlertsReset = containerAlertsReset;
function containerAlertsSelectedServer(sid) {
  if (String(sid) === String(containerAlerts.serverId)) return;
  containerAlertsReset(); containerAlerts.serverId = sid;
}
globalThis.containerAlertsSelectedServer = containerAlertsSelectedServer;

function containerAlertsRender() {
  const client = containerAlerts, data = client.data, server = containerAlertsServer();
  const admin = Boolean(server && hubCanAdmin(server));
  if (!admin && client.pending) {
    client.pending = null;
    if ($("containerAlertDialog").open) $("containerAlertDialog").close();
  }
  $("containerAlertsCount").textContent = data ? String(data.rules.length) : "—";
  $("containerAlertsSource").textContent = data
    ? `${CONTAINER_ALERT_SOURCES[data.source_status]}${data.observed_at ?
      ` · ${new Intl.DateTimeFormat("ru", { dateStyle: "medium", timeStyle: "short" }).format(new Date(data.observed_at * 1000))}` : ""}. Подтверждение тревоги: ${data.hold_seconds === 0 ? "сразу" : `${data.hold_seconds} с`}.`
    : client.loading ? "Загружаем правила мониторинга…" : "Правила мониторинга недоступны.";
  $("containerAlertsAdd").disabled = !admin || !data || client.busy || client.loading || data.rules.length >= 12 ||
    !containerAlertsAvailable().some((name) => !data.rules.some((rule) => rule.name === name));
  $("containerAlertsHold").disabled = !admin || !data || client.busy || client.loading;
  const list = $("containerAlertsList"); list.replaceChildren();
  if (!data?.rules.length) {
    const empty = document.createElement("p"); empty.className = "field-help";
    empty.textContent = data ? "Пока ни за одним контейнером не следим. Добавьте его из полного снимка Docker." : "Нет настроенных правил.";
    list.append(empty); return;
  }
  const observations = new Map(data.observations.map((row) => [row.name, row.status]));
  for (const row of data.rules) {
    const status = observations.get(row.name) || "unknown";
    const article = document.createElement("article"); article.className = "container-alert-row";
    const head = document.createElement("div"); head.className = "container-card-top";
    const name = document.createElement("h4"); name.textContent = row.name;
    const badge = document.createElement("span");
    badge.className = `status-badge ${status === "running" ? "" : status === "unknown" ? "waiting" : "offline"}`;
    badge.textContent = CONTAINER_ALERT_STATUSES[status]; head.append(name, badge);
    const conditions = document.createElement("p"); conditions.className = "field-help";
    conditions.textContent = [row.stopped && "остановка", row.unhealthy && "unhealthy", row.missing && "исчезновение"]
      .filter(Boolean).join(" · ");
    article.append(head, conditions);
    if (admin) {
      const actions = document.createElement("div"); actions.className = "container-alert-actions";
      for (const [mode, label] of [["edit", "Изменить"], ["delete", "Удалить"]]) {
        const button = document.createElement("button"); button.type = "button";
        button.className = "secondary-button"; button.textContent = label;
        button.setAttribute("aria-label", `${label}: ${row.name}`);
        button.disabled = client.busy || client.loading;
        button.addEventListener("click", () => containerAlertsOpen(mode, row.name)); actions.append(button);
      }
      article.append(actions);
    }
    list.append(article);
  }
}
globalThis.containerAlertsRenderInventory = containerAlertsRender;

async function containerAlertsRefresh() {
  if (!state.token || state.selectedId === null || containerAlerts.busy) return;
  containerAlertsSelectedServer(state.selectedId);
  const current = containerAlertsContext(), seq = ++containerAlerts.seq;
  containerAlerts.loading = true; containerAlertsRender();
  try {
    const payload = containerAlertsValidate(await request(containerAlertsPath()));
    if (!current() || seq !== containerAlerts.seq) return;
    containerAlerts.data = payload; clearError($("containerAlertsError"));
  } catch (error) {
    if (current() && seq === containerAlerts.seq) {
      containerAlerts.data = null;
      showError($("containerAlertsError"), error.status === 404
        ? "Обновите Hub для настройки Docker-оповещений." : error.message || "Не удалось загрузить правила Docker.");
    }
  } finally {
    if (current() && seq === containerAlerts.seq) { containerAlerts.loading = false; containerAlertsRender(); }
  }
}
globalThis.containerAlertsRefresh = containerAlertsRefresh;

function containerAlertsOpen(mode, name = null) {
  const client = containerAlerts, server = containerAlertsServer(), data = client.data;
  if (!state.token || !server || !hubCanAdmin(server) || !data || client.busy || client.loading ||
      !["create", "edit", "delete", "hold"].includes(mode)) return;
  const row = data.rules.find((item) => item.name === name);
  if ((mode === "edit" || mode === "delete") && !row) return;
  const options = mode === "create"
    ? containerAlertsAvailable().filter((value) => !data.rules.some((item) => item.name === value))
    : row ? [row.name] : [];
  if (mode === "create" && (!options.length || data.rules.length >= 12)) return;
  client.pending = { mode, name, revision: data.revision,
    hold_seconds: data.hold_seconds, rules: data.rules.map((item) => ({ ...item })) };
  $("containerAlertDialogHeading").textContent = mode === "create" ? "Следить за контейнером"
    : mode === "edit" ? "Изменить оповещение" : mode === "delete" ? "Удалить оповещение?"
      : "Время подтверждения";
  $("containerAlertDialogHint").textContent = mode === "delete"
    ? `Правило для ${row.name} будет удалено. Активная тревога закроется как смена настройки.`
    : mode === "hold" ? "Короткие сбои можно пропустить, если проблема исчезла до подтверждения."
      : "Выберите условия, о которых нужно сообщать. Изменение не управляет самим контейнером.";
  $("containerAlertRuleFields").hidden = mode === "delete" || mode === "hold";
  $("containerAlertHoldField").hidden = mode !== "hold";
  $("containerAlertName").replaceChildren();
  for (const value of options) {
    const option = document.createElement("option"); option.value = value; option.textContent = value;
    $("containerAlertName").append(option);
  }
  $("containerAlertName").value = mode === "create" ? options[0] : row?.name || "";
  $("containerAlertName").disabled = mode !== "create";
  $("containerAlertName").required = mode === "create";
  $("containerAlertStopped").checked = row?.stopped ?? true;
  $("containerAlertUnhealthy").checked = row?.unhealthy ?? true;
  $("containerAlertMissing").checked = row?.missing ?? false;
  $("containerAlertHoldSeconds").value = String(data.hold_seconds);
  $("containerAlertHoldSeconds").required = mode === "hold";
  $("containerAlertConfirm").textContent = mode === "delete" ? "Удалить" : "Сохранить";
  clearError($("containerAlertDialogError"));
  $("containerAlertDialog").showModal();
  (mode === "hold" ? $("containerAlertHoldSeconds") : mode === "delete" ? $("containerAlertConfirm") : $("containerAlertName")).focus?.();
}
globalThis.containerAlertsOpen = containerAlertsOpen;

function containerAlertsPayload() {
  const pending = containerAlerts.pending;
  if (!pending) throw new Error("Настройка уже закрыта.");
  let rules = pending.rules, hold = pending.hold_seconds;
  if (pending.mode === "hold") {
    const raw = $("containerAlertHoldSeconds").value.trim();
    if (!/^(0|[1-9][0-9]*)$/.test(raw)) throw new Error("Введите целое число секунд.");
    hold = Number(raw);
    if (!Number.isInteger(hold) || hold < 0 || hold > 86400) throw new Error("Допустимо от 0 до 86 400 секунд.");
  } else if (pending.mode === "delete") {
    rules = rules.filter((row) => row.name !== pending.name);
  } else {
    const name = $("containerAlertName").value;
    if (!CONTAINER_ALERT_NAME.test(name) || pending.mode === "create" &&
        !containerAlertsAvailable().includes(name) || pending.mode === "edit" && name !== pending.name)
      throw new Error("Выберите контейнер из актуального списка Docker.");
    const row = { name, stopped: $("containerAlertStopped").checked,
      unhealthy: $("containerAlertUnhealthy").checked, missing: $("containerAlertMissing").checked };
    if (!(row.stopped || row.unhealthy || row.missing)) throw new Error("Выберите хотя бы одно условие.");
    rules = rules.filter((item) => item.name !== pending.name);
    rules.push(row);
  }
  return { revision: pending.revision, hold_seconds: hold, rules };
}

function containerAlertsSettingsKey(value) {
  return JSON.stringify({ hold_seconds: value.hold_seconds,
    rules: [...value.rules].map((row) => ({ name: row.name, stopped: row.stopped,
      unhealthy: row.unhealthy, missing: row.missing })).sort((a, b) => a.name.localeCompare(b.name)) });
}

async function containerAlertsSubmit(event) {
  event.preventDefault();
  const client = containerAlerts, pending = client.pending, server = containerAlertsServer();
  if (!pending || client.busy || !state.token || !server || !hubCanAdmin(server)) return;
  let payload;
  try { payload = containerAlertsPayload(); }
  catch (error) { showError($("containerAlertDialogError"), error.message); return; }
  const current = containerAlertsContext(); client.busy = true; client.seq++;
  $("containerAlertCancel").disabled = true; $("containerAlertConfirm").disabled = true;
  containerAlertsRender();
  try {
    const saved = containerAlertsValidate(await request(containerAlertsPath(), {
      method: "PUT", body: JSON.stringify(payload),
    }));
    if (!current()) return;
    client.data = saved;
    client.pending = null; $("containerAlertDialog").close();
    $("containerAlertsMessage").textContent = pending.mode === "delete" ? "Правило удалено."
      : "Правила сохранены. Hub подтвердит проблему после выбранной задержки.";
    $("containerAlertsMessage").hidden = false;
    clearError($("containerAlertsError"));
  } catch (error) {
    if (!current()) return;
    if (error.status === 409) {
      client.pending = null; $("containerAlertDialog").close();
      try { client.data = containerAlertsValidate(await request(containerAlertsPath())); }
      catch { client.data = null; }
      if (!current()) return;
      $("containerAlertsMessage").textContent = "Настройки изменились в другой сессии. Проверьте новые правила и повторите изменение.";
      $("containerAlertsMessage").hidden = false;
    } else {
      // A lost PUT response may still have committed. Read back the server
      // revision and exact rule set; never repeat a mutation automatically.
      try {
        const fresh = containerAlertsValidate(await request(containerAlertsPath()));
        if (!current()) return;
        client.data = fresh;
        const wanted = containerAlertsSettingsKey(payload);
        const actual = containerAlertsSettingsKey(fresh);
        if (fresh.revision > payload.revision && wanted === actual) {
          client.pending = null; $("containerAlertDialog").close();
          $("containerAlertsMessage").textContent = "Настройки подтверждены повторным чтением Hub.";
          $("containerAlertsMessage").hidden = false;
        } else {
          client.pending = null; $("containerAlertDialog").close();
          showError($("containerAlertsError"), "Не удалось подтвердить сохранение. Проверьте текущие правила перед повтором.");
        }
      } catch {
        if (current()) {
          client.pending = null; $("containerAlertDialog").close();
          showError($("containerAlertsError"), "Ответ потерян. Неизвестно, сохранились ли настройки; обновите правила перед повтором.");
        }
      }
    }
  } finally {
    if (current()) {
      client.busy = false; $("containerAlertCancel").disabled = false;
      $("containerAlertConfirm").disabled = false; containerAlertsRender();
    }
  }
}
globalThis.containerAlertsSubmit = containerAlertsSubmit;

$("containerAlertsAdd").addEventListener("click", () => containerAlertsOpen("create"));
$("containerAlertsHold").addEventListener("click", () => containerAlertsOpen("hold"));
$("containerAlertCancel").addEventListener("click", () => {
  if (!containerAlerts.busy) { containerAlerts.pending = null; $("containerAlertDialog").close(); }
});
$("containerAlertForm").addEventListener("submit", containerAlertsSubmit);
$("containerAlertDialog").addEventListener("cancel", (event) => {
  if (containerAlerts.busy) event.preventDefault(); else containerAlerts.pending = null;
});
$("containerAlertDialog").addEventListener("close", () => {
  if (!containerAlerts.busy) containerAlerts.pending = null;
});

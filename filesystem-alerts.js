/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

const filesystemAlerts = { generation: 0, seq: 0, serverId: null, data: null,
  busy: false, loading: false, pending: null };
const FILESYSTEM_ALERT_SOURCES = {
  ok: "Свежий полный отчёт", stale: "Отчёт устарел",
  partial: "Список файловых систем неполный", unavailable: "Данные недоступны",
};
const FILESYSTEM_ALERT_STATES = {
  normal: "Норма", alert: "Порог достигнут", unknown: "Нет достоверных данных",
};
const FILESYSTEM_ALERT_METRICS = { space: "Место", inodes: "Inode" };

function filesystemAlertsKey(row) { return row.metric + "\0" + row.mountpoint; }
function filesystemAlertsMountpoint(value) {
  return typeof value === "string" && value.startsWith("/") &&
    new TextEncoder().encode(value).length <= 128 &&
    !/[\u0000-\u001f\u007f-\u009f]/.test(value) &&
    (value === "/" || value.split("/").slice(1).every((part) =>
      part && part !== "." && part !== ".."));
}
function filesystemAlertsPercent(value) {
  return value === null || typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100;
}
function filesystemAlertsValidate(payload) {
  if (!payload || String(payload.server_id) !== String(filesystemAlerts.serverId) ||
      !Number.isSafeInteger(payload.revision) || payload.revision < 0 ||
      !Number.isInteger(payload.hold_seconds) || payload.hold_seconds < 0 || payload.hold_seconds > 86400 ||
      !Object.hasOwn(FILESYSTEM_ALERT_SOURCES, payload.source_status) ||
      !(payload.observed_at === null || Number.isSafeInteger(payload.observed_at) && payload.observed_at > 0) ||
      !Array.isArray(payload.rules) || payload.rules.length > 32 ||
      !Array.isArray(payload.filesystems) || payload.filesystems.length > 16 ||
      !Array.isArray(payload.observations) || payload.observations.length > 32 ||
      (payload.source_status !== "ok" && payload.filesystems.length))
    throw new Error("Hub вернул неверные правила файловых систем.");
  const rules = new Set();
  for (const row of payload.rules) {
    if (!row || !filesystemAlertsMountpoint(row.mountpoint) ||
        !Object.hasOwn(FILESYSTEM_ALERT_METRICS, row.metric) ||
        !Number.isInteger(row.threshold_percent) || row.threshold_percent < 1 || row.threshold_percent > 100 ||
        rules.has(filesystemAlertsKey(row)))
      throw new Error("Hub вернул неверное правило файловой системы.");
    rules.add(filesystemAlertsKey(row));
  }
  const mounts = new Set();
  for (const row of payload.filesystems) {
    if (!row || !filesystemAlertsMountpoint(row.mountpoint) || mounts.has(row.mountpoint) ||
        typeof row.fstype !== "string" || row.fstype.length > 80 ||
        !filesystemAlertsPercent(row.space_used_percent) ||
        !filesystemAlertsPercent(row.inodes_used_percent))
      throw new Error("Hub вернул неверный список файловых систем.");
    mounts.add(row.mountpoint);
  }
  const observed = new Set();
  for (const row of payload.observations) {
    if (!row || !rules.has(filesystemAlertsKey(row)) || observed.has(filesystemAlertsKey(row)) ||
        !Object.hasOwn(FILESYSTEM_ALERT_STATES, row.status) ||
        !filesystemAlertsPercent(row.used_percent))
      throw new Error("Hub вернул неверное состояние файловой системы.");
    observed.add(filesystemAlertsKey(row));
  }
  return payload;
}
function filesystemAlertsServer() {
  return state.servers.find((item) => String(item.id) === String(filesystemAlerts.serverId));
}
function filesystemAlertsContext() {
  const generation = filesystemAlerts.generation, sid = filesystemAlerts.serverId;
  const token = state.token, base = state.base;
  return () => Boolean(token) && token === state.token && base === state.base &&
    generation === filesystemAlerts.generation && String(sid) === String(filesystemAlerts.serverId) &&
    String(sid) === String(state.selectedId);
}
function filesystemAlertsPath() {
  return "/api/v1/servers/" + encodeURIComponent(filesystemAlerts.serverId) + "/filesystems/alerts";
}
function filesystemAlertsAvailable() {
  const data = filesystemAlerts.data, server = filesystemAlertsServer();
  if (!server?.online || data?.source_status !== "ok") return [];
  const pairs = [];
  for (const row of data.filesystems) {
    if (row.space_used_percent !== null) pairs.push({ mountpoint: row.mountpoint, metric: "space" });
    if (row.inodes_used_percent !== null) pairs.push({ mountpoint: row.mountpoint, metric: "inodes" });
  }
  return pairs;
}
function filesystemAlertsReset() {
  filesystemAlerts.generation++; filesystemAlerts.seq++;
  Object.assign(filesystemAlerts, { serverId: null, data: null, busy: false, loading: false, pending: null });
  if ($("filesystemAlertDialog").open) $("filesystemAlertDialog").close();
  clearError($("filesystemAlertsError")); clearError($("filesystemAlertDialogError"));
  $("filesystemAlertsMessage").hidden = true;
  $("filesystemAlertsMessage").textContent = "";
  filesystemAlertsRender();
}
globalThis.filesystemAlertsReset = filesystemAlertsReset;
function filesystemAlertsSelectedServer(sid) {
  if (String(sid) === String(filesystemAlerts.serverId)) return;
  filesystemAlertsReset(); filesystemAlerts.serverId = sid;
}
globalThis.filesystemAlertsSelectedServer = filesystemAlertsSelectedServer;

function filesystemAlertsRender() {
  const client = filesystemAlerts, data = client.data, server = filesystemAlertsServer();
  const admin = Boolean(server && hubCanAdmin(server));
  if (!admin && client.pending) {
    client.pending = null;
    if ($("filesystemAlertDialog").open) $("filesystemAlertDialog").close();
  }
  $("filesystemAlertsCount").textContent = data ? String(data.rules.length) : "—";
  $("filesystemAlertsSource").textContent = data ?
    FILESYSTEM_ALERT_SOURCES[data.source_status] +
      (data.observed_at ? " · " + new Intl.DateTimeFormat("ru", { dateStyle: "medium", timeStyle: "short" })
        .format(new Date(data.observed_at * 1000)) : "") +
      ". Подтверждение тревоги: " + (data.hold_seconds === 0 ? "сразу" : data.hold_seconds + " с") + "." :
    client.loading ? "Загружаем правила мониторинга…" : "Правила мониторинга недоступны.";
  const configured = new Set(data?.rules.map(filesystemAlertsKey) || []);
  $("filesystemAlertsAdd").disabled = !admin || !data || client.busy || client.loading ||
    data.rules.length >= 32 || !filesystemAlertsAvailable().some((pair) => !configured.has(filesystemAlertsKey(pair)));
  $("filesystemAlertsHold").disabled = !admin || !data || client.busy || client.loading;
  const list = $("filesystemAlertsList"); list.replaceChildren();
  if (!data?.rules.length) {
    const empty = document.createElement("p"); empty.className = "field-help";
    empty.textContent = data ? "Правил пока нет. Добавьте диск из свежего отчёта Agent." : "Нет настроенных правил.";
    list.append(empty); return;
  }
  const observations = new Map(data.observations.map((row) => [filesystemAlertsKey(row), row]));
  for (const row of data.rules) {
    const observation = observations.get(filesystemAlertsKey(row));
    const status = observation?.status || "unknown";
    const article = document.createElement("article"); article.className = "filesystem-alert-row";
    const head = document.createElement("div"); head.className = "filesystem-alert-head";
    const name = document.createElement("h3"); name.textContent = row.mountpoint;
    const badge = document.createElement("span");
    badge.className = "status-badge " + (status === "normal" ? "" : status === "unknown" ? "waiting" : "offline");
    badge.textContent = FILESYSTEM_ALERT_STATES[status]; head.append(name, badge);
    const condition = document.createElement("p"); condition.className = "field-help";
    condition.textContent = FILESYSTEM_ALERT_METRICS[row.metric] + ": порог " + row.threshold_percent + "%" +
      (typeof observation?.used_percent === "number" ?
        " · занято " + observation.used_percent.toFixed(1) + "%" : "");
    article.append(head, condition);
    if (admin) {
      const actions = document.createElement("div"); actions.className = "filesystem-alert-actions";
      for (const [mode, label] of [["edit", "Изменить порог"], ["delete", "Удалить"]]) {
        const button = document.createElement("button"); button.type = "button";
        button.className = "secondary-button"; button.textContent = label;
        button.setAttribute("aria-label", label + ": " + row.mountpoint + ", " + FILESYSTEM_ALERT_METRICS[row.metric]);
        button.disabled = client.busy || client.loading;
        button.addEventListener("click", () => filesystemAlertsOpen(mode, filesystemAlertsKey(row)));
        actions.append(button);
      }
      article.append(actions);
    }
    list.append(article);
  }
}
globalThis.filesystemAlertsRenderInventory = filesystemAlertsRender;

async function filesystemAlertsRefresh() {
  if (!state.token || state.selectedId === null || filesystemAlerts.busy) return;
  filesystemAlertsSelectedServer(state.selectedId);
  const current = filesystemAlertsContext(), seq = ++filesystemAlerts.seq;
  filesystemAlerts.loading = true; filesystemAlertsRender();
  try {
    const payload = filesystemAlertsValidate(await request(filesystemAlertsPath()));
    if (!current() || seq !== filesystemAlerts.seq) return;
    filesystemAlerts.data = payload; clearError($("filesystemAlertsError"));
  } catch (error) {
    if (current() && seq === filesystemAlerts.seq) {
      filesystemAlerts.data = null;
      showError($("filesystemAlertsError"), error.status === 404
        ? "Обновите Hub для настройки оповещений по дискам." :
          error.message || "Не удалось загрузить правила файловых систем.");
    }
  } finally {
    if (current() && seq === filesystemAlerts.seq) {
      filesystemAlerts.loading = false; filesystemAlertsRender();
    }
  }
}
globalThis.filesystemAlertsRefresh = filesystemAlertsRefresh;

function filesystemAlertsFillMetric() {
  const pending = filesystemAlerts.pending;
  if (!pending || pending.mode !== "create") return;
  const mountpoint = $("filesystemAlertMountpoint").value;
  const select = $("filesystemAlertMetric"); select.replaceChildren();
  const matches = pending.options.filter((pair) => pair.mountpoint === mountpoint);
  for (const pair of matches) {
    const option = document.createElement("option"); option.value = pair.metric;
    option.textContent = FILESYSTEM_ALERT_METRICS[pair.metric]; select.append(option);
  }
  select.value = matches[0]?.metric || "";
}
function filesystemAlertsOpen(mode, key = null) {
  const client = filesystemAlerts, server = filesystemAlertsServer(), data = client.data;
  if (!state.token || !server || !hubCanAdmin(server) || !data || client.busy || client.loading ||
      !["create", "edit", "delete", "hold"].includes(mode)) return;
  const row = data.rules.find((item) => filesystemAlertsKey(item) === key);
  if (["edit", "delete"].includes(mode) && !row) return;
  const configured = new Set(data.rules.map(filesystemAlertsKey));
  const options = mode === "create"
    ? filesystemAlertsAvailable().filter((pair) => !configured.has(filesystemAlertsKey(pair)))
    : row ? [{ mountpoint: row.mountpoint, metric: row.metric }] : [];
  if (mode === "create" && (!options.length || data.rules.length >= 32)) return;
  client.pending = { mode, key, revision: data.revision, hold_seconds: data.hold_seconds,
    rules: data.rules.map((item) => ({ ...item })), options };
  $("filesystemAlertDialogHeading").textContent = mode === "create" ? "Добавить правило"
    : mode === "edit" ? "Изменить порог" : mode === "delete" ? "Удалить правило?" : "Время подтверждения";
  $("filesystemAlertDialogHint").textContent = row ? row.mountpoint + " · " + FILESYSTEM_ALERT_METRICS[row.metric] :
    mode === "hold" ? "Одна задержка применяется ко всем правилам этого сервера." :
      "Выберите диск и показатель из свежего отчёта Agent.";
  $("filesystemAlertRuleFields").hidden = mode === "hold" || mode === "delete";
  $("filesystemAlertHoldField").hidden = mode !== "hold";
  const mount = $("filesystemAlertMountpoint"); mount.replaceChildren();
  for (const mountpoint of [...new Set(options.map((item) => item.mountpoint))]) {
    const option = document.createElement("option"); option.value = mountpoint;
    option.textContent = mountpoint; mount.append(option);
  }
  mount.value = options[0]?.mountpoint || "";
  const metric = $("filesystemAlertMetric"); metric.replaceChildren();
  if (mode === "create") filesystemAlertsFillMetric();
  else if (row) {
    const option = document.createElement("option"); option.value = row.metric;
    option.textContent = FILESYSTEM_ALERT_METRICS[row.metric]; metric.append(option); metric.value = row.metric;
  }
  mount.disabled = mode !== "create"; metric.disabled = mode !== "create";
  $("filesystemAlertThreshold").value = String(row?.threshold_percent ?? 90);
  $("filesystemAlertThreshold").required = mode === "create" || mode === "edit";
  $("filesystemAlertHoldSeconds").value = String(data.hold_seconds);
  $("filesystemAlertHoldSeconds").required = mode === "hold";
  $("filesystemAlertConfirm").textContent = mode === "delete" ? "Удалить" : "Сохранить";
  clearError($("filesystemAlertDialogError"));
  $("filesystemAlertDialog").showModal();
  (mode === "hold" ? $("filesystemAlertHoldSeconds") :
    mode === "delete" ? $("filesystemAlertConfirm") : $("filesystemAlertThreshold")).focus?.();
}
globalThis.filesystemAlertsOpen = filesystemAlertsOpen;

function filesystemAlertsPayload() {
  const pending = filesystemAlerts.pending;
  if (!pending) throw new Error("Откройте правило заново.");
  let hold = pending.hold_seconds, rules = pending.rules;
  if (pending.mode === "hold") {
    const raw = $("filesystemAlertHoldSeconds").value;
    if (!/^(0|[1-9][0-9]*)$/.test(raw) || Number(raw) > 86400)
      throw new Error("Укажите задержку от 0 до 86 400 секунд.");
    hold = Number(raw);
  } else if (pending.mode === "delete") {
    rules = rules.filter((row) => filesystemAlertsKey(row) !== pending.key);
  } else {
    const mountpoint = $("filesystemAlertMountpoint").value, metric = $("filesystemAlertMetric").value;
    const raw = $("filesystemAlertThreshold").value;
    if (!filesystemAlertsMountpoint(mountpoint) || !Object.hasOwn(FILESYSTEM_ALERT_METRICS, metric) ||
        (pending.mode === "create" && !pending.options.some((pair) =>
          pair.mountpoint === mountpoint && pair.metric === metric)) ||
        (pending.mode === "edit" && filesystemAlertsKey({ mountpoint, metric }) !== pending.key))
      throw new Error("Выберите диск и показатель из актуального списка.");
    if (!/^(100|[1-9][0-9]?)$/.test(raw))
      throw new Error("Порог должен быть целым числом от 1 до 100%.");
    rules = rules.filter((row) => filesystemAlertsKey(row) !== pending.key);
    rules.push({ mountpoint, metric, threshold_percent: Number(raw) });
  }
  return { revision: pending.revision, hold_seconds: hold, rules };
}
function filesystemAlertsSettingsKey(value) {
  return JSON.stringify({ hold_seconds: value.hold_seconds,
    rules: [...value.rules].map((row) => ({ mountpoint: row.mountpoint, metric: row.metric,
      threshold_percent: row.threshold_percent }))
      .sort((a, b) => filesystemAlertsKey(a).localeCompare(filesystemAlertsKey(b))) });
}
async function filesystemAlertsSubmit(event) {
  event.preventDefault();
  const client = filesystemAlerts, pending = client.pending, server = filesystemAlertsServer();
  if (!pending || client.busy || !state.token || !server || !hubCanAdmin(server)) return;
  let payload;
  try { payload = filesystemAlertsPayload(); }
  catch (error) { showError($("filesystemAlertDialogError"), error.message); return; }
  const current = filesystemAlertsContext(); client.busy = true; client.seq++;
  $("filesystemAlertCancel").disabled = true; $("filesystemAlertConfirm").disabled = true;
  filesystemAlertsRender();
  try {
    const saved = filesystemAlertsValidate(await request(filesystemAlertsPath(), {
      method: "PUT", body: JSON.stringify(payload),
    }));
    if (!current()) return;
    client.data = saved;
    client.pending = null; $("filesystemAlertDialog").close();
    $("filesystemAlertsMessage").textContent = pending.mode === "delete" ? "Правило удалено." :
      "Правила сохранены. Hub подтвердит проблему после выбранной задержки.";
    $("filesystemAlertsMessage").hidden = false; clearError($("filesystemAlertsError"));
  } catch (error) {
    if (!current()) return;
    client.pending = null; $("filesystemAlertDialog").close();
    try {
      const fresh = filesystemAlertsValidate(await request(filesystemAlertsPath()));
      if (!current()) return;
      client.data = fresh;
      if (error.status === 409) {
        $("filesystemAlertsMessage").textContent = "Настройки изменились в другой сессии. Проверьте новые правила перед повтором.";
        $("filesystemAlertsMessage").hidden = false;
      } else if (fresh.revision > payload.revision &&
                 filesystemAlertsSettingsKey(fresh) === filesystemAlertsSettingsKey(payload)) {
        $("filesystemAlertsMessage").textContent = "Настройки подтверждены повторным чтением Hub.";
        $("filesystemAlertsMessage").hidden = false;
      } else {
        showError($("filesystemAlertsError"), "Не удалось подтвердить сохранение. Проверьте текущие правила перед повтором.");
      }
    } catch {
      if (current()) showError($("filesystemAlertsError"),
        "Ответ потерян. Неизвестно, сохранились ли настройки; обновите правила перед повтором.");
    }
  } finally {
    if (current()) {
      client.busy = false; $("filesystemAlertCancel").disabled = false;
      $("filesystemAlertConfirm").disabled = false; filesystemAlertsRender();
    }
  }
}
globalThis.filesystemAlertsSubmit = filesystemAlertsSubmit;

$("filesystemAlertsAdd").addEventListener("click", () => filesystemAlertsOpen("create"));
$("filesystemAlertsHold").addEventListener("click", () => filesystemAlertsOpen("hold"));
$("filesystemAlertMountpoint").addEventListener("change", filesystemAlertsFillMetric);
$("filesystemAlertCancel").addEventListener("click", () => {
  if (!filesystemAlerts.busy) { filesystemAlerts.pending = null; $("filesystemAlertDialog").close(); }
});
$("filesystemAlertForm").addEventListener("submit", filesystemAlertsSubmit);
$("filesystemAlertDialog").addEventListener("cancel", (event) => {
  if (filesystemAlerts.busy) event.preventDefault(); else filesystemAlerts.pending = null;
});
$("filesystemAlertDialog").addEventListener("close", () => {
  if (!filesystemAlerts.busy) filesystemAlerts.pending = null;
});

/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

const accessClient = { generation: 0, pending: null, policy: null, selects: new Map(),
  loading: false, busy: false };
const ACCESS_ROLES = { viewer: "Наблюдатель", operator: "Оператор", admin: "Администратор" };

function accessPath(pending) {
  if (pending.kind === "user") return `/api/v1/users/${encodeURIComponent(pending.key)}/server-access`;
  return `/api/v1/telegram/bindings/${pending.key}/${pending.key}/server-access`;
}

function accessCurrent(pending) {
  return accessClient.pending === pending && accessClient.generation === pending.generation &&
    state.token === pending.token && state.base === pending.base && Boolean(state.token) &&
    hubCanGlobalAdmin();
}

function accessValidate(payload) {
  const policy = payload?.access;
  if (!policy || !Number.isSafeInteger(policy.revision) || policy.revision < 0 ||
      !["all", "selected"].includes(policy.mode) || !Array.isArray(policy.grants) ||
      policy.grants.length > 1024 || (policy.mode === "all" && policy.grants.length)) {
    throw new Error("Центр мониторинга вернул неверные права серверов.");
  }
  const known = new Set(state.servers.map((server) => String(server.id)));
  const ids = new Set();
  for (const grant of policy.grants) {
    if (!grant || typeof grant.server_id !== "string" || !known.has(grant.server_id) ||
        ids.has(grant.server_id) || !Object.hasOwn(ACCESS_ROLES, grant.role)) {
      throw new Error("Центр мониторинга вернул неверный список доступных серверов. Обновите панель.");
    }
    ids.add(grant.server_id);
  }
  return { revision: policy.revision, mode: policy.mode,
    grants: policy.grants.map((grant) => ({ server_id: grant.server_id, role: grant.role })) };
}

function accessRender() {
  const client = accessClient, pending = client.pending, policy = client.policy;
  const mode = $("accessMode").value;
  $("accessMode").disabled = client.loading || client.busy || !policy ||
    (pending?.kind === "user" && pending.key === state.user?.id);
  $("accessSelectedFields").hidden = mode !== "selected" || !policy;
  for (const select of client.selects.values()) select.disabled = client.loading || client.busy;
  $("accessDialogSave").disabled = client.loading || client.busy || !policy ||
    (pending?.kind === "user" && pending.key === state.user?.id);
  $("accessDialogReload").disabled = client.loading || client.busy || !pending;
  $("accessDialogCancel").disabled = client.busy;
  $("accessDialogSave").textContent = client.busy ? "Сохраняем…" : "Сохранить доступ";
}

function accessBuildRows(policy) {
  const list = $("accessServerRows"); list.replaceChildren();
  accessClient.selects.clear();
  const grants = new Map(policy.grants.map((grant) => [grant.server_id, grant.role]));
  for (const server of [...state.servers].sort((a, b) => String(a.name || a.id).localeCompare(String(b.name || b.id), "ru"))) {
    const id = String(server.id);
    const row = document.createElement("div"); row.className = "access-server-row";
    const name = document.createElement("strong"); name.textContent = String(server.name || id);
    const select = document.createElement("select");
    select.setAttribute("aria-label", `Доступ к серверу ${server.name || id}`);
    for (const [role, label] of [["none", "Нет доступа"], ...Object.entries(ACCESS_ROLES)]) {
      const option = document.createElement("option"); option.value = role; option.textContent = label;
      select.append(option);
    }
    select.value = grants.get(id) || "none";
    accessClient.selects.set(id, select);
    row.append(name, select); list.append(row);
  }
  if (!state.servers.length) {
    const empty = document.createElement("p"); empty.className = "field-help";
    empty.textContent = "Серверов пока нет. Добавьте сервер, затем назначьте доступ.";
    list.append(empty);
  }
}

async function accessLoad(pending) {
  if (!accessCurrent(pending)) return;
  accessClient.loading = true; accessClient.policy = null; accessRender();
  clearError($("accessDialogError"));
  $("accessDialogMessage").hidden = true;
  try {
    const policy = accessValidate(await request(accessPath(pending)));
    if (!accessCurrent(pending)) return;
    accessClient.policy = policy;
    $("accessMode").value = policy.mode;
    accessBuildRows(policy);
  } catch (error) {
    if (accessCurrent(pending)) showError($("accessDialogError"), error.status === 404
      ? "Запись не найдена или Hub нужно обновить для управления доступом к серверам."
      : error.message || "Не удалось загрузить доступ к серверам.");
  } finally {
    if (accessCurrent(pending)) { accessClient.loading = false; accessRender(); }
  }
}

function accessOpen(kind, key, label, role) {
  if (!state.token || !hubCanGlobalAdmin() || !["user", "telegram"].includes(kind) ||
      typeof label !== "string" || label.length > 200 || !Object.hasOwn(ACCESS_ROLES, role) ||
      (kind === "user" && (typeof key !== "string" || !key || key.length > 64)) ||
      (kind === "telegram" && (!Number.isSafeInteger(key) || key <= 0))) return;
  accessClient.generation++;
  const pending = { generation: accessClient.generation, token: state.token, base: state.base,
    kind, key, label, role };
  accessClient.pending = pending;
  accessClient.policy = null;
  accessClient.selects.clear();
  accessClient.loading = false; accessClient.busy = false;
  $("accessDialogHeading").textContent = kind === "telegram" ? "Серверы Telegram-пользователя" : "Серверы пользователя панели";
  $("accessDialogTarget").textContent = `${label} · ${ACCESS_ROLES[role]}`;
  $("accessDialogHelp").textContent = kind === "telegram"
    ? "Роль Telegram ограничивает права на каждом сервере. Изменение отменит ожидающие подтверждения и команды этой привязки."
    : key === state.user?.id
      ? "Свой доступ можно просмотреть здесь. Ограничить собственную учётную запись нельзя."
      : "Общая роль пользователя ограничивает права на каждом сервере. Изменение отменит ожидающие команды и закроет его открытые терминалы и файловые соединения.";
  $("accessMode").value = "all";
  $("accessServerRows").replaceChildren();
  clearError($("accessDialogError"));
  $("accessDialogMessage").hidden = true;
  if (!$("accessDialog").open) $("accessDialog").showModal();
  void accessLoad(pending);
}
globalThis.accessOpen = accessOpen;

function accessClose() {
  if (accessClient.busy) return;
  accessClient.generation++;
  accessClient.pending = null; accessClient.policy = null;
  accessClient.selects.clear(); accessClient.loading = false;
  if ($("accessDialog").open) $("accessDialog").close();
}

function accessReset() {
  accessClient.busy = false;
  accessClose();
  clearError($("accessDialogError"));
  $("accessDialogMessage").hidden = true;
  $("accessServerRows").replaceChildren();
}
globalThis.accessReset = accessReset;

async function accessSave(event) {
  event.preventDefault();
  const client = accessClient, pending = client.pending, policy = client.policy;
  if (!pending || !policy || client.loading || client.busy || !accessCurrent(pending) ||
      (pending.kind === "user" && pending.key === state.user?.id)) return;
  const mode = $("accessMode").value;
  if (!["all", "selected"].includes(mode)) return;
  const grants = [];
  if (mode === "selected") for (const [server_id, select] of client.selects) {
    if (select.value === "none") continue;
    if (!Object.hasOwn(ACCESS_ROLES, select.value)) {
      showError($("accessDialogError"), "Выберите допустимую роль для каждого сервера."); return;
    }
    grants.push({ server_id, role: select.value });
  }
  if (grants.length > 1024) {
    showError($("accessDialogError"), "Можно назначить не более 1024 серверов."); return;
  }
  clearError($("accessDialogError"));
  client.busy = true; accessRender();
  try {
    const result = accessValidate(await request(accessPath(pending), {
      method: "PATCH", body: JSON.stringify({ revision: policy.revision, mode, grants }),
    }));
    if (!accessCurrent(pending)) return;
    if (result.revision !== policy.revision + 1 || result.mode !== mode) {
      throw new Error("Центр мониторинга вернул неверную версию доступа.");
    }
    client.policy = result;
    accessBuildRows(result);
    $("accessDialogMessage").textContent = "Доступ сохранён. Изменения применены к действующим сеансам.";
    $("accessDialogMessage").hidden = false;
    if (pending.kind === "user") globalThis.usersRefresh?.();
    else globalThis.telegramRefresh?.();
  } catch (error) {
    if (accessCurrent(pending)) showError($("accessDialogError"), error.status === 409
      ? "Права изменились в другой вкладке. Нажмите «Обновить», проверьте настройки и сохраните снова."
      : !error.status ? "Ответ не получен; изменение могло сохраниться. Нажмите «Обновить» перед повторной попыткой."
        : error.message || "Не удалось сохранить доступ.");
  } finally {
    if (accessCurrent(pending)) { client.busy = false; accessRender(); }
  }
}

$("accessDialogForm").addEventListener("submit", accessSave);
$("accessMode").addEventListener("change", accessRender);
$("accessDialogReload").addEventListener("click", () => { if (accessClient.pending && !accessClient.busy) void accessLoad(accessClient.pending); });
$("accessDialogCancel").addEventListener("click", accessClose);
$("accessDialog").addEventListener("cancel", (event) => { event.preventDefault(); accessClose(); });
$("accessDialog").addEventListener("close", () => { if (accessClient.pending && !accessClient.busy) accessClose(); });

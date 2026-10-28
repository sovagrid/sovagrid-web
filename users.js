/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

const usersClient = { generation: 0, refreshSeq: 0, rows: null, busy: false,
  loading: false, pending: null };
const USER_ROLE_NAMES = { viewer: "Наблюдатель", operator: "Оператор", admin: "Администратор" };

function usersDialogBusy(busy) {
  for (const id of ["userUsername", "userRole", "userEnabled", "userPassword", "userGeneratePassword",
    "userRevealPassword", "userCopyPassword", "userPasswordSaved", "userDialogConfirm", "userDialogCancel"]) $(id).disabled = busy;
}

function usersCurrent(generation, token, base) {
  return usersClient.generation === generation && state.token === token && state.base === base &&
    Boolean(token) && hubCanGlobalAdmin();
}

function usersValidateUser(user) {
  if (!user || typeof user !== "object" || typeof user.id !== "string" || !user.id ||
      user.id.length > 64 || typeof user.username !== "string" || !user.username ||
      [...user.username].length > 80 || !Object.hasOwn(USER_ROLE_NAMES, user.role) ||
      typeof user.enabled !== "boolean" || !Number.isSafeInteger(user.revision) || user.revision < 0 ||
      !Number.isSafeInteger(user.created_at) || !Number.isSafeInteger(user.updated_at)) {
    throw new Error("Центр мониторинга вернул неверную учётную запись.");
  }
  return { id: user.id, username: user.username, role: user.role, enabled: user.enabled,
    revision: user.revision, created_at: user.created_at, updated_at: user.updated_at };
}

function usersReset() {
  usersClient.generation++;
  usersClient.refreshSeq++;
  Object.assign(usersClient, { rows: null, busy: false, loading: false, pending: null });
  usersDialogBusy(false);
  $("userPassword").value = "";
  $("userPassword").type = "password";
  $("userUsername").value = "";
  $("userGeneratedConfirm").hidden = true;
  $("userPasswordSaved").checked = false;
  $("userPasswordStatus").textContent = "";
  if ($("userDialog").open) $("userDialog").close();
  clearError($("usersError"));
  clearError($("userDialogError"));
  $("usersMessage").hidden = true;
  $("usersMessage").textContent = "";
  usersRender();
}
globalThis.usersReset = usersReset;

function usersRender() {
  const client = usersClient;
  $("usersAdd").disabled = !hubCanGlobalAdmin() || !client.rows || client.busy || client.loading;
  $("usersReload").disabled = client.busy || client.loading || !hubCanGlobalAdmin();
  $("usersCount").textContent = client.rows ? String(client.rows.length) : "—";
  const list = $("usersList");
  list.replaceChildren();
  if (!client.rows?.length) {
    const empty = document.createElement("p");
    empty.className = "field-help";
    empty.textContent = client.loading ? "Получаем список пользователей…" : "Список пользователей ещё не загружен.";
    list.append(empty);
    return;
  }
  for (const user of [...client.rows].sort((a, b) => a.username.localeCompare(b.username, "ru"))) {
    const row = document.createElement("article"); row.className = "user-row";
    const identity = document.createElement("div"); identity.className = "user-identity";
    const name = document.createElement("h3"); name.textContent = user.username;
    const description = document.createElement("p");
    const own = user.id === state.user?.id;
    description.textContent = `${USER_ROLE_NAMES[user.role]} · ${user.enabled ? "Доступ открыт" : "Доступ отключён"}${own ? " · Это вы" : ""}`;
    identity.append(name, description);
    const actions = document.createElement("div"); actions.className = "user-actions";
    for (const [mode, text] of [["access", "Изменить доступ"], ["servers", "Доступ к серверам"], ["password", "Новый пароль"], ["delete", "Удалить"]]) {
      const button = document.createElement("button");
      button.type = "button"; button.className = "secondary-button";
      button.textContent = text;
      button.setAttribute("aria-label", `${text}: ${user.username}`);
      button.disabled = client.busy || !hubCanGlobalAdmin();
      button.addEventListener("click", () => mode === "servers"
        ? globalThis.accessOpen?.("user", user.id, user.username, user.role) : usersOpen(mode, user));
      actions.append(button);
    }
    row.append(identity, actions); list.append(row);
  }
}

async function usersRefresh() {
  if (!state.token || !hubCanGlobalAdmin() || usersClient.busy) return;
  const generation = usersClient.generation, token = state.token, base = state.base;
  const seq = ++usersClient.refreshSeq;
  usersClient.loading = true; usersRender();
  try {
    const result = await request("/api/v1/users");
    if (!usersCurrent(generation, token, base) || seq !== usersClient.refreshSeq) return;
    if (!Array.isArray(result.users) || result.users.length > 1000) throw new Error("Центр мониторинга вернул неверный список пользователей.");
    const rows = result.users.map(usersValidateUser);
    if (new Set(rows.map((user) => user.id)).size !== rows.length) throw new Error("В списке пользователей повторяются записи.");
    usersClient.rows = rows; clearError($("usersError"));
  } catch (error) {
    if (usersCurrent(generation, token, base) && seq === usersClient.refreshSeq) {
      if (error.status === 404) usersClient.rows = null;
      showError($("usersError"), error.status === 404 ? "Обновите Hub, чтобы управлять пользователями через панель." :
        error.message || "Не удалось загрузить пользователей.");
    }
  } finally {
    if (usersCurrent(generation, token, base) && seq === usersClient.refreshSeq) {
      usersClient.loading = false; usersRender();
    }
  }
}
globalThis.usersRefresh = usersRefresh;

function usersOpen(mode, user = null) {
  if (!state.token || !hubCanGlobalAdmin() || usersClient.busy || !usersClient.rows ||
      !["create", "access", "password", "delete"].includes(mode)) return;
  if (mode !== "create" && (!user || !usersClient.rows.some((item) => item.id === user.id))) return;
  usersClient.pending = { mode, user: user ? { ...user } : null };
  const create = mode === "create", access = mode === "access", password = create || mode === "password";
  $("userDialogHeading").textContent = { create: "Новый пользователь", access: "Изменить доступ", password: "Задать новый пароль", delete: "Удалить пользователя" }[mode];
  $("userDialogTarget").textContent = user ? user.username : "Отдельный вход в панель SovaGrid";
  $("userUsernameField").hidden = !create;
  $("userUsername").value = "";
  $("userUsername").required = create;
  $("userRoleField").hidden = !(create || access);
  $("userRole").value = user?.role || "viewer";
  $("userEnabledField").hidden = !access;
  $("userEnabled").checked = user?.enabled ?? true;
  $("userPasswordField").hidden = !password;
  $("userPassword").value = ""; $("userPassword").type = "password";
  $("userPassword").required = password;
  $("userRevealPassword").textContent = "Показать";
  $("userRevealPassword").setAttribute("aria-pressed", "false");
  $("userGeneratedConfirm").hidden = true;
  $("userPasswordSaved").checked = false;
  $("userPasswordStatus").textContent = "";
  $("userDialogNotice").textContent = create
    ? "Передайте человеку логин, пароль и адрес подключения по доверенному каналу. Пароль в панели повторно не показывается."
    : mode === "delete" ? "Вход будет удалён, его сеансы завершатся, а ожидающие команды будут отменены. История действий сохранится."
      : "Изменение завершит сеансы этого пользователя и отменит его ожидающие команды. Доступы к SSH и Telegram настраиваются отдельно.";
  $("userDialogConfirm").textContent = { create: "Создать пользователя", access: "Сохранить доступ", password: "Сменить пароль", delete: "Удалить пользователя" }[mode];
  clearError($("userDialogError"));
  usersDialogBusy(false);
  $("userDialog").showModal();
  (create ? $("userUsername") : password ? $("userPassword") : $("userDialogConfirm")).focus?.();
}

function usersClose() {
  if (usersClient.busy) return;
  usersClient.pending = null;
  $("userUsername").value = ""; $("userPassword").value = "";
  $("userPassword").type = "password";
  if ($("userDialog").open) $("userDialog").close();
}

function usersGeneratePassword() {
  if (usersClient.busy || !globalThis.crypto?.getRandomValues ||
      !["create", "password"].includes(usersClient.pending?.mode)) return;
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  $("userPassword").value = [...bytes].map((value) => alphabet[value & 63]).join("");
  bytes.fill(0);
  $("userPassword").type = "text";
  $("userRevealPassword").textContent = "Скрыть";
  $("userRevealPassword").setAttribute("aria-pressed", "true");
  usersClient.pending.generated = true;
  $("userGeneratedConfirm").hidden = false;
  $("userPasswordSaved").checked = false;
  $("userPasswordStatus").textContent = "Сохраните этот пароль перед подтверждением.";
  $("userPassword").focus?.();
}

function usersPasswordEdited() {
  if (usersClient.busy) return;
  if (usersClient.pending) usersClient.pending.generated = false;
  $("userGeneratedConfirm").hidden = true;
  $("userPasswordSaved").checked = false;
  $("userPasswordStatus").textContent = "";
}

async function usersCopyPassword() {
  if (usersClient.busy || !usersClient.pending || !$("userPassword").value) return;
  const pending = usersClient.pending, generation = usersClient.generation;
  const token = state.token, base = state.base;
  try {
    if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
    await navigator.clipboard.writeText($("userPassword").value);
    if (usersCurrent(generation, token, base) && usersClient.pending === pending) {
      $("userPasswordStatus").textContent = "Пароль скопирован. Сохраните его в надёжном месте.";
    }
  } catch {
    if (usersCurrent(generation, token, base) && usersClient.pending === pending) {
      $("userPasswordStatus").textContent = "Буфер обмена недоступен. Покажите пароль, выделите и скопируйте его вручную.";
    }
  }
}

async function usersSubmit(event) {
  event.preventDefault();
  const pending = usersClient.pending;
  if (!pending || usersClient.busy || !state.token || !hubCanGlobalAdmin()) return;
  clearError($("userDialogError"));
  const { mode, user } = pending;
  let path = "/api/v1/users", method = "POST", body;
  const role = $("userRole").value;
  if (["create", "access"].includes(mode) && !Object.hasOwn(USER_ROLE_NAMES, role)) return;
  if (mode === "create" || mode === "password") {
    if (pending.generated && !$("userPasswordSaved").checked) {
      showError($("userDialogError"), "Сохраните сгенерированный пароль и подтвердите это перед отправкой."); return;
    }
    const password = $("userPassword").value;
    if ([...password].length < 12 || [...password].length > 1024 || !password.trim()) {
      showError($("userDialogError"), "Пароль должен содержать от 12 до 1024 символов."); return;
    }
    if (mode === "create") {
      const username = $("userUsername").value.trim();
      if (!username || [...username].length > 80 || /[\p{C}\p{Zl}\p{Zp}]/u.test(username)) {
        showError($("userDialogError"), "Введите логин от 1 до 80 символов без переносов строки."); return;
      }
      body = { username, password, role };
    } else {
      path += `/${encodeURIComponent(user.id)}/password`;
      body = { revision: user.revision, password };
    }
  } else if (mode === "access") {
    path += `/${encodeURIComponent(user.id)}`; method = "PATCH";
    body = { revision: user.revision, role, enabled: $("userEnabled").checked };
  } else if (mode === "delete") {
    path += `/${encodeURIComponent(user.id)}?revision=${user.revision}`; method = "DELETE";
  }
  const generation = usersClient.generation, token = state.token, base = state.base;
  usersClient.busy = true;
  usersClient.refreshSeq++;
  usersClient.loading = false;
  $("userPassword").value = "";
  const confirmText = $("userDialogConfirm").textContent;
  $("userDialogConfirm").textContent = "Сохраняем…";
  usersDialogBusy(true);
  usersRender();
  try {
    const result = await request(path, { method, ...(body ? { body: JSON.stringify(body) } : {}) });
    body = null;
    if (!usersCurrent(generation, token, base) || usersClient.pending !== pending) return;
    if (mode === "delete") {
      if (result.removed !== true) throw new Error("Удаление не подтверждено центром мониторинга.");
    } else {
      const updated = usersValidateUser(result.user);
      if (user && (updated.id !== user.id || updated.revision !== user.revision + 1)) {
        throw new Error("Центр мониторинга вернул неверную версию учётной записи.");
      }
    }
    if (user?.id === state.user?.id && (result.sessions_revoked || mode === "delete")) {
      logout(false);
      $("loginNotice").textContent = "Ваш доступ изменён. Войдите снова с действующими данными.";
      $("loginNotice").hidden = false;
      return;
    }
    usersClient.busy = false; usersClose();
    $("usersMessage").textContent = { create: "Пользователь создан. Передайте ему данные входа по доверенному каналу.",
      access: "Доступ обновлён.", password: "Новый пароль сохранён. Передайте его пользователю по доверенному каналу.",
      delete: "Пользователь удалён." }[mode];
    $("usersMessage").hidden = false;
    await usersRefresh();
  } catch (error) {
    if (usersCurrent(generation, token, base) && usersClient.pending === pending) {
      const message = error.status === 409
        ? mode === "create" ? "Такой логин уже используется. Выберите другой или обновите список."
          : mode === "password" ? "Учётная запись изменилась. Закройте окно и обновите список."
            : "Запись изменилась или это последний действующий администратор. Закройте окно и обновите список."
        : error.status === 403 ? "Для этого действия нужен доступ администратора."
          : !error.status ? "Ответ не получен; изменение могло сохраниться. Закройте окно и обновите список перед повторной попыткой."
          : error.message || "Не удалось изменить пользователя.";
      showError($("userDialogError"), message + (["create", "password"].includes(mode) ? " Введите пароль заново." : ""));
    }
  } finally {
    body = null;
    if (usersCurrent(generation, token, base)) {
      usersClient.busy = false;
      $("userDialogConfirm").textContent = confirmText;
      usersDialogBusy(false);
      usersRender();
    }
  }
}

$("usersAdd").addEventListener("click", () => usersOpen("create"));
$("usersReload").addEventListener("click", usersRefresh);
$("userDialogForm").addEventListener("submit", usersSubmit);
$("userDialogCancel").addEventListener("click", usersClose);
$("userDialog").addEventListener("cancel", (event) => { event.preventDefault(); usersClose(); });
$("userDialog").addEventListener("close", () => { if (!usersClient.busy) usersClose(); });
$("userGeneratePassword").addEventListener("click", usersGeneratePassword);
$("userCopyPassword").addEventListener("click", usersCopyPassword);
$("userPassword").addEventListener("input", usersPasswordEdited);
$("userRevealPassword").addEventListener("click", () => {
  const reveal = $("userPassword").type === "password";
  $("userPassword").type = reveal ? "text" : "password";
  $("userRevealPassword").textContent = reveal ? "Скрыть" : "Показать";
  $("userRevealPassword").setAttribute("aria-pressed", String(reveal));
});

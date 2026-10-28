/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

const telegramClient = {
  generation: 0, refreshSeq: 0, data: null, loading: false,
  tokenBusy: false, bindingBusy: false, pairingBusy: false,
  pendingRoles: Object.create(null), pendingBinding: null, pendingApproval: null,
  requestsRenderKey: null, bindingsRenderKey: null,
};
const TELEGRAM_ROLES = { viewer: "Наблюдатель", operator: "Оператор", admin: "Администратор" };

function telegramReset() {
  telegramClient.generation++;
  telegramClient.refreshSeq++;
  telegramClient.data = null;
  telegramClient.loading = false;
  telegramClient.tokenBusy = false;
  telegramClient.bindingBusy = false;
  telegramClient.pairingBusy = false;
  telegramClient.pendingRoles = Object.create(null);
  telegramClient.pendingBinding = null;
  telegramClient.pendingApproval = null;
  telegramClient.requestsRenderKey = null;
  telegramClient.bindingsRenderKey = null;
  $("telegramTokenInput").value = "";
  $("telegramTokenInput").type = "password";
  $("telegramRevealToken").textContent = "Показать";
  $("telegramRevealToken").setAttribute("aria-label", "Показать введённый токен");
  $("telegramRevealToken").setAttribute("aria-pressed", "false");
  $("telegramUserId").value = "";
  $("telegramRole").value = "viewer";
  if ($("telegramRemoveTokenDialog").open) $("telegramRemoveTokenDialog").close();
  if ($("telegramRemoveBindingDialog").open) $("telegramRemoveBindingDialog").close();
  if ($("telegramApproveDialog").open) $("telegramApproveDialog").close();
  for (const id of ["telegramError", "telegramTokenError", "telegramBindingError",
    "telegramRemoveTokenError", "telegramRemoveBindingError", "telegramPairingError",
    "telegramApproveError"]) clearError($(id));
  renderTelegram();
}
globalThis.telegramReset = telegramReset;

function telegramCurrent(generation, token, base) {
  return telegramClient.generation === generation && state.token === token &&
    state.base === base && Boolean(token);
}

function telegramInvalidateRefresh() {
  // An older GET must never overwrite the result of a token or role change.
  telegramClient.refreshSeq++;
  telegramClient.loading = false;
}

function telegramValidate(payload) {
  const data = payload?.telegram;
  if (!data || !["managed", "managed_externally"].includes(data.mode) ||
      typeof data.configured !== "boolean" || typeof data.polling !== "boolean" ||
      typeof data.connected !== "boolean" ||
      (data.pending_incident_notifications != null &&
        (!Number.isSafeInteger(data.pending_incident_notifications) || data.pending_incident_notifications < 0)) ||
      (data.bot_username != null && (typeof data.bot_username !== "string" ||
        !/^[A-Za-z0-9_]{5,32}$/.test(data.bot_username))) ||
      (data.error !== null && (typeof data.error !== "string" || data.error.length > 200)) ||
      (data.last_success_at !== null && (!Number.isFinite(data.last_success_at) || data.last_success_at < 0)) ||
      !Array.isArray(data.bindings) || data.bindings.length > 1000 ||
      data.bindings.some((binding) => !Number.isSafeInteger(binding?.user_id) || binding.user_id <= 0 ||
        !Number.isSafeInteger(binding.chat_id) || binding.chat_id !== binding.user_id ||
        !Object.hasOwn(TELEGRAM_ROLES, binding.role)) ||
      !Array.isArray(data.pending_requests) || data.pending_requests.length > 100 ||
      data.pending_requests.some((item) => !Number.isSafeInteger(item?.user_id) || item.user_id <= 0 ||
        !Number.isSafeInteger(item.chat_id) || item.chat_id !== item.user_id ||
        !Number.isFinite(item.requested_at) || item.requested_at < 0 ||
        [item.first_name, item.last_name, item.username].some((name) =>
          name != null && (typeof name !== "string" || name.length > 128)))) {
    throw new Error("Центр мониторинга вернул неверные настройки Telegram.");
  }
  return data;
}

function telegramName(item) {
  const name = [item.first_name, item.last_name].filter((part) => typeof part === "string" && part.trim()).join(" ").trim();
  return name || (item.username ? `@${item.username}` : `Пользователь #${item.user_id}`);
}

function renderTelegram() {
  const data = telegramClient.data;
  const badge = $("telegramBadge");
  const stateText = !data ? telegramClient.loading ? "Проверяем" : "Нет данных" :
    !data.configured ? "Не настроен" : data.error ? "Сбой связи" : data.connected ? "На связи" :
      data.polling ? "Подключается" : "Остановлен";
  badge.textContent = stateText;
  badge.className = `status-badge ${data?.connected ? "" : "waiting"}`;
  $("telegramStatusText").textContent = !data ? "Состояние бота недоступно." :
    !data.configured ? "Добавьте токен BotFather, чтобы включить уведомления и команды." :
      data.error ? "Опрос Telegram завершился ошибкой; Hub пробует подключиться снова. Проверьте сеть и токен." :
      data.connected ? "Бот получает обновления Telegram. Доступ ограничен привязками и ролями ниже." :
        data.polling ? "Опрос Telegram включён, ожидаем успешного соединения." :
          "Токен сохранён, но опрос Telegram сейчас не работает.";
  if (data?.pending_incident_notifications > 0) {
    $("telegramStatusText").textContent += ` Уведомлений в очереди: ${data.pending_incident_notifications}. Hub сохраняет их и повторяет отправку при восстановлении связи.`;
  }
  const externallyManaged = data?.mode === "managed_externally";
  $("telegramTokenState").textContent = !data?.configured ? "Не настроен" : "Сохранён: ••••••••";
  $("telegramTokenState").className = `status-badge ${data?.configured ? "" : "waiting"}`;
  $("telegramTokenInput").placeholder = data?.configured ? "•••••••• — введите новый токен для замены" : "Вставьте токен BotFather";
  $("telegramTokenInput").disabled = !data || externallyManaged || telegramClient.tokenBusy;
  $("telegramRevealToken").disabled = !data || externallyManaged || telegramClient.tokenBusy;
  $("telegramSaveToken").disabled = !data || externallyManaged || telegramClient.tokenBusy;
  $("telegramRemoveToken").hidden = !data?.configured || externallyManaged;
  $("telegramRemoveToken").disabled = telegramClient.tokenBusy;
  $("telegramTokenHint").textContent = externallyManaged
    ? "Токен управляется настройками службы на сервере. В этой панели его нельзя заменить или удалить."
    : "Введите новый токен для сохранения или замены. Сохранённый токен не возвращается в браузер.";
  $("telegramLastSuccess").textContent = data?.last_success_at
    ? `Последний успешный ответ Telegram: ${timestamp(data.last_success_at)}` : "Успешного ответа Telegram пока не было.";
  const username = data?.bot_username;
  const botLink = $("telegramOpenBot");
  botLink.hidden = !data?.configured || !username;
  botLink.href = username ? `https://t.me/${username}` : "#";
  $("telegramRequestHint").textContent = !data?.configured
    ? "Сначала сохраните токен бота. После этого люди смогут отправить запрос на доступ."
    : username ? `Ваш бот: @${username}. Откройте его по кнопке и поделитесь ссылкой с пользователем.`
      : "Откройте созданного в BotFather бота в Telegram и отправьте ему /connect.";
  const requests = data?.pending_requests || [];
  $("telegramRequestCount").textContent = String(requests.length);
  const requestsList = $("telegramRequests");
  const requestsKey = JSON.stringify([Boolean(data), requests, telegramClient.pairingBusy]);
  if (requestsKey !== telegramClient.requestsRenderKey) {
    telegramClient.requestsRenderKey = requestsKey;
    requestsList.replaceChildren();
    if (!requests.length) {
      const note = document.createElement("p"); note.className = "advanced-empty";
      note.textContent = data ? "Новых запросов пока нет." : "Запросы пока недоступны.";
      requestsList.append(note);
    }
    for (const item of requests) {
      const row = document.createElement("div"); row.className = "telegram-binding telegram-request";
      const identity = document.createElement("div");
      const name = document.createElement("strong"); name.textContent = telegramName(item);
      const detail = document.createElement("span");
      detail.textContent = [item.username && `@${item.username}`, `Запрос ${timestamp(item.requested_at)}`]
        .filter(Boolean).join(" · ");
      identity.append(name, detail);
      const actions = document.createElement("div"); actions.className = "telegram-request-actions";
      const role = document.createElement("select");
      role.setAttribute("aria-label", `Роль для ${telegramName(item)}`);
      for (const [value, label] of Object.entries(TELEGRAM_ROLES)) {
        const option = document.createElement("option"); option.value = value; option.textContent = label;
        role.append(option);
      }
      role.value = telegramClient.pendingRoles[item.user_id] || "viewer";
      role.disabled = telegramClient.pairingBusy;
      role.addEventListener("change", () => { telegramClient.pendingRoles[item.user_id] = role.value; });
      const approve = document.createElement("button"); approve.type = "button";
      approve.className = "primary-button"; approve.textContent = "Разрешить";
      approve.disabled = telegramClient.pairingBusy;
      approve.setAttribute("aria-label", `Разрешить доступ для ${telegramName(item)}`);
      approve.addEventListener("click", () => telegramPrepareApproval(item, role.value));
      const reject = document.createElement("button"); reject.type = "button";
      reject.className = "secondary-button"; reject.textContent = "Отклонить";
      reject.disabled = telegramClient.pairingBusy;
      reject.setAttribute("aria-label", `Отклонить запрос ${telegramName(item)}`);
      reject.addEventListener("click", () => telegramChangePairing(item, "reject"));
      actions.append(role, approve, reject); row.append(identity, actions); requestsList.append(row);
    }
  }
  $("telegramUserId").disabled = !data || telegramClient.bindingBusy;
  $("telegramRole").disabled = !data || telegramClient.bindingBusy;
  $("telegramSaveBinding").disabled = !data || telegramClient.bindingBusy;
  const bindings = data?.bindings || [];
  $("telegramBindingCount").textContent = String(bindings.length);
  const list = $("telegramBindings");
  const bindingsKey = JSON.stringify([Boolean(data), bindings, telegramClient.bindingBusy]);
  if (bindingsKey !== telegramClient.bindingsRenderKey) {
    telegramClient.bindingsRenderKey = bindingsKey;
    list.replaceChildren();
    if (!bindings.length) {
      const note = document.createElement("p");
      note.className = "advanced-empty";
      note.textContent = data ? "Пользователи пока не добавлены." : "Список недоступен.";
      list.append(note);
    }
    for (const binding of bindings) {
      const row = document.createElement("div"); row.className = "telegram-binding";
      const body = document.createElement("div");
      const title = document.createElement("strong"); title.textContent = `${TELEGRAM_ROLES[binding.role]} · ${telegramName(binding)}`;
      const detail = document.createElement("span"); detail.textContent = binding.username ? `@${binding.username}` : `Telegram ID ${binding.user_id}`;
      body.append(title, detail);
      const remove = document.createElement("button"); remove.className = "secondary-button";
      remove.type = "button"; remove.textContent = "Удалить доступ";
      remove.setAttribute("aria-label", `Удалить доступ для ${telegramName(binding)}`);
      remove.disabled = telegramClient.bindingBusy;
      remove.addEventListener("click", () => telegramPrepareRemoveBinding(binding));
      const servers = document.createElement("button"); servers.className = "secondary-button";
      servers.type = "button"; servers.textContent = "Доступ к серверам";
      servers.setAttribute("aria-label", `Доступ к серверам для ${telegramName(binding)}`);
      servers.disabled = telegramClient.bindingBusy;
      servers.addEventListener("click", () => globalThis.accessOpen?.("telegram", binding.user_id,
        telegramName(binding), binding.role));
      row.append(body, remove, servers);
      list.append(row);
    }
  }
}

async function telegramRefresh() {
  if (!state.token || state.view !== "telegram") return;
  const generation = telegramClient.generation, sequence = ++telegramClient.refreshSeq;
  const token = state.token, base = state.base;
  telegramClient.loading = true;
  renderTelegram();
  try {
    const payload = await request("/api/v1/telegram", { timeoutMs: 12000 });
    if (!telegramCurrent(generation, token, base) || sequence !== telegramClient.refreshSeq) return;
    telegramClient.data = telegramValidate(payload);
    clearError($("telegramError"));
  } catch (error) {
    if (!telegramCurrent(generation, token, base) || sequence !== telegramClient.refreshSeq) return;
    telegramClient.data = null;
    showError($("telegramError"), error.message || "Не удалось загрузить настройки Telegram.");
  } finally {
    if (telegramCurrent(generation, token, base) && sequence === telegramClient.refreshSeq) {
      telegramClient.loading = false;
      renderTelegram();
    }
  }
}
globalThis.telegramRefresh = telegramRefresh;

async function telegramSaveToken(event) {
  event.preventDefault();
  clearError($("telegramTokenError"));
  if (telegramClient.tokenBusy || telegramClient.data?.mode !== "managed") return;
  const value = $("telegramTokenInput").value.trim();
  // Clear the DOM before sending; it must not retain a secret after an error.
  $("telegramTokenInput").value = "";
  $("telegramTokenInput").type = "password";
  $("telegramRevealToken").textContent = "Показать";
  $("telegramRevealToken").setAttribute("aria-label", "Показать введённый токен");
  $("telegramRevealToken").setAttribute("aria-pressed", "false");
  if (!/^[0-9]{5,20}:[A-Za-z0-9_-]{30,80}$/.test(value)) {
    showError($("telegramTokenError"), "Неверный формат токена. Скопируйте его целиком из BotFather и вставьте снова.");
    $("telegramTokenInput").focus();
    return;
  }
  const hadToken = telegramClient.data.configured;
  const generation = telegramClient.generation, token = state.token, base = state.base;
  telegramInvalidateRefresh();
  telegramClient.tokenBusy = true;
  renderTelegram();
  try {
    const payload = await request("/api/v1/telegram/token", {
      method: "POST", body: JSON.stringify({ token: value }), timeoutMs: 16000,
    });
    if (!telegramCurrent(generation, token, base)) return;
    const verified = telegramValidate(payload);
    telegramInvalidateRefresh();
    telegramClient.data = verified;
    clearError($("telegramError"));
  } catch (error) {
    if (!telegramCurrent(generation, token, base)) return;
    showError($("telegramTokenError"), error.status === 409
      ? "Токен этого центра управляется настройками службы на сервере."
      : error.status === 422 ? "BotFather отклонил токен. Проверьте его и вставьте снова."
        : error.status === 503 ? `Telegram сейчас недоступен для проверки. ${hadToken ? "Прежний токен сохранён." : "Новый токен не сохранён."} Попробуйте позже.`
          : error.status === undefined ? "Ответ не получен. Токен мог сохраниться; проверьте обновлённое состояние перед повторной отправкой."
            : "Не удалось сохранить токен. Проверьте его формат и состояние Hub; затем вставьте снова.");
    void telegramRefresh();
  } finally {
    if (telegramCurrent(generation, token, base)) {
      telegramClient.tokenBusy = false;
      renderTelegram();
    }
  }
}

async function telegramRemoveToken() {
  if (telegramClient.tokenBusy || telegramClient.data?.mode !== "managed" ||
      !telegramClient.data.configured) return;
  const generation = telegramClient.generation, token = state.token, base = state.base;
  telegramInvalidateRefresh();
  telegramClient.tokenBusy = true;
  $("telegramConfirmRemoveToken").disabled = true;
  $("telegramCancelRemoveToken").disabled = true;
  renderTelegram();
  clearError($("telegramRemoveTokenError"));
  try {
    const payload = await request("/api/v1/telegram/token", { method: "DELETE", timeoutMs: 16000 });
    if (!telegramCurrent(generation, token, base)) return;
    const verified = telegramValidate(payload);
    telegramInvalidateRefresh();
    telegramClient.data = verified;
    $("telegramRemoveTokenDialog").close();
    clearError($("telegramError"));
  } catch (error) {
    if (!telegramCurrent(generation, token, base)) return;
    showError($("telegramRemoveTokenError"), error.status === 409
      ? "Токен управляется настройками службы на сервере."
      : "Не удалось удалить токен. Проверьте состояние Hub и повторите запрос.");
  } finally {
    if (telegramCurrent(generation, token, base)) {
      telegramClient.tokenBusy = false;
      $("telegramConfirmRemoveToken").disabled = false;
      $("telegramCancelRemoveToken").disabled = false;
      renderTelegram();
    }
  }
}

async function telegramSaveBinding(event, reviewed = null) {
  event.preventDefault();
  clearError($("telegramBindingError"));
  if (telegramClient.bindingBusy || !telegramClient.data) return;
  const raw = $("telegramUserId").value.trim(), role = $("telegramRole").value;
  const userId = Number(raw);
  if (!/^[1-9][0-9]*$/.test(raw) || !Number.isSafeInteger(userId) ||
      !Object.hasOwn(TELEGRAM_ROLES, role)) {
    showError($("telegramBindingError"), "Введите положительный ID личного чата и выберите роль.");
    return;
  }
  if (reviewed && role !== "admin") {
    showError($("telegramApproveError"), "Роль изменилась. Закройте подтверждение и проверьте выбор снова.");
    return;
  }
  if (role === "admin") {
    if (!reviewed) {
      telegramClient.pendingApproval = { kind: "manual", userId, chatId: userId,
        generation: telegramClient.generation, token: state.token, base: state.base };
      $("telegramApproveSummary").textContent =
        `Вручную выдать роль администратора Telegram ID ${userId}? По умолчанию доступ действует на все серверы; после добавления его можно ограничить кнопкой «Доступ к серверам».`;
      clearError($("telegramApproveError"));
      $("telegramApproveDialog").showModal();
      return;
    }
    if (reviewed !== telegramClient.pendingApproval || reviewed.kind !== "manual" ||
        reviewed.userId !== userId || reviewed.chatId !== userId ||
        !telegramCurrent(reviewed.generation, reviewed.token, reviewed.base)) {
      showError($("telegramApproveError"), "ID или сеанс изменились. Проверьте роль и подтвердите заново.");
      return;
    }
    telegramClient.pendingApproval = null;
    $("telegramApproveDialog").close();
  }
  const generation = telegramClient.generation, token = state.token, base = state.base;
  telegramInvalidateRefresh();
  telegramClient.bindingBusy = true;
  renderTelegram();
  try {
    const result = await request("/api/v1/telegram/bindings", {
      method: "POST", body: JSON.stringify({ user_id: userId, chat_id: userId, role }), timeoutMs: 12000,
    });
    if (!telegramCurrent(generation, token, base)) return;
    if (result?.binding?.user_id !== userId || result.binding.chat_id !== userId || result.binding.role !== role) {
      throw new Error("Hub не подтвердил роль.");
    }
    $("telegramUserId").value = "";
    $("telegramRole").value = "viewer";
    await telegramRefresh();
  } catch (error) {
    if (!telegramCurrent(generation, token, base)) return;
    showError($("telegramBindingError"), error.message || "Не удалось сохранить роль.");
  } finally {
    if (telegramCurrent(generation, token, base)) {
      telegramClient.bindingBusy = false;
      renderTelegram();
    }
  }
}

function telegramPrepareRemoveBinding(binding) {
  if (!telegramClient.data || telegramClient.bindingBusy || !Number.isSafeInteger(binding?.user_id) ||
      binding.user_id <= 0 || binding.user_id !== binding.chat_id) return;
  telegramClient.pendingBinding = { userId: binding.user_id, chatId: binding.chat_id,
    generation: telegramClient.generation, token: state.token, base: state.base };
  $("telegramRemoveBindingSummary").textContent =
    `Удалить доступ для ${telegramName(binding)} (${TELEGRAM_ROLES[binding.role]})? Ожидающие команды этого пользователя будут отменены.`;
  clearError($("telegramRemoveBindingError"));
  $("telegramRemoveBindingDialog").showModal();
}

function telegramPrepareApproval(item, role) {
  if (telegramClient.pairingBusy || !Object.hasOwn(TELEGRAM_ROLES, role) ||
      !telegramClient.data?.pending_requests.some((request) =>
        request.user_id === item.user_id && request.chat_id === item.chat_id)) return;
  if (role !== "admin") {
    void telegramChangePairing(item, "approve", role);
    return;
  }
  telegramClient.pendingApproval = {
    kind: "pairing",
    userId: item.user_id, chatId: item.chat_id, name: telegramName(item),
    generation: telegramClient.generation, token: state.token, base: state.base,
  };
  $("telegramApproveSummary").textContent =
    `Выдать роль администратора пользователю ${telegramName(item)} (Telegram ID ${item.user_id})?`;
  clearError($("telegramApproveError"));
  $("telegramApproveDialog").showModal();
}

async function telegramChangePairing(item, action, role = "viewer") {
  if (telegramClient.pairingBusy || !telegramClient.data ||
      !["approve", "reject"].includes(action) ||
      (action === "approve" && !Object.hasOwn(TELEGRAM_ROLES, role)) ||
      !Number.isSafeInteger(item?.user_id) || item.user_id <= 0 || item.chat_id !== item.user_id ||
      !telegramClient.data.pending_requests.some((request) =>
        request.user_id === item.user_id && request.chat_id === item.chat_id)) return;
  const generation = telegramClient.generation, token = state.token, base = state.base;
  clearError($("telegramPairingError"));
  telegramInvalidateRefresh();
  telegramClient.pairingBusy = true;
  $("telegramConfirmApprove").disabled = true;
  $("telegramCancelApprove").disabled = true;
  renderTelegram();
  try {
    const payload = await request(`/api/v1/telegram/requests/${item.user_id}/${item.chat_id}/${action}`, {
      method: "POST", body: JSON.stringify(action === "approve" ? { role } : {}), timeoutMs: 12000,
    });
    if (!telegramCurrent(generation, token, base)) return;
    telegramInvalidateRefresh();
    telegramClient.data = telegramValidate(payload);
    delete telegramClient.pendingRoles[item.user_id];
    telegramClient.pendingApproval = null;
    if ($("telegramApproveDialog").open) $("telegramApproveDialog").close();
    clearError($("telegramError"));
  } catch (error) {
    if (!telegramCurrent(generation, token, base)) return;
    if ($("telegramApproveDialog").open) $("telegramApproveDialog").close();
    telegramClient.pendingApproval = null;
    showError($("telegramPairingError"), error.status === 404 || error.status === 409
      ? "Запрос уже обработан или устарел. Список обновляется."
      : "Не удалось обработать запрос. Проверьте связь с Hub и повторите попытку.");
    void telegramRefresh();
  } finally {
    if (telegramCurrent(generation, token, base)) {
      telegramClient.pairingBusy = false;
      $("telegramConfirmApprove").disabled = false;
      $("telegramCancelApprove").disabled = false;
      renderTelegram();
    }
  }
}

async function telegramRemoveBinding() {
  const pending = telegramClient.pendingBinding;
  if (!pending || telegramClient.bindingBusy || !telegramCurrent(pending.generation, pending.token, pending.base)) return;
  telegramInvalidateRefresh();
  telegramClient.bindingBusy = true;
  $("telegramConfirmRemoveBinding").disabled = true;
  $("telegramCancelRemoveBinding").disabled = true;
  renderTelegram();
  clearError($("telegramRemoveBindingError"));
  try {
    const result = await request(`/api/v1/telegram/bindings/${pending.userId}/${pending.chatId}`, {
      method: "DELETE", timeoutMs: 12000,
    });
    if (!telegramCurrent(pending.generation, pending.token, pending.base)) return;
    if (typeof result?.removed !== "boolean") throw new Error("Hub не подтвердил удаление роли.");
    telegramClient.pendingBinding = null;
    $("telegramRemoveBindingDialog").close();
    await telegramRefresh();
  } catch (error) {
    if (!telegramCurrent(pending.generation, pending.token, pending.base)) return;
    showError($("telegramRemoveBindingError"), error.message || "Не удалось удалить доступ.");
  } finally {
    if (telegramCurrent(pending.generation, pending.token, pending.base)) {
      telegramClient.bindingBusy = false;
      $("telegramConfirmRemoveBinding").disabled = false;
      $("telegramCancelRemoveBinding").disabled = false;
      renderTelegram();
    }
  }
}

$("telegramTokenForm").addEventListener("submit", telegramSaveToken);
$("telegramRevealToken").addEventListener("click", () => {
  const input = $("telegramTokenInput");
  input.type = input.type === "password" ? "text" : "password";
  const revealed = input.type === "text";
  $("telegramRevealToken").textContent = revealed ? "Скрыть" : "Показать";
  $("telegramRevealToken").setAttribute("aria-label", revealed ? "Скрыть введённый токен" : "Показать введённый токен");
  $("telegramRevealToken").setAttribute("aria-pressed", String(revealed));
  input.focus();
});
$("telegramRemoveToken").addEventListener("click", () => {
  if (telegramClient.data?.mode === "managed" && telegramClient.data.configured) {
    clearError($("telegramRemoveTokenError"));
    $("telegramRemoveTokenDialog").showModal();
  }
});
$("telegramConfirmRemoveToken").addEventListener("click", telegramRemoveToken);
$("telegramCancelRemoveToken").addEventListener("click", () => { if (!telegramClient.tokenBusy) $("telegramRemoveTokenDialog").close(); });
$("telegramRemoveTokenDialog").addEventListener("cancel", (event) => { if (telegramClient.tokenBusy) event.preventDefault(); });
$("telegramBindingForm").addEventListener("submit", telegramSaveBinding);
$("telegramConfirmApprove").addEventListener("click", () => {
  const pending = telegramClient.pendingApproval;
  if (pending && telegramCurrent(pending.generation, pending.token, pending.base)) {
    if (pending.kind === "manual") void telegramSaveBinding({ preventDefault() {} }, pending);
    else if (pending.kind === "pairing")
      void telegramChangePairing({ user_id: pending.userId, chat_id: pending.chatId }, "approve", "admin");
  }
});
$("telegramCancelApprove").addEventListener("click", () => {
  if (!telegramClient.pairingBusy) $("telegramApproveDialog").close();
});
$("telegramApproveDialog").addEventListener("cancel", (event) => {
  if (telegramClient.pairingBusy) event.preventDefault();
});
$("telegramApproveDialog").addEventListener("close", () => {
  if (!telegramClient.pairingBusy) telegramClient.pendingApproval = null;
});
$("telegramConfirmRemoveBinding").addEventListener("click", telegramRemoveBinding);
$("telegramCancelRemoveBinding").addEventListener("click", () => { if (!telegramClient.bindingBusy) $("telegramRemoveBindingDialog").close(); });
$("telegramRemoveBindingDialog").addEventListener("cancel", (event) => { if (telegramClient.bindingBusy) event.preventDefault(); });
$("telegramRemoveBindingDialog").addEventListener("close", () => { if (!telegramClient.bindingBusy) telegramClient.pendingBinding = null; });
